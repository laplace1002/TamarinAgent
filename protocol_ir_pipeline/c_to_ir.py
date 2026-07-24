from __future__ import annotations

import bisect
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .cases import ProtocolCase
from .ir import build_protocol_ir_bundle
from .llm import LLMClient, llm_call_record
from .modeling_contract import build_modeling_contract, write_modeling_contract_artifacts
from .proofspec import ProofSpec, case_goals_proof_spec


C_TO_IR_SYSTEM = """You are a conservative C-to-ProtocolIR extractor for security-protocol verification.
Return only strict JSON.

Global rules:
1. Use only the supplied C code slices, comments, deterministic code facts, and previous JSON extraction facts.
2. Every protocol-relevant output item must include source evidence with file, line_start, line_end, and reason.
3. If evidence is incomplete, output an assumption or open_question. Prefer unknown over guessing.
4. Do not invent protocol behavior from function names alone.
5. Separate code facts, security intent, and modeling decisions.
6. Comments may justify intended goals; code checks and control flow must justify implementation behavior.
7. Do not create a security claim unless there is explicit security intent or an accept/check boundary.
8. Preserve proof-relevant value provenance: setup/state, fresh generation, adversarial input, verified input, derived material, and opaque forwarding.
9. Preserve crypto dependencies and accept boundaries; do not silently drop transcript inputs, nonces, attributes, identities, or checks.
10. Do not output Sapic+, ProVerif, or Tamarin code in this C-to-IR extraction stage.
11. Do not use arrays of bare strings for extraction facts. Each list item must be a JSON object with a stable id/name, summary/meaning, evidence when available, confidence, and assumptions/open_questions when relevant."""


JSON_RETRY_SYSTEM = """You repair JSON extraction output.
Return only one complete strict JSON object. Do not include Markdown."""


@dataclass(frozen=True)
class CToIRStage:
    stage_id: str
    filename: str
    title: str
    objective: str
    output_shape: dict[str, Any]
    code_slice_policy: str
    instructions: list[str]


EXTRACTION_STAGES: tuple[CToIRStage, ...] = (
    CToIRStage(
        stage_id="01_intent",
        filename="01_intent.json",
        title="File-Level Protocol Intent",
        objective="Extract security intent, protocol phases, trust assumptions, known attacks, and out-of-scope details.",
        code_slice_policy="Use top-level comments, security-relevant comments, file summaries, and exported function comments.",
        output_shape={
            "security_intent": [
                {
                    "id": "intent_id",
                    "goal": "short statement",
                    "kind": "integrity|authentication|secrecy|freshness|known_attack|out_of_scope|availability|unknown",
                    "evidence": [{"file": "path", "line_start": 1, "line_end": 2, "reason": "why this span supports the item"}],
                    "confidence": "high|medium|low",
                }
            ],
            "protocol_phases": [],
            "trust_assumptions": [],
            "known_attacks": [],
            "out_of_scope": [],
            "open_questions": [],
        },
        instructions=[
            "Do not extract function-level behavior yet.",
            "Treat comments as intent evidence, not as implementation proof.",
            "Mark any dependency on headers, other source files, deployment configuration, or external certification as open_question.",
            "Put vulnerabilities, caveats, and unmitigated threats in known_attacks or out_of_scope, not in trust_assumptions.",
            "Trust assumptions should be positive assumptions required for claims, such as trusted hardware, correct crypto, authenticated public keys, or uncompromised local state.",
            "Do not create an open_question merely because a function body is not in selected_code_slices when deterministic_code_context contains that function span; later stages will inspect bodies.",
        ],
    ),
    CToIRStage(
        stage_id="02_functions",
        filename="02_functions.json",
        title="Function Role Classification",
        objective="Classify C functions by their protocol role and decide which bodies need detailed extraction.",
        code_slice_policy="Use function signatures, line spans, local call lists, and compact body excerpts.",
        output_shape={
            "functions": [
                {
                    "name": "function_name",
                    "class": "protocol_entrypoint|lifecycle_transition|message_constructor|message_parser_checker|crypto_derivation|state_update|local_helper|implementation_detail|unknown",
                    "protocol_relevance": "high|medium|low",
                    "protocol_surface": ["state|crypto|message|check|lifecycle|environment|none"],
                    "why_relevant": "short reason",
                    "evidence": [],
                    "needs_body_slice": True,
                }
            ],
            "open_questions": [],
        },
        instructions=[
            "Do not infer protocol behavior from names alone; use calls, comments, parameters, and state access as evidence.",
            "Prefer implementation_detail for memory-only helpers, formatting helpers, or error-handling helpers unless they affect messages, checks, or crypto.",
            "Keep one compact record per function. Do not enumerate reads_state, writes_state, external_inputs, or external_outputs in this stage; those are extracted later from deterministic field access and focused code slices.",
            "Output exactly one functions[] record for each function in deterministic_code_context.function_index.",
            "Use at most one evidence item per function. Keep why_relevant and evidence.reason under 20 words each.",
            "Do not include code excerpts, call lists, summaries, or fields not present in the required output shape.",
        ],
    ),
    CToIRStage(
        stage_id="03_state",
        filename="03_state.json",
        title="State and Secret Classification",
        objective="Classify persistent C state and proof-relevant local values into ProtocolIR value-provenance categories.",
        code_slice_policy="Use struct/union/enum definitions, global variables, and relevant read/write snippets.",
        output_shape={
            "state_variables": [
                {
                    "c_name": "struct_or_field_name",
                    "ir_name": "symbolicName",
                    "classification": "fresh_secret|fresh_public|caller_secret_input|derived_secret|public_authenticated|public_untrusted|adversary_input|lifecycle_control|transcript_binding|implementation_scratch|unknown",
                    "owner_role": "role or unknown",
                    "written_by": [],
                    "read_by": [],
                    "protocol_meaning": "short meaning",
                    "evidence": [],
                    "assumptions": [],
                    "confidence": "high|medium|low",
                }
            ],
            "derived_values": [],
            "implementation_only_values": [],
            "open_questions": [],
        },
        instructions=[
            "Do not put scratch buffers, local temporaries, or byte offsets into protocol state unless they cross a transition or enter crypto/message/check semantics.",
            "Classify secrets and public values by provenance, not by C type.",
            "Do not infer KDF/HMAC/encryption derivation details in this stage; defer cryptographic equations to Stage 05. Here, only classify storage fields and persistent values.",
            "A field initialized from caller input or stored state is not fresh unless code evidence shows local random generation before first use.",
            "Protocol nonces are usually fresh_public or transcript_binding, not fresh_secret, unless code evidence says they must remain confidential.",
            "Caller-provided authentication material such as passwords, PSKs, or passphrases should be caller_secret_input, not adversary_input, unless the caller is explicitly modeled as the adversary.",
        ],
    ),
    CToIRStage(
        stage_id="04_environment",
        filename="04_environment.json",
        title="External Environment Model",
        objective="Classify external APIs, missing definitions, and environment assumptions that affect protocol behavior.",
        code_slice_policy="Use external call inventory, call-site snippets, missing includes, and compile diagnostics.",
        output_shape={
            "external_interfaces": [
                {
                    "name": "interface_group_name",
                    "members": ["external_symbol"],
                    "classification": "adversarial_channel|trusted_crypto_primitive|randomness_source|trusted_parser_marshaler|transport|memory_resource_helper|trusted_platform_api|unknown",
                    "protocol_assumption": "short assumption",
                    "modeled_as": "symbolic abstraction",
                    "evidence": [],
                    "open_question_if_unmodeled": "question or empty",
                }
            ],
            "modeling_assumptions": [],
            "open_questions": [],
        },
        instructions=[
            "External crypto APIs should normally become ideal symbolic primitives only under an explicit modeling assumption.",
            "External transport or network-like APIs should be adversarial unless the supplied code proves otherwise.",
            "If an external transport crosses a trust boundary between protocol roles, classify it as adversarial_channel. Use transport only for trusted local dispatch that is not attacker-observable.",
            "Do not mix local conversion/error helpers into an adversarial_channel group; that group should contain only actual send, receive, transmit, or externally visible channel operations.",
            "Missing headers should create open_questions, not invented facts.",
            "Group related external symbols together. Do not create one external_interfaces record per C function.",
            "Return at most 12 external_interfaces records. Each members list should contain at most 8 representative symbols.",
            "Use at most one evidence item per interface group. Keep protocol_assumption under 25 words.",
        ],
    ),
    CToIRStage(
        stage_id="05_crypto",
        filename="05_crypto.json",
        title="Crypto Transcript Extraction",
        objective="Extract symbolic crypto computations, dependencies, transcript inputs, and checked outputs.",
        code_slice_policy="Use crypto-related functions, random generation, hashing/MAC/KDF/encryption calls, and dependent state snippets.",
        output_shape={
            "crypto_operations": [
                {
                    "id": "crypto_op_id",
                    "kind": "random|hash|hmac|mac|kdf|sign|verify|encrypt|decrypt|dh|keygen|unknown",
                    "inputs": [],
                    "output": "symbolic output",
                    "purpose": "short purpose",
                    "used_by_checks": [],
                    "used_by_messages": [],
                    "evidence": [],
                    "abstraction": "what low-level detail is abstracted",
                }
            ],
            "dropped_details": [],
            "open_questions": [],
        },
        instructions=[
            "Preserve operand order when code or comments make it explicit.",
            "It is acceptable to abstract byte encoding, but not to drop fields that affect derivability, equality checks, secrecy, authentication, or known attacks.",
            "State whether decryption output is trusted only after a verification/check boundary.",
            "For HMAC/MAC operations, inputs must be field-level transcript terms, not a phrase like 'buffer contents'. Include hash inputs, nonces, attributes, command/response codes, names, handles, and passphrase contribution when present.",
            "If code initializes an HMAC and then calls hmac_update/mac_update multiple times, list every update argument as a separate inputs element in exact order. Do not collapse later update arguments into the first hash input.",
            "If the HMAC key length includes extra caller material, represent the key as a combined key material term such as sessionKey_plus_passphrase.",
            "If two HMAC operations use the same init expression and key length expression, their key material inputs must be represented consistently.",
            "For hash transcript operations such as cpHash/rpHash, list the semantic fields hashed by the code.",
            "If the same KDF label is used with different input order, emit separate crypto_operations. Nonce order is proof-relevant.",
            "For encryption/decryption key derivation, distinguish command direction from response direction when the nonce order differs.",
        ],
    ),
    CToIRStage(
        stage_id="06_messages",
        filename="06_messages.json",
        title="Message Extraction",
        objective="Convert C buffer construction/parsing into symbolic protocol messages.",
        code_slice_policy="Use buffer append/read, send/receive, marshal/unmarshal, parser/checker, and transport-adjacent snippets.",
        output_shape={
            "messages": [
                {
                    "label": "M1_or_semantic_name",
                    "from": "sender role or unknown",
                    "to": "receiver role or unknown",
                    "term": "symbolic_term(...)",
                    "fields": [],
                    "protected_fields": [],
                    "attacker_visible_fields": [],
                    "constructed_by": [],
                    "accepted_by": [],
                    "evidence": [],
                }
            ],
            "abstractions": [],
            "open_questions": [],
        },
        instructions=[
            "Keep fields that appear in crypto transcripts, checks, events, or claims.",
            "Byte offsets, endian conversions, and exact marshaling may be abstracted only if their security role is recorded or marked out of scope.",
            "Use function-style symbolic terms suitable for later ProtocolIR/Sapic+ generation.",
        ],
    ),
    CToIRStage(
        stage_id="07_checks_events",
        filename="07_checks_events.json",
        title="Checks and Trusted Events",
        objective="Extract security-relevant checks, failure behavior, success boundaries, and trusted events.",
        code_slice_policy="Use parser/checker functions, verify/decrypt/hash comparisons, error returns, and accept-state snippets.",
        output_shape={
            "checks": [
                {
                    "name": "check_name",
                    "condition": "symbolic condition",
                    "on_failure": "abort|return_error|ignore|unknown",
                    "on_success_event": "event name or empty",
                    "protects": [],
                    "source_message": "message label or unknown",
                    "evidence": [],
                }
            ],
            "events": [
                {
                    "name": "event_name",
                    "when": "before_send|after_send|after_check|after_receive|state_update|unknown",
                    "role": "role or unknown",
                    "arguments": [],
                    "evidence": [],
                }
            ],
            "open_questions": [],
        },
        instructions=[
            "A trusted accept event may only appear after the code verifies the needed condition.",
            "Do not treat parsed network input as trusted before a verification boundary.",
            "Record failure branches that prevent accept events.",
            "For goto/error branches, inspect dominating assignments and comments before marking the failure return value unknown.",
        ],
    ),
    CToIRStage(
        stage_id="08_lifecycle",
        filename="08_lifecycle.json",
        title="Lifecycle Extraction",
        objective="Extract a semantic finite-state lifecycle from entrypoints, state updates, errors, and continuation/cleanup branches.",
        code_slice_policy="Use init/start/end/close/free/session/state functions and state-update snippets.",
        output_shape={
            "lifecycle": {
                "states": [],
                "transitions": [
                    {
                        "from": "state",
                        "to": "state",
                        "trigger_function": "function name",
                        "guard": "condition or empty",
                        "events": [],
                        "evidence": [],
                    }
                ],
            },
            "open_questions": [],
        },
        instructions=[
            "Use semantic states, not C basic-block labels.",
            "Include branches caused by errors, options, attributes, continuation flags, compromise, or cleanup.",
            "When success and failure paths join at an out/cleanup label, preserve the return-code guard and cleanup branch separately.",
            "If a cleanup action is implemented inline, do not rewrite it as a call to a similarly named helper unless there is a direct call site.",
            "When continuation attributes decide whether state is freed, flushed, or reset for reuse, emit separate transitions for each guarded branch.",
            "If a cleanup label checks a CONTINUE_SESSION-style flag after both success and error paths, do not first collapse failures into a single error state; split failure-and-continue from failure-and-not-continue just like success branches.",
            "Do not write one transition whose events say both 'if CONTINUE_SESSION is set' and 'if CONTINUE_SESSION is not set'; that is two transitions with different guards.",
            "Do not merge error transitions across functions when those functions use different cleanup logic; command-preparation errors, transport errors, response-check errors, and explicit-close errors should be separate if the C code handles them differently.",
            "If the file only covers a lifecycle slice, say so explicitly.",
        ],
    ),
    CToIRStage(
        stage_id="09_claims",
        filename="09_claims.json",
        title="Claim and Lemma Candidate Extraction",
        objective="Generate a fine-grained claim proof profile from intent, checks, events, lifecycle, and threat model. When user goals are absent, infer the security goals that the code evidence supports.",
        code_slice_policy="Use previous extraction facts plus security-intent comments; code slices are secondary.",
        output_shape={
            "claims": [
                {
                    "lemma_name": "stable_lemma_name",
                    "claim_category": "executability|key_secrecy|command_authentication|response_authentication|command_payload_confidentiality|response_payload_confidentiality|validation|known_attack|lifecycle|continued_session|other",
                    "goal_type": "authentication|secrecy|executability|state_safety|source|known_attack|property",
                    "trace_kind": "all-traces|exists-trace",
                    "expected_state": "ProvedSatisfying|CounterexampleFound",
                    "intent": "informal statement",
                    "required_events": [
                        {
                            "name": "event/action fact name",
                            "role": "role that emits it",
                            "when": "semantic boundary where it is emitted",
                            "arguments": [],
                            "source_boundary": "function/check/send/receive boundary evidence",
                        }
                    ],
                    "preserved_values": [],
                    "holds_under": [],
                    "does_not_hold_under": [],
                    "anti_compression_note": "why this claim must not be merged into a broader lemma",
                    "evidence": [],
                }
            ],
            "rejected_claims": [],
            "open_questions": [],
        },
        instructions=[
            "Default to the `claim` profile, not a smoke profile, when the user has not supplied proof goals.",
            "Only generate a claim when supported by explicit security intent and corresponding checks/events/lifecycle facts.",
            "Generate separate command/request authentication and response authentication claims when the code has distinct protected send/accept boundaries.",
            "Generate payload confidentiality claims for encrypted plaintext command/request and response parameters; do not replace payload confidentiality with session-key secrecy.",
            "Generate session/key secrecy claims separately for fresh or derived keys that are intended to remain private.",
            "Generate validation-only claims for checks that establish consistency, such as name/hash/public-material checks, but do not imply origin authenticity.",
            "Generate known-attack claims when the code or comments expose an unmitigated attack branch.",
            "Prefer explicit exists-trace attack witnesses for fake setup, replay, MITM, or untrusted continuation branches when the attack state is intended to be reachable.",
            "For explicit exists-trace attack witnesses, set expected_state to ProvedSatisfying. Use CounterexampleFound only for all-traces/safety properties that are intentionally expected to be falsified.",
            "Generate continued-session or lifecycle variants when state, nonce, transcript, handle, attrs, or trust changes across commands.",
            "Do not turn an assumption into a proved property.",
            "Do not merge, rename, weaken, or replace a fine-grained claim with a generic integrity/secrecy lemma. If a candidate is deliberately compressed or rejected, record that decision in rejected_claims with evidence.",
        ],
    ),
    CToIRStage(
        stage_id="10_protocol_ir",
        filename="10_protocol_ir.json",
        title="ProtocolIR Assembly",
        objective="Assemble a ProtocolIR candidate using the existing project schema and hidden field_evidence.",
        code_slice_policy="Use all previous extraction facts. Only include code snippets needed to resolve conflicts.",
        output_shape={
            "schema": "protocol_ir_pipeline_protocol_ir_v1",
            "protocol_name": "ProtocolName",
            "roles": [],
            "principals": [],
            "crypto": {"builtins": [], "functions": [], "equations": [], "assumptions": []},
            "fresh_terms": [],
            "long_term_keys": [],
            "messages": [],
            "actions": [],
            "checks": [],
            "events": [],
            "claims": [],
            "compromise": {"reveal_events": [], "policy": ""},
            "abstractions": [],
            "modeling_assumptions": [],
            "semantic_constraints": [],
            "field_evidence": [
                {
                    "field_path": "messages.0.term",
                    "source_quote": "short source excerpt or empty",
                    "evidence_kind": "direct|nearby|assumption|none",
                    "reason": "why this ProtocolIR field is supported or why it needs review",
                    "evidence_confidence_score": 0.0,
                    "consistency_confidence_score": 0.0,
                    "semantic_impact_score": 1.0,
                    "priority_llm": 0.0,
                }
            ],
            "resolved_open_questions": [],
            "open_questions": [],
        },
        instructions=[
            "Use the stable ProtocolIR fields exactly; do not invent a parallel EvidenceIR schema.",
            "Do not emit placeholder records with empty term, condition, role, action, event, or intent fields. If a value is unknown, write an explicit unknown(...) term and add an open_question.",
            "For messages, copy the non-empty symbolic term from Stage 06 exactly unless a conflict is identified.",
            "For crypto, preserve Stage 05 cpHash, rpHash, HMAC, KDF, nonce-order, passphrase, and attrs inputs.",
            "Keep the assembled ProtocolIR compact: at most 12 messages, 12 actions, 16 checks, 32 events, 16 claims, and 24 semantic_constraints unless lifecycle/continued-session variants need more. Do not drop fine-grained security claims just to meet compactness.",
            "Do not cap field_evidence below the number of non-empty review-UI fields; every reviewable field needs its own score metadata.",
            "Use at most one concise source quote per field_evidence item.",
            "Every claim must cite checks/events/security_intent via field_evidence or supporting assumptions.",
            "Every message field used in crypto should appear in messages, checks, actions, or semantic_constraints.",
            "Distinguish setup/lifecycle messages from the core protected command/response messages in actions, semantic_constraints, or abstractions.",
            "Every abstraction must say what was dropped and why it is safe, assumed, or out of scope.",
            "Output one ProtocolIR candidate JSON object directly.",
        ],
    ),
)


CRITIC_STAGE = CToIRStage(
    stage_id="11_critic",
    filename="11_critic.json",
    title="ProtocolIR Critic",
    objective="Audit an assembled ProtocolIR against C evidence and previous extraction facts.",
    code_slice_policy="Use all previous facts, assembled ProtocolIR, and critical source slices.",
    output_shape={
        "blocking_issues": [],
        "nonblocking_warnings": [],
        "required_patches": [],
        "confidence_summary": {},
    },
    instructions=[
        "Find unsupported security claims, missing checks before trusted events, dropped crypto transcript inputs, omitted lifecycle branches, assumptions hidden as facts, missing source evidence, and known attacks accidentally removed.",
        "Do not report a missing explicit equality check when the value is already an input to a verified MAC/HMAC/hash check and the model records that dependency.",
        "Do not require explicit verification of KDF, DH, RNG, or ideal cryptographic primitive outputs when they are already stated as modeling assumptions; instead report if the assumption is missing or hidden.",
        "Do not report a check as missing if previous extraction facts include that check with source evidence.",
        "Do not invent TPM-spec requirements not present in the supplied C file; mark them as open questions unless the C evidence or user goals require them.",
        "Do not repair the IR in this stage; produce an audit report.",
    ],
)


CONTROL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "do",
    "case",
    "else",
    "goto",
}

CALL_EXCLUDE = CONTROL_KEYWORDS | {
    "define",
    "defined",
    "include",
    "typedef",
    "struct",
    "union",
    "enum",
    "likely",
    "unlikely",
}

SECURITY_KEYWORDS = (
    "auth",
    "authenticate",
    "check",
    "cipher",
    "crypto",
    "decrypt",
    "derive",
    "encrypt",
    "hmac",
    "integrity",
    "key",
    "kdf",
    "mac",
    "nonce",
    "proof",
    "random",
    "secret",
    "session",
    "sign",
    "tamper",
    "verify",
)

CRYPTO_CALL_KEYWORDS = (
    "aead",
    "aes",
    "auth",
    "cfb",
    "cipher",
    "crypto",
    "decrypt",
    "derive",
    "digest",
    "ecdh",
    "encrypt",
    "hash",
    "hmac",
    "kdf",
    "mac",
    "nonce",
    "random",
    "rng",
    "sha",
    "sign",
    "verify",
)

BUFFER_CALL_KEYWORDS = (
    "append",
    "be16",
    "be32",
    "buf",
    "buffer",
    "get",
    "marshal",
    "parse",
    "put",
    "read",
    "recv",
    "send",
    "transmit",
    "unmarshal",
    "write",
)

LIFECYCLE_KEYWORDS = (
    "begin",
    "close",
    "continue",
    "end",
    "finish",
    "free",
    "init",
    "open",
    "reset",
    "session",
    "start",
    "state",
    "stop",
)


def build_c_code_context(source_paths: list[Path], *, max_function_excerpt_chars: int = 2400) -> dict[str, Any]:
    files = []
    all_functions: dict[str, dict[str, Any]] = {}
    all_calls: dict[str, dict[str, Any]] = {}
    missing_includes: list[dict[str, Any]] = []
    for path in source_paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        masked, comments = _mask_comments_and_strings(text, str(path))
        starts = _line_starts(text)
        functions = _extract_functions(text, masked, starts, str(path), max_excerpt_chars=max_function_excerpt_chars)
        typedefs = _extract_type_definitions(text, masked, starts, str(path))
        includes = _extract_includes(text, starts, str(path))
        file_calls = _extract_calls(text, masked, starts, str(path), functions)
        field_accesses = _extract_field_accesses(text, masked, starts, str(path), functions, typedefs)
        crypto_transcripts = _extract_crypto_transcripts(text, starts, str(path), functions)
        _attach_calls_to_functions(functions, file_calls)
        for include in includes:
            if include.get("kind") == "local":
                include_path = path.parent / str(include.get("target") or "")
                if not include_path.exists():
                    missing_includes.append(include)
        for func in functions:
            all_functions.setdefault(func["name"], func)
        for call in file_calls:
            entry = all_calls.setdefault(
                call["name"],
                {
                    "name": call["name"],
                    "call_sites": [],
                    "files": [],
                    "categories": sorted(_call_categories(call["name"])),
                },
            )
            entry["call_sites"].append({"file": call["file"], "line": call["line"], "enclosing_function": call.get("enclosing_function", "")})
            if call["file"] not in entry["files"]:
                entry["files"].append(call["file"])
        files.append(
            {
                "path": str(path),
                "line_count": len(text.splitlines()),
                "includes": includes,
                "comments": comments[:80],
                "security_comments": _security_comments(comments),
                "type_definitions": typedefs,
                "field_accesses": field_accesses,
                "crypto_transcripts": crypto_transcripts,
                "functions": functions,
            }
        )
    function_names = set(all_functions)
    external_calls = [
        value
        for name, value in sorted(all_calls.items())
        if name not in function_names and name not in CALL_EXCLUDE
    ]
    return {
        "schema": "protocol_ir_pipeline_c_code_context_v1",
        "source_files": [str(path) for path in source_paths],
        "files": files,
        "function_index": [
            {
                "name": func["name"],
                "file": func["file"],
                "line_start": func["line_start"],
                "line_end": func["line_end"],
                "signature": func["signature"],
                "calls": func.get("calls", []),
                "cleanup_labels": func.get("cleanup_labels", []),
                "categories": _function_categories(func),
            }
            for func in sorted(all_functions.values(), key=lambda item: (item["file"], item["line_start"], item["name"]))
        ],
        "external_calls": external_calls,
        "crypto_calls": [item for item in external_calls if "crypto" in item.get("categories", [])],
        "buffer_calls": [item for item in external_calls if "buffer" in item.get("categories", [])],
        "missing_includes": missing_includes,
        "field_accesses": [
            access
            for file_entry in files
            for access in file_entry.get("field_accesses", [])
        ],
        "crypto_transcript_hints": [
            transcript
            for file_entry in files
            for transcript in file_entry.get("crypto_transcripts", [])
        ],
    }


def build_stage_prompt(
    stage: CToIRStage,
    code_context: dict[str, Any],
    previous_facts: dict[str, Any] | None = None,
    *,
    protocol_name: str = "",
    goals: list[dict[str, Any]] | None = None,
    max_prompt_code_chars: int = 24000,
) -> str:
    previous_facts = previous_facts if isinstance(previous_facts, dict) else {}
    payload = {
        "protocol_name_hint": protocol_name,
        "user_supplied_goals": goals or [],
        "stage": {
            "id": stage.stage_id,
            "title": stage.title,
            "objective": stage.objective,
            "code_slice_policy": stage.code_slice_policy,
            "instructions": stage.instructions,
            "required_output_shape": stage.output_shape,
        },
        "deterministic_code_context": _compact_context_for_prompt(code_context, stage.stage_id),
        "selected_code_slices": select_code_slices_for_stage(
            code_context,
            stage.stage_id,
            max_chars=max_prompt_code_chars,
        ),
        "previous_extraction_facts": _compact_previous_facts_for_prompt(previous_facts, stage.stage_id),
    }
    return f"""Perform this C-to-ProtocolIR extraction stage.

Return only one strict JSON object matching the required output shape.
Do not emit Markdown, Sapic+, ProVerif, or Tamarin code.
Do not return arrays of bare strings for extraction facts. Use JSON objects with stable ids/names, evidence, confidence, and assumptions/open_questions where relevant.

Extraction payload:
{_prompt_json(payload)}
"""


def build_json_retry_prompt(original_prompt: str, raw_response: str, failure_reason: str) -> str:
    return f"""The previous C-to-IR extraction response was not parseable as one complete JSON object.

Failure reason:
{failure_reason}

Previous response:
{raw_response[:12000]}

Original extraction task:
{original_prompt}

Return one complete strict JSON object only."""


def _compact_previous_facts_for_prompt(previous_facts: dict[str, Any], stage_id: str) -> dict[str, Any]:
    if not previous_facts:
        return {}
    compact: dict[str, Any] = {}
    for key, value in previous_facts.items():
        if not isinstance(value, dict):
            compact[key] = value
            continue
        if key == "01_intent":
            compact[key] = {
                "security_intent": _compact_list(value.get("security_intent"), ["id", "kind", "goal", "confidence", "evidence"], limit=8),
                "known_attacks": _compact_list(value.get("known_attacks"), ["id", "attack", "description", "confidence", "evidence"], limit=6),
                "trust_assumptions": _compact_list(value.get("trust_assumptions"), ["id", "assumption", "description", "confidence", "evidence"], limit=8),
                "out_of_scope": _compact_list(value.get("out_of_scope"), ["id", "item", "description", "confidence", "evidence"], limit=8),
                "open_questions": _compact_list(value.get("open_questions"), ["id", "question", "confidence", "evidence"], limit=6),
            }
        elif key == "02_functions":
            compact[key] = {
                "functions": _compact_list(
                    value.get("functions"),
                    ["name", "class", "protocol_relevance", "protocol_surface", "needs_body_slice", "why_relevant", "evidence"],
                    limit=80,
                ),
                "open_questions": _compact_list(value.get("open_questions"), ["id", "question", "confidence", "evidence"], limit=6),
            }
        elif key == "03_state":
            compact[key] = {
                "state_variables": _compact_list(
                    value.get("state_variables"),
                    ["c_name", "ir_name", "classification", "owner_role", "protocol_meaning", "confidence", "evidence"],
                    limit=80,
                ),
                "derived_values": _compact_list(value.get("derived_values"), ["ir_name", "classification", "protocol_meaning", "confidence", "evidence"], limit=20),
                "implementation_only_values": _compact_list(value.get("implementation_only_values"), ["c_name", "classification", "protocol_meaning", "confidence", "evidence"], limit=20),
                "open_questions": _compact_list(value.get("open_questions"), ["id", "question", "confidence", "evidence"], limit=6),
            }
        elif key == "04_environment":
            compact[key] = {
                "external_interfaces": _compact_list(
                    value.get("external_interfaces"),
                    ["name", "members", "classification", "protocol_assumption", "modeled_as", "evidence", "open_question_if_unmodeled"],
                    limit=16,
                ),
                "modeling_assumptions": _compact_list(value.get("modeling_assumptions"), ["id", "assumption", "summary", "confidence", "evidence"], limit=10),
                "open_questions": _compact_list(value.get("open_questions"), ["id", "question", "confidence", "evidence"], limit=6),
            }
        elif key == "05_crypto":
            compact[key] = {
                "crypto_operations": _compact_list(
                    value.get("crypto_operations"),
                    ["id", "kind", "inputs", "output", "purpose", "used_by_checks", "used_by_messages", "abstraction", "evidence"],
                    limit=24,
                ),
                "dropped_details": _compact_list(value.get("dropped_details"), ["id", "detail", "reason", "evidence"], limit=10),
                "open_questions": _compact_list(value.get("open_questions"), ["id", "question", "confidence", "evidence"], limit=6),
            }
        elif key == "06_messages":
            compact[key] = {
                "messages": _compact_list(
                    value.get("messages"),
                    ["label", "from", "to", "term", "fields", "protected_fields", "attacker_visible_fields", "constructed_by", "accepted_by", "evidence"],
                    limit=16,
                ),
                "abstractions": _compact_list(value.get("abstractions"), ["id", "summary", "reason", "evidence"], limit=10),
                "open_questions": _compact_list(value.get("open_questions"), ["id", "question", "confidence", "evidence"], limit=6),
            }
        elif key == "07_checks_events":
            compact[key] = {
                "checks": _compact_list(
                    value.get("checks"),
                    ["name", "condition", "on_failure", "on_success_event", "protects", "source_message", "evidence"],
                    limit=30,
                ),
                "events": _compact_list(value.get("events"), ["name", "when", "role", "arguments", "evidence"], limit=16),
                "open_questions": _compact_list(value.get("open_questions"), ["id", "question", "confidence", "evidence"], limit=6),
            }
        elif key == "08_lifecycle":
            lifecycle = value.get("lifecycle") if isinstance(value.get("lifecycle"), dict) else {}
            compact[key] = {
                "lifecycle": {
                    "states": _compact_list(lifecycle.get("states"), ["id", "name", "meaning", "confidence", "evidence"], limit=16),
                    "transitions": _compact_list(
                        lifecycle.get("transitions"),
                        ["from", "to", "trigger_function", "guard", "events", "evidence"],
                        limit=24,
                    ),
                },
                "open_questions": _compact_list(value.get("open_questions"), ["id", "question", "confidence", "evidence"], limit=6),
            }
        elif key == "09_claims":
            compact[key] = {
                "claims": _compact_list(
                    value.get("claims"),
                    [
                        "lemma_name",
                        "claim_category",
                        "goal_type",
                        "trace_kind",
                        "expected_state",
                        "intent",
                        "required_events",
                        "preserved_values",
                        "holds_under",
                        "does_not_hold_under",
                        "anti_compression_note",
                        "evidence",
                    ],
                    limit=16,
                ),
                "rejected_claims": _compact_list(value.get("rejected_claims"), ["lemma_name", "intent", "reason", "evidence"], limit=8),
                "open_questions": _compact_list(value.get("open_questions"), ["id", "question", "confidence", "evidence"], limit=6),
            }
        else:
            compact[key] = _compact_generic_fact(value)
    return compact


def _compact_list(value: Any, keys: list[str], *, limit: int) -> list[Any]:
    if not isinstance(value, list):
        return []
    return [_compact_dict_item(item, keys) if isinstance(item, dict) else item for item in value[:limit]]


def _compact_dict_item(item: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in keys:
        if key not in item:
            continue
        value = item.get(key)
        if key == "evidence":
            result[key] = _compact_evidence(value)
        elif isinstance(value, str):
            result[key] = _truncate_text(value, 180)
        else:
            result[key] = value
    return result


def _compact_evidence(value: Any) -> list[dict[str, Any]]:
    evidence = value if isinstance(value, list) else []
    result = []
    for item in evidence[:1]:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "file": item.get("file"),
                "line_start": item.get("line_start"),
                "line_end": item.get("line_end"),
                "reason": _truncate_text(str(item.get("reason") or ""), 160),
            }
        )
    return result


def _compact_generic_fact(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, list):
            result[key] = [
                _compact_dict_item(
                    entry,
                    ["id", "name", "label", "kind", "classification", "summary", "meaning", "condition", "intent", "confidence", "evidence"],
                )
                if isinstance(entry, dict)
                else _truncate_text(str(entry), 160)
                for entry in item[:30]
            ]
        elif isinstance(item, dict):
            result[key] = _compact_generic_fact(item)
        elif isinstance(item, str):
            result[key] = _truncate_text(item, 240)
        else:
            result[key] = item
    return result


def run_c_to_ir_extraction(
    *,
    source_paths: list[Path],
    output_dir: Path,
    llm: LLMClient | None = None,
    protocol_name: str = "",
    goals: list[dict[str, Any]] | None = None,
    emit_prompts_only: bool = False,
    max_stage_retries: int = 1,
    emit_modeling_contract: bool = True,
    max_prompt_code_chars: int = 24000,
    max_stages: int | None = None,
    resume_existing: bool = False,
    rerun_from_stage: int | None = None,
) -> dict[str, Any]:
    if not source_paths:
        raise ValueError("At least one C source file is required.")
    store = ArtifactStore(output_dir)
    source_paths = [path.expanduser().resolve() for path in source_paths]
    code_context = build_c_code_context(source_paths)
    store.write_json("input/c_code_context.json", code_context)
    store.write_json("input/source_files.json", [str(path) for path in source_paths])
    facts: dict[str, Any] = {}
    stages = list(EXTRACTION_STAGES)
    if max_stages is not None and max_stages > 0:
        stages = stages[:max_stages]
    if emit_prompts_only:
        for stage in stages + [CRITIC_STAGE]:
            prompt = build_stage_prompt(
                stage,
                code_context,
                facts,
                protocol_name=protocol_name,
                goals=goals,
                max_prompt_code_chars=max_prompt_code_chars,
            )
            store.write_text(f"prompts/c_to_ir/{stage.stage_id}_{stage.title.replace(' ', '_').lower()}.txt", prompt)
        store.stage_record("c_to_ir_prompts_emitted", stages=[stage.stage_id for stage in stages])
        return {
            "status": "prompts_emitted",
            "output_dir": str(output_dir),
            "code_context": str(store.path("input/c_code_context.json")),
            "stages": [stage.stage_id for stage in stages],
        }
    if llm is None:
        raise RuntimeError("LLM client is required unless emit_prompts_only=True.")

    last_raw = ""
    for stage_index, stage in enumerate(stages, start=1):
        existing_path = store.path(f"history/c_to_ir/{stage.filename}")
        should_reuse = resume_existing and existing_path.exists()
        if rerun_from_stage is not None and stage_index >= rerun_from_stage:
            should_reuse = False
        if should_reuse:
            parsed = json.loads(existing_path.read_text(encoding="utf-8"))
            facts[stage.stage_id] = parsed
            store.stage_record("c_to_ir_stage_reused", extraction_stage=stage.stage_id, artifact=str(existing_path))
            continue
        if stage.stage_id == "10_protocol_ir":
            parsed = _assemble_protocol_ir_from_extraction_facts(facts, protocol_name=protocol_name)
            facts[stage.stage_id] = parsed
            store.write_json(f"history/c_to_ir/{stage.filename}", parsed)
            store.stage_record("c_to_ir_stage_deterministic_done", extraction_stage=stage.stage_id)
            continue
        prompt = build_stage_prompt(
            stage,
            code_context,
            facts,
            protocol_name=protocol_name,
            goals=goals,
            max_prompt_code_chars=max_prompt_code_chars,
        )
        prompt_path = store.write_text(f"prompts/c_to_ir/{stage.stage_id}_{stage.title.replace(' ', '_').lower()}.txt", prompt)
        parsed, raw = _complete_stage_json(
            llm,
            C_TO_IR_SYSTEM,
            prompt,
            store,
            stage,
            max_retries=max_stage_retries,
        )
        last_raw = raw
        facts[stage.stage_id] = parsed
        store.write_json(f"history/c_to_ir/{stage.filename}", parsed)
        store.stage_record("c_to_ir_stage_done", extraction_stage=stage.stage_id, prompt=str(prompt_path))

    if "10_protocol_ir" not in facts:
        store.stage_record("c_to_ir_partial_done", completed_stages=[stage.stage_id for stage in stages])
        return {
            "status": "partial_completed",
            "output_dir": str(output_dir),
            "completed_stages": [stage.stage_id for stage in stages],
            "next_stage": EXTRACTION_STAGES[len(stages)].stage_id if len(stages) < len(EXTRACTION_STAGES) else None,
            "last_response_chars": len(last_raw),
        }

    protocol_ir = facts.get("10_protocol_ir")
    if not isinstance(protocol_ir, dict):
        raise RuntimeError("Stage 10 did not produce a ProtocolIR JSON object.")
    case = _case_from_c_context(code_context, protocol_ir, protocol_name=protocol_name, goals=goals or [])
    proof_spec = case_goals_proof_spec(case) if case.goals else ProofSpec(
        case=case.name,
        mode="llm_discovered",
        source="c_to_ir_extraction",
        expectations=[],
        notes=["Claims were extracted from C code; generated claims become proof targets downstream."],
    )
    ir_bundle = build_protocol_ir_bundle(case, protocol_ir, proof_spec, include_open_questions=True)
    store.write_json("ir/protocol_ir.json", ir_bundle["protocol_ir"])
    store.write_json("ir/validation.json", ir_bundle["validation"])
    store.write_json("ir/proof_context.json", ir_bundle["proof_context"])
    store.write_json("ir/field_reviews.json", {"field_reviews": ir_bundle["field_reviews"]})
    if emit_modeling_contract:
        contract = build_modeling_contract(
            case,
            proof_spec,
            ir_bundle,
            plan=protocol_ir,
            source="c_to_ir",
            include_review_questions=True,
        )
        write_modeling_contract_artifacts(output_dir, contract)

    critic_prompt = build_stage_prompt(
        CRITIC_STAGE,
        code_context,
        {**facts, "assembled_protocol_ir": ir_bundle["protocol_ir"], "validation": ir_bundle["validation"]},
        protocol_name=case.name,
        goals=goals,
        max_prompt_code_chars=max_prompt_code_chars,
    )
    store.write_text("prompts/c_to_ir/11_critic_protocolir_critic.txt", critic_prompt)
    critic, _critic_raw = _complete_stage_json(
        llm,
        C_TO_IR_SYSTEM,
        critic_prompt,
        store,
        CRITIC_STAGE,
        max_retries=max_stage_retries,
    )
    store.write_json("history/c_to_ir/11_critic.json", critic)
    return {
        "status": "completed",
        "output_dir": str(output_dir),
        "protocol_ir": str(store.path("ir/protocol_ir.json")),
        "validation_ok": ir_bundle["validation"].get("ok"),
        "critic_blocking_issues": len(critic.get("blocking_issues", [])) if isinstance(critic, dict) else None,
        "last_response_chars": len(last_raw),
    }


def select_code_slices_for_stage(code_context: dict[str, Any], stage_id: str, *, max_chars: int = 24000) -> list[dict[str, Any]]:
    slices: list[dict[str, Any]] = []
    for file_entry in code_context.get("files", []):
        if not isinstance(file_entry, dict):
            continue
        path = str(file_entry.get("path") or "")
        if stage_id == "01_intent":
            for comment in file_entry.get("security_comments", [])[:24]:
                if isinstance(comment, dict):
                    slices.append(_slice_from_comment(path, comment, "security_comment"))
            for comment in file_entry.get("comments", [])[:8]:
                if isinstance(comment, dict):
                    slices.append(_slice_from_comment(path, comment, "top_comment"))
            continue
        if stage_id == "03_state":
            for typedef in file_entry.get("type_definitions", [])[:40]:
                slices.append(_simple_slice(path, typedef, "type_definition"))
        functions = [item for item in file_entry.get("functions", []) if isinstance(item, dict)]
        for func in functions:
            categories = set(func.get("categories") or _function_categories(func))
            name = str(func.get("name") or "").lower()
            include = False
            summary_only = False
            if stage_id == "02_functions":
                include = True
                summary_only = True
            elif stage_id == "04_environment":
                include = False
            elif stage_id == "05_crypto":
                include = "crypto" in categories
            elif stage_id == "06_messages":
                include = "buffer" in categories or any(token in name for token in ("send", "recv", "message", "msg", "cmd", "response", "request"))
            elif stage_id == "07_checks_events":
                include = any(token in name for token in ("check", "verify", "parse", "recv", "response", "decrypt", "validate", "accept"))
            elif stage_id == "08_lifecycle":
                include = "lifecycle" in categories
            elif stage_id in {"09_claims", "10_protocol_ir", "11_critic"}:
                include = False
            if include:
                slices.append(_function_summary_slice(path, func) if summary_only else _simple_slice(path, func, "function"))
    return _limit_slices(slices, max_chars=max_chars)


def _assemble_protocol_ir_from_extraction_facts(facts: dict[str, Any], *, protocol_name: str = "") -> dict[str, Any]:
    state = facts.get("03_state") if isinstance(facts.get("03_state"), dict) else {}
    environment = facts.get("04_environment") if isinstance(facts.get("04_environment"), dict) else {}
    crypto_facts = facts.get("05_crypto") if isinstance(facts.get("05_crypto"), dict) else {}
    message_facts = facts.get("06_messages") if isinstance(facts.get("06_messages"), dict) else {}
    check_facts = facts.get("07_checks_events") if isinstance(facts.get("07_checks_events"), dict) else {}
    lifecycle_facts = facts.get("08_lifecycle") if isinstance(facts.get("08_lifecycle"), dict) else {}
    claim_facts = facts.get("09_claims") if isinstance(facts.get("09_claims"), dict) else {}

    messages = _protocol_ir_messages_from_facts(message_facts)
    roles = _roles_from_messages(messages)
    fresh_terms = _fresh_terms_from_facts(state, crypto_facts)
    long_term_keys = _long_term_keys_from_facts(state)
    checks = _checks_from_facts(check_facts)
    events = _events_from_facts(check_facts)
    claims = _claims_from_facts(claim_facts)
    crypto = _crypto_from_facts(crypto_facts, environment)
    semantic_constraints = _semantic_constraints_from_facts(crypto_facts, lifecycle_facts, claim_facts)
    modeling_assumptions = _modeling_assumptions_from_facts(environment, crypto_facts)
    abstractions = _abstractions_from_facts(facts)
    open_questions = _open_questions_from_facts(facts)
    field_evidence = _field_evidence_from_facts(fresh_terms, long_term_keys, messages, checks, events, claims)

    return {
        "schema": "protocol_ir_pipeline_protocol_ir_v1",
        "protocol_name": protocol_name or "C_Derived_Protocol",
        "roles": roles,
        "principals": [{"name": role, "role_hint": role} for role in roles],
        "crypto": crypto,
        "fresh_terms": fresh_terms,
        "long_term_keys": long_term_keys,
        "messages": messages,
        "actions": _actions_from_messages(messages, checks, events),
        "checks": checks,
        "events": events,
        "claims": claims,
        "compromise": {"reveal_events": [], "policy": "No compromise/reveal behavior was extracted from the supplied C file."},
        "abstractions": abstractions,
        "modeling_assumptions": modeling_assumptions,
        "semantic_constraints": semantic_constraints,
        "field_evidence": field_evidence,
        "resolved_open_questions": [],
        "open_questions": open_questions,
    }


def _protocol_ir_messages_from_facts(message_facts: dict[str, Any]) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    for index, item in enumerate(message_facts.get("messages", []) if isinstance(message_facts, dict) else [], start=1):
        if not isinstance(item, dict):
            continue
        label = str(item.get("label") or item.get("name") or f"M{index}")
        term = str(item.get("term") or f"unknown_message_{index}()")
        protection = _message_protection_from_terms(label, term, item)
        messages.append(
            {
                "label": label,
                "step": index,
                "from": _role_name(item.get("from") or "unknown_sender"),
                "to": _role_name(item.get("to") or "unknown_receiver"),
                "term": term,
                "meaning": _truncate_text(_message_meaning(item), 220),
                "protection": protection,
                "sender_knows": _string_list(item.get("constructed_by")),
                "receiver_can_decrypt": None,
                "receiver_must_treat_as_opaque": [],
                "_evidence": item.get("evidence", []),
            }
        )
    return messages


def _message_meaning(item: dict[str, Any]) -> str:
    field_names = []
    for field in item.get("fields", []) if isinstance(item.get("fields"), list) else []:
        if isinstance(field, dict) and field.get("name"):
            field_names.append(str(field.get("name")))
    if field_names:
        return "Fields: " + ", ".join(field_names[:12])
    return str(item.get("meaning") or item.get("description") or "")


def _message_protection_from_terms(label: str, term: str, item: dict[str, Any]) -> str:
    field_text = " ".join(_string_list(item.get("protected_fields")) + _string_list(item.get("fields"))).lower()
    text = " ".join(
        [
            label,
            field_text,
        ]
    ).lower()
    if "hmac" in text or "mac" in text:
        return "mac"
    if "encryptedparameter" in field_text or "encrypted parameter" in field_text:
        return "symmetric-encryption"
    return "plain"


def _roles_from_messages(messages: list[dict[str, Any]]) -> list[str]:
    roles: list[str] = []
    for message in messages:
        for key in ("from", "to"):
            role = _role_name(message.get(key))
            if role and role not in roles:
                roles.append(role)
    return roles or ["host", "TPM"]


def _fresh_terms_from_facts(state: dict[str, Any], crypto_facts: dict[str, Any]) -> list[dict[str, str]]:
    fresh: list[dict[str, str]] = []
    for item in state.get("state_variables", []) if isinstance(state, dict) else []:
        if not isinstance(item, dict):
            continue
        classification = str(item.get("classification") or "")
        if classification not in {"fresh_public", "fresh_secret"}:
            continue
        name = str(item.get("ir_name") or item.get("c_name") or "").strip()
        if not name:
            continue
        fresh.append(
            {
                "name": name,
                "owner": _owner_for_term(name),
                "purpose": str(item.get("protocol_meaning") or classification),
            }
        )
    for op in crypto_facts.get("crypto_operations", []) if isinstance(crypto_facts, dict) else []:
        if not isinstance(op, dict) or str(op.get("kind")) != "random":
            continue
        name = str(op.get("output") or "").strip()
        if name and not any(item.get("name") == name for item in fresh):
            fresh.append({"name": name, "owner": _owner_for_term(name), "purpose": str(op.get("purpose") or "random value")})
    return fresh


def _long_term_keys_from_facts(state: dict[str, Any]) -> list[dict[str, str]]:
    keys: list[dict[str, str]] = []
    for item in state.get("state_variables", []) if isinstance(state, dict) else []:
        if not isinstance(item, dict):
            continue
        classification = str(item.get("classification") or "")
        if classification != "caller_secret_input":
            continue
        name = str(item.get("ir_name") or item.get("c_name") or "").strip()
        if name.lower().endswith("len") or name.lower().endswith("length"):
            continue
        if name:
            keys.append(
                {
                    "name": name,
                    "owner": "host",
                    "public_term": "",
                    "policy": str(item.get("protocol_meaning") or "Caller-supplied secret input."),
                }
            )
    return keys


def _checks_from_facts(check_facts: dict[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for item in check_facts.get("checks", []) if isinstance(check_facts, dict) else []:
        if not isinstance(item, dict):
            continue
        condition = str(item.get("condition") or "")
        if not condition:
            continue
        checks.append(
            {
                "check_id": str(item.get("name") or f"check_{len(checks) + 1}"),
                "role": _role_name(item.get("role") or _role_for_message(item.get("source_message"))),
                "condition": condition,
                "source_message": str(item.get("source_message") or ""),
                "proof_relevance": ", ".join(_string_list(item.get("protects"))),
                "_evidence": item.get("evidence", []),
            }
        )
    return checks


def _events_from_facts(check_facts: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for item in check_facts.get("events", []) if isinstance(check_facts, dict) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not name:
            continue
        events.append(
            {
                "name": name,
                "arguments": _string_list(item.get("arguments")),
                "role": _role_name(item.get("role") or "host"),
                "when": str(item.get("when") or ""),
                "proof_relevance": "trusted event extracted after C check/accept boundary",
                "_evidence": item.get("evidence", []),
            }
        )
    return events


def _claims_from_facts(claim_facts: dict[str, Any]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for item in claim_facts.get("claims", []) if isinstance(claim_facts, dict) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("lemma_name") or "")
        if not name:
            continue
        goal_type = str(item.get("goal_type") or "property")
        if goal_type in {"known_attack", "state_safety"}:
            goal_type = "property"
        required_events = item.get("required_events") or item.get("event_schema") or []
        claims.append(
            {
                "lemma_name": name,
                "claim_category": str(item.get("claim_category") or item.get("category") or ""),
                "goal_type": goal_type,
                "expected_state": str(item.get("expected_state") or "ProvedSatisfying"),
                "trace_kind": str(item.get("trace_kind") or "unknown"),
                "intent": str(item.get("intent") or ""),
                "required_events": required_events if isinstance(required_events, list) else _string_list(required_events),
                "event_schema": _string_list(required_events),
                "preserved_values": _string_list(item.get("preserved_values")),
                "holds_under": _string_list(item.get("holds_under")),
                "does_not_hold_under": _string_list(item.get("does_not_hold_under")),
                "anti_compression_note": str(item.get("anti_compression_note") or ""),
                "witness": str(item.get("witness") or ""),
                "expected_raw": str(item.get("expected_raw") or ""),
                "_evidence": item.get("evidence", []),
            }
        )
    return claims


def _crypto_from_facts(crypto_facts: dict[str, Any], environment: dict[str, Any]) -> dict[str, Any]:
    builtins: list[str] = []
    functions: list[str] = []
    equations: list[str] = []
    kind_to_builtin = {
        "hash": "hashing",
        "hmac": "hashing",
        "mac": "hashing",
        "kdf": "hashing",
        "encrypt": "symmetric-encryption",
        "decrypt": "symmetric-encryption",
        "dh": "diffie-hellman",
    }
    kind_to_function = {
        "hmac": "hmac/2",
        "mac": "mac/2",
        "kdf": "kdf/2",
        "verify": "verify/2",
        "encrypt": "aescfb_encrypt/3",
        "decrypt": "aescfb_decrypt/3",
        "dh": "dh/2",
    }
    for op in crypto_facts.get("crypto_operations", []) if isinstance(crypto_facts, dict) else []:
        if not isinstance(op, dict):
            continue
        kind = str(op.get("kind") or "unknown")
        if kind_to_builtin.get(kind) and kind_to_builtin[kind] not in builtins:
            builtins.append(kind_to_builtin[kind])
        if kind_to_function.get(kind) and kind_to_function[kind] not in functions:
            functions.append(kind_to_function[kind])
        output = str(op.get("output") or "")
        if output:
            equations.append(f"{output} = {kind}({', '.join(_string_list(op.get('inputs')))})")
    assumptions = _modeling_assumptions_from_facts(environment, crypto_facts)
    return {"builtins": builtins, "functions": functions, "equations": equations[:24], "assumptions": assumptions}


def _semantic_constraints_from_facts(
    crypto_facts: dict[str, Any],
    lifecycle_facts: dict[str, Any],
    claim_facts: dict[str, Any],
) -> list[dict[str, Any]]:
    constraints: list[dict[str, Any]] = []
    for op in crypto_facts.get("crypto_operations", []) if isinstance(crypto_facts, dict) else []:
        if not isinstance(op, dict):
            continue
        op_id = str(op.get("id") or f"crypto_{len(constraints) + 1}")
        constraints.append(
            {
                "id": f"crypto.{op_id}",
                "kind": "crypto_operation",
                "summary": str(op.get("purpose") or op_id),
                "constraint": f"{op.get('output')} = {op.get('kind')}({', '.join(_string_list(op.get('inputs')))})",
                "policy": f"Preserve crypto dependency: {op.get('output')} depends on {', '.join(_string_list(op.get('inputs')))}.",
                "evidence": _first_evidence_list(op),
                "confidence": "high",
            }
        )
    lifecycle = lifecycle_facts.get("lifecycle") if isinstance(lifecycle_facts.get("lifecycle"), dict) else {}
    for index, transition in enumerate(lifecycle.get("transitions", []) if isinstance(lifecycle, dict) else [], start=1):
        if not isinstance(transition, dict):
            continue
        constraints.append(
            {
                "id": f"lifecycle.transition_{index}",
                "kind": "lifecycle_transition",
                "summary": f"{transition.get('from')} -> {transition.get('to')} via {transition.get('trigger_function')}",
                "constraint": f"guard: {transition.get('guard')}; events: {', '.join(_string_list(transition.get('events')))}",
                "policy": f"Preserve lifecycle transition {transition.get('from')} -> {transition.get('to')} under guard {transition.get('guard')}.",
                "evidence": _first_evidence_list(transition),
                "confidence": "medium",
            }
        )
    for rejected in claim_facts.get("rejected_claims", []) if isinstance(claim_facts, dict) else []:
        if not isinstance(rejected, dict):
            continue
        constraints.append(
            {
                "id": f"rejected_claim.{rejected.get('lemma_name') or len(constraints) + 1}",
                "kind": "rejected_claim",
                "summary": str(rejected.get("intent") or "Rejected claim"),
                "constraint": str(rejected.get("reason") or "This claim is not supported by the supplied C evidence."),
                "policy": str(rejected.get("reason") or "Do not turn this unsupported claim into a proof target."),
                "evidence": _first_evidence_list(rejected),
                "confidence": "high",
            }
        )
    return constraints[:40]


def _modeling_assumptions_from_facts(environment: dict[str, Any], crypto_facts: dict[str, Any]) -> list[str]:
    assumptions: list[str] = []
    for item in environment.get("external_interfaces", []) if isinstance(environment, dict) else []:
        if isinstance(item, dict) and item.get("protocol_assumption"):
            assumptions.append(str(item.get("protocol_assumption")))
    for item in environment.get("modeling_assumptions", []) if isinstance(environment, dict) else []:
        if isinstance(item, dict):
            assumptions.append(str(item.get("assumption") or item.get("summary") or item.get("description") or ""))
        else:
            assumptions.append(str(item))
    for item in crypto_facts.get("dropped_details", []) if isinstance(crypto_facts, dict) else []:
        if isinstance(item, dict):
            assumptions.append("Crypto detail abstracted: " + str(item.get("detail") or item.get("reason") or item))
    return _dedupe_texts([item for item in assumptions if item.strip()])[:20]


def _abstractions_from_facts(facts: dict[str, Any]) -> list[str]:
    abstractions: list[str] = []
    for stage_id in ("01_intent", "05_crypto", "06_messages"):
        stage = facts.get(stage_id) if isinstance(facts.get(stage_id), dict) else {}
        for key in ("out_of_scope", "dropped_details", "abstractions"):
            for item in stage.get(key, []) if isinstance(stage, dict) else []:
                if isinstance(item, dict):
                    text = item.get("summary") or item.get("item") or item.get("detail") or item.get("reason") or item.get("description")
                else:
                    text = item
                if text:
                    abstractions.append(str(text))
    return _dedupe_texts(abstractions)[:20]


def _open_questions_from_facts(facts: dict[str, Any]) -> list[str]:
    questions: list[str] = []
    for stage_id, stage in facts.items():
        if not isinstance(stage, dict):
            continue
        for item in stage.get("open_questions", []):
            if isinstance(item, dict):
                text = item.get("question") or item.get("summary") or item.get("id")
            else:
                text = item
            if text:
                questions.append(f"{stage_id}: {text}")
    return _dedupe_texts(questions)[:30]


def _actions_from_messages(messages: list[dict[str, Any]], checks: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    checks_by_message: dict[str, list[str]] = {}
    for check in checks:
        source = str(check.get("source_message") or "")
        if source:
            checks_by_message.setdefault(source, []).append(str(check.get("check_id") or check.get("condition")))
    events_by_role: dict[str, list[str]] = {}
    for event in events:
        role = _role_name(event.get("role"))
        events_by_role.setdefault(role, []).append(str(event.get("name")))
    for message in messages:
        label = str(message.get("label") or "")
        sender = _role_name(message.get("from"))
        receiver = _role_name(message.get("to"))
        actions.append(
            {
                "action_id": f"send_{label}",
                "role": sender,
                "kind": "send",
                "generates": [],
                "message_in": [],
                "message_out": [label],
                "checks": [],
                "events": events_by_role.get(sender, [])[:4],
            }
        )
        if checks_by_message.get(label):
            actions.append(
                {
                    "action_id": f"receive_check_{label}",
                    "role": receiver,
                    "kind": "receive_check",
                    "generates": [],
                    "message_in": [label],
                    "message_out": [],
                    "checks": checks_by_message[label],
                    "events": events_by_role.get(receiver, [])[:4],
                }
            )
    return actions[:16]


def _field_evidence_from_facts(
    fresh_terms: list[dict[str, Any]],
    long_term_keys: list[dict[str, Any]],
    messages: list[dict[str, Any]],
    checks: list[dict[str, Any]],
    events: list[dict[str, Any]],
    claims: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    groups = (
        ("fresh_terms", fresh_terms, "fresh/session value extracted from C state or crypto facts"),
        ("long_term_keys", long_term_keys, "long-term/setup value extracted from C state facts"),
        ("messages", messages, "message field extracted from C buffer construction/parsing"),
        ("checks", checks, "check field extracted from C branch/comparison"),
        ("events", events, "trusted event field extracted from accept/check boundary"),
        ("claims", claims, "claim field extracted from security intent and checks"),
    )
    for section, items, reason in groups:
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            raw_evidence = item.get("_evidence")
            for key, value in item.items():
                if str(key).startswith("_") or value in (None, "", [], {}):
                    continue
                evidence.extend(_field_evidence_entries(f"{section}.{index}.{key}", raw_evidence, reason))
    return evidence


def _field_evidence_entries(field_path: str, raw_evidence: Any, reason: str) -> list[dict[str, Any]]:
    item = _first_evidence(raw_evidence)
    quote = ""
    if item:
        quote = f"{item.get('file')}:{item.get('line_start')}-{item.get('line_end')} {item.get('reason')}"
    return [
        {
            "field_path": field_path,
            "source_quote": _truncate_text(quote, 260),
            "evidence_kind": "direct" if item else "none",
            "reason": reason,
            "evidence_confidence_score": 0.85 if item else 0.2,
            "consistency_confidence_score": 0.75,
            "semantic_impact_score": 0.8,
            "priority_llm": 0.5,
        }
    ]


def _first_evidence_list(item: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = _first_evidence(item.get("evidence"))
    return [evidence] if evidence else []


def _first_evidence(raw_evidence: Any) -> dict[str, Any] | None:
    if isinstance(raw_evidence, list):
        for item in raw_evidence:
            if isinstance(item, dict):
                return item
    return None


def _role_name(value: Any) -> str:
    raw = str(value or "").strip()
    if raw.lower() == "tpm":
        return "TPM"
    if raw.lower() == "host":
        return "host"
    if not raw:
        return ""
    return re.sub(r"[^A-Za-z0-9_]", "_", raw)


def _role_for_message(label: Any) -> str:
    text = str(label or "").lower()
    if "response" in text:
        return "host"
    if "request" in text or "command" in text:
        return "TPM"
    return "host"


def _owner_for_term(name: str) -> str:
    lowered = name.lower()
    if lowered.startswith("tpm") or "tpm" in lowered:
        return "TPM"
    return "host"


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        result = []
        for item in value:
            if isinstance(item, dict):
                text = item.get("name") or item.get("term") or item.get("value") or item.get("id") or item.get("label") or item.get("summary")
            else:
                text = item
            if text not in (None, ""):
                result.append(str(text))
        return result
    if isinstance(value, dict):
        text = value.get("name") or value.get("term") or value.get("value") or value.get("id") or value.get("summary")
        return [str(text)] if text else []
    return [str(value)] if str(value) else []


def _dedupe_texts(items: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _complete_stage_json(
    llm: LLMClient,
    system: str,
    prompt: str,
    store: ArtifactStore,
    stage: CToIRStage,
    *,
    max_retries: int,
) -> tuple[dict[str, Any], str]:
    current_prompt = prompt
    raw = ""
    max_attempts = max(1, 1 + max_retries)
    for attempt in range(1, max_attempts + 1):
        parsed, raw = llm.complete_json_or_text(system, current_prompt)
        store.write_text(f"history/c_to_ir/{stage.stage_id}_attempt_{attempt}.raw.txt", raw or "")
        store.append_jsonl(
            "history/llm_calls.jsonl",
            llm_call_record(
                llm,
                stage=f"c_to_ir_{stage.stage_id}",
                system=system,
                prompt=current_prompt,
                attempt=attempt,
                parsed_json=parsed is not None,
                extra={"stage_title": stage.title, "response_chars_recorded": len(raw or "")},
            ),
        )
        if parsed is not None:
            return parsed, raw
        if attempt < max_attempts:
            current_prompt = build_json_retry_prompt(current_prompt, raw, "Response was not parseable JSON.")
            store.write_text(f"prompts/c_to_ir/{stage.stage_id}_retry_{attempt}.txt", current_prompt)
            system = JSON_RETRY_SYSTEM
    raise RuntimeError(f"C-to-IR stage {stage.stage_id} did not return parseable JSON after {max_attempts} attempt(s).")


def _mask_comments_and_strings(text: str, file_path: str) -> tuple[str, list[dict[str, Any]]]:
    chars = list(text)
    starts = _line_starts(text)
    comments: list[dict[str, Any]] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            start = i
            i += 2
            while i < n and text[i] != "\n":
                i += 1
            end = i
            comments.append(_comment_record(text, starts, file_path, start, end, "line"))
            _blank_non_newline(chars, start, end)
            continue
        if ch == "/" and nxt == "*":
            start = i
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i = min(n, i + 2)
            end = i
            comments.append(_comment_record(text, starts, file_path, start, end, "block"))
            _blank_non_newline(chars, start, end)
            continue
        if ch in {"'", '"'}:
            quote = ch
            start = i
            i += 1
            escaped = False
            while i < n:
                current = text[i]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    i += 1
                    break
                elif current == "\n" and quote == "'":
                    break
                i += 1
            _blank_non_newline(chars, start, i)
            continue
        i += 1
    return "".join(chars), comments


def _extract_includes(text: str, starts: list[int], file_path: str) -> list[dict[str, Any]]:
    includes: list[dict[str, Any]] = []
    for match in re.finditer(r'(?m)^\s*#\s*include\s+(?:"([^"]+)"|<([^>]+)>)', text):
        local = match.group(1)
        system = match.group(2)
        includes.append(
            {
                "file": file_path,
                "line": _offset_to_line(starts, match.start()),
                "target": local or system or "",
                "kind": "local" if local else "system",
            }
        )
    return includes


def _extract_functions(
    text: str,
    masked: str,
    starts: list[int],
    file_path: str,
    *,
    max_excerpt_chars: int,
) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    seen_starts: set[int] = set()
    for brace in [match.start() for match in re.finditer(r"\{", masked)]:
        j = brace - 1
        while j >= 0 and masked[j].isspace():
            j -= 1
        if j < 0 or masked[j] != ")":
            continue
        open_paren = _find_matching_left(masked, j, "(", ")")
        if open_paren < 0:
            continue
        name_end = open_paren
        k = name_end - 1
        while k >= 0 and masked[k].isspace():
            k -= 1
        name_stop = k + 1
        while k >= 0 and (masked[k].isalnum() or masked[k] == "_"):
            k -= 1
        name = masked[k + 1 : name_stop]
        if not name or name in CONTROL_KEYWORDS:
            continue
        sig_start = _signature_start(masked, k + 1)
        if sig_start in seen_starts:
            continue
        body_end = _find_matching_right(masked, brace, "{", "}")
        if body_end < 0:
            continue
        seen_starts.add(sig_start)
        signature = " ".join(text[sig_start:brace].strip().split())
        body = text[brace : body_end + 1]
        excerpt = _balanced_excerpt(body, max_excerpt_chars)
        cleanup_labels = _extract_cleanup_labels(body, brace, starts, file_path)
        func = {
            "name": name,
            "file": file_path,
            "line_start": _offset_to_line(starts, sig_start),
            "line_end": _offset_to_line(starts, body_end),
            "signature": signature,
            "body_excerpt": excerpt,
            "cleanup_labels": cleanup_labels,
            "calls": [],
            "external_calls": [],
        }
        func["categories"] = _function_categories(func)
        functions.append(func)
    return sorted(functions, key=lambda item: item["line_start"])


def _balanced_excerpt(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 1200:
        return text[:max_chars] + "\n/* ... truncated ... */"
    head_chars = max_chars // 2
    tail_chars = max_chars - head_chars
    return text[:head_chars] + "\n/* ... middle truncated ... */\n" + text[-tail_chars:]


def _extract_cleanup_labels(body: str, body_offset: int, starts: list[int], file_path: str) -> list[dict[str, Any]]:
    labels: list[dict[str, Any]] = []
    pattern = re.compile(r"(?m)^\s*(out|err\w*|error|cleanup)\s*:")
    matches = list(pattern.finditer(body))
    for index, match in enumerate(matches[:8]):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        snippet = body[start:end]
        labels.append(
            {
                "file": file_path,
                "label": match.group(1),
                "line_start": _offset_to_line(starts, body_offset + start),
                "line_end": _offset_to_line(starts, body_offset + max(start, end - 1)),
                "text": _truncate_text(snippet, 1800),
            }
        )
    return labels


def _extract_type_definitions(text: str, masked: str, starts: list[int], file_path: str) -> list[dict[str, Any]]:
    definitions: list[dict[str, Any]] = []
    pattern = re.compile(r"\b(?:typedef\s+)?(struct|union|enum)(?:\s+([A-Za-z_]\w*))?\s*\{")
    for match in pattern.finditer(masked):
        brace = masked.find("{", match.start(), match.end())
        end_brace = _find_matching_right(masked, brace, "{", "}")
        if end_brace < 0:
            continue
        semi = masked.find(";", end_brace)
        end = semi + 1 if semi >= 0 else end_brace + 1
        trailer = masked[end_brace + 1 : end].strip(" ;\t\r\n")
        if match.group(2):
            name = match.group(2) or ""
        elif trailer:
            name = trailer.split(",")[0].strip().split()[0]
        else:
            name = ""
        source = text[match.start() : end]
        definitions.append(
            {
                "kind": match.group(1),
                "name": name or "anonymous",
                "file": file_path,
                "line_start": _offset_to_line(starts, match.start()),
                "line_end": _offset_to_line(starts, end),
                "source_excerpt": source[:4000] + ("\n/* ... truncated ... */" if len(source) > 4000 else ""),
                "field_names": _extract_field_names(source),
            }
        )
    return definitions


def _extract_calls(
    text: str,
    masked: str,
    starts: list[int],
    file_path: str,
    functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    line_to_function: list[tuple[int, int, str]] = [
        (int(func["line_start"]), int(func["line_end"]), str(func["name"])) for func in functions
    ]
    calls: list[dict[str, Any]] = []
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", masked):
        name = match.group(1)
        if name in CALL_EXCLUDE:
            continue
        line = _offset_to_line(starts, match.start())
        enclosing = ""
        for start, end, func_name in line_to_function:
            if start <= line <= end:
                enclosing = func_name
                break
        calls.append(
            {
                "name": name,
                "file": file_path,
                "line": line,
                "enclosing_function": enclosing,
                "categories": sorted(_call_categories(name)),
            }
        )
    return calls


def _extract_field_accesses(
    text: str,
    masked: str,
    starts: list[int],
    file_path: str,
    functions: list[dict[str, Any]],
    typedefs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    field_names = sorted(
        {
            str(field)
            for typedef in typedefs
            for field in typedef.get("field_names", [])
            if isinstance(field, str) and field
        }
    )
    if not field_names:
        return []
    line_to_function: list[tuple[int, int, str]] = [
        (int(func["line_start"]), int(func["line_end"]), str(func["name"])) for func in functions
    ]
    by_field: dict[str, dict[str, Any]] = {}
    for field in field_names:
        pattern = re.compile(rf"(?:->|\.)\s*{re.escape(field)}\b")
        for match in pattern.finditer(masked):
            line = _offset_to_line(starts, match.start())
            enclosing = ""
            for start, end, func_name in line_to_function:
                if start <= line <= end:
                    enclosing = func_name
                    break
            line_text = _source_line(text, starts, line)
            window_text = _source_window(text, starts, line, before=2, after=2)
            kind = _field_access_kind(masked, match.end(), line_text, window_text, field)
            entry = by_field.setdefault(
                field,
                {
                    "field": field,
                    "file": file_path,
                    "read_count": 0,
                    "write_count": 0,
                    "functions": [],
                    "examples": [],
                },
            )
            if kind == "write":
                entry["write_count"] += 1
            else:
                entry["read_count"] += 1
            if enclosing and enclosing not in entry["functions"]:
                entry["functions"].append(enclosing)
            if len(entry["examples"]) < 8:
                entry["examples"].append(
                    {
                        "line": line,
                        "function": enclosing,
                        "kind": kind,
                        "source": _truncate_text(window_text.strip(), 520),
                    }
                )
    return sorted(by_field.values(), key=lambda item: item["field"])


def _extract_crypto_transcripts(
    text: str,
    starts: list[int],
    file_path: str,
    functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    transcripts: list[dict[str, Any]] = []
    for func in functions:
        function_name = str(func.get("name") or "")
        line_start = int(func.get("line_start") or 1)
        line_end = int(func.get("line_end") or line_start)
        source = _source_window(text, starts, line_start, before=0, after=max(0, line_end - line_start))
        current: dict[str, Any] | None = None
        for statement in _c_statements(source, line_start):
            stmt = statement["text"]
            line = statement["line_start"]
            if "hmac_sha256_init" in stmt:
                if current:
                    transcripts.append(current)
                args = _call_args(stmt, "hmac_sha256_init_usingrawkey") or _call_args(stmt, "hmac_sha256_init")
                current = {
                    "kind": "hmac",
                    "function": function_name,
                    "file": file_path,
                    "line_start": line,
                    "line_end": statement["line_end"],
                    "init": _truncate_text(stmt, 260),
                    "key_arguments": args[1:] if len(args) > 1 else args,
                    "updates": [],
                    "final": "",
                }
                continue
            if "sha256_init" in stmt and "hmac_" not in stmt:
                if current:
                    transcripts.append(current)
                current = {
                    "kind": "hash",
                    "function": function_name,
                    "file": file_path,
                    "line_start": line,
                    "line_end": statement["line_end"],
                    "init": _truncate_text(stmt, 260),
                    "updates": [],
                    "final": "",
                }
                continue
            if current and ("hmac_sha256_update" in stmt or ("sha256_update" in stmt and "hmac_" not in stmt)):
                call_name = "hmac_sha256_update" if "hmac_sha256_update" in stmt else "sha256_update"
                args = _call_args(stmt, call_name)
                current["updates"].append(
                    {
                        "line": line,
                        "argument": _truncate_text(args[1] if len(args) > 1 else "", 180),
                        "size": _truncate_text(args[2] if len(args) > 2 else "", 120),
                        "statement": _truncate_text(stmt, 260),
                    }
                )
                current["line_end"] = statement["line_end"]
                continue
            if current and ("hmac_sha256_final" in stmt or ("sha256_final" in stmt and "hmac_" not in stmt)):
                current["final"] = _truncate_text(stmt, 260)
                current["line_end"] = statement["line_end"]
                transcripts.append(current)
                current = None
        if current:
            transcripts.append(current)
    return transcripts


def _c_statements(source: str, start_line: int) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    buffer: list[str] = []
    statement_start = start_line
    for offset, raw_line in enumerate(source.splitlines(), start=0):
        line_no = start_line + offset
        stripped = raw_line.strip()
        if not buffer and stripped:
            statement_start = line_no
        buffer.append(raw_line)
        if ";" in raw_line:
            text = " ".join(part.strip() for part in buffer if part.strip())
            statements.append({"line_start": statement_start, "line_end": line_no, "text": text})
            buffer = []
    if buffer:
        text = " ".join(part.strip() for part in buffer if part.strip())
        if text:
            statements.append({"line_start": statement_start, "line_end": start_line + len(source.splitlines()) - 1, "text": text})
    return statements


def _call_args(statement: str, function_name: str) -> list[str]:
    start = statement.find(f"{function_name}(")
    if start < 0:
        return []
    arg_start = start + len(function_name) + 1
    depth = 0
    end = -1
    for index in range(arg_start, len(statement)):
        ch = statement[index]
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                end = index
                break
            depth -= 1
    if end < 0:
        return []
    args_text = statement[arg_start:end]
    return [_truncate_text(arg.strip(), 220) for arg in _split_top_level_commas(args_text)]


def _split_top_level_commas(text: str) -> list[str]:
    args: list[str] = []
    depth = 0
    start = 0
    for index, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            args.append(text[start:index])
            start = index + 1
    args.append(text[start:])
    return args


def _attach_calls_to_functions(functions: list[dict[str, Any]], calls: list[dict[str, Any]]) -> None:
    by_function: dict[str, list[dict[str, Any]]] = {}
    for call in calls:
        enclosing = str(call.get("enclosing_function") or "")
        if enclosing:
            by_function.setdefault(enclosing, []).append(call)
    known = {func["name"] for func in functions}
    for func in functions:
        local_calls = by_function.get(func["name"], [])
        func["calls"] = sorted({call["name"] for call in local_calls if call["name"] != func["name"]})
        func["external_calls"] = sorted({call["name"] for call in local_calls if call["name"] not in known and call["name"] not in CALL_EXCLUDE})
        func["categories"] = _function_categories(func)


def _function_categories(func: dict[str, Any]) -> list[str]:
    text = " ".join(
        [
            str(func.get("name") or ""),
            str(func.get("signature") or ""),
            " ".join(str(item) for item in func.get("calls", []) or []),
            " ".join(str(item) for item in func.get("external_calls", []) or []),
        ]
    ).lower()
    categories: set[str] = set()
    if any(token in text for token in CRYPTO_CALL_KEYWORDS):
        categories.add("crypto")
    if any(token in text for token in BUFFER_CALL_KEYWORDS):
        categories.add("buffer")
    if any(token in text for token in LIFECYCLE_KEYWORDS):
        categories.add("lifecycle")
    if any(token in text for token in ("check", "verify", "validate", "compare", "memcmp", "return -", "error")):
        categories.add("check")
    return sorted(categories)


def _call_categories(name: str) -> set[str]:
    lowered = name.lower()
    categories: set[str] = set()
    if any(token in lowered for token in CRYPTO_CALL_KEYWORDS):
        categories.add("crypto")
    if any(token in lowered for token in BUFFER_CALL_KEYWORDS):
        categories.add("buffer")
    if any(token in lowered for token in LIFECYCLE_KEYWORDS):
        categories.add("lifecycle")
    return categories


def _security_comments(comments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for comment in comments:
        text = str(comment.get("text") or "").lower()
        if any(keyword in text for keyword in SECURITY_KEYWORDS):
            result.append(comment)
    return result[:80]


def _comment_record(text: str, starts: list[int], file_path: str, start: int, end: int, kind: str) -> dict[str, Any]:
    raw = text[start:end]
    return {
        "file": file_path,
        "line_start": _offset_to_line(starts, start),
        "line_end": _offset_to_line(starts, max(start, end - 1)),
        "kind": kind,
        "text": raw[:3000] + ("\n/* ... truncated ... */" if len(raw) > 3000 else ""),
    }


def _slice_from_comment(path: str, comment: dict[str, Any], kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "file": path,
        "line_start": comment.get("line_start"),
        "line_end": comment.get("line_end"),
        "text": comment.get("text", ""),
    }


def _simple_slice(path: str, item: dict[str, Any], kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "file": path,
        "name": item.get("name"),
        "line_start": item.get("line_start"),
        "line_end": item.get("line_end"),
        "signature": item.get("signature"),
        "categories": item.get("categories", []),
        "calls": item.get("calls", []),
        "external_calls": item.get("external_calls", []),
        "cleanup_labels": item.get("cleanup_labels", []),
        "text": item.get("body_excerpt") or item.get("source_excerpt") or "",
    }


def _function_summary_slice(path: str, item: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "name": item.get("name"),
        "signature": _truncate_text(str(item.get("signature") or ""), 260),
        "line_start": item.get("line_start"),
        "line_end": item.get("line_end"),
        "categories": item.get("categories", []),
        "calls": _truncate_list(item.get("calls", []), 18),
        "external_calls": _truncate_list(item.get("external_calls", []), 18),
    }
    return {
        "kind": "function_summary",
        "file": path,
        "name": item.get("name"),
        "line_start": item.get("line_start"),
        "line_end": item.get("line_end"),
        "text": _prompt_json(summary),
    }


def _limit_slices(slices: list[dict[str, Any]], *, max_chars: int) -> list[dict[str, Any]]:
    limited: list[dict[str, Any]] = []
    used = 0
    for item in slices:
        text = str(item.get("text") or "")
        if not text:
            continue
        remaining = max_chars - used
        if remaining <= 0:
            break
        copied = dict(item)
        if len(text) > remaining:
            copied["text"] = text[: max(0, remaining)] + "\n/* ... prompt budget truncated ... */"
        limited.append(copied)
        used += len(str(copied.get("text") or ""))
    return limited


def _compact_context_for_prompt(code_context: dict[str, Any], stage_id: str = "") -> dict[str, Any]:
    context = {
        "schema": code_context.get("schema"),
        "source_files": code_context.get("source_files", []),
        "function_index": [_compact_function_index_item(item) for item in code_context.get("function_index", [])[:120]],
        "missing_includes": code_context.get("missing_includes", []),
    }
    if stage_id in {"03_state", "10_protocol_ir", "11_critic"}:
        context["type_definitions"] = [
            {
                "file": type_def.get("file"),
                "kind": type_def.get("kind"),
                "name": type_def.get("name"),
                "line_start": type_def.get("line_start"),
                "line_end": type_def.get("line_end"),
                "field_names": type_def.get("field_names", []),
            }
            for file_entry in code_context.get("files", [])
            if isinstance(file_entry, dict)
            for type_def in file_entry.get("type_definitions", [])
            if isinstance(type_def, dict)
        ][:80]
        context["field_accesses"] = [_compact_field_access(item) for item in code_context.get("field_accesses", [])[:120]]
    if stage_id in {"04_environment", "10_protocol_ir", "11_critic"}:
        context["external_calls"] = [_compact_call_item(item) for item in code_context.get("external_calls", [])[:30]]
    if stage_id in {"04_environment", "05_crypto", "07_checks_events", "10_protocol_ir", "11_critic"}:
        context["crypto_calls"] = [_compact_call_item(item) for item in code_context.get("crypto_calls", [])[:20]]
    if stage_id in {"05_crypto", "07_checks_events", "10_protocol_ir", "11_critic"}:
        context["crypto_transcript_hints"] = [_compact_crypto_transcript(item) for item in code_context.get("crypto_transcript_hints", [])[:40]]
    if stage_id in {"04_environment", "06_messages", "07_checks_events", "10_protocol_ir", "11_critic"}:
        context["buffer_calls"] = [_compact_call_item(item) for item in code_context.get("buffer_calls", [])[:20]]
    if stage_id in {"09_claims", "10_protocol_ir", "11_critic"}:
        context["note"] = "This late stage should rely primarily on previous_extraction_facts; deterministic context is only an index for provenance checks."
    return context


def _compact_function_index_item(item: dict[str, Any]) -> dict[str, Any]:
    compact = {
        "name": item.get("name"),
        "file": item.get("file"),
        "line_start": item.get("line_start"),
        "line_end": item.get("line_end"),
        "signature": _truncate_text(str(item.get("signature") or ""), 260),
        "calls": _truncate_list(item.get("calls", []), 16),
        "categories": item.get("categories", []),
    }
    cleanup_labels = item.get("cleanup_labels")
    if cleanup_labels:
        compact["cleanup_labels"] = [
            {
                "label": label.get("label"),
                "line_start": label.get("line_start"),
                "line_end": label.get("line_end"),
                "text": _truncate_text(str(label.get("text") or ""), 900),
            }
            for label in cleanup_labels[:4]
            if isinstance(label, dict)
        ]
    return compact


def _compact_call_item(item: dict[str, Any]) -> dict[str, Any]:
    call_sites = item.get("call_sites", [])
    enclosing_functions = []
    lines = []
    for site in call_sites[:6] if isinstance(call_sites, list) else []:
        if not isinstance(site, dict):
            continue
        func = site.get("enclosing_function")
        line = site.get("line")
        if func and func not in enclosing_functions:
            enclosing_functions.append(func)
        if line is not None:
            lines.append(line)
    return {
        "name": item.get("name"),
        "categories": item.get("categories", []),
        "call_site_count": len(call_sites) if isinstance(call_sites, list) else 0,
        "enclosing_functions": enclosing_functions[:6],
        "lines": lines[:6],
    }


def _compact_field_access(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "field": item.get("field"),
        "file": item.get("file"),
        "read_count": item.get("read_count", 0),
        "write_count": item.get("write_count", 0),
        "functions": _truncate_list(item.get("functions", []), 10),
        "examples": _truncate_list(item.get("examples", []), 5),
    }


def _compact_crypto_transcript(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": item.get("kind"),
        "function": item.get("function"),
        "file": item.get("file"),
        "line_start": item.get("line_start"),
        "line_end": item.get("line_end"),
        "key_arguments": item.get("key_arguments", []),
        "updates": item.get("updates", []),
        "final": item.get("final"),
    }


def _truncate_list(value: Any, limit: int) -> list[Any]:
    if not isinstance(value, list):
        return []
    result = value[:limit]
    if len(value) > limit:
        result.append(f"... {len(value) - limit} more")
    return result


def _truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _case_from_c_context(
    code_context: dict[str, Any],
    protocol_ir: dict[str, Any],
    *,
    protocol_name: str,
    goals: list[dict[str, Any]],
) -> ProtocolCase:
    name = protocol_name or str(protocol_ir.get("protocol_name") or "C_Protocol")
    description = (
        "ProtocolIR extracted from C source files by the staged C-to-IR LLM pipeline.\n\n"
        f"Source files: {', '.join(str(path) for path in code_context.get('source_files', []))}\n"
        "Use field_evidence, modeling_assumptions, and open_questions to review code provenance."
    )
    return ProtocolCase(
        name=name,
        description=description,
        goals=goals,
        assumptions=[],
        notes="Generated from C source through staged extraction; not a direct C correctness proof.",
        difficulty="hard",
        source_files={Path(str(path)).name: str(path) for path in code_context.get("source_files", [])},
    )


def _extract_field_names(source: str) -> list[str]:
    field_names: list[str] = []
    body_match = re.search(r"\{(.*)\}", source, flags=re.S)
    if not body_match:
        return field_names
    for raw_line in body_match.group(1).splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line or line.startswith("#") or line in {"public:", "private:", "protected:"}:
            continue
        if ";" not in line or "(" in line:
            continue
        before_semicolon = line.split(";", 1)[0]
        for part in before_semicolon.split(","):
            match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^]]*\])?\s*$", part.strip())
            if match:
                field_names.append(match.group(1))
    return list(dict.fromkeys(field_names))


def _source_line(text: str, starts: list[int], line: int) -> str:
    if line <= 0 or line > len(starts):
        return ""
    start = starts[line - 1]
    end = starts[line] - 1 if line < len(starts) else len(text)
    return text[start:end]


def _source_window(text: str, starts: list[int], line: int, *, before: int, after: int) -> str:
    start_line = max(1, line - before)
    end_line = min(len(starts), line + after)
    start = starts[start_line - 1]
    end = starts[end_line] - 1 if end_line < len(starts) else len(text)
    return text[start:end]


def _field_access_kind(masked: str, end_offset: int, line_text: str, window_text: str, field: str) -> str:
    if _field_is_first_call_arg(line_text, field, {"memcpy", "memset", "memmove", "get_random_bytes", "aes_prepareenckey"}):
        return "write"
    if _field_is_last_call_arg(window_text, field, {"tpm2_KDFa", "tpm2_KDFe", "KDFa", "KDFe"}):
        return "write"
    tail = masked[end_offset : min(len(masked), end_offset + 16)]
    if re.match(r"\s*(?:\+\+|--|\+=|-=|\*=|/=|%=|\|=|&=|\^=|=(?!=))", tail):
        return "write"
    return "read"


def _field_is_first_call_arg(line_text: str, field: str, function_names: set[str]) -> bool:
    compact = " ".join(line_text.strip().split())
    access_patterns = (f"->{field}", f".{field}")
    for function_name in function_names:
        prefix = f"{function_name}("
        start = compact.find(prefix)
        if start < 0:
            continue
        args = compact[start + len(prefix) :]
        first_arg = args.split(",", 1)[0]
        if any(pattern in first_arg for pattern in access_patterns):
            return True
    return False


def _field_is_last_call_arg(text: str, field: str, function_names: set[str]) -> bool:
    compact = " ".join(text.strip().split())
    access_patterns = (f"->{field}", f".{field}")
    for function_name in function_names:
        prefix = f"{function_name}("
        start = compact.find(prefix)
        if start < 0:
            continue
        end = compact.find(");", start)
        if end < 0:
            end = compact.find(")", start)
        if end < 0:
            continue
        args = compact[start + len(prefix) : end]
        last_arg = args.rsplit(",", 1)[-1]
        if any(pattern in last_arg for pattern in access_patterns):
            return True
    return False


def _line_starts(text: str) -> list[int]:
    return [0] + [index + 1 for index, char in enumerate(text) if char == "\n"]


def _offset_to_line(starts: list[int], offset: int) -> int:
    return bisect.bisect_right(starts, max(0, offset))


def _blank_non_newline(chars: list[str], start: int, end: int) -> None:
    for index in range(start, min(end, len(chars))):
        if chars[index] != "\n":
            chars[index] = " "


def _find_matching_left(text: str, close_index: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    for index in range(close_index, -1, -1):
        ch = text[index]
        if ch == close_ch:
            depth += 1
        elif ch == open_ch:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _find_matching_right(text: str, open_index: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        ch = text[index]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _signature_start(masked: str, name_start: int) -> int:
    line_start = masked.rfind("\n", 0, name_start) + 1
    previous_semicolon = masked.rfind(";", 0, name_start)
    previous_close = masked.rfind("}", 0, name_start)
    boundary = max(previous_semicolon, previous_close)
    if boundary >= 0 and boundary + 1 > line_start:
        return boundary + 1
    # Include common multi-line return attributes without swallowing preceding declarations.
    previous_blank = masked.rfind("\n\n", 0, name_start)
    if previous_blank >= 0 and previous_blank + 2 < line_start:
        return previous_blank + 2
    return line_start


def _prompt_json(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)
