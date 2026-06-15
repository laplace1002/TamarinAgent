from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .cases import ProtocolCase
from .proofspec import PROVED_SATISFYING, ProofSpec, infer_goal_type


@dataclass
class IRValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)
    repair_target: str = "ProtocolIR"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_protocol_ir_bundle(
    case: ProtocolCase,
    plan: dict[str, Any],
    proof_spec: ProofSpec,
    *,
    include_open_questions: bool = False,
    include_semantic_review_questions: bool = False,
) -> dict[str, Any]:
    protocol_ir = normalize_protocol_ir(
        case,
        plan,
        proof_spec,
        include_open_questions=include_open_questions,
    )
    validation = validate_protocol_ir(protocol_ir, proof_spec)
    proof_context = build_proof_context(
        case,
        protocol_ir,
        proof_spec,
        validation,
        include_semantic_review_questions=include_semantic_review_questions,
    )
    field_reviews = build_field_reviews(case, protocol_ir, proof_spec, validation, proof_context)
    return {
        "protocol_ir": protocol_ir,
        "validation": validation.to_dict(),
        "proof_context": proof_context,
        "field_reviews": field_reviews,
    }


def build_preservation_boundary(
    case: ProtocolCase,
    protocol_ir: dict[str, Any],
    proof_context: dict[str, Any],
    proof_spec: ProofSpec,
) -> dict[str, Any]:
    complexity = _abstraction_complexity(case, protocol_ir, proof_spec)
    needed = complexity["score"] >= 5
    if not needed:
        return {
            "needed": False,
            "score": complexity["score"],
            "triggers": complexity["triggers"],
            "reason": "Protocol appears simple enough for direct Sapic+ generation from ProtocolIR and proof goals.",
            "constraints": {},
        }

    target_lemmas = proof_context.get("target_lemmas", [])
    messages = protocol_ir.get("messages", [])
    crypto = protocol_ir.get("crypto", {})
    return {
        "needed": True,
        "score": complexity["score"],
        "triggers": complexity["triggers"],
        "reason": "Protocol has enough proof-relevant structure that Sapic+ generation should preserve explicit proof-goal boundaries.",
        "constraints": {
            "proof_targets": [
                {
                    "name": target.get("name"),
                    "goal_type": target.get("goal_type"),
                    "expected_state": target.get("expected_state"),
                    "trace_kind": target.get("trace_kind"),
                    "preservation_contract": _target_preservation_contract(target),
                }
                for target in target_lemmas
            ],
            "state_stages": _infer_state_stages(protocol_ir),
            "value_dependencies": _infer_target_value_dependencies(protocol_ir, target_lemmas),
            "event_dependencies": _infer_target_event_dependencies(protocol_ir, target_lemmas),
            "compromise_model": _infer_compromise_model(protocol_ir, target_lemmas),
            "message_abstraction": [
                {
                    "label": message.get("label"),
                    "from": message.get("from"),
                    "to": message.get("to"),
                    "term": message.get("term"),
                    "preserve": "sender/receiver, protected payload derivability, and fields used by checks/events/lemmas",
                }
                for message in messages
                if isinstance(message, dict)
            ],
            "crypto_abstraction": {
                "builtins": crypto.get("builtins", []),
                "functions": crypto.get("functions", []),
                "policy": (
                    "Keep only crypto distinctions that affect derivability, secrecy, authentication checks, compromise, "
                    "or expected counterexamples; simplify presentation details that do not affect target lemmas."
                ),
            },
            "open_questions": protocol_ir.get("open_questions", []),
        },
    }


def build_semantic_review_questions(
    case: ProtocolCase,
    protocol_ir: dict[str, Any],
    proof_context: dict[str, Any],
    proof_spec: ProofSpec,
) -> list[dict[str, Any]]:
    """Derive user-facing modeling questions from IR risk signals.

    These questions are intentionally about abstraction boundaries, provenance,
    compromise, and target outcomes instead of protocol-specific facts.
    """

    boundary = proof_context.get("preservation_boundary")
    if not isinstance(boundary, dict) or not boundary.get("needed"):
        return []

    target_lemmas = [item for item in _as_list(proof_context.get("target_lemmas")) if isinstance(item, dict)]
    messages = [item for item in _as_list(protocol_ir.get("messages")) if isinstance(item, dict)]
    long_term_keys = [item for item in _as_list(protocol_ir.get("long_term_keys")) if isinstance(item, dict)]
    fresh_terms = [item for item in _as_list(protocol_ir.get("fresh_terms")) if isinstance(item, dict)]
    abstractions = _as_string_list(protocol_ir.get("abstractions")) + _as_string_list(protocol_ir.get("modeling_assumptions"))
    goal_types = {_goal_type(target.get("goal_type"), target.get("name")) for target in target_lemmas}
    expected_states = {str(target.get("expected_state") or "") for target in target_lemmas}
    crypto = protocol_ir.get("crypto") if isinstance(protocol_ir.get("crypto"), dict) else {}
    crypto_surface = " ".join(_as_string_list(crypto.get("builtins")) + _as_string_list(crypto.get("functions")))
    questions: list[dict[str, Any]] = []

    def add_question(
        question_id: str,
        question: str,
        *,
        why: str,
        signals: list[str],
        severity: str = "medium",
    ) -> None:
        if any(item.get("id") == question_id for item in questions):
            return
        questions.append(
            {
                "id": question_id,
                "source": "semantic_review",
                "severity": severity,
                "question": question,
                "why": why,
                "signals": signals,
                "default_if_unanswered": "Continue with the current ProtocolIR abstraction and record this as unresolved.",
            }
        )

    if int(boundary.get("score") or 0) >= 8 or (case.difficulty or "").lower() == "hard":
        add_question(
            "semantic_review.abstraction_boundary",
            (
                "This case is using a proof-critical abstraction boundary. Which protocol details must remain explicit "
                "rather than be collapsed into opaque helper terms for the target lemmas?"
            ),
            why="High-complexity models can accidentally prove a different abstraction than the natural-language protocol.",
            signals=_compact_signals(boundary.get("triggers"), abstractions),
            severity="high",
        )

    if "authentication" in goal_types or "secrecy" in goal_types:
        add_question(
            "semantic_review.value_provenance",
            (
                "For values used in secrecy/authentication targets, which ones are trusted setup or role state, which are "
                "freshly generated, and which are only learned from the adversarial network after checks?"
            ),
            why="Proof outcomes depend on whether target-relevant values come from setup/state, local generation, derivation, or network input.",
            signals=_compact_signals(_value_names(long_term_keys + fresh_terms), _message_labels(messages)),
            severity="high" if long_term_keys or len(messages) >= 4 else "medium",
        )

    if _has_explicit_compromise_model(protocol_ir):
        add_question(
            "semantic_review.compromise_scope",
            (
                "If compromise or reveal behavior matters, which secrets can be revealed and what ordering relative to "
                "session completion should the lemmas preserve?"
            ),
            why="Forward-secrecy and compromise lemmas are very sensitive to reveal timing and to which long-term or session values are exposed.",
            signals=_compact_signals(protocol_ir.get("compromise"), [target.get("name") for target in target_lemmas]),
            severity="high",
        )

    if "CounterexampleFound" in expected_states:
        add_question(
            "semantic_review.expected_attack_surface",
            (
                "For targets expected to produce a counterexample, what protocol behavior or missing check should remain "
                "available so the model does not over-strengthen the protocol?"
            ),
            why="Benchmark attack targets should stay non-vacuous; repair/generation must not add restrictions solely to prove them.",
            signals=_compact_signals(
                [target.get("name") for target in target_lemmas if str(target.get("expected_state") or "") == "CounterexampleFound"],
                boundary.get("triggers"),
            ),
            severity="high",
        )

    crypto_hits = [
        token
        for token in ("diffie", "kem", "hkdf", "kdf", "mac", "sign", "senc", "aenc", "hash")
        if token in crypto_surface.lower()
    ]
    if len(messages) >= 4 or len(set(crypto_hits)) >= 3:
        add_question(
            "semantic_review.message_and_crypto_abstraction",
            (
                "Which message fields or crypto derivation stages are proof-relevant and must be represented separately, "
                "and which may be safely packaged as opaque terms?"
            ),
            why="Over-collapsing message fields or derivations can erase equality checks, role evidence, or attacker derivability.",
            signals=_compact_signals(_message_labels(messages), crypto_hits),
            severity="medium",
        )

    return questions[:5]


def normalize_protocol_ir(
    case: ProtocolCase,
    plan: dict[str, Any],
    proof_spec: ProofSpec,
    *,
    include_open_questions: bool = False,
) -> dict[str, Any]:
    plan = plan if isinstance(plan, dict) else {}
    candidate = _extract_ir_candidate(plan)

    messages = _normalize_messages(candidate, plan)
    roles = _normalize_roles(candidate, plan, messages)
    fresh_terms = _normalize_fresh_terms(candidate, plan)
    long_term_keys = _normalize_long_term_keys(candidate, plan)
    checks = _normalize_checks(candidate, plan)
    events = _normalize_events(candidate, plan)
    claims = _normalize_claims(candidate, plan, proof_spec)
    actions = _normalize_actions(candidate, plan, messages, fresh_terms, checks, events)
    crypto = _normalize_crypto(case, candidate, plan, messages)
    resolved_open_questions = _as_list(candidate.get("resolved_open_questions") or plan.get("resolved_open_questions"))
    modeling_assumptions = _as_string_list(candidate.get("modeling_assumptions") or plan.get("modeling_assumptions"))
    semantic_constraints = _normalize_semantic_constraints(
        candidate,
        plan,
        resolved_open_questions,
        long_term_keys,
        messages,
        fresh_terms,
    )

    protocol_ir = {
        "schema": "protocol_ir_pipeline_protocol_ir_v1",
        "protocol_name": str(
            candidate.get("protocol_name")
            or candidate.get("name")
            or plan.get("protocol_name")
            or case.name
        ),
        "roles": roles,
        "principals": _normalize_principals(candidate, plan, roles),
        "crypto": crypto,
        "fresh_terms": fresh_terms,
        "long_term_keys": long_term_keys,
        "messages": messages,
        "actions": actions,
        "checks": checks,
        "events": events,
        "claims": claims,
        "compromise": _normalize_compromise(candidate, plan),
        "abstractions": _as_string_list(candidate.get("abstractions") or plan.get("abstractions")),
        "modeling_assumptions": modeling_assumptions,
        "resolved_open_questions": resolved_open_questions,
        "semantic_constraints": semantic_constraints,
        "field_evidence": _normalize_field_evidence(candidate, plan),
        "open_questions": (
            _as_string_list(candidate.get("open_questions") or plan.get("open_questions"))
            if include_open_questions
            else []
        ),
    }
    protocol_ir["field_evidence"] = _complete_field_evidence_coverage(protocol_ir, case)
    return protocol_ir


def validate_protocol_ir(protocol_ir: dict[str, Any], proof_spec: ProofSpec) -> IRValidationResult:
    errors: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []

    roles = _as_list(protocol_ir.get("roles"))
    role_names = {str(role) for role in roles if str(role)}
    messages = [msg for msg in _as_list(protocol_ir.get("messages")) if isinstance(msg, dict)]
    claims = [claim for claim in _as_list(protocol_ir.get("claims")) if isinstance(claim, dict)]
    fresh_terms = [item for item in _as_list(protocol_ir.get("fresh_terms")) if isinstance(item, dict)]

    if not role_names:
        errors.append("ProtocolIR has no roles; planner must identify protocol roles before Sapic+ generation.")
    _check(checks, "roles_present", bool(role_names), "roles are available", "ProtocolIR has no roles.")

    if not messages:
        errors.append("ProtocolIR has no message declarations; planner must extract protocol messages before Sapic+ generation.")
    _check(
        checks,
        "messages_present",
        bool(messages),
        f"{len(messages)} message declaration(s)",
        "no message declarations",
    )

    labels: list[str] = []
    for index, message in enumerate(messages, start=1):
        label = str(message.get("label") or f"M{index}")
        labels.append(label)
        missing = [
            field_name
            for field_name in ("from", "to", "term")
            if not str(message.get(field_name) or "").strip()
        ]
        if missing:
            errors.append(f"Message `{label}` is missing required field(s): {', '.join(missing)}.")
        term = str(message.get("term") or "")
        if re.search(r"\{[^{}]+}\s*[_A-Za-z0-9(]", term) or re.search(r"\b(?:aenc|adec|senc)\s*\{", term):
            errors.append(
                f"Message `{label}` uses brace/subscript encryption notation; ProtocolIR terms must use function syntax such as `aenc(m, pk)`."
            )
        if re.search(r"(?<!['A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*'(?!['A-Za-z0-9_])", term):
            errors.append(f"Message `{label}` uses primed variables; use identifiers such as `na_recv` or `na1`.")
        for field_name in ("from", "to"):
            role = str(message.get(field_name) or "")
            if role and role_names and role not in role_names:
                warnings.append(f"Message `{label}` references role `{role}` not listed in roles.")

    duplicate_labels = sorted({label for label in labels if labels.count(label) > 1})
    if duplicate_labels:
        errors.append(f"Duplicate message labels: {duplicate_labels}.")
    _check(
        checks,
        "message_labels_unique",
        not duplicate_labels,
        "message labels are unique",
        f"duplicate labels: {duplicate_labels}",
    )

    for item in fresh_terms:
        name = str(item.get("name") or "").strip()
        owner = str(item.get("owner") or item.get("role") or "").strip()
        if not name:
            errors.append("A fresh term entry is missing `name`.")
        if owner and role_names and owner not in role_names:
            warnings.append(f"Fresh term `{name}` owner `{owner}` is not listed in roles.")
        if not owner:
            warnings.append(f"Fresh term `{name or '<unnamed>'}` has no owner role.")

    target_names = set(proof_spec.names)
    claim_names = {str(claim.get("lemma_name") or claim.get("name") or "") for claim in claims}
    missing_claims = sorted(name for name in target_names if name and name not in claim_names)
    if missing_claims:
        errors.append(f"Target proof_spec lemma(s) missing from ProtocolIR claims: {missing_claims}.")
    if not claims:
        errors.append("ProtocolIR has no claims; planner must extract proof claims before Sapic+ generation.")
    _check(
        checks,
        "target_claims_present",
        not missing_claims,
        "all proof_spec targets have claim records",
        f"missing target claims: {missing_claims}",
    )

    encrypted = [
        msg
        for msg in messages
        if _message_protection(str(msg.get("term") or "")) in {"asymmetric-encryption", "symmetric-encryption", "signing", "mac"}
    ]
    untagged = [
        str(msg.get("label"))
        for msg in encrypted
        if not _looks_tagged(str(msg.get("term") or ""))
    ]
    if untagged:
        warnings.append(f"Encrypted/message-authenticated terms lack obvious public tags: {untagged}.")
    _check(
        checks,
        "message_tags_present",
        not untagged if encrypted else True,
        "encrypted/message-authenticated messages have public tags or none detected",
        f"untagged encrypted messages: {untagged}",
    )

    return IRValidationResult(ok=not errors, errors=errors, warnings=warnings, checks=checks)


def build_proof_context(
    case: ProtocolCase,
    protocol_ir: dict[str, Any],
    proof_spec: ProofSpec,
    validation: IRValidationResult | dict[str, Any] | None = None,
    *,
    include_semantic_review_questions: bool = False,
) -> dict[str, Any]:
    claims = _claim_by_name(protocol_ir.get("claims"))
    target_lemmas = []
    if proof_spec.expectations:
        for expectation in proof_spec.expectations:
            claim = claims.get(expectation.name, {})
            goal_type = str(claim.get("goal_type") or expectation.goal_type or infer_goal_type(expectation.name, expectation.trace_kind))
            required_events = (
                _as_string_list(expectation.required_events)
                or _as_string_list(claim.get("event_schema") or claim.get("required_events"))
                or _required_events_for_goal(goal_type, protocol_ir.get("roles", []))
            )
            target_lemmas.append(
                {
                    "name": expectation.name,
                    "goal_type": goal_type,
                    "trace_kind": expectation.trace_kind,
                    "expected_state": expectation.expected_state,
                    "expected_raw": expectation.expected_raw,
                    "intent": expectation.intent or claim.get("intent", ""),
                    "required_events": required_events,
                    "witness": claim.get("witness", ""),
                    "claim_source": "proof_spec",
                }
            )
    else:
        for claim in _as_list(protocol_ir.get("claims")):
            if not isinstance(claim, dict):
                continue
            name = str(claim.get("lemma_name") or claim.get("name") or "").strip()
            if not name:
                continue
            goal_type = str(claim.get("goal_type") or infer_goal_type(name))
            required_events = (
                _as_string_list(claim.get("event_schema") or claim.get("required_events"))
                or _required_events_for_goal(goal_type, protocol_ir.get("roles", []))
            )
            target_lemmas.append(
                {
                    "name": name,
                    "goal_type": goal_type,
                    "trace_kind": str(claim.get("trace_kind") or "unknown"),
                    "expected_state": str(claim.get("expected_state") or PROVED_SATISFYING),
                    "expected_raw": str(claim.get("expected_raw") or ""),
                    "intent": str(claim.get("intent") or ""),
                    "required_events": required_events,
                    "witness": str(claim.get("witness") or ""),
                    "claim_source": "protocol_ir",
                }
            )

    requires_sources = any(_is_source_goal(target) for target in target_lemmas)
    source_lines = _source_line_map(protocol_ir.get("messages")) if requires_sources else []
    validation_payload = validation.to_dict() if isinstance(validation, IRValidationResult) else (validation or {})

    contract = {
        "schema": "protocol_ir_pipeline_proof_context_v1",
        "case": case.name,
        "source": "derived_from_protocol_ir_and_proof_spec",
        "goal_mode": proof_spec.mode,
        "proof_spec_source": proof_spec.source,
        "roles": protocol_ir.get("roles", []),
        "messages": protocol_ir.get("messages", []),
        "fresh": protocol_ir.get("fresh_terms", []),
        "crypto": protocol_ir.get("crypto", {}),
        "target_lemmas": target_lemmas,
        "event_obligations": _event_obligations(target_lemmas),
        "proof_obligations": {
            "requires_sources_lemma": requires_sources,
            "source_line_map": source_lines,
            "source_policy": (
                "Source/typing helper obligations are disabled unless a user-facing target lemma is explicitly "
                "classified as source/typing. Do not add non-target source-helper lemmas or auxiliary source-helper events for secrecy, "
                "authentication, executability, or general property targets."
            ),
        },
        "knowledge_contract": _knowledge_contract(protocol_ir),
        "semantic_assumption_contract": _semantic_assumption_contract(protocol_ir, target_lemmas),
        "generation_policies": _generation_policies(protocol_ir, target_lemmas),
        "validation": validation_payload,
    }
    contract["preservation_boundary"] = build_preservation_boundary(case, protocol_ir, contract, proof_spec)
    contract["semantic_review_questions"] = (
        build_semantic_review_questions(case, protocol_ir, contract, proof_spec)
        if include_semantic_review_questions
        else []
    )
    return contract


def build_field_reviews(
    case: ProtocolCase,
    protocol_ir: dict[str, Any],
    proof_spec: ProofSpec,
    validation: IRValidationResult | dict[str, Any] | None,
    proof_context: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Build field-level confidence metadata for human review.

    The planner may provide source quotes and LLM priority scores, but this
    function normalizes them and adds deterministic consistency/impact signals.
    `priority_score` is always the formula score
    max(1 - evidence, 1 - consistency) * impact; the LLM-provided
    `priority_llm` is recorded as an auxiliary signal only.
    """

    validation_payload = validation.to_dict() if isinstance(validation, IRValidationResult) else (validation or {})
    proof_context = proof_context if isinstance(proof_context, dict) else {}
    source_text = _case_source_text(case)
    evidence_by_path = _field_evidence_by_path(protocol_ir, source_text)
    diagnostics_by_path = _consistency_diagnostics_by_path(protocol_ir, validation_payload, proof_context)
    paths = sorted(_reviewable_field_paths(protocol_ir, proof_context, diagnostics_by_path, evidence_by_path))
    result: list[dict[str, Any]] = []
    for path in paths:
        section = path.split(".", 1)[0]
        diagnostics = diagnostics_by_path.get(path, [])
        evidence = evidence_by_path.get(path, [])
        fallback_impact = _semantic_impact_for_path(path, protocol_ir, proof_context)
        fallback_evidence_confidence = _evidence_confidence(evidence)
        fallback_consistency_confidence = "low" if diagnostics else "high"
        llm_scores = _llm_review_scores_for_path(protocol_ir, path)
        evidence_score = llm_scores.get("evidence_confidence_score")
        consistency_score = llm_scores.get("consistency_confidence_score")
        impact_score = llm_scores.get("semantic_impact_score")
        evidence_confidence = _score_label(evidence_score, fallback=fallback_evidence_confidence)
        consistency_confidence = _score_label(consistency_score, fallback=fallback_consistency_confidence)
        impact = _score_label(impact_score, fallback=fallback_impact)
        formula_priority = _formula_priority(
            evidence_confidence,
            consistency_confidence,
            impact,
            evidence_confidence_score=evidence_score,
            consistency_confidence_score=consistency_score,
            semantic_impact_score=impact_score,
        )
        llm_priority = _llm_priority_for_path(protocol_ir, path)
        priority_score = formula_priority
        priority_source = "formula"
        priority_level = _priority_level(priority_score)
        review_status = _review_status_for_field(
            priority_level=priority_level,
            evidence_confidence=evidence_confidence,
            consistency_confidence=consistency_confidence,
            diagnostics=diagnostics,
        )
        value = _get_dotted(protocol_ir, path)
        result.append(
            {
                "id": path,
                "schema": "protocol_ir_pipeline_field_review_v1",
                "section": section,
                "field_path": path,
                "value_snapshot": value,
                "source_evidence": evidence,
                "evidence_confidence": evidence_confidence,
                "evidence_confidence_score": evidence_score if evidence_score is not None else _label_score(evidence_confidence),
                "consistency_confidence": consistency_confidence,
                "consistency_confidence_score": consistency_score if consistency_score is not None else _label_score(consistency_confidence),
                "semantic_impact": impact,
                "semantic_impact_score": impact_score if impact_score is not None else _label_score(impact),
                "semantic_impact_source": "llm" if impact_score is not None else "fallback",
                "priority_llm": llm_priority,
                "priority_formula": formula_priority,
                "priority_score": priority_score,
                "priority_source": priority_source,
                "priority_level": priority_level,
                "review_status": review_status,
                "diagnostics": diagnostics,
                "suggested_action": _suggested_review_action(path, review_status, diagnostics, impact),
            }
        )
    result.sort(key=lambda item: (-float(item.get("priority_score") or 0), str(item.get("field_path") or "")))
    return result


def _extract_ir_candidate(plan: dict[str, Any]) -> dict[str, Any]:
    if _looks_like_protocol_ir(plan):
        return plan
    for key in ("protocol_ir", "ProtocolIR", "protocolIR", "ir", "IR"):
        value = plan.get(key)
        if isinstance(value, dict):
            return value
    return plan


def _looks_like_protocol_ir(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    schema = str(value.get("schema") or "")
    if schema.startswith(("protocol_ir_pipeline_protocol_ir", "autosm_style_protocol_ir")):
        return True
    return bool(value.get("messages") and value.get("claims") and (value.get("fresh_terms") or value.get("long_term_keys") or value.get("actions")))


def _normalize_roles(candidate: dict[str, Any], plan: dict[str, Any], messages: list[dict[str, Any]]) -> list[str]:
    roles = []
    for source in (candidate.get("roles"), candidate.get("Roles"), plan.get("roles")):
        for role in _as_list(source):
            if isinstance(role, dict):
                name = role.get("name") or role.get("role") or role.get("id")
            else:
                name = role
            _append_unique(roles, _clean_identifier_like(name))
    for message in messages:
        _append_unique(roles, _clean_identifier_like(message.get("from")))
        _append_unique(roles, _clean_identifier_like(message.get("to")))
    for item in _as_list(candidate.get("fresh_terms") or candidate.get("fresh_values") or plan.get("fresh_values")):
        if isinstance(item, dict):
            _append_unique(roles, _clean_identifier_like(item.get("owner") or item.get("role")))
    return roles


def _normalize_principals(candidate: dict[str, Any], plan: dict[str, Any], roles: list[str]) -> list[dict[str, str]]:
    raw_principals = candidate.get("principals") or candidate.get("agents") or plan.get("principals")
    principals = []
    for item in _as_list(raw_principals):
        if isinstance(item, dict):
            name = _clean_identifier_like(item.get("name") or item.get("role") or item.get("id"))
            if name:
                principals.append({"name": name, "role_hint": str(item.get("role") or name)})
        else:
            name = _clean_identifier_like(item)
            if name:
                principals.append({"name": name, "role_hint": name})
    if not principals:
        principals = [{"name": role, "role_hint": role} for role in roles]
    return principals


def _normalize_messages(candidate: dict[str, Any], plan: dict[str, Any]) -> list[dict[str, Any]]:
    raw_messages = candidate.get("messages") or candidate.get("Messages") or plan.get("messages")
    messages = []
    for index, item in enumerate(_as_list(raw_messages), start=1):
        if isinstance(item, str):
            message = {"term": item}
        elif isinstance(item, dict):
            message = dict(item)
        else:
            continue
        step = _int_or_default(message.get("step") or message.get("index"), index)
        label = str(message.get("label") or message.get("name") or message.get("id") or f"M{step}")
        sender = _clean_identifier_like(message.get("from") or message.get("sender") or message.get("src"))
        receiver = _clean_identifier_like(message.get("to") or message.get("receiver") or message.get("dst"))
        term = str(
            message.get("term")
            or message.get("term_shape")
            or message.get("message")
            or message.get("content")
            or ""
        ).strip()
        protection = str(message.get("protection") or _message_protection(term) or "plain")
        messages.append(
            {
                "label": _fact_suffix(label),
                "step": step,
                "from": sender,
                "to": receiver,
                "term": term,
                "meaning": str(message.get("meaning") or message.get("description") or ""),
                "protection": protection,
                "sender_knows": _as_string_list(message.get("sender_knows")),
                "receiver_can_decrypt": _maybe_bool(message.get("receiver_can_decrypt")),
                "receiver_must_treat_as_opaque": _as_string_list(
                    message.get("receiver_must_treat_as_opaque") or message.get("opaque_for")
                ),
            }
        )
    messages.sort(key=lambda item: item.get("step", 0))
    return messages


def _normalize_fresh_terms(candidate: dict[str, Any], plan: dict[str, Any]) -> list[dict[str, str]]:
    raw_fresh = (
        candidate.get("fresh_terms")
        or candidate.get("fresh_values")
        or candidate.get("fresh")
        or plan.get("fresh_terms")
        or plan.get("fresh_values")
    )
    fresh_terms = []
    for item in _as_list(raw_fresh):
        if isinstance(item, dict):
            name = str(item.get("name") or item.get("term") or item.get("value") or "").strip()
            owner = _clean_identifier_like(item.get("owner") or item.get("role"))
            purpose = str(item.get("purpose") or item.get("meaning") or "")
        else:
            name = str(item).strip()
            owner = ""
            purpose = ""
        if name:
            fresh_terms.append({"name": name, "owner": owner, "purpose": purpose})
    return _dedupe_dicts(fresh_terms, key="name")


def _normalize_long_term_keys(candidate: dict[str, Any], plan: dict[str, Any]) -> list[dict[str, str]]:
    raw_keys = candidate.get("long_term_keys") or candidate.get("keys") or plan.get("long_term_keys")
    keys = []
    for item in _as_list(raw_keys):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("key") or item.get("private_term") or "").strip()
        owner = _clean_identifier_like(item.get("owner") or item.get("role"))
        public_term = str(item.get("public_term") or item.get("public") or "").strip()
        policy = str(item.get("policy") or item.get("reveal_policy") or item.get("description") or "").strip()
        if name or owner or public_term:
            key = {"name": name, "owner": owner, "public_term": public_term}
            if policy:
                key["policy"] = policy
            keys.append(key)
    return keys


def _normalize_semantic_constraints(
    candidate: dict[str, Any],
    plan: dict[str, Any],
    resolved_open_questions: list[Any],
    long_term_keys: list[dict[str, str]],
    messages: list[dict[str, Any]],
    fresh_terms: list[dict[str, str]],
) -> list[dict[str, Any]]:
    constraints: list[dict[str, Any]] = []
    for item in _as_list(candidate.get("semantic_constraints") or plan.get("semantic_constraints")):
        if isinstance(item, dict):
            constraints.append(dict(item))
        elif item:
            constraints.append({"kind": "text_policy", "policy": str(item)})

    for question in resolved_open_questions:
        if not isinstance(question, dict):
            continue
        question_id = str(question.get("id") or "")
        answer = str(question.get("answer") or "").strip()
        if not answer:
            continue
        answer_lc = answer.lower()
        base = {
            "source": "resolved_open_question",
            "question_id": question_id,
            "answer": answer,
        }
        constraints.append(
            {
                **base,
                "kind": "binding_answer",
                "policy": "This answered semantic-review question is binding for Sapic+ generation and repair; prefer it over stale normalized IR fields when they conflict.",
            }
        )
        if "trusted setup" in answer_lc or "role state" in answer_lc or "long-term" in answer_lc or "private key" in answer_lc:
            constraints.append(
                {
                    **base,
                    "kind": "trust_boundary",
                    "values": _constraint_values_from_answer(answer, long_term_keys, fallback_kind="long_term_key"),
                    "policy": (
                        "Values identified as trusted setup, role state, long-term keys, or private keys must be created as private fresh setup/state material, "
                        "passed through role parameters or persistent private facts, and never replaced by public constants or public function terms."
                    ),
                    "forbidden_patterns": [
                        "private/setup key represented only as f(identity) without a fresh private origin",
                        "private/setup key learned from in(...)",
                        "private/setup key output on the public channel unless an explicit reveal/compromise event is modeled",
                    ],
                }
            )
        if "public key" in answer_lc or "trusted binding" in answer_lc or "binding from identity" in answer_lc:
            constraints.append(
                {
                    **base,
                    "kind": "identity_binding",
                    "values": _constraint_values_from_answer(answer, long_term_keys, fallback_kind="public_binding"),
                    "policy": (
                        "Identity-to-public-key bindings described as trusted setup must be represented as setup/state parameters or persistent trusted facts. "
                        "Do not accept arbitrary public keys learned from the adversarial network as peer identity bindings."
                    ),
                }
            )
        if "network-learned" in answer_lc or "after decrypt" in answer_lc or "after decrypting" in answer_lc or "after checks" in answer_lc:
            constraints.append(
                {
                    **base,
                    "kind": "network_after_check",
                    "messages": [str(message.get("label")) for message in messages if isinstance(message, dict) and message.get("label")],
                    "policy": (
                        "Values learned from network messages become trusted only after the role performs the stated decryption, pattern match, identity check, freshness check, or opaque-forwarding boundary."
                    ),
                }
            )
        if "freshly generated" in answer_lc or "fresh" in answer_lc:
            constraints.append(
                {
                    **base,
                    "kind": "fresh_generation",
                    "values": _constraint_values_from_answer(answer, fresh_terms, fallback_kind="fresh"),
                    "policy": "Values identified as fresh must be introduced by `new` in the owning role before first use, not learned from the network.",
                }
            )
        if "opaque" in answer_lc or "forwarded unchanged" in answer_lc:
            constraints.append(
                {
                    **base,
                    "kind": "opaque_forwarding",
                    "messages": [str(message.get("label")) for message in messages if isinstance(message, dict) and message.get("label")],
                    "policy": "Opaque carried terms may be forwarded unchanged, but the forwarding role must not emit events over protected payload fields it cannot derive.",
                }
            )

    return _dedupe_constraint_dicts(constraints)


def _normalize_field_evidence(candidate: dict[str, Any], plan: dict[str, Any]) -> list[dict[str, Any]]:
    raw_items = (
        candidate.get("field_evidence")
        or candidate.get("field_reviews")
        or candidate.get("review_checklist")
        or plan.get("field_evidence")
        or plan.get("field_reviews")
        or plan.get("review_checklist")
    )
    result: list[dict[str, Any]] = []
    for item in _as_list(raw_items):
        if not isinstance(item, dict):
            continue
        field_path = _normalize_review_path(item.get("field_path") or item.get("path") or item.get("id"))
        if not field_path:
            continue
        source_evidence = item.get("source_evidence")
        quote = str(item.get("source_quote") or item.get("quote") or "")
        evidence_kind = str(item.get("evidence_kind") or item.get("kind") or "")
        if isinstance(source_evidence, list) and source_evidence:
            first = source_evidence[0]
            if isinstance(first, dict):
                quote = quote or str(first.get("quote") or first.get("source_quote") or "")
                evidence_kind = evidence_kind or str(first.get("kind") or first.get("evidence_kind") or "")
        priority = _number_or_none(
            item.get("priority_llm")
            if "priority_llm" in item
            else item.get("llm_priority", item.get("priority_score", item.get("priority")))
        )
        evidence_score = _score_or_none(item.get("evidence_confidence_score", item.get("evidence_score")))
        consistency_score = _score_or_none(item.get("consistency_confidence_score", item.get("consistency_score")))
        impact_score = _score_or_none(item.get("semantic_impact_score", item.get("impact_score")))
        normalized = {
            "field_path": field_path,
            "source_quote": quote,
            "evidence_kind": evidence_kind or "direct",
            "reason": str(item.get("reason") or item.get("summary") or item.get("diagnostic") or ""),
        }
        if priority is not None:
            normalized["priority_llm"] = _score_or_none(priority)
        if evidence_score is not None:
            normalized["evidence_confidence_score"] = evidence_score
        if consistency_score is not None:
            normalized["consistency_confidence_score"] = consistency_score
        if impact_score is not None:
            normalized["semantic_impact_score"] = impact_score
        result.append(normalized)
    return result


def _complete_field_evidence_coverage(protocol_ir: dict[str, Any], case: ProtocolCase) -> list[dict[str, Any]]:
    """Ensure each review-UI field has a field_evidence entry.

    LLM-provided field_evidence keeps its numeric scores. Missing entries are
    added as source-span fallback stubs without numeric scores, so later review
    metadata can still distinguish LLM scoring from deterministic fallback.
    """

    existing = [item for item in _as_list(protocol_ir.get("field_evidence")) if isinstance(item, dict)]
    covered = {
        _normalize_review_path(item.get("field_path") or item.get("path") or item.get("id"))
        for item in existing
        if _normalize_review_path(item.get("field_path") or item.get("path") or item.get("id"))
    }
    source_text = _case_source_text(case)
    completed = list(existing)
    for path in sorted(_ui_review_field_evidence_paths(protocol_ir)):
        if path in covered:
            continue
        value = _get_dotted(protocol_ir, path)
        quote = _best_source_quote_for_value(value, source_text)
        completed.append(
            {
                "field_path": path,
                "source_quote": quote,
                "evidence_kind": "direct" if quote else "none",
                "reason": "Coverage fallback: the LLM did not provide field_evidence for this UI-visible review field.",
                "coverage_source": "deterministic_fallback",
            }
        )
    return completed


def _ui_review_field_evidence_paths(protocol_ir: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    keys_by_section = {
        "fresh_terms": ("name", "owner", "purpose"),
        "long_term_keys": ("name", "owner", "public_term", "policy"),
        "messages": ("label", "from", "to", "protection", "term", "meaning"),
        "checks": ("role", "condition", "source_message", "action"),
        "events": ("name", "role", "when", "arguments"),
        "claims": ("lemma_name", "goal_type", "trace_kind", "expected_state", "event_schema"),
    }
    for section, keys in keys_by_section.items():
        for index, item in enumerate(_as_list(protocol_ir.get(section))):
            if not isinstance(item, dict):
                continue
            for key in keys:
                if key in item and item.get(key) not in (None, "", [], {}):
                    paths.add(f"{section}.{index}.{key}")
    return paths


def _normalize_crypto(
    case: ProtocolCase,
    candidate: dict[str, Any],
    plan: dict[str, Any],
    messages: list[dict[str, Any]],
) -> dict[str, Any]:
    raw_crypto = candidate.get("crypto") if isinstance(candidate.get("crypto"), dict) else {}
    text = " ".join(
        [
            case.description,
            " ".join(case.assumptions),
            jsonish(plan.get("assumptions")),
            " ".join(str(message.get("term") or "") for message in messages),
        ]
    ).lower()
    builtins = _as_string_list(raw_crypto.get("builtins") or candidate.get("builtins") or plan.get("builtins"))
    if any(token in text for token in ("aenc", "pub(", "public key", "asymmetric", "pk(")):
        _append_unique(builtins, "asymmetric-encryption")
    if any(token in text for token in ("senc", "symmetric", "shared key")):
        _append_unique(builtins, "symmetric-encryption")
    if any(token in text for token in ("hash", "h(", "kdf")):
        _append_unique(builtins, "hashing")
    if any(token in text for token in ("sign", "signature", "verify(")):
        _append_unique(builtins, "signing")
    if any(token in text for token in ("diffie", "dh", "^", "exponent")):
        _append_unique(builtins, "diffie-hellman")

    functions = _as_string_list(raw_crypto.get("functions") or candidate.get("functions") or plan.get("functions"))
    if "kdf" in text and not any(item.startswith("kdf/") for item in functions):
        functions.append("kdf/2")
    return {
        "builtins": builtins,
        "functions": functions,
        "equations": _as_string_list(raw_crypto.get("equations") or candidate.get("equations") or plan.get("equations")),
        "assumptions": _as_string_list(case.assumptions),
    }


def _normalize_checks(candidate: dict[str, Any], plan: dict[str, Any]) -> list[dict[str, Any]]:
    checks = []
    for item in _as_list(candidate.get("checks") or plan.get("checks")):
        if isinstance(item, dict):
            check = {
                "role": _clean_identifier_like(item.get("role")),
                "condition": str(item.get("condition") or item.get("check") or ""),
                "source_message": str(item.get("source_message") or item.get("source_step") or ""),
            }
            for key in ("check_id", "action", "proof_relevance"):
                if key in item:
                    check[key] = item.get(key)
            checks.append(check)
        elif item:
            checks.append({"role": "", "condition": str(item), "source_message": ""})
    return checks


def _normalize_events(candidate: dict[str, Any], plan: dict[str, Any]) -> list[dict[str, Any]]:
    events = []
    for item in _as_list(candidate.get("events") or plan.get("events")):
        if isinstance(item, dict):
            event = {
                "name": str(item.get("name") or item.get("event") or ""),
                "arguments": _as_string_list(item.get("arguments") or item.get("args")),
                "role": _clean_identifier_like(item.get("role")),
                "when": str(item.get("when") or item.get("placement") or ""),
            }
            for key in ("event_id", "source_message", "action", "proof_relevance"):
                if key in item:
                    event[key] = item.get(key)
            events.append(event)
    return [event for event in events if event["name"]]


def _normalize_actions(
    candidate: dict[str, Any],
    plan: dict[str, Any],
    messages: list[dict[str, Any]],
    fresh_terms: list[dict[str, str]],
    checks: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    actions = []
    raw_actions = candidate.get("actions") or candidate.get("processes") or plan.get("actions")
    for item in _as_list(raw_actions):
        if isinstance(item, dict) and "actions" in item:
            role = _clean_identifier_like(item.get("role") or item.get("name") or item.get("process"))
            for action in _as_list(item.get("actions")):
                if isinstance(action, dict):
                    merged = dict(action)
                    merged.setdefault("role", role)
                    actions.append(_normalize_action(merged, len(actions) + 1))
        elif isinstance(item, dict):
            actions.append(_normalize_action(item, len(actions) + 1))

    if actions:
        return actions

    for item in fresh_terms:
        owner = item.get("owner") or ""
        actions.append(
            {
                "action_id": f"{owner or 'role'}_generate_{_fact_suffix(item.get('name'))}",
                "role": owner,
                "kind": "generate",
                "generates": [item.get("name")],
                "message_in": [],
                "message_out": [],
                "checks": [],
                "events": [],
            }
        )
    for message in messages:
        label = message.get("label")
        sender = message.get("from")
        receiver = message.get("to")
        actions.append(
            {
                "action_id": f"{sender or 'sender'}_send_{label}",
                "role": sender,
                "kind": "send",
                "generates": [],
                "message_in": [],
                "message_out": [label],
                "checks": [],
                "events": [f"OUT_{_fact_suffix(label)}({label})"],
            }
        )
        actions.append(
            {
                "action_id": f"{receiver or 'receiver'}_receive_{label}",
                "role": receiver,
                "kind": "receive",
                "generates": [],
                "message_in": [label],
                "message_out": [],
                "checks": [],
                "events": [f"IN_{_fact_suffix(label)}({label})"],
            }
        )
    for index, check in enumerate(checks, start=1):
        actions.append(
            {
                "action_id": f"{check.get('role') or 'role'}_check_{index}",
                "role": check.get("role", ""),
                "kind": "check",
                "generates": [],
                "message_in": [],
                "message_out": [],
                "checks": [check.get("condition", "")],
                "events": [],
            }
        )
    for index, event in enumerate(events, start=1):
        actions.append(
            {
                "action_id": f"{event.get('role') or 'role'}_event_{event.get('name') or index}",
                "role": event.get("role", ""),
                "kind": "event",
                "generates": [],
                "message_in": [],
                "message_out": [],
                "checks": [],
                "events": [_event_text(event)],
            }
        )
    return actions


def _normalize_action(item: dict[str, Any], index: int) -> dict[str, Any]:
    kind = str(item.get("kind") or item.get("type") or item.get("action_type") or "").lower()
    if not kind:
        if item.get("message_out") or item.get("message_sent"):
            kind = "send"
        elif item.get("message_in") or item.get("message_received"):
            kind = "receive"
        else:
            kind = "step"
    return {
        "action_id": str(item.get("action_id") or item.get("name") or f"action_{index}"),
        "role": _clean_identifier_like(item.get("role") or item.get("process")),
        "kind": kind,
        "generates": _as_string_list(item.get("generates") or item.get("fresh")),
        "message_in": _as_string_list(item.get("message_in") or item.get("message_received")),
        "message_out": _as_string_list(item.get("message_out") or item.get("message_sent")),
        "checks": _as_string_list(item.get("checks") or item.get("conditions")),
        "events": _as_string_list(item.get("events") or item.get("action_facts")),
    }


def _normalize_claims(
    candidate: dict[str, Any],
    plan: dict[str, Any],
    proof_spec: ProofSpec,
) -> list[dict[str, Any]]:
    claims = []
    raw_claims = candidate.get("claims") or candidate.get("lemmas") or plan.get("claims") or plan.get("lemmas")
    for item in _as_list(raw_claims):
        if not isinstance(item, dict):
            continue
        name = str(item.get("lemma_name") or item.get("name") or item.get("id") or "").strip()
        if not name:
            continue
        goal_type = _goal_type(item.get("goal_type") or item.get("kind") or item.get("type"), name)
        event_schema = _as_string_list(item.get("event_schema") or item.get("required_events"))
        if not event_schema:
            event_schema = _required_events_for_goal(goal_type, candidate.get("roles") or plan.get("roles") or [])
        claims.append(
            {
                "lemma_name": name,
                "goal_type": goal_type,
                "expected_state": str(item.get("expected_state") or PROVED_SATISFYING),
                "trace_kind": str(item.get("trace_kind") or "unknown"),
                "intent": str(item.get("intent") or item.get("description") or ""),
                "event_schema": event_schema,
                "witness": str(item.get("witness") or ""),
                "expected_raw": str(item.get("expected_raw") or ""),
            }
        )

    by_name = {claim["lemma_name"]: claim for claim in claims}
    for expectation in proof_spec.expectations:
        if expectation.name in by_name:
            by_name[expectation.name]["goal_type"] = _goal_type(expectation.goal_type, expectation.name)
            by_name[expectation.name]["expected_state"] = expectation.expected_state
            by_name[expectation.name]["trace_kind"] = expectation.trace_kind
            if expectation.expected_raw and not by_name[expectation.name].get("expected_raw"):
                by_name[expectation.name]["expected_raw"] = expectation.expected_raw
            if expectation.required_events and not by_name[expectation.name].get("event_schema"):
                by_name[expectation.name]["event_schema"] = _as_string_list(expectation.required_events)
            if expectation.intent and not by_name[expectation.name].get("intent"):
                by_name[expectation.name]["intent"] = expectation.intent
            continue
        goal_type = _goal_type(expectation.goal_type, expectation.name)
        event_schema = _as_string_list(expectation.required_events) or _required_events_for_goal(
            goal_type,
            candidate.get("roles") or plan.get("roles") or [],
        )
        claims.append(
            {
                "lemma_name": expectation.name,
                "goal_type": goal_type,
                "expected_state": expectation.expected_state,
                "trace_kind": expectation.trace_kind,
                "intent": expectation.intent,
                "event_schema": event_schema,
                "witness": "",
                "expected_raw": expectation.expected_raw,
            }
        )
    return _dedupe_dicts(claims, key="lemma_name")


def _normalize_compromise(candidate: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    raw = candidate.get("compromise") or plan.get("compromise")
    if isinstance(raw, dict):
        return {
            "reveal_events": _as_string_list(raw.get("reveal_events") or raw.get("reveals")),
            "policy": str(raw.get("policy") or raw.get("description") or ""),
        }
    return {"reveal_events": [], "policy": ""}


def _abstraction_complexity(
    case: ProtocolCase,
    protocol_ir: dict[str, Any],
    proof_spec: ProofSpec,
) -> dict[str, Any]:
    triggers = []
    score = 0
    difficulty = (case.difficulty or "").lower()
    if difficulty == "hard":
        score += 3
        triggers.append("difficulty=hard")
    elif difficulty == "medium":
        score += 1
        triggers.append("difficulty=medium")

    messages = [msg for msg in _as_list(protocol_ir.get("messages")) if isinstance(msg, dict)]
    if len(messages) >= 4:
        score += 2
        triggers.append(f"message_count={len(messages)}")
    elif len(messages) >= 3:
        score += 1
        triggers.append(f"message_count={len(messages)}")

    open_questions = _as_string_list(protocol_ir.get("open_questions"))
    if open_questions:
        score += min(3, len(open_questions))
        triggers.append(f"open_questions={len(open_questions)}")

    builtins = _as_string_list((protocol_ir.get("crypto") or {}).get("builtins"))
    functions = _as_string_list((protocol_ir.get("crypto") or {}).get("functions"))
    crypto_surface = " ".join(builtins + functions).lower()
    crypto_hits = [
        token
        for token in ("diffie", "kem", "hkdf", "kdf", "mac", "sign", "senc", "aenc", "hash")
        if token in crypto_surface
    ]
    if len(set(crypto_hits)) >= 3:
        score += 2
        triggers.append("multiple_crypto_layers")

    goal_types = {_goal_type(item.goal_type, item.name) for item in proof_spec.expectations}
    expected_states = {item.expected_state for item in proof_spec.expectations}
    if "authentication" in goal_types and "secrecy" in goal_types:
        score += 2
        triggers.append("mixed_authentication_and_secrecy_targets")
    if "CounterexampleFound" in expected_states and "ProvedSatisfying" in expected_states:
        score += 2
        triggers.append("mixed_expected_verified_and_attack_targets")

    if _has_explicit_compromise_model(protocol_ir):
        score += 3
        triggers.append("explicit_compromise_model")
    if _has_mixed_sensitive_expected_outcomes(proof_spec):
        score += 3
        triggers.append("mixed_sensitive_expected_outcomes")

    return {"score": score, "triggers": triggers}


def _target_preservation_contract(target: dict[str, Any]) -> dict[str, str]:
    expected_state = str(target.get("expected_state") or "")
    if expected_state == "CounterexampleFound":
        outcome_policy = (
            "Preserve the protocol-justified trace class that should witness the target outcome; "
            "do not strengthen the model just to make every target prove."
        )
    elif expected_state == PROVED_SATISFYING:
        outcome_policy = (
            "Preserve the checks, guards, and event dependencies needed for the target outcome; "
            "do not make the property vacuous by moving events before the protocol evidence they summarize."
        )
    else:
        outcome_policy = "Preserve the expected proof outcome described by proof_spec without changing target intent."

    return {
        "semantic_anchor": (
            "Keep the lemma tied to the same protocol meaning: its witness or forbidden trace, quantified values, "
            "roles, events, equality constraints, and trace-ordering constraints."
        ),
        "dependency_policy": (
            "Every value used by this target must stay connected to the same provenance class in ProtocolIR: "
            "fresh generation, setup/state, prior input, successful check/decryption, derived computation, or opaque carry."
        ),
        "abstraction_policy": (
            "Abstraction may rename or package terms/events, but it must preserve derivability, role ownership, "
            "trust boundary, and the protocol stage at which target-relevant evidence becomes available."
        ),
        "outcome_policy": outcome_policy,
        "anti_vacuity_policy": (
            "Do not satisfy the target by deleting events, deleting lemmas, weakening antecedents, replacing formulas "
            "with True, or emitting target events without the protocol evidence they claim."
        ),
    }


def _has_explicit_compromise_model(protocol_ir: dict[str, Any]) -> bool:
    compromise = protocol_ir.get("compromise") if isinstance(protocol_ir.get("compromise"), dict) else {}
    return bool(
        _as_string_list(compromise.get("reveal_events") or compromise.get("reveals"))
        or str(compromise.get("policy") or "").strip()
    )


def _has_mixed_sensitive_expected_outcomes(proof_spec: ProofSpec) -> bool:
    sensitive_states: dict[str, set[str]] = {}
    for item in proof_spec.expectations:
        goal_type = _goal_type(item.goal_type, item.name)
        if goal_type not in {"secrecy", "authentication"}:
            continue
        sensitive_states.setdefault(goal_type, set()).add(item.expected_state)
    return any(
        {"CounterexampleFound", PROVED_SATISFYING}.issubset(states)
        for states in sensitive_states.values()
    )


def _infer_state_stages(protocol_ir: dict[str, Any]) -> list[dict[str, Any]]:
    stages = []
    for action in _as_list(protocol_ir.get("actions")):
        if not isinstance(action, dict):
            continue
        action_id = str(action.get("action_id") or action.get("name") or "")
        material = _as_string_list(action.get("generates")) + _as_string_list(action.get("checks"))
        events = _as_string_list(action.get("events"))
        if material or events:
            stages.append(
                {
                    "action": action_id,
                    "role": action.get("role"),
                    "kind": action.get("kind"),
                    "message_in": _as_string_list(action.get("message_in")),
                    "message_out": _as_string_list(action.get("message_out")),
                    "material_or_checks": material[:8],
                    "events": events[:8],
                    "preserve": "Values/events from this stage should remain after the same derivation/check boundary.",
                }
            )
    return stages


def _infer_target_value_dependencies(
    protocol_ir: dict[str, Any],
    target_lemmas: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    dependencies = []
    target_text = _target_text(target_lemmas)
    for item in _as_list(protocol_ir.get("fresh_terms")):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        dependencies.append(
            {
                "value": name,
                "role": item.get("owner") or item.get("role"),
                "source": "fresh",
                "reason": _target_relevance(name, target_text),
                "preserve": "Generate in the owning role before the first use, and carry only through explicit state, messages, or derivations.",
            }
        )
    for item in _as_list(protocol_ir.get("long_term_keys")):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        dependencies.append(
            {
                "value": name,
                "role": item.get("owner") or item.get("role"),
                "source": "setup_or_role_state",
                "public_term": item.get("public_term"),
                "reason": _target_relevance(name, target_text),
                "preserve": "Keep setup/state material distinct from adversary-controlled network input unless the NL explicitly exposes it.",
            }
        )
    for message in _as_list(protocol_ir.get("messages")):
        if not isinstance(message, dict):
            continue
        label = str(message.get("label") or "")
        dependencies.append(
            {
                "value": label,
                "from": message.get("from"),
                "to": message.get("to"),
                "source": "message",
                "term": message.get("term"),
                "reason": _target_relevance(f"{label} {message.get('term') or ''}", target_text),
                "preserve": "Preserve who creates, observes, checks, derives, or opaquely forwards this message term.",
            }
        )
    return dependencies


def _infer_target_event_dependencies(
    protocol_ir: dict[str, Any],
    target_lemmas: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    dependencies = []
    target_text = _target_text(target_lemmas)
    for event in _as_list(protocol_ir.get("events")):
        if not isinstance(event, dict):
            continue
        name = str(event.get("name") or "")
        args = _as_string_list(event.get("arguments"))
        dependencies.append(
            {
                "event": name,
                "arguments": args,
                "role": event.get("role"),
                "when": event.get("when"),
                "reason": _target_relevance(f"{name} {' '.join(args)}", target_text),
                "preserve": "Emit only at the protocol point where the role has the evidence represented by the event arguments.",
            }
        )
    for target in target_lemmas:
        if not dependencies:
            dependencies.append(
                {
                    "target": target.get("name"),
                    "preserve": "Introduce minimal protocol-specific events only when they summarize real role evidence needed by this target.",
                }
            )
    return dependencies


def _target_text(target_lemmas: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for target in target_lemmas:
        for key in ("name", "goal_type", "trace_kind", "expected_state", "intent"):
            value = target.get(key)
            if value:
                parts.append(str(value))
        parts.extend(_as_string_list(target.get("required_events")))
    return " ".join(parts).lower()


def _target_relevance(candidate: str, target_text: str) -> str:
    tokens = {
        token.lower()
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", candidate)
        if len(token) > 2 and token.lower() not in {"the", "and", "msg", "term"}
    }
    if target_text and any(token in target_text for token in tokens):
        return "directly_named_or_structurally_related_to_a_target"
    return "contextual_protocol_dependency"


def _infer_compromise_model(protocol_ir: dict[str, Any], target_lemmas: list[dict[str, Any]]) -> dict[str, Any]:
    compromise = protocol_ir.get("compromise") if isinstance(protocol_ir.get("compromise"), dict) else {}
    has_compromise = bool(
        _as_string_list(compromise.get("reveal_events") or compromise.get("reveals"))
        or str(compromise.get("policy") or "").strip()
    )
    return {
        "reveal_events": _as_string_list(compromise.get("reveal_events") or compromise.get("reveals")),
        "policy": str(compromise.get("policy") or ""),
        "relevant_targets": [target.get("name") for target in target_lemmas] if has_compromise else [],
        "preserve": "If the IR includes compromise behavior, model the event and its ordering explicitly instead of leaving it implicit.",
    }


def _source_line_map(raw_messages: Any) -> list[dict[str, Any]]:
    source_lines = []
    for message in _as_list(raw_messages):
        if not isinstance(message, dict):
            continue
        label = _fact_suffix(message.get("label") or message.get("step") or "M")
        sender = str(message.get("from") or "")
        receiver = str(message.get("to") or "")
        if not label or not sender or not receiver:
            continue
        source_lines.append(
            {
                "message": label,
                "send_action": f"{sender}_send_{label}",
                "receive_action": f"{receiver}_receive_{label}",
                "sender_role": sender,
                "receiver_role": receiver,
                "term": message.get("term", ""),
                "emit_out_fact_pattern": f"OUT_{label}(m)",
                "emit_in_fact_pattern": f"IN_{label}(m)",
                "policy": "The receive-side IN fact must be justified by an earlier OUT fact or adversary knowledge.",
            }
        )
    return source_lines


def _is_source_goal(target: dict[str, Any]) -> bool:
    goal_type = _goal_type(target.get("goal_type"), target.get("name"))
    return goal_type == "source"


def _knowledge_contract(protocol_ir: dict[str, Any]) -> dict[str, Any]:
    messages = [msg for msg in _as_list(protocol_ir.get("messages")) if isinstance(msg, dict)]
    fresh_terms = [item for item in _as_list(protocol_ir.get("fresh_terms")) if isinstance(item, dict)]
    message_flow = []
    opaque_constraints = []
    for message in messages:
        term = str(message.get("term") or "")
        protection = str(message.get("protection") or _message_protection(term) or "plain")
        crypto_terms = _crypto_terms(term)
        flow = {
            "message": message.get("label"),
            "from": message.get("from"),
            "to": message.get("to"),
            "term": term,
            "protection": protection,
            "crypto_terms": crypto_terms,
            "sender_policy": "Sender must know all plaintext fields or carry the protected term opaquely from a previous input.",
            "receiver_policy": _receiver_policy(protection),
        }
        message_flow.append(flow)
        if crypto_terms and message.get("receiver_can_decrypt") is False:
            opaque_constraints.append(
                {
                    "message": message.get("label"),
                    "role": message.get("to"),
                    "policy": "Receiver cannot destruct this protected term; carry it as an opaque variable if forwarding.",
                }
            )
    return {
        "fresh_ownership": fresh_terms,
        "message_knowledge_flow": message_flow,
        "opaque_forward_constraints": opaque_constraints,
        "state_carrying_policy": [
            "A later event/lemma term must be generated locally, received in plaintext, derived by decryption/check, or carried in role state.",
            "Do not fix unbound variables by inventing unrelated setup facts.",
        ],
    }


def _semantic_assumption_contract(protocol_ir: dict[str, Any], target_lemmas: list[dict[str, Any]]) -> dict[str, Any]:
    messages = [msg for msg in _as_list(protocol_ir.get("messages")) if isinstance(msg, dict)]
    value_sources = []
    for item in _as_list(protocol_ir.get("long_term_keys")):
        if isinstance(item, dict):
            policy = str(item.get("policy") or "").strip()
            value_sources.append(
                {
                    "value": item.get("name"),
                    "owner": item.get("owner") or item.get("role"),
                    "source": "setup_or_role_state",
                    "public_term": item.get("public_term"),
                    "policy": (
                        policy
                        or "Keep private setup/state material distinct from adversary-controlled network input unless an explicit reveal or compromise exposes it."
                    ),
                }
            )
    for item in _as_list(protocol_ir.get("fresh_terms")):
        if isinstance(item, dict):
            value_sources.append(
                {
                    "value": item.get("name"),
                    "owner": item.get("owner") or item.get("role"),
                    "source": "generated",
                    "policy": "Generate this value only in the owner role before use.",
                }
            )
    for message in messages:
        value_sources.append(
            {
                "value": message.get("label"),
                "owner": message.get("to"),
                "source": "network_message",
                "term": message.get("term"),
                "policy": "Values learned from this message require an input, pattern match, decryption, verification, or opaque carry consistent with protection.",
            }
        )
    positive_security_targets = [
        {
            "name": target.get("name"),
            "goal_type": target.get("goal_type"),
            "expected_state": target.get("expected_state"),
        }
        for target in target_lemmas
        if (
            str(target.get("expected_state") or "") == "ProvedSatisfying"
            and _goal_type(target.get("goal_type"), target.get("name")) in {"secrecy", "authentication"}
        )
    ]
    return {
        "purpose": "Keep generated Sapic+ aligned with the abstract protocol semantics, without protocol-specific hard-coded assumptions.",
        "value_sources": value_sources,
        "positive_security_targets": positive_security_targets,
        "semantic_constraints": _as_list(protocol_ir.get("semantic_constraints")),
        "policies": [
            "Preserve value provenance: generated values stay generated, setup/state values stay setup/state, and network inputs remain adversary-controlled unless checked or authenticated.",
            "Resolved open-question answers are binding semantic constraints. Do not override them with stale normalized fields such as `public_term` when they conflict.",
            "If a value's provenance or trust boundary is ambiguous and affects a target lemma, state the modeling assumption in modeling_notes/open_questions instead of silently changing the protocol.",
            "Do not add restrictions solely to make ProvedSatisfying targets pass; add protocol checks/events only when justified by the NL/IR.",
        ],
    }


def _generation_policies(protocol_ir: dict[str, Any], target_lemmas: list[dict[str, Any]]) -> list[str]:
    policies = [
        "Generate from ProtocolIR and derived proof goals as reviewed parser output; do not reinterpret the natural-language protocol after this stage.",
        "Preserve value provenance: setup/state stays setup/state, fresh terms are generated by their owner, network inputs remain adversary-controlled until checked, and derived values stay tied to their derivation.",
        "Preserve ordered check/event boundaries: emit proof events only after the role has the evidence represented by the event arguments.",
        "Keep event payload schemas compact and consistent across roles and lemmas for the same session, secret, transcript, or source value.",
    ]
    if any(str(target.get("expected_state") or "") == "CounterexampleFound" for target in target_lemmas):
        policies.append(
            "For expected CounterexampleFound targets, preserve the reviewed attack surface; do not add protocol checks, restrictions, closed-world principals, or vacuous lemmas solely to make the target prove."
        )
    if any(_is_source_goal(target) for target in target_lemmas):
        policies.append(
            "For explicit source/typing targets, preserve reviewed IN_/OUT_ source facts and their message boundaries; do not add auxiliary source-helper obligations for unrelated targets."
        )
    if _has_explicit_compromise_model(protocol_ir):
        policies.append(
            "Model compromise/reveal events explicitly and preserve which values they expose and how lemma exceptions or ordering depend on them."
        )
    opaque_forwarding = any(
        _as_string_list(message.get("receiver_must_treat_as_opaque")) or message.get("receiver_can_decrypt") is False
        for message in _as_list(protocol_ir.get("messages"))
        if isinstance(message, dict)
    )
    if opaque_forwarding:
        policies.append(
            "Preserve opaque-forwarding boundaries: a role may carry protected terms unchanged, but may not emit proof events over fields it cannot derive."
        )
    return _dedupe_strings(policies)


def _event_obligations(target_lemmas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    obligations = []
    for target in target_lemmas:
        obligations.append(
            {
                "lemma": target.get("name"),
                "goal_type": target.get("goal_type"),
                "required_events": target.get("required_events", []),
                "placement_policy": _placement_policy(str(target.get("goal_type") or "")),
            }
        )
    return obligations


def _required_events_for_goal(goal_type: Any, roles: Any) -> list[str]:
    kind = _goal_type(goal_type)
    first, second = _first_two_roles(roles)
    if kind == "secrecy":
        return [f"Secret({first}, {second}, secret)", "K(secret) in lemma conclusion/attack condition"]
    if kind == "authentication":
        return [f"Running({second}, {first}, session)", f"Commit({first}, {second}, session)"]
    if kind == "executability":
        return [f"Complete({first}, {second}, session) or Commit({first}, {second}, session)"]
    if kind == "source":
        return ["IN_Message(m)", "OUT_Message(m)", "KU(m) only as adversary-source alternative"]
    return ["Protocol-specific event matching the lemma intent"]


def _placement_policy(goal_type: str) -> str:
    kind = _goal_type(goal_type)
    if kind == "secrecy":
        return "Emit Secret only after the role legitimately derives or installs the protected value."
    if kind == "authentication":
        return "Emit Running at the peer's matching start/accept step and Commit only at claimant completion."
    if kind == "executability":
        return "Witness a terminal honest protocol step, not setup-only reachability."
    if kind == "source":
        return "Emit IN_/OUT_ source facts at the actual receive/send steps used by the source lemma."
    return "Place events at semantically meaningful protocol steps."


def _claim_by_name(claims: Any) -> dict[str, dict[str, Any]]:
    result = {}
    for claim in _as_list(claims):
        if isinstance(claim, dict):
            name = str(claim.get("lemma_name") or claim.get("name") or "")
            if name:
                result[name] = claim
    return result


def _check(checks: list[dict[str, Any]], name: str, passed: bool, pass_detail: str, fail_detail: str) -> None:
    checks.append({"name": name, "result": "pass" if passed else "warn", "detail": pass_detail if passed else fail_detail})


def _message_protection(term: str) -> str:
    lower = term.lower()
    if "aenc" in lower or re.search(r"\{.*\}\s*(?:pub|pk|\w+)", term):
        return "asymmetric-encryption"
    if "senc" in lower or "symmetric" in lower:
        return "symmetric-encryption"
    if "sign" in lower or "signature" in lower:
        return "signing"
    if "mac" in lower:
        return "mac"
    if "hash" in lower or "h(" in lower:
        return "hashing"
    return "plain"


def _looks_tagged(term: str) -> bool:
    return bool(re.search(r"'[^']+'|\"[^\"]+\"|\btag\b|<[ \t]*[A-Za-z0-9_]+[ \t]*,", term))


def _crypto_terms(term: str) -> list[dict[str, str]]:
    terms = []
    for name in ("aenc", "senc", "sign", "mac", "h", "hash", "kdf"):
        if re.search(rf"\b{name}\s*\(", term):
            terms.append({"kind": name, "term_hint": name})
    if re.search(r"\{.*\}", term):
        terms.append({"kind": "brace-encryption-notation", "term_hint": "normalize to Sapic+/Tamarin function syntax during generation"})
    return terms


def _receiver_policy(protection: str) -> str:
    if protection == "asymmetric-encryption":
        return "Receiver learns plaintext fields only with matching private-key state; otherwise it forwards ciphertext opaquely."
    if protection == "symmetric-encryption":
        return "Receiver learns plaintext fields only with the symmetric key already in state or derivable from prior messages."
    if protection == "signing":
        return "Receiver verifies authenticity with public verification data; signatures do not reveal private signing keys."
    if protection == "mac":
        return "Receiver checks MACs only with the MAC key; do not infer key ownership from the MAC alone."
    return "Receiver can learn fields exposed in the input pattern."


def _event_text(event: dict[str, Any]) -> str:
    args = ", ".join(_as_string_list(event.get("arguments")))
    return f"{event.get('name')}({args})" if args else str(event.get("name") or "")


def _first_two_roles(roles: Any) -> tuple[str, str]:
    normalized = []
    for role in _as_list(roles):
        if isinstance(role, dict):
            name = _clean_identifier_like(role.get("name") or role.get("role"))
        else:
            name = _clean_identifier_like(role)
        if name:
            normalized.append(name)
    if not normalized:
        return "A", "B"
    if len(normalized) == 1:
        return normalized[0], "peer"
    return normalized[0], normalized[1]


def _goal_type(value: Any = "", name: Any = "") -> str:
    raw = str(value or "").lower()
    if raw in {"auth", "authentication", "agreement", "injective_agreement"}:
        return "authentication"
    if raw in {"secret", "secrecy"}:
        return "secrecy"
    if raw in {"exec", "executability", "reachability", "exists-trace"}:
        return "executability"
    if raw in {"source", "typing", "sources"}:
        return "source"
    if raw in {"property", "invariant"}:
        return "property"
    return infer_goal_type(str(name or ""), "")


def _case_source_text(case: ProtocolCase) -> str:
    parts = [case.description]
    if case.assumptions:
        parts.append("\n".join(str(item) for item in case.assumptions))
    for goal in case.goals:
        parts.append(jsonish(goal))
    return "\n".join(part for part in parts if str(part or "").strip())


def _field_evidence_by_path(protocol_ir: dict[str, Any], source_text: str) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for item in _as_list(protocol_ir.get("field_evidence")):
        if not isinstance(item, dict):
            continue
        path = _normalize_review_path(item.get("field_path") or item.get("path"))
        if not path:
            continue
        quote = str(item.get("source_quote") or item.get("quote") or "").strip()
        kind = str(item.get("evidence_kind") or item.get("kind") or "").strip().lower() or "direct"
        evidence = _source_evidence_entry(quote, source_text, kind=kind, reason=str(item.get("reason") or ""))
        result.setdefault(path, []).append(evidence)
    for path in _core_evidence_paths(protocol_ir):
        if path in result:
            continue
        value = _get_dotted(protocol_ir, path)
        quote = _best_source_quote_for_value(value, source_text)
        result[path] = [_source_evidence_entry(quote, source_text, kind="direct" if quote else "none")]
    return result


def _source_evidence_entry(quote: str, source_text: str, *, kind: str, reason: str = "") -> dict[str, Any]:
    quote = str(quote or "").strip()
    # "inferred" is the paper-facing synonym of "nearby"; do not let it fall
    # through to the "direct" default, which would inflate evidence confidence.
    kind = {"inferred": "nearby"}.get(kind, kind)
    kind = kind if kind in {"direct", "nearby", "assumption", "none"} else "direct"
    start = -1
    end = -1
    if quote:
        start = source_text.find(quote)
        if start < 0:
            start = source_text.lower().find(quote.lower())
        if start >= 0:
            end = start + len(quote)
        else:
            kind = "nearby" if kind == "direct" else kind
    else:
        kind = "none"
    payload: dict[str, Any] = {
        "kind": kind,
        "quote": quote,
        "char_start": start if start >= 0 else None,
        "char_end": end if end >= 0 else None,
    }
    if reason:
        payload["reason"] = reason
    return payload


def _core_evidence_paths(protocol_ir: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for section in ("fresh_terms", "long_term_keys", "messages", "checks", "events", "claims"):
        for index, item in enumerate(_as_list(protocol_ir.get(section))):
            if not isinstance(item, dict):
                continue
            for key in item:
                if key in {"field_evidence", "source_evidence"}:
                    continue
                value = item.get(key)
                if value not in (None, "", [], {}):
                    paths.append(f"{section}.{index}.{key}")
    if isinstance(protocol_ir.get("compromise"), dict):
        for key, value in protocol_ir["compromise"].items():
            if value not in (None, "", [], {}):
                paths.append(f"compromise.{key}")
    return paths


def _best_source_quote_for_value(value: Any, source_text: str) -> str:
    candidates: list[str] = []
    if isinstance(value, list):
        candidates.extend(str(item) for item in value if item)
    elif isinstance(value, dict):
        candidates.extend(str(item) for item in value.values() if isinstance(item, (str, int, float)))
    else:
        candidates.append(str(value or ""))
    for candidate in candidates:
        text = candidate.strip()
        if len(text) < 2:
            continue
        if text in source_text:
            return text
        if text.lower() in source_text.lower():
            return text
    for candidate in candidates:
        tokens = [token for token in re.findall(r"[A-Za-z0-9_~$]+", candidate) if len(token) >= 2]
        for token in tokens:
            if token in source_text or token.lower() in source_text.lower():
                return token
    return ""


def _consistency_diagnostics_by_path(
    protocol_ir: dict[str, Any],
    validation: dict[str, Any],
    proof_context: dict[str, Any],
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for warning in _as_string_list(validation.get("warnings")):
        for path in _paths_for_warning(protocol_ir, warning):
            result.setdefault(path, []).append(warning)
    for error in _as_string_list(validation.get("errors")):
        for path in _paths_for_warning(protocol_ir, error):
            result.setdefault(path, []).append(error)
    _diagnose_event_required_mismatch(protocol_ir, proof_context, result)
    _diagnose_event_before_check(protocol_ir, result)
    _diagnose_value_class_conflicts(protocol_ir, result)
    _diagnose_derivability_risks(protocol_ir, result)
    return result


def _paths_for_warning(protocol_ir: dict[str, Any], warning: str) -> list[str]:
    text = str(warning or "")
    paths: list[str] = []
    for section in ("messages", "fresh_terms", "long_term_keys", "claims", "checks", "events"):
        for index, item in enumerate(_as_list(protocol_ir.get(section))):
            if not isinstance(item, dict):
                continue
            label = str(item.get("label") or item.get("name") or item.get("lemma_name") or "")
            if label and label in text:
                key = "term" if section == "messages" else "name"
                if section == "claims":
                    key = "lemma_name"
                paths.append(f"{section}.{index}.{key}")
    if "claim" in text.lower() or "lemma" in text.lower():
        paths.extend(f"claims.{index}.lemma_name" for index, _item in enumerate(_as_list(protocol_ir.get("claims"))))
    return paths or ["modeling_assumptions.0"]


def _diagnose_event_required_mismatch(protocol_ir: dict[str, Any], proof_context: dict[str, Any], result: dict[str, list[str]]) -> None:
    event_signatures = {_event_signature(event): index for index, event in enumerate(_as_list(protocol_ir.get("events"))) if isinstance(event, dict)}
    event_names = {_event_name(signature) for signature in event_signatures}
    for target_index, target in enumerate(_as_list(proof_context.get("target_lemmas"))):
        if not isinstance(target, dict):
            continue
        missing = []
        for required in _as_string_list(target.get("required_events")):
            if required and required not in event_signatures and _event_name(required) not in event_names:
                missing.append(required)
        if missing:
            path = f"claims.{target_index}.event_schema"
            result.setdefault(path, []).append(f"Required proof event(s) not emitted with matching schema: {missing}.")


def _diagnose_event_before_check(protocol_ir: dict[str, Any], result: dict[str, list[str]]) -> None:
    checks_by_role_message = {
        (str(check.get("role") or ""), str(check.get("source_message") or ""))
        for check in _as_list(protocol_ir.get("checks"))
        if isinstance(check, dict) and str(check.get("condition") or "").strip()
    }
    for event_index, event in enumerate(_as_list(protocol_ir.get("events"))):
        if not isinstance(event, dict):
            continue
        role = str(event.get("role") or "")
        source_message = str(event.get("source_message") or "")
        when = str(event.get("when") or "")
        if source_message and (role, source_message) not in checks_by_role_message and any(token in when.lower() for token in ("accept", "complete", "verify", "decrypt")):
            result.setdefault(f"events.{event_index}.when", []).append(
                f"Event is tied to {source_message}, but no local check/decrypt/verify record for role {role or '<unknown>'} was found."
            )


def _diagnose_value_class_conflicts(protocol_ir: dict[str, Any], result: dict[str, list[str]]) -> None:
    fresh_names = {str(item.get("name") or ""): index for index, item in enumerate(_as_list(protocol_ir.get("fresh_terms"))) if isinstance(item, dict)}
    key_names = {str(item.get("name") or ""): index for index, item in enumerate(_as_list(protocol_ir.get("long_term_keys"))) if isinstance(item, dict)}
    for name in sorted(set(fresh_names).intersection(key_names)):
        if not name:
            continue
        result.setdefault(f"fresh_terms.{fresh_names[name]}.name", []).append(
            f"Value `{name}` is classified as both fresh/per-session and long-term/setup."
        )
        result.setdefault(f"long_term_keys.{key_names[name]}.name", []).append(
            f"Value `{name}` is classified as both fresh/per-session and long-term/setup."
        )


def _diagnose_derivability_risks(protocol_ir: dict[str, Any], result: dict[str, list[str]]) -> None:
    key_owners: dict[str, str] = {}
    for key in _as_list(protocol_ir.get("long_term_keys")):
        if isinstance(key, dict):
            name = str(key.get("name") or "")
            owner = str(key.get("owner") or "")
            if name:
                key_owners[name] = owner
    for index, message in enumerate(_as_list(protocol_ir.get("messages"))):
        if not isinstance(message, dict):
            continue
        receiver = str(message.get("to") or "")
        term = str(message.get("term") or "")
        if _message_protection(term) in {"symmetric-encryption", "asymmetric-encryption"} and message.get("receiver_can_decrypt") is False:
            result.setdefault(f"messages.{index}.receiver_can_decrypt", []).append(
                f"Receiver {receiver or '<unknown>'} is marked unable to decrypt a protected message; later checks/events must not depend on hidden plaintext."
            )
        for key_name, owner in key_owners.items():
            if key_name and key_name in term and receiver and owner and receiver not in owner.split("/"):
                if message.get("receiver_can_decrypt") is True:
                    result.setdefault(f"messages.{index}.receiver_can_decrypt", []).append(
                        f"Message uses `{key_name}` owned by `{owner}`; confirm receiver `{receiver}` can derive the decryption key."
                    )


def _reviewable_field_paths(
    protocol_ir: dict[str, Any],
    proof_context: dict[str, Any],
    diagnostics_by_path: dict[str, list[str]],
    evidence_by_path: dict[str, list[dict[str, Any]]],
) -> set[str]:
    paths = set(evidence_by_path) | set(diagnostics_by_path)
    for section in ("claims", "events", "checks", "messages", "fresh_terms", "long_term_keys"):
        for index, item in enumerate(_as_list(protocol_ir.get(section))):
            if not isinstance(item, dict):
                continue
            keys = {
                "claims": ("lemma_name", "goal_type", "trace_kind", "expected_state", "event_schema", "intent", "witness"),
                "events": ("name", "role", "when", "arguments", "proof_relevance"),
                "checks": ("role", "condition", "source_message", "action"),
                "messages": ("label", "from", "to", "term", "protection", "receiver_can_decrypt", "receiver_must_treat_as_opaque"),
                "fresh_terms": ("name", "owner", "purpose"),
                "long_term_keys": ("name", "owner", "public_term", "policy"),
            }[section]
            for key in keys:
                if key in item and item.get(key) not in (None, "", [], {}):
                    paths.add(f"{section}.{index}.{key}")
    if isinstance(protocol_ir.get("compromise"), dict):
        for key in protocol_ir["compromise"]:
            paths.add(f"compromise.{key}")
    for index, _target in enumerate(_as_list(proof_context.get("target_lemmas"))):
        if f"claims.{index}.expected_state" not in paths:
            paths.add(f"claims.{index}.expected_state")
    return paths


def _semantic_impact_for_path(path: str, protocol_ir: dict[str, Any], proof_context: dict[str, Any]) -> str:
    if path.startswith("claims.") or path.startswith("events.") or path.startswith("checks.") or path.startswith("compromise."):
        return "high"
    if "expected_state" in path or "event_schema" in path or "required_events" in path:
        return "high"
    if path.startswith("messages.") and any(token in path for token in ("term", "protection", "receiver_can_decrypt", "receiver_must_treat_as_opaque")):
        return "medium"
    if path.startswith("fresh_terms.") or path.startswith("long_term_keys."):
        return "medium"
    return "low"


def _evidence_confidence(evidence: list[dict[str, Any]]) -> str:
    if any(item.get("kind") == "direct" and item.get("char_start") is not None for item in evidence):
        return "high"
    if any(item.get("kind") in {"direct", "nearby", "assumption"} and item.get("quote") for item in evidence):
        return "medium"
    return "low"


def _formula_priority(
    evidence_confidence: str,
    consistency_confidence: str,
    semantic_impact: str,
    *,
    evidence_confidence_score: float | None = None,
    consistency_confidence_score: float | None = None,
    semantic_impact_score: float | None = None,
) -> float:
    evidence_score = evidence_confidence_score if evidence_confidence_score is not None else _label_score(evidence_confidence)
    consistency_score = (
        consistency_confidence_score
        if consistency_confidence_score is not None
        else _label_score(consistency_confidence)
    )
    impact = semantic_impact_score if semantic_impact_score is not None else _label_score(semantic_impact)
    uncertainty = max(1.0 - evidence_score, 1.0 - consistency_score)
    return round(_clamp(uncertainty * impact), 3)


def _llm_priority_for_path(protocol_ir: dict[str, Any], path: str) -> float | None:
    for item in _as_list(protocol_ir.get("field_evidence")):
        if not isinstance(item, dict):
            continue
        if _normalize_review_path(item.get("field_path") or item.get("path")) != path:
            continue
        priority = _score_or_none(item.get("priority_llm"))
        if priority is not None:
            return priority
    return None


def _llm_review_scores_for_path(protocol_ir: dict[str, Any], path: str) -> dict[str, float]:
    scores: dict[str, float] = {}
    for item in _as_list(protocol_ir.get("field_evidence")):
        if not isinstance(item, dict):
            continue
        if _normalize_review_path(item.get("field_path") or item.get("path")) != path:
            continue
        for key in ("evidence_confidence_score", "consistency_confidence_score", "semantic_impact_score"):
            score = _score_or_none(item.get(key))
            if score is not None:
                scores[key] = score
        break
    return scores


def _score_label(score: float | None, *, fallback: str) -> str:
    if score is None:
        return fallback
    if score >= 0.7:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"


def _label_score(label: str) -> float:
    return {"high": 1.0, "medium": 0.5, "low": 0.0}.get(str(label or "").lower(), 0.5)


def _score_or_none(value: Any) -> float | None:
    number = _number_or_none(value)
    if number is None:
        return None
    if number > 1.0:
        number = number / 100.0
    return _clamp(number)


def _priority_level(score: float) -> str:
    if score >= 0.7:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"


def _review_status_for_field(
    *,
    priority_level: str,
    evidence_confidence: str,
    consistency_confidence: str,
    diagnostics: list[str],
) -> str:
    if priority_level == "high" or consistency_confidence == "low":
        return "must_review"
    if priority_level == "medium" or evidence_confidence != "high" or diagnostics:
        return "needs_review"
    return "high_confidence"


def _suggested_review_action(path: str, review_status: str, diagnostics: list[str], impact: str) -> str:
    if review_status == "high_confidence":
        return "No action needed unless the source description was interpreted incorrectly."
    if path.startswith("claims."):
        return "Review this proof target first; confirm the lemma name, expected outcome, event schema, and intended security property."
    if path.startswith("events."):
        return "Confirm the event is emitted only after the role can derive and check every event argument."
    if path.startswith("checks."):
        return "Confirm this local check is explicitly required by the source protocol or intentionally absent."
    if path.startswith("compromise."):
        return "Confirm reveal scope and timing before generating secrecy or authentication lemmas."
    if diagnostics:
        return "Inspect the diagnostic, then edit, confirm, or mark this as an intentional assumption."
    if impact == "medium":
        return "Check provenance and derivability before confirming this field."
    return "Confirm or mark as a system/default assumption."


def _normalize_review_path(value: Any) -> str:
    path = str(value or "").strip().strip("/")
    path = path.replace("/", ".")
    aliases = {
        "fresh": "fresh_terms",
        "setup": "long_term_keys",
        "proof_targets": "claims",
    }
    parts = [part for part in path.split(".") if part != ""]
    if not parts:
        return ""
    parts[0] = aliases.get(parts[0], parts[0])
    return ".".join(parts)


def _get_dotted(root: Any, path: str) -> Any:
    current = root
    for part in path.split("."):
        if isinstance(current, list):
            if not part.isdigit():
                return None
            index = int(part)
            if index < 0 or index >= len(current):
                return None
            current = current[index]
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _event_signature(event: dict[str, Any]) -> str:
    name = str(event.get("name") or "")
    args = _as_string_list(event.get("arguments"))
    return f"{name}({','.join(args)})" if args else name


def _event_name(signature: str) -> str:
    return str(signature or "").split("(", 1)[0].strip()


def _number_or_none(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return round(max(low, min(high, value)), 3)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _as_string_list(value: Any) -> list[str]:
    result = []
    for item in _as_list(value):
        if item is None:
            continue
        if isinstance(item, dict):
            text = item.get("name") or item.get("term") or item.get("value") or item.get("description")
        else:
            text = item
        text = str(text or "").strip()
        if text:
            result.append(text)
    return result


def _dedupe_strings(items: list[str]) -> list[str]:
    result = []
    seen = set()
    for item in items:
        text = str(item)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _constraint_values_from_answer(answer: str, known_values: list[dict[str, str]], fallback_kind: str) -> list[dict[str, str]]:
    answer_lc = answer.lower()
    values: list[dict[str, str]] = []
    for item in known_values:
        if not isinstance(item, dict):
            continue
        names = [
            str(item.get("name") or "").strip(),
            str(item.get("public_term") or "").strip(),
            str(item.get("owner") or "").strip(),
        ]
        if any(name and name.lower() in answer_lc for name in names):
            values.append(
                {
                    "name": str(item.get("name") or ""),
                    "owner": str(item.get("owner") or item.get("role") or ""),
                    "public_term": str(item.get("public_term") or ""),
                }
            )
    for token in re.findall(r"\b[A-Z][A-Za-z0-9_]*\b|~[A-Za-z][A-Za-z0-9_]*", answer):
        if token in {"A", "B", "C", "S", "Trusted", "Freshly", "Network", "Do"}:
            continue
        if not any(value.get("name") == token for value in values):
            values.append({"name": token, "owner": "", "public_term": "", "source": fallback_kind})
    return values[:12]


def _dedupe_constraint_dicts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for item in items:
        key = jsonish(
            {
                "kind": item.get("kind"),
                "question_id": item.get("question_id"),
                "policy": item.get("policy"),
                "values": item.get("values"),
                "messages": item.get("messages"),
            }
        )
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _compact_signals(*values: Any, limit: int = 12) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        for item in _as_list(value):
            if item is None:
                continue
            if isinstance(item, dict):
                text = str(
                    item.get("label")
                    or item.get("name")
                    or item.get("lemma_name")
                    or item.get("value")
                    or item.get("term")
                    or jsonish(item)
                )
            else:
                text = str(item)
            text = re.sub(r"\s+", " ", text).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            result.append(text[:180])
            if len(result) >= limit:
                return result
    return result


def _message_labels(messages: list[dict[str, Any]]) -> list[str]:
    return [str(message.get("label") or "") for message in messages if str(message.get("label") or "")]


def _value_names(values: list[dict[str, Any]]) -> list[str]:
    names = []
    for value in values:
        name = str(value.get("name") or value.get("value") or "").strip()
        owner = str(value.get("owner") or value.get("role") or "").strip()
        if name and owner:
            names.append(f"{name}@{owner}")
        elif name:
            names.append(name)
    return names


def _append_unique(values: list[str], value: Any) -> None:
    text = str(value or "").strip()
    if text and text not in values:
        values.append(text)


def _clean_identifier_like(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.strip("'\"")
    return re.sub(r"[^A-Za-z0-9_]", "_", text).strip("_") or text


def _fact_suffix(value: Any) -> str:
    text = _clean_identifier_like(value)
    if not text:
        return "M"
    if text[0].isdigit():
        return f"M{text}"
    return text


def _int_or_default(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _maybe_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"true", "yes", "1"}:
        return True
    if text in {"false", "no", "0"}:
        return False
    return None


def _dedupe_dicts(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        marker = str(item.get(key) or "")
        if marker and marker in seen:
            continue
        if marker:
            seen.add(marker)
        result.append(item)
    return result


def jsonish(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        return " ".join(f"{jsonish(k)} {jsonish(v)}" for k, v in value.items())
    if isinstance(value, list):
        return " ".join(jsonish(item) for item in value)
    return str(value)
