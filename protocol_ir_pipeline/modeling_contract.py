from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .cases import ProtocolCase
from .ir import build_proof_context
from .proofspec import ProofSpec


CONTRACT_SCHEMA = "protocol_ir_pipeline_modeling_contract_v1"


def build_modeling_contract(
    case: ProtocolCase,
    proof_spec: ProofSpec,
    ir_bundle: dict[str, Any],
    *,
    plan: dict[str, Any] | None = None,
    assumption_ledger: dict[str, Any] | None = None,
    source: str = "protocol_ir",
    include_review_questions: bool = False,
) -> dict[str, Any]:
    """Build a reviewable modeling contract before Sapic+ generation.

    The contract deliberately repeats the proof-relevant provenance, checks,
    event placement, and expected attack surface in a compact shape. It is a
    human-review interface, not a replacement for ProtocolIR.
    """

    protocol_ir = _as_dict(ir_bundle.get("protocol_ir"))
    validation = _as_dict(ir_bundle.get("validation"))
    proof_context = _as_dict(ir_bundle.get("proof_context") or ir_bundle.get("proof_contract"))
    if not proof_context:
        proof_context = build_proof_context(
            case,
            protocol_ir,
            proof_spec,
            validation,
            include_semantic_review_questions=include_review_questions,
        )
    boundary = _as_dict(proof_context.get("preservation_boundary"))
    ledger = assumption_ledger if isinstance(assumption_ledger, dict) else {}
    messages = [_as_dict(item) for item in _as_list(protocol_ir.get("messages")) if isinstance(item, dict)]
    actions = [_as_dict(item) for item in _as_list(protocol_ir.get("actions")) if isinstance(item, dict)]
    target_lemmas = [_as_dict(item) for item in _as_list(proof_context.get("target_lemmas")) if isinstance(item, dict)]
    semantic_questions = _semantic_questions(proof_context, ledger) if include_review_questions else []
    open_questions = _open_questions(protocol_ir, plan, semantic_questions, ledger) if include_review_questions else []

    return {
        "schema": CONTRACT_SCHEMA,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "source": source,
        "case": {
            "name": case.name,
            "difficulty": case.difficulty,
            "goal_mode": proof_spec.mode,
            "proof_spec_source": proof_spec.source,
        },
        "risk": {
            "level": ledger.get("risk_level") or _risk_level_from_boundary(boundary, validation, target_lemmas),
            "score": ledger.get("risk_score"),
            "triggers": ledger.get("risk_triggers") or _risk_triggers(boundary, validation, target_lemmas),
            "preservation_boundary_needed": boundary.get("needed"),
            "preservation_boundary_score": boundary.get("score"),
            "validation_ok": validation.get("ok"),
            "validation_warnings": validation.get("warnings", []),
        },
        "roles": _as_list(protocol_ir.get("roles")),
        "setup": _setup_section(protocol_ir),
        "fresh": _fresh_section(protocol_ir),
        "state_and_derived": _state_and_derived_section(protocol_ir, proof_context),
        "messages": [_message_entry(message, actions) for message in messages],
        "checks": _checks_section(protocol_ir, actions),
        "events": _events_section(protocol_ir, proof_context),
        "proof_targets": [_proof_target_entry(target) for target in target_lemmas],
        "expected_attack_surface": _expected_attack_surface(target_lemmas, semantic_questions, protocol_ir, boundary),
        "abstraction_boundary": _abstraction_boundary(protocol_ir, proof_context, semantic_questions),
        "compromise": _as_dict(protocol_ir.get("compromise")),
        "open_questions": open_questions,
        "field_reviews": _field_reviews_section(ir_bundle),
        "source_artifacts": {
            "protocol_ir": "ir/protocol_ir.json",
            "field_reviews": "ir/field_reviews.json",
            "proof_context": "derived from ProtocolIR and proof/spec.initial.json",
            "assumption_ledger": "ir/assumption_ledger.json",
        },
    }


def render_modeling_contract_markdown(contract: dict[str, Any]) -> str:
    lines: list[str] = []
    case = _as_dict(contract.get("case"))
    risk = _as_dict(contract.get("risk"))
    lines.append(f"# Modeling Contract: {case.get('name') or 'Protocol'}")
    lines.append("")
    lines.append("## Review Status")
    lines.append(f"- Difficulty: {_display(case.get('difficulty'))}")
    lines.append(f"- Goal mode: {_display(case.get('goal_mode'))}")
    lines.append(f"- Proof source: {_display(case.get('proof_spec_source'))}")
    lines.append(f"- Risk: {_display(risk.get('level'))} ({_display(risk.get('score'))})")
    lines.append(f"- Preservation boundary: {_yes_no(risk.get('preservation_boundary_needed'))} (score {_display(risk.get('preservation_boundary_score'))})")
    warnings = _as_list(risk.get("validation_warnings"))
    if warnings:
        lines.append("- Validation warnings:")
        for warning in warnings:
            lines.append(f"  - {_md(warning)}")
    triggers = _as_list(risk.get("triggers"))
    if triggers:
        lines.append("- Risk triggers:")
        for trigger in triggers:
            lines.append(f"  - {_md(trigger)}")
    field_reviews = _as_list(contract.get("field_reviews"))
    if field_reviews:
        must = sum(1 for item in field_reviews if isinstance(item, dict) and item.get("review_status") == "must_review")
        needs = sum(1 for item in field_reviews if isinstance(item, dict) and item.get("review_status") == "needs_review")
        confirmed = sum(1 for item in field_reviews if isinstance(item, dict) and item.get("review_status") == "user_confirmed")
        lines.append(f"- Field review: {must} must review, {needs} needs review, {confirmed} confirmed.")

    lines.append("")
    lines.append("## Roles")
    for role in _as_list(contract.get("roles")):
        lines.append(f"- `{role}`")
    if not _as_list(contract.get("roles")):
        lines.append("- None recorded.")

    lines.append("")
    lines.append("## Setup / State / Fresh")
    setup = _as_list(contract.get("setup"))
    fresh = _as_list(contract.get("fresh"))
    state_and_derived = _as_dict(contract.get("state_and_derived"))
    lines.append("### Setup")
    _append_records(lines, setup, fields=("name", "owner", "public_term", "policy"), empty="No setup values recorded.")
    lines.append("### Fresh")
    _append_records(lines, fresh, fields=("name", "owner", "purpose"), empty="No fresh values recorded.")
    lines.append("### Derived / Carried")
    _append_records(lines, _as_list(state_and_derived.get("value_dependencies")), fields=("value", "role", "source", "preserve"), empty="No derived value dependencies recorded.")

    lines.append("")
    lines.append("## Messages And Checks")
    messages = _as_list(contract.get("messages"))
    if not messages:
        lines.append("- No messages recorded.")
    for message in messages:
        if not isinstance(message, dict):
            continue
        lines.append(f"### {message.get('label') or 'Message'}")
        lines.append(f"- Flow: `{_display(message.get('from'))} -> {_display(message.get('to'))}`")
        lines.append(f"- Term: `{_display(message.get('term'))}`")
        if message.get("meaning"):
            lines.append(f"- Meaning: {_md(message.get('meaning'))}")
        lines.append(f"- Protection: {_display(message.get('protection'))}")
        lines.append(f"- Receiver can decrypt: {_yes_no(message.get('receiver_can_decrypt'))}")
        checks = _as_list(message.get("checks"))
        if checks:
            lines.append("- Checks:")
            for check in checks:
                lines.append(f"  - {_md(check)}")
        events = _as_list(message.get("events_after"))
        if events:
            lines.append("- Events after this boundary:")
            for event in events:
                lines.append(f"  - `{event}`")

    lines.append("")
    lines.append("## Events")
    _append_records(lines, _as_list(contract.get("events")), fields=("name", "role", "when", "arguments"), empty="No events recorded.")

    lines.append("")
    lines.append("## Proof Targets")
    proof_targets = _as_list(contract.get("proof_targets"))
    if not proof_targets:
        lines.append("- No proof targets recorded.")
    for target in proof_targets:
        if not isinstance(target, dict):
            continue
        lines.append(
            f"- `{target.get('name')}`: {target.get('goal_type') or 'property'}, "
            f"expected `{target.get('expected_state') or 'unknown'}`"
        )
        if target.get("intent"):
            lines.append(f"  - Intent: {_md(target.get('intent'))}")
        required_events = _as_list(target.get("required_events"))
        if required_events:
            lines.append(f"  - Required events: {', '.join(f'`{event}`' for event in required_events)}")
        if target.get("preservation_policy"):
            lines.append(f"  - Preserve: {_md(target.get('preservation_policy'))}")

    lines.append("")
    lines.append("## Expected Attack Surface")
    attack_surface = _as_list(contract.get("expected_attack_surface"))
    if attack_surface:
        for item in attack_surface:
            if isinstance(item, dict):
                lines.append(f"- `{item.get('target')}`: {_md(item.get('policy'))}")
            else:
                lines.append(f"- {_md(item)}")
    else:
        lines.append("- No expected counterexample target recorded.")

    lines.append("")
    lines.append("## Abstraction Boundary")
    abstraction = _as_dict(contract.get("abstraction_boundary"))
    _append_text_items(lines, abstraction.get("must_preserve"), "Must preserve")
    _append_text_items(lines, abstraction.get("may_abstract"), "May abstract")
    _append_text_items(lines, abstraction.get("assumptions"), "Assumptions")

    lines.append("")
    lines.append("## Open Questions")
    open_questions = _as_list(contract.get("open_questions"))
    if open_questions:
        for question in open_questions:
            if isinstance(question, dict):
                qid = question.get("id") or "question"
                lines.append(f"- `{qid}`: {_md(question.get('question') or question.get('answer') or question)}")
                lines.append(f"  - Review status: `{_display(question.get('review_status') or 'needs_review')}`")
                if question.get("proposed_answer"):
                    lines.append(f"  - LLM proposed answer: {_md(question.get('proposed_answer'))}")
                if question.get("proposed_resolution"):
                    lines.append(f"  - LLM proposed resolution: {_md(question.get('proposed_resolution'))}")
                if question.get("proposal_confidence"):
                    lines.append(f"  - Proposal confidence: {_md(question.get('proposal_confidence'))}")
                if question.get("why"):
                    lines.append(f"  - Why: {_md(question.get('why'))}")
                if question.get("default_if_unanswered"):
                    lines.append(f"  - Default: {_md(question.get('default_if_unanswered'))}")
                if question.get("answer"):
                    lines.append(f"  - Reviewed answer: {_md(question.get('answer'))}")
                if question.get("resolution"):
                    lines.append(f"  - Reviewed resolution: {_md(question.get('resolution'))}")
            else:
                lines.append(f"- {_md(question)}")
    else:
        lines.append("- None.")

    lines.append("")
    return "\n".join(lines)


def write_modeling_contract_artifacts(
    output_dir: Path,
    contract: dict[str, Any],
    *,
    json_name: str = "modeling_contract.json",
    markdown_name: str = "modeling_contract.md",
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / json_name
    markdown_path = output_dir / markdown_name
    json_path.write_text(json.dumps(contract, indent=2, ensure_ascii=False), encoding="utf-8")
    markdown_path.write_text(render_modeling_contract_markdown(contract), encoding="utf-8")
    return json_path, markdown_path


def load_modeling_contract_inputs(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    ir_dir = run_dir / "ir"
    protocol_ir = _read_json(ir_dir / "protocol_ir.json")
    proof_context = _read_json(ir_dir / "proof_context.json") or _read_json(ir_dir / "proof_contract.json")
    validation = _read_json(ir_dir / "validation.json")
    field_reviews = _read_json(ir_dir / "field_reviews.json")
    assumption_ledger = _read_json(ir_dir / "assumption_ledger.json")
    return (
        {
            "protocol_ir": protocol_ir,
            "proof_context": proof_context,
            "validation": validation,
            "field_reviews": field_reviews.get("field_reviews", []) if isinstance(field_reviews, dict) else [],
        },
        assumption_ledger,
        _read_json(run_dir / "input" / "case.json"),
    )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _setup_section(protocol_ir: dict[str, Any]) -> list[dict[str, Any]]:
    setup: list[dict[str, Any]] = []
    for item in _as_list(protocol_ir.get("long_term_keys")):
        if isinstance(item, dict):
            setup.append(
                {
                    "name": item.get("name"),
                    "owner": item.get("owner"),
                    "public_term": item.get("public_term"),
                    "policy": item.get("policy")
                    or "Treat as setup/state knowledge owned by the role; do not learn it from the adversarial network.",
                }
            )
    for assumption in _as_list(_as_dict(protocol_ir.get("crypto")).get("assumptions")):
        setup.append({"name": "assumption", "owner": "", "public_term": "", "policy": str(assumption)})
    return setup


def _fresh_section(protocol_ir: dict[str, Any]) -> list[dict[str, Any]]:
    fresh = []
    for item in _as_list(protocol_ir.get("fresh_terms")):
        if not isinstance(item, dict):
            continue
        fresh.append(
            {
                "name": item.get("name"),
                "owner": item.get("owner") or item.get("role"),
                "purpose": item.get("purpose"),
            }
        )
    return fresh


def _field_reviews_section(ir_bundle: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in _as_list(ir_bundle.get("field_reviews")):
        if not isinstance(item, dict):
            continue
        review = dict(item)
        field_path = _contract_field_path(str(review.get("field_path") or ""))
        if not field_path:
            continue
        review["field_path"] = field_path
        review["section"] = field_path.split(".", 1)[0]
        review.setdefault("review_status", "needs_review")
        review.setdefault("review_decision", "")
        result.append(review)
    return result


def _contract_field_path(path: str) -> str:
    parts = [part for part in str(path or "").split(".") if part != ""]
    if not parts:
        return ""
    section_map = {
        "fresh_terms": "fresh",
        "long_term_keys": "setup",
        "claims": "proof_targets",
    }
    key_map = {
        "lemma_name": "name",
        "event_schema": "required_events",
    }
    parts[0] = section_map.get(parts[0], parts[0])
    parts[-1] = key_map.get(parts[-1], parts[-1])
    return ".".join(parts)


def _state_and_derived_section(protocol_ir: dict[str, Any], proof_context: dict[str, Any]) -> dict[str, Any]:
    semantic_contract = _as_dict(proof_context.get("semantic_assumption_contract"))
    boundary = _as_dict(proof_context.get("preservation_boundary"))
    constraints = _as_dict(boundary.get("constraints"))
    return {
        "value_sources": _as_list(semantic_contract.get("value_sources")),
        "value_dependencies": _as_list(constraints.get("value_dependencies")),
        "state_stages": _as_list(constraints.get("state_stages")) or _as_list(protocol_ir.get("actions")),
    }


def _message_entry(message: dict[str, Any], actions: list[dict[str, Any]]) -> dict[str, Any]:
    label = str(message.get("label") or "")
    related_actions = [
        action
        for action in actions
        if label in [str(item) for item in _as_list(action.get("message_in")) + _as_list(action.get("message_out"))]
    ]
    checks = []
    events_after = []
    for action in related_actions:
        checks.extend(str(item) for item in _as_list(action.get("checks")) if str(item))
        events_after.extend(str(item) for item in _as_list(action.get("events")) if str(item))
    return {
        "label": label,
        "step": message.get("step"),
        "from": message.get("from"),
        "to": message.get("to"),
        "term": message.get("term"),
        "meaning": message.get("meaning"),
        "protection": message.get("protection"),
        "receiver_can_decrypt": message.get("receiver_can_decrypt"),
        "receiver_must_treat_as_opaque": message.get("receiver_must_treat_as_opaque", []),
        "checks": _dedupe(checks),
        "events_after": _dedupe(events_after),
    }


def _checks_section(protocol_ir: dict[str, Any], actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks = []
    for item in _as_list(protocol_ir.get("checks")):
        if isinstance(item, dict):
            checks.append(item)
        elif str(item):
            checks.append({"condition": str(item)})
    for action in actions:
        for check in _as_list(action.get("checks")):
            if str(check):
                checks.append(
                    {
                        "role": action.get("role"),
                        "condition": str(check),
                        "source_message": ", ".join(str(value) for value in _as_list(action.get("message_in"))),
                        "action": action.get("action_id") or action.get("action"),
                    }
                )
    return _dedupe_dicts(checks)


def _events_section(protocol_ir: dict[str, Any], proof_context: dict[str, Any]) -> list[dict[str, Any]]:
    events = []
    for item in _as_list(protocol_ir.get("events")):
        if isinstance(item, dict):
            events.append(item)
    obligations = {str(item.get("lemma")): item for item in _as_list(proof_context.get("event_obligations")) if isinstance(item, dict)}
    for event in events:
        event["proof_relevance"] = [
            obligation.get("lemma")
            for obligation in obligations.values()
            if any(str(event.get("name") or "") in str(required) for required in _as_list(obligation.get("required_events")))
        ]
    return events


def _proof_target_entry(target: dict[str, Any]) -> dict[str, Any]:
    preservation = _as_dict(target.get("preservation_contract"))
    return {
        "name": target.get("name"),
        "claim_category": target.get("claim_category"),
        "goal_type": target.get("goal_type"),
        "trace_kind": target.get("trace_kind"),
        "expected_state": target.get("expected_state"),
        "expected_raw": target.get("expected_raw"),
        "intent": target.get("intent"),
        "required_events": target.get("required_events", []),
        "preserved_values": target.get("preserved_values", []),
        "anti_compression_note": target.get("anti_compression_note"),
        "preservation_policy": preservation.get("outcome_policy") or preservation.get("semantic_anchor"),
        "witness": target.get("witness"),
    }


def _expected_attack_surface(
    target_lemmas: list[dict[str, Any]],
    semantic_questions: list[dict[str, Any]],
    protocol_ir: dict[str, Any],
    boundary: dict[str, Any],
) -> list[dict[str, str]]:
    result = []
    for target in target_lemmas:
        if str(target.get("expected_state") or "") == "CounterexampleFound":
            witness = str(target.get("witness") or "").strip()
            result.append(
                {
                    "target": str(target.get("name") or ""),
                    "policy": witness
                    or "Preserve the protocol behavior that should witness this counterexample; do not add checks or restrictions solely to make it prove.",
                }
            )
    for question in semantic_questions:
        if "attack" in str(question.get("id") or "").lower() or "counterexample" in str(question.get("question") or "").lower():
            result.append({"target": "semantic_review", "policy": str(question.get("question") or "")})
    for assumption in _as_list(protocol_ir.get("modeling_assumptions")):
        text = str(assumption)
        if any(token in text.lower() for token in ("replay", "attack", "counterexample", "do not add")):
            result.append({"target": "modeling_assumption", "policy": text})
    if boundary.get("needed") and not result:
        result.append(
            {
                "target": "boundary",
                "policy": "Keep expected proof outcomes aligned with the derived proof context; do not make targets vacuous.",
            }
        )
    return _dedupe_dicts(result)


def _abstraction_boundary(
    protocol_ir: dict[str, Any],
    proof_context: dict[str, Any],
    semantic_questions: list[dict[str, Any]],
) -> dict[str, Any]:
    boundary = _as_dict(proof_context.get("preservation_boundary"))
    constraints = _as_dict(boundary.get("constraints"))
    must_preserve = []
    for question in semantic_questions:
        if "abstraction" in str(question.get("id") or "").lower():
            must_preserve.append(str(question.get("question") or ""))
    must_preserve.extend(str(item) for item in _as_list(proof_context.get("generation_policies")) if str(item))
    may_abstract = []
    message_abstraction = _as_list(constraints.get("message_abstraction"))
    if message_abstraction:
        may_abstract.append("Message presentation may be renamed or packaged only when sender, receiver, checks, role ownership, and derivability are preserved.")
    crypto = _as_dict(constraints.get("crypto_abstraction"))
    if crypto.get("policy"):
        may_abstract.append(str(crypto.get("policy")))
    semantic_contract = _as_dict(proof_context.get("semantic_assumption_contract"))
    assumptions = (
        _as_list(protocol_ir.get("abstractions"))
        + _as_list(protocol_ir.get("modeling_assumptions"))
        + _as_list(semantic_contract.get("semantic_constraints"))
    )
    return {
        "needed": boundary.get("needed"),
        "score": boundary.get("score"),
        "triggers": boundary.get("triggers", []),
        "must_preserve": _dedupe(must_preserve),
        "may_abstract": _dedupe(may_abstract),
        "assumptions": _dedupe([str(item) for item in assumptions if str(item)]),
    }


def _semantic_questions(proof_context: dict[str, Any], ledger: dict[str, Any]) -> list[dict[str, Any]]:
    questions = _as_list(ledger.get("all_semantic_review_questions")) or _as_list(proof_context.get("semantic_review_questions"))
    return [item for item in questions if isinstance(item, dict)]


def _open_questions(
    protocol_ir: dict[str, Any],
    plan: dict[str, Any] | None,
    semantic_questions: list[dict[str, Any]],
    ledger: dict[str, Any],
) -> list[Any]:
    questions: list[Any] = []
    questions.extend(_as_list(protocol_ir.get("open_questions")))
    if isinstance(plan, dict):
        questions.extend(_as_list(plan.get("open_questions")))
    questions.extend(_as_list(ledger.get("unresolved_questions")))
    answered_ids = {
        str(item.get("id") or "")
        for item in _as_list(ledger.get("answered_questions"))
        if isinstance(item, dict)
    }
    for question in semantic_questions:
        if str(question.get("id") or "") not in answered_ids and question not in questions:
            questions.append(question)
    return [_reviewable_open_question(item, index) for index, item in enumerate(_dedupe_any(questions), start=1)]


def _reviewable_open_question(item: Any, index: int) -> dict[str, Any]:
    if isinstance(item, dict):
        question = dict(item)
    else:
        question = {
            "id": f"open_question_{index}",
            "source": "planner",
            "severity": "medium",
            "question": str(item),
        }
    question.setdefault("id", f"open_question_{index}")
    question.setdefault("source", "unknown")
    question.setdefault("severity", "medium")
    question.setdefault("question", str(item))
    if question.get("answer") and not question.get("proposed_answer"):
        question["proposed_answer"] = question.get("answer")
    if question.get("resolution") and not question.get("proposed_resolution"):
        question["proposed_resolution"] = question.get("resolution")
    question.setdefault("proposed_answer", _default_proposed_answer(question))
    question.setdefault("proposed_resolution", _default_proposed_resolution(question))
    question.setdefault("answer", question.get("proposed_answer") or "")
    question.setdefault("resolution", question.get("proposed_resolution") or "")
    question.setdefault("review_status", "needs_review")
    question.setdefault("proposal_source", question.get("proposal_source") or "contract_builder_default")
    return question


def _default_proposed_answer(question: dict[str, Any]) -> str:
    text = " ".join(
        str(question.get(key) or "")
        for key in ("id", "question", "why", "default_if_unanswered")
    ).lower()
    signals = ", ".join(str(item) for item in _as_list(question.get("signals")) if str(item))
    if "value_provenance" in text or "trusted setup" in text:
        return (
            "Classify proof-relevant values by source: long-term keys and role state are setup/state; "
            "fresh terms are generated inside their owner role; network messages are adversary-controlled "
            "until successfully decrypted, matched, or otherwise checked."
        )
    if "compromise_scope" in text or "reveal" in text or "compromise" in text:
        return (
            "Keep compromise/reveal behavior explicit. A reveal event exposes only the configured secret "
            "and should be handled as a lemma exception or ordered condition, not as an implicit default."
        )
    if "expected_attack_surface" in text or "counterexample" in text or "attack" in text:
        return (
            "Preserve the missing check or adversary behavior that is supposed to witness the counterexample; "
            "do not add restrictions solely to make the target prove."
        )
    if "message_and_crypto_abstraction" in text or "crypto" in text or "message fields" in text:
        return (
            "Keep message fields, equality checks, and crypto derivations explicit when they affect derivability, "
            "authentication evidence, secrecy, or expected counterexamples."
        )
    if signals:
        return f"Review the proof-relevant signals and preserve their provenance or checks: {signals}."
    return "Use the ProtocolIR as the default modeling assumption and record any uncertainty before Sapic+ generation."


def _default_proposed_resolution(question: dict[str, Any]) -> str:
    text = " ".join(
        str(question.get(key) or "")
        for key in ("id", "question", "why", "default_if_unanswered")
    ).lower()
    if "value_provenance" in text or "trusted setup" in text:
        return (
            "Sapic+ generation must introduce every event/lemma value through fresh generation, setup/state, "
            "a prior input, a successful decryption/pattern match, or carried role state."
        )
    if "compromise_scope" in text or "reveal" in text or "compromise" in text:
        return (
            "Generate reveal events only when the contract requires them, and preserve their ordering/exception "
            "conditions in the lemmas."
        )
    if "expected_attack_surface" in text or "counterexample" in text or "attack" in text:
        return (
            "Keep the expected counterexample reachable and non-vacuous; reject generated models that remove the "
            "reviewed attack surface."
        )
    if "message_and_crypto_abstraction" in text or "crypto" in text or "message fields" in text:
        return (
            "Only abstract presentation details that do not affect sender/receiver roles, protected payload "
            "derivability, equality checks, event arguments, or target lemma outcomes."
        )
    return "Treat the proposed answer as a generation constraint unless the human reviewer edits or rejects it."


def _risk_level_from_boundary(boundary: dict[str, Any], validation: dict[str, Any], target_lemmas: list[dict[str, Any]]) -> str:
    score = int(boundary.get("score") or 0)
    if validation.get("warnings"):
        score += 1
    if any(str(target.get("expected_state") or "") == "CounterexampleFound" for target in target_lemmas):
        score += 1
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _risk_triggers(boundary: dict[str, Any], validation: dict[str, Any], target_lemmas: list[dict[str, Any]]) -> list[str]:
    triggers = [str(item) for item in _as_list(boundary.get("triggers"))]
    if validation.get("warnings"):
        triggers.append(f"ir_warning_count={len(_as_list(validation.get('warnings')))}")
    if any(str(target.get("expected_state") or "") == "CounterexampleFound" for target in target_lemmas):
        triggers.append("expected_counterexample_target")
    return _dedupe(triggers)


def _append_records(lines: list[str], records: list[Any], *, fields: tuple[str, ...], empty: str) -> None:
    if not records:
        lines.append(f"- {empty}")
        return
    for record in records:
        if not isinstance(record, dict):
            lines.append(f"- {_md(record)}")
            continue
        parts = []
        for field in fields:
            value = record.get(field)
            if value in (None, "", []):
                continue
            if isinstance(value, list):
                value_text = ", ".join(str(item) for item in value)
            else:
                value_text = str(value)
            parts.append(f"{field}: {value_text}")
        lines.append(f"- {_md('; '.join(parts)) if parts else _md(record)}")


def _append_text_items(lines: list[str], items: Any, title: str) -> None:
    values = [str(item) for item in _as_list(items) if str(item)]
    if not values:
        lines.append(f"- {title}: none recorded.")
        return
    lines.append(f"- {title}:")
    for item in values:
        lines.append(f"  - {_md(item)}")


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _dedupe_any(values: list[Any]) -> list[Any]:
    seen = set()
    result = []
    for value in values:
        try:
            key = json.dumps(value, sort_keys=True, ensure_ascii=False)
        except TypeError:
            key = str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _dedupe_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in _dedupe_any(values) if isinstance(item, dict)]


def _display(value: Any) -> str:
    if value is None or value == "":
        return "-"
    return str(value)


def _yes_no(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "-"


def _md(value: Any) -> str:
    return str(value).replace("\n", " ").strip()
