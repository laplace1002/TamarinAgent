from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any, Callable

from .abstraction_hints import retrieve_abstraction_hints
from .artifacts import ArtifactStore
from .cases import ProtocolCase, case_slug
from .diagnostics import build_compile_diagnostics
from .errors import StageFailure
from .ir import build_protocol_ir_bundle
from .llm import LLMClient, llm_call_record
from .modeling_contract import build_modeling_contract, write_modeling_contract_artifacts
from .prompts import (
    IR_REPAIR_SYSTEM,
    PLANNER_SYSTEM,
    PROOF_REPAIR_SYSTEM,
    REPAIR_SYSTEM,
    SAPIC_SYSTEM,
    SAPIC_FORMAT_REPAIR_SYSTEM,
    ir_repair_prompt,
    planner_prompt,
    proof_repair_prompt,
    repair_prompt,
    sapic_prompt,
    sapic_json_retry_prompt,
    planner_retry_prompt,
)
from .proof_lint import ProofLintResult, proof_lint
from .proofspec import actual_state_from_result
from .proofspec import ProofSpec, build_initial_proof_spec, complete_discovered_proof_spec
from .sapic import VerificationResult, basic_sapic_lint, extract_lemma_names, extract_sapic, run_tamarin
from .sapic import lemma_coverage, run_tamarin_proof
from .sapic import run_tamarin_proof_lemma, semantic_constraint_lint, target_lemma_lint


@dataclass
class PipelineConfig:
    output_dir: Path
    tamarin_bin: str = "tamarin-prover"
    tamarin_timeout: int = 120
    tamarin_derivcheck_timeout: int | None = 0
    max_generation_rounds: int = 1
    max_repair_rounds: int = 2
    proof_timeout: int = 600
    lemma_proof_timeout: int = 60
    prove: bool = True
    prove_each_lemma: bool = True
    full_proof: bool = False
    expose_benchmark_goals: bool = False
    verify: bool = True
    skip_llm: bool = False
    max_ir_repair_rounds: int = 2
    fail_on_open_questions: bool = False
    ask_open_questions: bool = False
    question_policy: str = "off"
    max_plan_retries: int = 2
    max_open_questions: int = 3
    max_semantic_review_questions: int = 1
    max_compile_repair_plateau_rounds: int = 2
    abstraction_hints_enabled: bool = False
    abstraction_hints_path: Path | None = None
    abstraction_retrieval_config_path: Path | None = None
    abstraction_hints_top_k: int = 3
    emit_modeling_contract: bool = False
    ir_review_gate_enabled: bool = True


ProgressReporter = Callable[[str, dict[str, Any]], None]
OpenQuestionResolver = Callable[[ProtocolCase, list[dict[str, Any]]], list[dict[str, Any]]]


REVIEWED_PROOF_MODE = "reviewed_proof_targets"
REVIEWED_PROOF_SOURCE = "reviewed_lemma_specification"


class ProtocolIRPipeline:
    """Confidence-guided Protocol IR route where the LLM generates Sapic+."""

    def __init__(
        self,
        config: PipelineConfig,
        llm: LLMClient | None,
        reporter: ProgressReporter | None = None,
        open_question_resolver: OpenQuestionResolver | None = None,
    ) -> None:
        self.config = config
        self.llm = llm
        self.reporter = reporter
        self.open_question_resolver = open_question_resolver

    def run_case(self, case: ProtocolCase) -> dict[str, Any]:
        run_dir = self.config.output_dir / case_slug(case.name)
        store = ArtifactStore(run_dir)
        _clear_ir_review_required(store)
        store.write_json("input/case.json", case)
        case_start = perf_counter()
        self._report("case_start", case=case.name, difficulty=case.difficulty, run_dir=str(run_dir))
        proof_spec = self._build_proof_spec(case, store)
        generation_rounds_used = 0
        ir_bundle: dict[str, Any] | None = None

        if self.config.skip_llm:
            self._report("offline_start", case=case.name)
            plan = self._offline_plan(case)
            ir_bundle = self._build_ir_bundle(case, plan, proof_spec, store)
            if self.config.emit_modeling_contract:
                self._write_modeling_contract(case, plan, proof_spec, ir_bundle, store)
            sapic_plus = self._offline_sapic(case)
            store.stage_record("offline", reason="--skip-llm was set")
            self._report("offline_done", case=case.name)
        else:
            if self.llm is None:
                raise RuntimeError("LLM client is required unless --skip-llm is set.")
            try:
                plan = self._plan(case, store)
            except StageFailure as exc:
                return self._failed_summary(case, store, run_dir, case_start, exc, proof_spec)
            try:
                ir_bundle = self._build_ir_bundle(case, plan, proof_spec, store)
                if self.config.question_policy != "off" or self.config.ask_open_questions:
                    plan, ir_bundle = self._resolve_semantic_review_questions(case, plan, proof_spec, ir_bundle, store)
                plan, ir_bundle = self._repair_ir_until_valid(case, plan, proof_spec, ir_bundle, store)
                if self.config.emit_modeling_contract:
                    self._write_modeling_contract(case, plan, proof_spec, ir_bundle, store)
            except StageFailure as exc:
                return self._failed_summary(case, store, run_dir, case_start, exc, proof_spec)
            try:
                generation_rounds_used = 1
                sapic_plus = self._generate_sapic(case, plan, proof_spec, store, ir_bundle=ir_bundle, generation_round=1)
            except StageFailure as exc:
                return self._failed_summary(case, store, run_dir, case_start, exc, proof_spec)

        proof_spec = complete_discovered_proof_spec(case, proof_spec, sapic_plus)
        store.write_json("proof/spec.json", proof_spec)
        self._report(
            "proof_spec_done",
            case=case.name,
            mode=_public_proof_mode(proof_spec),
            source=_public_proof_source(proof_spec),
            lemma_count=len(proof_spec.expectations),
        )

        lint_issues = _compile_lint(sapic_plus, proof_spec.names, ir_bundle)
        store.write_json("lint/initial.json", {"issues": lint_issues})
        self._report("lint_done", case=case.name, label="initial", issue_count=len(lint_issues))
        verification = None
        proof = None
        coverage = None
        proof_lint_result = None
        if self.config.verify:
            verification = self._verify(sapic_plus, store, "initial", lint_issues)
            sapic_plus, verification, lint_issues, generation_rounds_used = self._compile_repair_or_regenerate(
                case,
                plan,
                ir_bundle,
                proof_spec,
                sapic_plus,
                verification,
                lint_issues,
                store,
                generation_rounds_used,
            )
            expected_lemmas = proof_spec.names
            coverage = self._lemma_coverage(case, sapic_plus, store, expected_lemmas)
            proof_lint_result = self._proof_lint(case, sapic_plus, store, proof_spec)
            if self.config.prove and verification.ok and not lint_issues and coverage.ok:
                if proof_lint_result.ok:
                    proof = self._prove(case, sapic_plus, store, proof_spec)
                sapic_plus, verification, coverage, proof, proof_lint_result, generation_rounds_used = self._proof_repair_loop(
                    case,
                    plan,
                    ir_bundle,
                    proof_spec,
                    sapic_plus,
                    verification,
                    coverage,
                    proof_lint_result,
                    proof,
                    store,
                    generation_rounds_used,
                )
            elif self.config.prove:
                skip_reason = "compile_or_coverage_failed"
                if verification.ok and not lint_issues and coverage.ok and proof_lint_result and not proof_lint_result.ok:
                    skip_reason = "proof_lint_failed"
                self._report(
                    "proof_skipped",
                    case=case.name,
                    reason=skip_reason,
                    compile_status=verification.status,
                    missing_lemmas=coverage.missing,
                    proof_lint_issues=proof_lint_result.issues if proof_lint_result else [],
                )
        else:
            store.stage_record("verify_skipped")

        final_path = store.write_text("final/model.spthy", sapic_plus)
        ir_review_required = _load_ir_review_required(store)
        summary = {
            "case": case.name,
            "run_dir": str(run_dir),
            "final_model": str(final_path),
            "goal_mode": _public_proof_mode(proof_spec),
            "proof_spec_source": _public_proof_source(proof_spec),
            "protocol_ir_ok": (ir_bundle or {}).get("validation", {}).get("ok") if ir_bundle else None,
            "protocol_ir_errors": (ir_bundle or {}).get("validation", {}).get("errors", []) if ir_bundle else [],
            "protocol_ir_warnings": (ir_bundle or {}).get("validation", {}).get("warnings", []) if ir_bundle else [],
            "preservation_boundary_needed": _preservation_boundary(ir_bundle).get("needed") if ir_bundle else None,
            "preservation_boundary_score": _preservation_boundary(ir_bundle).get("score") if ir_bundle else None,
            "preservation_boundary_triggers": _preservation_boundary(ir_bundle).get("triggers", []) if ir_bundle else [],
            "semantic_review_question_count": len(_semantic_review_questions(ir_bundle)) if ir_bundle else 0,
            "semantic_review_questions": _semantic_review_questions(ir_bundle) if ir_bundle else [],
            "question_policy": self.config.question_policy,
            "assumption_ledger": _load_assumption_ledger(store),
            "abstraction_hints": (ir_bundle or {}).get("abstraction_hints") if ir_bundle else {},
            "sapic_backend": "llm",
            "generation_rounds_used": generation_rounds_used,
            "max_generation_rounds": self.config.max_generation_rounds,
            "max_repair_rounds": self.config.max_repair_rounds,
            "proof_expectations": [
                {
                    "name": item.name,
                    "trace_kind": item.trace_kind,
                    "expected_state": item.expected_state,
                    "expected_raw": item.expected_raw,
                    "source": item.source,
                    "goal_type": item.goal_type,
                    "intent": item.intent,
                }
                for item in proof_spec.expectations
            ],
            "lint_issues": lint_issues,
            "verification_ok": (verification.ok and not lint_issues) if verification else None,
            "verification_status": verification.status if verification else "not_run",
            "verification_returncode_ok": verification.returncode_ok if verification else None,
            "verification_returncode": verification.returncode if verification else None,
            "verification_has_warnings": verification.has_warnings if verification else None,
            "verification_warnings": verification.warnings if verification else [],
            "lemma_coverage_ok": coverage.ok if coverage else None,
            "proof_lint_ok": proof_lint_result.ok if proof_lint_result else None,
            "proof_lint_issues": proof_lint_result.issues if proof_lint_result else [],
            "expected_lemmas": coverage.expected if coverage else self._target_lemma_names(case, sapic_plus),
            "present_lemmas": coverage.present if coverage else [],
            "missing_lemmas": coverage.missing if coverage else [],
            "extra_lemmas": coverage.extra if coverage else [],
            "proof_ok": proof.ok if proof else None,
            "proof_status": proof.status if proof else ("not_run" if not self.config.prove else "skipped"),
            "proof_returncode": proof.returncode if proof else None,
            "proof_lemma_results": proof.lemma_results if proof else {},
            "proof_missing_results": proof.missing_results if proof else [],
            "proof_lemma_expected_states": proof.lemma_expected_states if proof else proof_spec.expected_states,
            "proof_lemma_actual_states": proof.lemma_actual_states if proof else {},
            "proof_lemma_matches": proof.lemma_matches if proof else {},
            "proof_mismatched_results": proof.mismatched_results if proof else [],
            "ir_review_required": bool(ir_review_required),
            "ir_review_reason": ir_review_required.get("reason", "") if ir_review_required else "",
            "ir_review_affected_fields": ir_review_required.get("affected_ir_fields", []) if ir_review_required else [],
            "ir_review_details": ir_review_required,
            "ir_review_gate_enabled": self.config.ir_review_gate_enabled,
        }
        summary.update(
            _final_outcome(
                summary,
                prove_enabled=self.config.prove,
                ir_review_gate_enabled=self.config.ir_review_gate_enabled,
            )
        )
        store.write_json("summary.json", summary)
        self._report(
            "case_done",
            case=case.name,
            status=summary["status"],
            ok=summary["ok"],
            elapsed_sec=round(perf_counter() - case_start, 2),
        )
        return summary

    def _failed_summary(
        self,
        case: ProtocolCase,
        store: ArtifactStore,
        run_dir: Path,
        case_start: float,
        error: StageFailure,
        proof_spec: ProofSpec | None = None,
    ) -> dict[str, Any]:
        store.stage_record("stage_failed", stage_name=error.stage, error=str(error), details=error.details)
        summary = {
            "case": case.name,
            "run_dir": str(run_dir),
            "final_model": None,
            "goal_mode": _public_proof_mode(proof_spec),
            "proof_spec_source": _public_proof_source(proof_spec),
            "protocol_ir_ok": None,
            "protocol_ir_errors": error.details.get("validation", {}).get("errors", []) if isinstance(error.details.get("validation"), dict) else [],
            "protocol_ir_warnings": error.details.get("validation", {}).get("warnings", []) if isinstance(error.details.get("validation"), dict) else [],
            "proof_expectations": [
                {
                    "name": item.name,
                    "trace_kind": item.trace_kind,
                    "expected_state": item.expected_state,
                    "expected_raw": item.expected_raw,
                    "source": item.source,
                    "goal_type": item.goal_type,
                    "intent": item.intent,
                }
                for item in (proof_spec.expectations if proof_spec else [])
            ],
            "failed_stage": error.stage,
            "error": str(error),
            "error_details": error.details,
            "verification_ok": False,
            "verification_status": "failed",
            "lemma_coverage_ok": None,
            "expected_lemmas": proof_spec.names if proof_spec else (_expected_lemma_names(case) if self.config.expose_benchmark_goals else []),
            "present_lemmas": [],
            "missing_lemmas": [],
            "extra_lemmas": [],
            "proof_ok": None,
            "proof_status": "skipped",
            "generation_rounds_used": error.details.get("generation_round", 0),
            "max_generation_rounds": self.config.max_generation_rounds,
            "max_repair_rounds": self.config.max_repair_rounds,
            "proof_lemma_results": {},
            "proof_missing_results": [],
            "proof_lemma_expected_states": proof_spec.expected_states if proof_spec else {},
            "proof_lemma_actual_states": {},
            "proof_lemma_matches": {},
            "proof_mismatched_results": [],
            "ir_review_gate_enabled": self.config.ir_review_gate_enabled,
        }
        summary.update(
            _final_outcome(
                summary,
                prove_enabled=self.config.prove,
                ir_review_gate_enabled=self.config.ir_review_gate_enabled,
            )
        )
        store.write_json("summary.json", summary)
        self._report(
            "case_failed",
            case=case.name,
            stage=error.stage,
            error=str(error),
            elapsed_sec=round(perf_counter() - case_start, 2),
        )
        return summary

    def _plan(self, case: ProtocolCase, store: ArtifactStore) -> dict[str, Any]:
        prompt = planner_prompt(case, expose_benchmark_goals=self.config.expose_benchmark_goals)
        store.write_text("prompts/01_plan.txt", prompt)
        start = perf_counter()
        self._report("plan_start", case=case.name)
        max_attempts = max(1, 1 + self.config.max_plan_retries)
        plan: dict[str, Any] | None = None
        raw_text = ""
        current_prompt = prompt
        failure_reason = ""
        for attempt in range(1, max_attempts + 1):
            if attempt > 1:
                store.write_text(f"prompts/01_plan_retry_{attempt - 1}.txt", current_prompt)
                self._report(
                    "plan_retry_start",
                    case=case.name,
                    attempt=attempt,
                    max_attempts=max_attempts,
                    previous_raw_response_bytes=len(raw_text or ""),
                )
            plan, raw_text = self.llm.complete_json_or_text(PLANNER_SYSTEM, current_prompt)  # type: ignore[union-attr]
            store.append_jsonl(
                "history/llm_calls.jsonl",
                llm_call_record(
                    self.llm,  # type: ignore[arg-type]
                    stage="planner",
                    system=PLANNER_SYSTEM,
                    prompt=current_prompt,
                    attempt=attempt,
                    case=case.name,
                    parsed_json=plan is not None,
                    extra={"raw_response_chars": len(raw_text or "")},
                ),
            )
            if plan is not None:
                if attempt > 1:
                    self._report(
                        "plan_retry_done",
                        case=case.name,
                        attempt=attempt,
                        raw_response_bytes=len(raw_text or ""),
                    )
                break
            failure_reason = _planner_json_failure_reason(raw_text)
            if raw_text.strip():
                raw_name = "history/01_plan.raw.txt" if attempt == 1 else f"history/01_plan_retry_{attempt - 1}.raw.txt"
                store.write_text(raw_name, raw_text)
            self._report(
                "plan_json_failed",
                case=case.name,
                attempt=attempt,
                max_attempts=max_attempts,
                reason=failure_reason,
                raw_response_bytes=len(raw_text or ""),
            )
            if attempt < max_attempts:
                current_prompt = planner_retry_prompt(
                    prompt,
                    raw_text,
                    failure_reason,
                    attempt + 1,
                    max_attempts,
                )
        if plan is None:
            raise StageFailure(
                "plan",
                "LLM planner response did not contain a parseable complete JSON object after retries.",
                {
                    "raw_response_bytes": len(raw_text or ""),
                    "attempts": max_attempts,
                    "reason": failure_reason,
                },
            )
        include_questions = self.config.question_policy != "off" or self.config.ask_open_questions
        if not include_questions:
            _clear_plan_open_questions(plan)
        store.write_json("history/01_plan.initial.json", plan)
        open_questions = _plan_open_questions(plan)
        raw_open_question_entries = _open_question_entries(open_questions)
        open_question_entries = _limit_open_questions(raw_open_question_entries, self.config.max_open_questions)
        deferred_open_question_entries = raw_open_question_entries[len(open_question_entries) :]
        if deferred_open_question_entries:
            store.write_json(
                "history/01_open_questions_deferred.json",
                {
                    "reason": "max_open_questions",
                    "limit": self.config.max_open_questions,
                    "deferred": deferred_open_question_entries,
                },
            )
            self._report(
                "open_questions_deferred",
                case=case.name,
                asked_count=len(open_question_entries),
                deferred_count=len(deferred_open_question_entries),
                limit=self.config.max_open_questions,
            )
        should_ask_plan = _should_ask_open_questions(
            self.config.question_policy,
            self.config.ask_open_questions,
            "planner",
            case,
            None,
            open_question_entries,
        )
        if should_ask_plan and open_question_entries:
            self._report(
                "open_questions_start",
                case=case.name,
                open_question_count=len(open_question_entries),
            )
            answers = (
                self.open_question_resolver(case, open_question_entries)
                if self.open_question_resolver is not None
                else []
            )
            plan, answered_questions, unresolved_questions = _apply_open_question_answers(
                plan,
                open_question_entries,
                answers,
            )
            store.write_json(
                "history/01_open_question_answers.json",
                {
                    "open_questions": open_question_entries,
                    "answered": answered_questions,
                    "unresolved": unresolved_questions,
                },
            )
            self._report(
                "open_questions_done",
                case=case.name,
                answered_count=len(answered_questions),
                unresolved_count=len(unresolved_questions),
            )
            open_questions = unresolved_questions
        elif open_question_entries:
            open_questions = open_question_entries
        else:
            open_questions = []
        if deferred_open_question_entries:
            open_questions = _as_open_question_list(open_questions) + deferred_open_question_entries
        plan_roles = _plan_roles(plan)
        store.write_json("history/01_plan.json", plan)
        store.stage_record("plan", roles=plan_roles, open_questions=open_questions)
        self._report(
            "plan_done",
            case=case.name,
            roles=plan_roles,
            open_question_count=len(open_questions),
            elapsed_sec=round(perf_counter() - start, 2),
        )
        if self.config.fail_on_open_questions and open_questions:
            store.write_json("history/01_open_questions.json", {"open_questions": open_questions})
            self._report(
                "open_questions_blocked",
                case=case.name,
                open_question_count=len(open_questions),
                open_questions=open_questions,
            )
            raise StageFailure(
                "plan_open_questions",
                "Planner produced open questions and --fail-on-open-questions is set.",
                {"open_questions": open_questions},
            )
        return plan

    def _build_ir_bundle(
        self,
        case: ProtocolCase,
        plan: dict[str, Any],
        proof_spec: ProofSpec,
        store: ArtifactStore,
        label: str = "initial",
    ) -> dict[str, Any]:
        include_questions = self.config.question_policy != "off" or self.config.ask_open_questions
        ir_bundle = build_protocol_ir_bundle(
            case,
            plan,
            proof_spec,
            include_open_questions=include_questions,
            include_semantic_review_questions=include_questions,
        )
        store.write_json(f"ir/{label}.json", ir_bundle)
        if label == "initial":
            store.write_json("ir/protocol_ir.json", ir_bundle["protocol_ir"])
            store.write_json("ir/field_reviews.json", {"field_reviews": ir_bundle.get("field_reviews", [])})
            store.write_json("ir/preservation_boundary.json", _preservation_boundary(ir_bundle))
            store.write_json("ir/semantic_review_questions.json", {"questions": _semantic_review_questions(ir_bundle)})
            store.write_json("ir/validation.json", ir_bundle["validation"])
        self._attach_abstraction_hints(case, proof_spec, ir_bundle, store, label)
        store.stage_record(
            "protocol_ir",
            label=label,
            ok=ir_bundle["validation"]["ok"],
            errors=ir_bundle["validation"]["errors"],
            warnings=ir_bundle["validation"]["warnings"],
            field_review_count=len(ir_bundle.get("field_reviews") or []),
            preservation_boundary_needed=_preservation_boundary(ir_bundle).get("needed"),
            preservation_boundary_score=_preservation_boundary(ir_bundle).get("score"),
            semantic_review_question_count=len(_semantic_review_questions(ir_bundle)),
        )
        self._report(
            "ir_done",
            case=case.name,
            label=label,
            ok=ir_bundle["validation"]["ok"],
            error_count=len(ir_bundle["validation"]["errors"]),
            warning_count=len(ir_bundle["validation"]["warnings"]),
            message_count=len(ir_bundle["protocol_ir"].get("messages") or []),
            claim_count=len(ir_bundle["protocol_ir"].get("claims") or []),
            field_review_count=len(ir_bundle.get("field_reviews") or []),
            preservation_boundary=_preservation_boundary(ir_bundle).get("needed"),
            preservation_boundary_score=_preservation_boundary(ir_bundle).get("score"),
            semantic_review_question_count=len(_semantic_review_questions(ir_bundle)),
        )
        return ir_bundle

    def _attach_abstraction_hints(
        self,
        case: ProtocolCase,
        proof_spec: ProofSpec,
        ir_bundle: dict[str, Any],
        store: ArtifactStore,
        label: str,
    ) -> None:
        if not self.config.abstraction_hints_enabled:
            hints = {"enabled": False, "selected": [], "reason": "disabled"}
        else:
            hints = retrieve_abstraction_hints(
                case,
                ir_bundle.get("protocol_ir") or {},
                proof_spec,
                cases_path=self.config.abstraction_hints_path,
                retrieval_config_path=self.config.abstraction_retrieval_config_path,
                top_k=self.config.abstraction_hints_top_k,
            )
        ir_bundle["abstraction_hints"] = hints
        store.write_json(f"ir/{label}.abstraction_hints.json", hints)
        if label == "initial":
            store.write_json("ir/abstraction_hints.json", hints)
        selected = hints.get("selected") if isinstance(hints, dict) else []
        store.stage_record(
            "abstraction_hints",
            label=label,
            enabled=hints.get("enabled") if isinstance(hints, dict) else False,
            selected_count=len(selected) if isinstance(selected, list) else 0,
            selected_ids=[item.get("id") for item in selected if isinstance(item, dict)] if isinstance(selected, list) else [],
        )
        self._report(
            "abstraction_hints_done",
            case=case.name,
            label=label,
            enabled=hints.get("enabled") if isinstance(hints, dict) else False,
            selected_count=len(selected) if isinstance(selected, list) else 0,
            selected_ids=[item.get("id") for item in selected if isinstance(item, dict)] if isinstance(selected, list) else [],
        )

    def _resolve_semantic_review_questions(
        self,
        case: ProtocolCase,
        plan: dict[str, Any],
        proof_spec: ProofSpec,
        ir_bundle: dict[str, Any],
        store: ArtifactStore,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        raw_questions = _open_question_entries(_semantic_review_questions(ir_bundle))
        planner_context = _open_question_entries(_plan_open_questions(plan)) + _open_question_entries(plan.get("resolved_open_questions"))
        questions = _select_semantic_review_questions(
            raw_questions,
            planner_context,
            self.config.max_semantic_review_questions,
        )
        deferred_questions = [
            question
            for question in raw_questions
            if str(question.get("id") or question.get("question") or "") not in {
                str(selected.get("id") or selected.get("question") or "") for selected in questions
            }
        ]
        ledger = _semantic_assumption_ledger(case, proof_spec, ir_bundle, questions, raw_questions)
        store.write_json("history/01_assumption_ledger.json", ledger)
        store.write_json("ir/assumption_ledger.json", ledger)
        store.stage_record(
            "assumption_ledger",
            question_policy=self.config.question_policy,
            risk_score=ledger["risk_score"],
            risk_level=ledger["risk_level"],
            selected_question_count=len(questions),
            unresolved_question_count=len(ledger["unresolved_questions"]),
        )

        if not questions:
            if raw_questions:
                store.write_json(
                    "history/01_semantic_review_questions_deferred.json",
                    {
                        "reason": "covered_by_planner_questions_or_budget",
                        "limit": self.config.max_semantic_review_questions,
                        "deferred": raw_questions,
                    },
                )
            return plan, ir_bundle

        store.write_json("history/01_semantic_review_questions.json", {"open_questions": questions})
        if deferred_questions:
            store.write_json(
                "history/01_semantic_review_questions_deferred.json",
                {
                    "reason": "covered_by_planner_questions_or_budget",
                    "limit": self.config.max_semantic_review_questions,
                    "deferred": deferred_questions,
                },
            )
            self._report(
                "semantic_review_questions_deferred",
                case=case.name,
                asked_count=len(questions),
                deferred_count=len(deferred_questions),
                limit=self.config.max_semantic_review_questions,
            )
        should_ask_semantic_review = _should_ask_open_questions(
            self.config.question_policy,
            self.config.ask_open_questions,
            "semantic_review",
            case,
            ir_bundle,
            questions,
        )
        if not should_ask_semantic_review:
            self._report(
                "semantic_review_questions_done",
                case=case.name,
                question_count=len(questions),
                asked=False,
                reason=_question_policy_skip_reason(self.config.question_policy, case, ir_bundle),
            )
            return plan, ir_bundle

        self._report(
            "semantic_review_questions_start",
            case=case.name,
            open_question_count=len(questions),
        )
        answers = (
            self.open_question_resolver(case, questions)
            if self.open_question_resolver is not None
            else []
        )
        updated_plan, answered, unresolved = _apply_open_question_answers(plan, questions, answers)
        store.write_json(
            "history/01_semantic_review_answers.json",
            {
                "open_questions": questions,
                "answered": answered,
                "unresolved": unresolved,
            },
        )
        updated_bundle = self._build_ir_bundle(
            case,
            updated_plan,
            proof_spec,
            store,
            label="semantic_reviewed",
        )
        updated_ledger = _semantic_assumption_ledger(case, proof_spec, updated_bundle, unresolved, raw_questions)
        updated_ledger["answered_questions"] = answered
        store.write_json("history/01_assumption_ledger.json", updated_ledger)
        store.write_json("ir/assumption_ledger.json", updated_ledger)
        store.write_json("history/01_plan.json", updated_plan)
        store.write_json("ir/protocol_ir.json", updated_bundle["protocol_ir"])
        store.write_json("ir/field_reviews.json", {"field_reviews": updated_bundle.get("field_reviews", [])})
        store.write_json("ir/preservation_boundary.json", _preservation_boundary(updated_bundle))
        store.write_json("ir/semantic_review_questions.json", {"questions": _semantic_review_questions(updated_bundle)})
        store.write_json("ir/validation.json", updated_bundle["validation"])
        self._report(
            "semantic_review_questions_done",
            case=case.name,
            answered_count=len(answered),
            unresolved_count=len(unresolved),
            asked=True,
        )
        if self.config.fail_on_open_questions and unresolved:
            self._report(
                "open_questions_blocked",
                case=case.name,
                open_question_count=len(unresolved),
                open_questions=unresolved,
            )
            raise StageFailure(
                "semantic_review_open_questions",
                "Semantic review produced unresolved open questions and --fail-on-open-questions is set.",
                {"open_questions": unresolved},
            )
        return updated_plan, updated_bundle

    def _repair_ir_until_valid(
        self,
        case: ProtocolCase,
        plan: dict[str, Any],
        proof_spec: ProofSpec,
        ir_bundle: dict[str, Any],
        store: ArtifactStore,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if ir_bundle["validation"]["ok"] or self.config.max_ir_repair_rounds <= 0:
            return plan, ir_bundle
        if self.llm is None:
            raise StageFailure(
                "protocol_ir",
                "ProtocolIR validation failed and no LLM is available for repair.",
                {"validation": ir_bundle["validation"]},
            )

        current_plan = plan
        current_bundle = ir_bundle
        for round_id in range(1, self.config.max_ir_repair_rounds + 1):
            prompt = ir_repair_prompt(
                case,
                current_plan,
                current_bundle,
                proof_spec,
                expose_benchmark_goals=self.config.expose_benchmark_goals,
            )
            store.write_text(f"prompts/01_ir_repair_round_{round_id}.txt", prompt)
            start = perf_counter()
            self._report(
                "ir_repair_start",
                case=case.name,
                round=round_id,
                error_count=len(current_bundle["validation"]["errors"]),
                warning_count=len(current_bundle["validation"]["warnings"]),
            )
            response, raw_text = self.llm.complete_json_or_text(IR_REPAIR_SYSTEM, prompt)
            store.append_jsonl(
                "history/llm_calls.jsonl",
                llm_call_record(
                    self.llm,
                    stage="protocol_ir_repair",
                    system=IR_REPAIR_SYSTEM,
                    prompt=prompt,
                    attempt=round_id,
                    case=case.name,
                    parsed_json=response is not None,
                    extra={"raw_response_chars": len(raw_text or ""), "round": round_id},
                ),
            )
            if response is None:
                if raw_text.strip():
                    store.write_text(f"history/01_ir_repair_round_{round_id}.raw.txt", raw_text)
                store.stage_record("protocol_ir_repair_rejected", round=round_id, reason="non_json")
                self._report("ir_repair_rejected", case=case.name, round=round_id, reason="non_json")
                continue
            current_plan = response
            store.write_json(f"history/01_ir_repair_round_{round_id}.json", response)
            current_bundle = self._build_ir_bundle(
                case,
                current_plan,
                proof_spec,
                store,
                label=f"repaired_{round_id}",
            )
            store.stage_record("protocol_ir_repair", round=round_id, ok=current_bundle["validation"]["ok"])
            self._report(
                "ir_repair_done",
                case=case.name,
                round=round_id,
                ok=current_bundle["validation"]["ok"],
                error_count=len(current_bundle["validation"]["errors"]),
                elapsed_sec=round(perf_counter() - start, 2),
            )
            if current_bundle["validation"]["ok"]:
                store.write_json("ir/protocol_ir.json", current_bundle["protocol_ir"])
                store.write_json("ir/field_reviews.json", {"field_reviews": current_bundle.get("field_reviews", [])})
                store.write_json("ir/preservation_boundary.json", _preservation_boundary(current_bundle))
                store.write_json("ir/validation.json", current_bundle["validation"])
                return current_plan, current_bundle

        raise StageFailure(
            "protocol_ir",
            "ProtocolIR validation failed after repair rounds.",
            {"validation": current_bundle["validation"]},
        )

    def _write_modeling_contract(
        self,
        case: ProtocolCase,
        plan: dict[str, Any],
        proof_spec: ProofSpec,
        ir_bundle: dict[str, Any],
        store: ArtifactStore,
    ) -> None:
        contract = build_modeling_contract(
            case,
            proof_spec,
            ir_bundle,
            plan=plan,
            assumption_ledger=_load_assumption_ledger(store),
            source="pipeline_pre_generation",
        )
        json_path, markdown_path = write_modeling_contract_artifacts(store.run_dir, contract)
        store.stage_record(
            "modeling_contract",
            json=str(json_path),
            markdown=str(markdown_path),
            risk_level=contract.get("risk", {}).get("level"),
        )
        self._report(
            "modeling_contract_done",
            case=case.name,
            json=str(json_path),
            markdown=str(markdown_path),
            risk_level=contract.get("risk", {}).get("level"),
        )

    def _generate_sapic(
        self,
        case: ProtocolCase,
        plan: dict[str, Any],
        proof_spec: ProofSpec,
        store: ArtifactStore,
        ir_bundle: dict[str, Any] | None = None,
        generation_round: int = 1,
        regeneration_diagnostics: str = "",
    ) -> str:
        prompt = sapic_prompt(
            case,
            plan,
            proof_spec,
            ir_bundle=ir_bundle,
            expose_benchmark_goals=self.config.expose_benchmark_goals,
            regeneration_diagnostics=regeneration_diagnostics,
        )
        prompt_path = _generation_prompt_path(generation_round)
        history_prefix = _generation_history_prefix(generation_round)
        model_label = _generation_initial_label(generation_round)
        store.write_text(prompt_path, prompt)
        start = perf_counter()
        self._report(
            "generation_start",
            case=case.name,
            round=generation_round,
            restart=bool(regeneration_diagnostics),
        )
        last_raw_text = ""
        last_response: dict[str, Any] | None = None
        max_attempts = 2
        current_prompt = prompt
        current_system = SAPIC_SYSTEM
        for attempt in range(1, max_attempts + 1):
            response, raw_text = self.llm.complete_json_or_text(current_system, current_prompt)  # type: ignore[union-attr]
            store.append_jsonl(
                "history/llm_calls.jsonl",
                llm_call_record(
                    self.llm,  # type: ignore[arg-type]
                    stage="sapic_generation",
                    system=current_system,
                    prompt=current_prompt,
                    attempt=attempt,
                    case=case.name,
                    parsed_json=response is not None,
                    extra={
                        "raw_response_chars": len(raw_text or ""),
                        "generation_round": generation_round,
                        "restart": bool(regeneration_diagnostics),
                    },
                ),
            )
            last_raw_text = raw_text or ""
            last_response = response
            if response is None:
                store.write_text(f"history/{history_prefix}_attempt_{attempt}.raw.txt", last_raw_text)
                extracted = extract_sapic(last_raw_text)
                reason = _sapic_json_failure_reason(last_raw_text, extracted)
                store.stage_record(
                    "sapic_generation_json_retry",
                    generation_round=generation_round,
                    attempt=attempt,
                    raw_response_bytes=len(last_raw_text),
                    extracted_bytes=len(extracted),
                    reason=reason,
                )
                self._report(
                    "generation_json_retry",
                    case=case.name,
                    round=generation_round,
                    attempt=attempt,
                    raw_response_bytes=len(last_raw_text),
                    extracted_bytes=len(extracted),
                    reason=reason,
                )
                if attempt >= max_attempts:
                    if extracted and _sapic_complete_enough(extracted, proof_spec.names):
                        response = {
                            "sapic_plus": extracted,
                            "modeling_notes": ["LLM returned non-JSON text; extracted a complete Sapic+/Tamarin theory from raw response."],
                            "expected_limitations": [],
                        }
                    else:
                        continue
                else:
                    current_prompt = sapic_json_retry_prompt(
                        prompt,
                        last_raw_text,
                        reason,
                        attempt + 1,
                        max_attempts,
                    )
                    current_system = SAPIC_FORMAT_REPAIR_SYSTEM
                    continue
            store.write_json(f"history/{history_prefix}_attempt_{attempt}.json", response)
            sapic_plus = extract_sapic(str(response.get("sapic_plus", last_raw_text)))
            if sapic_plus.strip() and _sapic_complete_enough(sapic_plus, proof_spec.names):
                if generation_round == 1:
                    store.write_json("history/02_sapic_generation.json", response)
                store.write_json(f"history/{history_prefix}.json", response)
                store.write_text(f"models/{model_label}.spthy", sapic_plus)
                store.stage_record(
                    "sapic_generation",
                    generation_round=generation_round,
                    bytes=len(sapic_plus),
                    attempt=attempt,
                    restart=bool(regeneration_diagnostics),
                )
                self._report(
                    "generation_done",
                    case=case.name,
                    round=generation_round,
                    bytes=len(sapic_plus),
                    json=last_response is not None,
                    attempt=attempt,
                    elapsed_sec=round(perf_counter() - start, 2),
                )
                return sapic_plus
            empty_reason = _incomplete_sapic_reason(sapic_plus, proof_spec.names)
            store.stage_record(
                "sapic_generation_empty",
                generation_round=generation_round,
                attempt=attempt,
                raw_response_bytes=len(last_raw_text),
                reason=empty_reason,
            )
            self._report(
                "generation_empty",
                case=case.name,
                round=generation_round,
                attempt=attempt,
                raw_response_bytes=len(last_raw_text),
                reason=empty_reason,
            )
        raise StageFailure(
            "generation",
            "LLM Sapic+ generation produced an empty model after retries.",
            {"generation_round": generation_round, "raw_response_bytes": len(last_raw_text)},
        )

    def _compile_repair_or_regenerate(
        self,
        case: ProtocolCase,
        plan: dict[str, Any],
        ir_bundle: dict[str, Any] | None,
        proof_spec: ProofSpec,
        sapic_plus: str,
        verification: VerificationResult,
        lint_issues: list[str],
        store: ArtifactStore,
        generation_round: int,
    ) -> tuple[str, VerificationResult, list[str], int]:
        current = sapic_plus
        current_result = verification
        current_lint_issues = lint_issues
        current_generation_round = max(1, generation_round)

        while True:
            current, current_result = self._repair_loop(
                case,
                plan,
                ir_bundle,
                proof_spec,
                current,
                current_result,
                store,
                generation_round=current_generation_round,
            )
            current_lint_issues = _compile_lint(current, proof_spec.names, ir_bundle)

            if current_result.ok and not current_lint_issues:
                return current, current_result, current_lint_issues, current_generation_round
            if self.config.skip_llm or self.llm is None:
                return current, current_result, current_lint_issues, current_generation_round
            if current_generation_round >= max(1, self.config.max_generation_rounds):
                return current, current_result, current_lint_issues, current_generation_round

            diagnostics = build_compile_diagnostics(current_result.diagnostics, current_lint_issues, current)
            next_round = current_generation_round + 1
            self._report(
                "generation_restart",
                case=case.name,
                next_round=next_round,
                previous_round=current_generation_round,
                previous_status=current_result.status,
                lint_issue_count=len(current_lint_issues),
            )
            store.stage_record(
                "generation_restart",
                next_round=next_round,
                previous_round=current_generation_round,
                previous_status=current_result.status,
                lint_issues=current_lint_issues,
            )

            try:
                current = self._generate_sapic(
                    case,
                    plan,
                    proof_spec,
                    store,
                    ir_bundle=ir_bundle,
                    generation_round=next_round,
                    regeneration_diagnostics=diagnostics,
                )
            except StageFailure as exc:
                store.stage_record(
                    "generation_restart_failed",
                    generation_round=next_round,
                    error=str(exc),
                    details=exc.details,
                )
                self._report(
                    "generation_restart_failed",
                    case=case.name,
                    round=next_round,
                    error=str(exc),
                )
                return current, current_result, current_lint_issues, current_generation_round

            current_generation_round = next_round
            current_lint_issues = _compile_lint(current, proof_spec.names, ir_bundle)
            label = _generation_initial_label(current_generation_round)
            store.write_json(f"lint/{label}.json", {"issues": current_lint_issues})
            self._report(
                "lint_done",
                case=case.name,
                label=label,
                issue_count=len(current_lint_issues),
            )
            current_result = self._verify(current, store, label, current_lint_issues)

    def _verify(
        self,
        sapic_plus: str,
        store: ArtifactStore,
        label: str,
        lint_issues: list[str] | None = None,
    ) -> VerificationResult:
        result = run_tamarin(
            sapic_plus=sapic_plus,
            output_path=store.path(f"models/{label}.spthy"),
            tamarin_bin=self.config.tamarin_bin,
            timeout=self.config.tamarin_timeout,
            derivcheck_timeout=self.config.tamarin_derivcheck_timeout,
        )
        effective_ok = result.ok and not (lint_issues or [])
        store.write_text(f"verify/{label}.stdout.txt", result.stdout)
        store.write_text(f"verify/{label}.stderr.txt", result.stderr)
        store.write_json(
            f"verify/{label}.json",
            {
                "ok": effective_ok,
                "status": result.status,
                "lint_issues": lint_issues or [],
                "returncode_ok": result.returncode_ok,
                "returncode": result.returncode,
                "has_warnings": result.has_warnings,
                "warnings": result.warnings,
                "command": result.command,
                "output_path": result.output_path,
                "elapsed_sec": result.elapsed_sec,
            },
        )
        store.stage_record(
            "verify",
            label=label,
            ok=effective_ok,
            lint_issues=lint_issues or [],
            returncode_ok=result.returncode_ok,
            returncode=result.returncode,
            has_warnings=result.has_warnings,
            warnings=result.warnings,
            elapsed_sec=result.elapsed_sec,
        )
        self._report(
            "verify_done",
            case=store.run_dir.name,
            label=label,
            status=result.status,
            ok=effective_ok,
            returncode=result.returncode,
            warning_count=len(result.warnings),
            lint_issue_count=len(lint_issues or []),
        )
        return result

    def _lemma_coverage(
        self,
        case: ProtocolCase,
        sapic_plus: str,
        store: ArtifactStore,
        expected_lemmas: list[str],
    ):
        coverage = lemma_coverage(sapic_plus, expected_lemmas)
        store.write_json(
            "proof/lemma_coverage.json",
            {
                "ok": coverage.ok,
                "expected": coverage.expected,
                "present": coverage.present,
                "missing": coverage.missing,
                "extra": coverage.extra,
            },
        )
        store.stage_record("lemma_coverage", ok=coverage.ok, missing=coverage.missing, extra=coverage.extra)
        self._report(
            "lemma_coverage_done",
            case=case.name,
            ok=coverage.ok,
            expected_count=len(coverage.expected),
            missing=coverage.missing,
            extra=coverage.extra,
        )
        return coverage

    def _prove(
        self,
        case: ProtocolCase,
        sapic_plus: str,
        store: ArtifactStore,
        proof_spec: ProofSpec,
        artifact_prefix: str = "proof",
    ):
        expected_lemmas = proof_spec.names
        self._report("proof_start", case=case.name, lemma_count=len(expected_lemmas))
        start = perf_counter()
        model_path = store.path(f"{artifact_prefix}/model.spthy")
        if self.config.prove_each_lemma:
            per_lemma = self._prove_each_lemma(case, sapic_plus, store, proof_spec, artifact_prefix=artifact_prefix)
            proof = _proof_result_from_per_lemma(per_lemma, proof_spec, model_path)
            proof.command = [self.config.tamarin_bin, str(store.path(f"{artifact_prefix}/per_lemma")), "--prove=<lemma>"]
            if self.config.tamarin_derivcheck_timeout is not None:
                proof.command.append(f"--derivcheck-timeout={self.config.tamarin_derivcheck_timeout}")
            proof.stdout = "\n\n".join(
                f"== {name} ==\n{record.get('stdout', '')}" for name, record in per_lemma.items()
            )
            proof.stderr = "\n\n".join(
                f"== {name} ==\n{record.get('stderr', '')}" for name, record in per_lemma.items() if record.get("stderr")
            )
            proof.per_lemma = per_lemma
            store.write_text(f"{artifact_prefix}/model.spthy", sapic_plus)
        else:
            proof = run_tamarin_proof(
                sapic_plus=sapic_plus,
                output_path=model_path,
                expected_lemmas=expected_lemmas,
                tamarin_bin=self.config.tamarin_bin,
                timeout=self.config.proof_timeout,
                proof_spec=proof_spec,
                derivcheck_timeout=self.config.tamarin_derivcheck_timeout,
            )
        full_proof = None
        if self.config.full_proof and self.config.prove_each_lemma and artifact_prefix == "proof":
            self._report("proof_full_start", case=case.name, timeout=self.config.proof_timeout)
            full_start = perf_counter()
            full_proof = run_tamarin_proof(
                sapic_plus=sapic_plus,
                output_path=store.path("proof/full_model.spthy"),
                expected_lemmas=expected_lemmas,
                tamarin_bin=self.config.tamarin_bin,
                timeout=self.config.proof_timeout,
                proof_spec=proof_spec,
                derivcheck_timeout=self.config.tamarin_derivcheck_timeout,
            )
            store.write_text("proof/full_stdout.txt", full_proof.stdout)
            store.write_text("proof/full_stderr.txt", full_proof.stderr)
            store.write_json("proof/full_result.json", _proof_result_payload(full_proof))
            self._report(
                "proof_full_done",
                case=case.name,
                status=full_proof.status,
                ok=full_proof.ok,
                returncode=full_proof.returncode,
                elapsed_sec=round(perf_counter() - full_start, 2),
            )
        store.write_text(f"{artifact_prefix}/stdout.txt", proof.stdout)
        store.write_text(f"{artifact_prefix}/stderr.txt", proof.stderr)
        payload = _proof_result_payload(proof)
        if full_proof:
            payload["full_proof"] = _proof_result_payload(full_proof)
        store.write_json(f"{artifact_prefix}/result.json", payload)
        store.stage_record(
            "proof",
            artifact_prefix=artifact_prefix,
            ok=proof.ok,
            status=proof.status,
            returncode=proof.returncode,
            lemma_results=proof.lemma_results,
            missing_results=proof.missing_results,
            mismatched_results=proof.mismatched_results,
        )
        self._report(
            "proof_done",
            case=case.name,
            status=proof.status,
            ok=proof.ok,
            returncode=proof.returncode,
            elapsed_sec=round(perf_counter() - start, 2),
        )
        return proof

    def _prove_each_lemma(
        self,
        case: ProtocolCase,
        sapic_plus: str,
        store: ArtifactStore,
        proof_spec: ProofSpec,
        artifact_prefix: str = "proof",
    ) -> dict[str, dict[str, Any]]:
        per_lemma: dict[str, dict[str, Any]] = {}
        timeout = self.config.lemma_proof_timeout
        for lemma_name in proof_spec.names:
            self._report("proof_lemma_start", case=case.name, lemma=lemma_name, timeout=timeout)
            start = perf_counter()
            result = run_tamarin_proof_lemma(
                sapic_plus=sapic_plus,
                output_path=store.path(f"{artifact_prefix}/per_lemma/{lemma_name}.spthy"),
                lemma_name=lemma_name,
                tamarin_bin=self.config.tamarin_bin,
                timeout=timeout,
                derivcheck_timeout=self.config.tamarin_derivcheck_timeout,
            )
            store.write_text(f"{artifact_prefix}/per_lemma/{lemma_name}.stdout.txt", result.stdout)
            store.write_text(f"{artifact_prefix}/per_lemma/{lemma_name}.stderr.txt", result.stderr)
            actual_raw = result.lemma_results.get(lemma_name)
            expected_state = proof_spec.expected_states.get(lemma_name, "ProvedSatisfying")
            actual_state = _actual_state_from_raw(actual_raw, result.status)
            matched = actual_state == expected_state
            record = {
                "ok": result.ok,
                "status": result.status,
                "returncode": result.returncode,
                "warnings": result.warnings,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "lemma_result": actual_raw,
                "expected_state": expected_state,
                "actual_state": actual_state,
                "matches_expected": matched,
                "missing_results": result.missing_results,
                "command": result.command,
                "output_path": result.output_path,
                "elapsed_sec": round(perf_counter() - start, 2),
            }
            store.write_json(f"{artifact_prefix}/per_lemma/{lemma_name}.json", record)
            per_lemma[lemma_name] = record
            partial_proof = _proof_result_from_per_lemma(per_lemma, proof_spec, store.path(f"{artifact_prefix}/model.spthy"))
            partial_proof.command = [
                self.config.tamarin_bin,
                str(store.path(f"{artifact_prefix}/per_lemma")),
                "--prove=<lemma>",
            ]
            if self.config.tamarin_derivcheck_timeout is not None:
                partial_proof.command.append(f"--derivcheck-timeout={self.config.tamarin_derivcheck_timeout}")
            store.write_json(f"{artifact_prefix}/result.partial.json", _proof_result_payload(partial_proof))
            self._report(
                "proof_lemma_done",
                case=case.name,
                lemma=lemma_name,
                status=result.status,
                actual_state=actual_state,
                expected_state=expected_state,
                match=matched,
                elapsed_sec=record["elapsed_sec"],
            )
        return per_lemma

    def _proof_lint(
        self,
        case: ProtocolCase,
        sapic_plus: str,
        store: ArtifactStore,
        proof_spec: ProofSpec,
    ) -> ProofLintResult:
        result = proof_lint(sapic_plus, proof_spec)
        store.write_json("proof/lint.json", {"ok": result.ok, "issues": result.issues})
        store.stage_record("proof_lint", ok=result.ok, issues=result.issues)
        self._report(
            "proof_lint_done",
            case=case.name,
            ok=result.ok,
            issue_count=len(result.issues),
        )
        return result

    def _repair_loop(
        self,
        case: ProtocolCase,
        plan: dict[str, Any],
        ir_bundle: dict[str, Any] | None,
        proof_spec: ProofSpec,
        sapic_plus: str,
        verification: VerificationResult,
        store: ArtifactStore,
        generation_round: int = 1,
    ) -> tuple[str, VerificationResult]:
        current_lint_issues = _compile_lint(sapic_plus, proof_spec.names, ir_bundle)
        if (verification.ok and not current_lint_issues) or self.config.skip_llm or self.config.max_repair_rounds <= 0:
            if verification.ok and not current_lint_issues:
                self._report(
                    "repair_skipped",
                    case=case.name,
                    generation_round=generation_round,
                    reason="verification clean",
                )
            return sapic_plus, verification
        if self.llm is None:
            return sapic_plus, verification

        current = sapic_plus
        current_result = verification
        rejected_feedback = ""
        plateau_rounds = 0
        last_signature = _compile_problem_signature(current_result, current_lint_issues)
        for round_id in range(1, self.config.max_repair_rounds + 1):
            diagnostics = build_compile_diagnostics(current_result.diagnostics, current_lint_issues, current)
            if rejected_feedback:
                diagnostics = diagnostics + "\n\nPrevious rejected repair attempt:\n" + rejected_feedback
            prompt = repair_prompt(
                case,
                plan,
                current,
                diagnostics,
                proof_spec=proof_spec,
                ir_bundle=ir_bundle,
                expose_benchmark_goals=self.config.expose_benchmark_goals,
            )
            label = _repair_label(generation_round, round_id)
            prompt_stem = _repair_prompt_stem(generation_round, round_id)
            store.write_text(f"prompts/{prompt_stem}.txt", prompt)
            start = perf_counter()
            self._report(
                "repair_start",
                case=case.name,
                generation_round=generation_round,
                round=round_id,
                previous_status=current_result.status,
                lint_issue_count=len(current_lint_issues),
            )
            response, raw_text = self.llm.complete_json_or_text(REPAIR_SYSTEM, prompt)
            store.append_jsonl(
                "history/llm_calls.jsonl",
                llm_call_record(
                    self.llm,
                    stage="compile_repair",
                    system=REPAIR_SYSTEM,
                    prompt=prompt,
                    attempt=round_id,
                    case=case.name,
                    parsed_json=response is not None,
                    extra={
                        "raw_response_chars": len(raw_text or ""),
                        "generation_round": generation_round,
                        "round": round_id,
                    },
                ),
            )
            if response is None:
                if raw_text.strip():
                    store.write_text(f"history/{prompt_stem}.raw.txt", raw_text)
                response = {
                    "repair_scope": "full_rewrite",
                    "sapic_plus": raw_text,
                    "repair_notes": ["LLM returned non-JSON text; extracted Sapic+ from raw response."],
                }
            repaired, repair_candidate_error = _repair_candidate_from_response(current, response, raw_text)
            if repair_candidate_error:
                store.write_json(f"history/{prompt_stem}.json", response)
                store.stage_record(
                    "repair_rejected",
                    generation_round=generation_round,
                    round=round_id,
                    reason=repair_candidate_error,
                )
                self._report(
                    "repair_rejected",
                    case=case.name,
                    generation_round=generation_round,
                    round=round_id,
                    reason=repair_candidate_error,
                )
                rejected_feedback = f"The previous repair response was rejected before verification: {repair_candidate_error}."
                continue
            if not repaired.strip():
                store.stage_record(
                    "repair_rejected",
                    generation_round=generation_round,
                    round=round_id,
                    reason="empty model",
                )
                self._report(
                    "repair_rejected",
                    case=case.name,
                    generation_round=generation_round,
                    round=round_id,
                    reason="empty model",
                )
                continue
            store.write_json(f"history/{prompt_stem}.json", response)
            store.write_text(f"models/{label}.spthy", repaired)
            lint_issues = _compile_lint(repaired, proof_spec.names, ir_bundle)
            store.write_json(f"lint/{label}.json", {"issues": lint_issues})
            self._report(
                "repair_generation_done",
                case=case.name,
                generation_round=generation_round,
                round=round_id,
                bytes=len(repaired),
                lint_issue_count=len(lint_issues),
                elapsed_sec=round(perf_counter() - start, 2),
            )
            candidate_result = self._verify(repaired, store, label, lint_issues)
            acceptance = _compile_repair_acceptance(
                current_result=current_result,
                current_lint_issues=current_lint_issues,
                current_sapic=current,
                candidate_result=candidate_result,
                candidate_lint_issues=lint_issues,
                candidate_sapic=repaired,
                expected_lemmas=proof_spec.names,
            )
            store.stage_record(
                "repair",
                generation_round=generation_round,
                round=round_id,
                ok=candidate_result.ok and not lint_issues,
                accepted=acceptance["accepted"],
                reason=acceptance["reason"],
                repair_scope=response.get("repair_scope"),
                current_score=acceptance["current_score"],
                candidate_score=acceptance["candidate_score"],
            )
            if acceptance["accepted"]:
                current = repaired
                current_result = candidate_result
                current_lint_issues = lint_issues
                rejected_feedback = ""
            else:
                self._report(
                    "repair_rejected",
                    case=case.name,
                    generation_round=generation_round,
                    round=round_id,
                    reason=acceptance["reason"],
                    candidate_status=candidate_result.status,
                    current_status=current_result.status,
                    candidate_warning_count=len(candidate_result.warnings),
                    current_warning_count=len(current_result.warnings),
                    candidate_lint_issue_count=len(lint_issues),
                    current_lint_issue_count=len(current_lint_issues),
                )
                rejected_feedback = _rejected_repair_feedback(
                    acceptance,
                    candidate_result,
                    lint_issues,
                    repaired,
                )
            current_signature = _compile_problem_signature(current_result, current_lint_issues)
            if current_signature == last_signature and not (current_result.ok and not current_lint_issues):
                plateau_rounds += 1
            else:
                plateau_rounds = 0
                last_signature = current_signature
            self._report(
                "repair_done",
                case=case.name,
                generation_round=generation_round,
                round=round_id,
                ok=current_result.ok and not current_lint_issues,
                status=current_result.status,
                accepted=acceptance["accepted"],
            )
            if current_result.ok and not current_lint_issues:
                break
            if plateau_rounds >= max(1, self.config.max_compile_repair_plateau_rounds):
                store.stage_record(
                    "repair_plateau_stop",
                    generation_round=generation_round,
                    round=round_id,
                    signature=current_signature,
                    plateau_rounds=plateau_rounds,
                )
                self._report(
                    "repair_plateau_stop",
                    case=case.name,
                    generation_round=generation_round,
                    round=round_id,
                    status=current_result.status,
                    plateau_rounds=plateau_rounds,
                    problem_signature=current_signature,
                )
                break
        return current, current_result

    def _proof_repair_loop(
        self,
        case: ProtocolCase,
        plan: dict[str, Any],
        ir_bundle: dict[str, Any] | None,
        proof_spec: ProofSpec,
        sapic_plus: str,
        verification: VerificationResult,
        coverage,
        proof_lint_result: ProofLintResult,
        proof,
        store: ArtifactStore,
        generation_rounds_used: int,
    ):
        if (proof and proof.ok) or self.config.skip_llm or self.config.max_repair_rounds <= 0 or self.llm is None:
            return sapic_plus, verification, coverage, proof, proof_lint_result, generation_rounds_used

        current = sapic_plus
        current_verification = verification
        current_coverage = coverage
        current_proof_lint = proof_lint_result
        current_proof = proof
        current_generation_round = max(1, generation_rounds_used)
        rejected_feedback = ""
        for round_id in range(1, self.config.max_repair_rounds + 1):
            diagnostics = _join_proof_diagnostics(current_coverage, current_proof_lint, current_proof, proof_spec)
            if rejected_feedback:
                diagnostics = diagnostics + "\n\nPrevious rejected proof-repair attempt:\n" + rejected_feedback
            prompt = proof_repair_prompt(
                case,
                plan,
                current,
                diagnostics,
                proof_spec=proof_spec,
                ir_bundle=ir_bundle,
                expose_benchmark_goals=self.config.expose_benchmark_goals,
            )
            store.write_text(f"prompts/04_proof_repair_round_{round_id}.txt", prompt)
            start = perf_counter()
            self._report(
                "proof_repair_start",
                case=case.name,
                round=round_id,
                proof_status=current_proof.status if current_proof else "not_run",
                missing_lemmas=current_coverage.missing,
                proof_lint_issue_count=len(current_proof_lint.issues),
            )
            response, raw_text = self.llm.complete_json_or_text(PROOF_REPAIR_SYSTEM, prompt)
            store.append_jsonl(
                "history/llm_calls.jsonl",
                llm_call_record(
                    self.llm,
                    stage="proof_repair",
                    system=PROOF_REPAIR_SYSTEM,
                    prompt=prompt,
                    attempt=round_id,
                    case=case.name,
                    parsed_json=response is not None,
                    extra={"raw_response_chars": len(raw_text or ""), "round": round_id},
                ),
            )
            if response is None:
                if raw_text.strip():
                    store.write_text(f"history/04_proof_repair_round_{round_id}.raw.txt", raw_text)
                response = {
                    "repair_scope": "full_rewrite",
                    "sapic_plus": raw_text,
                    "repair_notes": ["LLM returned non-JSON text; extracted Sapic+ from raw response."],
                }
            if _repair_requires_ir_review(response):
                marker = _ir_review_required_payload(
                    response,
                    round_id=round_id,
                    proof_spec=proof_spec,
                    current_proof=current_proof,
                )
                store.write_json(f"history/04_proof_repair_round_{round_id}.json", response)
                if not self.config.ir_review_gate_enabled:
                    store.stage_record(
                        "proof_repair_rejected",
                        round=round_id,
                        reason="requires_ir_review_disabled",
                        ir_review_reason=marker["reason"],
                        affected_ir_fields=marker["affected_ir_fields"],
                    )
                    self._report(
                        "proof_repair_rejected",
                        case=case.name,
                        round=round_id,
                        reason="requires_ir_review_disabled",
                        ir_review_reason=marker["reason"],
                    )
                    rejected_feedback = (
                        "The previous proof-repair response requested IR review, but this run has "
                        "IR-review gating disabled. Preserve the reviewed IR/proof expectations and "
                        "return a Sapic+ patch or full rewrite instead. Reported reason: "
                        f"{marker['reason']}"
                    )
                    continue
                store.write_json("ir_review_required.json", marker)
                store.stage_record(
                    "ir_review_required",
                    round=round_id,
                    reason=marker["reason"],
                    affected_ir_fields=marker["affected_ir_fields"],
                    mismatched_results=marker["mismatched_results"],
                )
                self._report(
                    "ir_review_required",
                    case=case.name,
                    round=round_id,
                    reason=marker["reason"],
                    affected_ir_fields=marker["affected_ir_fields"],
                )
                return current, current_verification, current_coverage, current_proof, current_proof_lint, current_generation_round
            repaired, repair_candidate_error = _repair_candidate_from_response(current, response, raw_text)
            if repair_candidate_error:
                store.write_json(f"history/04_proof_repair_round_{round_id}.json", response)
                if raw_text.strip():
                    store.write_text(f"history/04_proof_repair_round_{round_id}.raw.txt", raw_text)
                store.stage_record("proof_repair_rejected", round=round_id, reason=repair_candidate_error)
                self._report("proof_repair_rejected", case=case.name, round=round_id, reason=repair_candidate_error)
                rejected_feedback = f"The previous proof-repair response was rejected before verification: {repair_candidate_error}."
                continue
            if not repaired.strip():
                store.write_json(f"history/04_proof_repair_round_{round_id}.json", response)
                if raw_text.strip():
                    store.write_text(f"history/04_proof_repair_round_{round_id}.raw.txt", raw_text)
                store.stage_record("proof_repair_rejected", round=round_id, reason="empty model")
                self._report("proof_repair_rejected", case=case.name, round=round_id, reason="empty model")
                rejected_feedback = "The previous proof-repair response was rejected before verification: empty model."
                continue
            store.write_json(f"history/04_proof_repair_round_{round_id}.json", response)
            store.write_text(f"models/proof_repaired_{round_id}.spthy", repaired)
            lint_issues = _compile_lint(repaired, proof_spec.names, ir_bundle)
            store.write_json(f"lint/proof_repaired_{round_id}.json", {"issues": lint_issues})
            candidate_verification = self._verify(repaired, store, f"proof_repaired_{round_id}", lint_issues)
            if not candidate_verification.ok or lint_issues:
                store.stage_record(
                    "proof_repair_rejected",
                    round=round_id,
                    reason="compile_failed",
                    status=candidate_verification.status,
                    lint_issues=lint_issues,
                )
                self._report(
                    "proof_repair_rejected",
                    case=case.name,
                    round=round_id,
                    reason="compile_failed",
                    status=candidate_verification.status,
                    warning_count=len(candidate_verification.warnings),
                    lint_issue_count=len(lint_issues),
                )
                rejected_feedback = _proof_repair_rejection_feedback(
                    "compile_failed",
                    candidate_result=candidate_verification,
                    candidate_lint_issues=lint_issues,
                    candidate_sapic=repaired,
                )
                self._report(
                    "proof_repair_done",
                    case=case.name,
                    round=round_id,
                    status="compile_failed",
                    elapsed_sec=round(perf_counter() - start, 2),
                )
                continue
            candidate_coverage = self._lemma_coverage(case, repaired, store, proof_spec.names)
            if not candidate_coverage.ok:
                store.stage_record(
                    "proof_repair_rejected",
                    round=round_id,
                    reason="coverage_failed",
                    missing=candidate_coverage.missing,
                    extra=candidate_coverage.extra,
                )
                self._report(
                    "proof_repair_rejected",
                    case=case.name,
                    round=round_id,
                    reason="coverage_failed",
                    missing_lemmas=candidate_coverage.missing,
                )
                rejected_feedback = _proof_repair_rejection_feedback(
                    "coverage_failed",
                    candidate_result=candidate_verification,
                    candidate_lint_issues=lint_issues,
                    candidate_coverage=candidate_coverage,
                    candidate_sapic=repaired,
                )
                self._report(
                    "proof_repair_done",
                    case=case.name,
                    round=round_id,
                    status="coverage_failed",
                    elapsed_sec=round(perf_counter() - start, 2),
                )
                continue
            candidate_proof_lint = self._proof_lint(case, repaired, store, proof_spec)
            if not candidate_proof_lint.ok:
                store.stage_record(
                    "proof_repair_rejected",
                    round=round_id,
                    reason="proof_lint_failed",
                    proof_lint_issues=candidate_proof_lint.issues,
                )
                self._report(
                    "proof_repair_rejected",
                    case=case.name,
                    round=round_id,
                    reason="proof_lint_failed",
                    proof_lint_issue_count=len(candidate_proof_lint.issues),
                )
                rejected_feedback = _proof_repair_rejection_feedback(
                    "proof_lint_failed",
                    candidate_result=candidate_verification,
                    candidate_lint_issues=lint_issues,
                    candidate_coverage=candidate_coverage,
                    candidate_proof_lint=candidate_proof_lint,
                    candidate_sapic=repaired,
                )
                self._report(
                    "proof_repair_done",
                    case=case.name,
                    round=round_id,
                    status="proof_lint_failed",
                    elapsed_sec=round(perf_counter() - start, 2),
                )
                continue
            candidate_prefix = f"proof/candidates/proof_repaired_{round_id}"
            candidate_proof = self._prove(case, repaired, store, proof_spec, artifact_prefix=candidate_prefix)
            proof_acceptance = _proof_repair_acceptance(current_proof, candidate_proof, proof_spec)
            if not proof_acceptance["accepted"]:
                store.stage_record(
                    "proof_repair_rejected",
                    round=round_id,
                    reason=proof_acceptance["reason"],
                    current_score=proof_acceptance["current_score"],
                    candidate_score=proof_acceptance["candidate_score"],
                    candidate_status=candidate_proof.status,
                    candidate_mismatched_results=candidate_proof.mismatched_results,
                )
                self._report(
                    "proof_repair_rejected",
                    case=case.name,
                    round=round_id,
                    reason=proof_acceptance["reason"],
                    candidate_status=candidate_proof.status,
                    current_status=current_proof.status if current_proof else "not_run",
                    candidate_score=proof_acceptance["candidate_score"],
                    current_score=proof_acceptance["current_score"],
                )
                rejected_feedback = _proof_repair_rejection_feedback(
                    proof_acceptance["reason"],
                    candidate_result=candidate_verification,
                    candidate_lint_issues=lint_issues,
                    candidate_coverage=candidate_coverage,
                    candidate_proof_lint=candidate_proof_lint,
                    candidate_sapic=repaired,
                    candidate_proof=candidate_proof,
                    current_proof=current_proof,
                )
                self._report(
                    "proof_repair_done",
                    case=case.name,
                    round=round_id,
                    status=candidate_proof.status,
                    ok=False,
                    accepted=False,
                    elapsed_sec=round(perf_counter() - start, 2),
                )
                continue
            _promote_proof_candidate(store, candidate_prefix)
            _retarget_promoted_proof_result(candidate_proof, store, candidate_prefix)
            store.write_json("proof/result.json", _proof_result_payload(candidate_proof))
            current = repaired
            current_verification = candidate_verification
            current_coverage = candidate_coverage
            current_proof_lint = candidate_proof_lint
            current_proof = candidate_proof
            rejected_feedback = ""
            store.stage_record(
                "proof_repair",
                round=round_id,
                accepted=True,
                reason=proof_acceptance["reason"],
                current_score=proof_acceptance["current_score"],
                candidate_score=proof_acceptance["candidate_score"],
                status=current_proof.status,
                ok=current_proof.ok,
            )
            self._report(
                "proof_repair_done",
                case=case.name,
                round=round_id,
                status=current_proof.status,
                ok=current_proof.ok,
                accepted=True,
                elapsed_sec=round(perf_counter() - start, 2),
            )
            if current_proof.ok:
                break
        if current_proof and not current_proof.ok:
            regenerated = self._proof_timeout_regenerate(
                case,
                plan,
                ir_bundle,
                proof_spec,
                current,
                current_verification,
                current_coverage,
                current_proof_lint,
                current_proof,
                store,
                current_generation_round,
            )
            if regenerated is not None:
                return regenerated
        return current, current_verification, current_coverage, current_proof or proof, current_proof_lint, current_generation_round

    def _proof_timeout_regenerate(
        self,
        case: ProtocolCase,
        plan: dict[str, Any],
        ir_bundle: dict[str, Any] | None,
        proof_spec: ProofSpec,
        sapic_plus: str,
        verification: VerificationResult,
        coverage,
        proof_lint_result: ProofLintResult,
        proof,
        store: ArtifactStore,
        generation_round: int,
    ):
        if proof.status != "timeout":
            return None
        timeout_diagnostics = _proof_timeout_diagnostics(proof)
        if not timeout_diagnostics:
            return None
        if generation_round >= max(1, self.config.max_generation_rounds):
            return None
        next_round = generation_round + 1
        diagnostics = _join_proof_diagnostics(coverage, proof_lint_result, proof, proof_spec)
        self._report(
            "proof_timeout_regeneration_start",
            case=case.name,
            next_round=next_round,
            previous_round=generation_round,
        )
        store.stage_record(
            "proof_timeout_regeneration_start",
            next_round=next_round,
            previous_round=generation_round,
            diagnosis=timeout_diagnostics,
        )
        try:
            regenerated = self._generate_sapic(
                case,
                plan,
                proof_spec,
                store,
                ir_bundle=ir_bundle,
                generation_round=next_round,
                regeneration_diagnostics=diagnostics,
            )
        except StageFailure as exc:
            store.stage_record(
                "proof_timeout_regeneration_failed",
                generation_round=next_round,
                error=str(exc),
                details=exc.details,
            )
            self._report("proof_timeout_regeneration_failed", case=case.name, round=next_round, error=str(exc))
            return None

        lint_issues = _compile_lint(regenerated, proof_spec.names, ir_bundle)
        label = _generation_initial_label(next_round)
        store.write_json(f"lint/{label}.json", {"issues": lint_issues})
        self._report("lint_done", case=case.name, label=label, issue_count=len(lint_issues))
        regenerated_verification = self._verify(regenerated, store, label, lint_issues)
        regenerated, regenerated_verification, lint_issues, used_round = self._compile_repair_or_regenerate(
            case,
            plan,
            ir_bundle,
            proof_spec,
            regenerated,
            regenerated_verification,
            lint_issues,
            store,
            next_round,
        )
        regenerated_coverage = self._lemma_coverage(case, regenerated, store, proof_spec.names)
        regenerated_proof_lint = self._proof_lint(case, regenerated, store, proof_spec)
        if not regenerated_verification.ok or lint_issues or not regenerated_coverage.ok or not regenerated_proof_lint.ok:
            self._report(
                "proof_timeout_regeneration_done",
                case=case.name,
                round=used_round,
                status=regenerated_verification.status,
                ok=False,
                accepted=False,
            )
            return None
        candidate_prefix = f"proof/candidates/regenerated_{used_round}"
        regenerated_proof = self._prove(case, regenerated, store, proof_spec, artifact_prefix=candidate_prefix)
        accepted = regenerated_proof.ok or regenerated_proof.status != proof.status
        self._report(
            "proof_timeout_regeneration_done",
            case=case.name,
            round=used_round,
            status=regenerated_proof.status if regenerated_proof else "not_run",
            ok=regenerated_proof.ok if regenerated_proof else False,
            accepted=accepted,
        )
        if not accepted:
            return None
        _promote_proof_candidate(store, candidate_prefix)
        _retarget_promoted_proof_result(regenerated_proof, store, candidate_prefix)
        store.write_json("proof/result.json", _proof_result_payload(regenerated_proof))
        return regenerated, regenerated_verification, regenerated_coverage, regenerated_proof, regenerated_proof_lint, used_round

    def _report(self, event: str, **payload: Any) -> None:
        if self.reporter is not None:
            self.reporter(event, payload)

    def _offline_plan(self, case: ProtocolCase) -> dict[str, Any]:
        return {
            "protocol_name": case.name,
            "roles": [],
            "fresh_values": [],
            "long_term_keys": [],
            "messages": [],
            "checks": [],
            "events": [],
            "lemmas": case.goals,
            "abstractions": ["Offline placeholder; run without --skip-llm for real modeling."],
            "open_questions": [],
        }

    def _target_lemma_names(self, case: ProtocolCase, sapic_plus: str) -> list[str]:
        if self.config.expose_benchmark_goals:
            return _expected_lemma_names(case)
        return extract_lemma_names(sapic_plus)

    def _build_proof_spec(self, case: ProtocolCase, store: ArtifactStore) -> ProofSpec:
        proof_spec = build_initial_proof_spec(case, expose_benchmark_goals=self.config.expose_benchmark_goals)
        store.write_json("proof/spec.initial.json", proof_spec)
        store.stage_record(
            "proof_spec",
            mode=proof_spec.mode,
            source=proof_spec.source,
            lemmas=proof_spec.names,
            expected_states=proof_spec.expected_states,
        )
        return proof_spec

    def _offline_sapic(self, case: ProtocolCase) -> str:
        theory_name = "".join(ch if ch.isalnum() else "_" for ch in case.name)
        theory_name = theory_name or "Protocol"
        return f"""theory {theory_name}
begin

builtins: symmetric-encryption

process:
  0

end
"""


def _generation_prompt_path(generation_round: int) -> str:
    if generation_round <= 1:
        return "prompts/02_sapic_generation.txt"
    return f"prompts/02_sapic_generation_round_{generation_round}.txt"


def _generation_history_prefix(generation_round: int) -> str:
    if generation_round <= 1:
        return "02_sapic_generation"
    return f"02_sapic_generation_round_{generation_round}"


def _generation_initial_label(generation_round: int) -> str:
    if generation_round <= 1:
        return "initial"
    return f"regenerated_{generation_round}"


def _repair_label(generation_round: int, repair_round: int) -> str:
    if generation_round <= 1:
        return f"repaired_{repair_round}"
    return f"regenerated_{generation_round}_repaired_{repair_round}"


def _repair_prompt_stem(generation_round: int, repair_round: int) -> str:
    if generation_round <= 1:
        return f"03_repair_round_{repair_round}"
    return f"03_generation_{generation_round}_repair_round_{repair_round}"


def _join_proof_diagnostics(coverage, proof_lint_result: ProofLintResult, proof, proof_spec: ProofSpec) -> str:
    parts = [
        "Full proof gate failed. Preserve the protocol semantics and target lemma names.",
        "The objective is to match each target lemma expected_state, not to force every lemma to verified.",
        "Proof expectations:\n"
        + "\n".join(
            f"- {item.name}: expected_state={item.expected_state}, trace_kind={item.trace_kind}, goal_type={item.goal_type}"
            for item in proof_spec.expectations
        ),
    ]
    if coverage and not coverage.ok:
        parts.append("Missing target lemmas:\n" + "\n".join(f"- {name}" for name in coverage.missing))
    if proof_lint_result and not proof_lint_result.ok:
        parts.append("Local proof lint issues:\n" + "\n".join(f"- {issue}" for issue in proof_lint_result.issues))
    if proof:
        parts.append(f"Proof status: {proof.status}")
        if proof.lemma_expected_states or proof.lemma_actual_states:
            rows = []
            for name in proof_spec.names:
                rows.append(
                    "- {name}: expected={expected}, actual={actual}, raw={raw}, match={match}".format(
                        name=name,
                        expected=proof.lemma_expected_states.get(name, proof_spec.expected_states.get(name)),
                        actual=proof.lemma_actual_states.get(name, "MissingProofResult"),
                        raw=proof.lemma_results.get(name, "<missing>"),
                        match=proof.lemma_matches.get(name, False),
                    )
                )
            parts.append("Expected-vs-actual target lemma states:\n" + "\n".join(rows))
        if proof.mismatched_results:
            parts.append("Mismatched target lemmas:\n" + "\n".join(f"- {name}" for name in proof.mismatched_results))
        if proof.lemma_results:
            parts.append(
                "Target lemma proof results:\n"
                + "\n".join(f"- {name}: {result}" for name, result in proof.lemma_results.items())
            )
        if proof.missing_results:
            parts.append("Missing proof results:\n" + "\n".join(f"- {name}" for name in proof.missing_results))
        timeout_diagnostics = _proof_timeout_diagnostics(proof)
        if timeout_diagnostics:
            parts.append(timeout_diagnostics)
        if proof.stderr:
            parts.append("Tamarin proof stderr:\n" + proof.stderr[-4000:])
        if proof.stdout:
            parts.append("Tamarin proof stdout tail:\n" + proof.stdout[-8000:])
    return "\n\n".join(parts)


def _proof_timeout_diagnostics(proof) -> str:
    if proof.status != "timeout":
        return ""
    text = "\n".join(
        str(part or "")
        for part in [
            proof.stdout,
            proof.stderr,
            *(
                f"{record.get('stdout', '')}\n{record.get('stderr', '')}"
                for record in (proof.per_lemma or {}).values()
                if isinstance(record, dict)
            ),
        ]
    )
    signals: list[str] = []
    heavy_term = r"(?:fst|snd|sdec|adec|hkdf|hmac|hash|verify)\("
    if re.search(rf'process="event[\s\S]{{0,1000}}{heavy_term}', text) or re.search(
        rf"--\[[\s\S]{{0,300}}(?:Secret|Running|Commit)[\s\S]{{0,1000}}{heavy_term}",
        text,
    ):
        signals.append(
            "Translated proof event payloads contain selector/destructor/crypto expressions; shrink event payloads to compact bound variables or session identifiers."
        )
    if re.search(r"process=\"event\s+(?:Secret|Running|Commit)[\s\S]{0,700}\b(?:recv|received|cipher|pkg|ticket|plain|fst|snd|sdec)\b", text):
        signals.append(
            "Risk-only semantic hint: proof events appear to carry values or identities close to received/decrypted network data. If those are intended principals or secrets, bind them to checked role identities/state before emitting Secret/Running/Commit events; otherwise state the assumption in modeling_notes."
        )
    if re.search(rf"State_[^\n]*{heavy_term}", text):
        signals.append(
            "Translated state facts carry repeated derived terms; introduce stable phase/session variables instead of reusing derived expressions across later events."
        )
    if re.search(r"\bvariants \(modulo AC\)\s*(?:\n|\r\n)\s*1\.", text):
        signals.append(
            "Tamarin is exploring many constructor/destructor variants; reduce nested parsing and avoid adding tuple-destructuring patches to a compile-clean model."
        )
    if "Derivation checks timed out" in text:
        signals.append(
            "Derivation checks timed out before proof search; regenerate or rewrite with smaller role topology and less nested term structure."
        )
    if proof.missing_results and proof.lemma_results:
        timeout_count = len(proof.missing_results)
        proved_count = len(proof.lemma_results)
        if timeout_count > proved_count:
            signals.append(
                "Risk-only search hint: some target lemmas prove or falsify, but most targets have no proof result. Keep proven target semantics, then simplify only the shared event/session representation used by the missing timeout targets."
            )
    if not signals:
        return ""
    return "Proof-timeout diagnosis:\n" + "\n".join(f"- {signal}" for signal in dict.fromkeys(signals))


def _proof_result_payload(proof) -> dict[str, Any]:
    return {
        "ok": proof.ok,
        "status": proof.status,
        "returncode": proof.returncode,
        "warnings": proof.warnings,
        "lemma_results": proof.lemma_results,
        "missing_results": proof.missing_results,
        "lemma_expected_states": proof.lemma_expected_states,
        "lemma_actual_states": proof.lemma_actual_states,
        "lemma_matches": proof.lemma_matches,
        "mismatched_results": proof.mismatched_results,
        "per_lemma": proof.per_lemma,
        "command": proof.command,
        "output_path": proof.output_path,
        "elapsed_sec": proof.elapsed_sec,
    }


def _proof_result_from_per_lemma(
    per_lemma: dict[str, dict[str, Any]],
    proof_spec: ProofSpec,
    output_path: Path,
):
    from .sapic import ProofResult

    lemma_results = {
        name: str(record["lemma_result"])
        for name, record in per_lemma.items()
        if record.get("lemma_result")
    }
    missing_results = [
        name
        for name in proof_spec.names
        if name not in lemma_results or per_lemma.get(name, {}).get("status") == "missing-proof-results"
    ]
    lemma_expected_states = dict(proof_spec.expected_states)
    lemma_actual_states = {
        name: str(per_lemma.get(name, {}).get("actual_state") or actual_state_from_result(lemma_results.get(name)))
        for name in proof_spec.names
    }
    lemma_matches = {
        name: bool(per_lemma.get(name, {}).get("matches_expected"))
        for name in proof_spec.names
    }
    mismatched_results = [name for name in proof_spec.names if not lemma_matches.get(name, False)]
    warnings = []
    for record in per_lemma.values():
        warnings.extend(str(warning) for warning in record.get("warnings", []) or [])
    returncodes = [int(record.get("returncode") or 0) for record in per_lemma.values()]
    elapsed_sec = sum(float(record.get("elapsed_sec") or 0) for record in per_lemma.values())
    statuses = {str(record.get("status") or "") for record in per_lemma.values()}
    if any(code == 124 for code in returncodes) or "timeout" in statuses:
        status = "timeout"
        returncode = 124
    elif any(code not in {0, 124} for code in returncodes) or "failed" in statuses:
        status = "failed"
        returncode = next((code for code in returncodes if code not in {0, 124}), 1)
    elif warnings:
        status = "warnings"
        returncode = 0
    elif missing_results:
        status = "missing-proof-results"
        returncode = 0
    elif mismatched_results:
        status = "expectation-mismatch"
        returncode = 0
    elif any(lemma_actual_states.get(name) == "CounterexampleFound" for name in proof_spec.names):
        status = "expected-matched"
        returncode = 0
    else:
        status = "verified"
        returncode = 0
    return ProofResult(
        ok=status in {"verified", "expected-matched"},
        status=status,
        returncode=returncode,
        stdout="",
        stderr="",
        command=[],
        output_path=output_path,
        warnings=warnings,
        lemma_results=lemma_results,
        missing_results=missing_results,
        lemma_actual_states=lemma_actual_states,
        lemma_expected_states=lemma_expected_states,
        lemma_matches=lemma_matches,
        mismatched_results=mismatched_results,
        per_lemma=per_lemma,
        elapsed_sec=round(elapsed_sec, 3),
    )


def _promote_proof_candidate(store: ArtifactStore, candidate_prefix: str) -> None:
    for name in ("model.spthy", "stdout.txt", "stderr.txt", "result.json"):
        source = store.path(f"{candidate_prefix}/{name}")
        if source.exists():
            store.write_text(f"proof/{name}", source.read_text(encoding="utf-8", errors="replace"))
    candidate_per_lemma = store.path(f"{candidate_prefix}/per_lemma")
    if not candidate_per_lemma.exists():
        return
    for source in candidate_per_lemma.iterdir():
        if source.is_file():
            store.write_text(
                f"proof/per_lemma/{source.name}",
                source.read_text(encoding="utf-8", errors="replace"),
            )


def _retarget_promoted_proof_result(proof, store: ArtifactStore, candidate_prefix: str) -> None:
    candidate_root = str(store.path(candidate_prefix))
    proof_root = str(store.path("proof"))
    proof.output_path = store.path("proof/model.spthy")
    proof.command = [_replace_path_prefix(item, candidate_root, proof_root) for item in proof.command]
    for record in (proof.per_lemma or {}).values():
        if not isinstance(record, dict):
            continue
        output_path = record.get("output_path")
        if output_path:
            record["output_path"] = _replace_path_prefix(str(output_path), candidate_root, proof_root)
        command = record.get("command")
        if isinstance(command, list):
            record["command"] = [_replace_path_prefix(item, candidate_root, proof_root) for item in command]


def _replace_path_prefix(value: Any, old_root: str, new_root: str) -> Any:
    if not isinstance(value, str):
        return value
    if value == old_root:
        return new_root
    if value.startswith(old_root + "/"):
        return new_root + value[len(old_root):]
    return value


def _proof_repair_acceptance(current_proof, candidate_proof, proof_spec: ProofSpec) -> dict[str, Any]:
    current_score = _proof_candidate_score(current_proof, proof_spec)
    candidate_score = _proof_candidate_score(candidate_proof, proof_spec)
    accepted = candidate_score > current_score
    if candidate_proof and candidate_proof.ok:
        accepted = True
    reason = "improved_proof" if accepted else "candidate_not_better_proof"
    return {
        "accepted": accepted,
        "reason": reason,
        "current_score": current_score,
        "candidate_score": candidate_score,
    }


def _proof_candidate_score(proof, proof_spec: ProofSpec) -> tuple[int, int, int, int, int]:
    if proof is None:
        return (-1, -len(proof_spec.names), -len(proof_spec.names), -len(proof_spec.names), 0)
    status_rank = {
        "not_run": 0,
        "tool_missing": 0,
        "timeout": 1,
        "missing-proof-results": 2,
        "failed": 3,
        "warnings": 4,
        "expectation-mismatch": 5,
        "expected-matched": 6,
        "verified": 7,
    }.get(str(proof.status or ""), 1)
    matched_count = sum(1 for value in (proof.lemma_matches or {}).values() if value)
    mismatched_count = len(proof.mismatched_results or [])
    missing_count = len(proof.missing_results or [])
    timeout_count = sum(
        1
        for record in (proof.per_lemma or {}).values()
        if isinstance(record, dict) and str(record.get("status") or "") == "timeout"
    )
    return (matched_count, -missing_count, -mismatched_count, -timeout_count, status_rank)


def _compile_repair_acceptance(
    current_result: VerificationResult,
    current_lint_issues: list[str],
    current_sapic: str,
    candidate_result: VerificationResult,
    candidate_lint_issues: list[str],
    candidate_sapic: str,
    expected_lemmas: list[str],
) -> dict[str, Any]:
    current_score = _compile_candidate_score(current_result, current_lint_issues, current_sapic, expected_lemmas)
    candidate_score = _compile_candidate_score(candidate_result, candidate_lint_issues, candidate_sapic, expected_lemmas)
    candidate_coverage = lemma_coverage(candidate_sapic, expected_lemmas) if expected_lemmas else None
    current_coverage = lemma_coverage(current_sapic, expected_lemmas) if expected_lemmas else None
    accepted = candidate_score > current_score
    if candidate_result.ok and candidate_coverage and not candidate_coverage.ok:
        accepted = False
    if (
        candidate_result.ok
        and candidate_coverage
        and candidate_coverage.ok
        and current_coverage
        and current_coverage.ok
        and not current_result.ok
    ):
        accepted = True
    reason = "improved" if accepted else _repair_rejection_reason(current_score, candidate_score)
    if candidate_result.ok and candidate_coverage and not candidate_coverage.ok:
        reason = "candidate_clean_but_missing_target_lemmas"
    return {
        "accepted": accepted,
        "reason": reason,
        "current_score": current_score,
        "candidate_score": candidate_score,
    }


def _compile_candidate_score(
    result: VerificationResult,
    lint_issues: list[str],
    sapic_plus: str,
    expected_lemmas: list[str],
) -> tuple[int, int, int, int, int, int]:
    status_rank = {"failed": 0, "warnings": 1, "clean": 2}.get(result.status, 0)
    coverage = lemma_coverage(sapic_plus, expected_lemmas) if expected_lemmas else None
    coverage_rank = 1 if coverage is None or coverage.ok else 0
    missing_count = len(coverage.missing) if coverage else 0
    return (
        status_rank,
        coverage_rank,
        -missing_count,
        -len(result.warnings),
        -_tamarin_warning_detail_count(result),
        -len(lint_issues),
    )


def _compile_lint(
    sapic_plus: str,
    expected_lemmas: list[str] | None = None,
    ir_bundle: dict[str, Any] | None = None,
) -> list[str]:
    issues = basic_sapic_lint(sapic_plus)
    issues.extend(target_lemma_lint(sapic_plus, expected_lemmas or []))
    issues.extend(semantic_constraint_lint(sapic_plus, _semantic_constraints(ir_bundle)))
    return issues


def _compile_problem_signature(result: VerificationResult, lint_issues: list[str]) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    return (
        result.status,
        tuple(_normalize_problem_text(warning) for warning in result.warnings),
        (f"warning_detail_count={_tamarin_warning_detail_count(result)}",),
        tuple(_normalize_problem_text(issue) for issue in lint_issues),
    )


def _normalize_problem_text(value: str) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\bline\s+\d+\b", "line <n>", text, flags=re.IGNORECASE)
    text = re.sub(r"\bcolumn\s+\d+\b", "column <n>", text, flags=re.IGNORECASE)
    text = re.sub(r"`State_[^`']+['`]?", "`State_<id>`", text)
    text = re.sub(r'"State_[^"]+"', '"State_<id>"', text)
    text = re.sub(r"\bState_[A-Za-z0-9_]+\b", "State_<id>", text)
    text = re.sub(r"\s+", " ", text)
    return text


def _tamarin_warning_detail_count(result: VerificationResult) -> int:
    output = result.diagnostics
    counts = [
        len(re.findall(r'(?m)^\s+\d+\.\s+in rule\b', output)),
        len(re.findall(r'(?m)^\s*Wellformedness-error\b', output)),
        len(re.findall(r'(?m)^\s*Variable bound twice\b', output)),
    ]
    return max(counts)


def _rejected_repair_feedback(
    acceptance: dict[str, Any],
    candidate_result: VerificationResult,
    candidate_lint_issues: list[str],
    candidate_sapic: str,
) -> str:
    parts = [
        f"The previous candidate was rejected because `{acceptance.get('reason')}`.",
        f"Candidate status was `{candidate_result.status}` with returncode={candidate_result.returncode}.",
    ]
    if candidate_lint_issues:
        parts.append("Candidate local lint issues:")
        parts.extend(f"- {issue}" for issue in candidate_lint_issues[:8])
    if candidate_result.warnings:
        parts.append("Candidate Tamarin warnings:")
        parts.extend(f"- {warning}" for warning in candidate_result.warnings[:8])
    if candidate_result.stderr:
        parts.append("Candidate stderr tail:\n" + candidate_result.stderr[-2000:])
    elif candidate_result.stdout:
        parts.append("Candidate stdout tail:\n" + candidate_result.stdout[-2000:])
    if re.search(r'(?m)^\s*[&|]\s*"', candidate_sapic or ""):
        parts.append("The candidate split a lemma formula into multiple quoted fragments; keep each lemma formula as one quoted string.")
    if re.search(r"\\[\/]|\/\\", candidate_sapic or ""):
        parts.append("The candidate used escaped logical operators such as `\\/` or `/\\`; use Tamarin `|` and `&` inside quoted formulas.")
    return "\n".join(parts)


def _proof_repair_rejection_feedback(
    reason: str,
    *,
    candidate_result: VerificationResult,
    candidate_lint_issues: list[str],
    candidate_sapic: str,
    candidate_coverage: Any | None = None,
    candidate_proof_lint: ProofLintResult | None = None,
    candidate_proof: Any | None = None,
    current_proof: Any | None = None,
) -> str:
    parts = [
        f"The previous proof-repair candidate was rejected because `{reason}`.",
        "Continue from the last compile-clean model, not from the rejected candidate.",
        f"Candidate compile status was `{candidate_result.status}` with returncode={candidate_result.returncode}.",
    ]
    if candidate_lint_issues:
        parts.append("Candidate local lint issues:")
        parts.extend(f"- {issue}" for issue in candidate_lint_issues[:8])
    if candidate_result.warnings:
        parts.append("Candidate Tamarin warnings:")
        parts.extend(f"- {warning}" for warning in candidate_result.warnings[:8])
    if candidate_coverage is not None and not candidate_coverage.ok:
        if candidate_coverage.missing:
            parts.append("Candidate missing target lemmas:")
            parts.extend(f"- {name}" for name in candidate_coverage.missing[:8])
        if candidate_coverage.extra:
            parts.append("Candidate extra lemmas:")
            parts.extend(f"- {name}" for name in candidate_coverage.extra[:8])
    if candidate_proof_lint is not None and not candidate_proof_lint.ok:
        parts.append("Candidate proof lint issues:")
        parts.extend(f"- {issue}" for issue in candidate_proof_lint.issues[:8])
    if candidate_proof is not None:
        parts.append(f"Candidate proof status was `{candidate_proof.status}`.")
        if candidate_proof.mismatched_results:
            parts.append("Candidate mismatched target lemmas:")
            parts.extend(f"- {name}" for name in candidate_proof.mismatched_results[:8])
        if candidate_proof.lemma_results:
            parts.append("Candidate target proof results:")
            parts.extend(f"- {name}: {result}" for name, result in list(candidate_proof.lemma_results.items())[:8])
    if current_proof is not None:
        parts.append(f"Current accepted proof status remains `{current_proof.status}`.")
        if current_proof.mismatched_results:
            parts.append("Current accepted mismatched target lemmas:")
            parts.extend(f"- {name}" for name in current_proof.mismatched_results[:8])
    if candidate_result.stderr:
        parts.append("Candidate stderr tail:\n" + candidate_result.stderr[-2000:])
    elif candidate_result.stdout:
        parts.append("Candidate stdout tail:\n" + candidate_result.stdout[-2000:])
    if _has_decrypt_tuple_destructure(candidate_sapic):
        parts.append(
            "The candidate reintroduced tuple destructuring immediately after decrypting an untrusted ciphertext; keep the decrypt/projection/check style from the last compile-clean model."
        )
    return "\n".join(parts)


def _has_decrypt_tuple_destructure(sapic_plus: str) -> bool:
    return bool(
        re.search(r"(?m)^\s*let\s+<[^>\n]+>\s*=\s*(?:sdec|adec)\s*\(", sapic_plus or "")
        or re.search(
            r"(?ms)^\s*let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:sdec|adec)\s*\([^;\n]+\)\s+in\s*\n\s*let\s+<[^>\n]+>\s*=\s*\1\b",
            sapic_plus or "",
        )
    )


def _repair_candidate_from_response(
    current_sapic: str,
    response: dict[str, Any],
    raw_text: str,
) -> tuple[str, str]:
    scope = str(response.get("repair_scope") or "").strip().lower()
    if scope == "requires_ir_review":
        return "", "requires_ir_review"
    patches = response.get("patches")
    if scope == "local_patch" or patches:
        if not isinstance(patches, list) or not patches:
            return "", "local_patch_missing_patches"
        patched, error = _apply_local_patches(current_sapic, patches)
        if error:
            return "", error
        return patched, ""

    sapic_value = response.get("sapic_plus", raw_text)
    repaired = extract_sapic(str(sapic_value))
    return repaired, ""


def _repair_requires_ir_review(response: dict[str, Any]) -> bool:
    scope = str(response.get("repair_scope") or "").strip().lower().replace("-", "_")
    if scope in {"requires_ir_review", "needs_ir_review", "ir_review_required"}:
        return True
    return response.get("requires_ir_review") is True


def _ir_review_required_payload(
    response: dict[str, Any],
    *,
    round_id: int,
    proof_spec: ProofSpec,
    current_proof: Any,
) -> dict[str, Any]:
    reason = str(
        response.get("ir_review_reason")
        or response.get("reason")
        or "Proof repair requires changing reviewed IR or proof-context semantics."
    ).strip()
    affected_fields = _string_list(
        response.get("affected_ir_fields")
        or response.get("affected_fields")
        or response.get("ir_fields")
        or []
    )
    repair_notes = _string_list(response.get("repair_notes") or response.get("notes") or [])
    return {
        "status": "needs_ir_review",
        "repair_scope": "requires_ir_review",
        "round": round_id,
        "reason": reason,
        "affected_ir_fields": affected_fields,
        "repair_notes": repair_notes,
        "proof_status": current_proof.status if current_proof else "not_run",
        "mismatched_results": list(current_proof.mismatched_results or []) if current_proof else [],
        "missing_results": list(current_proof.missing_results or []) if current_proof else [],
        "proof_lemma_expected_states": proof_spec.expected_states,
        "proof_lemma_actual_states": dict(current_proof.lemma_actual_states or {}) if current_proof else {},
    }


def _load_ir_review_required(store: ArtifactStore) -> dict[str, Any]:
    path = store.path("ir_review_required.json")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _clear_ir_review_required(store: ArtifactStore) -> None:
    try:
        store.path("ir_review_required.json").unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []


def _sapic_json_failure_reason(raw_text: str, extracted_sapic: str) -> str:
    if not (raw_text or "").strip():
        return "empty_response"
    if extracted_sapic and not _sapic_complete_enough(extracted_sapic, []):
        return _incomplete_sapic_reason(extracted_sapic, [])
    if extracted_sapic:
        return "non_json_response_with_complete_sapic"
    return "non_json_response_without_extractable_sapic"


def _sapic_complete_enough(sapic_plus: str, expected_lemmas: list[str]) -> bool:
    return not _incomplete_sapic_reason(sapic_plus, expected_lemmas)


def _incomplete_sapic_reason(sapic_plus: str, expected_lemmas: list[str]) -> str:
    text = sapic_plus or ""
    stripped = text.strip()
    if not stripped:
        return "empty_sapic"
    if not re.search(r"(?m)^\s*theory\s+[A-Za-z_][A-Za-z0-9_]*\b", text):
        return "missing_theory_header"
    if not re.search(r"(?m)^\s*begin\b", text):
        return "missing_begin"
    if not re.search(r"(?m)^\s*process\s*:", text):
        return "missing_process_block"
    if not re.search(r"(?m)^\s*end\s*$", text):
        return "missing_trailing_end"
    present = set(extract_lemma_names(text))
    missing = [name for name in expected_lemmas if name and name not in present]
    if missing:
        return "missing_target_lemmas:" + ",".join(missing[:8])
    return ""


def _apply_local_patches(current_sapic: str, patches: list[Any]) -> tuple[str, str]:
    patched = current_sapic
    text_patches: list[tuple[int, str, str]] = []
    line_patches: list[tuple[int, int, int, str]] = []
    for index, patch in enumerate(patches, start=1):
        if not isinstance(patch, dict):
            return "", f"local_patch_{index}_not_object"
        patch_type = str(patch.get("type") or "").strip()
        if patch_type == "replace_text":
            old = str(patch.get("old") or "")
            new = str(patch.get("new") or "")
            if not old:
                return "", f"local_patch_{index}_empty_old_text"
            text_patches.append((index, old, new))
        elif patch_type == "replace_lines":
            start_line = _positive_int(patch.get("start_line"))
            end_line = _positive_int(patch.get("end_line"))
            if start_line is None or end_line is None or end_line < start_line:
                return "", f"local_patch_{index}_invalid_line_range"
            lines = current_sapic.splitlines()
            if start_line > len(lines) or end_line > len(lines):
                return "", f"local_patch_{index}_line_range_out_of_bounds"
            line_patches.append((index, start_line, end_line, str(patch.get("new") or "")))
        else:
            return "", f"local_patch_{index}_unknown_type_{patch_type or 'missing'}"
    for index, old, new in text_patches:
        count = patched.count(old)
        if count != 1:
            return "", f"local_patch_{index}_old_text_match_count_{count}"
        patched = patched.replace(old, new, 1)
    if line_patches:
        sorted_ranges = sorted(line_patches, key=lambda item: (item[1], item[2]))
        previous_end = 0
        for index, start_line, end_line, _new in sorted_ranges:
            if start_line <= previous_end:
                return "", f"local_patch_{index}_overlapping_line_range"
            previous_end = end_line
        lines = patched.splitlines()
        for _index, start_line, end_line, new in sorted(line_patches, key=lambda item: item[1], reverse=True):
            replacement = new.splitlines()
            lines[start_line - 1 : end_line] = replacement
        trailing_newline = "\n" if patched.endswith("\n") else ""
        patched = "\n".join(lines) + trailing_newline
    return patched, ""


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _repair_rejection_reason(
    current_score: tuple[int, int, int, int, int, int],
    candidate_score: tuple[int, int, int, int, int, int],
) -> str:
    labels = [
        "status",
        "lemma_coverage",
        "missing_lemma_count",
        "warning_count",
        "warning_detail_count",
        "lint_issue_count",
    ]
    for label, current, candidate in zip(labels, current_score, candidate_score):
        if candidate < current:
            return f"candidate_worse_{label}"
    return "candidate_not_better"


def _expected_lemma_names(case: ProtocolCase) -> list[str]:
    names: list[str] = []
    for goal in case.goals:
        if isinstance(goal, dict) and goal.get("name"):
            names.append(str(goal["name"]))
    return names


def _final_outcome(
    summary: dict[str, Any],
    *,
    prove_enabled: bool,
    ir_review_gate_enabled: bool = True,
) -> dict[str, Any]:
    if ir_review_gate_enabled and summary.get("ir_review_required") is True:
        return {"ok": False, "status": "needs_ir_review"}
    verification_ok = summary.get("verification_ok")
    verification_status = str(summary.get("verification_status") or "not_run")
    if verification_ok is not True:
        return {"ok": False if verification_ok is False else None, "status": verification_status}

    if not prove_enabled:
        return {"ok": True, "status": verification_status}

    proof_ok = summary.get("proof_ok")
    proof_status = str(summary.get("proof_status") or "skipped")
    if proof_ok is True:
        return {"ok": True, "status": proof_status}
    if proof_ok is False:
        return {"ok": False, "status": f"proof_{proof_status}"}
    return {"ok": False, "status": f"proof_{proof_status}"}


def _open_question_entries(open_questions: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(_as_open_question_list(open_questions), start=1):
        if isinstance(raw, dict):
            question = str(raw.get("question") or raw.get("text") or raw.get("description") or raw)
            entry = dict(raw)
        else:
            question = str(raw)
            entry = {"question": question}
        question_key = question.strip()
        if not question_key or question_key in seen:
            continue
        seen.add(question_key)
        entry["id"] = str(entry.get("id") or entry.get("key") or f"q{index}")
        entry["question"] = question
        entries.append(entry)
    return entries


def _limit_open_questions(questions: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    return questions[:limit]


def _select_semantic_review_questions(
    review_questions: list[dict[str, Any]],
    planner_questions: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    covered_categories = _covered_semantic_review_categories(planner_questions)
    selected = [
        question
        for question in review_questions
        if _semantic_review_category(question) not in covered_categories
    ]
    if not selected and not planner_questions:
        selected = review_questions
    selected.sort(key=_open_question_priority)
    return selected[:limit]


def _clear_plan_open_questions(plan: dict[str, Any]) -> None:
    if not isinstance(plan, dict):
        return
    plan["open_questions"] = []
    protocol_ir = plan.get("protocol_ir")
    if isinstance(protocol_ir, dict):
        protocol_ir["open_questions"] = []


def _plan_roles(plan: dict[str, Any]) -> list[Any]:
    if not isinstance(plan, dict):
        return []
    roles = plan.get("roles")
    if isinstance(roles, list):
        return roles
    protocol_ir = plan.get("protocol_ir")
    if isinstance(protocol_ir, dict):
        nested_roles = protocol_ir.get("roles")
        if isinstance(nested_roles, list):
            return nested_roles
    return []


def _should_ask_open_questions(
    question_policy: str,
    ask_open_questions: bool,
    stage: str,
    case: ProtocolCase,
    ir_bundle: dict[str, Any] | None,
    questions: list[dict[str, Any]],
) -> bool:
    policy = (question_policy or "manual").lower()
    if policy == "off":
        return False
    if policy == "manual":
        return ask_open_questions
    if policy != "auto":
        return ask_open_questions
    if not questions:
        return False
    difficulty = (case.difficulty or "").lower()
    if difficulty == "easy":
        return False
    if stage == "planner":
        if ask_open_questions and difficulty in {"medium", "hard"}:
            return True
        return difficulty == "hard"
    risk = _question_risk(case, ir_bundle, questions)
    threshold = 5
    if ask_open_questions:
        return risk["score"] >= threshold
    return difficulty == "hard" and risk["score"] >= threshold


def _question_policy_skip_reason(
    question_policy: str,
    case: ProtocolCase,
    ir_bundle: dict[str, Any] | None,
) -> str:
    policy = (question_policy or "manual").lower()
    if policy == "off":
        return "question_policy=off"
    if policy == "auto":
        risk = _question_risk(case, ir_bundle, _open_question_entries(_semantic_review_questions(ir_bundle)))
        return f"question_policy=auto risk_score={risk['score']} below ask threshold"
    return "--ask-open-questions not set"


def _question_risk(
    case: ProtocolCase,
    ir_bundle: dict[str, Any] | None,
    questions: list[dict[str, Any]],
) -> dict[str, Any]:
    score = 0
    triggers: list[str] = []
    difficulty = (case.difficulty or "").lower()
    if difficulty == "hard":
        score += 3
        triggers.append("difficulty=hard")
    elif difficulty == "medium":
        score += 2
        triggers.append("difficulty=medium")

    boundary = _preservation_boundary(ir_bundle)
    boundary_score = int(boundary.get("score") or 0)
    if boundary_score >= 8:
        score += 3
        triggers.append(f"preservation_boundary_score={boundary_score}")
    elif boundary_score >= 5:
        score += 2
        triggers.append(f"preservation_boundary_score={boundary_score}")

    validation = (ir_bundle or {}).get("validation") if ir_bundle else {}
    if isinstance(validation, dict) and validation.get("warnings"):
        score += 1
        triggers.append(f"ir_warning_count={len(validation.get('warnings') or [])}")

    proof_context = _proof_context(ir_bundle)
    target_lemmas = proof_context.get("target_lemmas") if isinstance(proof_context, dict) else []
    goal_types = {
        str(target.get("goal_type") or "").lower()
        for target in target_lemmas
        if isinstance(target, dict)
    }
    expected_states = {
        str(target.get("expected_state") or "")
        for target in target_lemmas
        if isinstance(target, dict)
    }
    if goal_types.intersection({"authentication", "secrecy", "source"}):
        score += 1
        triggers.append("proof_sensitive_goal_types")
    if "CounterexampleFound" in expected_states:
        score += 1
        triggers.append("expected_counterexample_target")
    if any(str(question.get("severity") or "").lower() == "high" for question in questions):
        score += 1
        triggers.append("high_severity_question")
    return {"score": score, "triggers": triggers}


def _semantic_assumption_ledger(
    case: ProtocolCase,
    proof_spec: ProofSpec,
    ir_bundle: dict[str, Any],
    unresolved_questions: list[dict[str, Any]],
    raw_questions: list[dict[str, Any]],
) -> dict[str, Any]:
    risk = _question_risk(case, ir_bundle, raw_questions)
    boundary = _preservation_boundary(ir_bundle)
    validation = ir_bundle.get("validation") if isinstance(ir_bundle, dict) else {}
    proof_context = _proof_context(ir_bundle)
    target_lemmas = proof_context.get("target_lemmas") if isinstance(proof_context, dict) else []
    return {
        "case": case.name,
        "difficulty": case.difficulty,
        "risk_score": risk["score"],
        "risk_level": "high" if risk["score"] >= 7 else ("medium" if risk["score"] >= 4 else "low"),
        "risk_triggers": risk["triggers"],
        "preservation_boundary": {
            "needed": boundary.get("needed"),
            "score": boundary.get("score"),
            "triggers": boundary.get("triggers", []),
        },
        "ir_warnings": validation.get("warnings", []) if isinstance(validation, dict) else [],
        "target_lemmas": [
            {
                "name": target.get("name"),
                "goal_type": target.get("goal_type"),
                "expected_state": target.get("expected_state"),
            }
            for target in target_lemmas
            if isinstance(target, dict)
        ],
        "proof_expectations": [
            {
                "name": item.name,
                "goal_type": item.goal_type,
                "expected_state": item.expected_state,
            }
            for item in proof_spec.expectations
        ],
        "unresolved_questions": unresolved_questions,
        "all_semantic_review_questions": raw_questions,
        "default_policy_if_unanswered": (
            "Continue with ProtocolIR and derived proof context, but preserve proof-critical provenance, checks, event placement, "
            "and expected counterexample surfaces; unresolved items are audit risks, not permission to silently widen lemmas."
        ),
    }


def _load_assumption_ledger(store: ArtifactStore) -> dict[str, Any]:
    path = store.path("ir/assumption_ledger.json")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _covered_semantic_review_categories(questions: list[dict[str, Any]]) -> set[str]:
    covered: set[str] = set()
    for question in questions:
        text = _open_question_search_text(question)
        if any(token in text for token in ("transcript", "finished", "mac", "header", "length")):
            covered.add("message_and_crypto_abstraction")
            covered.add("abstraction_boundary")
        if any(token in text for token in ("key schedule", "derived key", "exporter", "cats", "cahts", "secret", "sse", "sss", "ssS".lower())):
            covered.add("message_and_crypto_abstraction")
            covered.add("value_provenance")
        if any(token in text for token in ("certificate", "cert", "public key", "pk", "trusted", "identity")):
            covered.add("value_provenance")
            covered.add("abstraction_boundary")
        if any(token in text for token in ("compromise", "reveal", "pfs", "forward secrecy")):
            covered.add("compromise_scope")
            covered.add("expected_attack_surface")
            covered.add("value_provenance")
    return covered


def _semantic_review_category(question: dict[str, Any]) -> str:
    question_id = str(question.get("id") or "")
    if question_id.startswith("semantic_review."):
        return question_id.split(".", 1)[1]
    text = _open_question_search_text(question)
    if "compromise" in text or "reveal" in text:
        return "compromise_scope"
    if "counterexample" in text or "attack" in text:
        return "expected_attack_surface"
    if "provenance" in text or "trusted setup" in text:
        return "value_provenance"
    if "message" in text or "crypto" in text:
        return "message_and_crypto_abstraction"
    return "abstraction_boundary"


def _open_question_priority(question: dict[str, Any]) -> tuple[int, int, str]:
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    category_rank = {
        "value_provenance": 0,
        "compromise_scope": 1,
        "expected_attack_surface": 2,
        "abstraction_boundary": 3,
        "message_and_crypto_abstraction": 4,
    }
    category = _semantic_review_category(question)
    severity = str(question.get("severity") or "").lower()
    return (severity_rank.get(severity, 1), category_rank.get(category, 9), str(question.get("id") or ""))


def _open_question_search_text(question: dict[str, Any]) -> str:
    parts = [
        str(question.get("id") or ""),
        str(question.get("question") or ""),
        str(question.get("why") or ""),
        " ".join(str(signal) for signal in _as_open_question_list(question.get("signals"))),
    ]
    return " ".join(parts).lower()


def _plan_open_questions(plan: dict[str, Any]) -> list[Any]:
    questions = _as_open_question_list(plan.get("open_questions"))
    protocol_ir = plan.get("protocol_ir")
    if isinstance(protocol_ir, dict):
        questions.extend(_as_open_question_list(protocol_ir.get("open_questions")))
    return questions


def _apply_open_question_answers(
    plan: dict[str, Any],
    questions: list[dict[str, Any]],
    answers: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    answer_by_id = {
        str(answer.get("id") or ""): str(answer.get("answer") or "").strip()
        for answer in answers
        if str(answer.get("answer") or "").strip()
    }
    answered: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    for question in questions:
        question_id = str(question.get("id") or "")
        answer = answer_by_id.get(question_id, "")
        if answer:
            answered.append({**question, "answer": answer})
        else:
            unresolved.append(question)

    updated = dict(plan)
    existing_resolved = _as_open_question_list(plan.get("resolved_open_questions"))
    updated["resolved_open_questions"] = existing_resolved + answered
    updated["open_questions"] = unresolved
    updated["semantic_constraints"] = _as_open_question_list(plan.get("semantic_constraints")) + _constraints_from_answered_questions(answered)

    protocol_ir = updated.get("protocol_ir")
    if isinstance(protocol_ir, dict):
        updated_ir = dict(protocol_ir)
        existing_ir_resolved = _as_open_question_list(protocol_ir.get("resolved_open_questions"))
        updated_ir_resolved = existing_ir_resolved + answered
        updated_ir["resolved_open_questions"] = updated_ir_resolved
        updated_ir["modeling_assumptions"] = _as_open_question_list(protocol_ir.get("modeling_assumptions")) + [
            f"Resolved open question {item.get('id')}: {item.get('answer')}" for item in answered
        ]
        updated_ir["semantic_constraints"] = _as_open_question_list(protocol_ir.get("semantic_constraints")) + _constraints_from_answered_questions(answered)
        updated_ir["open_questions"] = unresolved
        updated["protocol_ir"] = updated_ir
    elif str(updated.get("schema") or "").startswith(("protocol_ir_pipeline_protocol_ir", "autosm_style_protocol_ir")):
        updated["modeling_assumptions"] = _as_open_question_list(plan.get("modeling_assumptions")) + [
            f"Resolved open question {item.get('id')}: {item.get('answer')}" for item in answered
        ]

    return updated, answered, unresolved


def _constraints_from_answered_questions(answered: list[dict[str, Any]]) -> list[dict[str, Any]]:
    constraints: list[dict[str, Any]] = []
    for item in answered:
        answer = str(item.get("answer") or "").strip()
        if not answer:
            continue
        answer_lc = answer.lower()
        base = {
            "source": "resolved_open_question",
            "question_id": str(item.get("id") or ""),
            "answer": answer,
        }
        constraints.append(
            {
                **base,
                "kind": "binding_answer",
                "policy": "Resolved open-question answers are binding semantic constraints for Sapic+ generation and repair.",
            }
        )
        if any(token in answer_lc for token in ("trusted setup", "role state", "long-term", "private key", "shared long-term", "server key")):
            constraints.append(
                {
                    **base,
                    "kind": "trust_boundary",
                    "policy": (
                        "Values identified as trusted setup, role state, long-term keys, shared long-term keys, or private keys must originate from private setup/state. "
                        "They must not be replaced by public constants, public functions of identities, or adversary network input."
                    ),
                }
            )
        if any(token in answer_lc for token in ("trusted binding", "binding from identity", "identity to", "peer public key", "arbitrary public key")):
            constraints.append(
                {
                    **base,
                    "kind": "identity_binding",
                    "policy": (
                        "Trusted identity/key bindings must be represented as setup/state knowledge. Do not accept arbitrary keys learned from the network as peer bindings."
                    ),
                }
            )
        if any(token in answer_lc for token in ("network-learned", "after decrypt", "after decrypting", "after checks")):
            constraints.append(
                {
                    **base,
                    "kind": "network_after_check",
                    "policy": "Network-learned values become trusted only after the stated decryption/check boundary.",
                }
            )
    return constraints


def _as_open_question_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _proof_context(ir_bundle: dict[str, Any] | None) -> dict[str, Any]:
    if not ir_bundle:
        return {}
    proof_context = ir_bundle.get("proof_context")
    if isinstance(proof_context, dict):
        return proof_context
    legacy_contract = ir_bundle.get("proof_contract")
    if isinstance(legacy_contract, dict):
        return legacy_contract
    return {}


def _preservation_boundary(ir_bundle: dict[str, Any] | None) -> dict[str, Any]:
    if not ir_bundle:
        return {}
    proof_context = _proof_context(ir_bundle)
    if proof_context:
        boundary = proof_context.get("preservation_boundary")
        if isinstance(boundary, dict):
            return boundary
    legacy = ir_bundle.get("proof_critical_abstraction")
    if isinstance(legacy, dict):
        return legacy
    return {}


def _semantic_review_questions(ir_bundle: dict[str, Any] | None) -> list[Any]:
    if not ir_bundle:
        return []
    proof_context = _proof_context(ir_bundle)
    if not isinstance(proof_context, dict):
        return []
    questions = proof_context.get("semantic_review_questions")
    if isinstance(questions, list):
        return questions
    return []


def _semantic_constraints(ir_bundle: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not ir_bundle:
        return []
    constraints: list[dict[str, Any]] = []
    protocol_ir = ir_bundle.get("protocol_ir")
    if isinstance(protocol_ir, dict):
        constraints.extend(
            item
            for item in _as_open_question_list(protocol_ir.get("semantic_constraints"))
            if isinstance(item, dict)
        )
    proof_context = _proof_context(ir_bundle)
    if isinstance(proof_context, dict):
        contract = proof_context.get("semantic_assumption_contract")
        if isinstance(contract, dict):
            constraints.extend(
                item
                for item in _as_open_question_list(contract.get("semantic_constraints"))
                if isinstance(item, dict)
            )
    return constraints


def _public_proof_mode(proof_spec: ProofSpec | None) -> str:
    if proof_spec and proof_spec.expectations:
        return REVIEWED_PROOF_MODE
    return "generated_proof_targets"


def _public_proof_source(proof_spec: ProofSpec | None) -> str | None:
    if proof_spec and proof_spec.expectations:
        return REVIEWED_PROOF_SOURCE
    return None


def _planner_json_failure_reason(raw_text: str) -> str:
    text = raw_text or ""
    stripped = text.strip()
    if not stripped:
        return "empty_response"
    open_braces = stripped.count("{")
    close_braces = stripped.count("}")
    open_brackets = stripped.count("[")
    close_brackets = stripped.count("]")
    if open_braces > close_braces or open_brackets > close_brackets:
        return (
            "likely_truncated_json"
            f" open_braces={open_braces} close_braces={close_braces}"
            f" open_brackets={open_brackets} close_brackets={close_brackets}"
        )
    if "{" not in stripped or "}" not in stripped:
        return "no_json_object_found"
    return "invalid_json_syntax"


def _actual_state_from_raw(actual_raw: str | None, proof_status: str) -> str:
    if actual_raw:
        if actual_raw.startswith("verified"):
            return "ProvedSatisfying"
        if actual_raw.startswith("falsified"):
            return "CounterexampleFound"
    if proof_status == "timeout":
        return "ProofTimeout"
    if proof_status == "missing-proof-results":
        return "MissingProofResult"
    if proof_status in {"failed", "warnings", "tool_missing"}:
        return "BlockedBeforeProof"
    return "Unknown"
