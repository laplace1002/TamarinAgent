#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
from dataclasses import asdict, is_dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from protocol_ir_pipeline import PipelineConfig, ProtocolIRPipeline
from protocol_ir_pipeline.artifacts import ArtifactStore
from protocol_ir_pipeline.cases import ProtocolCase
from protocol_ir_pipeline.ir import build_field_reviews, build_proof_context, build_protocol_ir_bundle
from protocol_ir_pipeline.llm import LLMClient, LLMConfig, llm_call_record, load_local_env
from protocol_ir_pipeline.modeling_contract import (
    build_modeling_contract,
    load_modeling_contract_inputs,
    render_modeling_contract_markdown,
    write_modeling_contract_artifacts,
)
from protocol_ir_pipeline.pipeline import (
    REVIEWED_PROOF_MODE,
    REVIEWED_PROOF_SOURCE,
    _compile_lint,
    _final_outcome,
    _planner_json_failure_reason,
)
from protocol_ir_pipeline.prompts import (
    PLANNER_SYSTEM,
    planner_prompt,
    planner_retry_prompt,
)
from protocol_ir_pipeline.proofspec import LemmaExpectation, ProofSpec, build_initial_proof_spec, complete_discovered_proof_spec
from protocol_ir_pipeline.source_obligations import source_intent_with_obligations


ALLOWED_PATCH_ROOTS = {
    "roles",
    "setup",
    "fresh",
    "state_and_derived",
    "messages",
    "checks",
    "events",
    "proof_targets",
    "expected_attack_surface",
    "abstraction_boundary",
    "compromise",
    "open_questions",
    "sapic_generation_requirements",
}

MESSAGE_USER_FIELDS = ("label", "step", "from", "to", "protection", "term", "meaning")
MESSAGE_DERIVED_FIELDS = ("sender_knows", "receiver_can_decrypt", "receiver_must_treat_as_opaque", "checks", "events_after")
MESSAGE_REVIEWED_IR_DERIVED_FIELDS = ("sender_knows", "receiver_can_decrypt", "receiver_must_treat_as_opaque")
STALE_DERIVED_FIELDS_STATUS = "stale_after_user_edit"
STALE_FIELD_REVIEW_DECISION = "stale_after_user_edit"
REDERIVED_DERIVED_FIELDS_STATUS = "rederived_after_user_edit"
MESSAGE_DERIVED_FIELDS_SIGNATURE = "derived_fields_signature"
MESSAGE_DERIVED_METADATA_FIELDS = (MESSAGE_DERIVED_FIELDS_SIGNATURE,)
# NOTE: must stay in sync with `reviewFieldsBySection` in contract_review_ui/app.js.
# Fields listed here but not rendered by the UI (previously "step", "intent",
# "preservation_policy") count as unresolved server-side while the user has no
# way to confirm them, so review progress can never reach "complete".
REVIEW_FIELDS_BY_SECTION = {
    "fresh": ("name", "owner", "purpose"),
    "setup": ("name", "owner", "public_term", "policy"),
    "messages": ("label", "from", "to", "protection", "term", "meaning"),
    "checks": ("role", "condition", "source_message", "action"),
    "events": ("name", "role", "when", "arguments"),
    "proof_targets": ("name", "goal_type", "trace_kind", "expected_state", "required_events"),
    "expected_attack_surface": ("target", "policy"),
}
REVIEW_NAV_SECTIONS = ("fresh", "setup", "messages", "checks", "events", "proof_targets", "attack_surface")
REVIEW_VISIBLE_SECTIONS = (*REVIEW_NAV_SECTIONS, "expected_attack_surface")
REVIEW_UNRESOLVED_STATUSES = {"must_review", "needs_review"}
REVIEW_HIDDEN_MESSAGE_FRAGMENTS = (
    ".sender_knows",
    ".receiver_can_decrypt",
    ".receiver_must_treat_as_opaque",
    ".checks",
    ".events_after",
    ".derived_fields_signature",
    ".derived_fields_status",
)


ACTIVE_WORKFLOW_ARCHIVE_PATTERNS = (
    "input/case.json",
    "proof/spec.initial.json",
    "prompts/01_plan*.txt",
    "prompts/02_sapic_generation*.txt",
    "prompts/02_reviewed_contract_sapic_generation*.txt",
    "prompts/03_repair_round_*.txt",
    "prompts/03_reviewed_contract_repair_round_*.txt",
    "prompts/04_proof_repair_round_*.txt",
    "prompts/review_patch_*.txt",
    "history/01_plan*.json",
    "history/01_plan*.raw.txt",
    "history/02_sapic_generation*.json",
    "history/02_sapic_generation*.raw.txt",
    "history/02_reviewed_contract_sapic_generation*.json",
    "history/02_reviewed_contract_sapic_generation*.raw.txt",
    "history/03_repair_round_*.json",
    "history/03_repair_round_*.raw.txt",
    "history/03_reviewed_contract_repair_round_*.json",
    "history/04_proof_repair_round_*.json",
    "history/04_proof_repair_round_*.raw.txt",
    "history/review_patch_*.json",
    "history/review_patch_*.raw.txt",
    "history/llm_calls.jsonl",
    "ir/*.json",
    "modeling_contract.json",
    "modeling_contract.md",
    "modeling_contract.reviewed.json",
    "modeling_contract.reviewed.md",
    "models/reviewed_contract*.spthy",
    "final/model.spthy",
    "lint/*.json",
    "lint/reviewed_contract*.json",
    "verify/*.json",
    "verify/*.spthy",
    "verify/*.stdout.txt",
    "verify/*.stderr.txt",
    "verify/reviewed_contract*",
    "proof/*.json",
    "proof/*.spthy",
    "proof/*.txt",
    "proof/per_lemma/*",
    "proof/candidates/**/*",
    "proof/reviewed_contract*",
    "batch/*.json",
)


WORKFLOW_IMPORT_PATTERNS = (
    "input/case.json",
    "proof/spec.initial.json",
    "prompts/*.txt",
    "history/01_plan.json",
    "history/02_sapic_generation*.json",
    "history/03_repair_round_*.json",
    "history/04_proof_repair_round_*.json",
    "history/llm_calls.jsonl",
    "history/stages.jsonl",
    "ir/protocol_ir.json",
    "ir/protocol_ir.reviewed.json",
    "ir/protocol_ir.reviewed.active.json",
    "ir/field_reviews.json",
    "ir/field_reviews.reviewed.json",
    "ir/field_reviews.reviewed.active.json",
    "ir/review_decisions.json",
    "ir/review_decisions.active.json",
    "ir/abstraction_hints.json",
    "ir/initial.abstraction_hints.json",
    "ir/preservation_boundary.json",
    "ir/semantic_review_questions.json",
    "ir/validation.json",
    "ir/assumption_ledger.json",
    "modeling_contract.json",
    "modeling_contract.md",
    "modeling_contract.reviewed.json",
    "modeling_contract.reviewed.md",
    "models/*.spthy",
    "final/model.spthy",
    "lint/*.json",
    "verify/*.json",
    "verify/*.stdout.txt",
    "verify/*.stderr.txt",
    "proof/*.json",
    "proof/*.spthy",
    "proof/*.txt",
    "proof/per_lemma/*",
    "workflow/current_step.json",
    "workflow/review_events.jsonl",
    "summary.json",
    "batch/*.json",
)


class WorkflowError(RuntimeError):
    def __init__(self, message: str, *, status: int = 500, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.detail = detail or {}

    def response_payload(self) -> dict[str, Any]:
        return {
            "error": str(self),
            "type": type(self).__name__,
            **self.detail,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a local modeling-contract review UI.")
    parser.add_argument(
        "--run-dir",
        type=Path,
        required=True,
        help="Workflow run directory. It can be an empty directory or an existing case run directory.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.getenv("CONTRACT_REVIEW_PORT", "8765")))
    parser.add_argument("--provider", default=os.getenv("LLM_PROVIDER", "deepseek"))
    parser.add_argument("--model", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-mode", default=os.getenv("OPENAI_API_MODE", "chat"))
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--max-tokens", type=int, default=38888)
    parser.add_argument("--llm-timeout", type=float, default=float(os.getenv("LLM_TIMEOUT", "1800")))
    parser.add_argument("--reasoning-effort", default=None)
    parser.add_argument("--max-plan-retries", type=int, default=2)
    parser.add_argument(
        "--max-generation-rounds",
        type=int,
        default=int(os.getenv("MAX_GENERATION_ROUNDS", "1")),
    )
    parser.add_argument("--max-repair-rounds", type=int, default=2)
    parser.add_argument(
        "--max-compile-repair-plateau-rounds",
        type=int,
        default=int(os.getenv("MAX_COMPILE_REPAIR_PLATEAU_ROUNDS", "2")),
    )
    parser.add_argument("--tamarin-bin", default="tamarin-prover")
    parser.add_argument("--tamarin-timeout", type=int, default=120)
    parser.add_argument(
        "--tamarin-derivcheck-timeout",
        type=int,
        default=int(os.getenv("TAMARIN_DERIVCHECK_TIMEOUT", "0")),
    )
    parser.add_argument("--proof-timeout", type=int, default=int(os.getenv("PROOF_TIMEOUT", "600")))
    parser.add_argument("--lemma-proof-timeout", type=int, default=int(os.getenv("LEMMA_PROOF_TIMEOUT", "100")))
    parser.add_argument(
        "--abstraction-hints",
        action="store_true",
        default=os.getenv("ABSTRACTION_HINTS", "").lower() in {"1", "true", "yes", "on"},
    )
    parser.add_argument(
        "--abstraction-hints-path",
        type=Path,
        default=Path(os.getenv("ABSTRACTION_HINTS_PATH")) if os.getenv("ABSTRACTION_HINTS_PATH") else None,
    )
    parser.add_argument(
        "--abstraction-retrieval-config",
        type=Path,
        default=Path(os.getenv("ABSTRACTION_RETRIEVAL_CONFIG")) if os.getenv("ABSTRACTION_RETRIEVAL_CONFIG") else None,
    )
    parser.add_argument("--abstraction-hints-top-k", type=int, default=int(os.getenv("ABSTRACTION_HINTS_TOP_K", "3")))
    parser.add_argument("--full-proof", action="store_true")
    parser.add_argument(
        "--workflow-library-dir",
        type=Path,
        default=None,
        help="Directory containing prepared per-case workflows that can be imported into this run.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent
    load_local_env(repo_root)
    static_dir = Path(__file__).resolve().parent / "contract_review_ui"
    state = ReviewState(
        run_dir=_resolve_path(args.run_dir, Path.cwd()),
        static_dir=static_dir,
        llm_config=LLMConfig(
            provider=args.provider,
            model=args.model,
            base_url=args.base_url,
            api_mode=args.api_mode,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            timeout=args.llm_timeout,
            reasoning_effort=args.reasoning_effort,
        ),
        max_plan_retries=args.max_plan_retries,
        max_generation_rounds=args.max_generation_rounds,
        max_repair_rounds=args.max_repair_rounds,
        max_compile_repair_plateau_rounds=args.max_compile_repair_plateau_rounds,
        tamarin_bin=args.tamarin_bin,
        tamarin_timeout=args.tamarin_timeout,
        tamarin_derivcheck_timeout=args.tamarin_derivcheck_timeout,
        proof_timeout=args.proof_timeout,
        lemma_proof_timeout=args.lemma_proof_timeout,
        abstraction_hints_enabled=args.abstraction_hints,
        abstraction_hints_path=_resolve_path(args.abstraction_hints_path, Path.cwd()) if args.abstraction_hints_path else None,
        abstraction_retrieval_config_path=_resolve_path(args.abstraction_retrieval_config, Path.cwd()) if args.abstraction_retrieval_config else None,
        abstraction_hints_top_k=args.abstraction_hints_top_k,
        full_proof=args.full_proof,
        workflow_library_dir=_resolve_path(args.workflow_library_dir, Path.cwd()) if args.workflow_library_dir else None,
    )
    state.ensure_contract()
    handler = make_handler(state)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    state.log_event("ui_start", "ready", url=f"http://{args.host}:{args.port}/")
    print(f"Contract review UI: http://{args.host}:{args.port}/", flush=True)
    print(f"Run dir: {state.run_dir}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


class ReviewState:
    def __init__(
        self,
        *,
        run_dir: Path,
        static_dir: Path,
        llm_config: LLMConfig,
        max_plan_retries: int = 2,
        max_generation_rounds: int = 1,
        max_repair_rounds: int = 2,
        max_compile_repair_plateau_rounds: int = 2,
        tamarin_bin: str = "tamarin-prover",
        tamarin_timeout: int = 120,
        tamarin_derivcheck_timeout: int | None = 0,
        proof_timeout: int = 600,
        lemma_proof_timeout: int = 100,
        abstraction_hints_enabled: bool = False,
        abstraction_hints_path: Path | None = None,
        abstraction_retrieval_config_path: Path | None = None,
        abstraction_hints_top_k: int = 3,
        full_proof: bool = False,
        workflow_library_dir: Path | None = None,
        enable_open_question_resolution: bool = False,
        sapic_generation_mode: str = "protocol_ir_pipeline",
    ) -> None:
        self.run_dir = run_dir
        self.static_dir = static_dir
        self.llm_config = llm_config
        self.max_plan_retries = max_plan_retries
        self.max_generation_rounds = max_generation_rounds
        self.max_repair_rounds = max_repair_rounds
        self.max_compile_repair_plateau_rounds = max_compile_repair_plateau_rounds
        self.tamarin_bin = tamarin_bin
        self.tamarin_timeout = tamarin_timeout
        self.tamarin_derivcheck_timeout = tamarin_derivcheck_timeout
        self.proof_timeout = proof_timeout
        self.lemma_proof_timeout = lemma_proof_timeout
        self.abstraction_hints_enabled = abstraction_hints_enabled
        self.abstraction_hints_path = abstraction_hints_path
        self.abstraction_retrieval_config_path = abstraction_retrieval_config_path
        self.abstraction_hints_top_k = abstraction_hints_top_k
        self.full_proof = full_proof
        self.workflow_library_dir = workflow_library_dir or (Path(__file__).resolve().parent / "runs" / "ui_benchmark18_nl")
        self.enable_open_question_resolution = enable_open_question_resolution
        self.sapic_generation_mode = sapic_generation_mode

    @property
    def contract_path(self) -> Path:
        return self.run_dir / "modeling_contract.json"

    @property
    def reviewed_path(self) -> Path:
        return self.run_dir / "modeling_contract.reviewed.json"

    @property
    def workflow_dir(self) -> Path:
        path = self.run_dir / "workflow"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def current_step_path(self) -> Path:
        return self.workflow_dir / "current_step.json"

    @property
    def events_path(self) -> Path:
        return self.workflow_dir / "review_events.jsonl"

    @property
    def attempts_dir(self) -> Path:
        path = self.workflow_dir / "nl_attempts"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def snapshots_dir(self) -> Path:
        path = self.workflow_dir / "snapshots"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def ensure_contract(self) -> bool:
        if self.contract_path.exists():
            return True
        if not (self.run_dir / "ir" / "protocol_ir.json").exists():
            return False
        ir_bundle, assumption_ledger, raw_case = load_modeling_contract_inputs(self.run_dir)
        case = _case_from_payload(raw_case, fallback_name=self.run_dir.name)
        proof_spec = _proof_spec_from_prepared_artifacts(self.run_dir, case)
        if not ir_bundle.get("proof_context"):
            validation = ir_bundle.get("validation") if isinstance(ir_bundle, dict) else {}
            protocol_ir = ir_bundle.get("protocol_ir") if isinstance(ir_bundle, dict) else {}
            if isinstance(protocol_ir, dict):
                ir_bundle["proof_context"] = build_proof_context(case, protocol_ir, proof_spec, validation)
        if not ir_bundle.get("field_reviews") and isinstance(ir_bundle.get("protocol_ir"), dict):
            ir_bundle["field_reviews"] = build_field_reviews(
                case,
                ir_bundle["protocol_ir"],
                proof_spec,
                ir_bundle.get("validation", {}),
                ir_bundle.get("proof_context", {}),
            )
            (self.run_dir / "ir").mkdir(parents=True, exist_ok=True)
            (self.run_dir / "ir" / "field_reviews.json").write_text(
                json.dumps({"field_reviews": ir_bundle["field_reviews"]}, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        contract = build_modeling_contract(
            case,
            proof_spec,
            ir_bundle,
            assumption_ledger=assumption_ledger,
            source="review_ui_existing_run",
        )
        write_modeling_contract_artifacts(self.run_dir, contract)
        self.log_event("contract", "generated_from_existing_ir", path=str(self.contract_path))
        return True

    def load_contract(self) -> dict[str, Any]:
        path = self.reviewed_path if self.reviewed_path.exists() else self.contract_path
        value = _read_json(path)
        if not value:
            self.ensure_contract()
            value = _read_json(self.contract_path)
        if isinstance(value, dict) and not value.get("field_reviews"):
            value = self._backfill_contract_field_reviews(value)
        return value

    def _backfill_contract_field_reviews(self, contract: dict[str, Any]) -> dict[str, Any]:
        try:
            case = _case_from_payload(_read_json(self.run_dir / "input" / "case.json"), fallback_name=_contract_case_name(contract))
            proof_spec = _proof_spec_from_contract_payload(contract)
            if not proof_spec.names:
                proof_spec = _proof_spec_from_prepared_artifacts(self.run_dir, case)
            ir_bundle = _prepared_ir_bundle(self.run_dir, case, proof_spec)
            generated = build_modeling_contract(
                case,
                proof_spec,
                ir_bundle,
                assumption_ledger=_read_json(self.run_dir / "ir" / "assumption_ledger.json"),
                source="review_ui_field_review_backfill",
            )
            reviews = generated.get("field_reviews")
            if isinstance(reviews, list) and reviews:
                updated = copy.deepcopy(contract)
                updated["field_reviews"] = reviews
                return updated
        except Exception as exc:
            self.log_event("contract", "field_review_backfill_failed", error=str(exc))
        return contract

    def workflow_status(self) -> dict[str, Any]:
        review_saved = self._review_saved_for_active_workflow()
        review = self._review_status_for_active_workflow(review_saved=review_saved)
        return {
            "run_dir": str(self.run_dir),
            "workflow_library_dir": str(self.workflow_library_dir),
            "settings": {
                "abstraction_hints_enabled": self.abstraction_hints_enabled,
                "abstraction_hints_top_k": self.abstraction_hints_top_k,
            },
            "current_step": _read_json(self.current_step_path),
            "events": self.load_events(limit=80),
            "artifacts": {
                "case": str(self.run_dir / "input" / "case.json"),
                "protocol_ir": str(self.run_dir / "ir" / "protocol_ir.json"),
                "field_reviews": str(self.run_dir / "ir" / "field_reviews.json"),
                "reviewed_protocol_ir": str(self.run_dir / "ir" / "protocol_ir.reviewed.json"),
                "review_decisions": str(self.run_dir / "ir" / "review_decisions.json"),
                "contract": str(self.contract_path),
                "reviewed_contract": str(self.reviewed_path),
                "sapic": str(self.run_dir / "final" / "model.spthy"),
                "verify": str(self.run_dir / "verify" / "initial.json"),
                "repair_verify": str(self.run_dir / "verify" / "reviewed_contract_repair_loop.json"),
                "proof": str(self.run_dir / "proof" / "result.json"),
                "nl_attempts": str(self.attempts_dir),
                "snapshots": str(self.snapshots_dir),
            },
            "exists": {
                "case": (self.run_dir / "input" / "case.json").exists(),
                "protocol_ir": (self.run_dir / "ir" / "protocol_ir.json").exists(),
                "contract": self.contract_path.exists(),
                "reviewed_contract": self.reviewed_path.exists(),
                "review_saved": review_saved,
                "review_complete": bool(review.get("complete")),
                "sapic": (self.run_dir / "final" / "model.spthy").exists(),
                "verify": (self.run_dir / "verify" / "initial.json").exists(),
                "repair_verify": (self.run_dir / "verify" / "reviewed_contract_repair_loop.json").exists(),
                "proof": (self.run_dir / "proof" / "result.json").exists(),
                "nl_attempts": any(self.attempts_dir.iterdir()),
                "snapshots": any(self.snapshots_dir.iterdir()),
            },
            "review": review,
        }

    def _review_saved_for_active_workflow(self) -> bool:
        events = self.load_events(limit=5000)
        reset_index = -1
        for index, event in enumerate(events):
            step = str(event.get("step") or "")
            status = str(event.get("status") or "")
            if step == "workflow_import" and status == "done":
                reset_index = index
            elif step == "contract" and status in {"ready_for_review", "generated_from_existing_ir"}:
                reset_index = index
        return any(
            str(event.get("step") or "") == "review" and str(event.get("status") or "") == "saved"
            and str(event.get("source") or "") == "user_save"
            for event in events[reset_index + 1 :]
        )

    def _review_status_for_active_workflow(self, *, review_saved: bool) -> dict[str, Any]:
        contract = self.load_contract() if self.contract_path.exists() or self.reviewed_path.exists() else {}
        return _review_progress_payload(contract, review_saved=review_saved)

    def workflow_library(self) -> dict[str, Any]:
        cases = []
        root = self.workflow_library_dir
        if root.exists():
            for case_json in _workflow_library_case_jsons(root):
                run_dir = case_json.parent.parent
                case = _read_json(case_json)
                summary = _read_json(run_dir / "batch" / "final_summary.json")
                proof_spec = _read_json(run_dir / "proof" / "spec.initial.json")
                difficulty = str(case.get("difficulty") or run_dir.parent.name)
                name = str(case.get("name") or run_dir.name)
                cases.append(
                    {
                        "id": f"{difficulty}/{run_dir.name}",
                        "name": name,
                        "difficulty": difficulty,
                        "run_dir": str(run_dir),
                        "ui_input": str((summary or {}).get("ui_input") or ""),
                        "proof_spec_source": str((summary or {}).get("proof_spec_source") or proof_spec.get("source") or ""),
                        "protocol_ir_ok": (summary or {}).get("protocol_ir_ok"),
                        "reviewed": (run_dir / "modeling_contract.reviewed.json").exists(),
                    }
                )
        cases.sort(key=lambda item: (str(item.get("difficulty")), str(item.get("name")).lower()))
        return {
            "library_dir": str(root),
            "exists": root.exists(),
            "case_count": len(cases),
            "cases": cases,
        }

    def import_workflow(self, case_id: str) -> dict[str, Any]:
        source = self._workflow_source_for_case(case_id)
        if source is None:
            raise WorkflowError(
                f"Unknown workflow library case: {case_id}",
                status=404,
                detail={"library": self.workflow_library()},
            )
        missing = [
            relative
            for relative in (
                "input/case.json",
                "ir/protocol_ir.json",
                "ir/validation.json",
                "modeling_contract.json",
                "modeling_contract.reviewed.json",
            )
            if not (source / relative).exists()
        ]
        if missing:
            raise WorkflowError(
                f"Workflow library case is incomplete: {case_id}",
                status=409,
                detail={"source_run_dir": str(source), "missing": missing},
            )
        attempt_id = f"import_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{_slug(source.name)}"
        archived_to = self._archive_active_workflow_artifacts(attempt_id)
        copied = []
        for path in _collect_existing_paths(source, WORKFLOW_IMPORT_PATTERNS):
            target = self.run_dir / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            if path.is_dir():
                shutil.copytree(path, target, dirs_exist_ok=True)
            else:
                shutil.copy2(path, target)
            copied.append(str(target.relative_to(self.run_dir)))
        case = _read_json(self.run_dir / "input" / "case.json")
        self.log_event(
            "workflow_import",
            "done",
            case=str(case.get("name") or source.name),
            source_run_dir=str(source),
            copied_count=len(copied),
            archived_previous_to=str(archived_to) if archived_to else "",
        )
        return {
            "case": str(case.get("name") or source.name),
            "source_run_dir": str(source),
            "archived_previous_to": str(archived_to) if archived_to else "",
            "copied": copied,
            "contract": self.load_contract(),
            "case_input": case,
            "workflow": self.workflow_status(),
        }

    def _workflow_source_for_case(self, case_id: str) -> Path | None:
        requested = str(case_id or "").strip()
        if not requested:
            return None
        root = self.workflow_library_dir
        candidates = []
        requested_norm = _slug(requested)
        for case_json in _workflow_library_case_jsons(root) if root.exists() else []:
            run_dir = case_json.parent.parent
            case = _read_json(case_json)
            difficulty = str(case.get("difficulty") or run_dir.parent.name)
            names = {
                _slug(str(case.get("name") or "")),
                _slug(run_dir.name),
                _slug(f"{difficulty}/{run_dir.name}"),
                _slug(f"{difficulty}/{case.get('name') or run_dir.name}"),
            }
            if requested_norm in names:
                candidates.append(run_dir)
        if not candidates:
            return None
        return sorted(candidates)[0]

    def load_events(self, *, limit: int = 50) -> list[dict[str, Any]]:
        if not self.events_path.exists():
            return []
        rows = []
        for line in self.events_path.read_text(encoding="utf-8").splitlines()[-limit:]:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                rows.append(value)
        return rows

    def log_event(self, step: str, status: str, **payload: Any) -> dict[str, Any]:
        event = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "step": step,
            "status": status,
            **payload,
        }
        event = _json_safe(event)
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True))
            handle.write("\n")
        self.current_step_path.write_text(json.dumps(event, indent=2, ensure_ascii=False), encoding="utf-8")
        return event

    def start_from_nl(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.log_event("nl_input", "start")
        case = _case_from_nl_payload(payload)
        attempt_id = self._next_nl_attempt_id(case.name)
        attempt_rel = f"workflow/nl_attempts/{attempt_id}"
        attempt_dir = self.run_dir / attempt_rel
        store = ArtifactStore(attempt_dir)
        self.log_event("nl_input", "attempt_created", case=case.name, attempt=attempt_id, attempt_dir=str(attempt_dir))
        store.write_json("input/case.json", case)
        proof_spec = build_initial_proof_spec(case, expose_benchmark_goals=False)
        store.write_json("proof/spec.initial.json", proof_spec)
        prompt = planner_prompt(case, expose_benchmark_goals=False, include_case_goals=True)
        store.write_text("prompts/01_plan.txt", prompt)
        self.log_event("planner", "llm_start", case=case.name, attempt=attempt_id)
        llm = LLMClient(self.llm_config)
        plan = self._run_planner_with_retries(
            llm=llm,
            store=store,
            case_name=case.name,
            attempt_id=attempt_id,
            prompt=prompt,
        )
        if not self.enable_open_question_resolution:
            _clear_plan_open_questions(plan)
        store.write_json("history/01_plan.json", plan)
        self.log_event("planner", "done", attempt=attempt_id, roles=_plan_roles(plan))
        ir_bundle = build_protocol_ir_bundle(case, plan, proof_spec)
        store.write_json("ir/protocol_ir.json", ir_bundle["protocol_ir"])
        store.write_json("ir/field_reviews.json", {"field_reviews": ir_bundle.get("field_reviews", [])})
        proof_context = _proof_context(ir_bundle)
        store.write_json("ir/preservation_boundary.json", proof_context.get("preservation_boundary", {}))
        store.write_json("ir/semantic_review_questions.json", {"questions": proof_context.get("semantic_review_questions", [])})
        store.write_json("ir/validation.json", ir_bundle["validation"])
        assumption_ledger = _workflow_assumption_ledger(case, proof_spec, ir_bundle)
        store.write_json("ir/assumption_ledger.json", assumption_ledger)
        contract = build_modeling_contract(
            case,
            proof_spec,
            ir_bundle,
            plan=plan,
            assumption_ledger=assumption_ledger,
            source="workflow_nl_input",
        )
        if self.enable_open_question_resolution:
            contract = self._propose_open_question_resolutions(
                contract=contract,
                case=case,
                plan=plan,
                ir_bundle=ir_bundle,
                store=store,
                context={"attempt": attempt_id, "case": case.name},
            )
        write_modeling_contract_artifacts(attempt_dir, contract)
        archived_to = self._archive_active_workflow_artifacts(attempt_id)
        self._publish_nl_attempt(attempt_dir)
        json_path = self.run_dir / "modeling_contract.json"
        markdown_path = self.run_dir / "modeling_contract.md"
        self.log_event(
            "contract",
            "ready_for_review",
            attempt=attempt_id,
            contract=str(json_path),
            markdown=str(markdown_path),
            attempt_dir=str(attempt_dir),
            archived_previous_to=str(archived_to) if archived_to else "",
            ir_ok=ir_bundle["validation"].get("ok"),
            ir_errors=ir_bundle["validation"].get("errors", []),
        )
        return {
            "case": case.name,
            "attempt": attempt_id,
            "attempt_dir": str(attempt_dir),
            "archived_previous_to": str(archived_to) if archived_to else "",
            "plan": plan,
            "ir_bundle": ir_bundle,
            "contract": contract,
            "contract_path": str(json_path),
            "markdown_path": str(markdown_path),
            "workflow": self.workflow_status(),
        }

    def _next_nl_attempt_id(self, case_name: str) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = _slug(case_name or "protocol")
        candidate = f"{timestamp}_{slug}"
        attempt_dir = self.attempts_dir / candidate
        suffix = 2
        while attempt_dir.exists():
            candidate = f"{timestamp}_{slug}_{suffix}"
            attempt_dir = self.attempts_dir / candidate
            suffix += 1
        return candidate

    def _run_planner_with_retries(
        self,
        *,
        llm: LLMClient,
        store: ArtifactStore,
        case_name: str,
        attempt_id: str,
        prompt: str,
    ) -> dict[str, Any]:
        max_attempts = max(1, 1 + self.max_plan_retries)
        current_prompt = prompt
        raw_text = ""
        failure_reason = ""
        for attempt in range(1, max_attempts + 1):
            if attempt > 1:
                store.write_text(f"prompts/01_plan_retry_{attempt - 1}.txt", current_prompt)
                self.log_event(
                    "planner",
                    "retry_start",
                    case=case_name,
                    attempt=attempt_id,
                    planner_attempt=attempt,
                    max_attempts=max_attempts,
                    previous_raw_response_bytes=len(raw_text or ""),
                )
            plan, raw_text = llm.complete_json_or_text(PLANNER_SYSTEM, current_prompt)
            store.append_jsonl(
                "history/llm_calls.jsonl",
                llm_call_record(
                    llm,
                    stage="ui_planner",
                    system=PLANNER_SYSTEM,
                    prompt=current_prompt,
                    attempt=attempt,
                    case=case_name,
                    parsed_json=plan is not None,
                    extra={
                        "raw_response_chars": len(raw_text or ""),
                        "ui_attempt": attempt_id,
                    },
                ),
            )
            if plan is not None:
                return plan
            failure_reason = _planner_json_failure_reason(raw_text)
            raw_name = "history/01_plan.raw.txt" if attempt == 1 else f"history/01_plan_retry_{attempt - 1}.raw.txt"
            raw_path = store.write_text(raw_name, raw_text or "")
            self.log_event(
                "planner",
                "json_failed",
                case=case_name,
                attempt=attempt_id,
                planner_attempt=attempt,
                max_attempts=max_attempts,
                reason=failure_reason,
                raw_response_bytes=len(raw_text or ""),
                raw_response_path=str(raw_path),
            )
            if attempt < max_attempts:
                current_prompt = planner_retry_prompt(
                    prompt,
                    raw_text,
                    failure_reason,
                    attempt + 1,
                    max_attempts,
                )
        raise WorkflowError(
            "LLM planner response did not contain a parseable complete JSON object after retries.",
            status=502,
            detail={
                "stage": "planner",
                "attempt": attempt_id,
                "attempt_dir": str(store.run_dir),
                "raw_response_path": str(store.run_dir / raw_name),
                "raw_response_tail": (raw_text or "")[-1600:],
                "reason": failure_reason,
                "planner_attempts": max_attempts,
                "workflow": self.workflow_status(),
            },
        )

    def _archive_active_workflow_artifacts(self, attempt_id: str) -> Path | None:
        existing = _collect_existing_paths(self.run_dir, ACTIVE_WORKFLOW_ARCHIVE_PATTERNS)
        if not existing:
            return None
        archive_dir = self.snapshots_dir / f"before_{attempt_id}"
        for path in existing:
            target = archive_dir / path.relative_to(self.run_dir)
            target.parent.mkdir(parents=True, exist_ok=True)
            if path.is_dir():
                shutil.copytree(path, target, dirs_exist_ok=True)
                shutil.rmtree(path)
            else:
                shutil.copy2(path, target)
                path.unlink()
        return archive_dir

    def _publish_nl_attempt(self, attempt_dir: Path) -> None:
        for relative in (
            "input/case.json",
            "proof/spec.initial.json",
            "prompts/01_plan.txt",
            "history/llm_calls.jsonl",
            "history/01_plan.json",
            "ir/protocol_ir.json",
            "ir/preservation_boundary.json",
            "ir/semantic_review_questions.json",
            "ir/validation.json",
            "ir/assumption_ledger.json",
            "modeling_contract.json",
            "modeling_contract.md",
        ):
            source = attempt_dir / relative
            if not source.exists():
                continue
            target = self.run_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def save_reviewed(self, contract: dict[str, Any]) -> dict[str, Any]:
        payload = copy.deepcopy(contract)
        _normalize_reviewed_open_questions(payload)
        _refresh_reviewed_message_derivations(payload, _read_json(self.run_dir / "ir" / "protocol_ir.json"))
        review = payload.setdefault("review", {})
        if isinstance(review, dict):
            review["status"] = "reviewed"
            review["updated_at"] = datetime.now().isoformat(timespec="seconds")
            review["source"] = "contract_review_ui"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.reviewed_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        markdown_path = self.run_dir / "modeling_contract.reviewed.md"
        markdown_path.write_text(render_modeling_contract_markdown(payload), encoding="utf-8")
        self._write_reviewed_ir_artifacts(payload)
        self.log_event("review", "saved", source="user_save", json=str(self.reviewed_path), markdown=str(markdown_path))
        return {
            "contract": payload,
            "json_path": str(self.reviewed_path),
            "markdown_path": str(markdown_path),
        }

    def _write_reviewed_ir_artifacts(self, contract: dict[str, Any]) -> None:
        try:
            case = _case_from_payload(_read_json(self.run_dir / "input" / "case.json"), fallback_name=_contract_case_name(contract))
            proof_spec = _proof_spec_from_contract_payload(contract)
            ir_bundle = _prepared_ir_bundle(self.run_dir, case, proof_spec)
            _apply_reviewed_contract_to_ir_bundle(contract, ir_bundle)
            reviewed_ir_path = self.run_dir / "ir" / "protocol_ir.reviewed.json"
            reviewed_field_reviews_path = self.run_dir / "ir" / "field_reviews.reviewed.json"
            review_decisions_path = self.run_dir / "ir" / "review_decisions.json"
            reviewed_ir_path.parent.mkdir(parents=True, exist_ok=True)
            reviewed_ir_path.write_text(json.dumps(ir_bundle["protocol_ir"], indent=2, ensure_ascii=False), encoding="utf-8")
            reviewed_field_reviews_path.write_text(
                json.dumps({"field_reviews": contract.get("field_reviews", [])}, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            review_decisions_path.write_text(
                json.dumps(_review_decisions_payload(contract), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as exc:  # pragma: no cover - save should not fail solely because sidecar sync failed.
            self.log_event("review", "reviewed_ir_sync_failed", error=str(exc))

    def propose_patch(self, *, contract: dict[str, Any], instruction: str, section: str) -> dict[str, Any]:
        llm = LLMClient(self.llm_config)
        prompt = contract_patch_prompt(contract, instruction, section)
        store = ArtifactStore(self.run_dir)
        attempt_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        prompt_stem = f"review_patch_{attempt_id}"
        store.write_text(f"prompts/{prompt_stem}.txt", prompt)
        self.log_event("review_patch", "llm_start", section=section or "auto", attempt=attempt_id)
        response = self._complete_json_with_retries(
            llm=llm,
            system=CONTRACT_PATCH_SYSTEM,
            prompt=prompt,
            store=store,
            prompt_stem=prompt_stem,
            step="review_patch",
            context={"section": section or "auto", "attempt": attempt_id},
            max_retries=self.max_plan_retries,
            retry_builder=contract_patch_retry_prompt,
        )
        store.write_json(f"history/{prompt_stem}.json", response)
        patches = response.get("patches", [])
        issues = validate_patch_list(patches)
        response["validation"] = {"ok": not issues, "issues": issues}
        self.log_event(
            "review_patch",
            "proposed",
            section=section or "auto",
            patch_count=len(patches) if isinstance(patches, list) else 0,
            validation_ok=not issues,
        )
        return response

    def _propose_open_question_resolutions(
        self,
        *,
        contract: dict[str, Any],
        case: ProtocolCase,
        plan: dict[str, Any],
        ir_bundle: dict[str, Any],
        store: ArtifactStore,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        questions = contract.get("open_questions")
        if not isinstance(questions, list) or not questions:
            return contract

        prompt = open_question_resolution_prompt(case, contract, plan, ir_bundle)
        store.write_text("prompts/01_open_question_resolution.txt", prompt)
        self.log_event("open_question_resolution", "llm_start", **context, question_count=len(questions))
        llm = LLMClient(self.llm_config)
        try:
            response = self._complete_json_with_retries(
                llm=llm,
                system=OPEN_QUESTION_RESOLUTION_SYSTEM,
                prompt=prompt,
                store=store,
                prompt_stem="01_open_question_resolution",
                step="open_question_resolution",
                context=context,
                max_retries=self.max_plan_retries,
                retry_builder=open_question_resolution_retry_prompt,
            )
        except WorkflowError as exc:
            self.log_event(
                "open_question_resolution",
                "fallback",
                **context,
                question_count=len(questions),
                error=str(exc),
            )
            _mark_open_question_defaults(contract, reason="llm_resolution_failed")
            return contract

        store.write_json("history/01_open_question_resolution.json", response)
        applied = _apply_open_question_resolution_proposals(contract, response)
        self.log_event(
            "open_question_resolution",
            "proposed",
            **context,
            question_count=len(questions),
            applied_count=applied,
        )
        return contract

    def _complete_json_with_retries(
        self,
        *,
        llm: LLMClient,
        system: str,
        prompt: str,
        store: ArtifactStore,
        prompt_stem: str,
        step: str,
        context: dict[str, Any],
        max_retries: int,
        retry_builder: Any,
        raw_fallback_builder: Any | None = None,
    ) -> dict[str, Any]:
        max_attempts = max(1, 1 + max_retries)
        current_prompt = prompt
        raw_text = ""
        failure_reason = ""
        raw_name = f"{prompt_stem}.raw.txt"
        for attempt in range(1, max_attempts + 1):
            if attempt > 1:
                retry_prompt_name = f"{prompt_stem}_retry_{attempt - 1}"
                store.write_text(f"prompts/{retry_prompt_name}.txt", current_prompt)
                self.log_event(
                    step,
                    "retry_start",
                    **context,
                    json_attempt=attempt,
                    max_attempts=max_attempts,
                    previous_raw_response_bytes=len(raw_text or ""),
                )
            parsed, raw_text = llm.complete_json_or_text(system, current_prompt)
            store.append_jsonl(
                "history/llm_calls.jsonl",
                llm_call_record(
                    llm,
                    stage=step,
                    system=system,
                    prompt=current_prompt,
                    attempt=attempt,
                    case=str(context.get("case") or ""),
                    parsed_json=parsed is not None,
                    extra={
                        **context,
                        "raw_response_chars": len(raw_text or ""),
                        "json_attempt": attempt,
                    },
                ),
            )
            if parsed is not None:
                return parsed
            if raw_fallback_builder is not None:
                fallback = raw_fallback_builder(raw_text)
                if fallback is not None:
                    raw_name = f"{prompt_stem}.raw.txt" if attempt == 1 else f"{prompt_stem}_retry_{attempt - 1}.raw.txt"
                    raw_path = store.write_text(f"history/{raw_name}", raw_text or "")
                    self.log_event(
                        step,
                        "raw_fallback",
                        **context,
                        json_attempt=attempt,
                        max_attempts=max_attempts,
                        raw_response_bytes=len(raw_text or ""),
                        raw_response_path=str(raw_path),
                    )
                    return fallback
            failure_reason = _planner_json_failure_reason(raw_text)
            raw_name = f"{prompt_stem}.raw.txt" if attempt == 1 else f"{prompt_stem}_retry_{attempt - 1}.raw.txt"
            raw_path = store.write_text(f"history/{raw_name}", raw_text or "")
            empty_metadata = getattr(llm, "last_empty_response_metadata", None) if not raw_text else None
            if empty_metadata:
                store.write_json(
                    f"history/{raw_name.removesuffix('.txt')}.metadata.json",
                    empty_metadata,
                )
            self.log_event(
                step,
                "json_failed",
                **context,
                json_attempt=attempt,
                max_attempts=max_attempts,
                reason=failure_reason,
                raw_response_bytes=len(raw_text or ""),
                raw_response_path=str(raw_path),
                empty_response_metadata=empty_metadata or {},
            )
            if attempt < max_attempts:
                current_prompt = retry_builder(
                    prompt,
                    raw_text,
                    failure_reason,
                    attempt + 1,
                    max_attempts,
                )
        raise WorkflowError(
            f"{step} LLM response did not contain a parseable complete JSON object after retries.",
            status=502,
            detail={
                "stage": step,
                **context,
                "raw_response_path": str(store.run_dir / "history" / raw_name),
                "raw_response_tail": (raw_text or "")[-1600:],
                "reason": failure_reason,
                "json_attempts": max_attempts,
                "empty_response_metadata": getattr(llm, "last_empty_response_metadata", None) or {},
                "workflow": self.workflow_status(),
            },
        )

    def generate_sapic(
        self,
        contract: dict[str, Any] | None = None,
        *,
        abstraction_hints: bool | None = None,
    ) -> dict[str, Any]:
        case, plan, proof_spec, ir_bundle, store, reviewed_contract = self._prepared_pipeline_context(contract)
        use_abstraction_hints = self.abstraction_hints_enabled if abstraction_hints is None else bool(abstraction_hints)
        pipeline = self._new_pipeline(abstraction_hints_enabled=use_abstraction_hints)
        pipeline._attach_abstraction_hints(case, proof_spec, ir_bundle, store, "initial")  # noqa: SLF001
        store.write_json("history/02_sapic_generation.contract.json", reviewed_contract)
        pipeline._report("case_start", case=case.name, difficulty=case.difficulty, run_dir=str(self.run_dir))  # noqa: SLF001
        self.log_event(
            "sapic_generation",
            "llm_start",
            pipeline="run_prepared_pipeline",
            abstraction_hints_enabled=use_abstraction_hints,
        )
        sapic_plus = pipeline._generate_sapic(  # noqa: SLF001
            case,
            plan,
            proof_spec,
            store,
            ir_bundle=ir_bundle,
            generation_round=1,
        )
        proof_spec = complete_discovered_proof_spec(case, proof_spec, sapic_plus)
        store.write_json("proof/spec.json", proof_spec)
        pipeline._report(  # noqa: SLF001
            "proof_spec_done",
            case=case.name,
            mode=proof_spec.mode,
            source=proof_spec.source,
            lemma_count=len(proof_spec.expectations),
        )
        lint_issues = _compile_lint(sapic_plus, proof_spec.names, ir_bundle)
        store.write_json("lint/initial.json", {"issues": lint_issues})
        pipeline._report("lint_done", case=case.name, label="initial", issue_count=len(lint_issues))  # noqa: SLF001
        store.write_text("final/model.spthy", sapic_plus)
        self._write_pipeline_summary(
            case=case,
            proof_spec=proof_spec,
            ir_bundle=ir_bundle,
            lint_issues=lint_issues,
            generation_rounds_used=1,
            store=store,
        )
        self.log_event(
            "sapic_generation",
            "done",
            model=str(self.run_dir / "final" / "model.spthy"),
            bytes=len(sapic_plus),
            lint_issue_count=len(lint_issues),
            pipeline="run_prepared_pipeline",
            abstraction_hints_enabled=use_abstraction_hints,
        )
        return {
            "sapic_plus": sapic_plus,
            "lint_issues": lint_issues,
            "history": _read_json(self.run_dir / "history" / "02_sapic_generation.json"),
            "abstraction_hints": ir_bundle.get("abstraction_hints") if isinstance(ir_bundle, dict) else {},
            "abstraction_hints_enabled": use_abstraction_hints,
            "model_artifacts": _model_artifacts(self.run_dir),
            "workflow": self.workflow_status(),
        }

    def compile_sapic(
        self,
        *,
        contract: dict[str, Any] | None = None,
        tamarin_bin: str = "tamarin-prover",
        timeout: int = 120,
    ) -> dict[str, Any]:
        sapic_plus = self._current_sapic()
        if not sapic_plus.strip():
            raise ValueError("No Sapic+ model exists yet. Generate Sapic+ first.")
        case, _plan, proof_spec, ir_bundle, store, _reviewed_contract = self._prepared_pipeline_context(contract)
        proof_spec = complete_discovered_proof_spec(case, proof_spec, sapic_plus)
        store.write_json("proof/spec.json", proof_spec)
        lint_issues = _compile_lint(sapic_plus, proof_spec.names, ir_bundle)
        store.write_json("lint/initial.json", {"issues": lint_issues})
        pipeline = self._new_pipeline(tamarin_bin=tamarin_bin, tamarin_timeout=timeout, llm=False)
        self.log_event("tamarin_compile", "start", tamarin_bin=tamarin_bin, timeout=timeout, pipeline="run_prepared_pipeline")
        result = pipeline._verify(sapic_plus, store, "initial", lint_issues)  # noqa: SLF001
        payload = _verification_payload(result, lint_issues)
        self._write_pipeline_summary(
            case=case,
            proof_spec=proof_spec,
            ir_bundle=ir_bundle,
            lint_issues=lint_issues,
            verification=result,
            generation_rounds_used=self._summary_generation_rounds_used(),
            store=store,
        )
        self.log_event(
            "tamarin_compile",
            "done",
            ok=payload["ok"],
            result_status=result.status,
            returncode=result.returncode,
            lint_issue_count=len(lint_issues),
            pipeline="run_prepared_pipeline",
        )
        return {**payload, "model_artifacts": _model_artifacts(self.run_dir), "workflow": self.workflow_status()}

    def repair_and_verify(
        self,
        *,
        contract: dict[str, Any] | None = None,
        tamarin_bin: str = "tamarin-prover",
        timeout: int = 120,
        max_rounds: int | None = None,
        abstraction_hints: bool | None = None,
    ) -> dict[str, Any]:
        current = self._current_sapic()
        if not current.strip():
            raise ValueError("No Sapic+ model exists yet. Generate Sapic+ first.")
        max_rounds = self.max_repair_rounds if max_rounds is None else max(0, max_rounds)
        use_abstraction_hints = self.abstraction_hints_enabled if abstraction_hints is None else bool(abstraction_hints)
        case, plan, proof_spec, ir_bundle, store, _reviewed_contract = self._prepared_pipeline_context(contract)
        pipeline = self._new_pipeline(
            tamarin_bin=tamarin_bin,
            tamarin_timeout=timeout,
            max_repair_rounds=max_rounds,
            abstraction_hints_enabled=use_abstraction_hints,
        )
        pipeline._attach_abstraction_hints(case, proof_spec, ir_bundle, store, "initial")  # noqa: SLF001
        proof_spec = complete_discovered_proof_spec(case, proof_spec, current)
        store.write_json("proof/spec.json", proof_spec)
        current_lint = _compile_lint(current, proof_spec.names, ir_bundle)
        store.write_json("lint/initial.json", {"issues": current_lint})
        self.log_event(
            "repair_verify",
            "start",
            max_rounds=max_rounds,
            timeout=timeout,
            pipeline="run_prepared_pipeline",
            abstraction_hints_enabled=use_abstraction_hints,
        )
        current_result = pipeline._verify(current, store, "initial", current_lint)  # noqa: SLF001
        generation_rounds_used = self._summary_generation_rounds_used()
        current, current_result, current_lint, generation_rounds_used = pipeline._compile_repair_or_regenerate(  # noqa: SLF001
            case,
            plan,
            ir_bundle,
            proof_spec,
            current,
            current_result,
            current_lint,
            store,
            generation_rounds_used,
        )
        store.write_text("final/model.spthy", current)
        payload = _verification_payload(current_result, current_lint)
        payload.update(
            {
                "max_rounds": max_rounds,
                "accepted_round": _last_accepted_compile_repair_round(store.run_dir),
                "attempts": _compile_repair_attempts(store.run_dir),
                "model_path": str(self.run_dir / "final" / "model.spthy"),
                "generation_rounds_used": generation_rounds_used,
                "abstraction_hints_enabled": use_abstraction_hints,
                "abstraction_hints": ir_bundle.get("abstraction_hints") if isinstance(ir_bundle, dict) else {},
            }
        )
        store.write_json("verify/reviewed_contract_repair_loop.json", payload)
        self._write_pipeline_summary(
            case=case,
            proof_spec=proof_spec,
            ir_bundle=ir_bundle,
            lint_issues=current_lint,
            verification=current_result,
            generation_rounds_used=generation_rounds_used,
            store=store,
        )
        payload = {
            **payload,
            "sapic_plus": current,
            "model_artifacts": _model_artifacts(self.run_dir),
            "workflow": self.workflow_status(),
        }
        self.log_event(
            "repair_verify",
            "done",
            ok=current_result.ok and not current_lint,
            result_status=current_result.status,
            accepted_round=payload.get("accepted_round"),
            attempt_count=len(payload.get("attempts") or []),
            pipeline="run_prepared_pipeline",
            abstraction_hints_enabled=use_abstraction_hints,
        )
        return payload

    def prove_sapic(
        self,
        *,
        contract: dict[str, Any] | None = None,
        tamarin_bin: str = "tamarin-prover",
        timeout: int = 60,
        per_lemma: bool = True,
    ) -> dict[str, Any]:
        sapic_plus = self._current_sapic()
        if not sapic_plus.strip():
            raise ValueError("No Sapic+ model exists yet. Generate Sapic+ first.")
        case, plan, proof_spec, ir_bundle, store, _reviewed_contract = self._prepared_pipeline_context(contract)
        pipeline = self._new_pipeline(
            tamarin_bin=tamarin_bin,
            proof_timeout=timeout,
            lemma_proof_timeout=timeout,
            prove_each_lemma=per_lemma,
        )
        pipeline._attach_abstraction_hints(case, proof_spec, ir_bundle, store, "initial")  # noqa: SLF001
        proof_spec = complete_discovered_proof_spec(case, proof_spec, sapic_plus)
        store.write_json("proof/spec.json", proof_spec)
        lint_issues = _compile_lint(sapic_plus, proof_spec.names, ir_bundle)
        store.write_json("lint/initial.json", {"issues": lint_issues})
        self.log_event("tamarin_prove", "start", lemma_count=len(proof_spec.names), timeout=timeout, per_lemma=per_lemma, pipeline="run_prepared_pipeline")
        verification = pipeline._verify(sapic_plus, store, "initial", lint_issues)  # noqa: SLF001
        generation_rounds_used = self._summary_generation_rounds_used()
        sapic_plus, verification, lint_issues, generation_rounds_used = pipeline._compile_repair_or_regenerate(  # noqa: SLF001
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
        coverage = pipeline._lemma_coverage(case, sapic_plus, store, proof_spec.names)  # noqa: SLF001
        proof_lint_result = pipeline._proof_lint(case, sapic_plus, store, proof_spec)  # noqa: SLF001
        proof = None
        if pipeline.config.prove and verification.ok and not lint_issues and coverage.ok:
            if proof_lint_result.ok:
                proof = pipeline._prove(case, sapic_plus, store, proof_spec)  # noqa: SLF001
            sapic_plus, verification, coverage, proof, proof_lint_result, generation_rounds_used = pipeline._proof_repair_loop(  # noqa: SLF001
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
        elif pipeline.config.prove:
            pipeline._report(  # noqa: SLF001
                "proof_skipped",
                case=case.name,
                reason="compile_or_coverage_failed",
                compile_status=verification.status,
                missing_lemmas=coverage.missing,
                proof_lint_issues=proof_lint_result.issues if proof_lint_result else [],
            )
        store.write_text("final/model.spthy", sapic_plus)
        self._write_pipeline_summary(
            case=case,
            proof_spec=proof_spec,
            ir_bundle=ir_bundle,
            lint_issues=lint_issues,
            verification=verification,
            coverage=coverage,
            proof_lint_result=proof_lint_result,
            proof=proof,
            generation_rounds_used=generation_rounds_used,
            store=store,
        )
        payload = _proof_payload(proof, proof_spec) if proof else _skipped_proof_payload(proof_spec, verification, coverage, proof_lint_result)
        payload["lint_issues"] = lint_issues
        payload["proof_lint_issues"] = proof_lint_result.issues if proof_lint_result else []
        payload["missing_lemmas"] = coverage.missing if coverage else []
        payload["workflow"] = self.workflow_status()
        store.write_json("proof/result.json", payload)
        payload["sapic_plus"] = sapic_plus
        payload["model_artifacts"] = _model_artifacts(self.run_dir)
        self.log_event(
            "tamarin_prove",
            "done",
            ok=payload.get("ok"),
            result_status=payload.get("status"),
            mismatched=payload.get("mismatched_results", []),
            pipeline="run_prepared_pipeline",
        )
        return payload

    def _new_pipeline(
        self,
        *,
        tamarin_bin: str | None = None,
        tamarin_timeout: int | None = None,
        proof_timeout: int | None = None,
        lemma_proof_timeout: int | None = None,
        max_repair_rounds: int | None = None,
        prove_each_lemma: bool = True,
        llm: bool = True,
        expose_benchmark_goals: bool = False,
        abstraction_hints_enabled: bool | None = None,
    ) -> ProtocolIRPipeline:
        return ProtocolIRPipeline(
            PipelineConfig(
                output_dir=self.run_dir.parent,
                tamarin_bin=tamarin_bin or self.tamarin_bin,
                tamarin_timeout=self.tamarin_timeout if tamarin_timeout is None else tamarin_timeout,
                tamarin_derivcheck_timeout=self.tamarin_derivcheck_timeout,
                proof_timeout=self.proof_timeout if proof_timeout is None else proof_timeout,
                lemma_proof_timeout=self.lemma_proof_timeout if lemma_proof_timeout is None else lemma_proof_timeout,
                max_generation_rounds=self.max_generation_rounds,
                max_repair_rounds=self.max_repair_rounds if max_repair_rounds is None else max_repair_rounds,
                prove=True,
                prove_each_lemma=prove_each_lemma,
                full_proof=self.full_proof,
                expose_benchmark_goals=expose_benchmark_goals,
                verify=True,
                skip_llm=False,
                question_policy="off",
                max_plan_retries=self.max_plan_retries,
                max_compile_repair_plateau_rounds=self.max_compile_repair_plateau_rounds,
                abstraction_hints_enabled=self.abstraction_hints_enabled if abstraction_hints_enabled is None else abstraction_hints_enabled,
                abstraction_hints_path=self.abstraction_hints_path,
                abstraction_retrieval_config_path=self.abstraction_retrieval_config_path,
                abstraction_hints_top_k=self.abstraction_hints_top_k,
            ),
            LLMClient(self.llm_config) if llm else None,
            reporter=self._pipeline_reporter,
        )

    def _pipeline_reporter(self, event: str, payload: dict[str, Any]) -> None:
        step = _pipeline_event_step(event)
        data = dict(payload)
        if "status" in data:
            data["result_status"] = data.pop("status")
        if "step" in data:
            data["pipeline_step"] = data.pop("step")
        self.log_event(step, event, pipeline_event=event, **data)

    def _prepared_pipeline_context(
        self,
        contract: dict[str, Any] | None,
    ) -> tuple[ProtocolCase, dict[str, Any], ProofSpec, dict[str, Any], ArtifactStore, dict[str, Any]]:
        reviewed_contract = contract if isinstance(contract, dict) else self.load_contract()
        if not reviewed_contract:
            raise ValueError("No modeling contract is available. Start from NL input or load an existing run first.")
        reviewed_contract = copy.deepcopy(reviewed_contract)
        _normalize_reviewed_open_questions(reviewed_contract)
        _refresh_reviewed_message_derivations(reviewed_contract, _read_json(self.run_dir / "ir" / "protocol_ir.json"))
        case = _case_from_payload(_read_json(self.run_dir / "input" / "case.json"), fallback_name=_contract_case_name(reviewed_contract))
        plan = _read_json(self.run_dir / "history" / "01_plan.json")
        if not plan:
            raise ValueError("Missing prepared planner artifact history/01_plan.json.")
        proof_spec = _proof_spec_from_prepared_artifacts(self.run_dir, case)
        ir_bundle = _prepared_ir_bundle(self.run_dir, case, proof_spec)
        if reviewed_contract:
            reviewed_proof_spec = _proof_spec_from_contract_payload(reviewed_contract)
            if reviewed_proof_spec.names:
                proof_spec = reviewed_proof_spec
            _apply_reviewed_contract_to_ir_bundle(reviewed_contract, ir_bundle)
        _enrich_prepared_ir_bundle(case, proof_spec, ir_bundle)
        store = ArtifactStore(self.run_dir)
        store.write_json("proof/spec.initial.json", proof_spec.prompt_payload())
        store.write_json("ir/protocol_ir.reviewed.active.json", ir_bundle.get("protocol_ir", {}))
        store.write_json("ir/field_reviews.reviewed.active.json", {"field_reviews": reviewed_contract.get("field_reviews", [])})
        store.write_json("ir/review_decisions.active.json", _review_decisions_payload(reviewed_contract))
        return case, plan, proof_spec, ir_bundle, store, reviewed_contract

    def _current_sapic(self) -> str:
        model_path = self.run_dir / "final" / "model.spthy"
        return model_path.read_text(encoding="utf-8") if model_path.exists() else ""

    def _summary_generation_rounds_used(self) -> int:
        summary = _read_json(self.run_dir / "summary.json")
        try:
            return max(1, int(summary.get("generation_rounds_used") or 1))
        except (TypeError, ValueError):
            return 1

    def _write_pipeline_summary(
        self,
        *,
        case: ProtocolCase,
        proof_spec: ProofSpec,
        ir_bundle: dict[str, Any],
        lint_issues: list[str],
        store: ArtifactStore,
        generation_rounds_used: int,
        verification: Any = None,
        coverage: Any = None,
        proof_lint_result: Any = None,
        proof: Any = None,
    ) -> dict[str, Any]:
        final_path = self.run_dir / "final" / "model.spthy"
        summary = _pipeline_summary_payload(
            case=case,
            run_dir=self.run_dir,
            final_path=final_path,
            proof_spec=proof_spec,
            ir_bundle=ir_bundle,
            lint_issues=lint_issues,
            verification=verification,
            coverage=coverage,
            proof_lint_result=proof_lint_result,
            proof=proof,
            generation_rounds_used=generation_rounds_used,
            max_generation_rounds=self.max_generation_rounds,
            max_repair_rounds=self.max_repair_rounds,
            prove_enabled=True,
        )
        store.write_json("summary.json", summary)
        return summary


CONTRACT_PATCH_SYSTEM = """You propose local edits to an AutoSM-style modeling contract.
Return only JSON. Do not emit Sapic+ code. Do not rewrite the whole contract."""


OPEN_QUESTION_RESOLUTION_SYSTEM = """You propose modeling-contract answers for open semantic review questions.
Return only JSON. Do not emit Sapic+ code."""


def open_question_resolution_prompt(
    case: ProtocolCase,
    contract: dict[str, Any],
    plan: dict[str, Any],
    ir_bundle: dict[str, Any],
) -> str:
    payload = {
        "case": {
            "name": case.name,
            "description": _compact_text(case.description, limit=1600),
            "assumptions": case.assumptions,
            "goals": case.goals,
            "notes": case.notes,
        },
        "planner_summary": {
            "protocol_name": plan.get("protocol_name") if isinstance(plan, dict) else "",
            "open_questions": plan.get("open_questions", []) if isinstance(plan, dict) else [],
            "resolved_open_questions": plan.get("resolved_open_questions", []) if isinstance(plan, dict) else [],
        },
        "protocol_ir": _compact_open_question_ir(ir_bundle.get("protocol_ir", {}) if isinstance(ir_bundle, dict) else {}),
        "proof_context": _compact_open_question_proof_context(_proof_context(ir_bundle)),
        "modeling_contract": {
            "case": contract.get("case"),
            "setup": contract.get("setup"),
            "fresh": contract.get("fresh"),
            "messages": contract.get("messages"),
            "checks": contract.get("checks"),
            "events": contract.get("events"),
            "proof_targets": contract.get("proof_targets"),
            "expected_attack_surface": contract.get("expected_attack_surface"),
            "abstraction_boundary": contract.get("abstraction_boundary"),
            "open_questions": contract.get("open_questions"),
        },
    }
    return f"""Propose answers and modeling resolutions for the open questions in this modeling contract.

Purpose:
- The LLM should provide a first-pass proposal, not silently resolve the review.
- The human reviewer will accept or edit each proposal in the UI.
- Prefer protocol-specific concrete resolutions over generic advice.

Return this JSON shape:
{{
  "resolutions": [
    {{
      "id": "question id from input",
      "proposed_answer": "Direct answer to the open question, grounded in the NL and IR.",
      "proposed_resolution": "Concrete modeling decision that Sapic+ generation must follow if accepted.",
      "confidence": "high|medium|low",
      "risk_notes": ["..."]
    }}
  ],
  "global_notes": ["..."]
}}

Rules:
- Return JSON only.
- Do not emit Sapic+ code.
- Do not mark proposals as accepted; set only proposed_* fields.
- If the benchmark/natural language implies an attack or missing check, preserve it in the proposed_resolution instead of fixing the protocol.
- If uncertain, say so in risk_notes and use confidence="low".

Input:
{json.dumps(payload, ensure_ascii=False, indent=2)}
"""


def open_question_resolution_retry_prompt(
    original_prompt: str,
    raw_response: str,
    failure_reason: str,
    attempt: int,
    max_attempts: int,
) -> str:
    raw = raw_response or ""
    tail = raw[-1600:] if raw else ""
    return f"""The previous open-question-resolution response was not parseable JSON.
Failure reason: {failure_reason}
Attempt: {attempt} of {max_attempts}

Return one complete JSON object for the original task, using exactly this shape:
{{
  "resolutions": [
    {{
      "id": "question id",
      "proposed_answer": "...",
      "proposed_resolution": "...",
      "confidence": "high|medium|low",
      "risk_notes": []
    }}
  ],
  "global_notes": []
}}

Previous response tail:
{tail}

Original task:
{original_prompt}
"""


def _compact_open_question_ir(protocol_ir: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(protocol_ir, dict):
        return {}
    keys = [
        "protocol_name",
        "roles",
        "principals",
        "crypto",
        "fresh_terms",
        "long_term_keys",
        "messages",
        "checks",
        "events",
        "claims",
        "compromise",
        "modeling_assumptions",
        "semantic_constraints",
        "open_questions",
        "resolved_open_questions",
    ]
    return {key: protocol_ir.get(key) for key in keys if key in protocol_ir}


def _compact_open_question_proof_context(proof_context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(proof_context, dict):
        return {}
    keys = [
        "target_lemmas",
        "event_obligations",
        "knowledge_contract",
        "semantic_assumption_contract",
        "generation_policies",
        "semantic_review_questions",
        "preservation_boundary",
    ]
    return {key: proof_context.get(key) for key in keys if key in proof_context}


def _apply_open_question_resolution_proposals(contract: dict[str, Any], response: dict[str, Any]) -> int:
    questions = contract.get("open_questions")
    resolutions = response.get("resolutions") if isinstance(response, dict) else None
    if not isinstance(questions, list) or not isinstance(resolutions, list):
        return 0
    by_id = {
        str(item.get("id") or ""): item
        for item in resolutions
        if isinstance(item, dict) and str(item.get("id") or "")
    }
    applied = 0
    for index, question in enumerate(questions):
        if not isinstance(question, dict):
            continue
        proposal = by_id.get(str(question.get("id") or ""))
        if proposal is None and index < len(resolutions) and isinstance(resolutions[index], dict):
            proposal = resolutions[index]
        if not isinstance(proposal, dict):
            continue
        if proposal.get("proposed_answer"):
            question["proposed_answer"] = str(proposal.get("proposed_answer"))
            question.setdefault("answer", question["proposed_answer"])
        if proposal.get("proposed_resolution"):
            question["proposed_resolution"] = str(proposal.get("proposed_resolution"))
            question.setdefault("resolution", question["proposed_resolution"])
        question["proposal_source"] = "llm"
        question["review_status"] = "needs_review"
        if proposal.get("confidence"):
            question["proposal_confidence"] = str(proposal.get("confidence"))
        if isinstance(proposal.get("risk_notes"), list):
            question["proposal_risk_notes"] = [str(item) for item in proposal.get("risk_notes") if str(item)]
        applied += 1
    return applied


def _mark_open_question_defaults(contract: dict[str, Any], *, reason: str) -> None:
    questions = contract.get("open_questions")
    if not isinstance(questions, list):
        return
    for question in questions:
        if not isinstance(question, dict):
            continue
        question.setdefault("review_status", "needs_review")
        question.setdefault("proposal_source", "contract_builder_default")
        question.setdefault("proposal_risk_notes", [])
        question["proposal_failure"] = reason


def _normalize_reviewed_open_questions(contract: dict[str, Any]) -> None:
    questions = contract.get("open_questions")
    if not isinstance(questions, list):
        return
    normalized: list[Any] = []
    for index, question in enumerate(questions):
        if isinstance(question, str):
            question = {
                "id": f"open_question_{index + 1}",
                "source": "legacy_string",
                "severity": "medium",
                "question": question,
            }
        if not isinstance(question, dict):
            normalized.append(question)
            continue
        question.setdefault("review_status", "needs_review")
        question.setdefault("proposed_answer", question.get("answer") or "")
        question.setdefault("proposed_resolution", question.get("resolution") or "")
        if question.get("review_status") == "accepted":
            question["answer"] = question.get("proposed_answer") or question.get("answer") or ""
            question["resolution"] = question.get("proposed_resolution") or question.get("resolution") or ""
        elif question.get("review_status") == "edited":
            question.setdefault("answer", question.get("proposed_answer") or "")
            question.setdefault("resolution", question.get("proposed_resolution") or "")
        normalized.append(question)
    contract["open_questions"] = normalized


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


def contract_patch_prompt(contract: dict[str, Any], instruction: str, section: str) -> str:
    payload = {
        "instruction": instruction,
        "requested_section": section,
        "editable_roots": sorted(ALLOWED_PATCH_ROOTS),
        "contract": contract,
    }
    return f"""Propose a small JSON Patch-style edit for this modeling contract.

Rules:
- Return a JSON object only.
- Patches use JSON Pointer paths.
- Allowed operations: add, replace, remove.
- Prefer small localized patches. Do not replace the whole contract.
- Preserve value provenance, event placement, expected counterexample surfaces, and proof target names unless the user explicitly asks to change them.
- If the requested change touches messages, compromise, proof targets, or expected_attack_surface, include a risk note.
- If the instruction is ambiguous, return no patches and put the ambiguity in risk_notes.

Return this shape:
{{
  "summary": "short summary",
  "risk_notes": ["..."],
  "patches": [
    {{"op": "add|replace|remove", "path": "/fresh/-", "value": {{"name": "~n", "owner": "A", "purpose": "..."}}}}
  ]
}}

Input:
{json.dumps(payload, ensure_ascii=False, indent=2)}
"""


def contract_patch_retry_prompt(
    original_prompt: str,
    raw_response: str,
    failure_reason: str,
    attempt: int,
    max_attempts: int,
) -> str:
    raw = raw_response or ""
    tail = raw[-1800:] if raw else ""
    return f"""The previous modeling-contract patch response was not parseable JSON.
Failure reason: {failure_reason}
Attempt: {attempt} of {max_attempts}

Return one complete valid JSON object only. Do not include Markdown.

Required shape:
{{
  "summary": "short summary",
  "risk_notes": ["..."],
  "patches": [
    {{"op": "add|replace|remove", "path": "/proof_targets/0/expected_state", "value": "CounterexampleFound"}}
  ]
}}

Rules:
- Patches must be an array.
- Allowed operations are add, replace, remove.
- Paths must be JSON Pointer paths.
- If no safe patch can be proposed, return an empty patches array and explain why in risk_notes.

Previous raw response tail:
{tail}

Original patch task:
{original_prompt}
"""


def _compact_text(text: str, *, limit: int) -> str:
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def make_handler(state: ReviewState):
    class ContractReviewHandler(BaseHTTPRequestHandler):
        server_version = "ContractReviewUI/0.1"

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/workflow":
                self._send_json(state.workflow_status())
                return
            if parsed.path == "/api/workflow_library":
                self._send_json(state.workflow_library())
                return
            if parsed.path == "/api/contract":
                self._send_json(
                    {
                        "contract": state.load_contract(),
                        "case_input": _read_json(state.run_dir / "input" / "case.json"),
                        "run_dir": str(state.run_dir),
                        "source_path": str(state.reviewed_path if state.reviewed_path.exists() else state.contract_path),
                        "reviewed_path": str(state.reviewed_path),
                        "tamarin_result": _existing_tamarin_result(state.run_dir),
                    }
                )
                return
            if parsed.path in {"/", "/index.html"}:
                self._send_static("index.html", "text/html; charset=utf-8")
                return
            static_name = parsed.path.lstrip("/")
            if static_name in {"app.js", "styles.css"}:
                content_type = "application/javascript; charset=utf-8" if static_name.endswith(".js") else "text/css; charset=utf-8"
                self._send_static(static_name, content_type)
                return
            self._send_json({"error": "not found"}, status=404)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            try:
                payload = self._read_json_body()
                if parsed.path == "/api/start_from_nl":
                    self._send_json(state.start_from_nl(payload))
                    return
                if parsed.path == "/api/import_workflow":
                    case_id = str(payload.get("case_id") or payload.get("case") or "").strip()
                    if not case_id:
                        self._send_json({"error": "case_id is required"}, status=400)
                        return
                    self._send_json(state.import_workflow(case_id))
                    return
                if parsed.path == "/api/save":
                    contract = payload.get("contract")
                    if not isinstance(contract, dict):
                        self._send_json({"error": "contract must be an object"}, status=400)
                        return
                    self._send_json(state.save_reviewed(contract))
                    return
                if parsed.path == "/api/propose_patch":
                    contract = payload.get("contract")
                    instruction = str(payload.get("instruction") or "").strip()
                    section = str(payload.get("section") or "").strip()
                    if not isinstance(contract, dict) or not instruction:
                        self._send_json({"error": "contract and instruction are required"}, status=400)
                        return
                    self._send_json(state.propose_patch(contract=contract, instruction=instruction, section=section))
                    return
                if parsed.path == "/api/apply_patch":
                    contract = payload.get("contract")
                    patches = payload.get("patches")
                    if not isinstance(contract, dict) or not isinstance(patches, list):
                        self._send_json({"error": "contract object and patches array are required"}, status=400)
                        return
                    issues = validate_patch_list(patches)
                    if issues:
                        self._send_json({"error": "invalid patches", "issues": issues}, status=400)
                        return
                    patched = apply_json_patches(contract, patches)
                    self._send_json({"contract": patched})
                    return
                if parsed.path == "/api/generate_sapic":
                    contract = payload.get("contract")
                    if contract is not None and not isinstance(contract, dict):
                        self._send_json({"error": "contract must be an object"}, status=400)
                        return
                    abstraction_hints = payload.get("abstraction_hints")
                    if abstraction_hints is not None and not isinstance(abstraction_hints, bool):
                        self._send_json({"error": "abstraction_hints must be a boolean"}, status=400)
                        return
                    self._send_json(state.generate_sapic(contract, abstraction_hints=abstraction_hints))
                    return
                if parsed.path == "/api/compile":
                    contract = payload.get("contract")
                    if contract is not None and not isinstance(contract, dict):
                        self._send_json({"error": "contract must be an object"}, status=400)
                        return
                    self._send_json(
                        state.compile_sapic(
                            contract=contract,
                            tamarin_bin=str(payload.get("tamarin_bin") or "tamarin-prover"),
                            timeout=int(payload.get("timeout") or 120),
                        )
                    )
                    return
                if parsed.path == "/api/repair_verify":
                    contract = payload.get("contract")
                    if contract is not None and not isinstance(contract, dict):
                        self._send_json({"error": "contract must be an object"}, status=400)
                        return
                    abstraction_hints = payload.get("abstraction_hints")
                    if abstraction_hints is not None and not isinstance(abstraction_hints, bool):
                        self._send_json({"error": "abstraction_hints must be a boolean"}, status=400)
                        return
                    raw_rounds = payload.get("max_rounds")
                    max_rounds = int(raw_rounds) if raw_rounds is not None else None
                    self._send_json(
                        state.repair_and_verify(
                            contract=contract,
                            tamarin_bin=str(payload.get("tamarin_bin") or "tamarin-prover"),
                            timeout=int(payload.get("timeout") or 120),
                            max_rounds=max_rounds,
                            abstraction_hints=abstraction_hints,
                        )
                    )
                    return
                if parsed.path == "/api/prove":
                    contract = payload.get("contract")
                    if contract is not None and not isinstance(contract, dict):
                        self._send_json({"error": "contract must be an object"}, status=400)
                        return
                    self._send_json(
                        state.prove_sapic(
                            contract=contract,
                            tamarin_bin=str(payload.get("tamarin_bin") or "tamarin-prover"),
                            timeout=int(payload.get("timeout") or 60),
                        )
                    )
                    return
                self._send_json({"error": "not found"}, status=404)
            except WorkflowError as exc:
                self._send_json(exc.response_payload(), status=exc.status)
            except Exception as exc:
                self._send_json({"error": str(exc), "type": type(exc).__name__}, status=500)

        def log_message(self, format: str, *args: Any) -> None:
            print(f"{self.address_string()} - {format % args}", flush=True)

        def _read_json_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or "0")
            if length > 4_000_000:
                raise ValueError("Request body is too large.")
            raw = self.rfile.read(length)
            if not raw:
                return {}
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("Expected JSON object.")
            return value

        def _send_json(self, data: Any, *, status: int = 200) -> None:
            raw = json.dumps(_json_safe(data), indent=2, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_static(self, filename: str, content_type: str) -> None:
            path = state.static_dir / filename
            if not path.exists():
                self._send_json({"error": f"missing static file {filename}"}, status=404)
                return
            raw = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return ContractReviewHandler


def _workflow_library_case_jsons(root: Path) -> list[Path]:
    if not root.exists():
        return []
    paths: dict[Path, Path] = {}
    for pattern in ("*/input/case.json", "*/*/input/case.json"):
        for case_json in root.glob(pattern):
            if case_json.is_file():
                paths[case_json.resolve()] = case_json
    return sorted(paths.values(), key=lambda path: str(path))


def validate_patch_list(patches: Any) -> list[str]:
    issues: list[str] = []
    if not isinstance(patches, list):
        return ["patches must be an array"]
    for index, patch in enumerate(patches):
        if not isinstance(patch, dict):
            issues.append(f"patch {index} must be an object")
            continue
        op = patch.get("op")
        path = patch.get("path")
        if op not in {"add", "replace", "remove"}:
            issues.append(f"patch {index} has unsupported op {op!r}")
        if not isinstance(path, str) or not path.startswith("/"):
            issues.append(f"patch {index} path must be a JSON Pointer")
            continue
        root = path.split("/", 2)[1].replace("~1", "/").replace("~0", "~")
        if root not in ALLOWED_PATCH_ROOTS:
            issues.append(f"patch {index} root /{root} is not editable")
        if op in {"add", "replace"} and "value" not in patch:
            issues.append(f"patch {index} op {op} requires value")
    return issues


def apply_json_patches(contract: dict[str, Any], patches: list[dict[str, Any]]) -> dict[str, Any]:
    document = copy.deepcopy(contract)
    for patch in patches:
        op = str(patch["op"])
        parts = _parse_pointer(str(patch["path"]))
        if not parts:
            raise ValueError("Replacing the whole contract is not allowed.")
        parent, key = _resolve_parent(document, parts, create=op == "add")
        if op == "add":
            _patch_add(parent, key, patch.get("value"))
        elif op == "replace":
            _patch_replace(parent, key, patch.get("value"))
        elif op == "remove":
            _patch_remove(parent, key)
    review = document.setdefault("review", {})
    if isinstance(review, dict):
        review["last_patch_at"] = datetime.now().isoformat(timespec="seconds")
    return document


def _write_verify_payload(
    store: ArtifactStore,
    label: str,
    result: Any,
    lint_issues: list[str] | None = None,
) -> dict[str, Any]:
    lint_issues = lint_issues or []
    payload = {
        "ok": result.ok and not lint_issues,
        "status": result.status,
        "returncode": result.returncode,
        "returncode_ok": result.returncode_ok,
        "warnings": result.warnings,
        "lint_issues": lint_issues,
        "command": result.command,
        "output_path": str(result.output_path),
        "elapsed_sec": getattr(result, "elapsed_sec", 0.0),
        "stdout_tail": result.stdout[-4000:],
        "stderr_tail": result.stderr[-4000:],
    }
    store.write_text(f"verify/{label}.stdout.txt", result.stdout)
    store.write_text(f"verify/{label}.stderr.txt", result.stderr)
    store.write_json(f"verify/{label}.json", payload)
    return payload


def _verification_payload(result: Any, lint_issues: list[str] | None = None) -> dict[str, Any]:
    lint_issues = lint_issues or []
    return {
        "ok": result.ok and not lint_issues,
        "status": result.status,
        "returncode": result.returncode,
        "returncode_ok": result.returncode_ok,
        "has_warnings": result.has_warnings,
        "warnings": result.warnings,
        "lint_issues": lint_issues,
        "command": result.command,
        "output_path": str(result.output_path),
        "elapsed_sec": getattr(result, "elapsed_sec", 0.0),
        "stdout_tail": result.stdout[-4000:],
        "stderr_tail": result.stderr[-4000:],
    }


def _repair_attempt_record(
    round_id: int,
    result: Any,
    lint_issues: list[str],
    *,
    accepted: bool,
    reason: str,
) -> dict[str, Any]:
    return {
        "round": round_id,
        "accepted": accepted,
        "reason": reason,
        "ok": result.ok and not lint_issues,
        "status": result.status,
        "returncode": result.returncode,
        "warning_count": len(result.warnings),
        "lint_issue_count": len(lint_issues),
        "warnings": result.warnings,
        "lint_issues": lint_issues,
    }


def _last_accepted_compile_repair_round(run_dir: Path) -> int | None:
    accepted_rounds = [
        int(record.get("round") or 0)
        for record in _stage_records(run_dir)
        if record.get("stage") == "repair" and record.get("accepted")
    ]
    accepted_rounds = [item for item in accepted_rounds if item > 0]
    return max(accepted_rounds) if accepted_rounds else None


def _compile_repair_attempts(run_dir: Path) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    for record in _stage_records(run_dir):
        if record.get("stage") != "repair":
            continue
        attempts.append(
            {
                "round": record.get("round"),
                "generation_round": record.get("generation_round"),
                "accepted": bool(record.get("accepted")),
                "reason": str(record.get("reason") or ""),
                "ok": bool(record.get("ok")),
                "status": _verify_status_for_label(run_dir, _repair_label_for_record(record)),
                "warning_count": _verify_warning_count_for_label(run_dir, _repair_label_for_record(record)),
                "lint_issue_count": _lint_issue_count_for_label(run_dir, _repair_label_for_record(record)),
                "repair_scope": record.get("repair_scope"),
            }
        )
    return attempts


def _existing_tamarin_result(run_dir: Path) -> dict[str, Any]:
    proof_payload = _read_json(run_dir / "proof" / "result.json")
    if proof_payload:
        return {
            "kind": "proof",
            "data": _existing_proof_payload(run_dir, proof_payload),
        }
    repair_payload = _read_json(run_dir / "verify" / "reviewed_contract_repair_loop.json")
    if repair_payload:
        payload = _existing_verify_payload(run_dir, repair_payload, label="repaired")
        payload["attempts"] = _compile_repair_attempts(run_dir)
        payload["max_rounds"] = repair_payload.get("max_rounds")
        payload["accepted_round"] = repair_payload.get("accepted_round")
        payload["generation_rounds_used"] = repair_payload.get("generation_rounds_used")
        return {"kind": "repair", "data": payload}
    verify_payload = _latest_verify_payload(run_dir)
    if verify_payload:
        return {
            "kind": "compile",
            "data": _existing_verify_payload(run_dir, verify_payload, label=str(verify_payload.get("label") or "initial")),
        }
    if (run_dir / "final" / "model.spthy").exists():
        return {
            "kind": "compile",
            "data": {
                "ok": None,
                "status": "model_available",
                "returncode": None,
                "warnings": [],
                "lint_issues": [],
                "stdout_tail": "",
                "stderr_tail": "",
                "sapic_plus": (run_dir / "final" / "model.spthy").read_text(encoding="utf-8"),
                "model_artifacts": _model_artifacts(run_dir),
            },
        }
    return {}


def _existing_proof_payload(run_dir: Path, proof_payload: dict[str, Any]) -> dict[str, Any]:
    stdout_tail = _read_tail(run_dir / "proof" / "stdout.txt")
    stderr_tail = _read_tail(run_dir / "proof" / "stderr.txt")
    return {
        "ok": proof_payload.get("ok"),
        "status": proof_payload.get("status") or "proof",
        "returncode": proof_payload.get("returncode"),
        "warnings": proof_payload.get("warnings", []),
        "lemma_results": proof_payload.get("lemma_results", {}),
        "missing_results": proof_payload.get("missing_results", []),
        "lemma_expected_states": proof_payload.get("lemma_expected_states", {}),
        "lemma_actual_states": proof_payload.get("lemma_actual_states", {}),
        "lemma_matches": proof_payload.get("lemma_matches", {}),
        "mismatched_results": proof_payload.get("mismatched_results", []),
        "command": proof_payload.get("command", []),
        "output_path": proof_payload.get("output_path", ""),
        "elapsed_sec": proof_payload.get("elapsed_sec", 0.0),
        "stdout_tail": stdout_tail or str(proof_payload.get("stdout_tail") or "")[-4000:],
        "stderr_tail": stderr_tail or str(proof_payload.get("stderr_tail") or "")[-4000:],
        "lint_issues": _existing_lint_issues(run_dir),
        "proof_lint_issues": _read_json(run_dir / "proof" / "lint.json").get("issues", []),
        "missing_lemmas": _read_json(run_dir / "proof" / "lemma_coverage.json").get("missing", []),
        "sapic_plus": _read_text_if_exists(run_dir / "final" / "model.spthy"),
        "model_artifacts": _model_artifacts(run_dir),
    }


def _existing_verify_payload(run_dir: Path, verify_payload: dict[str, Any], *, label: str) -> dict[str, Any]:
    payload = {
        "ok": verify_payload.get("ok"),
        "status": verify_payload.get("status") or "compile",
        "returncode": verify_payload.get("returncode"),
        "returncode_ok": verify_payload.get("returncode_ok"),
        "has_warnings": verify_payload.get("has_warnings"),
        "warnings": verify_payload.get("warnings", []),
        "lint_issues": verify_payload.get("lint_issues", []),
        "command": verify_payload.get("command", []),
        "output_path": verify_payload.get("output_path", ""),
        "elapsed_sec": verify_payload.get("elapsed_sec", 0.0),
        "stdout_tail": _read_tail(run_dir / "verify" / f"{label}.stdout.txt") or str(verify_payload.get("stdout_tail") or "")[-4000:],
        "stderr_tail": _read_tail(run_dir / "verify" / f"{label}.stderr.txt") or str(verify_payload.get("stderr_tail") or "")[-4000:],
        "sapic_plus": _read_text_if_exists(run_dir / "final" / "model.spthy"),
        "model_artifacts": _model_artifacts(run_dir),
    }
    return payload


def _latest_verify_payload(run_dir: Path) -> dict[str, Any]:
    latest: dict[str, Any] = {}
    latest_mtime = -1.0
    for path in (run_dir / "verify").glob("*.json"):
        if path.name == "reviewed_contract_repair_loop.json":
            continue
        payload = _read_json(path)
        if not payload:
            continue
        mtime = path.stat().st_mtime
        if mtime > latest_mtime:
            latest = dict(payload)
            latest["label"] = path.stem
            latest_mtime = mtime
    return latest


def _existing_lint_issues(run_dir: Path) -> list[Any]:
    summary_issues = _read_json(run_dir / "summary.json").get("lint_issues")
    if isinstance(summary_issues, list):
        return summary_issues
    for path in sorted((run_dir / "lint").glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        issues = _read_json(path).get("issues")
        if isinstance(issues, list):
            return issues
    return []


def _read_tail(path: Path, *, limit: int = 4000) -> str:
    try:
        return path.read_text(encoding="utf-8")[-limit:]
    except OSError:
        return ""


def _read_text_if_exists(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _model_artifacts(run_dir: Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in [
        *sorted((run_dir / "models").glob("*.spthy")),
        run_dir / "proof" / "model.spthy",
        run_dir / "proof" / "full_model.spthy",
        run_dir / "final" / "model.spthy",
    ]:
        if not path.exists() or not path.is_file():
            continue
        relative = str(path.relative_to(run_dir))
        if relative in seen:
            continue
        seen.add(relative)
        label = _model_artifact_label(path, run_dir)
        verify_payload = _model_artifact_result_payload(path, run_dir)
        lint_issues = verify_payload.get("lint_issues")
        warnings = verify_payload.get("warnings")
        artifacts.append(
            {
                "label": label,
                "path": relative,
                "code": path.read_text(encoding="utf-8"),
                "ok": verify_payload.get("ok"),
                "status": verify_payload.get("status") or _model_artifact_stage(path, run_dir),
                "accepted": _model_artifact_accepted(path, run_dir),
                "warning_count": len(warnings) if isinstance(warnings, list) else 0,
                "lint_issue_count": len(lint_issues) if isinstance(lint_issues, list) else 0,
            }
        )
    return artifacts


def _model_artifact_label(path: Path, run_dir: Path) -> str:
    relative = path.relative_to(run_dir)
    if relative.parts == ("final", "model.spthy"):
        return "Current final model"
    if relative.parts == ("proof", "model.spthy"):
        return "Proof model"
    if relative.parts == ("proof", "full_model.spthy"):
        return "Full proof model"
    stem = path.stem
    if stem == "initial":
        return "Initial generated model"
    if stem.startswith("regenerated_") and "_repaired_" not in stem:
        return f"Regenerated model {stem.removeprefix('regenerated_')}"
    if stem.startswith("proof_repaired_"):
        return f"Proof repair candidate {stem.removeprefix('proof_repaired_')}"
    if stem.startswith("repaired_"):
        return f"Compile repair candidate {stem.removeprefix('repaired_')}"
    match = re.match(r"^regenerated_(\d+)_repaired_(\d+)$", stem)
    if match:
        return f"Regenerated {match.group(1)} repair candidate {match.group(2)}"
    return stem.replace("_", " ").title()


def _model_artifact_stage(path: Path, run_dir: Path) -> str:
    relative = path.relative_to(run_dir)
    if relative.parts and relative.parts[0] == "final":
        summary = _read_json(run_dir / "summary.json")
        return str(summary.get("verification_status") or summary.get("status") or "current")
    if relative.parts and relative.parts[0] == "proof":
        result = _read_json(run_dir / "proof" / "result.json")
        return str(result.get("status") or "proof")
    return "generated"


def _model_artifact_result_payload(path: Path, run_dir: Path) -> dict[str, Any]:
    relative = path.relative_to(run_dir)
    if relative.parts == ("final", "model.spthy"):
        summary = _read_json(run_dir / "summary.json")
        warnings = summary.get("verification_warnings")
        lint_issues = summary.get("lint_issues")
        return {
            "ok": summary.get("verification_ok"),
            "status": summary.get("verification_status") or summary.get("status") or "current",
            "warnings": warnings if isinstance(warnings, list) else [],
            "lint_issues": lint_issues if isinstance(lint_issues, list) else [],
        }
    if relative.parts == ("proof", "model.spthy"):
        result = _read_json(run_dir / "proof" / "result.json")
        return {
            "ok": result.get("ok"),
            "status": result.get("status") or "proof",
            "warnings": result.get("warnings", []),
            "lint_issues": result.get("lint_issues", []),
        }
    if relative.parts == ("proof", "full_model.spthy"):
        result = _read_json(run_dir / "proof" / "full_result.json")
        return {
            "ok": result.get("ok"),
            "status": result.get("status") or "full_proof",
            "warnings": result.get("warnings", []),
            "lint_issues": result.get("lint_issues", []),
        }
    return _read_json(run_dir / "verify" / f"{path.stem}.json")


def _model_artifact_accepted(path: Path, run_dir: Path) -> bool:
    relative = path.relative_to(run_dir)
    if relative.parts and relative.parts[0] == "final":
        return _model_artifact_result_payload(path, run_dir).get("ok") is True
    if relative.parts == ("proof", "model.spthy"):
        result = _read_json(run_dir / "proof" / "result.json")
        return bool(result.get("ok"))
    stem = path.stem
    if stem == "initial" or (stem.startswith("regenerated_") and "_repaired_" not in stem):
        return bool(_read_json(run_dir / "verify" / f"{stem}.json").get("ok"))
    for record in _stage_records(run_dir):
        stage = record.get("stage")
        if stage == "repair" and _repair_label_for_record(record) == stem:
            return bool(record.get("accepted"))
        if stage == "proof_repair" and stem == f"proof_repaired_{record.get('round')}":
            return bool(record.get("accepted"))
    return bool(_read_json(run_dir / "verify" / f"{stem}.json").get("ok"))


def _stage_records(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "history" / "stages.jsonl"
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _repair_label_for_record(record: dict[str, Any]) -> str:
    try:
        generation_round = int(record.get("generation_round") or 1)
        repair_round = int(record.get("round") or 0)
    except (TypeError, ValueError):
        generation_round = 1
        repair_round = 0
    if repair_round <= 0:
        return "initial"
    if generation_round <= 1:
        return f"repaired_{repair_round}"
    return f"regenerated_{generation_round}_repaired_{repair_round}"


def _verify_status_for_label(run_dir: Path, label: str) -> str:
    return str(_read_json(run_dir / "verify" / f"{label}.json").get("status") or "")


def _verify_warning_count_for_label(run_dir: Path, label: str) -> int:
    warnings = _read_json(run_dir / "verify" / f"{label}.json").get("warnings")
    return len(warnings) if isinstance(warnings, list) else 0


def _lint_issue_count_for_label(run_dir: Path, label: str) -> int:
    issues = _read_json(run_dir / "lint" / f"{label}.json").get("issues")
    return len(issues) if isinstance(issues, list) else 0


def _collect_existing_paths(root: Path, patterns: tuple[str, ...]) -> list[Path]:
    paths: dict[str, Path] = {}
    for pattern in patterns:
        for path in root.glob(pattern):
            if not path.exists() or _is_workflow_internal(path, root):
                continue
            paths[str(path.relative_to(root))] = path
    return [paths[key] for key in sorted(paths)]


def _is_workflow_internal(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    parts = relative.parts
    return bool(parts and parts[0] == "workflow")


def _proof_context(ir_bundle: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(ir_bundle, dict):
        return {}
    proof_context = ir_bundle.get("proof_context")
    if isinstance(proof_context, dict):
        return proof_context
    legacy_contract = ir_bundle.get("proof_contract")
    if isinstance(legacy_contract, dict):
        return legacy_contract
    return {}


def _prepared_ir_bundle(run_dir: Path, case: ProtocolCase, proof_spec: ProofSpec) -> dict[str, Any]:
    protocol_ir = _read_json(run_dir / "ir" / "protocol_ir.json")
    if not protocol_ir:
        raise ValueError("Missing prepared ProtocolIR artifact ir/protocol_ir.json.")
    validation = _read_json(run_dir / "ir" / "validation.json")
    proof_context = build_proof_context(case, protocol_ir, proof_spec, validation)
    if not proof_context.get("target_lemmas"):
        legacy_context = _read_json(run_dir / "ir" / "proof_context.json") or _read_json(run_dir / "ir" / "proof_contract.json")
        if isinstance(legacy_context, dict) and legacy_context.get("target_lemmas"):
            proof_context = legacy_context
    field_reviews_payload = _read_json(run_dir / "ir" / "field_reviews.json")
    field_reviews = field_reviews_payload.get("field_reviews", []) if isinstance(field_reviews_payload, dict) else []
    if not field_reviews:
        field_reviews = build_field_reviews(case, protocol_ir, proof_spec, validation, proof_context)
    return {
        "protocol_ir": protocol_ir,
        "proof_context": proof_context,
        "validation": validation,
        "field_reviews": field_reviews,
    }


def _refresh_reviewed_message_derivations(contract: dict[str, Any], original_protocol_ir: dict[str, Any]) -> None:
    messages = contract.get("messages")
    if not isinstance(messages, list):
        return
    original_messages = _message_rows(original_protocol_ir)
    stale_indexes: list[int] = []
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        original = original_messages[index] if index < len(original_messages) else None
        signature = _message_core_signature(message)
        if not _message_derivations_need_refresh(message, original, signature):
            continue
        for field in MESSAGE_DERIVED_FIELDS + MESSAGE_DERIVED_METADATA_FIELDS:
            message.pop(field, None)
        message.update(_derive_message_fields(message))
        message[MESSAGE_DERIVED_FIELDS_SIGNATURE] = signature
        message["derived_fields_status"] = REDERIVED_DERIVED_FIELDS_STATUS
        stale_indexes.append(index)
    _remove_stale_message_field_reviews(contract, stale_indexes)
    for index in stale_indexes:
        _mark_stale_field_reviews_for_change(contract, f"messages.{index}.__row__")


def _message_rows(protocol_ir: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(protocol_ir, dict):
        return []
    return [item for item in protocol_ir.get("messages", []) if isinstance(item, dict)]


def _message_derivations_need_refresh(message: dict[str, Any], original: dict[str, Any] | None, signature: str | None = None) -> bool:
    if str(message.get("derived_fields_status") or "") == STALE_DERIVED_FIELDS_STATUS:
        return True
    current_signature = signature or _message_core_signature(message)
    stored_signature = str(message.get(MESSAGE_DERIVED_FIELDS_SIGNATURE) or "")
    if stored_signature:
        return stored_signature != current_signature
    if original is None:
        return True
    return any(_message_compare_value(message.get(field)) != _message_compare_value(original.get(field)) for field in MESSAGE_USER_FIELDS)


def _message_core_signature(message: dict[str, Any]) -> str:
    payload = {field: _message_compare_value(message.get(field)) for field in MESSAGE_USER_FIELDS}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _derive_message_fields(message: dict[str, Any]) -> dict[str, Any]:
    term = str(message.get("term") or "")
    meaning = str(message.get("meaning") or "")
    protection = _message_protection_from_reviewed_message(message)
    return {
        "sender_knows": _infer_sender_knows_from_message(term, meaning),
        "receiver_can_decrypt": _infer_receiver_can_decrypt_from_message(term, meaning, protection),
        "receiver_must_treat_as_opaque": _infer_receiver_opaque_values_from_message(term, meaning, protection),
        "checks": [],
        "events_after": [],
    }


def _message_protection_from_reviewed_message(message: dict[str, Any]) -> str:
    explicit = str(message.get("protection") or "").strip()
    if explicit:
        return explicit
    return _infer_message_protection(str(message.get("term") or ""))


def _infer_message_protection(term: str) -> str:
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


def _infer_receiver_can_decrypt_from_message(term: str, meaning: str, protection: str) -> bool:
    lower = f"{protection} {term} {meaning}".lower()
    cannot_decrypt = any(token in lower for token in ("cannot decrypt", "can't decrypt", "can not decrypt", "opaque", "treat as opaque", "forward unchanged"))
    can_decrypt = any(token in lower for token in ("adec", "decrypt", "receiver can decrypt", "opens", "verifies"))
    if cannot_decrypt and not can_decrypt:
        return False
    if any(token in lower for token in ("aenc", "senc", "{", "enc(", "aead")):
        return True
    return protection not in {"opaque", "unknown"}


def _infer_receiver_opaque_values_from_message(term: str, meaning: str, protection: str) -> list[str]:
    text = f"{term} {meaning}"
    lower = f"{protection} {text}".lower()
    if "opaque" not in lower and "ticket" not in lower:
        return []
    return [
        str(token)
        for token in re.findall(r"\b[A-Za-z][A-Za-z0-9_]*(?:_for_[A-Za-z][A-Za-z0-9_]*)?\b", text)
        if "ticket" in token.lower() or "opaque" in token.lower()
    ]


def _infer_sender_knows_from_message(term: str, meaning: str) -> list[str]:
    atoms = re.findall(r"~?[A-Za-z][A-Za-z0-9_]*", f"{term} {meaning}")
    functions = {"aenc", "senc", "enc", "aead", "sign", "mac", "h", "hash", "kdf", "pk", "pub", "verify"}
    result = []
    for atom in atoms:
        name = atom.split("(", 1)[0].lstrip("~")
        if name.lower() in functions or atom in result:
            continue
        result.append(atom)
    return result[:12]


def _message_compare_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value).strip()


def _remove_stale_message_field_reviews(contract: dict[str, Any], indexes: list[int]) -> None:
    reviews = contract.get("field_reviews")
    if not indexes or not isinstance(reviews, list):
        return
    stale_paths = {
        f"messages.{index}.{field}"
        for index in indexes
        for field in MESSAGE_DERIVED_FIELDS
    }
    contract["field_reviews"] = [
        item
        for item in reviews
        if not isinstance(item, dict) or str(item.get("field_path") or "") not in stale_paths
    ]


def _mark_stale_field_reviews_for_change(contract: dict[str, Any], changed_path: str) -> None:
    reviews = contract.get("field_reviews")
    if not isinstance(reviews, list):
        return
    changed = _parse_contract_field_path(changed_path)
    if not changed:
        return
    stale_paths = _dependent_field_review_paths(contract, changed)
    if not stale_paths:
        return
    reason = f"This field may be stale because {changed['display_path']} changed."
    now = datetime.now().isoformat(timespec="seconds")
    for item in reviews:
        if not isinstance(item, dict):
            continue
        if str(item.get("field_path") or "") not in stale_paths:
            continue
        _mark_review_item_stale(item, reason, now)


def _parse_contract_field_path(path: str) -> dict[str, Any] | None:
    parts = str(path or "").split(".")
    if len(parts) < 3:
        return None
    try:
        index = int(parts[1])
    except ValueError:
        return None
    field = ".".join(parts[2:])
    return {
        "section": parts[0],
        "row_index": index,
        "field": field,
        "display_path": f"{parts[0]}.{index}.{field}",
    }


def _dependent_field_review_paths(contract: dict[str, Any], changed: dict[str, Any]) -> set[str]:
    paths: set[str] = set()

    def add(section: str, index: int | None, field: str) -> None:
        if index is None or index < 0 or not field:
            return
        paths.add(f"{section}.{index}.{field}")

    section = str(changed.get("section") or "")
    index = int(changed.get("row_index") or 0)
    field = str(changed.get("field") or "")
    if section == "messages":
        for review_field in REVIEW_FIELDS_BY_SECTION["messages"]:
            add("messages", index, review_field)
        for review_field in MESSAGE_DERIVED_FIELDS:
            add("messages", index, review_field)
        if field == "label" or field == "__row__":
            _add_message_label_dependents(contract, index, paths)
    elif section in {"fresh", "setup"}:
        for review_field in REVIEW_FIELDS_BY_SECTION.get(section, ()):
            add(section, index, review_field)
        _add_value_reference_dependents(contract, section, index, paths)
    elif section == "checks":
        for review_field in REVIEW_FIELDS_BY_SECTION["checks"]:
            add("checks", index, review_field)
        _add_event_dependents_for_check(contract, index, paths)
    elif section == "events":
        for review_field in REVIEW_FIELDS_BY_SECTION["events"]:
            add("events", index, review_field)
        _add_proof_target_dependents_for_event(contract, index, paths)
    elif section == "proof_targets":
        for review_field in REVIEW_FIELDS_BY_SECTION["proof_targets"]:
            add("proof_targets", index, review_field)
    paths.add(str(changed.get("display_path") or ""))
    return paths


def _mark_review_item_stale(item: dict[str, Any], reason: str, timestamp: str) -> None:
    if item.get("stale_after_user_edit") and str(item.get("review_status") or "") in {"user_confirmed", "system_assumption"}:
        return
    item["review_status"] = "needs_review"
    item["review_decision"] = STALE_FIELD_REVIEW_DECISION
    item["stale_after_user_edit"] = True
    item["stale_reason"] = reason
    item["stale_at"] = timestamp
    item["consistency_confidence"] = "low"
    item["consistency_confidence_score"] = 0.0
    # Intentional UX override beyond the paper's priority formula: any field
    # invalidated by a user edit is floored at 0.7 so it is always re-reviewed,
    # regardless of its semantic-impact score.
    item["priority_score"] = max(_float_or_zero(item.get("priority_score")), 0.7)
    item["priority_level"] = "high"
    if not item.get("priority_source") or item.get("priority_source") == "formula":
        item["priority_source"] = "stale"
    diagnostics = item.get("diagnostics")
    if not isinstance(diagnostics, list):
        diagnostics = []
    if reason not in diagnostics:
        diagnostics.insert(0, reason)
    item["diagnostics"] = diagnostics
    item["suggested_action"] = "Re-check this field after the related edit, then edit or confirm it."


def _float_or_zero(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _add_message_label_dependents(contract: dict[str, Any], message_index: int, paths: set[str]) -> None:
    messages = contract.get("messages") if isinstance(contract.get("messages"), list) else []
    message = messages[message_index] if message_index < len(messages) and isinstance(messages[message_index], dict) else {}
    label = str(message.get("label") or "").strip()
    if not label:
        return
    for index, check in enumerate(contract.get("checks", []) if isinstance(contract.get("checks"), list) else []):
        if isinstance(check, dict) and str(check.get("source_message") or "").strip() == label:
            for field in REVIEW_FIELDS_BY_SECTION["checks"]:
                paths.add(f"checks.{index}.{field}")
    _add_text_reference_dependents(contract, label, ("events", "proof_targets"), paths)


def _add_event_dependents_for_check(contract: dict[str, Any], check_index: int, paths: set[str]) -> None:
    checks = contract.get("checks") if isinstance(contract.get("checks"), list) else []
    check = checks[check_index] if check_index < len(checks) and isinstance(checks[check_index], dict) else {}
    source = str(check.get("source_message") or "").strip()
    if source:
        _add_text_reference_dependents(contract, source, ("events",), paths)


def _add_proof_target_dependents_for_event(contract: dict[str, Any], event_index: int, paths: set[str]) -> None:
    events = contract.get("events") if isinstance(contract.get("events"), list) else []
    event = events[event_index] if event_index < len(events) and isinstance(events[event_index], dict) else {}
    name = str(event.get("name") or "").strip()
    if name:
        _add_text_reference_dependents(contract, name, ("proof_targets",), paths)


def _add_value_reference_dependents(contract: dict[str, Any], section: str, row_index: int, paths: set[str]) -> None:
    rows = contract.get(section) if isinstance(contract.get(section), list) else []
    row = rows[row_index] if row_index < len(rows) and isinstance(rows[row_index], dict) else {}
    value = str(row.get("name") or "").strip()
    if value:
        _add_text_reference_dependents(contract, value, ("messages", "checks", "events", "proof_targets"), paths)


def _add_text_reference_dependents(contract: dict[str, Any], needle: str, sections: tuple[str, ...], paths: set[str]) -> None:
    if not needle:
        return
    for section in sections:
        rows = contract.get(section) if isinstance(contract.get(section), list) else []
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            if needle not in json.dumps(row, ensure_ascii=False):
                continue
            for field in REVIEW_FIELDS_BY_SECTION.get(section, ()):
                paths.add(f"{section}.{index}.{field}")


def _review_progress_payload(contract: dict[str, Any], *, review_saved: bool) -> dict[str, Any]:
    reviews = contract.get("field_reviews") if isinstance(contract, dict) else []
    all_reviews = [item for item in reviews if isinstance(item, dict)] if isinstance(reviews, list) else []
    visible_reviews = [item for item in all_reviews if _is_review_field_visible(str(item.get("field_path") or ""))]
    unresolved = [item for item in visible_reviews if _review_item_status(item) in REVIEW_UNRESOLVED_STATUSES]
    sections: dict[str, dict[str, Any]] = {}
    has_reviews = bool(all_reviews)
    for section in REVIEW_NAV_SECTIONS:
        section_items = [
            item
            for item in visible_reviews
            if _review_nav_section_owns_field(section, str(item.get("field_path") or ""))
        ]
        section_unresolved = [
            item for item in section_items if _review_item_status(item) in REVIEW_UNRESOLVED_STATUSES
        ]
        sections[section] = {
            "status": "pending" if not has_reviews or section_unresolved else "done",
            "total": len(section_items),
            "unresolved": len(section_unresolved),
            "status_counts": _review_status_counts(section_items),
        }
    complete = bool(all_reviews) and not unresolved
    return {
        "saved": review_saved,
        "complete": complete,
        "status": "done" if complete else "pending",
        "total": len(visible_reviews),
        "unresolved": len(unresolved),
        "status_counts": _review_status_counts(visible_reviews),
        "sections": sections,
    }


def _review_status_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "must_review": 0,
        "needs_review": 0,
        "system_assumption": 0,
        "user_confirmed": 0,
        "high_confidence": 0,
    }
    for item in items:
        status = _review_item_status(item)
        counts[status] = counts.get(status, 0) + 1
    return counts


def _review_item_status(item: dict[str, Any]) -> str:
    return str(item.get("review_status") or "needs_review")


def _review_nav_section_owns_field(section: str, field_path: str) -> bool:
    owner = _review_field_path_section(field_path)
    if owner == "expected_attack_surface":
        return section == "attack_surface"
    return owner == section


def _review_field_path_section(field_path: str) -> str:
    return str(field_path or "").split(".", 1)[0]


def _is_review_field_visible(field_path: str) -> bool:
    path = str(field_path or "")
    section = _review_field_path_section(path)
    if section not in REVIEW_VISIBLE_SECTIONS:
        return False
    if section == "messages" and any(fragment in path for fragment in REVIEW_HIDDEN_MESSAGE_FRAGMENTS):
        return False
    field = ".".join(path.split(".")[2:])
    visible_fields = REVIEW_FIELDS_BY_SECTION.get(section)
    if visible_fields is not None and (not field or field not in visible_fields):
        return False
    return True


def _apply_reviewed_contract_to_ir_bundle(contract: dict[str, Any], ir_bundle: dict[str, Any]) -> None:
    protocol_ir = ir_bundle.get("protocol_ir") if isinstance(ir_bundle.get("protocol_ir"), dict) else {}
    proof_context = _proof_context(ir_bundle)
    _copy_reviewed_rows(contract, protocol_ir, contract_key="fresh", ir_key="fresh_terms", fields=("name", "owner", "purpose"))
    _copy_reviewed_rows(
        contract,
        protocol_ir,
        contract_key="setup",
        ir_key="long_term_keys",
        fields=("name", "owner", "public_term", "policy"),
        skip_names={"assumption"},
    )
    _copy_reviewed_messages(contract, protocol_ir)
    _copy_reviewed_rows(contract, protocol_ir, contract_key="checks", ir_key="checks", fields=("role", "condition", "source_message", "action"))
    _copy_reviewed_rows(contract, protocol_ir, contract_key="events", ir_key="events", fields=("name", "role", "when", "arguments", "proof_relevance"))
    _copy_reviewed_proof_targets(contract, protocol_ir, proof_context)
    if isinstance(contract.get("compromise"), dict):
        protocol_ir["compromise"] = copy.deepcopy(contract["compromise"])
    _append_review_decision_constraints(contract, protocol_ir)
    ir_bundle["protocol_ir"] = protocol_ir
    ir_bundle["proof_context"] = proof_context
    ir_bundle["field_reviews"] = copy.deepcopy(contract.get("field_reviews", []))


def _copy_reviewed_messages(contract: dict[str, Any], protocol_ir: dict[str, Any]) -> None:
    rows = contract.get("messages")
    if not isinstance(rows, list):
        return
    original_messages = _message_rows(protocol_ir)
    copied = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        original = original_messages[index] if index < len(original_messages) else None
        current = copy.deepcopy(row)
        if _message_derivations_need_refresh(current, original):
            current.update(_derive_message_fields(current))
            current[MESSAGE_DERIVED_FIELDS_SIGNATURE] = _message_core_signature(current)
        message = {field: copy.deepcopy(current.get(field)) for field in MESSAGE_USER_FIELDS if field in current}
        for field in MESSAGE_REVIEWED_IR_DERIVED_FIELDS:
            if field in current:
                message[field] = copy.deepcopy(current.get(field))
        copied.append(message)
    protocol_ir["messages"] = copied


def _copy_reviewed_rows(
    contract: dict[str, Any],
    protocol_ir: dict[str, Any],
    *,
    contract_key: str,
    ir_key: str,
    fields: tuple[str, ...],
    skip_names: set[str] | None = None,
) -> None:
    rows = contract.get(contract_key)
    if not isinstance(rows, list):
        return
    skip_names = skip_names or set()
    copied = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("name") or "") in skip_names:
            continue
        copied.append({field: copy.deepcopy(row.get(field)) for field in fields if field in row})
    protocol_ir[ir_key] = copied


def _copy_reviewed_proof_targets(contract: dict[str, Any], protocol_ir: dict[str, Any], proof_context: dict[str, Any]) -> None:
    targets = [item for item in contract.get("proof_targets", []) if isinstance(item, dict)] if isinstance(contract, dict) else []
    if not targets:
        return
    claims = []
    target_lemmas = []
    for target in targets:
        name = str(target.get("name") or "").strip()
        if not name:
            continue
        required_events = [str(event) for event in target.get("required_events", []) if event] if isinstance(target.get("required_events"), list) else _split_csvish(target.get("required_events"))
        claim = {
            "lemma_name": name,
            "goal_type": str(target.get("goal_type") or ""),
            "expected_state": str(target.get("expected_state") or "ProvedSatisfying"),
            "trace_kind": str(target.get("trace_kind") or "unknown"),
            "intent": str(target.get("intent") or ""),
            "event_schema": required_events,
            "witness": str(target.get("witness") or ""),
        }
        claims.append(claim)
        target_lemmas.append(
            {
                "name": name,
                "goal_type": claim["goal_type"],
                "trace_kind": claim["trace_kind"],
                "expected_state": claim["expected_state"],
                "expected_raw": str(target.get("expected_raw") or ""),
                "intent": claim["intent"],
                "required_events": required_events,
                "witness": claim["witness"],
                "claim_source": "reviewed_contract",
            }
        )
    if claims:
        protocol_ir["claims"] = claims
        if isinstance(proof_context, dict):
            proof_context["target_lemmas"] = target_lemmas
            proof_context["event_obligations"] = [
                {"lemma": item["name"], "required_events": item.get("required_events", [])}
                for item in target_lemmas
            ]
            proof_context["source"] = "reviewed_contract"


def _append_review_decision_constraints(contract: dict[str, Any], protocol_ir: dict[str, Any]) -> None:
    constraints = protocol_ir.setdefault("semantic_constraints", [])
    if not isinstance(constraints, list):
        constraints = []
        protocol_ir["semantic_constraints"] = constraints
    for item in contract.get("field_reviews", []) if isinstance(contract.get("field_reviews"), list) else []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("review_status") or "")
        if status not in {"user_confirmed", "system_assumption", "must_review", "needs_review"}:
            continue
        constraints.append(
            {
                "kind": "field_review_decision",
                "field_path": str(item.get("field_path") or ""),
                "review_status": status,
                "priority_score": item.get("priority_score"),
                "priority_source": item.get("priority_source"),
                "policy": _review_decision_policy(status),
            }
        )


def _review_decision_policy(status: str) -> str:
    if status == "user_confirmed":
        return "User manually confirmed this field; preserve it during Sapic+ generation and repair."
    if status == "system_assumption":
        return "This field is intentionally treated as a default/system assumption; keep it explicit in modeling notes."
    if status == "must_review":
        return "This proof-critical field remains unresolved; do not silently strengthen or reinterpret it."
    return "This field still needs review; preserve current IR semantics and report any uncertainty."


def _review_decisions_payload(contract: dict[str, Any]) -> dict[str, Any]:
    reviews = contract.get("field_reviews") if isinstance(contract, dict) else []
    return {
        "schema": "protocol_ir_pipeline_review_decisions_v1",
        "case": (contract.get("case") or {}).get("name") if isinstance(contract.get("case"), dict) else "",
        "decisions": [
            {
                "field_path": item.get("field_path"),
                "review_status": item.get("review_status"),
                "priority_score": item.get("priority_score"),
                "priority_source": item.get("priority_source"),
                "diagnostics": item.get("diagnostics", []),
            }
            for item in reviews
            if isinstance(item, dict)
        ],
    }


def _split_csvish(value: Any) -> list[str]:
    text = str(value or "")
    if not text:
        return []
    return [item.strip() for item in text.split(",") if item.strip()]


def _parse_pointer(path: str) -> list[str]:
    if path == "":
        return []
    if not path.startswith("/"):
        raise ValueError(f"Invalid JSON Pointer: {path}")
    return [part.replace("~1", "/").replace("~0", "~") for part in path.split("/")[1:]]


def _resolve_parent(document: Any, parts: list[str], *, create: bool) -> tuple[Any, str]:
    current = document
    for part in parts[:-1]:
        if isinstance(current, list):
            index = _array_index(part, len(current), allow_end=False)
            current = current[index]
        elif isinstance(current, dict):
            if part not in current:
                if not create:
                    raise KeyError(f"Missing path segment: {part}")
                current[part] = {}
            current = current[part]
        else:
            raise TypeError(f"Cannot traverse into {type(current).__name__}")
    return current, parts[-1]


def _patch_add(parent: Any, key: str, value: Any) -> None:
    if isinstance(parent, list):
        if key == "-":
            parent.append(value)
        else:
            parent.insert(_array_index(key, len(parent), allow_end=True), value)
    elif isinstance(parent, dict):
        parent[key] = value
    else:
        raise TypeError(f"Cannot add to {type(parent).__name__}")


def _patch_replace(parent: Any, key: str, value: Any) -> None:
    if isinstance(parent, list):
        parent[_array_index(key, len(parent), allow_end=False)] = value
    elif isinstance(parent, dict):
        if key not in parent:
            raise KeyError(f"Missing key for replace: {key}")
        parent[key] = value
    else:
        raise TypeError(f"Cannot replace in {type(parent).__name__}")


def _patch_remove(parent: Any, key: str) -> None:
    if isinstance(parent, list):
        del parent[_array_index(key, len(parent), allow_end=False)]
    elif isinstance(parent, dict):
        if key not in parent:
            raise KeyError(f"Missing key for remove: {key}")
        del parent[key]
    else:
        raise TypeError(f"Cannot remove from {type(parent).__name__}")


def _array_index(value: str, length: int, *, allow_end: bool) -> int:
    if value == "-" and allow_end:
        return length
    try:
        index = int(value)
    except ValueError as exc:
        raise ValueError(f"Expected array index, got {value!r}") from exc
    upper = length if allow_end else length - 1
    if index < 0 or index > upper:
        raise IndexError(f"Array index {index} out of range")
    return index


def _proof_spec_from_proof_context(case: ProtocolCase, proof_context: dict[str, Any]) -> ProofSpec:
    expectations = []
    for target in proof_context.get("target_lemmas", []) if isinstance(proof_context, dict) else []:
        if not isinstance(target, dict):
            continue
        name = str(target.get("name") or "").strip()
        if not name:
            continue
        expectations.append(
            LemmaExpectation(
                name=name,
                trace_kind=str(target.get("trace_kind") or "unknown"),
                expected_state=str(target.get("expected_state") or "ProvedSatisfying"),
                expected_raw=str(target.get("expected_raw") or ""),
                source=str(proof_context.get("proof_spec_source") or proof_context.get("source") or REVIEWED_PROOF_SOURCE),
                goal_type=str(target.get("goal_type") or ""),
                intent=str(target.get("intent") or ""),
                required_events=[str(event) for event in target.get("required_events", []) if event],
            )
        )
    return ProofSpec(
        case=case.name,
        mode=REVIEWED_PROOF_MODE,
        source=REVIEWED_PROOF_SOURCE,
        expectations=expectations,
        notes=["Reconstructed from derived proof context for review UI."],
    )


def _proof_spec_from_contract_payload(contract: dict[str, Any]) -> ProofSpec:
    case_payload = contract.get("case") if isinstance(contract.get("case"), dict) else {}
    expectations = []
    for target in contract.get("proof_targets", []) if isinstance(contract, dict) else []:
        if not isinstance(target, dict):
            continue
        name = str(target.get("name") or "").strip()
        if not name:
            continue
        expectations.append(
            LemmaExpectation(
                name=name,
                trace_kind=str(target.get("trace_kind") or "unknown"),
                expected_state=str(target.get("expected_state") or "ProvedSatisfying"),
                expected_raw=str(target.get("expected_raw") or ""),
                source=REVIEWED_PROOF_SOURCE,
                goal_type=str(target.get("goal_type") or ""),
                intent=source_intent_with_obligations(
                    case_name=str(case_payload.get("name") or "Protocol"),
                    lemma_name=name,
                    goal_type=str(target.get("goal_type") or ""),
                    intent=str(target.get("intent") or ""),
                ),
                required_events=[str(event) for event in target.get("required_events", []) if event],
            )
        )
    return ProofSpec(
        case=str(case_payload.get("name") or "Protocol"),
        mode=REVIEWED_PROOF_MODE,
        source=REVIEWED_PROOF_SOURCE,
        expectations=expectations,
        notes=["Reconstructed from reviewed modeling contract."],
    )


def _proof_spec_from_prepared_artifacts(run_dir: Path, case: ProtocolCase) -> ProofSpec:
    spec_path = run_dir / "proof" / "spec.initial.json"
    if spec_path.exists():
        raw = _read_json(spec_path)
        expectations = [
            LemmaExpectation(
                name=str(item.get("name") or ""),
                trace_kind=str(item.get("trace_kind") or "unknown"),
                expected_state=str(item.get("expected_state") or "ProvedSatisfying"),
                expected_raw=str(item.get("expected_raw") or ""),
                source=REVIEWED_PROOF_SOURCE,
                goal_type=str(item.get("goal_type") or ""),
                intent=source_intent_with_obligations(
                    case_name=case.name,
                    lemma_name=str(item.get("name") or ""),
                    goal_type=str(item.get("goal_type") or ""),
                    intent=str(item.get("intent") or ""),
                ),
                required_events=[str(event) for event in item.get("required_events", []) if event],
            )
            for item in raw.get("expectations", [])
            if isinstance(item, dict) and item.get("name")
        ]
        return ProofSpec(
            case=str(raw.get("case") or case.name),
            mode=REVIEWED_PROOF_MODE,
            source=REVIEWED_PROOF_SOURCE,
            expectations=expectations,
            notes=["Loaded from reviewed lemma specification."],
        )

    proof_context = _read_json(run_dir / "ir" / "proof_context.json") or _read_json(run_dir / "ir" / "proof_contract.json")
    if not isinstance(proof_context, dict) or not proof_context.get("target_lemmas"):
        protocol_ir = _read_json(run_dir / "ir" / "protocol_ir.json")
        validation = _read_json(run_dir / "ir" / "validation.json")
        if isinstance(protocol_ir, dict) and protocol_ir:
            proof_context = build_proof_context(
                case,
                protocol_ir,
                ProofSpec(case=case.name, mode=REVIEWED_PROOF_MODE, source=REVIEWED_PROOF_SOURCE, expectations=[]),
                validation,
            )
        else:
            proof_context = {}
    proof_spec = _proof_spec_from_proof_context(case, proof_context)
    if proof_spec.names:
        proof_spec.notes = ["Loaded from reviewed lemma specification."]
        return proof_spec
    return ProofSpec(
        case=case.name,
        mode=REVIEWED_PROOF_MODE,
        source=REVIEWED_PROOF_SOURCE,
        expectations=[],
        notes=["No reviewed proof targets were available."],
    )


def _enrich_prepared_ir_bundle(case: ProtocolCase, proof_spec: ProofSpec, ir_bundle: dict[str, Any]) -> None:
    proof_context = _proof_context(ir_bundle)
    if not isinstance(proof_context, dict):
        return
    by_name = {item.name: item for item in proof_spec.expectations}
    for target in proof_context.get("target_lemmas", []):
        if not isinstance(target, dict):
            continue
        name = str(target.get("name") or "")
        expectation = by_name.get(name)
        goal_type = str(target.get("goal_type") or (expectation.goal_type if expectation else ""))
        enriched = source_intent_with_obligations(
            case_name=case.name,
            lemma_name=name,
            goal_type=goal_type,
            intent=str(target.get("intent") or (expectation.intent if expectation else "")),
        )
        if enriched:
            target["intent"] = enriched
            if expectation and not expectation.intent:
                expectation.intent = enriched


def _pipeline_summary_payload(
    *,
    case: ProtocolCase,
    run_dir: Path,
    final_path: Path,
    proof_spec: ProofSpec,
    ir_bundle: dict[str, Any],
    lint_issues: list[str],
    verification: Any,
    coverage: Any,
    proof_lint_result: Any,
    proof: Any,
    generation_rounds_used: int,
    max_generation_rounds: int,
    max_repair_rounds: int,
    prove_enabled: bool,
) -> dict[str, Any]:
    validation = ir_bundle.get("validation") if isinstance(ir_bundle, dict) else {}
    validation = validation if isinstance(validation, dict) else {}
    summary = {
        "case": case.name,
        "source_run": str(run_dir),
        "run_dir": str(run_dir),
        "final_model": str(final_path),
        "goal_mode": REVIEWED_PROOF_MODE,
        "proof_spec_source": REVIEWED_PROOF_SOURCE,
        "protocol_ir_ok": validation.get("ok"),
        "protocol_ir_errors": validation.get("errors", []),
        "protocol_ir_warnings": validation.get("warnings", []),
        "generation_rounds_used": generation_rounds_used,
        "max_generation_rounds": max_generation_rounds,
        "max_repair_rounds": max_repair_rounds,
        "proof_expectations": [_expectation_payload(item) for item in proof_spec.expectations],
        "lint_issues": lint_issues,
        "verification_ok": (verification.ok and not lint_issues) if verification else None,
        "verification_status": verification.status if verification else "not_run",
        "verification_returncode_ok": verification.returncode_ok if verification else None,
        "verification_returncode": verification.returncode if verification else None,
        "verification_has_warnings": verification.has_warnings if verification else None,
        "verification_warnings": verification.warnings if verification else [],
        "lemma_coverage_ok": coverage.ok if coverage else None,
        "expected_lemmas": coverage.expected if coverage else proof_spec.names,
        "present_lemmas": coverage.present if coverage else [],
        "missing_lemmas": coverage.missing if coverage else [],
        "extra_lemmas": coverage.extra if coverage else [],
        "proof_lint_ok": proof_lint_result.ok if proof_lint_result else None,
        "proof_lint_issues": proof_lint_result.issues if proof_lint_result else [],
        "proof_ok": proof.ok if proof else None,
        "proof_status": proof.status if proof else ("not_run" if not prove_enabled else "skipped"),
        "proof_returncode": proof.returncode if proof else None,
        "proof_lemma_results": proof.lemma_results if proof else {},
        "proof_missing_results": proof.missing_results if proof else [],
        "proof_lemma_expected_states": proof.lemma_expected_states if proof else proof_spec.expected_states,
        "proof_lemma_actual_states": proof.lemma_actual_states if proof else {},
        "proof_lemma_matches": proof.lemma_matches if proof else {},
        "proof_mismatched_results": proof.mismatched_results if proof else [],
    }
    summary.update(_final_outcome(summary, prove_enabled=prove_enabled))
    return summary


def _expectation_payload(item: LemmaExpectation) -> dict[str, str]:
    return {
        "name": item.name,
        "trace_kind": item.trace_kind,
        "expected_state": item.expected_state,
        "expected_raw": item.expected_raw,
        "source": item.source,
        "goal_type": item.goal_type,
        "intent": item.intent,
    }


def _proof_payload(proof: Any, proof_spec: ProofSpec) -> dict[str, Any]:
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
        "output_path": str(proof.output_path),
        "stdout_tail": proof.stdout[-4000:],
        "stderr_tail": proof.stderr[-4000:],
        "proof_expectations": [_expectation_payload(item) for item in proof_spec.expectations],
    }


def _skipped_proof_payload(
    proof_spec: ProofSpec,
    verification: Any,
    coverage: Any,
    proof_lint_result: Any,
) -> dict[str, Any]:
    return {
        "ok": False,
        "status": "skipped",
        "returncode": None,
        "warnings": verification.warnings if verification else [],
        "lemma_results": {},
        "missing_results": proof_spec.names,
        "lemma_expected_states": proof_spec.expected_states,
        "lemma_actual_states": {},
        "lemma_matches": {},
        "mismatched_results": proof_spec.names,
        "per_lemma": {},
        "command": verification.command if verification else [],
        "output_path": str(verification.output_path) if verification else "",
        "stdout_tail": verification.stdout[-4000:] if verification else "",
        "stderr_tail": verification.stderr[-4000:] if verification else "",
        "proof_expectations": [_expectation_payload(item) for item in proof_spec.expectations],
        "compile_status": verification.status if verification else "not_run",
        "coverage_ok": coverage.ok if coverage else None,
        "proof_lint_ok": proof_lint_result.ok if proof_lint_result else None,
    }


def _case_from_nl_payload(payload: dict[str, Any]) -> ProtocolCase:
    name = str(payload.get("name") or payload.get("protocol_name") or "Protocol").strip() or "Protocol"
    description = str(payload.get("description") or payload.get("natural_language") or "").strip()
    if not description:
        raise ValueError("Natural-language description is required.")
    goals = payload.get("goals")
    if isinstance(goals, str):
        goals = [_parse_goal_text_line(line) for line in goals.splitlines() if line.strip()]
        goals = [goal for goal in goals if goal]
    if not isinstance(goals, list):
        goals = []
    assumptions = payload.get("assumptions")
    if isinstance(assumptions, str):
        assumptions = [line.strip() for line in assumptions.splitlines() if line.strip()]
    if not isinstance(assumptions, list):
        assumptions = []
    return ProtocolCase(
        name=name,
        description=description,
        goals=[item for item in goals if isinstance(item, dict)],
        assumptions=[str(item) for item in assumptions],
        notes=str(payload.get("notes") or "Created from review UI NL input."),
        difficulty=str(payload.get("difficulty") or ""),
    )


def _workflow_assumption_ledger(
    case: ProtocolCase,
    proof_spec: ProofSpec,
    ir_bundle: dict[str, Any],
) -> dict[str, Any]:
    proof_context = _proof_context(ir_bundle)
    validation = ir_bundle.get("validation", {}) if isinstance(ir_bundle, dict) else {}
    boundary = proof_context.get("preservation_boundary", {}) if isinstance(proof_context, dict) else {}
    questions = proof_context.get("semantic_review_questions", []) if isinstance(proof_context, dict) else []
    target_lemmas = proof_context.get("target_lemmas", []) if isinstance(proof_context, dict) else []
    score = 0
    triggers: list[str] = []
    difficulty = (case.difficulty or "").lower()
    if difficulty == "hard":
        score += 3
        triggers.append("difficulty=hard")
    elif difficulty == "medium":
        score += 2
        triggers.append("difficulty=medium")
    boundary_score = int(boundary.get("score") or 0)
    if boundary_score >= 8:
        score += 3
        triggers.append(f"preservation_boundary_score={boundary_score}")
    elif boundary_score >= 5:
        score += 2
        triggers.append(f"preservation_boundary_score={boundary_score}")
    warnings = validation.get("warnings", []) if isinstance(validation, dict) else []
    if warnings:
        score += 1
        triggers.append(f"ir_warning_count={len(warnings)}")
    goal_types = {
        str(item.get("goal_type") or "").lower()
        for item in target_lemmas
        if isinstance(item, dict)
    }
    expected_states = {
        str(item.get("expected_state") or "")
        for item in target_lemmas
        if isinstance(item, dict)
    }
    if goal_types.intersection({"authentication", "secrecy", "source"}):
        score += 1
        triggers.append("proof_sensitive_goal_types")
    if "CounterexampleFound" in expected_states:
        score += 1
        triggers.append("expected_counterexample_target")
    if any(isinstance(item, dict) and str(item.get("severity") or "").lower() == "high" for item in questions):
        score += 1
        triggers.append("high_severity_question")
    return {
        "case": case.name,
        "difficulty": case.difficulty,
        "risk_score": score,
        "risk_level": "high" if score >= 7 else ("medium" if score >= 4 else "low"),
        "risk_triggers": triggers,
        "preservation_boundary": {
            "needed": boundary.get("needed"),
            "score": boundary.get("score"),
            "triggers": boundary.get("triggers", []),
        },
        "ir_warnings": warnings,
        "target_lemmas": [
            {
                "name": item.get("name"),
                "goal_type": item.get("goal_type"),
                "expected_state": item.get("expected_state"),
            }
            for item in target_lemmas
            if isinstance(item, dict)
        ],
        "proof_expectations": [
            {
                "name": item.name,
                "goal_type": item.goal_type,
                "expected_state": item.expected_state,
            }
            for item in proof_spec.expectations
        ],
        "unresolved_questions": questions,
        "all_semantic_review_questions": questions,
        "default_policy_if_unanswered": "Preserve proof-critical provenance, checks, event placement, and expected attack surface.",
    }


def _contract_case_name(contract: dict[str, Any]) -> str:
    case = contract.get("case") if isinstance(contract.get("case"), dict) else {}
    return str(case.get("name") or "Protocol")


def _clean_goal_name(text: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in text.strip().lower())
    cleaned = "_".join(part for part in cleaned.split("_") if part)
    return cleaned[:48] or "goal"


def _parse_goal_text_line(line: str) -> dict[str, str] | None:
    stripped = line.strip()
    if not stripped:
        return None
    ordered = _parse_ordered_goal_text_line(stripped)
    if ordered is not None:
        return ordered
    metadata_match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?::|-)\s*(.+)$", stripped)
    if metadata_match and "=" in metadata_match.group(2):
        metadata: dict[str, str] = {}
        notes: list[str] = []
        for part in re.split(r"\s*;\s*", metadata_match.group(2)):
            if not part.strip():
                continue
            key_value = re.match(r"^([A-Za-z_][A-Za-z0-9_ ]*)\s*=\s*(.+)$", part.strip())
            if not key_value:
                notes.append(part.strip())
                continue
            key = key_value.group(1).strip().lower().replace(" ", "_")
            metadata[key] = key_value.group(2).strip()
        goal = {
            "name": metadata_match.group(1),
            "type": metadata.get("goal_type") or metadata.get("type") or metadata.get("choice_type") or "",
            "description": metadata.get("description") or metadata.get("notes") or "; ".join(notes),
        }
        if metadata.get("trace_kind"):
            goal["trace_kind"] = metadata["trace_kind"]
        if metadata.get("expected_result"):
            goal["expected_result"] = metadata["expected_result"]
            goal["expected_state"] = metadata["expected_result"]
        return goal
    match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?\s*(?::\s*(.*))?$", stripped)
    if not match:
        return {"name": _clean_goal_name(stripped), "type": "", "description": ""}
    return {
        "name": match.group(1),
        "type": (match.group(2) or "").strip(),
        "description": (match.group(3) or "").strip(),
    }


def _parse_ordered_goal_text_line(line: str) -> dict[str, str] | None:
    if ";" not in line:
        return None
    parts = [part.strip() for part in line.split(";")]
    if len(parts) < 4:
        return None
    name, goal_type, trace_kind, expected_result = parts[:4]
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
        return None
    goal = {
        "name": name,
        "type": goal_type,
        "description": "; ".join(part for part in parts[4:] if part),
    }
    if trace_kind:
        goal["trace_kind"] = trace_kind
    if expected_result:
        goal["expected_result"] = expected_result
        goal["expected_state"] = expected_result
    return goal


def _case_from_payload(payload: dict[str, Any], *, fallback_name: str) -> ProtocolCase:
    return ProtocolCase(
        name=str(payload.get("name") or payload.get("modelName") or payload.get("protocol") or fallback_name),
        description=str(payload.get("description") or payload.get("nl") or payload.get("text") or ""),
        goals=list(payload.get("goals") or payload.get("lemmas") or []),
        assumptions=[str(item) for item in payload.get("assumptions") or []],
        notes=str(payload.get("notes") or ""),
        difficulty=str(payload.get("difficulty") or ""),
        source_files=dict(payload.get("source_files") or payload.get("sourceFiles") or {}),
        reference_sapic=payload.get("reference_sapic") or payload.get("referenceSapic"),
        reference_tamarin=payload.get("reference_tamarin") or payload.get("referenceTamarin"),
    )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _json_safe(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    return value


def _pipeline_event_step(event: str) -> str:
    if event.startswith("generation_") or event == "sapic_generation":
        return "sapic_generation"
    if event.startswith("repair_") or event == "verify_done":
        return "repair_verify"
    if event.startswith("proof_") or event in {"lemma_coverage_done", "proof_lint_done"}:
        return "tamarin_prove"
    if event == "case_done":
        return "pipeline"
    return str(event or "pipeline")


def _slug(value: str) -> str:
    text = "".join(ch.lower() if ch.isalnum() else "_" for ch in value.strip())
    text = "_".join(part for part in text.split("_") if part)
    return text[:60] or "protocol"


def _resolve_path(path: Path, base: Path) -> Path:
    if path.is_absolute():
        return path
    cwd_path = Path.cwd() / path
    if cwd_path.exists():
        return cwd_path
    return base / path


if __name__ == "__main__":
    raise SystemExit(main())
