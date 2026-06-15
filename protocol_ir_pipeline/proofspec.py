from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .cases import ProtocolCase

DEFAULT_BENCHMARK_SUMMARY = Path(
    os.environ.get("AUTOSM_BENCHMARK_SUMMARY", "benchmark/summarized_results.txt")
)

PROVED_SATISFYING = "ProvedSatisfying"
COUNTEREXAMPLE_FOUND = "CounterexampleFound"
MISSING_PROOF_RESULT = "MissingProofResult"
PROOF_TIMEOUT = "ProofTimeout"
BLOCKED_BEFORE_PROOF = "BlockedBeforeProof"
NOT_RUN = "NotRun"
UNKNOWN = "Unknown"


@dataclass
class LemmaExpectation:
    name: str
    trace_kind: str = "unknown"
    expected_state: str = PROVED_SATISFYING
    expected_raw: str = "verified"
    source: str = "generated"
    goal_type: str = ""
    intent: str = ""
    required_events: list[str] = field(default_factory=list)


@dataclass
class ProofSpec:
    case: str
    mode: str
    source: str
    expectations: list[LemmaExpectation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def names(self) -> list[str]:
        return [item.name for item in self.expectations]

    @property
    def expected_states(self) -> dict[str, str]:
        return {item.name: item.expected_state for item in self.expectations}

    def expectation_for(self, lemma_name: str) -> LemmaExpectation | None:
        for item in self.expectations:
            if item.name == lemma_name:
                return item
        return None

    def prompt_payload(self) -> dict[str, Any]:
        return {
            "case": self.case,
            "mode": self.mode,
            "source": self.source,
            "expectations": [
                {
                    "name": item.name,
                    "trace_kind": item.trace_kind,
                    "expected_state": item.expected_state,
                    "goal_type": item.goal_type,
                    "intent": item.intent,
                    "required_events": item.required_events,
                }
                for item in self.expectations
            ],
            "notes": self.notes,
        }


@dataclass
class ReferenceSection:
    case: str
    source: str
    variant: str
    lemmas: dict[str, LemmaExpectation]


def build_initial_proof_spec(
    case: ProtocolCase,
    expose_benchmark_goals: bool,
    include_case_goals: bool = False,
    benchmark_summary_path: Path = DEFAULT_BENCHMARK_SUMMARY,
) -> ProofSpec:
    if expose_benchmark_goals:
        return benchmark_proof_spec(case, benchmark_summary_path)
    if include_case_goals:
        return case_goals_proof_spec(case)
    return ProofSpec(
        case=case.name,
        mode="llm_discovered",
        source="generated_after_sapic",
        expectations=[],
        notes=[
            "Benchmark reference goals are hidden. The generated model's own lemmas will become proof targets after Sapic+ generation."
        ],
    )


def case_goals_proof_spec(case: ProtocolCase) -> ProofSpec:
    goal_info = _goal_info(case)
    expectations: list[LemmaExpectation] = []
    for name in _dataset_goal_names(case):
        info = goal_info.get(name, {})
        trace_kind = str(info.get("trace_kind") or "unknown")
        expectations.append(
            LemmaExpectation(
                name=name,
                trace_kind=trace_kind,
                expected_state=str(info.get("expected_state") or info.get("expected_result") or UNKNOWN),
                expected_raw=str(info.get("expected_raw") or ""),
                source=str(info.get("source") or "case_goals"),
                goal_type=str(info.get("type") or infer_goal_type(name, trace_kind)),
                intent=str(info.get("description") or ""),
            )
        )
    if not expectations:
        return ProofSpec(
            case=case.name,
            mode="llm_discovered",
            source="generated_after_sapic",
            expectations=[],
            notes=["No user-supplied case goals were present; generated lemmas will be inferred."],
        )
    return ProofSpec(
        case=case.name,
        mode="user_supplied_goals",
        source="case_goals",
        expectations=expectations,
        notes=[
            "User-supplied UI goals are loaded from the dataset case.goals field.",
            "Planner should preserve target lemma names, goal types, trace kinds, and expected states when provided.",
        ],
    )


def complete_discovered_proof_spec(case: ProtocolCase, proof_spec: ProofSpec, sapic_plus: str) -> ProofSpec:
    if proof_spec.expectations:
        return proof_spec
    expectations = [
        LemmaExpectation(
            name=name,
            expected_state=PROVED_SATISFYING,
            expected_raw="verified",
            source="llm_discovered",
            intent="Generated lemma is expected to prove unless it is explicitly modeled as an attack-search lemma.",
        )
        for name in extract_lemma_names(sapic_plus)
    ]
    return ProofSpec(
        case=case.name,
        mode="llm_discovered",
        source="generated_model",
        expectations=expectations,
        notes=[
            "No benchmark expected states were exposed; default generated-lemma expectation is ProvedSatisfying."
        ],
    )


def benchmark_proof_spec(
    case: ProtocolCase,
    benchmark_summary_path: Path = DEFAULT_BENCHMARK_SUMMARY,
) -> ProofSpec:
    dataset_spec = dataset_expected_results_proof_spec(case)
    if dataset_spec is not None:
        return dataset_spec

    sections = parse_benchmark_summary(benchmark_summary_path)
    chosen = choose_reference_section(case, sections)
    goal_info = _goal_info(case)
    if chosen is None:
        expectations = [
            LemmaExpectation(
                name=name,
                expected_state=PROVED_SATISFYING,
                expected_raw="verified",
                source="dataset_fallback",
                goal_type=goal_info.get(name, {}).get("type", ""),
                intent=goal_info.get(name, {}).get("description", ""),
            )
            for name in _dataset_goal_names(case)
        ]
        return ProofSpec(
            case=case.name,
            mode="benchmark_reference",
            source="dataset_fallback",
            expectations=expectations,
            notes=[
                f"No AutoSM summarized result was found in {benchmark_summary_path}; falling back to dataset goal names."
            ],
        )

    expectations: list[LemmaExpectation] = []
    for lemma in chosen.lemmas.values():
        info = goal_info.get(lemma.name, {})
        expectations.append(
            LemmaExpectation(
                name=lemma.name,
                trace_kind=lemma.trace_kind,
                expected_state=lemma.expected_state,
                expected_raw=lemma.expected_raw,
                source=lemma.source,
                goal_type=str(info.get("type") or infer_goal_type(lemma.name, lemma.trace_kind)),
                intent=str(info.get("description") or ""),
            )
        )
    return ProofSpec(
        case=case.name,
        mode="benchmark_reference",
        source=chosen.source,
        expectations=expectations,
        notes=[
            "Benchmark expected states are loaded from AutoSM summarized_results.txt.",
            "Expected CounterexampleFound means the generated model should preserve the attack/counterexample, not over-prove the lemma.",
        ],
    )


def dataset_expected_results_proof_spec(case: ProtocolCase) -> ProofSpec | None:
    expected_results = getattr(case, "expected_results", {}) or {}
    if not isinstance(expected_results, dict) or not expected_results:
        return None

    goal_info = _goal_info(case)
    ordered_names = []
    for name in _dataset_goal_names(case):
        if name in expected_results and name not in ordered_names:
            ordered_names.append(name)
    for name in expected_results:
        if name not in ordered_names:
            ordered_names.append(name)

    expectations: list[LemmaExpectation] = []
    for name in ordered_names:
        result = expected_results.get(name)
        if not isinstance(result, dict):
            continue
        info = goal_info.get(name, {})
        trace_kind = str(result.get("trace_kind") or info.get("trace_kind") or "unknown")
        expectations.append(
            LemmaExpectation(
                name=name,
                trace_kind=trace_kind,
                expected_state=str(result.get("expected_state") or info.get("expected_state") or PROVED_SATISFYING),
                expected_raw=str(result.get("expected_raw") or info.get("expected_raw") or ""),
                source=str(result.get("source") or "dataset_expected_results"),
                goal_type=str(info.get("type") or infer_goal_type(name, trace_kind)),
                intent=str(info.get("description") or ""),
            )
        )
    if not expectations:
        return None
    return ProofSpec(
        case=case.name,
        mode="benchmark_reference",
        source="dataset_expected_results",
        expectations=expectations,
        notes=[
            "Benchmark expected states are loaded from the dataset expected_results field, typically parsed from UI Markdown.",
            "Expected CounterexampleFound means the generated IR/contract should preserve the attack/counterexample surface, not repair it.",
        ],
    )


def parse_benchmark_summary(path: Path) -> list[ReferenceSection]:
    if not path.exists():
        return []
    sections: list[ReferenceSection] = []
    current_source = ""
    current_case = ""
    current_variant = ""
    current_lemmas: dict[str, LemmaExpectation] = {}

    def flush() -> None:
        if current_source:
            sections.append(
                ReferenceSection(
                    case=current_case,
                    source=current_source,
                    variant=current_variant,
                    lemmas=dict(current_lemmas),
                )
            )

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        analyzed = re.match(r"^analyzed:\s+(.+\.spthy)\s*$", line)
        if analyzed:
            flush()
            current_source = analyzed.group(1)
            current_case, current_variant = source_to_case(current_source)
            current_lemmas = {}
            continue
        result = parse_lemma_result_line(line)
        if result and current_source:
            name, trace_kind, raw_result = result
            current_lemmas[name] = LemmaExpectation(
                name=name,
                trace_kind=trace_kind,
                expected_state=proof_state_from_result(raw_result),
                expected_raw=raw_result,
                source=current_source,
                goal_type=infer_goal_type(name, trace_kind),
            )
    flush()
    return sections


def choose_reference_section(case: ProtocolCase, sections: list[ReferenceSection]) -> ReferenceSection | None:
    candidates = [section for section in sections if section.case == normalize_case_name(case.name)]
    if not candidates:
        return None
    goals = set(_dataset_goal_names(case))

    def score(section: ReferenceSection) -> tuple[int, int, int, int]:
        overlap = len(goals.intersection(section.lemmas)) if goals else 0
        variant_priority = 2 if section.variant == "P" else 1 if section.variant == "R" else 0
        has_results = 1 if section.lemmas else 0
        return (overlap, variant_priority, has_results, len(section.lemmas))

    return max(candidates, key=score)


def parse_lemma_result_line(line: str) -> tuple[str, str, str] | None:
    match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s+\(([^)]*)\):\s+(.+)$", line)
    if not match:
        return None
    return match.group(1), match.group(2), " ".join(match.group(3).split())


def proof_state_from_result(result: str) -> str:
    text = " ".join((result or "").split()).lower()
    if text.startswith("verified"):
        return PROVED_SATISFYING
    if text.startswith("falsified"):
        return COUNTEREXAMPLE_FOUND
    if "timeout" in text:
        return PROOF_TIMEOUT
    return UNKNOWN


def actual_state_from_result(result: str | None) -> str:
    if not result:
        return MISSING_PROOF_RESULT
    return proof_state_from_result(result)


def evaluate_lemma_matches(
    lemma_results: dict[str, str],
    proof_spec: ProofSpec,
) -> tuple[dict[str, str], dict[str, bool], list[str]]:
    states: dict[str, str] = {}
    matches: dict[str, bool] = {}
    mismatched: list[str] = []
    for expectation in proof_spec.expectations:
        actual_state = actual_state_from_result(lemma_results.get(expectation.name))
        states[expectation.name] = actual_state
        matched = actual_state == expectation.expected_state
        matches[expectation.name] = matched
        if not matched:
            mismatched.append(expectation.name)
    return states, matches, mismatched


def source_to_case(source: str) -> tuple[str, str]:
    name = Path(source).name.removesuffix(".spthy")
    variant = ""
    match = re.match(r"^(.*)-([PR])$", name)
    if match:
        name = match.group(1)
        variant = match.group(2)
    return normalize_case_name(name), variant


def normalize_case_name(name: str) -> str:
    normalized = name.strip().replace("-", "_").replace(" ", "_")
    normalized = re.sub(r"_+", "_", normalized)
    return normalized


def infer_goal_type(name: str, trace_kind: str = "") -> str:
    lower = name.lower()
    if trace_kind == "exists-trace" or "exec" in lower or "session" in lower or "complete" in lower:
        return "executability"
    if "secret" in lower or "secrecy" in lower:
        return "secrecy"
    if lower.startswith("inj") or "auth" in lower or "agree" in lower or "agreement" in lower:
        return "authentication"
    if "typing" in lower or "source" in lower:
        return "source"
    return "property"


def _dataset_goal_names(case: ProtocolCase) -> list[str]:
    return [str(goal["name"]) for goal in case.goals if isinstance(goal, dict) and goal.get("name")]


def _goal_info(case: ProtocolCase) -> dict[str, dict[str, Any]]:
    return {str(goal["name"]): goal for goal in case.goals if isinstance(goal, dict) and goal.get("name")}


def extract_lemma_names(sapic_plus: str) -> list[str]:
    names: list[str] = []
    for match in re.finditer(r"(?m)^\s*lemma\s+([A-Za-z_][A-Za-z0-9_]*)\b", sapic_plus or ""):
        names.append(match.group(1))
    return names
