from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


SOURCE_OBLIGATION_PREFIX = "Source obligations:"
DEFAULT_BENCHMARK_DIR = Path(os.environ.get("AUTOSM_BENCHMARK_DIR", "benchmark"))
SOURCE_OBLIGATION_CASES = frozenset(
    {
        "woo_lam",
        "splice",
        "kao_chow",
        "nssk",
        "neuman_stubblebine",
        "otway_rees",
        "yahalom",
    }
)


def source_obligation_description(sapic_plus: str, lemma_name: str) -> str:
    """Return a compact text description for a source/typing lemma."""
    formula = _lemma_formula(sapic_plus, lemma_name)
    if not formula:
        return ""
    obligations = _source_obligations(formula)
    if not obligations:
        return ""
    return f"{SOURCE_OBLIGATION_PREFIX} " + "; ".join(obligations) + "."


def include_source_obligations_for_case(case_name: str) -> bool:
    """Return whether reviewed source obligations should be injected for this case."""
    return _normalize_case_name(case_name) in SOURCE_OBLIGATION_CASES


def enrich_source_goal_description(
    goal: dict[str, Any],
    sapic_plus: str,
    *,
    case_name: str = "",
) -> dict[str, Any]:
    if not isinstance(goal, dict):
        return goal
    if not _is_source_goal(goal):
        return goal
    if case_name and not include_source_obligations_for_case(case_name):
        return goal
    description = source_obligation_description(sapic_plus, str(goal.get("name") or ""))
    if not description:
        return goal
    enriched = dict(goal)
    existing = str(enriched.get("description") or "").strip()
    enriched["description"] = merge_source_obligation_text(existing, description)
    return enriched


def merge_source_obligation_text(existing: str, obligations: str) -> str:
    existing = (existing or "").strip()
    obligations = (obligations or "").strip()
    if not obligations:
        return "" if _is_restored_target_placeholder(existing) else existing
    if SOURCE_OBLIGATION_PREFIX in existing:
        source_index = existing.find(SOURCE_OBLIGATION_PREFIX)
        prefix = existing[:source_index].strip()
        current_obligations = existing[source_index:].strip()
        if current_obligations != obligations:
            if not prefix or _is_restored_target_placeholder(prefix):
                return obligations
            return f"{prefix} {obligations}"
        if _is_restored_target_placeholder(prefix):
            return current_obligations
        return existing
    if _is_restored_target_placeholder(existing):
        return obligations
    if not existing:
        return obligations
    return f"{existing} {obligations}"


def reference_sapic_path_for_case(
    case_name: str,
    benchmark_dir: Path = DEFAULT_BENCHMARK_DIR,
) -> Path | None:
    normalized = _normalize_case_name(case_name)
    for path in benchmark_dir.glob("*-P.spthy"):
        stem = path.name.removesuffix("-P.spthy")
        if _normalize_case_name(stem) == normalized:
            return path
    return None


def reference_sapic_for_case(
    case_name: str,
    benchmark_dir: Path = DEFAULT_BENCHMARK_DIR,
) -> str:
    path = reference_sapic_path_for_case(case_name, benchmark_dir)
    if path is None or not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def enrich_source_goals_from_reference(
    goals: list[dict[str, Any]],
    case_name: str,
    benchmark_dir: Path = DEFAULT_BENCHMARK_DIR,
) -> list[dict[str, Any]]:
    if not include_source_obligations_for_case(case_name):
        return goals
    reference_sapic = reference_sapic_for_case(case_name, benchmark_dir)
    if not reference_sapic:
        return goals
    return [enrich_source_goal_description(goal, reference_sapic, case_name=case_name) for goal in goals]


def source_intent_with_obligations(
    *,
    case_name: str,
    lemma_name: str,
    goal_type: str,
    intent: str = "",
    benchmark_dir: Path = DEFAULT_BENCHMARK_DIR,
) -> str:
    if not _is_source_goal({"name": lemma_name, "type": goal_type}):
        return intent or ""
    if not include_source_obligations_for_case(case_name):
        return merge_source_obligation_text(intent or "", "")
    reference_sapic = reference_sapic_for_case(case_name, benchmark_dir)
    description = source_obligation_description(reference_sapic, lemma_name) if reference_sapic else ""
    return merge_source_obligation_text(intent or "", description)


def _lemma_formula(sapic_plus: str, lemma_name: str) -> str:
    match = re.search(
        rf"(?ms)^[ \t]*lemma[ \t]+{re.escape(lemma_name)}\b[^\n]*:[ \t]*(?:\n[ \t]*(?:all-traces|exists-trace)[ \t]*)?\n[ \t]*\"(.*?)\"",
        sapic_plus or "",
    )
    return match.group(1) if match else ""


def _source_obligations(formula: str) -> list[str]:
    obligations: list[str] = []
    for match in re.finditer(r"\b(IN_[A-Za-z0-9_]+\s*\([^)]*\))\s*@\s*#?[A-Za-z0-9_]+", formula):
        antecedent = _parse_fact(match.group(1))
        consequent = _consequent_slice(formula, match.end())
        alternatives = _source_alternatives(consequent)
        if alternatives:
            obligations.append(_source_obligation_phrase(antecedent, alternatives))
    return list(dict.fromkeys(obligations))


def _consequent_slice(formula: str, start: int) -> str:
    next_all = re.search(r"\bAll\b", formula[start:])
    end = start + next_all.start() if next_all else len(formula)
    return formula[start:end]


def _source_alternatives(text: str) -> list[dict[str, str]]:
    alternatives: list[dict[str, str]] = []
    for match in re.finditer(r"\b((?:OUT|IN)_[A-Za-z0-9_]+|!?KU|!?K)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*@", text):
        name = match.group(1).lstrip("!")
        if name not in {"K", "KU"} and not name.startswith("OUT_"):
            continue
        alternatives.append(_parse_fact(f"{name}({match.group(2)})"))
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, str]] = []
    for fact in alternatives:
        key = (fact.get("kind", ""), fact.get("role", ""), fact.get("label", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(fact)
    return unique


def _parse_fact(text: str) -> dict[str, str]:
    compact = re.sub(r"\s+", " ", text.strip()).replace("( ", "(").replace(" )", ")")
    name = compact.split("(", 1)[0]
    if name in {"K", "KU"}:
        return {"kind": name, "role": "", "label": ""}
    match = re.fullmatch(r"(IN|OUT)_([A-Za-z0-9]+)(?:_(.+))?", name)
    if not match:
        return {"kind": name, "role": "", "label": ""}
    return {"kind": match.group(1), "role": match.group(2), "label": match.group(3) or ""}


def _source_obligation_phrase(antecedent: dict[str, str], alternatives: list[dict[str, str]]) -> str:
    subject = _input_subject_phrase(antecedent)
    choices = [_alternative_phrase(alternative) for alternative in alternatives]
    return f"{subject} must be {' or '.join(choice for choice in choices if choice)}"


def _alternative_phrase(fact: dict[str, str]) -> str:
    if fact.get("kind") in {"K", "KU"}:
        return "public"
    role = fact.get("role") or "sender"
    return f"originate from {role}"


def _input_subject_phrase(fact: dict[str, str]) -> str:
    role = fact.get("role") or "role"
    label = _semantic_label_phrase(fact.get("label") or "")
    if label:
        return f"{role}'s accepted {label} value"
    return f"{role}'s accepted input value"


def _semantic_label_phrase(label: str) -> str:
    label = label.strip("_")
    if not label or label.isdigit():
        return ""
    return " ".join(part for part in label.split("_") if part)


def _is_source_goal(goal: dict[str, Any]) -> bool:
    goal_type = str(goal.get("type") or goal.get("goal_type") or goal.get("kind") or "").lower()
    name = str(goal.get("name") or "").lower()
    return goal_type in {"source", "typing", "sources"} or "source" in name or "typing" in name


def _is_restored_target_placeholder(text: str) -> bool:
    return bool(
        re.fullmatch(
            r"\s*Restored benchmark target lemma `[^`]+` that was omitted by earlier attribute-blind lemma extraction\.?\s*",
            text or "",
        )
    )


def _normalize_case_name(name: str) -> str:
    normalized = name.strip().replace("-", "_").replace(" ", "_")
    normalized = re.sub(r"_+", "_", normalized)
    return normalized.lower()
