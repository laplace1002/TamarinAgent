from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from .cases import ProtocolCase
from .proofspec import ProofSpec


def default_abstraction_cases_path() -> Path:
    return Path(__file__).resolve().parents[1] / "examples" / "protocol-abstraction-cases.json"


def default_retrieval_config_path() -> Path:
    return Path(__file__).resolve().parents[1] / "config" / "abstraction_retrieval.json"


def load_retrieval_config(config_path: str | Path | None = None) -> dict[str, Any]:
    key = str(config_path) if config_path else None
    return _load_retrieval_config_cached(key)


@lru_cache(maxsize=8)
def _load_retrieval_config_cached(config_path: str | None) -> dict[str, Any]:
    path = Path(config_path or os.getenv("ABSTRACTION_RETRIEVAL_CONFIG") or default_retrieval_config_path())
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    config = _default_retrieval_config()
    config.update(payload)
    config["_config_path"] = str(path)
    return config


def retrieve_abstraction_hints(
    case: ProtocolCase,
    protocol_ir: dict[str, Any],
    proof_spec: ProofSpec,
    cases_path: Path | None = None,
    retrieval_config_path: Path | None = None,
    top_k: int = 3,
) -> dict[str, Any]:
    if top_k <= 0:
        return {"enabled": False, "selected": [], "query_features": []}
    path = cases_path or default_abstraction_cases_path()
    retrieval_config = load_retrieval_config(retrieval_config_path)
    examples = _load_abstraction_cases(path)
    if not examples:
        return {
            "enabled": False,
            "source_path": str(path),
            "retrieval_config_path": retrieval_config.get("_config_path"),
            "selected": [],
            "query_features": [],
            "error": "No abstraction cases could be loaded.",
        }

    query_features = _query_features(case, protocol_ir, proof_spec, retrieval_config)
    should_enable, gate_reason = _retrieval_gate(case, protocol_ir, proof_spec, query_features, retrieval_config)
    if not should_enable:
        return {
            "enabled": False,
            "source_path": str(path),
            "retrieval_config_path": retrieval_config.get("_config_path"),
            "selected": [],
            "query_features": sorted(query_features),
            "reason": gate_reason,
        }
    scored = []
    for example in examples:
        score, reasons = _score_example(example, query_features, case, retrieval_config)
        if score > 0:
            scored.append((score, reasons, example))
    scored.sort(key=lambda item: (-item[0], str(item[2].get("id") or "")))
    selected = [_distill_example(example, score, reasons) for score, reasons, example in scored[:top_k]]
    return {
        "enabled": True,
        "source_path": str(path),
        "retrieval_config_path": retrieval_config.get("_config_path"),
        "query_features": sorted(query_features),
        "selected": selected,
        "policy": (
            "Use these examples only as proof-engineering and abstraction guidance. "
            "Do not copy protocol names, concrete message flows, lemma formulas, or benchmark-specific fixes."
        ),
    }


def _load_abstraction_cases(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _query_features(
    case: ProtocolCase,
    protocol_ir: dict[str, Any],
    proof_spec: ProofSpec,
    retrieval_config: dict[str, Any],
) -> set[str]:
    features: set[str] = set()
    difficulty = (case.difficulty or "").lower()
    if difficulty:
        features.add(f"difficulty:{difficulty}")

    text = " ".join(
        [
            case.name,
            case.description,
            case.notes,
            _protocol_surface_text(protocol_ir),
            " ".join(item.name for item in proof_spec.expectations),
            " ".join(item.goal_type for item in proof_spec.expectations),
        ]
    ).lower()
    token_map = _feature_keywords(retrieval_config)
    for feature, needles in token_map.items():
        if any(_contains_feature(text, needle) for needle in needles):
            features.add(feature)

    goal_types = {item.goal_type.lower() for item in proof_spec.expectations}
    for goal_type in goal_types:
        if goal_type:
            features.add(goal_type)
    if any(item.expected_state == "CounterexampleFound" for item in proof_spec.expectations):
        features.add("expected_counterexample")
    if len(_as_list(protocol_ir.get("messages"))) >= 4:
        features.add("multi_message")
    if len(_as_list(protocol_ir.get("roles"))) >= 3:
        features.add("multi_role")
    return features


def _protocol_surface_text(protocol_ir: dict[str, Any]) -> str:
    crypto = protocol_ir.get("crypto") if isinstance(protocol_ir.get("crypto"), dict) else {}
    parts: list[str] = []
    parts.extend(str(item) for item in _as_list(crypto.get("builtins")))
    parts.extend(str(item) for item in _as_list(crypto.get("functions")))
    for message in _as_list(protocol_ir.get("messages")):
        if isinstance(message, dict):
            parts.extend(
                str(message.get(key) or "")
                for key in ("label", "term", "meaning", "protection")
            )
    for check in _as_list(protocol_ir.get("checks")):
        if isinstance(check, dict):
            parts.append(str(check.get("condition") or ""))
    compromise = protocol_ir.get("compromise") if isinstance(protocol_ir.get("compromise"), dict) else {}
    parts.append(str(compromise.get("policy") or ""))
    parts.extend(str(item) for item in _as_list(compromise.get("reveal_events")))
    return " ".join(parts)


def _contains_feature(text: str, needle: str) -> bool:
    if needle.startswith(" ") or needle.endswith(" "):
        return needle in f" {text} "
    if re.fullmatch(r"[A-Za-z0-9_+-]+", needle):
        return re.search(rf"(?<![A-Za-z0-9_]){re.escape(needle)}(?![A-Za-z0-9_])", text) is not None
    return needle in text


def _retrieval_gate(
    case: ProtocolCase,
    protocol_ir: dict[str, Any],
    proof_spec: ProofSpec,
    query_features: set[str],
    retrieval_config: dict[str, Any],
) -> tuple[bool, str]:
    difficulty = (case.difficulty or "").lower()
    gate_config = retrieval_config.get("gate") if isinstance(retrieval_config.get("gate"), dict) else {}
    always_enable_difficulties = _config_set(gate_config, "always_enable_difficulties", {"medium", "hard"})
    if difficulty in always_enable_difficulties:
        return True, f"difficulty={difficulty}"
    easy_complex_features = _config_set(
        retrieval_config,
        "easy_complex_features",
        set(),
    )
    if difficulty == "easy" and not query_features.intersection(easy_complex_features):
        return False, "easy_low_complexity_case"
    easy_matches = query_features.intersection(easy_complex_features)
    for disabled_set in _config_set_list(gate_config, "easy_single_feature_disable", []):
        if difficulty == "easy" and easy_matches == disabled_set:
            return False, "easy_single_feature_disabled"
    complex_features = _config_set(
        retrieval_config,
        "complex_features",
        set(),
    )
    min_complex_feature_count = _config_int(gate_config, "min_complex_feature_count", 2)
    if len(query_features.intersection(complex_features)) >= min_complex_feature_count:
        return True, "multiple_complex_features"
    if len(_as_list(protocol_ir.get("messages"))) >= 4 or len(_as_list(protocol_ir.get("roles"))) >= 3:
        return True, "multi_message_or_multi_role"
    if any(item.expected_state == "CounterexampleFound" for item in proof_spec.expectations) and any(
        item.goal_type.lower() in {"authentication", "secrecy"} for item in proof_spec.expectations
    ):
        return True, "proof_sensitive_counterexample"
    return False, "low_complexity_case"


def _score_example(
    example: dict[str, Any],
    query_features: set[str],
    case: ProtocolCase,
    retrieval_config: dict[str, Any],
) -> tuple[int, list[str]]:
    example_features = {str(item).lower() for item in _as_list(example.get("features"))}
    goal_family = {str(item).lower() for item in _as_list(example.get("security_goal_family"))}
    family = str(example.get("protocol_family") or "").lower()
    haystack = " ".join([family, " ".join(example_features), " ".join(goal_family), str(example.get("name") or "")]).lower()

    score = 0
    reasons: list[str] = []
    for feature in query_features:
        token = feature.split(":", 1)[-1]
        if token in example_features or token in goal_family or re.search(rf"\b{re.escape(token)}\b", haystack):
            score += 2
            reasons.append(feature)
    broad_matches = _config_set(
        retrieval_config,
        "broad_match_features",
        {"agreement", "authentication", "secrecy", "property", "executability", "expected_counterexample"},
    )
    if not set(reasons).difference(broad_matches):
        return 0, []
    difficulty = (case.difficulty or "").lower()
    if difficulty and str(example.get("difficulty_band") or "").lower() == difficulty:
        score += 1
        reasons.append(f"difficulty_band={difficulty}")
    for boost in _as_list(retrieval_config.get("family_boosts")):
        if not isinstance(boost, dict):
            continue
        if _boost_matches(boost, query_features, example_features):
            boost_score = _config_int(boost, "score", 0)
            if boost_score > 0:
                score += boost_score
                reasons.append(str(boost.get("name") or "family_boost"))
    return score, sorted(set(reasons))


def _distill_example(example: dict[str, Any], score: int, reasons: list[str]) -> dict[str, Any]:
    return {
        "id": example.get("id"),
        "name": example.get("name"),
        "score": score,
        "matched_reasons": reasons[:12],
        "protocol_family": example.get("protocol_family"),
        "features": _as_list(example.get("features"))[:12],
        "security_goal_family": _as_list(example.get("security_goal_family"))[:8],
        "difficulty_band": example.get("difficulty_band"),
        "abstraction_lessons": _as_list(example.get("abstraction_lessons"))[:5],
        "avoid_copying": example.get("avoid_copying"),
    }


def _default_retrieval_config() -> dict[str, Any]:
    return {
        "feature_keywords": {},
        "easy_complex_features": [],
        "complex_features": [],
        "broad_match_features": [
            "agreement",
            "authentication",
            "secrecy",
            "property",
            "executability",
            "expected_counterexample",
        ],
        "family_boosts": [],
        "gate": {
            "always_enable_difficulties": ["medium", "hard"],
            "min_complex_feature_count": 2,
            "easy_single_feature_disable": [],
        },
    }


def _feature_keywords(retrieval_config: dict[str, Any]) -> dict[str, list[str]]:
    raw = retrieval_config.get("feature_keywords")
    if not isinstance(raw, dict):
        return {}
    keywords: dict[str, list[str]] = {}
    for feature, needles in raw.items():
        feature_name = str(feature).strip().lower()
        if not feature_name:
            continue
        values = [str(item).lower() for item in _as_list(needles) if str(item)]
        if values:
            keywords[feature_name] = values
    return keywords


def _config_set(config: dict[str, Any], key: str, default: set[str]) -> set[str]:
    if key not in config:
        return set(default)
    values = _as_list(config.get(key))
    return {str(item).lower() for item in values if str(item)}


def _config_set_list(config: dict[str, Any], key: str, default: list[set[str]]) -> list[set[str]]:
    if key not in config:
        return [set(item) for item in default]
    values = _as_list(config.get(key))
    sets: list[set[str]] = []
    for value in values:
        items = _as_list(value)
        feature_set = {str(item).lower() for item in items if str(item)}
        if feature_set:
            sets.append(feature_set)
    return sets


def _config_int(config: dict[str, Any], key: str, default: int) -> int:
    try:
        return int(config.get(key, default))
    except (TypeError, ValueError):
        return default


def _boost_matches(boost: dict[str, Any], query_features: set[str], example_features: set[str]) -> bool:
    query_any = _config_set(boost, "query_any", set())
    query_all = _config_set(boost, "query_all", set())
    example_any = _config_set(boost, "example_any", set())
    example_all = _config_set(boost, "example_all", set())
    if query_any and not query_features.intersection(query_any):
        return False
    if query_all and not query_all.issubset(query_features):
        return False
    if example_any and not example_features.intersection(example_any):
        return False
    if example_all and not example_all.issubset(example_features):
        return False
    return bool(query_any or query_all or example_any or example_all)


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]
