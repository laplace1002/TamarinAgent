from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ProtocolCase:
    name: str
    description: str
    goals: list[dict[str, Any]] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    expected_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    notes: str = ""
    difficulty: str = ""
    source_files: dict[str, str] = field(default_factory=dict)
    reference_sapic: str | None = None
    reference_tamarin: str | None = None


def load_cases(path: Path) -> list[ProtocolCase]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "cases" in raw:
        raw_cases = raw["cases"]
    elif isinstance(raw, list):
        raw_cases = raw
    else:
        raise ValueError("Dataset must be a list or an object with a 'cases' list.")

    cases: list[ProtocolCase] = []
    for index, item in enumerate(raw_cases):
        if not isinstance(item, dict):
            raise ValueError(f"Case {index} must be a JSON object.")
        name = item.get("name") or item.get("modelName") or item.get("protocol")
        description = item.get("description") or item.get("nl") or item.get("text")
        if not name or not description:
            raise ValueError(f"Case {index} must contain name and description.")
        cases.append(
            ProtocolCase(
                name=str(name),
                description=str(description),
                goals=list(item.get("goals") or item.get("lemmas") or []),
                assumptions=list(item.get("assumptions") or []),
                expected_results=dict(item.get("expected_results") or item.get("expectedResults") or {}),
                notes=str(item.get("notes") or ""),
                difficulty=str(item.get("difficulty") or ""),
                source_files=dict(item.get("sourceFiles") or item.get("source_files") or {}),
                reference_sapic=item.get("referenceSapic") or item.get("sapic"),
                reference_tamarin=item.get("referenceTamarin") or item.get("tamarin"),
            )
        )
    return cases


def case_slug(name: str) -> str:
    slug = "".join(ch if ch.isalnum() else "_" for ch in name.strip())
    slug = "_".join(part for part in slug.split("_") if part)
    return slug or "protocol"
