from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


class ArtifactStore:
    """Small append-only artifact writer for reproducible research runs."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def path(self, relative: str) -> Path:
        path = self.run_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def write_text(self, relative: str, content: str) -> Path:
        path = self.path(relative)
        path.write_text(content or "", encoding="utf-8")
        return path

    def write_json(self, relative: str, data: Any) -> Path:
        path = self.path(relative)
        path.write_text(
            json.dumps(_jsonable(data), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path

    def append_jsonl(self, relative: str, data: Any) -> Path:
        path = self.path(relative)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(_jsonable(data), ensure_ascii=False, sort_keys=True))
            f.write("\n")
        return path

    def stage_record(self, stage: str, **payload: Any) -> dict[str, Any]:
        record = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "stage": stage,
            **payload,
        }
        self.append_jsonl("history/stages.jsonl", record)
        return record


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if isinstance(value, tuple):
        return [_jsonable(v) for v in value]
    return value
