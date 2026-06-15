from __future__ import annotations


class StageFailure(RuntimeError):
    def __init__(self, stage: str, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.stage = stage
        self.details = details or {}
