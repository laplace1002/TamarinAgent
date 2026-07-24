#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from protocol_ir_pipeline.c_to_ir import run_c_to_ir_extraction
from protocol_ir_pipeline.llm import LLMClient, LLMConfig, load_local_env


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the staged C-to-ProtocolIR extraction frontend. "
            "Use --emit-prompts-only to inspect the generic LLM instructions without making API calls."
        )
    )
    parser.add_argument(
        "--source",
        type=Path,
        action="append",
        required=True,
        help="C source file. Repeat for multiple files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for code context, prompts, LLM histories, and ProtocolIR artifacts.",
    )
    parser.add_argument("--name", default="", help="Optional protocol name hint.")
    parser.add_argument(
        "--goals-file",
        type=Path,
        default=None,
        help="Optional JSON file containing a list of user-supplied goal/lemma records.",
    )
    parser.add_argument(
        "--emit-prompts-only",
        action="store_true",
        help="Only preprocess C and write all C-to-IR prompts; do not call an LLM.",
    )
    parser.add_argument("--max-stage-retries", type=int, default=1)
    parser.add_argument(
        "--max-stages",
        type=int,
        default=None,
        help="Debug mode: run only the first N extraction stages, then stop before ProtocolIR assembly.",
    )
    parser.add_argument(
        "--resume-existing",
        action="store_true",
        help="Reuse existing history/c_to_ir stage JSON files in output-dir and continue with missing stages.",
    )
    parser.add_argument(
        "--rerun-from-stage",
        type=int,
        default=None,
        help="With --resume-existing, reuse earlier stages and rerun this 1-based stage number and later stages.",
    )
    parser.add_argument("--max-prompt-code-chars", type=int, default=24000)
    parser.add_argument(
        "--no-modeling-contract",
        action="store_true",
        help="Do not emit modeling_contract.json/md after ProtocolIR assembly.",
    )
    parser.add_argument("--provider", default="deepseek")
    parser.add_argument("--model", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-mode", default="chat")
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--max-tokens", type=int, default=38888)
    parser.add_argument("--llm-timeout", type=float, default=1800.0)
    parser.add_argument("--reasoning-effort", default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    load_local_env(REPO_ROOT)
    goals = _load_goals(args.goals_file)
    llm = None
    if not args.emit_prompts_only:
        llm = LLMClient(
            LLMConfig(
                provider=args.provider,
                model=args.model,
                base_url=args.base_url,
                api_mode=args.api_mode,
                temperature=args.temperature,
                max_tokens=args.max_tokens,
                timeout=args.llm_timeout,
                reasoning_effort=args.reasoning_effort,
            )
        )
    summary = run_c_to_ir_extraction(
        source_paths=args.source,
        output_dir=args.output_dir,
        llm=llm,
        protocol_name=args.name,
        goals=goals,
        emit_prompts_only=args.emit_prompts_only,
        max_stage_retries=args.max_stage_retries,
        emit_modeling_contract=not args.no_modeling_contract,
        max_prompt_code_chars=args.max_prompt_code_chars,
        max_stages=args.max_stages,
        resume_existing=args.resume_existing,
        rerun_from_stage=args.rerun_from_stage,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


def _load_goals(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict) and isinstance(raw.get("goals"), list):
        return [item for item in raw["goals"] if isinstance(item, dict)]
    raise ValueError("--goals-file must be a JSON list or an object with a goals list.")


if __name__ == "__main__":
    raise SystemExit(main())
