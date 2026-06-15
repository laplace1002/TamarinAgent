from __future__ import annotations

import re
from dataclasses import dataclass, field

from .proofspec import PROVED_SATISFYING, ProofSpec


RESERVED_FACTS = {
    "K",
    "KU",
    "KD",
    "Fr",
    "In",
    "Out",
    "Eq",
    "OnlyOnce",
    "LessThan",
    "All",
    "Ex",
    "not",
    "F",
}
SOURCE_HELPER_GOAL_TYPES = {"source", "typing"}


@dataclass
class ProofLintResult:
    ok: bool
    issues: list[str] = field(default_factory=list)


def proof_lint(sapic_plus: str, proof_spec: ProofSpec) -> ProofLintResult:
    issues: list[str] = []
    text = sapic_plus or ""
    lemma_bodies = extract_lemma_bodies(text)
    event_arities = extract_event_arities(text)
    proof_events = extract_event_calls(text)
    issues.extend(_proof_event_payload_issues(proof_events))
    issues.extend(_proof_event_schema_issues(lemma_bodies))

    for expectation in proof_spec.expectations:
        body = lemma_bodies.get(expectation.name)
        if body is None:
            issues.append(f"Target lemma `{expectation.name}` is missing.")
            continue
        if expectation.goal_type not in SOURCE_HELPER_GOAL_TYPES and _has_sources_attribute(text, expectation.name):
            issues.append(
                f"Lemma `{expectation.name}` is goal_type={expectation.goal_type}; only source/typing helper lemmas may use the `[sources]` attribute."
            )
        referenced_facts = extract_action_facts(body)
        non_reserved = [fact for fact in referenced_facts if fact not in RESERVED_FACTS]
        if expectation.trace_kind == "exists-trace" and "exists-trace" not in body:
            issues.append(f"Lemma `{expectation.name}` is expected to be exists-trace but does not contain an `exists-trace` body line.")
        if expectation.goal_type in SOURCE_HELPER_GOAL_TYPES and not _looks_like_source_lemma(body):
            issues.append(
                f"Lemma `{expectation.name}` is a source/typing helper but does not relate protocol input events to output events or adversary knowledge; avoid vacuous `AUTO_typing` lemmas."
            )
        if expectation.expected_state == PROVED_SATISFYING and not non_reserved and expectation.goal_type not in SOURCE_HELPER_GOAL_TYPES:
            issues.append(
                f"Lemma `{expectation.name}` does not reference any protocol event/action fact; it may be vacuous."
            )
        if expectation.goal_type == "secrecy" and re.search(r"\bIn\s*\([^)]*\)\s*@", body):
            issues.append(
                f"Lemma `{expectation.name}` uses process input fact `In(...)` as a secrecy condition; use adversary knowledge `K(secret) @ #i` plus honest/reveal guards."
            )
        if expectation.goal_type == "authentication" and "injective" in expectation.name.lower():
            correspondence_facts = [
                fact
                for fact in non_reserved
                if fact.startswith("Running") or fact.startswith("Server")
            ]
            commit_facts = [fact for fact in non_reserved if fact.startswith("Commit")]
            if commit_facts and not correspondence_facts:
                issues.append(
                    f"Lemma `{expectation.name}` is an injective authentication target but only reasons about Commit facts; include the reviewed Running/Server correspondence evidence plus uniqueness."
                )
        if re.search(r"==>\s*(True|true)\b", body):
            issues.append(
                f"Lemma `{expectation.name}` has a vacuous `==> True/true` conclusion; preserve a meaningful proof obligation."
            )
        for fact in non_reserved:
            if fact not in event_arities:
                issues.append(
                    f"Lemma `{expectation.name}` references action fact `{fact}`, but no matching `event {fact}(...)` appears in the generated process."
                )
                continue
            for arity in referenced_facts[fact]:
                if arity not in event_arities[fact]:
                    issues.append(
                        f"Lemma `{expectation.name}` references `{fact}` with arity {arity}, but generated events use arity {sorted(event_arities[fact])}."
                    )

    return ProofLintResult(ok=not issues, issues=issues)


def _looks_like_source_lemma(body: str) -> bool:
    text = body or ""
    if re.search(r"==>\s*(True|true)\b", text):
        return False
    has_input_event = bool(re.search(r"\b(IN|In)_[A-Za-z0-9_]*\s*\(", text) or re.search(r"\bIN_[A-Za-z0-9_]*\s*\(", text))
    has_source = bool(re.search(r"\b(OUT|Out)_[A-Za-z0-9_]*\s*\(", text) or re.search(r"\b(K|KU)\s*\(", text))
    return has_input_event and has_source


def _has_sources_attribute(sapic_plus: str, lemma_name: str) -> bool:
    pattern = rf"(?m)^\s*lemma\s+{re.escape(lemma_name)}\s*\[[^]]*\bsources\b[^]]*\]\s*:"
    return bool(re.search(pattern, sapic_plus or ""))


def extract_lemma_bodies(sapic_plus: str) -> dict[str, str]:
    bodies: dict[str, str] = {}
    matches = list(re.finditer(r"(?m)^\s*lemma\s+([A-Za-z_][A-Za-z0-9_]*)\b[^\n]*:", sapic_plus or ""))
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else _theory_end_index(sapic_plus)
        bodies[match.group(1)] = sapic_plus[start:end]
    return bodies


def extract_event_arities(sapic_plus: str) -> dict[str, set[int]]:
    arities: dict[str, set[int]] = {}
    for name, args in extract_event_calls(sapic_plus):
        arity = _count_args(args)
        arities.setdefault(name, set()).add(arity)
    return arities


def extract_event_calls(sapic_plus: str) -> list[tuple[str, str]]:
    return _extract_fact_calls(sapic_plus or "", prefix_pattern=r"\bevent\s+")


def extract_action_facts(lemma_body: str) -> dict[str, set[int]]:
    facts: dict[str, set[int]] = {}
    for name, args in _extract_fact_calls(lemma_body or "", suffix_pattern=r"\s*@"):
        facts.setdefault(name, set()).add(_count_args(args))
    return facts


def _extract_fact_calls(text: str, *, prefix_pattern: str = r"\b", suffix_pattern: str = "") -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []
    pattern = re.compile(prefix_pattern + r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for match in pattern.finditer(text or ""):
        close = _matching_paren_index(text, match.end() - 1)
        if close is None:
            continue
        if suffix_pattern and not re.match(suffix_pattern, text[close + 1 :]):
            continue
        calls.append((match.group(1), text[match.end() : close]))
    return calls


def _matching_paren_index(text: str, open_index: int) -> int | None:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _count_args(value: str) -> int:
    text = (value or "").strip()
    if not text:
        return 0
    depth = 0
    count = 1
    for char in text:
        if char in "(<[":
            depth += 1
        elif char in ")>]":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            count += 1
    return count


def _theory_end_index(sapic_plus: str) -> int:
    match = re.search(r"(?m)^\s*end\s*$", sapic_plus or "")
    return match.start() if match else len(sapic_plus or "")


PROOF_EVENT_PREFIXES = ("Secret", "Running", "Commit")
DERIVED_EVENT_TERM_RE = re.compile(r"\b(fst|snd|sdec|adec|hkdf|hmac|hash|verify)\s*\(")


def _proof_event_payload_issues(event_calls: list[tuple[str, str]]) -> list[str]:
    issues: list[str] = []
    for name, args in event_calls:
        if not name.startswith(PROOF_EVENT_PREFIXES):
            continue
        if DERIVED_EVENT_TERM_RE.search(args):
            issues.append(
                f"Proof event `{name}` carries selector/destructor/derived terms; emit compact bound variables or a stable session identifier instead."
            )
    return sorted(set(issues))


def _proof_event_schema_issues(lemma_bodies: dict[str, str]) -> list[str]:
    issues: list[str] = []
    for lemma_name, body in sorted(lemma_bodies.items()):
        calls = [
            (name, args)
            for name, args in _extract_fact_calls(body or "", suffix_pattern=r"\s*@")
            if name.startswith(("Running", "Commit"))
        ]
        if not calls:
            continue
        running = {
            _normalize_term_shape(parts[2])
            for name, args in calls
            if name.startswith("Running") and len((parts := _split_args(args))) >= 3
        }
        commit = {
            _normalize_term_shape(parts[2])
            for name, args in calls
            if name.startswith("Commit") and len((parts := _split_args(args))) >= 3
        }
        if running and commit and running != commit:
            issues.append(
                f"Lemma `{lemma_name}` compares Running/Commit facts with inconsistent session payload shapes; keep the same nonce/key representation within each target direction."
            )
    return issues


def _split_args(args: str) -> list[str]:
    text = (args or "").strip()
    if not text:
        return []
    parts: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(text):
        if char in "(<[":
            depth += 1
        elif char in ")>]":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    parts.append(text[start:].strip())
    return parts


def _normalize_term_shape(term: str) -> str:
    text = re.sub(r"\s+", "", term or "")
    pieces: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "'":
            end = index + 1
            while end < len(text) and text[end] != "'":
                end += 1
            if end < len(text):
                end += 1
            pieces.append(text[index:end])
            index = end
            continue
        if char == "~" or char.isalpha() or char == "_":
            start = index
            if char == "~":
                index += 1
            if index < len(text) and (text[index].isalpha() or text[index] == "_"):
                index += 1
                while index < len(text) and (text[index].isalnum() or text[index] == "_"):
                    index += 1
                token = text[start:index]
                if index < len(text) and text[index] == "(" and not token.startswith("~"):
                    pieces.append(token)
                else:
                    pieces.append("VAR")
                continue
            index = start + 1
            pieces.append(char)
            continue
        pieces.append(char)
        index += 1
    return "".join(pieces)
