from __future__ import annotations

import re


def build_compile_diagnostics(tamarin_diagnostics: str, lint_issues: list[str], sapic_plus: str = "") -> str:
    parts = []
    if tamarin_diagnostics:
        parts.append(tamarin_diagnostics)
    wellformedness_context = wellformedness_context_from_diagnostics(tamarin_diagnostics, sapic_plus)
    if wellformedness_context:
        parts.append("Wellformedness warning analysis:\n" + wellformedness_context)
    process_context = process_context_from_diagnostics(tamarin_diagnostics, sapic_plus)
    if process_context:
        parts.append("Translated rule/process context:\n" + process_context)
    guardedness_context = guardedness_context_from_diagnostics(tamarin_diagnostics, sapic_plus)
    if guardedness_context:
        parts.append("Formula guardedness analysis:\n" + guardedness_context)
    context = source_context_from_diagnostics(sapic_plus, tamarin_diagnostics)
    if context:
        parts.append("Source context near Tamarin parser locations:\n" + context)
    parser_hint = parser_context_hints(sapic_plus, tamarin_diagnostics)
    if parser_hint:
        parts.append("Parser error analysis:\n" + parser_hint)
    if lint_issues:
        lint_text = "\n".join(f"- {issue}" for issue in lint_issues)
        parts.append(f"Local Sapic+ lint issues:\n{lint_text}")
    return "\n\n".join(parts)


def source_context_from_diagnostics(sapic_plus: str, diagnostics: str, radius: int = 3) -> str:
    if not sapic_plus or not diagnostics:
        return ""
    locations = _extract_locations(diagnostics)
    if not locations:
        return ""
    lines = sapic_plus.splitlines()
    blocks: list[str] = []
    seen: set[tuple[int, int]] = set()
    for line_no, column in locations:
        if (line_no, column) in seen or line_no < 1 or line_no > len(lines):
            continue
        seen.add((line_no, column))
        start = max(1, line_no - radius)
        end = min(len(lines), line_no + radius)
        rendered = [f"location line={line_no} column={column}"]
        for current in range(start, end + 1):
            marker = ">" if current == line_no else " "
            rendered.append(f"{marker} {current:4d} | {lines[current - 1]}")
            if current == line_no and column > 0:
                rendered.append("       | " + " " * max(0, column - 1) + "^")
        blocks.append("\n".join(rendered))
    return "\n\n".join(blocks)


def wellformedness_context_from_diagnostics(diagnostics: str, sapic_plus: str = "") -> str:
    text = diagnostics or ""
    if "Facts occur in the left-hand-side but not in any right-hand-side" not in text:
        return ""
    entries = _extract_lhs_without_rhs_entries(text)
    parts: list[str] = []
    if entries:
        parts.append("Tamarin reports state facts that are consumed but never produced:")
        parts.extend(f"- {entry}" for entry in entries[:8])
    if re.search(r"\bin\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*;\s*\n\s*let\s+<", sapic_plus or ""):
        parts.append(
            "The Sapic+ source receives an untrusted variable and immediately destructures it with `let <...> = msg in`. "
            "When the role should continue only for a known public tuple shape, receive that shape directly, e.g. `in(<tag, peer, payload>);`. "
            "If the message is intentionally opaque, do not parse it before forwarding or storing it."
        )
    if _has_decrypt_then_tuple_destructure(sapic_plus or ""):
        parts.append(
            "The Sapic+ source receives an arbitrary ciphertext and immediately tuple-destructures the decrypted plaintext. "
            "Keep the ciphertext as an input variable, decrypt once, and avoid local tuple patterns that introduce failed branches. "
            "For tuple plaintexts, prefer projection functions such as `fst/snd` plus simple `if` guards over `let <...> = adec(...) in`."
        )
    if re.search(r"\bin\s*\(\s*(?:aenc|senc)\s*\(", sapic_plus or ""):
        parts.append(
            "The Sapic+ source pattern-matches encrypted constructors directly in `in(...)`. "
            "This can make variables non-derivable from the input premise or bind role parameters twice. "
            "Receive an opaque ciphertext variable instead, then decrypt and check fields in the role body."
        )
    if re.search(r"\belse\s+0\b", sapic_plus or ""):
        parts.append(
            "The Sapic+ source contains `else 0` branches. For this parser, nested `if ... then ... else 0` "
            "can translate into unreachable dead-state facts. Prefer omitting the else branch when failure should stop, "
            "or rewrite the check as a successful receive/protected-message pattern before continuing."
        )
    if re.search(r"\blet\s+<[^>\n]*'[^']+'[^>\n]*>\s*=", sapic_plus or ""):
        parts.append(
            "The Sapic+ source destructures messages with quoted literal constants inside `let <...> = ... in` patterns. "
            "This can create implicit failed-match branches that translate into unreachable state facts. Put public tags in the "
            "successful receive/protected constructor shape, or bind fields first and compare against already-bound identifiers "
            "only when direct receiving is impossible."
        )
    if re.search(r"\bif\b[^\n]*\s[&|]\s[^\n]*\bthen\b", sapic_plus or ""):
        parts.append(
            "The Sapic+ source has compound boolean conditions inside `if ... then`. This parser accepts simple guards more reliably; "
            "use pattern matching/equality patterns or nested simple checks instead of `if a = x & b = y then`."
        )
    if re.search(r"\belse\s+event\b", sapic_plus or ""):
        parts.append(
            "Adding events to an else branch usually does not fix the warning; the unreachable branch/state must be removed "
            "or the preceding check must be restructured."
        )
    parts.append(
        "Repair target: rewrite the affected role so every process state consumed by a translated rule is reachable from a successful "
        "receive/parse/check path. Do not change lemmas, add dummy events, add helper restrictions, or add builtins just to silence this warning."
    )
    return "\n".join(parts)


def process_context_from_diagnostics(diagnostics: str, sapic_plus: str = "", radius: int = 2) -> str:
    """Connect generated Tamarin rule names back to Sapic+ process text when possible."""

    if not diagnostics:
        return ""
    rule_names = _referenced_rule_names(diagnostics)
    if not rule_names:
        return ""
    rule_contexts = _extract_rule_process_contexts(diagnostics)
    parts: list[str] = []
    for rule_name in rule_names[:10]:
        context = rule_contexts.get(rule_name)
        if not context:
            continue
        if _is_generic_process_text(str(context.get("process") or "")):
            continue
        line = f"- rule `{rule_name}`"
        if context.get("role"):
            line += f" role={context['role']}"
        if context.get("process"):
            line += f" process=`{context['process']}`"
        parts.append(line)
        source = _source_context_for_process(sapic_plus, str(context.get("process") or ""), radius=radius)
        if source:
            parts.append(source)
    if not parts:
        return ""
    parts.append(
        "Repair target: use the process text above to change the corresponding Sapic+ check/pattern/event, not an unrelated lemma."
    )
    return "\n".join(parts)


def guardedness_context_from_diagnostics(diagnostics: str, sapic_plus: str = "", radius: int = 3) -> str:
    if not diagnostics:
        return ""
    lemma_names = []
    for match in re.finditer(r"Lemma\s+`([^`]+)'\s+cannot be converted to a guarded formula", diagnostics):
        lemma_names.append(match.group(1))
    if not lemma_names and "Formula guardedness" not in diagnostics:
        return ""
    parts = []
    if lemma_names:
        parts.append("Tamarin rejected guardedness for lemma(s): " + ", ".join(dict.fromkeys(lemma_names)))
    else:
        parts.append("Tamarin reported a Formula guardedness warning.")
    for lemma_name in dict.fromkeys(lemma_names):
        context = _source_context_for_lemma(sapic_plus, lemma_name, radius=radius)
        if context:
            parts.append(context)
    parts.append(
        "Repair target: rewrite the lemma formula into Tamarin guarded form. For source/AUTO_typing lemmas, use separate top-level conjuncts such as `(All ... IN_M1(...) @ #i ==> ...) & (All ... IN_M2(...) @ #i ==> ...)` rather than one universal quantifier wrapping many implications."
    )
    return "\n".join(parts)


def parser_context_hints(sapic_plus: str, diagnostics: str) -> str:
    if not sapic_plus or not diagnostics:
        return ""
    locations = _extract_locations(diagnostics)
    if not locations:
        return ""
    lines = sapic_plus.splitlines()
    hints: list[str] = []
    for line_no, column in locations[:4]:
        if line_no < 1 or line_no > len(lines):
            continue
        line = _strip_line_comment(lines[line_no - 1]).strip()
        if re.match(r"^builtins\s*:", line, flags=re.IGNORECASE) and "pairing" in line.lower():
            hints.append(
                f"Line {line_no}: remove `pairing` from `builtins:` for ordinary tuples; tuple syntax does not require a pairing builtin."
            )
        if re.match(r"^let\s+\w+\s*\(.*\)\s*=", line) and re.search(r"\([^)]*,[^)]*\)", line):
            hints.append(
                f"Line {line_no}: role parameter lists must be flat identifiers; replace tuple parameters with flat parameters and build tuples inside the role body if needed."
            )
        if re.search(r"\bif\b.*=\s*<[^>\n]+>\s*then\b", line):
            hints.append(
                f"Line {line_no}: `if term = <pattern> then` does not bind new fields. Use `let decoded = term in` followed by a `let <...> = decoded in` pattern with `=expected` equality markers."
            )
        if (
            re.match(r"^in\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*;", line)
            and line_no < len(lines)
            and re.search(r"^\s*let\s+<", _strip_line_comment(lines[line_no]).strip())
        ):
            hints.append(
                f"Line {line_no}: avoid `in(msg); let <...> = msg in` for known public tuple messages; receive the tuple shape directly with `in(<...>);` when the role should continue only on that shape."
            )
        if re.match(r"^in\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*;", line) and _decrypt_context_tuple_destructures(lines, line_no):
            hints.append(
                f"Line {line_no}: received ciphertext is decrypted and immediately tuple-destructured; avoid tuple patterns that introduce failed branches, or use projection functions plus simple checks when needed."
            )
        if re.match(r"^in\s*\(\s*(?:aenc|senc)\s*\(", line):
            hints.append(
                f"Line {line_no}: do not pattern-match encrypted constructors directly in `in(...)`; receive a ciphertext variable, then decrypt and check fields inside the role."
            )
        if re.match(r"^in\s*\(\s*<[^>\n]*=", line):
            hints.append(
                f"Line {line_no}: do not use equality subpatterns inside `in(<...>)`; receive fresh fields and compare them inside the role body."
            )
        if re.match(r"^let\s+", line) and line.endswith(";"):
            hints.append(
                f"Line {line_no}: local Sapic+ `let` bindings and pattern matches must continue with `in`, not `;`."
            )
        if re.search(r"\blet\s*=\s*<", line):
            hints.append(
                f"Line {line_no}: do not put a whole tuple after `let =`. Destructure the received term first, then compare individual fields against bound expected variables."
            )
        if re.search(r"\blet\s*=\s*'[^']+'\s*=", line):
            hints.append(
                f"Line {line_no}: bind the quoted constant to a variable before using an equality pattern; write `let expected = 'TAG' in let =expected = tag in`."
            )
        if re.search(r"\blet\s*=\s*(?:true|false)\s*=", line):
            hints.append(
                f"Line {line_no}: boolean constants are not valid equality-pattern binders; use `if condition = true then (...)`."
            )
        if re.search(r"\blet\s+<[^>\n]*=\s*'[^']+'", line):
            hints.append(
                f"Line {line_no}: quoted constants cannot be equality subpatterns directly; bind the expected constant first and use `=expected` in the tuple pattern."
            )
        if re.match(r"^(?:verify|sdec|adec|h|mac|hmac|kdf)\s*\([^;\n]*\)\s*=\s*true\s*;", line, flags=re.IGNORECASE):
            hints.append(
                f"Line {line_no}: boolean checks cannot be standalone statements; use `if ... = true then ...` or a `let =expected = actual in` guard."
            )
    return "\n".join(dict.fromkeys(hints))


def _extract_locations(diagnostics: str) -> list[tuple[int, int]]:
    locations: list[tuple[int, int]] = []
    for match in re.finditer(r"\(line\s+(\d+),\s*column\s+(\d+)\)", diagnostics or "", flags=re.IGNORECASE):
        locations.append((int(match.group(1)), int(match.group(2))))
    return locations


def _extract_lhs_without_rhs_entries(diagnostics: str) -> list[str]:
    entries: list[str] = []
    for match in re.finditer(
        r"^\s*\d+\.\s+in rule\s+\"[^\"]+\":\s+factName\s+`[^`]+'.*$",
        diagnostics or "",
        flags=re.MULTILINE,
    ):
        entries.append(match.group(0).strip())
    return entries


def _referenced_rule_names(diagnostics: str) -> list[str]:
    names: list[str] = []
    for pattern in (
        r'in rule "([^"]+)"',
        r'Perhaps you want to use the fact in rule "([^"]+)"',
        r'from rule ([A-Za-z0-9_]+)',
    ):
        for match in re.finditer(pattern, diagnostics or ""):
            name = match.group(1).strip()
            if name and name not in names:
                names.append(name)
    return names


def _extract_rule_process_contexts(diagnostics: str) -> dict[str, dict[str, str]]:
    contexts: dict[str, dict[str, str]] = {}
    pattern = re.compile(
        r'rule\s+\(modulo\s+[^)]*\)\s+([A-Za-z0-9_]+)\s*\[(.*?)(?=\nrule\s+\(modulo|\nrestriction\b|\nlemma\b|\n/\*|\Z)',
        flags=re.DOTALL,
    )
    for match in pattern.finditer(diagnostics or ""):
        rule_name = match.group(1)
        block = match.group(2)
        process_match = re.search(r'process="((?:\\"|[^"])*)"', block, flags=re.DOTALL)
        role_match = re.search(r"role='([^']*)'", block)
        contexts[rule_name] = {
            "process": _compact_text(process_match.group(1).replace('\\"', '"')) if process_match else "",
            "role": role_match.group(1) if role_match else "",
        }
    return contexts


def _source_context_for_process(sapic_plus: str, process_text: str, radius: int = 2) -> str:
    if not sapic_plus or not process_text:
        return ""
    lines = sapic_plus.splitlines()
    candidate_indices = _candidate_source_lines_for_process(lines, process_text)
    if not candidate_indices:
        return ""
    rendered = ["  likely Sapic+ source context:"]
    seen: set[int] = set()
    for index in candidate_indices[:3]:
        if index in seen:
            continue
        seen.add(index)
        start = max(1, index + 1 - radius)
        end = min(len(lines), index + 1 + radius)
        for current in range(start, end + 1):
            marker = ">" if current == index + 1 else " "
            rendered.append(f"  {marker} {current:4d} | {lines[current - 1]}")
    return "\n".join(rendered)


def _candidate_source_lines_for_process(lines: list[str], process_text: str) -> list[int]:
    normalized_process = _normalize_process_text(process_text)
    if not normalized_process:
        return []
    scored: list[tuple[int, int]] = []
    process_kind = _process_kind(process_text)
    process_tokens = _semantic_tokens(process_text)
    for index, raw_line in enumerate(lines):
        source = _strip_line_comment(raw_line).strip()
        if not source:
            continue
        normalized_source = _normalize_process_text(source)
        score = 0
        if len(normalized_process) >= 4 and normalized_process in normalized_source:
            score += 8
        if len(normalized_source) >= 4 and normalized_source in normalized_process:
            score += 5
        if process_kind and source.lower().startswith(process_kind):
            score += 3
        source_tokens = _semantic_tokens(source)
        score += len(process_tokens.intersection(source_tokens))
        if score >= 4:
            scored.append((score, index))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [index for _, index in scored]


def _source_context_for_lemma(sapic_plus: str, lemma_name: str, radius: int = 3) -> str:
    if not sapic_plus or not lemma_name:
        return ""
    lines = sapic_plus.splitlines()
    for index, raw_line in enumerate(lines):
        if re.match(rf"\s*lemma\s+{re.escape(lemma_name)}\b", raw_line):
            start = max(1, index + 1 - radius)
            end = min(len(lines), index + 1 + 12)
            rendered = [f"source context for lemma `{lemma_name}`:"]
            for current in range(start, end + 1):
                marker = ">" if current == index + 1 else " "
                rendered.append(f"{marker} {current:4d} | {lines[current - 1]}")
            return "\n".join(rendered)
    return ""


def _process_kind(process_text: str) -> str:
    lowered = (process_text or "").strip().lower()
    for kind in ("let ", "if ", "event ", "out(", "in("):
        if lowered.startswith(kind):
            return kind.strip()
    return ""


def _is_generic_process_text(process_text: str) -> bool:
    return _compact_text(process_text) in {"0", "|", "!", "(", ")"}


def _semantic_tokens(text: str) -> set[str]:
    ignored = {"let", "if", "then", "else", "in", "out", "event", "true", "false"}
    return {
        token.lower()
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text or "")
        if len(token) > 1 and token.lower() not in ignored
    }


def _normalize_process_text(text: str) -> str:
    compact = _compact_text(text)
    compact = re.sub(r"\.[0-9]+\b", "", compact)
    compact = re.sub(r"\s+", "", compact)
    return compact.lower()


def _compact_text(text: str) -> str:
    return " ".join((text or "").split())


def _strip_line_comment(line: str) -> str:
    if "//" in line:
        return line.split("//", 1)[0]
    return line


def _has_decrypt_then_tuple_destructure(sapic_plus: str) -> bool:
    lines = (sapic_plus or "").splitlines()
    for index, raw_line in enumerate(lines):
        line = _strip_line_comment(raw_line).strip()
        if not re.match(r"^in\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*;", line):
            continue
        if _decrypt_context_tuple_destructures(lines, index + 1):
            return True
    return False


def _decrypt_context_tuple_destructures(lines: list[str], line_no: int) -> bool:
    if line_no < 1 or line_no >= len(lines):
        return False
    next_line = _strip_line_comment(lines[line_no]).strip()
    if re.match(r"^let\s+<[^>\n]+>\s*=\s*(?:sdec|adec)\s*\(", next_line):
        return True
    match = re.match(r"^let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:sdec|adec)\s*\(", next_line)
    if not match or line_no + 1 >= len(lines):
        return False
    decrypted_name = match.group(1)
    following = _strip_line_comment(lines[line_no + 1]).strip()
    return bool(re.match(rf"^let\s+<[^>\n]+>\s*=\s*{re.escape(decrypted_name)}\b", following))
