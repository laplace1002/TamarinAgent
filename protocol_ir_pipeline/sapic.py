from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from time import perf_counter

from .proofspec import ProofSpec, evaluate_lemma_matches


@dataclass
class VerificationResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    command: list[str]
    output_path: Path
    warnings: list[str]
    elapsed_sec: float = 0.0

    @property
    def diagnostics(self) -> str:
        warning_text = "\n".join(f"- {warning}" for warning in self.warnings)
        return "\n".join(
            part
            for part in [
                self.stdout,
                self.stderr,
                f"Detected Tamarin warnings:\n{warning_text}" if warning_text else "",
            ]
            if part
        ).strip()

    @property
    def returncode_ok(self) -> bool:
        return self.returncode == 0

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    @property
    def status(self) -> str:
        if self.returncode != 0:
            return "failed"
        if self.warnings:
            return "warnings"
        return "clean"


@dataclass
class LemmaCoverageResult:
    expected: list[str]
    present: list[str]
    missing: list[str]
    extra: list[str]

    @property
    def ok(self) -> bool:
        return not self.missing


@dataclass
class ProofResult:
    ok: bool
    status: str
    returncode: int
    stdout: str
    stderr: str
    command: list[str]
    output_path: Path
    warnings: list[str]
    elapsed_sec: float = 0.0
    lemma_results: dict[str, str] = field(default_factory=dict)
    missing_results: list[str] = field(default_factory=list)
    lemma_actual_states: dict[str, str] = field(default_factory=dict)
    lemma_expected_states: dict[str, str] = field(default_factory=dict)
    lemma_matches: dict[str, bool] = field(default_factory=dict)
    mismatched_results: list[str] = field(default_factory=list)
    per_lemma: dict[str, dict[str, object]] = field(default_factory=dict)

    @property
    def diagnostics(self) -> str:
        return "\n".join(part for part in [self.stdout, self.stderr] if part).strip()


def extract_sapic(value: str) -> str:
    text = (value or "").strip()
    if text.startswith("```"):
        text = _strip_fence(text)
    match = re.search(r"\btheory\b[\s\S]*?\bend\b", text)
    if match:
        return match.group(0).strip() + "\n"
    return text + ("\n" if text and not text.endswith("\n") else "")


def basic_sapic_lint(sapic_plus: str) -> list[str]:
    issues: list[str] = []
    text = sapic_plus or ""
    if not re.search(r"\btheory\s+\w+", text):
        issues.append("Missing `theory <Name>` header.")
    if "begin" not in text:
        issues.append("Missing `begin`.")
    if not re.search(r"\bprocess\s*:", text):
        issues.append("Missing `process:` block.")
    if not _has_trailing_end(text):
        issues.append("Missing trailing `end`.")
    if text.count("begin") > text.count("end") + 1:
        issues.append("Unbalanced begin/end markers look suspicious.")
    issues.extend(pseudo_sapic_lint(text))
    return issues


def target_lemma_lint(sapic_plus: str, expected_lemmas: list[str]) -> list[str]:
    if not expected_lemmas:
        return []
    coverage = lemma_coverage(sapic_plus, expected_lemmas)
    issues: list[str] = []
    for missing in coverage.missing:
        split_matches = [
            present
            for present in coverage.present
            if present.startswith(f"{missing}_") or present.startswith(f"{missing}__")
        ]
        if split_matches:
            issues.append(
                f"Target lemma `{missing}` is missing but appears to have been split/renamed as {split_matches}. Keep the exact target lemma name `{missing}` and put any per-message/source obligations inside that lemma formula."
            )
        else:
            issues.append(f"Target lemma `{missing}` is missing; keep all requested lemma names exactly.")
    return issues


def semantic_constraint_lint(sapic_plus: str, semantic_constraints: list[dict[str, object]] | None) -> list[str]:
    constraints = [item for item in (semantic_constraints or []) if isinstance(item, dict)]
    if not constraints:
        return []
    issues: list[str] = []
    text = sapic_plus or ""
    trusted_setup_constraints = [
        item
        for item in constraints
        if str(item.get("kind") or "") == "trust_boundary"
    ]
    if trusted_setup_constraints and _uses_public_function_as_setup_key(text):
        issues.append(
            "Semantic constraint violation: resolved open-question answers identify setup/state/private key material or trusted identity bindings, but the model uses a public function term such as `ltk(id)` as the key source. Use fresh private setup, role parameters, or persistent private state/facts instead."
        )
    if trusted_setup_constraints:
        for name in _trusted_private_value_names(trusted_setup_constraints):
            if name and _is_output_on_public_channel(text, name):
                issues.append(
                    f"Semantic constraint violation: trusted setup/private value `{name}` is output on the public channel without an explicit reveal/compromise policy."
                )
    return issues


def extract_lemma_names(sapic_plus: str) -> list[str]:
    names: list[str] = []
    for match in re.finditer(r"(?m)^\s*lemma\s+([A-Za-z_][A-Za-z0-9_]*)\b", sapic_plus or ""):
        names.append(match.group(1))
    return names


@lru_cache(maxsize=1)
def tamarin_supported_builtins() -> set[str]:
    config_path = os.getenv("TAMARIN_BUILTINS_FILE")
    path = Path(config_path) if config_path else Path(__file__).resolve().parents[1] / "config" / "tamarin_builtins.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {}
    builtins = payload.get("builtins") if isinstance(payload, dict) else None
    if not isinstance(builtins, list):
        return set()
    return {str(item).strip().lower() for item in builtins if str(item).strip()}


def _declares_builtin(lines: list[str], builtin: str) -> bool:
    wanted = builtin.strip().lower()
    for raw_line in lines:
        line = _strip_line_comment(raw_line).strip()
        if not re.match(r"^builtins\s*:", line, flags=re.IGNORECASE):
            continue
        items = [item.strip().lower() for item in line.split(":", 1)[1].split(",") if item.strip()]
        if wanted in items:
            return True
    return False


def lemma_coverage(sapic_plus: str, expected_lemmas: list[str]) -> LemmaCoverageResult:
    expected = _dedupe(expected_lemmas)
    present = _dedupe(extract_lemma_names(sapic_plus))
    missing = [name for name in expected if name not in present]
    extra = [name for name in present if name not in expected]
    return LemmaCoverageResult(expected=expected, present=present, missing=missing, extra=extra)


def pseudo_sapic_lint(sapic_plus: str) -> list[str]:
    """Catch common non-Sapic+ constructs before invoking Tamarin."""

    issues: list[str] = []
    lines = (sapic_plus or "").splitlines()
    bound_names: set[str] = set()
    process_seen = False
    role_body_seen = False
    process_body_seen = False
    bare_role_macros: set[str] = set()
    decrypted_bindings: dict[str, int] = {}
    for lineno, raw_line in enumerate(lines, start=1):
        line = _strip_line_comment(raw_line).strip()
        if not line:
            continue
        if re.match(r"^process\s*:", line):
            process_seen = True
            process_body_seen = True
            role_body_seen = False
            decrypted_bindings = {}
        elif re.match(r"^let\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\([^)]*\))?\s*=", line):
            role_body_seen = True
            bound_names = _role_decl_params(line)
            decrypted_bindings = {}
        elif re.match(r"^(lemma|restriction|axiom)\b", line):
            role_body_seen = False
            process_body_seen = False
            bound_names = set()
            decrypted_bindings = {}
        if role_body_seen or process_body_seen:
            for name in _fresh_decl_names(line):
                bound_names.add(name)
            bound_names.update(_local_let_bound_names(line))
            reused = _input_tuple_reuses_bound_names(line, bound_names)
            if reused:
                issues.append(
                    f"Line {lineno}: input tuple pattern reuses already-bound name(s) {', '.join(sorted(reused))}; receive fresh `*_recv` fields and compare them inside the role body to avoid `Variable bound twice` warnings."
                )
            direct_destructure = _line_directly_tuple_destructures_decryptor(line)
            decrypted_name = _line_decrypts_to_identifier(line)
            destructured_decrypted = _tuple_destructure_source_identifier(line)
            if direct_destructure:
                issues.append(
                    f"Line {lineno}: decrypted plaintext is tuple-destructured directly; this can create unreachable failed-parse states. Decrypt once into a variable, then use projection functions plus simple checks when needed."
                )
            elif destructured_decrypted and destructured_decrypted in decrypted_bindings:
                issues.append(
                    f"Line {lineno}: plaintext decrypted on line {decrypted_bindings[destructured_decrypted]} is tuple-destructured; this can create unreachable failed-parse states. Prefer projection functions plus simple checks for decrypted adversary-controlled messages."
                )
            if decrypted_name:
                decrypted_bindings[decrypted_name] = lineno
        if re.match(r"^builtins\s*:", line, flags=re.IGNORECASE):
            builtin_body = line.split(":", 1)[1]
            if "," not in builtin_body and len(builtin_body.split()) > 1:
                issues.append(
                    f"Line {lineno}: multiple builtins must be comma-separated, e.g. `builtins: hashing, asymmetric-encryption`."
                )
            builtin_items = [
                item.strip().lower()
                for item in builtin_body.split(",")
                if item.strip()
            ]
            supported_builtins = tamarin_supported_builtins()
            unsupported = [
                item
                for item in builtin_items
                if item not in supported_builtins and not item.startswith("{*")
            ]
            if unsupported:
                issues.append(
                    f"Line {lineno}: builtin(s) not listed in the configured Tamarin builtin set: {', '.join(unsupported)}. If this Tamarin version supports them, update AutoSM-style/config/tamarin_builtins.json or set TAMARIN_BUILTINS_FILE; protocol-specific operations such as mac/hmac/kdf usually belong under `functions:`."
                )
            if "pairing" in builtin_items:
                issues.append(
                    f"Line {lineno}: `pairing` is not a valid builtin in this Sapic+ parser; remove it for ordinary tuples/pairs, or use a supported pairing builtin only if the protocol explicitly needs one."
                )
        if re.match(r"^builtins\s*:\s*pairing\b", line, flags=re.IGNORECASE):
            issues.append(
                f"Line {lineno}: `builtins: pairing` is invalid; use a Tamarin builtin such as `bilinear-pairing` only when needed."
            )
        if re.match(r"^equations\s*:\s*$", line, flags=re.IGNORECASE):
            issues.append(f"Line {lineno}: empty `equations:` declaration is invalid; remove it.")
        if re.match(r"^equtions\s*:", line, flags=re.IGNORECASE):
            issues.append(f"Line {lineno}: misspelled `equtions:` declaration; use `equations:` or remove it.")
        if re.match(r"^functions\s*:", line, flags=re.IGNORECASE):
            bad_symbols = []
            if re.search(r"(?<![A-Za-z0-9_])\+/2(?![A-Za-z0-9_])", line):
                bad_symbols.append("+/2")
            if re.search(r"(?<![A-Za-z0-9_])\*/2(?![A-Za-z0-9_])", line):
                bad_symbols.append("*/2")
            if re.search(r"(?<![A-Za-z0-9_])g/0(?![A-Za-z0-9_])", line):
                bad_symbols.append("g/0")
            if re.search(r"(?<![A-Za-z0-9_])pk/1(?![A-Za-z0-9_])", line) and _declares_builtin(lines, "asymmetric-encryption"):
                bad_symbols.append("pk/1")
            if re.search(r"(?<![A-Za-z0-9_])h/1(?![A-Za-z0-9_])", line) and _declares_builtin(lines, "hashing"):
                bad_symbols.append("h/1")
            if bad_symbols:
                issues.append(
                    f"Line {lineno}: do not redeclare builtin/operator symbols {', '.join(bad_symbols)}. With builtins such as hashing, asymmetric-encryption, or diffie-hellman, use the provided symbols directly instead of listing them under `functions:`."
                )
        if re.search(r"\baenc\s*\{", line) or re.search(r"\badec\s*\{", line):
            issues.append(
                f"Line {lineno}: brace encryption/destructor syntax is not accepted by this Sapic+ parser; use function-style terms such as `aenc(m, pk)` and `adec(c, sk)` with suitable equations/destructor declarations."
            )
        if re.search(r"\}\s*_[A-Za-z_~'$]", line):
            issues.append(
                f"Line {lineno}: subscript encryption notation like `{{m}}_k` is not accepted; use explicit function application `aenc(m, k)`."
            )
        bare_let_match = re.match(r"^let\s+([A-Z][A-Za-z0-9_]*)\s*=\s*$", line)
        if bare_let_match:
            role = bare_let_match.group(1)
            bare_role_macros.add(role)
            issues.append(
                f"Line {lineno}: zero-argument role macro `{role}` must be declared as `let {role}() =`, not `let {role} =`."
            )
        if re.match(r"^(public|const|constants)\b", line, flags=re.IGNORECASE):
            issues.append(
                f"Line {lineno}: top-level public/constant declarations are not part of the supported Sapic+ subset; use quoted constants like `'A'` in terms."
            )
        if not process_seen and not role_body_seen and re.match(r"^event\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", line):
            issues.append(
                f"Line {lineno}: top-level event declarations are invalid; emit events inside processes with `event Fact(args);`."
            )
        if re.match(r"^let\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*:[^)]*\)\s*=", line):
            issues.append(
                f"Line {lineno}: typed role parameters are outside the supported subset; prefer `let Role(x) = ...`."
            )
        role_decl_match = re.match(r"^let\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*=", line)
        if role_decl_match and re.search(r"\([^)]*,[^)]*\)", role_decl_match.group(2)):
            issues.append(
                f"Line {lineno}: tuple/pair patterns inside role parameters are not in the stable Sapic+ subset; pass flat parameters such as `id1, pk1, id2, pk2` and destructure only inside the role body."
            )
        if re.match(r"^let\s+", line) and not role_decl_match and line.endswith(";"):
            issues.append(
                f"Line {lineno}: local Sapic+ `let` bindings and pattern matches must end with `in`, not `;`."
            )
        if _line_receives_plain_variable(line) and lineno < len(lines):
            next_line = _strip_line_comment(lines[lineno]).strip()
            if re.match(r"^let\s+<", next_line):
                issues.append(
                    f"Line {lineno}: `in(msg); let <...> = msg in` is fragile for known public tuple messages and can create unreachable failed-parse states; receive the tuple shape directly with `in(<...>);` when the role should continue only on that shape."
                )
            decrypted_name = _line_decrypts_to_identifier(next_line)
            if _line_directly_tuple_destructures_decryptor(next_line) or (
                decrypted_name
                and lineno + 1 < len(lines)
                and _line_tuple_destructures_identifier(
                    _strip_line_comment(lines[lineno + 1]).strip(),
                    decrypted_name,
                )
            ):
                issues.append(
                    f"Line {lineno}: received ciphertext is decrypted and immediately tuple-destructured; this can create failed-parse states. Keep the ciphertext variable, decrypt once, then use projection functions plus simple checks when needed."
                )
        if re.match(r"^in\s*\(\s*(?:aenc|senc)\s*\(", line):
            issues.append(
                f"Line {lineno}: do not pattern-match encrypted constructors directly in `in(...)`; receive a ciphertext variable, then decrypt and check fields inside the role body to avoid non-derivable variables or repeated role-parameter binding."
            )
        if re.search(r"^in\s*\(\s*<[^>\n]*=", line):
            issues.append(
                f"Line {lineno}: input tuple patterns cannot use equality subpatterns such as `<='TAG', ...>` or `<=expected`; receive fresh fields and compare them inside the role body."
            )
        if re.search(r"\blet\s+<[^>\n]*'[^']+'[^>\n]*>\s*=", line):
            issues.append(
                f"Line {lineno}: quoted constants inside tuple destructuring patterns can create unreachable failed-match branches; prefer role parameters and equality patterns such as `let <=expected, payload> = term in`."
            )
        if re.search(r"\blet\s+<[^>\n]*=\s*'[^']+'", line):
            issues.append(
                f"Line {lineno}: quoted constants cannot be used directly as equality subpatterns. Bind the expected constant first, then use a variable equality pattern such as `let <=expected_tag, payload> = term in`."
            )
        if re.search(r"\blet\s*=\s*<", line):
            issues.append(
                f"Line {lineno}: Sapic+ equality patterns cannot compare a whole tuple term on the left side, e.g. `let =<tag, x> = msg in`. Destructure first, then compare fields against bound expected variables."
            )
        if re.search(r"\blet\s*=\s*'[^']+'\s*=", line):
            issues.append(
                f"Line {lineno}: Sapic+ equality patterns should compare against a bound identifier, not a quoted constant directly. Bind the expected constant first, then use `let =expected = actual in`."
            )
        if re.search(r"\blet\s*=\s*(?:true|false)\s*=", line):
            issues.append(
                f"Line {lineno}: Sapic+ equality patterns cannot check boolean constants such as `true`/`false`; use `if condition = true then (...)` for boolean checks."
            )
        if re.search(r"\blet\s*=\s*[A-Za-z_][A-Za-z0-9_]*\s*\(", line):
            issues.append(
                f"Line {lineno}: Sapic+ equality patterns cannot call functions on the left side, e.g. `let =h(x) = y in`. Bind or compute the expected term first, then compare using a variable equality pattern such as `let expected = h(x) in let =expected = y in`."
            )
        if re.match(r"^(?:verify|sdec|adec|h|mac|hmac|kdf)\s*\([^;\n]*\)\s*=\s*true\s*;", line, flags=re.IGNORECASE):
            issues.append(
                f"Line {lineno}: boolean checks cannot be standalone process statements; use `if ... = true then ...` or bind the expected value and compare with a `let =expected = actual in` guard."
            )
        if _if_equality_binds_new_tuple_vars(line):
            issues.append(
                f"Line {lineno}: `if term = <pattern>` does not bind new variables reliably in Sapic+; first decrypt/derive into a term, then use `let <..., bound_var, ...> = term in` with equality patterns `=expected` for checks."
            )
        if re.search(r"\bif\b.*\s[&|]\s.*\bthen\b", line):
            issues.append(
                f"Line {lineno}: compound boolean guards inside `if ... then` are fragile in this Sapic+ subset; use pattern matching or nested simple checks."
            )
        if (
            _inside_lemma_body(lines, lineno)
            and _is_source_like_lemma_name(_current_lemma_name(lines, lineno))
            and _source_formula_has_wide_or_antecedent(raw_line)
        ):
            issues.append(
                f"Line {lineno}: source/typing lemmas should use separate conjuncts per input event; avoid one large disjunction antecedent such as `IN_M1(m) | IN_M2(m) | ...`, which often fails Tamarin guardedness."
            )
        if role_body_seen or process_body_seen:
            if re.search(r"\binsert\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", line):
                issues.append(
                    f"Line {lineno}: `insert Fact(...)` is not in the supported Sapic+ process subset; pass setup/state values as role parameters or use raw MSR rules consistently."
                )
            if re.search(r"\blookup\s+!?[A-Za-z_][A-Za-z0-9_]*\s*\(", line):
                issues.append(
                    f"Line {lineno}: `lookup !Fact(...) as ... in` is not in the supported Sapic+ process subset; pass setup/state values as role parameters or use raw MSR rules consistently."
                )
            if re.match(r"^\[\s*[!?]?[A-Za-z_][A-Za-z0-9_]*\s*\([^]]*\)\s*\]\s*;?$", line):
                issues.append(
                    f"Line {lineno}: raw fact-premise syntax cannot appear as a Sapic+ process statement; use role parameters, events, or a full raw MSR rule."
                )
        lemma_attr_match = re.match(
            r"^lemma\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(exists[-_]trace)\s*\]\s*:",
            line,
            flags=re.IGNORECASE,
        )
        if lemma_attr_match:
            lemma_name = lemma_attr_match.group(1)
            attr = lemma_attr_match.group(2)
            issues.append(
                f"Line {lineno}: `{attr}` must be a lemma-body line, not a bracket attribute. Use `lemma {lemma_name}:` then `exists-trace` on the next line."
            )
        bracket_attr_match = re.match(r"^lemma\s+\w+\s*\[[^]]*\]\s*:", line)
        if bracket_attr_match and not lemma_attr_match:
            unknown_attrs = _unknown_lemma_attributes(line)
            if unknown_attrs:
                issues.append(
                    f"Line {lineno}: unknown lemma attribute(s) {', '.join(unknown_attrs)}; trace qualifiers such as `exists-trace` must be lemma body lines, while source helpers may use known attributes like `[sources]`."
                )
        trace_inline_match = re.match(r"^lemma\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(all-traces|exists-trace)\b", line)
        if trace_inline_match:
            lemma_name = trace_inline_match.group(1)
            trace_kind = trace_inline_match.group(2)
            issues.append(
                f"Line {lineno}: `{trace_kind}` must not be inline after `lemma {lemma_name}:`; use a separate `exists-trace` body line only for reachability lemmas, and omit `all-traces` for universal lemmas."
            )
        if line == "all-traces" and _inside_lemma_body(lines, lineno) and not _inside_quoted_formula(lines, lineno):
            issues.append(
                f"Line {lineno}: omit `all-traces`; universal lemmas are the default and should place the quoted formula directly under `lemma name:`."
            )
        if re.match(r"^lemma\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*\"", line):
            issues.append(
                f"Line {lineno}: lemma formula should start on a body line after `lemma name:`, not inline after the colon."
            )
        if (
            _inside_lemma_body(lines, lineno)
            and not _inside_quoted_formula(lines, lineno)
            and _looks_like_unquoted_formula_line(line)
        ):
            issues.append(
                f"Line {lineno}: lemma formulas must be quoted strings in `.spthy` syntax; keep the formula inside double quotes instead of writing bare `All`/`Ex` formulas."
            )
        if _inside_lemma_body(lines, lineno) and re.search(r'^\s*[&|]\s*"', raw_line):
            issues.append(
                f"Line {lineno}: do not split a lemma into multiple quoted formula fragments joined outside quotes; use one quoted formula string under the lemma."
            )
        if _inside_lemma_body(lines, lineno) and re.search(r"\\[\/]|\/\\", raw_line):
            issues.append(
                f"Line {lineno}: Tamarin formulas do not use escaped ProVerif/LaTeX operators like `\\/` or `/\\`; use `|`/`∨` and `&`/`∧` inside the quoted formula."
            )
        if re.search(r"\b(True|true)\b", line) and re.search(r"==>|lemma\s+", line):
            issues.append(
                f"Line {lineno}: avoid vacuous lemma conclusions such as `==> True/true`; source/typing lemmas should relate protocol input events, output events, and adversary knowledge instead."
            )
        if re.search(r"\bIn\s*\([^)]*\)\s*@", line):
            issues.append(
                f"Line {lineno}: lemma formulas should usually reason about adversary knowledge with `K(term) @ #i` or protocol events, not process input facts `In(...) @ #i`."
            )
        if re.search(r"#[A-Za-z_][A-Za-z0-9_]*\s*>", line):
            issues.append(
                f"Line {lineno}: Tamarin trace timepoints use `<`; rewrite `#j > #i` as `#i < #j`."
            )
        for bad_identifier in re.findall(r"(?<!')\b[A-Za-z_][A-Za-z0-9_]*'(?=\W|$)", line):
            issues.append(
                f"Line {lineno}: identifier `{bad_identifier}` contains a prime suffix; use an alphanumeric name such as `{bad_identifier[:-1]}_recv`."
            )
        if re.search(r"(?<!')\b[a-z][A-Za-z0-9_]*'(?=\W|$)", line):
            issues.append(
                f"Line {lineno}: variable identifiers may not use prime suffixes; rename primed variables to names like `na_recv`."
            )
        if process_seen and process_body_seen and bare_role_macros:
            for role in sorted(bare_role_macros):
                if re.search(rf"(?<![A-Za-z0-9_])!?\s*{re.escape(role)}(?!\s*\()", line):
                    issues.append(
                        f"Line {lineno}: role `{role}` is invoked without parentheses; use `{role}()` or `!{role}()` to match `let {role}() =`."
                    )
        if re.search(r"(?<![A-Za-z0-9_'])g\s*\^", line):
            issues.append(
                f"Line {lineno}: bare DH generator `g^...` is likely unbound; use quoted generator `'g'^...`."
            )
        if re.search(r"\badd\s*\(", line):
            issues.append(
                f"Line {lineno}: `add(...)` is not a stable DH builtin in this route; avoid inventing exponent addition and use Tamarin DH idioms with `^`, `*`, and tupled hash inputs."
            )
    issues.extend(_undefined_projection_selector_lint(sapic_plus))
    issues.extend(formula_guardedness_lint(sapic_plus))
    return issues


def formula_guardedness_lint(sapic_plus: str) -> list[str]:
    """Catch common formula shapes that Tamarin cannot guard."""

    issues: list[str] = []
    for lemma in _lemma_blocks(sapic_plus):
        lemma_name = lemma["name"]
        start_line = lemma["line"]
        formula = _formula_text_from_lemma_block(lemma["block"])
        if not formula:
            continue
        normalized = _normalize_formula_text(formula)
        if _has_one_quantifier_wrapping_many_implications(normalized):
            issues.append(
                f"Line {start_line}: lemma `{lemma_name}` has one universal quantifier wrapping multiple implication clauses. Tamarin guardedness usually requires separate top-level conjuncts, e.g. `(All ... Fact1(...) @ #i ==> ...) & (All ... Fact2(...) @ #i ==> ...)`."
            )
        if _is_source_like_lemma_name(lemma_name) and _source_formula_needs_parenthesized_conjuncts(normalized):
            issues.append(
                f"Line {start_line}: source/typing lemma `{lemma_name}` has multiple implications that are not clearly separated as parenthesized top-level conjuncts. Write `(All ... IN_M1(...) @ #i ==> ...) & (All ... IN_M2(...) @ #i ==> ...)`, with each implication carrying its own quantifier."
            )
        for quantifier in _all_quantifier_antecedents(normalized):
            antecedent = quantifier["antecedent"]
            if not antecedent:
                continue
            if "@" not in antecedent:
                issues.append(
                    f"Line {start_line}: lemma `{lemma_name}` has a universally quantified implication whose antecedent has no action fact `Fact(...) @ #i`; equalities, time comparisons, or pure term conditions alone do not guard quantified variables."
                )
            elif _looks_like_reveal_only_guard(antecedent):
                issues.append(
                    f"Line {start_line}: lemma `{lemma_name}` appears to quantify variables guarded only by reveal/compromise side conditions. Put the protocol event that introduces the target value in the main antecedent, and keep reveal/compromise as an exception in the conclusion."
                )
            unguarded = _universals_missing_antecedent_guard(quantifier)
            if unguarded:
                issues.append(
                    f"Line {start_line}: lemma `{lemma_name}` universally quantifies variable(s) {', '.join(unguarded)} that do not occur in the implication antecedent. Tamarin guardedness requires each universal variable to be guarded by an antecedent action fact/equality; if the variable is only a witness in the conclusion, move it under `Ex` in the consequent."
                )
    return _dedupe(issues)


def _undefined_projection_selector_lint(sapic_plus: str) -> list[str]:
    text = sapic_plus or ""
    declared = set(
        re.findall(
            r"(?<![A-Za-z0-9_])((?:proj[3-9][0-9]*|thd|(?:m[0-9]+|req)_[A-Za-z0-9_]+))\s*/\s*1\b",
            text,
        )
    )
    if not declared:
        return []
    issues: list[str] = []
    equations_text = _top_level_equations_text(text)
    for name in sorted(declared):
        if not re.search(rf"\b{re.escape(name)}\s*\(", equations_text):
            issues.append(
                f"Projection-like function `{name}/1` is declared without equations; it will be an uninterpreted constructor, not a tuple selector. Use nested `fst`/`snd` bindings or define selector equations before relying on it to parse tuple fields."
            )
    return issues


def _top_level_equations_text(sapic_plus: str) -> str:
    lines = []
    collecting = False
    for raw_line in (sapic_plus or "").splitlines():
        line = _strip_line_comment(raw_line).strip()
        if re.match(r"^equations\s*:", line, flags=re.IGNORECASE):
            collecting = True
            lines.append(line.split(":", 1)[1])
            continue
        if collecting and re.match(r"^(builtins|functions|let|process|lemma|restriction|rule|end)\b", line):
            break
        if collecting:
            lines.append(line)
    return "\n".join(lines)


def _inside_lemma_body(lines: list[str], lineno: int) -> bool:
    start = lineno - 1
    for index in range(start, -1, -1):
        if index >= len(lines):
            continue
        if index == start:
            current = _strip_line_comment(lines[index]).strip()
            if re.match(r"^(lemma|restriction|axiom)\b", current):
                continue
        text = _strip_line_comment(lines[index]).strip()
        if not text:
            continue
        if re.match(r"^(lemma|restriction|axiom)\b", text):
            return True
        if re.match(r"^(let|process|rule|end)\b", text):
            return False
    return False


def _looks_like_unquoted_formula_line(line: str) -> bool:
    if line.startswith('"') or line in {"all-traces", "exists-trace"}:
        return False
    return bool(re.match(r"^(All|Ex)\b", line) or re.search(r"\s(@|==>|&|\|)\s", line))


def _lemma_blocks(sapic_plus: str) -> list[dict[str, object]]:
    lines = (sapic_plus or "").splitlines()
    starts: list[tuple[int, str]] = []
    for index, raw_line in enumerate(lines):
        match = re.match(r"\s*lemma\s+([A-Za-z_][A-Za-z0-9_]*)\b", raw_line)
        if match:
            starts.append((index, match.group(1)))
    blocks: list[dict[str, object]] = []
    for pos, (start, name) in enumerate(starts):
        end = starts[pos + 1][0] if pos + 1 < len(starts) else len(lines)
        blocks.append({"name": name, "line": start + 1, "block": "\n".join(lines[start:end])})
    return blocks


def _formula_text_from_lemma_block(block: object) -> str:
    text = str(block or "")
    pieces = []
    in_quote = False
    current: list[str] = []
    escaped = False
    for char in text:
        if escaped:
            if in_quote:
                current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            if in_quote:
                current.append(char)
            continue
        if char == '"':
            if in_quote:
                pieces.append("".join(current))
                current = []
            in_quote = not in_quote
            continue
        if in_quote:
            current.append(char)
    return "\n".join(pieces)


def _normalize_formula_text(formula: str) -> str:
    text = formula or ""
    replacements = {
        "∀": "All",
        "∃": "Ex",
        "⇒": "==>",
        "∧": "&",
        "∨": "|",
        "¬": "not ",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return " ".join(text.split())


def _has_one_quantifier_wrapping_many_implications(formula: str) -> bool:
    all_count = len(re.findall(r"\bAll\b\s+[^.]+\.", formula))
    implication_count = formula.count("==>")
    if all_count == 0:
        return False
    if implication_count < 2 or all_count >= implication_count:
        return False
    first_implication = formula.find("==>")
    first_quantifier = re.search(r"\bAll\b", formula)
    if not first_quantifier or first_quantifier.start() > first_implication:
        return False
    return len(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)\s*@\s*#?[A-Za-z0-9_]+", formula)) >= 2


def _source_formula_needs_parenthesized_conjuncts(formula: str) -> bool:
    if formula.count("==>") < 2:
        return False
    conjuncts = _split_top_level_conjuncts(formula)
    if len(conjuncts) >= 2 and all(_is_parenthesized_source_conjunct(item) for item in conjuncts):
        return False
    if len(re.findall(r"\bAll\b\s+[^.]+\.", formula)) < formula.count("==>"):
        return True
    return True


def _split_top_level_conjuncts(formula: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(formula or ""):
        if char in "([":
            depth += 1
        elif char in ")]":
            depth = max(0, depth - 1)
        elif char == "&" and depth == 0:
            parts.append(formula[start:index].strip())
            start = index + 1
    parts.append((formula or "")[start:].strip())
    return [part for part in parts if part]


def _is_parenthesized_source_conjunct(text: str) -> bool:
    value = (text or "").strip()
    if not (value.startswith("(") and value.endswith(")")):
        return False
    inner = value[1:-1].strip()
    return bool(re.match(r"^All\b[^.]+\..+==>.+", inner)) and inner.count("==>") == 1


def _all_quantifier_antecedents(formula: str) -> list[dict[str, object]]:
    antecedents: list[dict[str, str]] = []
    for match in re.finditer(r"\bAll\b\s+([^.]+)\.\s*(.+?)(?===>)", formula):
        variables = _quantified_variables(match.group(1))
        antecedent = match.group(1).strip()
        antecedent = match.group(2).strip()
        antecedents.append({"variables": variables, "antecedent": antecedent})
    return antecedents


def _looks_like_reveal_only_guard(antecedent: str) -> bool:
    if not antecedent or "@" not in antecedent:
        return False
    fact_names = [
        match.group(1).lower()
        for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*@", antecedent)
    ]
    if not fact_names:
        return False
    return all(any(token in name for token in ("reveal", "rev", "ltk")) for name in fact_names)


def _quantified_variables(text: str) -> list[str]:
    variables: list[str] = []
    for token in re.findall(r"#?[A-Za-z_][A-Za-z0-9_]*", text or ""):
        if token in {"All", "Ex"}:
            continue
        if token.startswith("#"):
            continue
        if token and token[0].islower() and token not in variables:
            variables.append(token)
    return variables


def _universals_missing_antecedent_guard(quantifier: dict[str, object]) -> list[str]:
    antecedent = str(quantifier.get("antecedent") or "")
    if not antecedent or "@" not in antecedent:
        return []
    guarded_tokens = _guarding_tokens(antecedent)
    return [
        variable
        for variable in quantifier.get("variables", [])
        if isinstance(variable, str) and variable not in guarded_tokens
    ]


def _guarding_tokens(antecedent: str) -> set[str]:
    tokens: set[str] = set()
    for _, args in _formula_action_facts(antecedent):
        tokens.update(_term_variables(args))
    for equality_match in re.finditer(r"(?<![A-Za-z0-9_])([a-z][A-Za-z0-9_]*)\s*=\s*([a-z][A-Za-z0-9_]*)(?![A-Za-z0-9_])", antecedent or ""):
        tokens.add(equality_match.group(1))
        tokens.add(equality_match.group(2))
    return tokens


def _formula_action_facts(text: str) -> list[tuple[str, str]]:
    facts: list[tuple[str, str]] = []
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for match in pattern.finditer(text or ""):
        close = _matching_paren_index(text, match.end() - 1)
        if close is None:
            continue
        if not re.match(r"\s*@\s*#?[A-Za-z0-9_]+", text[close + 1 :]):
            continue
        facts.append((match.group(1), text[match.end() : close]))
    return facts


def _matching_paren_index(text: str, open_index: int) -> int | None:
    depth = 0
    for index in range(open_index, len(text or "")):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _uses_public_function_as_setup_key(text: str) -> bool:
    declared_functions: set[str] = set()
    for match in re.finditer(r"(?im)^\s*functions\s*:\s*([^\n]+)", text or ""):
        for item in match.group(1).split(","):
            name = item.strip().split("/", 1)[0].strip()
            if name:
                declared_functions.add(name)
    if not declared_functions:
        return False
    key_like_functions = {
        name
        for name in declared_functions
        if re.search(r"(?:ltk|key|sk|secret|priv)", name, flags=re.IGNORECASE)
    }
    if not key_like_functions:
        return False
    for function_name in key_like_functions:
        if re.search(rf"\b{re.escape(function_name)}\s*\(", text):
            return True
    return False


def _trusted_private_value_names(constraints: list[dict[str, object]]) -> list[str]:
    names: list[str] = []
    for constraint in constraints:
        for value in constraint.get("values") if isinstance(constraint.get("values"), list) else []:
            if isinstance(value, dict):
                name = str(value.get("name") or "").strip()
            else:
                name = str(value or "").strip()
            if name and name not in names and re.search(r"(?:ltk|key|sk|secret|priv|kas|kbs)", name, flags=re.IGNORECASE):
                names.append(name)
    return names


def _is_output_on_public_channel(text: str, name: str) -> bool:
    escaped = re.escape(name)
    return re.search(rf"\bout\s*\(\s*~?{escaped}\s*\)", text or "") is not None


def _inside_quoted_formula(lines: list[str], lineno: int) -> bool:
    quote_count = 0
    for index in range(lineno - 2, -1, -1):
        text = _strip_line_comment(lines[index]).strip()
        if not text:
            continue
        if re.match(r"^(let|process|rule|end)\b", text):
            break
        quote_count += _unescaped_quote_count(text)
        if re.match(r"^(lemma|restriction|axiom)\b", text):
            break
    return quote_count % 2 == 1


def _current_lemma_name(lines: list[str], lineno: int) -> str:
    start = lineno - 1
    for index in range(start, -1, -1):
        text = _strip_line_comment(lines[index]).strip()
        if not text:
            continue
        match = re.match(r"^(?:lemma|restriction|axiom)\s+([A-Za-z_][A-Za-z0-9_]*)\b", text)
        if match:
            return match.group(1)
        if re.match(r"^(let|process|rule|end)\b", text):
            return ""
    return ""


def _is_source_like_lemma_name(name: str) -> bool:
    lowered = (name or "").lower()
    return any(token in lowered for token in ("source", "typing", "type"))


def _if_equality_binds_new_tuple_vars(line: str) -> bool:
    match = re.search(r"\bif\s+(.+?)\s*=\s*<([^>\n]+)>\s*then\b", line)
    if not match:
        return False
    left_tokens = set(_term_variables(match.group(1)))
    pattern = match.group(2)
    for token in _term_variables(pattern):
        if token not in left_tokens and not token.startswith("="):
            return True
    return False


def _term_variables(term: str) -> list[str]:
    variables = []
    for token in re.findall(r"=?~?[A-Za-z_][A-Za-z0-9_]*", term or ""):
        cleaned = token.lstrip("=").lstrip("~")
        if cleaned and cleaned[0].islower():
            variables.append(cleaned)
    return variables


def _source_formula_has_wide_or_antecedent(line: str) -> bool:
    text = line.replace("∨", "|").replace("=>", "==>")
    if "==>" not in text:
        return False
    antecedent = text.split("==>", 1)[0]
    return "|" in antecedent and len(re.findall(r"\bIN_[A-Za-z0-9_]*\s*\(", antecedent)) >= 2


def _unescaped_quote_count(text: str) -> int:
    count = 0
    escaped = False
    for char in text:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            count += 1
    return count


def _strip_line_comment(line: str) -> str:
    if "//" in line:
        return line.split("//", 1)[0]
    return line


def _line_receives_plain_variable(line: str) -> bool:
    return bool(re.match(r"^in\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*;", line or ""))


def _line_decrypts_to_identifier(line: str) -> str | None:
    match = re.match(r"^let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:sdec|adec)\s*\(", line or "")
    return match.group(1) if match else None


def _line_directly_tuple_destructures_decryptor(line: str) -> bool:
    return bool(re.match(r"^let\s+<[^>\n]+>\s*=\s*(?:sdec|adec)\s*\(", line or ""))


def _line_tuple_destructures_identifier(line: str, identifier: str) -> bool:
    if not identifier:
        return False
    return bool(re.match(rf"^let\s+<[^>\n]+>\s*=\s*{re.escape(identifier)}\b", line or ""))


def _tuple_destructure_source_identifier(line: str) -> str | None:
    match = re.match(r"^let\s+<[^>\n]+>\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\b", line or "")
    return match.group(1) if match else None


def _role_decl_params(line: str) -> set[str]:
    match = re.match(r"^let\s+[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]*)\)\s*=", line or "")
    if not match:
        return set()
    return {
        item.strip()
        for item in match.group(1).split(",")
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", item.strip())
    }


def _fresh_decl_names(line: str) -> list[str]:
    match = re.match(r"^new\s+(~?[A-Za-z_][A-Za-z0-9_]*)\s*;", line or "")
    return [match.group(1)] if match else []


def _local_let_bound_names(line: str) -> set[str]:
    match = re.match(r"^let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", line or "")
    return {match.group(1)} if match else set()


def _input_tuple_reuses_bound_names(line: str, bound_names: set[str]) -> set[str]:
    match = re.match(r"^in\s*\(\s*<(.+)>\s*\)\s*;", line or "")
    if not match:
        return set()
    tokens = set(re.findall(r"(?<!['~])[A-Za-z_][A-Za-z0-9_]*", match.group(1)))
    return tokens.intersection(bound_names)


def _has_trailing_end(text: str) -> bool:
    lines = (text or "").splitlines()
    for raw_line in reversed(lines):
        stripped = _strip_line_comment(raw_line).strip()
        if not stripped:
            continue
        return stripped == "end"
    return False


def _unknown_lemma_attributes(line: str) -> list[str]:
    match = re.match(r"^lemma\s+\w+\s*\[([^]]*)\]\s*:", line)
    if not match:
        return []
    allowed = {
        "sources",
        "reuse",
        "use_induction",
        "hide_lemma",
        "left",
        "right",
        "both",
    }
    attrs = [item.strip().split("=", 1)[0].strip() for item in match.group(1).split(",")]
    return [attr for attr in attrs if attr and attr not in allowed]


def run_tamarin(
    sapic_plus: str,
    output_path: Path,
    tamarin_bin: str = "tamarin-prover",
    timeout: int = 120,
    mode: str = "msr",
    derivcheck_timeout: int | None = 0,
) -> VerificationResult:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(sapic_plus, encoding="utf-8")
    command = [tamarin_bin, str(output_path), f"-m={mode}"]
    _append_derivcheck_timeout(command, derivcheck_timeout)
    start = perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        warnings = detect_tamarin_warnings(completed.stdout, completed.stderr)
        return VerificationResult(
            ok=completed.returncode == 0 and not warnings,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            command=command,
            output_path=output_path,
            warnings=warnings,
            elapsed_sec=round(perf_counter() - start, 3),
        )
    except FileNotFoundError as exc:
        return VerificationResult(
            ok=False,
            returncode=127,
            stdout="",
            stderr=f"{tamarin_bin} not found: {exc}",
            command=command,
            output_path=output_path,
            warnings=[],
            elapsed_sec=round(perf_counter() - start, 3),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _process_output_text(exc.stdout)
        stderr = _process_output_text(exc.stderr) or f"Timed out after {timeout} seconds."
        return VerificationResult(
            ok=False,
            returncode=124,
            stdout=stdout,
            stderr=stderr,
            command=command,
            output_path=output_path,
            warnings=detect_tamarin_warnings(stdout, stderr),
            elapsed_sec=round(perf_counter() - start, 3),
        )


def run_tamarin_proof(
    sapic_plus: str,
    output_path: Path,
    expected_lemmas: list[str],
    tamarin_bin: str = "tamarin-prover",
    timeout: int = 600,
    quit_on_warning: bool = True,
    proof_spec: ProofSpec | None = None,
    derivcheck_timeout: int | None = 0,
) -> ProofResult:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(sapic_plus, encoding="utf-8")
    command = [tamarin_bin, str(output_path), "--prove"]
    _append_derivcheck_timeout(command, derivcheck_timeout)
    if quit_on_warning:
        command.append("--quit-on-warning")
    start = perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        warnings = detect_tamarin_warnings(completed.stdout, completed.stderr)
        lemma_results = parse_proof_summary(completed.stdout + "\n" + completed.stderr)
        missing_results = [name for name in expected_lemmas if name not in lemma_results]
        lemma_actual_states, lemma_matches, mismatched_results = _proof_expectation_matches(
            lemma_results,
            expected_lemmas,
            proof_spec,
        )
        lemma_expected_states = _proof_expected_states(expected_lemmas, proof_spec)
        ok = completed.returncode == 0 and not warnings and not missing_results and not mismatched_results
        status = _proof_status(
            completed.returncode,
            warnings,
            missing_results,
            mismatched_results,
            lemma_results,
            expected_lemmas,
        )
        return ProofResult(
            ok=ok,
            status=status,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            command=command,
            output_path=output_path,
            warnings=warnings,
            lemma_results=lemma_results,
            missing_results=missing_results,
            lemma_actual_states=lemma_actual_states,
            lemma_expected_states=lemma_expected_states,
            lemma_matches=lemma_matches,
            mismatched_results=mismatched_results,
            per_lemma={},
            elapsed_sec=round(perf_counter() - start, 3),
        )
    except FileNotFoundError as exc:
        return ProofResult(
            ok=False,
            status="tool_missing",
            returncode=127,
            stdout="",
            stderr=f"{tamarin_bin} not found: {exc}",
            command=command,
            output_path=output_path,
            warnings=[],
            lemma_results={},
            missing_results=list(expected_lemmas),
            lemma_actual_states={},
            lemma_expected_states=_proof_expected_states(expected_lemmas, proof_spec),
            lemma_matches={name: False for name in expected_lemmas},
            mismatched_results=list(expected_lemmas),
            per_lemma={},
            elapsed_sec=round(perf_counter() - start, 3),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _process_output_text(exc.stdout)
        stderr = _process_output_text(exc.stderr) or f"Timed out after {timeout} seconds."
        lemma_results = parse_proof_summary(stdout + "\n" + stderr)
        lemma_actual_states, lemma_matches, mismatched_results = _proof_expectation_matches(
            lemma_results,
            expected_lemmas,
            proof_spec,
        )
        return ProofResult(
            ok=False,
            status="timeout",
            returncode=124,
            stdout=stdout,
            stderr=stderr,
            command=command,
            output_path=output_path,
            warnings=detect_tamarin_warnings(stdout, stderr),
            lemma_results=lemma_results,
            missing_results=[name for name in expected_lemmas if name not in lemma_results],
            lemma_actual_states=lemma_actual_states,
            lemma_expected_states=_proof_expected_states(expected_lemmas, proof_spec),
            lemma_matches=lemma_matches,
            mismatched_results=mismatched_results,
            per_lemma={},
            elapsed_sec=round(perf_counter() - start, 3),
        )


def run_tamarin_proof_lemma(
    sapic_plus: str,
    output_path: Path,
    lemma_name: str,
    tamarin_bin: str = "tamarin-prover",
    timeout: int = 60,
    quit_on_warning: bool = True,
    derivcheck_timeout: int | None = 0,
) -> ProofResult:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(sapic_plus, encoding="utf-8")
    command = [tamarin_bin, str(output_path), f"--prove={lemma_name}"]
    _append_derivcheck_timeout(command, derivcheck_timeout)
    if quit_on_warning:
        command.append("--quit-on-warning")
    start = perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        warnings = detect_tamarin_warnings(completed.stdout, completed.stderr)
        lemma_results = parse_proof_summary(completed.stdout + "\n" + completed.stderr)
        missing_results = [lemma_name] if lemma_name not in lemma_results else []
        ok = completed.returncode == 0 and not warnings and not missing_results
        status = _single_proof_status(completed.returncode, warnings, missing_results, lemma_results.get(lemma_name, ""))
        return ProofResult(
            ok=ok,
            status=status,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            command=command,
            output_path=output_path,
            warnings=warnings,
            lemma_results=lemma_results,
            missing_results=missing_results,
            elapsed_sec=round(perf_counter() - start, 3),
        )
    except FileNotFoundError as exc:
        return ProofResult(
            ok=False,
            status="tool_missing",
            returncode=127,
            stdout="",
            stderr=f"{tamarin_bin} not found: {exc}",
            command=command,
            output_path=output_path,
            warnings=[],
            lemma_results={},
            missing_results=[lemma_name],
            elapsed_sec=round(perf_counter() - start, 3),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _process_output_text(exc.stdout)
        stderr = _process_output_text(exc.stderr) or f"Timed out after {timeout} seconds."
        lemma_results = parse_proof_summary(stdout + "\n" + stderr)
        return ProofResult(
            ok=False,
            status="timeout",
            returncode=124,
            stdout=stdout,
            stderr=stderr,
            command=command,
            output_path=output_path,
            warnings=detect_tamarin_warnings(stdout, stderr),
            lemma_results=lemma_results,
            missing_results=[lemma_name] if lemma_name not in lemma_results else [],
            elapsed_sec=round(perf_counter() - start, 3),
        )


def _process_output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _append_derivcheck_timeout(command: list[str], derivcheck_timeout: int | None) -> None:
    if derivcheck_timeout is not None:
        command.append(f"--derivcheck-timeout={derivcheck_timeout}")


def parse_proof_summary(output: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        match = re.match(
            r"^([A-Za-z_][A-Za-z0-9_]*)\s+\(([^)]*)\):\s+(.+)$",
            line,
        )
        if not match:
            continue
        lemma_name = match.group(1)
        result = " ".join(match.group(3).split())
        results[lemma_name] = result
    return results


def _proof_status(
    returncode: int,
    warnings: list[str],
    missing_results: list[str],
    mismatched_results: list[str],
    lemma_results: dict[str, str],
    expected_lemmas: list[str],
) -> str:
    if returncode == 124:
        return "timeout"
    if returncode != 0:
        return "failed"
    if warnings:
        return "warnings"
    if missing_results:
        return "missing-proof-results"
    if mismatched_results:
        return "expectation-mismatch"
    unverified = [name for name in expected_lemmas if not lemma_results.get(name, "").startswith("verified")]
    if unverified:
        return "expected-matched"
    return "verified"


def _single_proof_status(
    returncode: int,
    warnings: list[str],
    missing_results: list[str],
    lemma_result: str,
) -> str:
    if returncode == 124:
        return "timeout"
    if returncode != 0:
        return "failed"
    if warnings:
        return "warnings"
    if missing_results:
        return "missing-proof-results"
    if lemma_result.startswith("verified"):
        return "verified"
    if lemma_result.startswith("falsified"):
        return "falsified"
    return "unknown"


def _proof_expected_states(expected_lemmas: list[str], proof_spec: ProofSpec | None) -> dict[str, str]:
    if proof_spec is None:
        return {name: "ProvedSatisfying" for name in expected_lemmas}
    return {name: proof_spec.expected_states.get(name, "ProvedSatisfying") for name in expected_lemmas}


def _proof_expectation_matches(
    lemma_results: dict[str, str],
    expected_lemmas: list[str],
    proof_spec: ProofSpec | None,
) -> tuple[dict[str, str], dict[str, bool], list[str]]:
    if proof_spec is not None:
        states, matches, mismatched = evaluate_lemma_matches(lemma_results, proof_spec)
        states = {name: states.get(name, "MissingProofResult") for name in expected_lemmas}
        matches = {name: matches.get(name, False) for name in expected_lemmas}
        mismatched = [name for name in expected_lemmas if not matches.get(name, False)]
        return states, matches, mismatched
    states: dict[str, str] = {}
    matches: dict[str, bool] = {}
    mismatched: list[str] = []
    for name in expected_lemmas:
        result = lemma_results.get(name, "")
        state = "ProvedSatisfying" if result.startswith("verified") else "CounterexampleFound" if result.startswith("falsified") else "MissingProofResult"
        states[name] = state
        matched = result.startswith("verified")
        matches[name] = matched
        if not matched:
            mismatched.append(name)
    return states, matches, mismatched


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            result.append(item)
            seen.add(item)
    return result


def detect_tamarin_warnings(stdout: str, stderr: str) -> list[str]:
    """Return warnings that should prevent a run from being counted as clean."""

    output = "\n".join(part for part in [stdout or "", stderr or ""] if part)
    warnings: list[str] = []
    patterns = [
        (r"WARNING:\s*the following wellformedness checks failed!?", "wellformedness checks failed"),
        (r"Facts occur in the left-hand-side but not in any right-hand-side", None),
        (r"Formula terms", None),
        (r"Lemma\s+`[^`]+['`]\s+uses terms of the wrong form", None),
        (r"Wellformedness-error\b[^\n]*", None),
        (r"Variable bound twice:\s*[^.\n]+", None),
        (r"WARNING:[^\n]*", None),
    ]
    seen: set[str] = set()
    for pattern, fallback in patterns:
        for match in re.finditer(pattern, output, flags=re.IGNORECASE):
            raw_text = " ".join(match.group(0).split()).rstrip("!")
            text = _normalize_warning(raw_text, fallback)
            if text not in seen:
                warnings.append(text)
                seen.add(text)
    return warnings


def _normalize_warning(raw_text: str, fallback: str | None) -> str:
    lower = raw_text.lower()
    if "wellformedness checks failed" in lower:
        return "wellformedness checks failed"
    if "facts occur in the left-hand-side" in lower:
        return "Facts occur in the left-hand-side but not in any right-hand-side"
    if lower.startswith("formula terms"):
        return "Formula terms use invalid non-variable terms"
    if "uses terms of the wrong form" in lower:
        return raw_text
    if lower.startswith("wellformedness-error"):
        return raw_text
    if lower.startswith("variable bound twice"):
        return raw_text
    return fallback or raw_text


def _strip_fence(text: str) -> str:
    lines = text.strip().splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()
