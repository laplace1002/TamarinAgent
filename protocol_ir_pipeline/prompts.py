from __future__ import annotations

import json
import re
from typing import Any

from .cases import ProtocolCase
from .proofspec import ProofSpec

PROOF_RESULT_STEP_SUFFIX_RE = re.compile(r"\s*\(\s*\d+\s+steps?\s*\)\s*$", re.IGNORECASE)
PROOF_RESULT_TEXT_KEYS = {"expected_raw", "expected_result", "expected"}


PLANNER_SYSTEM = """You parse natural-language protocol descriptions into ProtocolIR for security protocol verification.
Return only JSON. Parse the protocol; do not repair, strengthen, or simplify away its proof-relevant behavior.
The ProtocolIR must preserve protocol semantics and make later modeling-contract and Sapic+ generation auditable.
When benchmark or review goals are supplied, preserve them as reviewed metadata and proof interfaces; do not let them drive unsupported protocol redesign."""

IR_REPAIR_SYSTEM = """You are repairing a lightweight ProtocolIR for security protocol modeling.
Return only JSON. Preserve the natural-language protocol semantics and target proof goals.
Do not write Sapic+ or Tamarin code in this stage."""

SAPIC_SYNTAX_CONTRACT = """Sapic+ syntax contract for this project:
- Use an untyped Sapic+ subset unless the input explicitly requires advanced typing.
- A complete model must look like:
  theory Name
  begin
  functions: f/1, g/2
  let A() =
    new n;
    out(n);
    in(x);
    event Done('A', x)
  process:
    (!A())
  lemma executable:
    exists-trace
    "Ex #i x. Done('A', x) @ i"
  end
- Role processes are declared with `let Role(params) = ...`; zero-argument roles must be `let Role() = ...`, not `let Role = ...`.
- Do not terminate `let Role(...) =` process macros with a standalone `.`. A role body ends before the next top-level `let`, `process:`, or lemma declaration.
- Role invocations must match the declaration: use `Role()` for zero-argument roles, including under replication as `!Role()`, not `!Role`.
- Role parameters must be flat identifiers. Do not put tuple/pair patterns in role parameter lists; use `let Role(id1, pk1, id2, pk2) = ...`, not `let Role((id1, pk1), (id2, pk2)) = ...`.
- Role arguments that need to appear later in checks, events, or lemmas should be stable identifiers, not reducible terms over local fresh secrets. Bind public values first, e.g. `let pkS = pk(skS) in`, then pass `pkS` to roles and events instead of repeatedly using `pk(skS)` inside guarded branches.
- Fresh names are introduced only inside processes with `new n;` or `new ~n;`.
- Use public-channel communication as `out(term);` and `in(x);` by default.
- Do not use pseudo-state process statements such as `insert Fact(...)`, `lookup !Fact(...) as x in`, or `[ Fact(...) ];`. In Sapic+ roles, pass setup/state values as role parameters or bind them in `process:` before role invocation.
- Use pattern matching with `let pattern = term in ...` when deconstructing messages. Tuple decomposition must put the tuple pattern on the left and the received/decrypted term on the right: write `let <a,b> = msg in`. Tuple construction is different and is valid as `let msg = <a,b> in`.
- Every local `let` binding or pattern match inside a process must continue with `in`, not `;`. Write `let m = <a,b> in`, not `let m = <a,b>;`.
- Avoid local parse/check chains that create implicit failed branches for adversary-controlled input. Prefer the successful-branch receive/protected-message templates in the process-reachability contract below.
- If an `if ... then` branch contains more than one process statement, wrap the whole continuation in parentheses. Without parentheses, later statements can be parsed outside the guarded branch and create unreachable translated state facts.
- Use `let` patterns, not `if`, to bind new variables from decrypted/parsed messages. Write `let decoded = adec(cipher, sk) in` then `let <=expected, fresh_value> = decoded in`. Do not write `if adec(cipher, sk) = <expected, fresh_value> then` when `fresh_value` is new.
- Use equality patterns `=expected` inside `let` patterns only for small checks over already-bound identifiers when a direct successful-branch receive/protected-message pattern is not clearer.
- Equality patterns compare against already-bound non-boolean identifiers only. Do not write `let =<tag, x> = msg in`, `let <='TAG', x> = msg in`, `let ='TAG' = tag in`, `let =h(x) = y in`, or `let =true = ok in`; bind the expected term first, then compare with `let =expected = actual in`.
- Boolean checks cannot stand alone as process statements, and boolean constants are not valid equality-pattern binders. Do not write `verify(sig, m, pk) = true;` or `let =true = verify(sig, m, pk) in`; use `if verify(sig, m, pk) = true then (...)`.
- Do not add a builtin to fix ordinary tuple syntax, pair syntax, or a wellformedness warning. Tuples such as `<a,b>` need no `pairing` builtin.
- Events are emitted inside processes with `event Fact(args);`. Do not declare events at top level.
- Lemma trace qualifiers are lemma-body lines, not bracket attributes: write `lemma l:\n  exists-trace\n  "..."`, never `lemma l [exists-trace]: "..."` or `lemma l [exists_trace]: "..."`.
- Lemma formulas are quoted strings in `.spthy` syntax. Keep formulas inside double quotes; do not remove quotes around `All`/`Ex` formulas during repair.
- Lemma formulas may only use public constants and variables bound by quantifiers/action facts. Do not write process-local fresh names such as `~sk`, or constructed terms over them such as `pk(~sk)`, directly in lemmas; expose the needed public key/identity through action-fact arguments and quantify that variable.
- Universal all-traces lemmas are the default: write `lemma l:\n  "All ..."` without an `all-traces` body line.
- Exists-trace lemmas need a separate body line: write `lemma l:\n  exists-trace\n  "Ex ..."`.
- Do not write `lemma l: exists-trace "..."`, `lemma l: all-traces "..."`, or `lemma l: "..."`.
- Tamarin trace timepoint ordering uses `<`; rewrite `#j > #i` as `#i < #j`.
- Asymmetric encryption uses function-style terms such as `aenc(m, pk)` and `adec(c, sk)` with `builtins: asymmetric-encryption` or suitable function/equation declarations. Do not use ProVerif-style `{m}_k`, `aenc{m}_k`, or `adec{c,k}`.
- When `builtins: asymmetric-encryption` is present, do not declare `functions: pk/1`; `pk` is reserved/provided by that builtin.
- When `builtins: hashing` is present, do not declare `functions: h/1`; use the builtin hash symbol directly, or choose a non-reserved helper name such as `hash1/1` only when a separate uninterpreted helper is needed.
- Sapic+ equality patterns cannot call functions on the left side. Do not write `let =h(x) = y in`; instead write `let expected = h(x) in let =expected = y in`.
- Identifiers must be alphanumeric/underscore. Do not use primed variables like `na'`; use `na_recv`, `na1`, or another valid identifier.
- Constants should be quoted terms such as `'A'`, `'B'`, and `'ACK'`.
- Builtins must use Tamarin names such as `hashing`, `symmetric-encryption`,
  `asymmetric-encryption`, `signing`, `diffie-hellman`, `xor`, or `natural-numbers`.
- Builtins are comma-separated. Do not write space-separated builtin lists.
- MAC/HMAC/KDF helpers are functions, not builtins. Use declarations such as `functions: kdf/2, mac/2`. Do not put `mac`, `hmac`, or `kdf` in `builtins:`, and do not redeclare builtin names such as `h/1` when `hashing` is enabled.
- Functions use declarations such as `functions: kdf/2, hash1/1`. Do not emit empty `equations:`.
- Diffie-Hellman idiom when `builtins: diffie-hellman` is used:
  use the quoted generator constant `'g'`, e.g. `'g'^x`; do not declare `g/0`.
  Do not declare `+/2` or `*/2`; `^` and `*` are provided by the DH builtin.
  Do not invent `add(...)` for exponent addition. If a protocol needs
  exponent mixing, prefer stable terms used by Tamarin examples such as
  `let exI = h1(<~eskI, ~lkI>) in`, `let hkI = 'g'^exI in`,
  and `let kI = h2(<Y^~lkI, pkR^exI, Y^exI, pkI, pkR>) in`.

Forbidden pseudo-Sapic+ patterns:
- `public A: agent`, `public agent A`, `const A`, `constants: ...`
- top-level `event Secret(agent, agent, msg)`
- `builtins: pairing` or adding `pairing` to a builtin list for ordinary tuples
- `builtins: ..., mac, ...` or space-separated builtins such as `builtins: hashing signing`
- `let A = ...`, `process: !A`, or `process: A` for role macros
- standalone `.` after a `let Role(...) =` process macro
- tuple/pair role parameters such as `let Role((id1, pk1)) = ...`
- role invocations that pass reducible identity terms such as `!B(skD, pk(skS))` when that public key is later used in checks/events; bind `pkS = pk(skS)` first and pass `pkS`
- local let bindings terminated by semicolon such as `let m = <a,b>;`
- treating tuple construction as tuple decomposition; `let msg = <a,b> in` is valid construction, while destructuring must be `let <a,b> = msg in`
- deeply nested parsing branches such as `let <a,b> = x in let <c,d> = y in ... else 0`
- binding checks such as `if adec(c, sk) = <na, nb> then` where `na`/`nb` are newly introduced by the comparison
- `lemma l [exists-trace]: ...` or `lemma l [exists_trace]: ...`
- unquoted lemma formulas such as `All x #i. Fact(x) @ i ==> ...`
- `lemma l: all-traces "..."`, `lemma l: exists-trace "..."`, `lemma l: "..."`
- `#j > #i` or any timepoint `>` comparison
- `aenc{m}_k`, `adec{c,k}`, `{m}_k`, or variables with prime suffixes such as `na'`
- `functions: pk/1` together with `builtins: asymmetric-encryption`
- `functions: h/1` together with `builtins: hashing`
- function calls, tuple terms, boolean constants, or quoted constants in equality patterns such as `let =h(x) = y in`, `let =true = ok in`, `let =<'TAG', x> = m in`, `let <='TAG', x> = m in`, or `let ='TAG' = tag in`
- standalone checks such as `verify(sig, m, pk) = true;`
- process pseudo-state such as `insert Fact(x);`, `lookup !Fact(x) as y in`, or `[ Fact(x) ];`
- vacuous proof goals such as `Fact(...) @ i ==> True` or `==> true`
- `functions: +/2`, `functions: */2`, `functions: g/0`, bare `g^x`, or `add(x,y)` in DH models
- `let A(x:agent) = ...` unless all types are valid Sapic+ types and are necessary
- `out(net, msg)` / `in(net, x)` unless a channel discipline is explicitly required
- Coq/ProVerif/TLA-style declarations, sort declarations, or standalone type declarations."""

SAPIC_PROCESS_REACHABILITY_CONTRACT = """Sapic+ process-reachability contract:
- The warning "Facts occur in the left-hand-side but not in any right-hand-side" is a process translation problem: a continuation or failure-state fact is consumed by a generated rule but never produced. Fix the role process shape, not lemmas, events, restrictions, builtins, or proof expectations.
- Model roles as continuing only on messages that pass their local parse/decrypt/check. Failed network attempts may stop silently; they do not need explicit `else 0`, dummy events, or dummy branches.
- Prefer successful-branch receive templates for untrusted network messages:
  - Plain structured input: `in(<tag, peer, payload>);` when the wire message is a public tuple and the role only continues for that shape. Use fresh field names in the input pattern; if a field must equal an already-bound role value, receive it as `field_recv` and check it in the role body.
  - Protected input: receive an opaque ciphertext variable, decrypt once, and then check fields with projections or simple `if` guards, e.g. `in(cipher); let plain = adec(cipher, skR) in let tag = fst(plain) in if tag = expected_tag then (...)`. Do not pattern-match encrypted constructors directly in `in(...)`.
  - Opaque forwarding: receive `in(cipher);` only when the role really treats `cipher` as opaque or forwards it without parsing.
- Avoid the fragile pattern `in(msg); let <...> = msg in ...` for public tuple messages when a structured input can bind the same fields directly.
- Do not put already-bound role parameters, local fresh names, or earlier state variables directly inside an `in(<...>)` tuple pattern. Patterns such as `in(<C_I, G_Y, C_R, cipher2>);` or `in(<C_R, cipher3, AD3>);` can bind `C_I`/`C_R` twice. Use `in(<ci_recv, G_Y, cr_recv, cipher2>);` followed by simple checks against `C_I`/`C_R`.
- Avoid the fragile pattern `in(cipher); let decoded = sdec(cipher, k) in let <...> = decoded in ...` when tuple matching creates dead failed-parse branches. Prefer nested `fst`/`snd` plus simple `if` guards, or keep the ciphertext opaque until a later event truly needs parsed fields.
- Do not write input patterns such as `in(aenc(<x,y>, pkA));`, `in(aenc(=nonce, pkB));`, or `in(senc(<x,y>, k));`. They often introduce non-derivable variables or "Variable bound twice" warnings because role parameters and new fields are being matched inside the input premise.
- Do not write equality subpatterns inside public input tuples, such as `in(<='TAG', x>);` or `in(<=expected, x);`. Receive fresh fields and compare them inside the role body with a simple `if` or a valid equality pattern over a bound identifier.
- Do not put quoted tags/constants inside local tuple destructuring of adversary-controlled or decrypted terms, such as `let <'TAG', x> = term in`. Put the tag in the successful receive/protected constructor shape, or bind `expected_tag = 'TAG'` and compare against an already-bound field only if direct receiving is impossible.
- For encrypted messages with tagged tuple payloads, avoid local tuple destructuring entirely after decryption when the plaintext came from the network. Use only built-in `fst`/`snd` selector chains plus simple checks against already-bound expected values; then emit events using the projected variables.
- Do not invent selector helpers such as `proj3/1`, `m2_tag/1`, or `req_na/1` unless you also define correct equations for every selector and use them consistently. Undeclared-equation selectors are ordinary uninterpreted functions and make honest traces unreachable.
- If a real semantic check must remain as `if condition then`, keep the condition simple and put the whole continuation inside parentheses when it has more than one statement.
- If the same reachability warning survives a local patch, or diagnostics mention several generated state facts/rules in one role, rewrite the affected role using these successful-branch templates instead of making another small textual patch."""

SAPIC_SYSTEM = """You are an expert in Sapic+ and Tamarin protocol modeling.
Generate a complete Sapic+ theory from the supplied reviewed IR and derived proof context.
Return only JSON. Do not include Markdown fences.

Requirements:
- The output sapic_plus must be a complete theory ... begin ... process: ... end document.
- Prefer Sapic+ processes over raw multiset rewriting rules.
- Include builtins/functions/equations needed by the messages.
- Use explicit events for secrecy/authentication claims.
- Include lemmas matching the requested security goals when possible.
- Keep role processes readable and named.
- Do not copy external reference models if they are included only as metadata.
- Follow the Sapic+ syntax contract exactly."""

SAPIC_GENERATION_SOURCE_CONTRACT = """Sapic+ generation source contract:
- Generate from the reviewed protocol artifacts. Do not reinterpret natural-language text, user goals, assumptions, or planning notes after they have been reviewed into protocol_ir/proof_context.
- Treat protocol_ir as the parsed protocol semantics and proof_context as derived proof-goal metadata.
- Treat reviewed_proof_targets as the authoritative target list when present.
- Do not bypass protocol_ir by inventing a different message flow unless ir_validation explicitly identifies a repair need.
- Use protocol_ir messages, actions, checks, fresh_terms, long_term_keys, and semantic_constraints to decide which role may generate, derive, decrypt, or only forward a term opaquely.
- Treat protocol_ir.semantic_constraints and proof_context.semantic_constraints as binding constraints from resolved open questions. If they conflict with a stale normalized field such as `public_term`, preserve the resolved answer and explain the conflict in modeling_notes.
- Treat field_reviews as human-review metadata. `user_confirmed` fields are authoritative, `system_assumption` fields must remain explicit assumptions, and unresolved `must_review`/`needs_review` fields are audit risks, not permission to silently strengthen, weaken, or reinterpret protocol semantics."""

SAPIC_GENERATION_PROOF_TARGET_CONTRACT = """Sapic+ generation proof-target contract:
- Preserve every reviewed target lemma name, trace kind, goal type, and reviewed expected outcome exactly.
- Preserve fine-grained code-derived claim profiles. Do not collapse request/command authentication, response authentication, payload confidentiality, key secrecy, validation, lifecycle, and attack-witness targets into one generic integrity or secrecy lemma.
- Do not add support lemmas unless proof_context explicitly marks them as reviewed target lemmas.
- Do not add non-target source/helper lemmas or auxiliary source events. `requires_sources_lemma=false` disables only non-target helpers; it must not suppress reviewed target lemmas whose goal_type is source or typing.
- For reviewed_expected_outcome=ProvedSatisfying, model enough checks, events, restrictions, and role state for the lemma to prove without becoming vacuous.
- For reviewed_expected_outcome=CounterexampleFound, preserve the reviewed attack surface. Do not over-strengthen the model, add unrealistic restrictions, hide public messages, remove adversary input, or rewrite the lemma just to make it verified.
- For every reviewed exists-trace target expected ProvedSatisfying, mentally execute the honest message path before finalizing: each tag, nonce, identity, ticket, and key check must succeed with the values produced by the sender.
- Every target lemma must be backed by explicit events emitted in the relevant role processes.
- Before writing a target lemma, resolve its event relation from proof_context.target_lemmas.required_events, proof_context.event_obligations, or protocol_ir.claims[].event_schema; do not fall back to a name-only lemma template when reviewed event schemas exist.
- Authentication goals should use Running/Commit-style events or protocol-specific equivalents with matching actor, peer, and session parameters.
- Generate separate request/command and response authentication lemmas when the reviewed claims distinguish the sender/receiver boundaries. Do not merge both directions into a single transcript-integrity lemma unless that merge is explicitly reviewed.
- Injective authentication goals must include the reviewed partner correspondence evidence (`Running*`, `Server`, or equivalent) plus uniqueness. Never reduce injective agreement to duplicate-`Commit` uniqueness unless the reviewed contract explicitly asks for that.
- Do not invent dummy, placeholder, wildcard, or existential-only values inside proof-event payloads. Event arguments must be values the role actually knows or has checked at that point, following the reviewed proof context.
- Secrecy goals should emit Secret-style events at the point the role actually believes the value is secret.
- Payload confidentiality goals must prove secrecy of the protected plaintext payload. Do not satisfy them by proving only session-key secrecy, ciphertext opacity, or secrecy of a public placeholder constant.
- Keep event payload schemas uniform for the same proof value across roles. If a session key, nonce pair, or transcript is represented as `session` in Running/Commit, use the same shape in Secret and matching lemmas unless proof_context explicitly requires different facts.
- Exists-trace goals must be reachable by the process and should reference meaningful completion or session events."""

SAPIC_GENERATION_ABSTRACTION_CONTRACT = """Sapic+ generation abstraction contract:
- Treat abstraction_hints as retrieval-based proof-engineering guidance only. Use lessons for proof-friendly abstraction choices, but do not copy protocol names, concrete message flows, lemma formulas, or case-specific fixes from retrieved examples.
- If proof_context.preservation_boundary.needed is true, use its constraints as the high-level abstraction boundary: preserve target preservation contracts, state stages, value dependencies, event dependencies, compromise assumptions, and expected proof outcomes.
- If proof_context.preservation_boundary.needed is false, keep the model simple and avoid adding abstraction machinery not needed by protocol_ir/proof_context.
- For long key schedules, transcript hashes, MAC inputs, or exporter/application keys, bind compact phase variables and reuse them. Do not repeatedly inline the full nested derivation/transcript term in later messages, events, or lemmas."""

SAPIC_GENERATION_PROVENANCE_CONTRACT = """Sapic+ generation value-provenance contract:
- Preserve value provenance and trust boundaries from protocol_ir/proof_context. Do not turn setup/state knowledge into arbitrary network input, or network input into trusted setup, unless the reviewed artifacts explicitly say so.
- Values marked by semantic constraints as trusted setup, role state, long-term keys, or private keys must originate as fresh private setup/state, role parameters, or persistent private facts.
- Do not replace private setup/state values with public constants or public functions of identity.
- Values classified as secret/private setup or role state by protocol_ir/proof_context must not be made public unless the reviewed compromise model explicitly exposes them.
- Do not introduce extra principals, keys, or compromise paths unless protocol_ir/proof_context explicitly includes them.
- Values needed later in events, checks, or lemmas should be passed as stable role parameters or bound public identifiers rather than recomputed as reducible terms inside guarded branches.
- Do not bridge Sapic+ role state through `insert`/`lookup` pseudo-statements. Bind setup keys and public identities once in `process:` and pass them to the roles that need them."""

SERVER_MEDIATED_BASELINE = """Server-mediated proof baseline:
- For server, KDC, ticket, or authority-mediated protocols, preserve the reviewed event schema for each target direction instead of forcing one global session payload.
- Represent issued keys, tickets, certificates, and credentials with compact bound variables plus origin/acceptance events; keep the full cryptographic container out of terminal proof-event payloads unless the target requires it.
- Use a bounded topology by default: one honest witness path, plus only the explicit replay, attacker principal, compromise, or second-session branch needed by a reviewed target.
- Forward opaque tickets, ciphertexts, and certificates opaquely unless the role is meant to decrypt or validate them."""

PROOF_ENGINEERING_BASELINE = """Proof-engineering baseline:
- Treat proof-search risk as protocol-shape driven, not difficulty driven: server/KDC mediation, tickets/certificates, source/typing targets, multiple authentication directions, expected replay/counterexample targets, and heavy destructor/equation use all require a compact proof model from the first generation.
- Prefer proof-friendly abstractions once the reviewed protocol dependencies are preserved. When abstraction_hints are present, use only their modeling lessons for compact topology, event payloads, and state-space control.
- Emit Secret/Running/Commit and other proof events over compact bound variables or session identifiers, not selector, destructor, hash, KDF, MAC, signature-verification, or decryption expressions.
- Normalize equivalent representations before emitting proof events: after a role checks that two terms represent the same reviewed value, use one canonical bound variable consistently for that target.
- Start with the smallest role topology that can witness the reviewed targets; add replication, extra principals, compromise branches, or second sessions only when the target semantics require them.
- For source/typing targets, derive the lemma and supporting events from the reviewed `Source obligations:` text. If that text is absent or ambiguous, keep the source target explicit but note the limitation rather than inventing broad helper obligations.
- When proof search or derivation checks time out, first reduce topology, event-term complexity, repeated derivations, and source-helper breadth; do not change target outcomes, lemma names, or add non-target helper lemmas."""

SAPIC_FORMAT_REPAIR_SYSTEM = """You are repairing the response format for a Sapic+ generation task.
Return only JSON. Do not include Markdown fences.

Requirements:
- Preserve the generated Sapic+ theory semantics unless the previous response was truncated.
- Put one complete theory ... begin ... process: ... end document in `sapic_plus`.
- Escape newlines inside the JSON string correctly.
- Include `modeling_notes` and `expected_limitations` arrays."""

PROOF_GOAL_CONTRACT = """Proof-goal modeling contract:
- Treat proof_spec expectations as target contracts, not just names.
- Target lemma names are immutable. Do not split, rename, suffix, or replace a target lemma with per-message variants. If a source/typing lemma needs per-message obligations, keep one lemma with the exact target name and put separate guarded conjuncts inside its single quoted formula.
- Code-derived fine-grained claim categories are also immutable unless the reviewed proof_spec explicitly changes them. Do not replace command authentication with generic integrity, response authentication with command authentication, payload confidentiality with key secrecy, or an attack witness with an over-constrained all-traces safety lemma.
- For source/typing target lemmas, first read the target `intent`; if it contains `Source obligations: ...`, implement those exact `IN_* => OUT_* or KU/K` obligations as the lemma's guarded conjuncts.
- For source/typing targets, preserve the reviewed `IN_*`/`OUT_*` action-fact schema from proof_context or preservation_boundary: keep fact names, arities, and payload roles stable unless the reviewed context explicitly permits abstraction.
- Treat `IN_*` source facts as accepted-input facts, not raw receive markers: emit them only after the reviewed parse/decrypt/check boundary for the referenced value. If a reviewed compromise/reveal path lets the adversary forge a protected input, include the matching exception or limit the source obligation to uncompromised traces.
- For source/typing obligations over accepted protected inputs, do not assert an unqualified honest origin across a compromised protection boundary; according to the reviewed compromise model, either relate the accepted value to a prior honest OUT, show adversary knowledge/public origin, or include the relevant compromise exception with its identity/key owner properly bound.
- Do not add non-target source-helper lemmas, `sources` lemmas, or auxiliary source-helper events unless a user-facing target lemma is explicitly `goal_type=source` or `goal_type=typing`.
- `goal_type=source` or source/typing target lemmas are helper lemmas. They must not be vacuous. Relate parsed inputs to prior outputs or adversary knowledge. Use known Tamarin attributes such as `[sources]` only when the target itself is a source/typing helper; never put `[sources]` on secrecy, authentication, property, or executability targets.
- For source/typing lemmas, use the canonical shape `lemma NAME [sources]: "(All ... #i. IN_X(...) @ i ==> ((Ex #j. OUT_Y(...) @ j & j < i) | (Ex #k. KU(v) @ k & k < i))) & (All ...)"`.
- Each source/typing conjunct must have its own `All ... . IN_... @ #i ==> ...`, be parenthesized before the top-level `&`, and relate an input event to a matching prior output or adversary knowledge. Do not replace this with generic `Sent/Received` events, a disjunctive antecedent, or a well-sortedness claim.
- Secrecy lemmas should reason about adversary knowledge with `K(secret) @ #j`, guarded by honest/reveal events when the protocol has long-term keys. Do not use process input facts `In(secret) @ #j` as a secrecy condition.
- Payload confidentiality lemmas must quantify the plaintext payload introduced or accepted by the honest role. Session-key secrecy may be a separate target, but it does not satisfy payload confidentiality unless the reviewed target explicitly says so.
- For secrecy reveal/compromise exceptions, preserve the reviewed timing policy. Do not add time-ordering constraints to exception clauses unless the reviewed contract requires them.
- If a protected input can be forged after a long-term-key reveal, source/typing and secrecy lemmas need the matching reveal/compromise exception. Do not assert unqualified honest origin or secrecy across a compromised protection boundary.
- Authentication lemmas should connect `Commit`/`Running` or protocol-specific completion events, include matching actor/peer/session parameters, and include compromise/reveal escape clauses when long-term keys can be revealed. Injective agreement must include this partner correspondence plus uniqueness; do not reduce it to duplicate-`Commit` uniqueness unless the reviewed contract explicitly asks for that property.
- If proof_spec contains distinct command/request and response authentication targets, keep distinct Commit/Running event pairs for each direction at the reviewed send/accept boundaries.
- For compromise/reveal/corruption actions used as lemma exceptions, emit the exception action fact before leaking the compromised secret. A process like `out(secret); event Reveal(id)` is wrong for lemmas guarded by that reveal/corruption fact; use `event Reveal(id); out(secret)` so adversary use of the leaked value is covered by the exception.
- `exists-trace` lemmas should witness reachable protocol completion or secret/session events. They should not be empty reachability shells.
- Every action fact referenced in a target lemma must be emitted by the process with the same fact name and arity. Keep event argument lists consistent across all emissions and lemma references.
- Keep the term shape of proof-relevant session values consistent across Secret/Running/Commit facts. Avoid proving about both `kab` and `<kab,t>` for the same session secret unless the reviewed target intentionally distinguishes those values.
- Lemma variables for public keys, peers, sessions, and reveal exceptions must be bound through emitted action facts. Never refer to process-local fresh names or reducible terms over them, such as `pk(~skA)`, directly inside a lemma; emit and quantify variables like `pkA`, `pkB`, or `actor`.
- Do not satisfy a target lemma by making it vacuous, deleting events, deleting lemmas, or replacing formulas with `True`/`true`.
- If the reviewed expected outcome is `CounterexampleFound` (including legacy `expected_state` fields in reviewed artifacts), preserve the intended attack surface while keeping the lemma semantically meaningful.
- If a `CounterexampleFound` target times out, reduce redundant search while preserving the attack surface: prefer one explicit adversary-controlled principal/key/session or one bounded attack branch supported by protocol_ir/proof_context. Do not force all peers to be honest, remove attacker-chosen public inputs, or use unbounded attacker-registration replication when one adversary identity suffices."""

REPAIR_SYSTEM = """You are repairing a Sapic+ theory using compiler/verifier feedback.
Return only JSON. Preserve the protocol semantics unless the diagnostic shows the model is malformed.
Do not remove requested lemmas just to make verification pass.
Follow the Sapic+ syntax contract exactly."""

PROOF_REPAIR_SYSTEM = """You are repairing a compile-clean Sapic+ theory that failed reviewed proof expectations.
Return only JSON. Preserve protocol semantics, target lemma names, trace kinds, and expected outcomes.
Do not weaken lemmas, delete events, or rewrite clean process syntax unless diagnostics identify a syntax regression.
Repair the semantic cause of the counterexample or expectation mismatch."""

REPAIR_TRIAGE_CONTRACT = """Repair triage contract:
- Repair only the current Sapic+ theory. Do not reinterpret natural-language text, user goals, assumptions, or planning notes after they have been reviewed into protocol_ir/proof_context.
- Use protocol_ir/proof_context as the source of truth for protocol behavior, role knowledge, event placement, target lemmas, and reviewed expected outcomes.
- Repair in this order: parser/syntax errors, Tamarin wellformedness warnings, unresolved or badly scoped names, event/lemma schema consistency, then proof expectation mismatches.
- Warnings such as "Variable bound twice" and "Facts occur in the left-hand-side but not in any right-hand-side" are blocking even when Tamarin exits with return code 0.
- Preserve resolved semantic constraints. Do not fix compile errors by changing trusted setup, private state, long-term keys, or private keys into public constants/functions. Use fresh setup/state, role parameters, or persistent private facts instead.
- Use abstraction_hints only for modeling style, such as transcript summaries, scoped events, and state-space control. Do not add auxiliary proof-helper lemmas from hints unless they are reviewed target lemmas.
- Do not delete target lemmas, rename target lemmas, remove target events, or change protocol behavior merely to match a proof result. Repairs must stay within protocol_ir/proof_context."""

REPAIR_DIAGNOSTIC_ACTIONS = """Diagnostic-specific repair actions:
- Process reachability: if diagnostics say "Facts occur in the left-hand-side but not in any right-hand-side", apply the process-reachability contract before touching lemmas. Rewrite the affected role so every generated continuation state is reachable from a successful receive/parse/check path. Do not add dummy events, dummy `else` branches, helper lemmas, restrictions, or builtins to silence this warning.
- No honest trace: if an expected ProvedSatisfying `exists-trace` lemma is falsified with "no trace found", repair the message path first. Check that decrypted fields are parsed by real selectors, every sender/receiver tuple shape matches, and every tag/nonce/identity check can succeed honestly.
- Undefined selectors: if diagnostics mention selector-like functions without equations (`proj3`, `m2_tag`, `req_na`, etc.), remove them and bind fields with nested `fst`/`snd`, or add complete selector equations. Do not keep them as uninterpreted helper functions.
- Process state syntax: if diagnostics point at `insert`, `lookup`, or `[ Fact(...) ];` inside a role, remove the pseudo-state bridge. Put setup/state values in role parameters or rewrite the model consistently as raw MSR rules; do not mix raw-rule premises with Sapic+ process statements.
- Compound checks: avoid `if a = x & b = y then`; use successful receive/protected-message patterns, equality-pattern checks over already-bound identifiers, or nested simple checks.
- Stable identifiers: if Tamarin says a variable inside an event/check is not bound even though it came from a role argument like `pk(sk)`, introduce stable public identifiers in `process:` and pass those identifiers to roles/events. Do not keep reducible `pk(sk)` terms inside guarded branches.
- Derivation-check timeout: if diagnostics say "Derivation checks timed out", treat it as a compile/wellformedness blocker. Simplify destructor-heavy role code and proof-event payloads: bind decrypted or verified payload components once, emit compact variables in action facts, and avoid carrying `fst/snd`, decrypt, verify, hash, MAC, or KDF expressions into events and lemmas. Do not change target lemma names, reviewed expected outcomes, or add benchmark-specific helper lemmas.
- Formula guardedness: every universally quantified variable must appear in an action fact in the antecedent, or be moved to an existential quantifier in the consequent if it is only a witness there. For source/typing targets, keep one target lemma with the exact name and make the quoted formula a top-level conjunction of individually guarded `All ... ==> ...` formulas.
- Event arity mismatches: if a lemma references an action fact with arity N but events emit a different arity, repair the event schema and lemma references consistently. Prefer adding the missing proof-relevant argument when protocol_ir/proof_context requires it; only reduce lemma arity when the reviewed event schema is smaller.
- Formula-term scope: if diagnostics mention "Formula terms" or "uses terms of the wrong form", remove process-local fresh names and reducible terms over them from lemmas. Emit needed public keys/identities/session values as action-fact arguments and quantify those variables in the lemma.
- Reserved builtins: if Tamarin says a declared function is reserved by a builtin, remove that declaration and use the builtin symbol directly, or rename only the project-specific helper. Do not disable the builtin to keep the helper name.
- Target lemma names: if a target lemma was split, renamed, or suffixed, merge formulas back under the exact target lemma name and remove replacement lemmas.
- Lemma string syntax: keep each lemma formula as one quoted string block under `lemma name:`. Use Tamarin operators `&`, `|`, `==>`, `not`, `All`, and `Ex`; do not use escaped ProVerif/LaTeX operators like `\\/` or `/\\`.
- Expected-outcome mismatch: for reviewed ProvedSatisfying targets that are falsified, add missing checks, events, honesty/reveal conditions, or role state required by protocol_ir/proof_context. For reviewed CounterexampleFound targets that verify, restore only adversary-visible messages, protocol choices, reveal paths, or lemma conditions supported by protocol_ir/proof_context.
- Counterexample timeout: keep the same attack surface but bound proof search with one explicit adversary-controlled principal/key/session when supported. Do not make every peer honest or delete attacker-visible choices needed by another CounterexampleFound target.
- Reveal ordering: if a ProvedSatisfying secrecy/authentication target is falsified through a trace that uses a compromised secret before the reveal/corruption action fact, move the exception event before `out(secret)`. Do not weaken target lemmas or delete the reveal path."""

REPAIR_PATCH_CONTRACT = """Repair patch contract:
- Choose the smallest safe repair scope.
- Use `repair_scope: "local_patch"` for parser line/column errors, invalid builtins, lint issues, malformed role parameters, local lemma syntax, or a small localized wellformedness warning.
- Use `repair_scope: "full_rewrite"` when several generated state facts/rules are unreachable, a role needs a successful-branch rewrite, or the current Sapic+ cannot be fixed by a small replacement. Preserve the model structure as much as possible and keep behavior aligned to protocol_ir/proof_context.
- For local patches, return `patches` and omit `sapic_plus` unless a full rewrite is truly needed.
- A local patch must be either `{"type": "replace_text", "old": "exact existing text", "new": "replacement text"}` or `{"type": "replace_lines", "start_line": 5, "end_line": 5, "new": "replacement line(s)"}`.
- When a `replace_lines` patch replaces an entire role definition, include the original `let Role(...) =` line in the replaced range exactly once. Do not insert a second role header immediately before the old one.
- When returning multiple `replace_lines` patches, keep line numbers relative to the original input model; the patch engine applies those ranges from bottom to top."""

PROOF_REPAIR_TRIAGE_CONTRACT = """Proof-mismatch repair triage:
- Use this prompt for models that already passed generation/compile/proof-lint gates but failed target proof expectations. If diagnostics show a new parser, wellformedness, coverage, or proof-lint regression, repair that regression first and make the smallest patch needed to return to a clean model.
- If diagnostics contain only lemma-local proof-lint issues and no Tamarin proof result, use `repair_scope: "local_patch"` and patch only the named lemma. Do not rewrite compile-clean role processes.
- If proof-lint identifies event schema, event payload, event placement, or value-provenance problems, patch the smallest affected event/binding/check lines. Use `full_rewrite` only when the affected role segment cannot be isolated.
- If matching the reviewed proof expectation would require changing protocol_ir/proof_context semantics, reviewed assumptions, target lemma names, trace kinds, or expected outcomes, do not patch Sapic+. Return `repair_scope: "requires_ir_review"` with a concise reason and the affected IR/proof-context fields.
- Read the expected-vs-actual table before changing the theory. A falsified lemma is only a problem when its reviewed expected_state is ProvedSatisfying; a verified lemma is only a problem when its reviewed expected_state is CounterexampleFound.
- Preserve every target lemma name, trace kind, and reviewed expected outcome. Do not weaken lemmas, delete events, make obligations vacuous, or change expected outcomes to match the current proof result.
- When the failing or timed-out target is goal_type=source/typing, repair only the source target first. If the reviewed intent contains `Source obligations: ...`, make each listed obligation one separately guarded conjunct. If the intent is missing or ambiguous, do not rewrite protocol roles to guess a new source policy; state the limitation in repair_notes.
- Keep already-matching target lemmas matching. If a non-injective authentication target should prove while the corresponding injective target should remain CounterexampleFound, fix partner existence/authenticity without adding uniqueness restrictions that remove replay.
- Prefer repairing protocol checks, trusted setup, value provenance, event placement, reveal ordering, and event arguments. Edit lemma formulas only when the formula is inconsistent with the reviewed event schema or compromise contract.
- For `exists-trace` failures that show `falsified - no trace found`, treat the blocker as missing reachability of the honest witness path, not as a timeout or search-tuning problem. Reconstruct one concrete reviewed honest path end-to-end with the same setup and state dependencies before considering broader simplifications.
- Proof repair is not a general syntax cleanup stage. Do not rewrite a compile-clean role into equality patterns, successful-branch templates, or different parse structure unless diagnostics explicitly identify that syntax shape as the current blocker."""

PROOF_REPAIR_DIAGNOSTIC_ACTIONS = """Proof-mismatch diagnostic actions:
- For source/typing proof-lint issues, proof failures, or proof timeouts, repair the source lemma itself from the reviewed `Source obligations:` text when present, while preserving reviewed `IN_*` placement and compromise/reveal exceptions. Use existing `IN_*` parse/input events as antecedents and relate each to the specified prior `OUT_*` events or adversary knowledge `KU(x)`/`K(x)`. Do not replace this with `Secret`, `Compromise`, identity knowledge, or synthetic `A_input`/`B_input` helper events.
- For expected ProvedSatisfying but actual CounterexampleFound, identify why the counterexample reaches the bad event: missing peer/key validation, attacker-chosen payload accepted as trusted state, wrong event arguments, event emitted too early, reveal event after leak, or a missing role-state dependency. Patch that cause, not the lemma result.
- For certificate, public-key, or signed-identity protocols, do not let the receiver accept an arbitrary network-supplied public key as an authenticated peer. Bind the accepted peer key to reviewed trusted setup, a certificate/trust-anchor check, or an expected role parameter before emitting Commit/Secret events.
- For secrecy targets, the secret named in `Secret(...)` must come from the intended fresh/session value or an authenticated transcript component. If the receiver decrypts attacker-supplied ciphertext and immediately marks the plaintext secret, add the missing authenticity/trust check or bind the ciphertext to a signed/authenticated message.
- For authentication targets, Commit and Running events must carry the same actor, peer, and session tuple. If a trace uses an attacker-generated key/signature with no honest Running event, add the reviewed trust/certificate/peer-state check rather than changing the authentication lemma.
- For reveal/compromise exceptions, emit the reveal/corruption event before `out(secret)`. If the counterexample relies on uncompromised attacker choice rather than a leaked long-term key, do not try to fix it by delaying or gating the reveal process.
- For expected CounterexampleFound but actual ProvedSatisfying, first check whether the lemma is too weak or missing reviewed event correspondence; if so, repair the lemma shape. Otherwise restore only the reviewed attack surface: replay, adversary-visible messages, unauthenticated choices, or compromise paths supported by protocol_ir/proof_context.
- For exists-trace targets that fail, make the honest path reachable with the reviewed setup and checks. When the actual state is `falsified - no trace found`, prioritize restoring a single concrete witness path over generic simplification, and do not prove other all-traces lemmas by blocking the honest execution path.
- For proof timeout, use the Proof-timeout diagnosis section when present; otherwise apply the proof-engineering baseline in this order: bound topology, compact event payloads, consistent session/secret representation, then source-helper breadth. Preserve target names, reviewed expected outcomes, and the reviewed attack surface.
- If timeout or mismatch involves server-mediated session establishment, normalize proof events back to the reviewed event schema for each target direction before changing role behavior or lemma strength.
- If one patch makes the model stop compiling, undo the proof-repair-specific mistake and restore the last clean syntax before attempting another semantic proof repair."""


def _sanitize_proof_result_text(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = " ".join(value.split())
    return PROOF_RESULT_STEP_SUFFIX_RE.sub("", text).strip()


def _sanitize_prompt_payload(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {str(item_key): _sanitize_prompt_payload(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_sanitize_prompt_payload(item) for item in value]
    if key in PROOF_RESULT_TEXT_KEYS:
        return _sanitize_proof_result_text(value)
    return value


def _prompt_json(payload: dict[str, Any]) -> str:
    return json.dumps(_sanitize_prompt_payload(payload), ensure_ascii=False, indent=2)


def planner_prompt(
    case: ProtocolCase,
    expose_benchmark_goals: bool = False,
    include_case_goals: bool = False,
) -> str:
    include_goals = expose_benchmark_goals or include_case_goals
    if expose_benchmark_goals:
        goal_mode = "benchmark_reference"
    elif include_case_goals:
        goal_mode = "user_supplied_goals"
    else:
        goal_mode = "llm_discovered"
    payload = {
        "name": case.name,
        "description": case.description,
        "assumptions": case.assumptions,
        "goals": case.goals if include_goals else [],
        "benchmark_expected_results": getattr(case, "expected_results", {}) if expose_benchmark_goals else {},
        "goal_mode": goal_mode,
        "notes": case.notes,
        "difficulty": case.difficulty,
    }
    if expose_benchmark_goals:
        goal_instruction = (
            "The target lemma names, trace kinds, and expected outcomes are supplied for benchmark alignment. "
            "Copy these fields into the matching claims as reviewed metadata. Use them to keep the parsed model faithful "
            "to the described protocol and proof interface, not to invent a proof result."
        )
    elif include_case_goals:
        goal_instruction = (
            "User-supplied review goals are supplied. Preserve their lemma names, goal types, trace kinds, "
            "and expected results when present. Treat missing expected results as unknown."
        )
    else:
        goal_instruction = "No benchmark target lemma names are supplied. Infer appropriate security goals and lemma names from the natural-language protocol description."
    return f"""Parse this natural-language protocol into a Protocol IR candidate.
{goal_instruction}

Return one ProtocolIR candidate JSON object directly. Do not wrap it in a top-level `plan` object and do not nest it under `protocol_ir`.

Return this JSON shape:
{{
  "schema": "protocol_ir_pipeline_protocol_ir_v1",
  "protocol_name": "...",
  "roles": ["A", "B"],
  "principals": [{{"name": "A", "role_hint": "initiator"}}],
  "crypto": {{
    "builtins": ["asymmetric-encryption", "hashing"],
    "functions": ["kdf/2"],
    "equations": [],
    "assumptions": []
  }},
  "fresh_terms": [{{"name": "~na", "owner": "A", "purpose": "nonce generated by A"}}],
  "long_term_keys": [{{"name": "ltkA", "owner": "A", "public_term": "pk(ltkA)", "policy": "private setup/state; reveal only via explicit Reveal(...) if modeled"}}],
  "messages": [
    {{
      "label": "M1",
      "step": 1,
      "from": "A",
      "to": "B",
      "term": "aenc(<'tag1', A, ~na>, pkB)",
      "meaning": "A sends identity and nonce to B",
      "protection": "asymmetric-encryption",
      "sender_knows": ["~na", "pkB"],
      "receiver_can_decrypt": true,
      "receiver_must_treat_as_opaque": []
    }}
  ],
  "actions": [
    {{
      "action_id": "A_send_M1",
      "role": "A",
      "kind": "send",
      "generates": ["~na"],
      "message_in": [],
      "message_out": ["M1"],
      "checks": [],
      "events": ["OUT_M1(m1)"]
    }}
  ],
  "checks": [{{"role": "B", "condition": "decrypt and check tag/nonce", "source_message": "M1"}}],
  "events": [{{"name": "Commit", "arguments": ["A", "B", "session"], "role": "A", "when": "A completes"}}],
  "claims": [
    {{
      "lemma_name": "...",
      "goal_type": "secrecy|authentication|executability|source|property",
      "expected_state": "ProvedSatisfying",
      "trace_kind": "all-traces|exists-trace|unknown",
      "intent": "...",
      "event_schema": ["Secret(A,B,secret)"],
      "witness": "..."
    }}
  ],
  "compromise": {{"reveal_events": [], "policy": "record exact reveal/corruption events, exposed values, and lemma exception timing if the NL/goals mention compromise"}},
  "abstractions": ["..."],
  "modeling_assumptions": [],
  "semantic_constraints": [],
  "field_evidence": [
    {{
      "field_path": "claims.0.expected_state",
      "source_quote": "verbatim source span from the protocol input, if available",
      "evidence_kind": "direct|nearby|assumption|none",
      "reason": "short diagnostic reason for this field confidence",
      "evidence_confidence_score": 0.0,
      "consistency_confidence_score": 0.0,
      "semantic_impact_score": 1.0,
      "priority_llm": 0.0
    }}
  ],
  "resolved_open_questions": [],
  "open_questions": []
}}

ProtocolIR rules:
- This is the parser stage: produce ProtocolIR only, not Sapic+ or raw Tamarin code.
- Parse the protocol as described. Do not repair, strengthen, weaken, or redesign it to force a proof outcome.
- Preserve supplied goal metadata exactly when present: lemma name, goal type, trace kind, expected result/state, and named event or action vocabulary.
- Preserve proof-relevant message semantics: sender/receiver order, tags, identities, payload fields, crypto relationships, argument order, and values used by checks/events/claims. Use compact symbolic labels for large terms, but keep dependencies explicit in `meaning`, `actions`, `checks`, `events`, `semantic_constraints`, or `abstractions`.
- Preserve value provenance and trust boundaries: setup/state, public identity, fresh generation, received network input, decrypted or verified value, derived key/material, opaque forwarded data, and explicit compromise/reveal behavior.
- Put checks and events only where the role has the evidence for their arguments through generation, state, receive, decryption, verification, derivation, or opaque carry.
- If an expected counterexample is supplied, keep the described attack surface when it follows from the input; do not manufacture a weaker protocol. If a satisfying result is supplied, keep the checks/events/reveal conditions meaningful and non-vacuous.
- Record proof-critical uncertainty in `modeling_assumptions`, `semantic_constraints`, `field_evidence`, or `open_questions` instead of silently choosing a stronger or weaker model.
- Use function-style symbolic terms in message `term`, such as `aenc(m, pk)`, `sign(m, sk)`, `h(m)`, or `kdf(...)`, and avoid notation that cannot be translated directly.
- Every supplied target lemma must have a matching `claims[].lemma_name`.
- `field_evidence` must cover every non-empty field that will be shown in the review UI. Add one `field_evidence` item for each of these paths when present:
  `fresh_terms.i.name`, `fresh_terms.i.owner`, `fresh_terms.i.purpose`;
  `long_term_keys.i.name`, `long_term_keys.i.owner`, `long_term_keys.i.public_term`, `long_term_keys.i.policy`;
  `messages.i.label`, `messages.i.from`, `messages.i.to`, `messages.i.protection`, `messages.i.term`, `messages.i.meaning`;
  `checks.i.role`, `checks.i.condition`, `checks.i.source_message`, `checks.i.action`;
  `events.i.name`, `events.i.role`, `events.i.when`, `events.i.arguments`;
  `claims.i.lemma_name`, `claims.i.goal_type`, `claims.i.trace_kind`, `claims.i.expected_state`, `claims.i.event_schema`.
- In `field_evidence`, use ProtocolIR paths exactly as listed above, use `evidence_kind="none"` when no direct source span supports a field, and use 0.0-1.0 scores for evidence confidence, consistency confidence, semantic impact, and review priority. Higher priority means review sooner.

Protocol input:
{_prompt_json(payload)}
"""


def planner_retry_prompt(
    original_prompt: str,
    raw_response: str,
    failure_reason: str,
    attempt: int,
    max_attempts: int,
) -> str:
    raw = raw_response or ""
    tail = raw[-1600:] if raw else ""
    return f"""The previous planner response was not parseable JSON.
Failure reason: {failure_reason}
Attempt: {attempt} of {max_attempts}

Return one complete valid JSON object for the original planner task. Do not include Markdown.

Retry rules:
- Make the JSON shorter than the previous response.
- Close every object, array, and string.
- Do not inline very large nested crypto expressions. Use compact symbolic labels for transcripts, derived keys, MAC inputs, and session identifiers.
- Keep message `term` fields short and use `meaning`, `sender_knows`, `actions`, `checks`, `events`, `semantic_constraints`, `crypto.assumptions`, and `abstractions` for explanatory detail.
- Preserve goal metadata, value provenance, check/event ordering, opaque forwarding, crypto argument order, and compromise/reveal scope.
- Do not repair, weaken, or redesign the protocol to force an expected result.
- Every supplied target lemma must have a matching ProtocolIR claim.
- Preserve and update exhaustive `field_evidence` coverage for every non-empty review-UI field listed in the original prompt.

Previous raw response tail, for debugging only:
{tail}

Original ProtocolIR parser task:
{original_prompt}
"""


def sapic_json_retry_prompt(
    original_prompt: str,
    raw_response: str,
    failure_reason: str,
    attempt: int,
    max_attempts: int,
) -> str:
    raw = raw_response or ""
    tail = raw[-2400:] if raw else ""
    return f"""The previous Sapic+ generation response was not usable as JSON.
Failure reason: {failure_reason}
Attempt: {attempt} of {max_attempts}

Return exactly one complete valid JSON object for the original Sapic+ generation task.

JSON shape:
{{
  "sapic_plus": "theory ...\\nbegin\\n...\\nprocess:\\n...\\nend",
  "modeling_notes": ["..."],
  "expected_limitations": ["..."]
}}

Retry rules:
- Do not include Markdown fences or prose outside the JSON object.
- Keep the Sapic+ theory complete; include `process:` and all target lemmas.
- Escape every newline in `sapic_plus` as `\\n`.
- Close every JSON string, array, and object.

Previous raw response tail:
{tail}

Original Sapic+ generation task:
{original_prompt}
"""


def _reviewed_proof_targets_payload(proof_spec: ProofSpec | None) -> dict | None:
    if not proof_spec:
        return None
    return {
        "case": proof_spec.case,
        "targets": [
            {
                "name": item.name,
                "trace_kind": item.trace_kind,
                "reviewed_expected_outcome": item.expected_state,
                "goal_type": item.goal_type,
                "intent": item.intent,
                "required_events": item.required_events,
            }
            for item in proof_spec.expectations
        ],
    }


def _proof_context_payload(ir_bundle: dict | None) -> dict | None:
    if not ir_bundle:
        return None
    proof_context = ir_bundle.get("proof_context")
    if not isinstance(proof_context, dict):
        legacy_contract = ir_bundle.get("proof_contract")
        proof_context = legacy_contract if isinstance(legacy_contract, dict) else None
    if not isinstance(proof_context, dict):
        return None

    semantic_constraints = proof_context.get("semantic_constraints")
    if semantic_constraints is None:
        semantic_contract = proof_context.get("semantic_assumption_contract")
        if isinstance(semantic_contract, dict):
            semantic_constraints = semantic_contract.get("semantic_constraints")

    payload = {
        "target_lemmas": proof_context.get("target_lemmas", []),
        "event_obligations": proof_context.get("event_obligations", []),
        "proof_obligations": proof_context.get("proof_obligations", {}),
        "preservation_boundary": proof_context.get("preservation_boundary", {}),
        "semantic_constraints": semantic_constraints or [],
        "generation_policies": proof_context.get("generation_policies", []),
    }
    return {
        key: value
        for key, value in payload.items()
        if value not in (None, {}, [])
    }


def sapic_prompt(
    case: ProtocolCase,
    plan: dict,
    proof_spec: ProofSpec | None = None,
    ir_bundle: dict | None = None,
    expose_benchmark_goals: bool = False,
    regeneration_diagnostics: str = "",
) -> str:
    payload = {
        "case": {"name": case.name, "difficulty": case.difficulty},
        "protocol_ir": (ir_bundle or {}).get("protocol_ir") if ir_bundle else None,
        "proof_context": _proof_context_payload(ir_bundle),
        "abstraction_hints": (ir_bundle or {}).get("abstraction_hints") if ir_bundle else None,
        "ir_validation": (ir_bundle or {}).get("validation") if ir_bundle else None,
        "field_reviews": (ir_bundle or {}).get("field_reviews") if ir_bundle else None,
        "reviewed_proof_targets": _reviewed_proof_targets_payload(proof_spec),
        "previous_generation_diagnostics": regeneration_diagnostics[-12000:] if regeneration_diagnostics else "",
    }
    regeneration_instruction = (
        "\n\tPrevious complete Sapic+ candidates failed the compile/wellformedness gate. "
        "Use previous_generation_diagnostics only as negative feedback and generate a fresh complete theory from scratch. "
        "Do not patch or preserve malformed syntax from the failed candidate."
        if regeneration_diagnostics
        else ""
    )
    return f"""Generate a complete Sapic+ theory from the reviewed protocol artifacts.
	{regeneration_instruction}

	{SAPIC_GENERATION_SOURCE_CONTRACT}
	{SAPIC_GENERATION_PROOF_TARGET_CONTRACT}
	{SAPIC_GENERATION_ABSTRACTION_CONTRACT}
	{SAPIC_GENERATION_PROVENANCE_CONTRACT}
	{PROOF_ENGINEERING_BASELINE}
	{SERVER_MEDIATED_BASELINE}

	{SAPIC_SYNTAX_CONTRACT}
	{SAPIC_PROCESS_REACHABILITY_CONTRACT}
	{PROOF_GOAL_CONTRACT}

Return this JSON shape:
{{
  "sapic_plus": "theory ...\\nbegin\\n...\\nprocess:\\n...\\nend",
  "modeling_notes": ["..."],
  "expected_limitations": ["..."]
}}

Input:
{_prompt_json(payload)}
"""


def repair_prompt(
    case: ProtocolCase,
    plan: dict,
    sapic_plus: str,
    diagnostics: str,
    proof_spec: ProofSpec | None = None,
    ir_bundle: dict | None = None,
    expose_benchmark_goals: bool = False,
) -> str:
    payload = {
        "case": {"name": case.name, "difficulty": case.difficulty},
        "protocol_ir": (ir_bundle or {}).get("protocol_ir") if ir_bundle else None,
        "proof_context": _proof_context_payload(ir_bundle),
        "abstraction_hints": (ir_bundle or {}).get("abstraction_hints") if ir_bundle else None,
        "ir_validation": (ir_bundle or {}).get("validation") if ir_bundle else None,
        "reviewed_proof_targets": _reviewed_proof_targets_payload(proof_spec),
        "sapic_plus": sapic_plus,
        "diagnostics": diagnostics[-12000:],
    }
    return f"""Repair the current Sapic+ theory using compiler/verifier feedback.

	{REPAIR_TRIAGE_CONTRACT}
	{REPAIR_DIAGNOSTIC_ACTIONS}
	{REPAIR_PATCH_CONTRACT}
	{PROOF_ENGINEERING_BASELINE}
	{SERVER_MEDIATED_BASELINE}

	{SAPIC_SYNTAX_CONTRACT}
	{SAPIC_PROCESS_REACHABILITY_CONTRACT}
	{PROOF_GOAL_CONTRACT}

Return this JSON shape:
{{
  "repair_scope": "local_patch|full_rewrite",
  "patches": [
    {{"type": "replace_text", "old": "exact existing text", "new": "replacement text"}},
    {{"type": "replace_lines", "start_line": 1, "end_line": 1, "new": "replacement line(s)"}}
  ],
  "sapic_plus": "repaired complete theory, only for full_rewrite or fallback",
  "repair_notes": ["..."]
}}

Input:
{_prompt_json(payload)}
"""


def proof_repair_prompt(
    case: ProtocolCase,
    plan: dict,
    sapic_plus: str,
    diagnostics: str,
    proof_spec: ProofSpec | None = None,
    ir_bundle: dict | None = None,
    expose_benchmark_goals: bool = False,
) -> str:
    payload = {
        "case": {"name": case.name, "difficulty": case.difficulty},
        "protocol_ir": (ir_bundle or {}).get("protocol_ir") if ir_bundle else None,
        "proof_context": _proof_context_payload(ir_bundle),
        "abstraction_hints": (ir_bundle or {}).get("abstraction_hints") if ir_bundle else None,
        "ir_validation": (ir_bundle or {}).get("validation") if ir_bundle else None,
        "reviewed_proof_targets": _reviewed_proof_targets_payload(proof_spec),
        "sapic_plus": sapic_plus,
        "diagnostics": diagnostics[-12000:],
    }
    return f"""Repair the current Sapic+ theory for proof expectation mismatches.

	{PROOF_REPAIR_TRIAGE_CONTRACT}
	{PROOF_REPAIR_DIAGNOSTIC_ACTIONS}
	{REPAIR_PATCH_CONTRACT}
	{PROOF_ENGINEERING_BASELINE}
	{SERVER_MEDIATED_BASELINE}

	{SAPIC_SYNTAX_CONTRACT}
	{PROOF_GOAL_CONTRACT}

Return this JSON shape:
{{
  "repair_scope": "local_patch|full_rewrite|requires_ir_review",
  "patches": [
    {{"type": "replace_text", "old": "exact existing text", "new": "replacement text"}},
    {{"type": "replace_lines", "start_line": 1, "end_line": 1, "new": "replacement line(s)"}}
  ],
  "sapic_plus": "repaired complete theory, only for full_rewrite or fallback",
  "ir_review_reason": "required only when repair_scope is requires_ir_review",
  "affected_ir_fields": ["protocol_ir.messages.0.term", "proof_context.target_lemmas.0.expected_state"],
  "repair_notes": ["..."]
}}

Input:
{_prompt_json(payload)}
"""


def ir_repair_prompt(
    case: ProtocolCase,
    plan: dict,
    ir_bundle: dict,
    proof_spec: ProofSpec,
    expose_benchmark_goals: bool = False,
) -> str:
    payload = {
        "name": case.name,
        "description": case.description,
        "assumptions": case.assumptions,
        "goals": case.goals if expose_benchmark_goals else [],
        "goal_mode": "benchmark_reference" if expose_benchmark_goals else "llm_discovered",
        "plan": plan,
        "proof_spec": proof_spec.prompt_payload(),
        "protocol_ir": ir_bundle.get("protocol_ir"),
        "validation": ir_bundle.get("validation"),
        "proof_context": _proof_context_payload(ir_bundle),
    }
    return f"""Repair only the lightweight ProtocolIR JSON.

Validation failed before Sapic+ generation. Fix the ProtocolIR so it can be used as a stable parser output.

Rules:
- Return one corrected ProtocolIR candidate JSON object directly.
- Use schema `protocol_ir_pipeline_protocol_ir_v1`.
- Do not wrap the result in a top-level `plan` object and do not nest it under `protocol_ir`.
- Do not output Sapic+ or raw Tamarin code.
- Preserve all target proof_spec lemma names and expected_state values.
- Every message needs label, step, from, to, term, protection, receiver_can_decrypt.
- Every target proof_spec lemma needs a matching `claims[].lemma_name`.
- Do not invent protocol messages that are not justified by the natural-language description; add only missing structural metadata.

Input:
{_prompt_json(payload)}
"""
