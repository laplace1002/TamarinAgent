# Generated Models vs. Manual Models: Direct Case Analysis

## 1. Purpose

This comparison examines models produced by our GPT-5.5 workflow and the independently developed Tamarin models in AutoSM. We select representative protocols and ask:

1. What modeling decisions are the same
2. Where do the two models differ
3. Does the difference change the protocol semantics or only the presentation
4. What does the difference tell us about the current strengths and limits of LLM-assisted modeling

## 2. Files Being Compared

Generated models are stored in:

```text
examples/prepared_workflows/gpt55/<CASE>/final/model.spthy
```

The reviewed IR for each model is stored in:

```text
examples/prepared_workflows/gpt55/<CASE>/ir/protocol_ir.reviewed.json
```

The manual models are taken from:

```text
https://github.com/zerrymore/AutoSM/tree/master/benchmark
```

AutoSM provides separate initiator (`-P`) and responder (`-R`) models. We read both files as one protocol-level reference, while preserving the fact that the manual model separates the two roles.

## 3. Selected Cases

The selected cases are chosen because each of them has a different modeling challenge rather than simply because it has a different size.

| Case | Why it is representative |
|---|---|
| NSPK | Short baseline for message direction, nonce provenance, agreement events, and compromise handling. |
| SSH | Stateful and repeated interaction with verified and unverified host-key paths. |

## 4. NSPK

### What is similar

Both models contain the classic three-message NSPK exchange:

1. the initiator sends an encrypted nonce;
2. the responder returns the initiator's nonce together with a fresh responder nonce
3. the initiator returns the responder's nonce.

Both models also use `Commit`, `Running`, and `Secret` events and include nonce secrecy and injective-agreement lemmas. This shows that the generated model recognizes the basic protocol shape.

### Important differences

The generated model uses a small, fixed process configuration with `A_Initiator` and `B_Responder`. It creates `skA`, `skB`, and `skC`, publishes all public keys, and also publishes `skC`:

```text
out(skC);
```

The AutoSM model instead uses replicated sessions and explicit compromise processes. It can reveal `skA` or `skB` through `RevLtk` events, and its secrecy and agreement lemmas explicitly exclude traces after those reveals.

The generated model therefore captures one intended execution more directly, but it does not preserve the manual model's unbounded-session and explicit long-term-key-compromise structure. Its `nonce_secrecy` lemma also has no reveal exception, even though a private key is exposed in the process configuration.

### Insight

For a simple protocol, an LLM can reproduce the visible message flow and familiar lemma names while still changing the threat model in a fundamental way. The main risk is LLM may silently simplify replication and compromise assumptions.


## 5. SSH

### What is similar

Both models contain client and server exchange contexts, ephemeral Diffie--Hellman values, host-key material, key derivation, encrypted traffic keys, and secrecy/agreement targets. Both distinguish a verified host-key path from an unverified path and expose a server-side secret/finished-key lifecycle.

### Important differences

The generated model has two explicit client behaviors: `HonestVerified` and `ClientUnverified`. Its process configuration publishes the host public key and an attacker-controlled signing key/material, allowing the model to represent both verified and unverified host-key behavior in one theory.

The AutoSM reference separates initiator and responder rules and uses explicit persistent state, replicated sessions, and reveal processes. Its event facts and lemmas are tied to the rule transitions that store intermediate state and later consume it. The generated model instead keeps much of the state in sequential `let` bindings inside role processes and emits a large number of derived-key events.

The semantic question is therefore whether the two models give the attacker the same ability to replay, substitute, or compromise host-key material, and whether `ClientAcceptVerified` and `ClientAcceptUnverified` occur after equivalent checks. These questions cannot be answered from matching lemma names alone.

### Insight

Stateful protocols expose a limitation of direct LLM-to-model translation: a sequential script can describe the intended successful exchange without preserving the state machine that controls which later transitions are possible. For SSH-like protocols, the most important comparison is not the number of derived keys but the relationship between stored state, repeated sessions, host-key trust decisions, and attacker-controlled alternatives.

## 9. Cross-Case Findings

The direct comparison suggests four recurring patterns.

### 9.1 LLMs preserve protocol narratives better than threat models

Across NSPK, Naxos, and KEMTLS, the generated models generally preserve the visible order of the honest exchange. The larger differences concern replication, key compromise, attacker knowledge, and the conditions under which a role accepts a message. These assumptions are often less prominent in the natural-language description and therefore easier for the generator to simplify.

### 9.2 Complexity changes the location of the error

For NSPK, the main risk is an overly simplified process configuration and missing compromise exceptions. For Naxos, it is exact key construction. For KEMTLS, it is phase and acceptance boundaries. For SSH and SPLICE, it is persistent state, repeated interaction, and restrictions. This is why one generic “model correctness” score would be less informative than case-based semantic analysis.

### 9.3 A compiled model can still be semantically weaker or stronger

Tamarin compilation checks whether the generated syntax and symbolic theory are acceptable. It does not check whether a generated event is emitted after the right verification, whether a compromise branch is missing, or whether a state token has been replaced by an unconstrained sequential binding. Successful proof results must therefore be read together with these model-to-model differences.

### 9.4 ProtocolIR review is most valuable at semantic boundaries

The most useful review fields are not generic descriptions. They are message boundaries, value provenance, check conditions, event placement, compromise assumptions, and proof-target scope. These fields explain why two models with similar messages can nevertheless have different security meanings.
