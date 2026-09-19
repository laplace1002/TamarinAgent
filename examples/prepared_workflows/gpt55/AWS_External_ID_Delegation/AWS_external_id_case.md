# AWS External-ID Delegation

This document records the GPT-5.5 experiment for the non-standard AWS cross-tenant delegation case. The workflow translates a source-grounded natural-language description into ProtocolIR, applies UI-visible review edits, generates SAPIC+/Tamarin, and checks the proof targets extracted from the natural-language input.

The complete raw run, including LLM transcripts, repair candidates, and full Tamarin diagnostics, remains under:

```text
runs/nonstandard_aws_gpt55_20260919
```

The prepared workflow directory contains the compact publication-facing artifacts.

Publication scope: `modeling_contract.reviewed.json` and the entire `review/` directory are local-only and excluded from the current GitHub tree. References to those paths below identify local review evidence, not files included in the published case.

This is a results archive. The raw `runs/` directory and intermediate repair candidates are retained locally, not uploaded. `proof/result.json` omits embedded diagnostic text while preserving all proof outcomes and per-lemma metadata; its `archive_provenance` field records the original result's SHA-256 hash. The continuation command below requires the original local run and pipeline environment, not only a fresh checkout of this case directory.

## 1. Case and input

The scenario models a service provider serving Alice and Mallory. The provider assumes customer-owned roles through STS. Three isolated configurations are compared:

1. `principal_only`: STS checks only the provider principal.
2. `caller_supplied`: STS checks an external ID, but the customer-supplied value is forwarded.
3. `provider_bound`: the provider obtains the external ID from its trusted mapping for the authenticated customer.

The attacker controls Mallory's authenticated customer requests and knows both public role identifiers and external IDs. The security question is whether Mallory can cause an operation on Alice's resource, while Alice's legitimate operation remains executable in every configuration.

The natural-language input is:

```text
input/natural_language.md
```

The source mechanisms and experiment-specific assumptions are listed separately in:

```text
input/sources.json
```

The pipeline input has empty `goals` and `assumptions` arrays. Security targets were extracted by the existing GPT-5.5 planner from the NL description rather than supplied as formal lemmas:

```text
input/case.json
proof/spec.json
```

## 2. Source and provenance

The natural-language description is an author-written, source-grounded scenario; it is not a verbatim quotation from AWS documentation. The official mechanisms used as its basis are:

- [AWS IAM: The confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html), which motivates distinguishing the provider from the customer that authorized a request and explains the role of an external ID.
- [AWS IAM: Access to AWS accounts owned by third parties](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html), which describes third-party role assumption and provider-assigned external IDs.

The source-to-NL mapping is:

| Natural-language part | Source basis | Experiment-specific additions |
|---|---|---|
| **Source-grounded mechanism** | Cross-account role assumption, provider/customer distinction, and external-ID use are based on the two AWS sources above. | The prose uses abstract roles and resources instead of reproducing AWS API or policy syntax. |
| **Explicit experimental scope and setup** | The provider, STS, customer-owned role, and customer-specific external-ID relationship follow the documented delegation pattern. | Alice/Mallory, three isolated configurations, public identifiers, authenticated channels, job correlation, and the trusted provider mapping are controlled modeling assumptions. |
| **Security questions** | The confused-deputy motivation supplies the authorization question. | Tenant isolation, the Mallory-to-Alice attack witness, and Alice's legitimate-job executability are author-defined research targets. |

The complete source metadata and the distinction between source mechanisms and experimental design are recorded in:

```text
input/sources.json
```

The sources were recorded on **September 19, 2026**. They ground the scenario's mechanism; they do not establish that the abstract model is a complete formalization of AWS IAM or STS.

## 3. ProtocolIR and UI review

The raw and reviewed IR artifacts are:

```text
ir/protocol_ir.json
ir/protocol_ir.reviewed.json
```

The review changed 18 existing UI-visible cells and added no rows. The cell-level audit is:

```text
review/ui_cell_edits.json
```

The reviewed contract is retained as provenance:

```text
modeling_contract.reviewed.json
```

## 4. Generation and verification

The model was generated from the reviewed contract with GPT-5.5. No generated model or formal lemma was manually edited. The final models are:

```text
final/model.spthy
final/model.msr.spthy
```

The compact proof result is:

```text
proof/result.json
```

The final proof run used the existing pipeline with a 240-second per-lemma timeout and zero proof-repair model changes. The final model passed the repository's static and event-alignment checks:

```text
review/static_check.json
review/event_alignment.json
```

To continue the reviewed run without re-running NL-to-IR:

```bash
python3 run_reviewed_pipeline.py \
  --run-dir runs/nonstandard_aws_gpt55_20260919 \
  --provider openai --model gpt-5.5 --api-mode responses \
  --reasoning-effort medium --max-generation-rounds 1 \
  --max-repair-rounds 0 --tamarin-timeout 120 \
  --lemma-proof-timeout 240 --resume
```

## 5. Tamarin results

| Target | Actual result | Meaning |
|---|---|---|
| `tenant_isolation_principal_only` | `falsified - found trace (9 steps)` | Principal-only delegation permits a cross-tenant operation. |
| `tenant_isolation_caller_supplied` | `falsified - found trace (10 steps)` | A caller-controlled public external ID does not bind the request to the authenticated customer. |
| `tenant_isolation_provider_bound` | `verified (48 steps)` | The provider-bound configuration preserves tenant isolation in this model. |
| `mallory_can_access_alice_resource_principal_only` | `verified (12 steps)` | The expected attack witness is reachable. |
| `mallory_can_access_alice_resource_caller_supplied` | `verified (12 steps)` | The expected attack witness is reachable. |
| `mallory_can_access_alice_resource_provider_bound` | `falsified - no trace found (40 steps)` | The expected Mallory-to-Alice attack has no trace. |
| `alice_legitimate_job_principal_only_executable` | `verified (12 steps)` | Alice's legitimate operation remains executable. |
| `alice_legitimate_job_caller_supplied_executable` | `verified (12 steps)` | Alice's legitimate operation remains executable. |
| `alice_legitimate_job_provider_bound_executable` | `verified (12 steps)` | The repair does not reject all legitimate jobs. |

The proof status is `expected-matched`: all nine actual outcomes agree with the reviewed expectations. `verified` on an attack `exists-trace` target means that the attack exists; it does not mean that the configuration is secure.

## 6. Interpretation boundary

This case demonstrates preservation of the distinction between provider authentication and customer authorization. It is not a complete IAM/STS model. The semantic review records three qualifications:

- an automatic compile repair moves one provider-bound role check to the Provider response boundary;
- the unused `AssumeRoleSuccess` auxiliary event has a reviewed-schema argument mismatch; and
- resource credential validation is modeled transitively through the honest Provider.

Therefore the target results support the stated authorization comparison, but do not establish full IR/model equivalence or complete AWS policy correctness. The detailed review is:

```text
review/model_review.json
```
