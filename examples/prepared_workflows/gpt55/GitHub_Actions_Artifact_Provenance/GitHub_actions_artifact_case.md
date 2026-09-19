# GitHub Actions Artifact Provenance

This document records the GPT-5.5 experiment for the non-standard CI artifact-provenance case. The workflow translates a source-grounded natural-language description into ProtocolIR, applies UI-visible review edits, generates SAPIC+/Tamarin, and checks the proof targets extracted from the natural-language input.

The complete raw run, including LLM transcripts, repair candidates, and full Tamarin diagnostics, remains under:

```text
runs/nonstandard_github_gpt55_20260919
```

The prepared workflow directory contains the compact publication-facing artifacts.

Publication scope: `modeling_contract.reviewed.json` and the entire `review/` directory are local-only and excluded from the current GitHub tree. References to those paths below identify local review evidence, not files included in the published case.

This is a results archive. The raw `runs/` directory and intermediate repair candidates are retained locally, not uploaded. `proof/result.json` omits embedded diagnostic text while preserving all proof outcomes and per-lemma metadata; its `archive_provenance` field records the original result's SHA-256 hash. The continuation command below requires the original local run, pipeline environment, and heuristic wrapper, not only a fresh checkout of this case directory.

## 1. Case and input

The scenario models a low-privilege producer workflow, a `workflow_run`-style privileged consumer, an artifact store, and a deployment service. Three isolated consumer configurations are compared:

1. `name_only`: select an artifact by the ordinary name `package` without binding it to the triggering run.
2. `run_bound`: bind the artifact to the exact triggering run, but allow fork runs to trigger the consumer.
3. `trusted_origin`: require protected-repository and protected-branch metadata in addition to exact-run binding.

The attacker controls fork commits and artifact bodies, but cannot forge authenticated CI/store metadata or acquire the deployment credential. The security questions distinguish exact run provenance from trusted source authorization and require a legitimate protected-branch deployment in every configuration.

The natural-language input is:

```text
input/natural_language.md
```

The source mechanisms and experiment-specific assumptions are listed separately in:

```text
input/sources.json
```

The pipeline input has empty `goals` and `assumptions` arrays. Security targets were extracted by the existing GPT-5.5 planner from the NL description:

```text
input/case.json
proof/spec.json
```

## 2. Source and provenance

The natural-language description is an author-written, source-grounded scenario; it is not a verbatim quotation from GitHub documentation. The official mechanisms used as its basis are:

- [GitHub Security Lab: Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/), which motivates the privilege boundary between untrusted pull-request code and a privileged follow-up workflow.
- [GitHub Security Lab: New patterns and mitigations for untrusted workflow execution](https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations/), which provides the artifact and privileged-workflow security context.
- [GitHub Docs: Events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), which provides the `workflow_run` event and its completed-run trigger semantics.

The source-to-NL mapping is:

| Natural-language part | Source basis | Experiment-specific additions |
|---|---|---|
| **Source-grounded mechanism** | A lower-privilege pull-request workflow, a privileged `workflow_run` consumer, attacker-controlled artifacts, and the privilege boundary are based on the GitHub Security Lab sources and event documentation above. | The model abstracts artifact transfer and deployment instead of modeling arbitrary script execution or the full GitHub Actions implementation. |
| **Explicit experimental scope and setup** | Fork-originated code, completed-run metadata, and a follow-up workflow reflect the documented untrusted-workflow pattern. | One protected repository, a designated protected branch, immutable authenticated platform/store records, three isolated selection policies, and the attacker's inability to forge metadata are controlled modeling assumptions. |
| **Security questions** | The source material motivates separating untrusted-code execution from privileged workflow behavior. | Exact run binding, trusted-origin authorization, fork-artifact reachability, and legitimate deployment executability are author-defined research targets. |

The complete source metadata and the distinction between source mechanisms and experimental design are recorded in:

```text
input/sources.json
```

The sources were recorded on **September 19, 2026**. They ground the scenario's mechanism; they do not establish that the abstract model is a complete formalization of GitHub Actions, artifact storage, or deployment security.

## 3. ProtocolIR and UI review

The raw and reviewed IR artifacts are:

```text
ir/protocol_ir.json
ir/protocol_ir.reviewed.json
```

The review changed 27 existing UI-visible cells and added no rows. The cell-level audit is:

```text
review/ui_cell_edits.json
```

The reviewed contract is retained as provenance:

```text
modeling_contract.reviewed.json
```

## 4. Generation and verification

The final accepted model is the unbounded replicated second-generation model. No generated model or formal lemma was manually edited. The final models are:

```text
final/model.spthy
final/model.msr.spthy
```

The compact proof result is:

```text
proof/result.json
```

The final proof run reused the existing model, used Tamarin heuristic `s`, allowed 180 seconds per lemma, and disabled automatic model repair. The final model passed the repository's static and event-alignment checks:

```text
review/static_check.json
review/event_alignment.json
```

To continue the reviewed run without re-running NL-to-IR:

```bash
python3 run_reviewed_pipeline.py \
  --run-dir runs/nonstandard_github_gpt55_20260919 \
  --provider openai --model gpt-5.5 --api-mode responses \
  --reasoning-effort medium --max-generation-rounds 1 \
  --max-repair-rounds 0 \
  --tamarin-bin examples/nonstandard_authorization_gpt55_20260919/tamarin_proof_s \
  --tamarin-timeout 120 --lemma-proof-timeout 180 --resume
```

## 5. Tamarin results

| Target | Actual result | Meaning |
|---|---|---|
| `name_only_fork_artifact_privileged_use_reachable` | `verified (12 steps)` | A fork artifact can reach privileged use under name-only selection. |
| `run_bound_fork_artifact_privileged_use_reachable` | `verified (13 steps)` | Exact-run binding alone does not reject a fork-triggered deployment. |
| `name_only_all_privileged_uses_are_trusted_origin` | `falsified - found trace (12 steps)` | Name-only selection admits an untrusted source. |
| `run_bound_all_privileged_uses_are_trusted_origin` | `falsified - found trace (12 steps)` | Exact run binding is not source authorization. |
| `trusted_origin_all_privileged_uses_are_trusted_origin` | `verified (10 steps)` | Protected source metadata is preserved for trusted-origin use. |
| `name_only_selected_artifact_belongs_to_triggering_run` | `falsified - found trace (10 steps)` | Name-only lookup can select an artifact from another run. |
| `run_bound_selected_artifact_belongs_to_triggering_run` | `verified (3 steps)` | Run binding preserves exact producer-run identity. |
| `trusted_origin_selected_artifact_belongs_to_triggering_run` | `verified (3 steps)` | Trusted-origin selection also preserves exact producer-run identity. |
| `legitimate_protected_branch_deployment_executable_all_configs` | `verified (29 steps)` | All three configurations retain a legitimate protected-branch deployment path. |

The proof status is `expected-matched`: all nine actual outcomes agree with the reviewed expectations. `verified` on an attack `exists-trace` target means that the attack exists; it does not mean that the configuration is secure.

## 6. Interpretation boundary

This case demonstrates that accurate artifact/run provenance is different from authorization of the source that produced the run. Signatures idealize authenticated platform and store statements; `PrivilegedUse` abstracts deployment authorization and does not model arbitrary script execution. The case is not a complete GitHub Actions or CI-platform verification.

The detailed provenance and abstraction review is:

```text
review/model_review.json
review/provenance_audit.json
```
