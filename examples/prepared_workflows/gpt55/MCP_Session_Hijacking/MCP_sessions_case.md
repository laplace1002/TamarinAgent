# MCP Session Hijacking

This document records the complete experiment for the `MCP_Session_Hijacking` case that converts Natural language protocol description to Tamarin model and proves certain security properties. It explains how we generated the ProtocolIR, reviewed it through the UI, generated the SAPIC+ and Tamarin models, and checked the reviewed proof targets.

The original input, reviewed artifacts, generated models, proof results, and review evidence are all kept under

```text
examples/prepared_workflows/gpt55
```

## 1. Case and Input

The case comes from the official MCP security guidance (https://github.com/modelcontextprotocol/modelcontextprotocol/blob/aa8ce049f089f92618340190d4ece141f663310d/docs/docs/2025-06-18/tutorials/security/security_best_practices.mdx) and describes two related attacks:

1. **Prompt-injection through session hijacking.** A client connects to Server A and receives a session ID. An attacker obtains that ID and sends a malicious event to Server B. Server B places the event in a shared queue, Server A retrieves it using the same ID, and Server A forwards the payload to the client.
2. **Session impersonation.** An attacker obtains a persistent session ID and uses it to call an MCP server. If the server performs no additional authorization check, it treats the attacker as the original client.

The natural-language input used in this experiment is:

```text
examples/prepared_workflows/gpt55/MCP_Session_Hijacking/input/natural_language.md
```

## 2. Generate the ProtocolIR

From the project directory, start the review UI with GPT-5.5:

```bash
cd /Users/ella/code/TAMARIN-Agent-master/public_contract_review_ui

python3 run_contract_review_ui.py \
    --run-dir runs/mcp_session_hijacking_gpt55 \
    --provider openai \
    --model gpt-5.5 \
    --api-mode responses \
    --reasoning-effort medium \
    --max-plan-retries 2 \
    --max-generation-rounds 3 \
    --max-repair-rounds 6 \
    --max-tokens 38888 \
    --host 127.0.0.1 \
    --port 8765
```

Open the UI at:

```text
http://127.0.0.1:8765/
```

Enter or load the official natural-language input, leave `goals` and `assumptions` empty, and select **Generate IR**.

The raw IR is:

```text
runs/mcp_session_hijacking_gpt55/ir/protocol_ir.json
```

## 3. Confidence-guided IR Review

Then human can review whether the IR-generated fields are correct or faithful based on the confidence scores by clicking "review details". 

Here we changed **six existing UI-visible cells** and added no rows. The reviewed artifacts are:

```text
runs/mcp_session_hijacking_gpt55/ir/protocol_ir.reviewed.json
runs/mcp_session_hijacking_gpt55/ir/protocol_ir.reviewed.active.json
```


## 4. Generate the SAPIC+ and Tamarin Models

The reviewed pipeline is provided by `run_reviewed_pipeline.py`.

### 4.1 Full Pipeline

Use this command when you want to regenerate SAPIC+ from the reviewed IR and then run compile/repair, proof/repair, and MSR export:

```bash
python3 run_reviewed_pipeline.py \
    --run-dir runs/mcp_session_hijacking_gpt55 \
    --provider openai \
    --model gpt-5.5 \
    --api-mode responses \
    --reasoning-effort medium \
    --max-tokens 38888 \
    --max-generation-rounds 3 \
    --max-repair-rounds 6 \
    --max-compile-repair-plateau-rounds 2 \
    --tamarin-timeout 120 \
    --lemma-proof-timeout 120 \
    --overwrite
```

The API key is loaded automatically from the project `.env` file.

### 4.2 Continue from an Existing SAPIC+ Model

If `final/model.spthy` already exists and you only want to continue with compile/repair and proof/repair, use `--resume`:

```bash
python3 run_reviewed_pipeline.py \
    --run-dir runs/mcp_session_hijacking_gpt55 \
    --provider openai \
    --model gpt-5.5 \
    --api-mode responses \
    --reasoning-effort medium \
    --max-tokens 38888 \
    --max-generation-rounds 3 \
    --max-repair-rounds 6 \
    --max-compile-repair-plateau-rounds 2 \
    --tamarin-timeout 120 \
    --lemma-proof-timeout 120 \
    --resume
```

`--resume` reuses the existing `final/model.spthy`.

## 5. Generated Artifacts

The main outputs are:

```text
runs/mcp_session_hijacking_gpt55/final/model.spthy
runs/mcp_session_hijacking_gpt55/final/model.msr.spthy
runs/mcp_session_hijacking_gpt55/proof/result.json
runs/mcp_session_hijacking_gpt55/verify/reviewed_contract_repair_loop.json
```

- `model.spthy` is the generated SAPIC+ theory.
- `model.msr.spthy` is the Tamarin multiset-rewriting representation (Tamarin model) exported.
- `proof/result.json` records expected states, actual states, and whether they matched; and
- `verify/reviewed_contract_repair_loop.json` records compile/repair activity.

## 6. Tamarin Results

The final proof summary:

| Target | Expected state | Actual result | Interpretation |
|---|---|---|---|
| `session_hijack_prompt_injection_reachable` | `ProvedSatisfying` | `verified (14 steps)` | Tamarin found a trace containing the expected prompt-injection attack sequence. |
| `session_hijack_impersonation_reachable` | `ProvedSatisfying` | `verified (11 steps)` | Tamarin found a trace containing the expected impersonation sequence. |
| `accepted_inbound_requests_are_authorized` | `CounterexampleFound` | `falsified - found trace (8 steps)` | Tamarin found a trace that violates the authorization property. |

In this experiment, `expected-matched` means that all three actual outcomes agree with the outcomes specified during review.

