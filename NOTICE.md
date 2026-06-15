# Notice

This public package is built for experiments around human-reviewed modeling contracts for security protocol verification.

The benchmark inputs used by this repository are derived from the AutoSM artifact and paper:

- Paper: Ziyu Mao, Jingyi Wang, Jun Sun, Shengchao Qin, and Jiawen Xiong. "LLM-Aided Automatic Modeling for Security Protocol Verification." ICSE 2025. DOI: 10.1109/ICSE55347.2025.00197.
- Artifact repository: https://github.com/zerrymore/AutoSM

AutoSM provides the source 18-case protocol benchmark and the original natural-language protocol inputs from which our UI-ready inputs were organized.

- `examples/ui_input_cases.json`
- `examples/ui_inputs.md`

Beyond reusing and citing the AutoSM benchmark inputs, this package adds review-focused artifacts and workflow code:

* A local contract-review UI for checking and editing protocol IR/modeling-contract fields before Sapic+/Tamarin generation.
* Field-level review metadata and UI flows for messages, checks, events, proof targets, attack surfaces, and abstraction hints.
* `examples/prepared_workflows/gpt55/`: GPT-5.5 raw IR and human-reviewed IR snapshots for the 18 AutoSM-derived benchmark cases.
* `examples/user_tested_workflows/deepseek_ui_20260615/`: two lightweight UI run snapshots, including prompts, LLM call metadata, generated Tamarin models, compile/repair outputs, and proof logs.
* A small abstraction-hint library, used only when the UI user enables `Use abstraction hints`.

## License

The upstream AutoSM artifact is distributed under GPLv3. Because this package includes benchmark inputs organized from that artifact, this public package is distributed with the GPLv3 license text in `LICENSE`.

## Additional Tools

This repository also interacts with external tools and APIs, including Tamarin, Sapic+, and LLM providers. Their use is governed by their respective licenses and terms.
