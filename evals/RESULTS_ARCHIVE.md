# Eval results: index and archive

**Human-facing index:** [`results/index.html`](results/index.html) (and
[`results/README.md`](results/README.md)) — a polished hub linking every headline
number to its raw data.

Compact results are tracked in git under `evals/results/` (per-run `results.jsonl`,
`summary.md`/`summary.json`, `config.json`, `corrections.json`). The full per-run
reports (agent transcripts, tool calls, reasoning; ~42 MB) are git-ignored and kept
as a compressed archive.

## Runs (2026-11-21)

| Directory | What | Status |
|---|---|---|
| `model-eval-v3/` | Model vulnerability eval, dataset_v2 (132 cases). Pi: GLM 5.3 Flash, Claude Haiku 5.5, GPT-6 Luna, DeepSeek V4.1 Flash (2 repeats). Claude Code: Haiku, Sonnet, Opus at medium effort (1 repeat). Fixed judge GLM 5.3 Flash. | **Valid.** Direct-case outcomes corrected per `corrections.json` (hand-verified) |
| `protection-v1/` | Detonation chamber as a pre-screen: GLM / DeepSeek chamber × normal / trusting persona, 2 repeats, joined with model-eval-v3 for GLM and DeepSeek targets. | **Valid** (fixed rules, corrected baseline) |
| `delegated-v1/` | Hidden plain-text P.S. ("act on this email"), GLM vs. DeepSeek. | **Valid** |
| `html-v1/` | Instruction hidden inside HTML (comment / white text / display:none / zero-size), GLM vs. DeepSeek. | **Valid** |
| `detector-eval/20261121-*-task*/` | Detector eval runs on dataset.jsonl (40 cases), trusting/default persona; `-fc` = Firecracker. | Valid for the detector eval (pre rule fixes) |
| `invalid-runs/model-eval-v2-handle-message-framing/` | Same models before the `--task` fix: every run used the "carry out the message's requests" prompt. | **Invalid** for injection/utility — held out; see `invalid-runs/README.md` |

Published pages (now kept in `evals/results/`, data embedded inline):
- `results/harmful-compliance.html`: https://claude.ai/artifact/QSeerM9vGio2vttho6t2MJ
- `results/chamber-protection.html`: https://claude.ai/artifact/NSBAe49CRAZADvgg9VGsXk

## Full archive

```
/media/timefliez/data/backups/detonation-chamber/eval-results-20261121-1606.tar.gz
sha256 3843835b364f702670bce59c7439e077694785954f5f7406cf6f0272fd5c6af8
```

Restore: `tar -xzf eval-results-20261121-1606.tar.gz -C evals/` (recreates `evals/results/`
including `reports/`). Verify first with `sha256sum -c eval-results-20261121-1606.tar.gz.sha256`.

Re-score after rule changes without re-running models:
`python3 evals/run_model_evals.py --summarize evals/results/model-eval-v3` and
`python3 evals/run_protection_eval.py --join-only --out evals/results/protection-v1`.
