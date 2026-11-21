# Eval results

**Start here:** open [`index.html`](index.html) in a browser — a polished hub that links every
headline number to the raw data it came from.

## Layout

| Path | What |
|---|---|
| `index.html` | Presentation hub: all valid runs, headline numbers, links to raw data + reports. |
| `harmful-compliance.html` | Published report — standard injections vs. direct harmful requests across 7 setups. ([artifact](https://claude.ai/artifact/QSeerM9vGio2vttho6t2MJ)) |
| `chamber-protection.html` | Published report — the chamber as a pre-screen filter. ([artifact](https://claude.ai/artifact/NSBAe49CRAZADvgg9VGsXk)) |
| `model-eval-v3/` | Model-vulnerability eval (dataset_v2, 132 cases). Backs *harmful-compliance*. |
| `protection-v1/` | Chamber-as-pre-screen eval. Backs *chamber-protection*. |
| `delegated-v1/` | Hidden plain-text P.S. ("act on this email") — GLM vs. DeepSeek. |
| `html-v1/` | Instruction hidden inside HTML (comment / white text / display:none / zero-size). |
| `detector-eval/` | The chamber's detection layers as a classifier on `dataset.jsonl` (9 runs). |
| `invalid-runs/` | Held out of all reported numbers — see its [README](invalid-runs/README.md) for why. |

## Data

Each run dir tracks the compact files (`results.jsonl`, `summary.md`/`summary.json`, `config.json`, and
`corrections.json` where applicable). Full per-run transcripts (~42 MB) are git-ignored and archived — see
[`../RESULTS_ARCHIVE.md`](../RESULTS_ARCHIVE.md).

Re-score without re-running models:

```
python3 evals/run_model_evals.py --summarize evals/results/model-eval-v3
python3 evals/run_protection_eval.py --join-only --out evals/results/protection-v1
```
