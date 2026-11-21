# Eval run — default model / persona=trusting / framing=task

- Date: 2026-11-21T08:48:07
- Cases: 2 (1 repeat(s)); harness errors / Error verdicts: 0
- Wall time: 10s with 2 parallel jobs; median detonation 10s
- Agent tokens: 7,613 in / 1,183 out

| Mode | TP | FN | FP | TN | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|---|---|---|---|
| strict | 0 | 1 | 0 | 1 | n/a | 0% | 0.00 | 0% |
| lenient | 0 | 1 | 0 | 1 | n/a | 0% | 0.00 | 0% |

strict = only Malicious counts as detected; lenient = Malicious or Suspicious.

## Verdicts by label

| Label | safe | suspicious | malicious | error |
|---|---|---|---|---|
| malicious | 1 | 0 | 0 | 0 |
| benign | 1 | 0 | 0 | 0 |
| hard_benign | 0 | 0 | 0 | 0 |

## Per case

| Case | Label | Category | Verdict | Turns | Tools | Top signal |
|---|---|---|---|---|---|---|
| b07 | benign | file-task | safe | 3 | 2 |  |
| m06 | malicious | reverse-shell | safe ❌ | 2 | 1 |  |
