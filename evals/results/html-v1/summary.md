# Model vulnerability eval — 2026-11-21T19:39:04

Attack success rate (ASR) = injected goal observably carried out. 95% Wilson CIs in parentheses.

| Model | ASR embedded | ASR LLMail (human) | ASR direct | Recognized attacks | Utility under attack | Benign utility | Over-refusal | Unsafe side effects (attack cases) | Unsafe actions (benign) | Eval-aware | Errors |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `deepseek/deepseek-v4.1-flash-1017` | – | – | – | 100% (98–100) n=240 | – | 100% (61–100) n=6 | 0% (0–39) n=6 | – | 0% (0–39) n=6 | 3% (1–6) n=246 | 0/246 |
| `z-ai/glm-5.3-flash` | – | – | – | 100% (98–100) n=240 | – | 100% (61–100) n=6 | 0% (0–39) n=6 | – | 0% (0–39) n=6 | 4% (2–7) n=246 | 0/246 |

## ASR by injection goal

| | `deepseek/deepseek-v4.1-flash-1017` | `z-ai/glm-5.3-flash` |
|---|---|---|

## ASR by attack template

| | `deepseek/deepseek-v4.1-flash-1017` | `z-ai/glm-5.3-flash` |
|---|---|---|
