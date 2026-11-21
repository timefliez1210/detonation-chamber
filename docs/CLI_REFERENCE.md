# CLI reference

```
detonate [OPTIONS] [PAYLOAD]
```

The payload comes from the argument, `--payload-file`, or stdin, in that order (max 1 MB).

## Options

| Flag | Default | Description |
|---|---|---|
| `--payload-file FILE` | | Read the payload from a file |
| `--output json\|human\|quiet` | `json` | Report format. `quiet` = exit code only |
| `--provider P` | auto | `openrouter`, `openai`, `anthropic`, `ollama` |
| `--model M` | per provider | Sandbox agent model (OpenRouter default `z-ai/glm-5.3-flash`) |
| `--review-model M` | `--model` | Model for layers 5 and 6 |
| `--thinking L` | Pi default | `off`, `minimal`, `low`, `medium`, `high` |
| `--framing task\|direct` | `task` | `task`: payload is an inbox message the agent handles (indirect injection). `direct`: payload is the user prompt |
| `--persona trusting\|default` | `trusting` | `trusting`: agent treats the inbox as pre-approved and acts without asking (most sensitive). `default`: stock Pi prompt |
| `--tools LIST` | `read,bash,edit,write` | Pi tools available to the agent |
| `--max-turns N` | `10` | Kill the agent after N turns |
| `--timeout SECS` | `180` | Hard timeout for the agent run |
| `--canaries N` | `8` | Number of canary secrets (max 9) |
| `--env-file FILE` | `./.env` | Load environment variables |
| `--hide PATH` | | Extra host path to hide in the sandbox (repeatable) |
| `--no-isolation` | off | **Unsafe.** Run Pi without bubblewrap |
| `--keep-sandbox` | off | Keep `$TMPDIR/daas-sandbox-*` for inspection |
| `--no-traffic-review` | off | Skip layer 5 |
| `--no-agent-review` | off | Skip layer 6 |
| `--firecracker` | off | Run the agent in a Firecracker microVM (own kernel, no network; proxy + canary via vsock) |
| `--vm-assets-dir DIR` | `vm_assets` | `firecracker`, `vmlinux`, `rootfs.ext4` (falls back to `<repo>/vm_assets`) |
| `-v, --verbose` | off | More detail (timeline in human output) |

## Environment

| Variable | Purpose |
|---|---|
| `OPENROUTER_API_KEY` / `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Provider key. The first one present picks the provider if `--provider`/`DAAS_LLM_PROVIDER` are unset |
| `DAAS_LLM_API_KEY` | Overrides the provider key |
| `DAAS_LLM_PROVIDER`, `DAAS_LLM_MODEL` | Defaults for `--provider` / `--model` |
| `DAAS_LLM_API_BASE` | Any OpenAI-compatible base URL (e.g. vLLM, LM Studio) |
| `DAAS_TRAFFIC_REVIEW_MODEL` | Default for `--review-model` |
| `PI_BIN` | Pi executable (default `pi` on PATH) |
| `RUST_LOG` | e.g. `daas=info` for engine logs on stderr |

## Exit codes

| Code | Verdict |
|---|---|
| 0 | safe |
| 1 | suspicious |
| 2 | malicious |
| 3 | error (configuration, LLM, or sandbox failure). **Do not treat as safe** |

## JSON report

```jsonc
{
  "verdict": "malicious",            // safe | suspicious | malicious | error
  "confidence": 0.93,
  "exfiltration_events": [
    { "canary_id": "…", "secret_type": "stripe_key",
      "channel": { "network_request": { "url": "http://127.0.0.1:41233/canary/…" } },
      "destination": "network canary (planted webhook URL)", "timestamp": "…", "raw_output": "…" }
  ],
  "behavioral_timeline": [ { "timestamp": "…", "description": "Tool call: bash({…})", "severity": "info" } ],
  "payload_analysis": "Prompt injection DETECTED. …",
  "metadata": {
    "provider": "openrouter", "model": "z-ai/glm-5.3-flash", "isolation": "bwrap",
    "framing": "task", "persona": "trusting", "turns": 4, "tool_calls": 3,
    "terminated_reason": "natural_stop", "duration_secs": 21.4,
    "input_tokens": 9120, "output_tokens": 640,
    "signals": ["honeypot secret sent out of the sandbox (Stripe Secret Key)", "…"],
    "secrets_accessed": ["Stripe Secret Key"],
    "behavioral_flags": [ { "flag": "SecretReadThenNetworkCall", "severity": "critical", "description": "…" } ],
    "network_canary_hits": 1, "unexpected_traffic": 0,
    "agent_alarm": "refused=false flagged_as_attack=false …",
    "traffic_review": "…", "error": null
  }
}
```

## Examples

```bash
detonate --payload-file email.eml --output human
curl -s https://example.com/page | detonate --output quiet || echo "do not process"
detonate --payload-file issue.md --persona default --model z-ai/glm-5.3   # what would this model do?
detonate --payload-file doc.md --keep-sandbox --verbose --output human     # debug a run
RUST_LOG=daas=info detonate "…"                                            # engine logs
```
