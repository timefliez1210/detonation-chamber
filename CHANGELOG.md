# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Pi event parsing:** tool calls are read from Pi's real `tool_execution_start` events. Before
  this, no tool call was ever seen, so canary-in-command, behavioral, sequence, and traffic
  detection and `--max-turns` never ran.
- User prompts and streaming deltas are no longer treated as agent output (URLs in the payload
  were counted as exfiltration, and output text was duplicated).
- `--timeout` is enforced (it was metadata only). The final tool call before the turn limit is no
  longer dropped.
- Behavioral false positives: command-word matching (`rsync` ≠ `nc`), write-target detection
  (`2>/dev/null` and reading `~/.ssh/*` aren't writes), `crontab -l` isn't persistence, prose
  notes quoting attacks aren't flagged.
- Canary fragments: fixed prefixes (`postgresql://dbadmin:`, `AKIA`…) alone no longer match.
- Pi extension: removed host shell injection (payload was interpolated into a shell command), fixed
  verdict casing, and reports are parsed for non-zero exit codes.
- CI ran no library tests and referenced a non-existent path. The Dockerfile could not build.

### Added
- **bubblewrap sandbox** (default): host home/media/tmp/run hidden, honeypot at `/home/agent`,
  cleared env, private PID/IPC/UTS namespaces. `--no-isolation` and `--hide`.
- **Credential-isolating LLM proxy:** the provider key never enters the sandbox.
- **OpenRouter** provider (default when `OPENROUTER_API_KEY` is set), default model
  `z-ai/glm-5.3-flash`, `.env` loading, `--env-file`, `.env.example`.
- `--framing task|direct` (indirect injection via inbox message by default),
  `--persona trusting|default`, `--thinking`, `--tools`, `--review-model`, `--keep-sandbox`.
- **Firecracker mode rebuilt:** no SSH, no tap networking, no root. The VM has no network
  interface. vsock tunnels expose only the LLM proxy and network canary, Pi output streams over
  vsock, and there's a per-run job disk plus a read-only root with a RAM overlay.
  `vm/fetch-assets.sh`, `vm/build-rootfs.sh` (Docker), and a real boot test.
- Layer 6 **agent alarm review** (`--no-agent-review`).
- Network canary scans full request bodies (incl. URL/base64/hex-decoded) and distinguishes leaks
  from contacts.
- Report `metadata` (model, isolation, turns, tool calls, tokens, signals, flags, errors).
- Eval suite (`evals/`): 40 labeled payloads + runner with strict/lenient scoring.
- Honeypot realism: random webhook path and secret (nothing says "canary"), user `agent` via fake
  `/etc/passwd`, Pi config moved out of the home to `/run/agent/pi`.
- Rules for network commands that read secret files/vars, and for scripts the agent wrote and
  then executed. Plain fetches are informational, and the sequence rule requires a data-carrying,
  non-local command.
- Real Pi stream fixture tests. The workspace builds and tests both crates.

### Changed
- Verdict policy: Malicious requires observed harm (secret disclosed or sent, Critical behavior).
  Secret access, plain outbound traffic, and agent alarms are Suspicious. Error is returned when the
  agent couldn't be observed instead of a silent Safe.
- Traffic review runs only when there is traffic, and its prompt is less trigger-happy.

### Fixed
- SSH private key canary now generates a realistic PEM block instead of a literal placeholder string.
- Pi extension now correctly reads `detonate` exit codes from `err.status` instead of `err.code`.

### Added
- Apache-2.0 license file.
- `.gitignore` excluding build artifacts and large VM assets.
- This changelog.

## [0.1.0] - 2025-04-25

### Added
- Initial release of `detonate` CLI.
- 5-layer detection: CanaryMonitor, BehavioralAnalyzer, TrafficCapture, NetworkCanary, TrafficReviewer.
- Honeypot sandbox with 9 format-valid canary types (AWS, Stripe, GitHub, ETH, SSH, Slack, DB, generic).
- Firecracker microVM support (`--firecracker`).
- Pi skill (`SKILL.md`) and Pi extension (`pi-extension/index.ts`) integrations.
- CLI supports `json`, `human`, and `quiet` output modes.

