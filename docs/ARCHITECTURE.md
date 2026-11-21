# Architecture

```
detonation-chamber/
├── src/main.rs            CLI (`detonate`): flags, .env, provider resolution, output, exit codes
├── daas/                  Library (+ an optional HTTP server binary, `daas`)
│   └── src/
│       ├── pi_agent.rs    Engine: sandbox setup, run Pi, parse events, analyze_events()
│       ├── sandbox.rs     bubblewrap command builder, Pi/Node resolution
│       ├── proxy.rs       Credential-isolating LLM proxy (127.0.0.1)
│       ├── canary.rs      Canary secret generation
│       ├── honeypot.rs    Honeypot filesystem + env layout
│       ├── monitor.rs     Canary matching (exact / core / fragment / encodings)
│       ├── behavioral.rs  Behavioral rules + network canary HTTP server
│       ├── traffic.rs     Traffic extraction + LLM traffic review
│       ├── agent_review.rs  Agent alarm review (layer 6)
│       ├── report.rs      Verdict policy + report building
│       └── types.rs       Shared types (report JSON schema)
├── pi-extension/          Pi extension registering a `detonate` tool
├── SKILL.md               Pi skill
└── evals/                 Labeled dataset + runner
```

## One detonation, step by step

1. **CLI** (`src/main.rs`) loads `.env`, resolves provider/model/key/base URL, verifies
   `bwrap` works, starts the **network canary** (random 127.0.0.1 port), and builds a `PiAgent`.
2. **Honeypot** (`PiAgent::create_sandbox`): a fresh `$TMPDIR/daas-sandbox-<uuid>/home/agent`
   (mode 0700) with canaries in `.env`, `.aws/credentials`, `.ssh/id_ed25519`, `config/app.conf`,
   `secrets/*`, the canary URL in `config/webhooks.yml` and `.env`, and decoy files. With task
   framing the payload is written to `~/inbox/message.md`.
3. **LLM proxy** (`proxy.rs`): started on 127.0.0.1. Pi's sandboxed config
   (written outside the honeypot home and mounted at `/run/agent/pi`, `PI_CODING_AGENT_DIR`) defines
   one provider `gateway` → proxy, model id `target`, and a placeholder key. The proxy rewrites `model`, adds `Authorization`, forwards to the upstream
   (`https://openrouter.ai/api/v1` by default) and streams the response back.
4. **Pi under bubblewrap** (`sandbox.rs`):
   `bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs {/home,/root,/media,/mnt,/run,/tmp,…}
   --ro-bind <node prefix> --ro-bind <pi node_modules> --ro-bind <fake passwd/group> /etc/{passwd,group}
   --bind <pi config> /run/agent/pi --bind <honeypot> /home/agent
   --unshare-pid --unshare-ipc --unshare-uts --die-with-parent --new-session --clearenv --setenv …
   -- node <pi cli.js> --mode json --print --no-session --no-extensions --no-skills
   --no-context-files --offline --provider gateway --model target --tools read,bash,edit,write
   [--append-system-prompt <trusting persona>] <prompt>`.
   The environment contains only `HOME=/home/agent`, `PATH`, locale, and the honeypot variables.
5. **Event loop**: Pi's JSONL is parsed line by line (`parse_pi_line`): `tool_execution_start`,
   `tool_execution_end`, `turn_start`, and assistant `message_end` (text, thinking, usage, errors).
   The run is killed on timeout or when turns exceed `--max-turns`.
6. **Analysis** (`analyze_events`, pure and unit-tested) runs layers 1, 3, and 4. Then the engine adds
   network-canary hits (layer 2), the traffic review (layer 5, only if there was traffic), and the
   agent alarm review (layer 6).
7. **Report** (`ReportBuilder::from_pi_result`) applies the verdict policy (see
   [DETECTION_LAYERS.md](DETECTION_LAYERS.md)) and the CLI prints JSON/human output and exits 0–3.
   The sandbox directory is deleted unless `--keep-sandbox`.

## Trust boundaries

| Asset | Where it lives | Reachable by the agent? |
|---|---|---|
| Your files (`/home`, `/media`, `/mnt`, …) | host | No (tmpfs over them) |
| Provider API key | `detonate` process env | No: separate PID namespace, cleared env, proxy adds it |
| Canary secrets | honeypot home + agent env | Yes, by design |
| Network | bwrap: shared with host. firecracker: none (vsock tunnels to proxy + canary only) | bwrap: yes. firecracker: no |
| Pi + Node install | host, read-only bind | Read-only |

## Firecracker backend (`firecracker.rs`, `vm/`)

With `--firecracker`, steps 4–5 change. Everything else (honeypot, proxy, analysis, report) is shared.

```
host                                            microVM (no NIC)
 detonate ── proxy :P  ◄── unix v.sock_P ◄─vsock─ socat 127.0.0.1:P ◄── Pi (gateway → 127.0.0.1:P)
          ── canary :C ◄── unix v.sock_C ◄─vsock─ socat 127.0.0.1:C ◄── agent's curl $WEBHOOK_URL
          ◄── JSONL ─────── unix v.sock_5000 ◄─vsock─ pi … | socat VSOCK-CONNECT:2:5000
 job.ext4 (mkfs.ext4 -d honeypot/) ───────────────► /dev/vdb → /mnt/job → /home/agent, /run/agent/pi
 rootfs.ext4 (read-only) ─────────────────────────► / + tmpfs overlay
```

* `vm/detonate-init` is PID 1: overlay root in RAM, mounts the job disk, binds the honeypot home
  and Pi config, starts one `socat` tunnel per forwarded port, runs Pi as `agent` with the job's
  environment, pipes stdout to vsock port 5000, then resets the VM.
* The host builds the job disk per run, listens on `/tmp/dcfc-<id>/v.sock_<port>` (Firecracker's
  guest-initiated vsock convention), bridges tunnel connections to `127.0.0.1:<port>`, and reads
  Pi's stream with the same loop as bubblewrap mode. Timeout / turn limit → VM killed.
* Pi's stderr is read back from the job disk with `debugfs` for error reporting.

The HTTP server binary (`daas`, `daas/src/main.rs` + `api.rs`/`orchestrator.rs`) wraps the same
engine behind a REST API and is not covered by the evals.
