# Development

## Prerequisites

* Rust (stable; edition 2021, uses `std::sync::LazyLock` → 1.80+)
* Node + Pi: `npm install -g @earendil-works/pi-coding-agent`
* bubblewrap (`bwrap`) with unprivileged user namespaces enabled
* An OpenRouter key in `.env` for live runs and evals (unit tests need no key)

## Build and test

```bash
cargo build --release                 # target/release/detonate
cargo test --workspace                # CLI + daas library (~115 tests, no network/LLM needed)
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

The repository is a Cargo workspace: the root crate (`detonation-tool`, binary `detonate`) and
`daas/` (library + optional `daas` HTTP server). CI (`.github/workflows/ci.yml`) runs fmt, clippy,
and the workspace tests.

`daas/tests/firecracker_e2e.rs` is `#[ignore]`d. It boots a real VM:
`vm/fetch-assets.sh && vm/build-rootfs.sh && cargo test -p daas --test firecracker_e2e -- --ignored`.
After changing `vm/detonate-init` or `vm/Dockerfile.rootfs`, rebuild the rootfs.

## Where to change things

| Task | File |
|---|---|
| Pi event parsing | `daas/src/pi_agent.rs::parse_pi_line` (fixture: `daas/tests/fixtures/pi_stream_bash.jsonl`, a real Pi stream) |
| Detection logic | `daas/src/pi_agent.rs::analyze_events`, `behavioral.rs`, `monitor.rs`, `traffic.rs` |
| Verdict policy | `daas/src/report.rs::from_pi_result` |
| Sandbox mounts | `daas/src/sandbox.rs::build_command` |
| Honeypot layout | `daas/src/honeypot.rs` |
| Prompts (task framing, trusting persona) | constants in `daas/src/pi_agent.rs` |

`analyze_events` is pure. Add tests by building `PiEvent` streams (see `daas/src/tests_e2e.rs`).
When Pi changes its JSON format, record a new fixture with
`pi --mode json --print --no-session … > stream.jsonl` and scrub paths before committing.

## Evals

```bash
python3 evals/run_evals.py --persona trusting --jobs 6     # writes evals/results/<run>/
python3 evals/run_evals.py --only m01,b03 --repeat 3       # flakiness check on a subset
```

Add cases to `evals/dataset.jsonl` (`id`, `label` ∈ malicious|benign|hard_benign, `category`,
`payload`). Use reserved TEST-NET IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and `.example`
domains for attacker endpoints, so no payload ever reaches a real third party.

## Debugging a run

```bash
RUST_LOG=daas=info detonate --payload-file x.md --keep-sandbox --verbose --output human
```

`--keep-sandbox` leaves `$TMPDIR/daas-sandbox-<uuid>/home/agent` (the agent's home, including
anything it wrote) for inspection.
