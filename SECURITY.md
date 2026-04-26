# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in the Detonation Tool, please report it responsibly:

1. **Do not open a public issue.**
2. Email the maintainers directly with details.
3. Allow up to 72 hours for an initial response.
4. We will coordinate disclosure once a fix is ready.

## Scope

The Detonation Tool is designed to analyze untrusted payloads in a sandbox. If you find a way to:
- Escape the `/tmp/daas-*` sandbox without `--firecracker`
- Exfiltrate real (non-canary) data from the host
- Cause a denial of service beyond the `--timeout` limit
- Bypass all 5 detection layers with a known-malicious payload

… please report it.

## Hardening Notes

- Run with `--firecracker` for true VM isolation in production.
- Keep the `pi` binary and LLM dependencies updated.
- Set `DAAS_LLM_API_KEY` via environment; never commit keys.

