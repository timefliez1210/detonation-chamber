# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in the Detonation Tool, please report it responsibly:

1. **Do not open a public issue.**
2. Email the maintainers directly with details.
3. Allow up to 72 hours for an initial response.
4. We will coordinate disclosure once a fix is ready.

## Scope

`detonate` runs attacker-controlled instructions with a real shell, inside a bubblewrap sandbox.
Please report anything that lets a payload:

- read or modify host files outside the honeypot (sandbox escape, mount leaks)
- obtain the provider API key (it should exist only in the `detonate` process and the local proxy)
- execute code on the host through `detonate`, the Pi extension, or the eval runner
- outlive the `--timeout` / `--max-turns` limits
- get a known-malicious payload a `safe` verdict *while the agent actually performed the attack*

## Hardening notes

- Keep the default bubblewrap isolation. `--no-isolation` exposes your files and the API key.
- In bubblewrap mode the network is shared with the host (the agent must reach the local proxy and
  canary), so payload commands can reach the internet. Use `--firecracker` for a VM with no network
  interface (only vsock tunnels to the proxy and canary) and a separate kernel.
- Hide additional data mounts with `--hide PATH`.
- Keep keys in `.env` (gitignored) or the environment; never commit them.
