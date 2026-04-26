# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

