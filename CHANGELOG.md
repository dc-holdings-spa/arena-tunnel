# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.1.0] — 2026-06-04

### Added

- Initial public release, extracted from the Adversario Arena monorepo via `git subtree split`.
- `arena-tunnel-server` — Go binary that bridges WSS↔UDP. Forwards binary WebSocket frames as UDP datagrams to a local WireGuard kernel interface.
- `arena-tunnel-client` (also known as `arena-byoc`) — Go binary that creates a TUN device, runs `wireguard-go` in-process, and wraps the WG UDP path through WSS to the server. Credentials baked at compile-time via `-ldflags`.
- `build.sh` — helper for control planes to compile per-user binaries on-demand.
- Cross-compile matrix: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64.
- Bundled `wintun.dll` for the Windows TUN driver.
- Documentation: README, ARCHITECTURE, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT.

### Known limitations

- IPv6 inside the tunnel is untested (the outer WSS path is IPv4-only by default).
- macOS requires `sudo` on first run because we don't yet ship a launchd service.
- Windows on ARM64 is not packaged (wintun-arm64 is still beta upstream).
