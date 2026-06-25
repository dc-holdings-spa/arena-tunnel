# Security Policy

## Supported Versions

We support the latest minor release. Older releases get critical-only patches for 90 days after the next minor ships.

| Version    | Supported |
|------------|-----------|
| `v1.1.x`   | ✅ active |
| `v1.0.x`   | ✅ critical patches only |
| `< v1.0`   | ❌        |

## Reporting a Vulnerability

Email **security@adversario.cl** with:

- A description of the vulnerability
- Steps to reproduce, or a working PoC
- The version / commit hash you tested against
- Your name / handle for credit (optional)

**Please do not file public GitHub issues for security vulnerabilities.**

We aim to acknowledge reports within 48 hours and ship a fix within 14 days for high-severity issues. Critical issues (RCE, auth bypass, kernel-level memory corruption) get a same-day acknowledgement and a 72-hour fix target.

We don't run a bug bounty program. We do credit reporters in the release notes unless they ask otherwise.

## Threat Model — what's in scope

| Threat                                                | Mitigated by                                                        |
|-------------------------------------------------------|---------------------------------------------------------------------|
| Eavesdropping on the WSS path                         | WireGuard ChaCha20-Poly1305 inside; TLS 1.3 outside (defence in depth) |
| Active MITM on the WSS path                           | WireGuard noise handshake authenticates the server pubkey            |
| Replay of WG packets                                  | WireGuard built-in replay window                                     |
| Spoofing a peer with a stolen pubkey                  | Per-peer AllowedIPs `/32` lock on the server side                    |
| Compromise of one client binary                       | The peer's keys are unique to that binary; revoke server-side and the binary is dead |
| DoS via unbounded UDP connections on the server       | `--idle-timeout` reaps inactive tunnels                              |
| Memory corruption in `wireguard-go`                   | Upstream's job; we pin to a known-good commit and bump deliberately   |

## What's NOT in scope

- The host kernel / TUN driver itself (delegate to your OS vendor).
- Cloudflare or whatever CDN you front this with — we trust them not to log payloads. If your threat model includes the CDN, pick a different fronting strategy or self-host the entire path.
- The WireGuard protocol — that's [donenfeld@](https://www.wireguard.com/contact/)'s job.
- Compromised endpoints (if your laptop is rooted, no tunnel can save you).

## Hardening recommendations (operators)

These don't ship by default; we leave them to deployers because some are infra-specific:

1. **Run the server as a non-root user.** No CAP_NET_ADMIN needed.
2. **Restrict the WG target.** Use `--wg 127.0.0.1:<port>` only — never bind to a public interface.
3. **Cap per-IP WSS connections at the CDN layer.** Cloudflare Rules can throttle aggressive clients before they hit your origin.
4. **Set sane WG AllowedIPs per peer.** A `/32` per client prevents one peer from impersonating another inside the tunnel.
5. **Monitor connection patterns.** Sustained > 100 reconnects/hour from one source IP is suspicious.

If you ship `arena-tunnel` as part of a SaaS offering: per AGPL-3.0 you must publish your modifications under the same license. That's a feature, not a bug. The protocol is public, the implementation is auditable, your users benefit.
