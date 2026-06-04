<div align="center">

# arena-tunnel

**WireGuard over WebSocket. Single Go binary. Free public ingress through any CDN.**

[![Build](https://github.com/dc-holdings-spa/arena-tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/dc-holdings-spa/arena-tunnel/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dc-holdings-spa/arena-tunnel?logo=github)](https://github.com/dc-holdings-spa/arena-tunnel/releases)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-orange.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/dc-holdings-spa/arena-tunnel)](https://goreportcard.com/report/github.com/dc-holdings-spa/arena-tunnel)
[![Go Version](https://img.shields.io/github/go-mod/go-version/dc-holdings-spa/arena-tunnel?filename=client%2Fgo.mod)](client/go.mod)

</div>

---

`arena-tunnel` punches a WireGuard VPN through any HTTP/HTTPS path — including a free Cloudflare Tunnel. No VPS rental. No Cloudflare Spectrum. No vendor lock-in. Two small Go binaries, one cleanly defined wire protocol.

Built for [Adversario Arena](https://arena.adversario.cl) — a Red Team training platform that needed a public ingress from a CGNAT-only home network. Released under AGPL-3.0 so anyone in the same boat can lift it for their own self-hosted setup.

## Why

WireGuard speaks UDP. Most free CDNs (Cloudflare Free, Fastly, Bunny) only proxy HTTP/WS. The expensive workarounds — Cloudflare Spectrum, a Hetzner UDP relay, Tailscale's DERP servers — either cost monthly money or lock you into a third party.

`arena-tunnel` solves it by encapsulating each WireGuard UDP datagram inside one binary WebSocket frame. The server unwraps frames back into UDP packets and hands them to a local WireGuard kernel interface. The CDN sees what looks like a long-lived WSS session — perfectly normal traffic for a chat app or a notification service.

Result: a **stable, encrypted, NAT-traversing tunnel that costs $0/month** and survives hostile networks (corporate proxies, captive portals, ISP-imposed CGNAT). Latency cost: ~80–150 ms one-way through a free CF tunnel from most of LATAM. Fine for everything except synchronous-RTT-sensitive workloads.

## Architecture

```
   Client side                      Public CDN                         Server side
─────────────────────         ────────────────────────         ──────────────────────────
arena-tunnel-client                                            arena-tunnel-server
   ├─ wireguard-go (TUN)                                            ↑
   └─ WSS dialer ──► wss://your-host/... ──► cloudflared ──►        │  WS upgrade
                          (free tier)                               ▼
                                                              WireGuard kernel iface
                                                                    │
                                                                    ▼
                                                              MASQUERADE / route
                                                                    │
                                                                    ▼
                                                              Your internal network
```

**Wire protocol**: one WS binary frame ↔ one UDP datagram. No framing on top. Nothing to reverse-engineer. ~50 lines of glue in each direction.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the long form (threat model, MTU math, why we don't multiplex, alternatives considered).

## Quick start

### Server (your network)

Requires a running WireGuard server on the same host (kernel or userspace) and a way to publish your HTTP port (`cloudflared tunnel`, `ngrok`, etc).

```bash
# 1. Set up WireGuard the normal way; here's a minimal server config:
cat > /etc/wireguard/wg0.conf <<'EOF'
[Interface]
PrivateKey = <server-priv>
ListenPort = 51820
Address    = 10.200.0.1/24

[Peer]
PublicKey  = <client-pub>
AllowedIPs = 10.200.0.2/32
EOF
systemctl enable --now wg-quick@wg0

# 2. Run arena-tunnel server (forwards WSS → WG UDP)
go install github.com/dc-holdings-spa/arena-tunnel/server@latest
arena-tunnel-server --listen 127.0.0.1:8888 --wg 127.0.0.1:51820

# 3. Expose 127.0.0.1:8888 publicly via your CDN of choice.
#    With cloudflared, add an ingress rule routing
#    wss://wg.example.com → http://127.0.0.1:8888.
```

### Client (anywhere on Internet)

Download the matching binary from [Releases](https://github.com/dc-holdings-spa/arena-tunnel/releases) and run it (root/Administrator required for the TUN device — same as Tailscale, OpenVPN, WireGuard):

```bash
# Linux / macOS — pass creds via flags
chmod +x arena-tunnel-client-linux-amd64
sudo ./arena-tunnel-client-linux-amd64 \
  -priv  <peer-priv-b64> \
  -pub   <server-pub-b64> \
  -ip    10.200.0.2 \
  -host  wg.example.com
```

Or build with credentials baked in for a zero-config UX — see [Build](#build) below.

```text
[tun] creating device "arena-byoc"
[+] WG up: tunnelIP=10.200.0.2 server=wg.example.com local-udp-port=43902
[wss] dialing wss://wg.example.com/tunnel
[wss] connected
```

A new network interface called `arena-byoc` exists with IP `10.200.0.2`. Ping the gateway:

```bash
ping 10.200.0.1
```

## Build

The client is designed to be **per-user, per-platform compiled** by an issuing service, with credentials baked at build time via Go's `-ldflags`. The end user downloads one binary, runs it, gets a tunnel — no config file, no env vars, no copy-pasting keys.

`build.sh` is the helper your control plane shells out to:

```bash
./build.sh \
  "<peer-priv-b64>" \
  "<server-pub-b64>" \
  "10.200.0.2" \
  "wg.example.com" \
  linux amd64 \
  ./arena-tunnel-client-linux-amd64
```

Cross-compile matrix:

| OS      | Arch   | Binary size  | Notes                                                                                   |
|---------|--------|--------------|-----------------------------------------------------------------------------------------|
| linux   | amd64  | ~6 MB        | statically linked, CGO disabled                                                          |
| linux   | arm64  | ~6 MB        | same                                                                                     |
| darwin  | amd64  | ~6 MB        | Intel Macs                                                                               |
| darwin  | arm64  | ~6 MB        | Apple Silicon                                                                            |
| windows | amd64  | ~6 MB        | ships with `wintun.dll` from [wintun.net](https://www.wintun.net/) (bundled in `assets/`) |

Or use the `Makefile`:

```bash
make build           # local platform
make build-all       # all 5 platforms (writes to dist/)
make release         # tag + push (used by CI)
```

## Configuration

### Server flags

| Flag             | Default              | Meaning                                                                            |
|------------------|----------------------|------------------------------------------------------------------------------------|
| `--listen`       | `127.0.0.1:8888`     | HTTP bind. Loopback because CDN terminates TLS upstream.                            |
| `--wg`           | `127.0.0.1:51820`    | Where unwrapped UDP datagrams go                                                    |
| `--idle-timeout` | `5m`                 | Drop a UDP tunnel after N idle                                                      |

### Client flags (override baked values)

| Flag      | Meaning                                              |
|-----------|------------------------------------------------------|
| `-priv`   | Client WG private key (base64)                       |
| `-pub`    | Server WG public key (base64)                        |
| `-ip`     | Tunnel IP assigned to this client (e.g. `10.200.0.2`)|
| `-host`   | WSS hostname (e.g. `wg.example.com`)                 |
| `-v`      | Verbose WireGuard logs                               |

### Compile-time variables (preferred for production)

Set via `go build -ldflags "-X main.X=Y"`:

```
main.privKeyB64        — client WG private key
main.serverPubKeyB64   — server WG public key
main.tunnelIP          — client's tunnel IP
main.serverHost        — WSS hostname
main.tunnelName        — TUN interface name (default "arena-byoc")
```

## Threat model

- **Confidentiality**: end-to-end via WireGuard ChaCha20-Poly1305 between client and server. The CDN sees an opaque WSS stream — no plaintext IPs, no scenario names, no command payloads.
- **Authenticity**: WireGuard's noise handshake. Public keys are pre-shared per peer (typed at config time or baked into the client binary).
- **Replay/MITM**: WireGuard handles both. The CDN-side TLS is a defence in depth.
- **The CDN itself**: trust boundary. Cloudflare sees connection metadata (timestamps, IPs, byte counts) but not content. Choose your CDN accordingly. If you don't want CF to see traffic patterns, swap in another fronting service — the protocol is CDN-agnostic.
- **Single-binary baked credentials**: if a user shares their binary, the recipient gets full tunnel access for the same peer slot. Treat the binary like an SSH private key. Most platforms (including Adversario) rotate the peer on revocation so a leaked binary is dead within minutes.

The full model is in [SECURITY.md](SECURITY.md). Vulnerability reports: [security@adversario.cl](mailto:security@adversario.cl).

## Status

Released as `v0.1.x`. Used in production by [Adversario Arena](https://arena.adversario.cl) since June 2026 to give BYOC2-tier students a WG ingress without renting a VPS. Pre-`v1.0`, the WS path may change. After `v1.0`, the wire protocol is stable.

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev loop, coding style, and what kinds of changes are likely to be accepted. Be excellent: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

[AGPL-3.0](LICENSE). If you ship a service backed by a modified version of this code, you must publish the modifications under the same license. The protocol itself is not patented and is documented in [ARCHITECTURE.md](ARCHITECTURE.md) so anyone can reimplement.

## Related work / inspiration

- [WireGuard](https://www.wireguard.com/) — the underlying VPN
- [wireguard-go](https://git.zx2c4.com/wireguard-go/) — userspace WG used by the client
- [wstunnel](https://github.com/erebe/wstunnel) — the Rust project that inspired the protocol shape (we wrote our own to drop the external dep)
- [Tailscale](https://tailscale.com/) — for proving you can run WG everywhere if you build the control plane
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) — the no-cost public ingress we lean on
- [wintun](https://www.wintun.net/) — Windows TUN driver, bundled
