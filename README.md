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

Built for [Adversario Arena](https://arena.adversario.cl) — a Red Team training platform that needs a public ingress from student machines behind CGNAT. Released under AGPL-3.0 so anyone in the same boat can lift it for their own setup.

## Why

WireGuard speaks UDP. Most free CDNs (Cloudflare Free, Fastly, Bunny) only proxy HTTP/WS. The expensive workarounds — Cloudflare Spectrum, a Hetzner UDP relay, Tailscale's DERP servers — either cost monthly money or lock you into a third party.

`arena-tunnel` solves it by encapsulating each WireGuard UDP datagram inside one binary WebSocket frame. The server unwraps frames back into UDP packets and hands them to a local WireGuard interface. The CDN sees what looks like a long-lived WSS session — perfectly normal traffic for a chat app or a notification service.

Result: a **stable, encrypted, NAT-traversing tunnel that costs $0/month** and survives hostile networks (corporate proxies, captive portals, ISP-imposed CGNAT). Latency cost: ~80–150 ms one-way through a free CF tunnel from most of LATAM. Fine for everything except synchronous-RTT-sensitive workloads.

## Architecture

```
   Client side                      Public CDN                         Server side
─────────────────────         ────────────────────────         ──────────────────────────
arena-byoc (client)                                            arena-tunnel-server
   ├─ wireguard-go (TUN)                                            ↑
   └─ WSS dialer ──► wss://your-host/tunnel ──► cloudflared ──►    │  WS upgrade
                          (free tier)                               ▼
                                                              WireGuard interface (wg-byoc)
                                                                    │
                                                                    ▼
                                                              route → internal network
```

**Wire protocol**: one WS binary frame ↔ one UDP datagram. No framing on top. ~50 lines of glue in each direction.

In Adversario Arena, `arena-manager` (the control plane) manages peer lifecycle via an OPNsense WireGuard API + a local `wg-byoc` interface. A browser-based pairing flow issues per-student credentials so students never handle raw keys. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design.

## Quick start — Arena students

Download the latest `arena-byoc` binary from [Releases](https://github.com/dc-holdings-spa/arena-tunnel/releases), then:

```bash
# Linux / macOS — run as root (TUN device needs CAP_NET_ADMIN)
chmod +x arena-tunnel-client-linux-amd64
sudo ./arena-tunnel-client-linux-amd64
```

On first run (or after `pair`), the binary prints a code and URL:

```
====================================================
  Arena BYOC2 — Pair this device
====================================================
  Code:    CBETQ3
  URL:     https://arena.adversario.cl/byoc2/connect?code=CBETQ3
  Open the URL in your browser, sign in, and click
  'Authorize this device' to continue.
====================================================
```

Open the URL, authorize, and the tunnel comes up automatically — no second command:

```
[+] arena-byoc v1.1.0
[+] WG up: tunnelIP=10.201.0.4 server=wg-byoc.adversario.cl local-udp-port=56096
[+] identity: student@example.com
[wss] connected

┌──────────────────────────────────────────────────────────────┐
│  ARENA BYOC2 // SLOT ACTIVO                                  │
├──────────────────────────────────────────────────────────────┤
│  TUNNEL IP        10.201.0.4                                 │
│  EDGE IP          10.130.60.10                               │
├──────────────────────────────────────────────────────────────┤
│  // LISTENER CONFIG                                          │
│  BIND IP          10.201.0.4                                 │
│  PORT             443                                        │
├──────────────────────────────────────────────────────────────┤
│  // SNI / COBERTURA                                          │
│  gateway-abc123.r.adversario.cl                              │
├──────────────────────────────────────────────────────────────┤
│  // HMAC COOKIE                                              │
│  nombre           __arena_tenant                             │
│  valor            <value>                                    │
└──────────────────────────────────────────────────────────────┘
```

Credentials are saved to `/root/.config/arena-byoc/config.json` (mode 0600). Subsequent runs skip the browser flow and connect directly.

## Subcommands

```
arena-byoc [flags]              Pair if needed, then run tunnel (default).
arena-byoc pair [--force]       Force the browser-pairing flow regardless of saved config.
arena-byoc logout               Wipe local config and revoke the peer server-side.
arena-byoc logout --keep-server Wipe local config only; leave the server-side peer alive.
arena-byoc status               Show stored identity + ping arena for peer state.
arena-byoc version              Print build version.
```

## Flags

| Flag           | Meaning                                                             |
|----------------|---------------------------------------------------------------------|
| `--arena`      | Override arena base URL (env: `ARENA_BYOC_URL`)                     |
| `--config`     | Override config file path (env: `ARENA_BYOC_CONFIG`)               |
| `--no-browser` | Print code+URL only; do not try to auto-open a browser              |
| `--force-pair` | Ignore cached config and re-pair                                    |
| `--token`      | Headless: exchange a one-shot token for credentials (Ansible/CI)   |
| `-v`           | Verbose WireGuard logs                                              |

## Quick start — DIY / self-hosted

Requires a running WireGuard server on the same host and a way to publish your HTTP port (`cloudflared tunnel`, `ngrok`, etc.).

```bash
# 1. Set up WireGuard server
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

# 2. Run arena-tunnel-server (forwards WSS → WG UDP)
sudo ./arena-tunnel-server-linux-amd64 --listen 127.0.0.1:8888 --wg 127.0.0.1:51820

# 3. Expose 127.0.0.1:8888 publicly.
#    With cloudflared: add an ingress rule routing wss://wg.example.com → http://127.0.0.1:8888

# 4. Run client with explicit keys (no pairing control plane needed)
sudo ./arena-tunnel-client-linux-amd64 \
  -priv  <peer-priv-b64> \
  -pub   <server-pub-b64> \
  -ip    10.200.0.2 \
  -host  wg.example.com
```

## Build

The client is designed to be **per-user, per-platform compiled** by a control plane, with credentials baked at build time via Go's `-ldflags`. The end user downloads one binary, runs it, gets a tunnel.

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

For the browser-pairing UX (recommended), skip `build.sh` and ship the stock binary from [Releases](https://github.com/dc-holdings-spa/arena-tunnel/releases) — credentials are exchanged at runtime.

Cross-compile matrix:

| OS      | Arch   | Notes                                                                                    |
|---------|--------|------------------------------------------------------------------------------------------|
| linux   | amd64  | statically linked, CGO disabled                                                          |
| linux   | arm64  | same                                                                                     |
| darwin  | amd64  | Intel Macs                                                                               |
| darwin  | arm64  | Apple Silicon                                                                            |
| windows | amd64  | ships with `wintun.dll` from [wintun.net](https://www.wintun.net/) in the `.zip` bundle |

Or use the `Makefile`:

```bash
make build           # local platform
make build-all       # all 5 platforms (writes to dist/)
```

## Compile-time variables

Set via `go build -ldflags "-X main.X=Y"` for baked-credential binaries:

```
main.privKeyB64        — client WG private key (base64)
main.serverPubKeyB64   — server WG public key (base64)
main.tunnelIP          — client tunnel IP (e.g. "10.201.0.4")
main.serverHost        — WSS hostname (e.g. "wg-byoc.adversario.cl")
main.version           — version string shown in logs + User-Agent
main.tunnelName        — TUN interface name (default "arena-byoc")
```

Baked creds take precedence over on-disk config. If all three of `privKeyB64 / serverPubKeyB64 / tunnelIP` are non-empty at build time, the pairing flow is skipped entirely.

## Threat model

- **Confidentiality**: end-to-end via WireGuard ChaCha20-Poly1305. The CDN sees an opaque WSS stream.
- **Authenticity**: WireGuard noise handshake authenticates both sides via public keys.
- **Replay/MITM**: WireGuard's replay window + TLS as defence in depth.
- **Peer identity**: each peer has a unique private key. Server enforces per-peer `/32` AllowedIPs so one peer can't impersonate another inside the tunnel.
- **Revocation**: the control plane (arena-manager) stores a SHA-256 hash of a revocation token issued at pairing time. `arena-byoc logout` sends a signed DELETE to revoke the peer; the server then refuses WG handshakes from that pubkey within seconds. A leaked binary is dead as soon as the peer is revoked.
- **The CDN**: trust boundary. Cloudflare sees connection metadata but not payload content. The protocol is CDN-agnostic — swap in any WSS-capable proxy.

Full model in [SECURITY.md](SECURITY.md). Vulnerability reports: [security@adversario.cl](mailto:security@adversario.cl).

## Status

`v1.1.0` — in production at [Adversario Arena](https://arena.adversario.cl) since June 2026, serving BYOC2-tier students daily. Wire protocol is stable as of `v1.0.0`.

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev loop, coding style, and what's likely to be accepted.

## License

[AGPL-3.0](LICENSE). If you ship a service backed by a modified version of this code, you must publish the modifications under the same license.

## Related work / inspiration

- [WireGuard](https://www.wireguard.com/) — the underlying VPN
- [wireguard-go](https://git.zx2c4.com/wireguard-go/) — userspace WG used by the client
- [wstunnel](https://github.com/erebe/wstunnel) — the Rust project that inspired the protocol shape
- [Tailscale](https://tailscale.com/) — for proving you can run WG everywhere if you build the control plane
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) — the no-cost public ingress
- [wintun](https://www.wintun.net/) — Windows TUN driver, bundled