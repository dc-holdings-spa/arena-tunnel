# Architecture

> Design notes that didn't fit in the README. Read this if you want to fork, reimplement, or understand the trade-offs.

## Goals (in order)

1. **Zero recurring cost.** No VPS, no Spectrum, no Tailscale subscription. Students are behind CGNAT — we still need a stable public ingress for their C2 listeners.
2. **Stable.** Survive Cloudflare tunnel restarts, ISP modem reboots, and student NAT type changes.
3. **Single binary distribution.** A student downloads one file, runs it, gets a tunnel. No installer, no config wizard, no copy-pasting keys.
4. **Open source.** No vendor lock-in. Anyone with similar constraints can deploy it.
5. **Hostile-network friendly.** Hotel WiFi, corporate proxies, captive portals — WSS over 443 passes through the same as any HTTPS app.

Explicit non-goals: kernel-level performance, multi-tenant on a single tunnel, replacing Tailscale's UX.

## Deployment topology (Adversario Arena)

```
  Student laptop                 Cloudflare CDN             arena-manager (192.168.1.10)
  ──────────────                 ──────────────             ────────────────────────────
  arena-byoc                                                arena-tunnel-server
    ├─ wireguard-go (TUN)                                     ↑
    └─ WSS dialer ──► wss://wg-byoc.adversario.cl/tunnel ──►  │ WS upgrade
                           (CF free tunnel)                    ▼
                                                         UDP → wg-byoc (WireGuard iface)
                                                               │
                                                               ▼
                                                         route 10.128.0.0/9
                                                               │
                                                               ▼
                                                         OPNsense → scenario VMs
                                                         (10.128.x.x / 10.130.x.x)

  Control plane (arena-manager)
  ────────────────────────────
  arena-manager (Next.js)
    ├─ POST /api/byoc2/pair/init   ← student CLI calls this
    ├─ GET  /api/byoc2/pair/poll   ← CLI polls until authorized
    ├─ browser /byoc2/connect      ← student authorizes in browser
    └─ OpnsenseRetryJob saga
         ├─ OPNsense WG API   → adds peer to wg101 (OPNsense)
         └─ wg-peer.ts        → adds peer to local wg-byoc interface
```

`arena-tunnel-server` runs as a systemd service on the same machine as `arena-manager`. It bridges WSS frames → UDP → `wg-byoc`. The WireGuard interface `wg-byoc` (port 51820) lives on the manager host and routes student traffic into the scenario network via OPNsense.

## Pairing flow (v2 lifecycle)

```
Student CLI                     arena-manager                      Student browser
────────────                    ─────────────                      ───────────────
sudo arena-byoc
  └─ POST /pair/init
        ← {code, claimUrl}
  └─ prints code + URL
  └─ polls GET /pair/poll?code=X  (every 2s, up to 10min)
                                                         open claimUrl in browser
                                                         sign in (NextAuth)
                                                         click "Authorize device"
                                  creates Byoc2Peer row
                                  encrypts creds → DB
                                  enqueues wg_add saga
                                    ├─ OPNsense: add peer to wg101
                                    ├─ local: wg addconf wg-byoc
                                    └─ sets opnsenseSyncState=active
  └─ poll returns 200 (once opnsenseSyncState=active)
        ← {privateKey, tunnelIp, serverPubKey, revocationToken}
  └─ saves config (0600)
  └─ runConnect() → WG up + WSS shovel
  └─ fetches /api/users/me/c2-state (Bearer revocationToken)
  └─ prints connection banner (edge IP, SNI, HMAC cookie)
```

The poll endpoint blocks at 202 until `Byoc2Peer.opnsenseSyncState = 'active'`. This ensures the WireGuard server knows the peer's public key before the client sends its first handshake — otherwise the handshake is silently dropped.

Revocation token: a 32-byte random value issued once at poll-time. Only the SHA-256 hash is stored server-side. The raw token is the bearer for `DELETE /api/byoc2/peer/[id]` (logout). A leaked DB cannot forge a valid bearer.

## The wire protocol

```
Time ─►
              Client                        Server
              ──────                        ──────
WG datagram ─► WS BinaryFrame ─► CDN ─► WS BinaryFrame ─► UDP datagram ─► wg-byoc
WG datagram ◄─ WS BinaryFrame ◄─ CDN ◄─ WS BinaryFrame ◄─ UDP datagram ◄─ wg-byoc
```

**One binary WebSocket frame holds exactly one UDP datagram.** No length prefix, no headers, no envelope. Text frames are ignored.

Why not multiplex? A single WireGuard connection already multiplexes inner IP flows. Adding our own multiplexer is wasted complexity and a footgun on idle timeouts.

Why not protobuf/msgpack? The frame boundary IS the framing. Zero extra CPU, zero extra bytes.

### MTU math

- WireGuard wire packet: up to 1420 bytes (1500 Ethernet − WG overhead).
- WebSocket binary frame header: 2–14 bytes.
- TLS: ~25 bytes per record.
- Client TUN MTU set to **1380** to leave headroom for WS+TLS overhead.

### Why per-connection UDP socket on the server

Each new WS connection gets a fresh `net.DialUDP` to `wg-byoc`. This gives **each tunnel a distinct UDP source port** so WireGuard correctly demuxes peers. If we shared one socket, all students' traffic would look like one peer and WG would constantly tear down/rebuild handshakes.

## Component diagram

```
┌──────────────────────────────────────────────────────────────┐
│                     client/main.go                           │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ wireguard-go device                                    │  │
│  │   ├── conn.NewDefaultBind() (UDP)                      │  │
│  │   └── TUN device "arena-byoc"                         │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     ▼ UDP loopback                           │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Local UDP listener on 127.0.0.1:<random>               │  │
│  │   ├─ udp → ws goroutine                               │  │
│  │   └─ ws → udp goroutine                               │  │
│  └──────────────────┬───────────────────────────────────┘  │
└─────────────────────┼────────────────────────────────────────┘
                      │ WSS  wss://wg-byoc.adversario.cl/tunnel
          ┌───────────┴──────────────┐
          │   Cloudflare CDN         │
          │   TLS termination + proxy│
          └───────────┬──────────────┘
                      │
┌─────────────────────┼────────────────────────────────────────┐
│              server/main.go                                  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ HTTP server, /tunnel route                             │  │
│  │   ├── WS upgrade                                      │  │
│  │   ├── net.DialUDP("127.0.0.1:51820") per connection   │  │
│  │   └── bidirectional shovel goroutines                 │  │
│  └──────────────────┬───────────────────────────────────┘  │
└─────────────────────┼────────────────────────────────────────┘
                      ▼ UDP
┌─────────────────────────────────────────────────────────────┐
│  wg-byoc (WireGuard interface on arena-manager host)        │
│  10.201.0.1/16 — student peer pool (one /32 per peer)       │
│  peers managed by arena-manager via opnsense-saga.ts        │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
                  OPNsense firewall → scenario VMs
                  (10.128.0.0/9 supernet)
```

## Why these technologies

| Choice               | Alternative                   | Reason                                                              |
|----------------------|-------------------------------|---------------------------------------------------------------------|
| Go                   | Rust, C, Zig                  | wireguard-go exists, is official. Tiny static binary. Cross-compiles to 5 platforms for free. |
| wireguard-go         | Kernel WG via wg-quick        | No kernel module on the client side. Works on macOS and Windows without drivers. |
| gorilla/websocket    | nhooyr.io/websocket           | Mature, battle-tested, simple API.                                  |
| AGPL-3.0             | MIT, Apache-2.0               | Forces SaaS forks to publish modifications. Standard for security infra. |
| Cloudflare Tunnel    | ngrok, Fastly, raw VPS        | Free, mature, supports WS natively, no per-GB pricing.              |

## Alternatives considered (and rejected)

### Pure IPv6
Most LATAM ISPs hand out a routable /64 even on CGNAT'd v4. ISP modem firewalls v6 inbound by default and the consumer firmware doesn't expose that setting. Dead end without ISP cooperation.

### UPnP / NAT-PMP / PCP
Common ISP modem firmwares don't expose UPnP on the user tier.

### Hetzner / Oracle / AWS Free Tier as UDP relay
All work technically. All violate the "no monthly cost + no vendor lock-in" requirements. Oracle Free Tier ARM Ampere is the most defensible variant; a Helm chart for it remains a future option.

### Tailscale / Headscale + DERP
Tailscale Free supports 100 devices. Rejected because: (a) depends on Tailscale.com staying alive and free; (b) the DERP transport is opaque — we can't add scenario-specific routing hooks; (c) Tailscale's modified WG has subtle differences from upstream.

### udp2raw + cloudflared TCP mode
Doubles encapsulation (UDP → fake TLS → TCP → cloudflared → ...). Latency matched WSS, with more moving parts.

### Cloudflare Workers as UDP relay
Workers Free CPU-ms accounting makes sustained C2 traffic a time bomb. One noisy student can blow the daily budget and brick everyone else until UTC midnight.

## Failure modes & recovery

| Failure                               | What happens                                                                             | Recovery           |
|---------------------------------------|------------------------------------------------------------------------------------------|--------------------|
| cloudflared restarts                  | WSS drops. Client logs `[wss] read: ...` and reconnects within 3s.                       | Auto.              |
| ISP reboots modem                     | Same + DNS repropagate. PersistentKeepalive=25s re-handshakes.                            | Auto, ~30s.        |
| Student switches NAT (WiFi → hotspot) | WSS reconnects on new source IP. WG roaming handles it.                                  | Auto.              |
| wg-byoc interface restart             | All clients see UDP write timeouts. Next WS roundtrip triggers WG re-handshake.          | Auto, ~10s.        |
| arena-tunnel-server crash             | systemd restarts the process. WSS reconnects.                                             | systemd auto.      |
| Cloudflare drops WS as idle           | WG PersistentKeepalive=25s keeps frames flowing; CF's idle timeout is 100s.              | Auto.              |
| Peer revoked server-side              | CLI's 60s poll detects `status=revoked` and exits. `arena-byoc pair` re-pairs.           | User re-pairs.     |

## Hardening (production checklist)

- [ ] `arena-tunnel-server` only listens on loopback. CF tunnel or nginx terminates TLS upstream.
- [ ] Run `arena-tunnel-server` as a non-root user. No `CAP_NET_ADMIN` needed on the server side.
- [ ] Per-peer WG AllowedIPs is `/32` — one student can't impersonate another inside the tunnel.
- [ ] `wg-byoc` peer list managed exclusively by arena-manager saga; no manual `wg set` in production.
- [ ] Revocation tokens stored as SHA-256 hashes only; raw token never persisted server-side.
- [ ] On Windows, ship `wintun.dll` next to the binary. The bundled `assets/wintun-amd64.dll` is signed by WireGuard Inc.

## Roadmap

- Add preshared key on the WS handshake (`Sec-WebSocket-Protocol` header) so the endpoint rejects non-clients before the WG handshake runs.
- Windows ARM64 packaging (wintun-arm64 upstream stabilization).
- Optional HTTP/3 (QUIC) transport for environments where deep-packet inspection hairpins WSS.