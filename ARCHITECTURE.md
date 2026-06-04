# Architecture

> The design notes that didn't fit in the README. Read this if you want to fork, reimplement, or just understand the trade-offs.

## Goals (in order)

1. **Zero recurring cost.** No VPS, no Spectrum, no Tailscale subscription. Diego's home network is behind CGNAT and ISP refuses port forwarding — we still need a stable public ingress.
2. **Stable.** Surviving Cloudflare tunnel restarts, ISP rebooting the modem, and student NAT type changes.
3. **Single binary distribution.** A user downloads one file, runs it, gets a tunnel. No installer, no config wizard, no SDK.
4. **Open source.** No vendor lock-in. Anyone with similar constraints can deploy it.
5. **Hostile-network friendly.** Hotel WiFi, corporate proxies, captive portals — should pass through WSS over 443 the same way every other HTTPS app does.

Explicit non-goals: kernel-level performance, multi-tenant on a single tunnel, replacing Tailscale's UX.

## The wire protocol

```
Time ─►
              Client                        Server
              ──────                        ──────
WG datagram ─► WS BinaryFrame ─► CDN ─► WS BinaryFrame ─► UDP datagram ─► wg-kernel
WG datagram ◄─ WS BinaryFrame ◄─ CDN ◄─ WS BinaryFrame ◄─ UDP datagram ◄─ wg-kernel
```

That's it. **One binary WebSocket frame holds exactly one UDP datagram.** No length prefix, no headers, no envelope. Text frames are ignored.

Why not multiplex multiple UDP flows into one WS? Because we don't need to. A single WireGuard connection has its own internal multiplexing of inner IP flows. Adding our own multiplexer would be wasted complexity and a footgun on idle timeouts.

Why not protobuf / msgpack / any framing? Adds CPU and bytes to a tight path. The frame boundary IS the framing.

### MTU math

- WireGuard wire packet maximum is typically 1420 bytes (1500 Ethernet MTU − WG overhead).
- WebSocket binary frame header is 2–14 bytes depending on payload size and masking. For payloads ≤ 125 bytes it's 2 bytes; for ≤ 64 KB it's 4 bytes (without masking).
- TLS adds another ~25 bytes per record.
- Total over-the-wire overhead per WG datagram: ≈ 30 bytes (~2%).

The client sets the TUN MTU to **1380** to leave headroom for the WS+TLS overhead. Larger MTUs would cause fragmentation at the CDN's TCP layer, which kills performance more than the smaller MTU costs in fragmentation at the IP layer.

### Why per-connection UDP socket on the server

For each new WS connection, the server `net.DialUDP`s a fresh socket to the WG target. This is critical: it gives **each tunnel a distinct UDP source port** so WireGuard correctly demuxes peers.

If we shared a single UDP socket across all tunnels, every student's traffic would look like it came from one source and WG would constantly tear down/rebuild handshakes. Don't be tempted to "optimize" this.

## Component diagram

```
                            ┌─────────────────────────────────────────────┐
                            │              client/main.go                  │
                            │  ┌────────────────────────────────────────┐ │
                            │  │ wireguard-go device                    │ │
                            │  │   ├── conn.NewDefaultBind() (UDP)      │ │
                            │  │   └── TUN device (arena-byoc)          │ │
                            │  └─────────────┬──────────────────────────┘ │
                            │                ▼ UDP                          │
                            │  ┌──────────────────────────────────────────┐│
                            │  │ Local UDP listener on 127.0.0.1:<random> ││
                            │  │  + bridge goroutines:                     ││
                            │  │   ┌────────────┐  ┌─────────────────┐    ││
                            │  │   │ udp → ws   │  │  ws → udp        │    ││
                            │  │   └────────────┘  └─────────────────┘    ││
                            │  └─────────────┬─────────────────────────────┘│
                            │                ▼ WSS                          │
                            └────────────────┼──────────────────────────────┘
                                             │
                                             ▼   wss://your-host/tunnel
                            ┌───────── Cloudflare CDN ──────────┐
                            │  TLS termination + WS proxy        │
                            └───────────────┬────────────────────┘
                                             │
                                             ▼
                            ┌────────────────┴─────────────────────────────┐
                            │              server/main.go                  │
                            │  ┌──────────────────────────────────────────┐│
                            │  │ HTTP server, /tunnel route               ││
                            │  │   ├── WS upgrade                          ││
                            │  │   ├── new net.DialUDP("127.0.0.1:51820") ││
                            │  │   └── bidirectional shovel goroutines    ││
                            │  └─────────────┬─────────────────────────────┘│
                            │                ▼                              │
                            └────────────────┼──────────────────────────────┘
                                             ▼
                            ┌─────────────────────────────────────────────┐
                            │ WireGuard kernel/userspace on same host     │
                            │ (wg0 / wg-byoc / whatever you named it)     │
                            └─────────────────────────────────────────────┘
```

## Why these technologies

| Choice                | Alternative                  | Why we picked it                                                 |
|-----------------------|------------------------------|------------------------------------------------------------------|
| Go                    | Rust, C, Zig                 | wireguard-go exists & is officially supported. Tiny static binary. Cross-compiles for free to 5 platforms. |
| wireguard-go (userspace) | Kernel WG via wg-quick     | Single binary on the client side, no kernel module dependency, works on macOS and Windows |
| gorilla/websocket     | nhooyr.io/websocket, net/http upgrade only | Mature, battle-tested, simple API. nhooyr is nicer but adds dependency churn. |
| AGPL-3.0              | MIT, Apache-2.0              | Forces SaaS forks to publish their modifications. Standard for security infra. Pick this if you want changes back. |
| Cloudflare Tunnel     | ngrok, Fastly, raw VPS       | Free, mature, supports WS natively, no per-GB pricing            |

## Alternatives considered (and rejected)

### Pure IPv6
Most LATAM ISPs hand out a routable /64 via SLAAC even on CGNAT'd v4. Tested on Diego's network — ISP modem firewalls v6 inbound by default and the customer tier can't disable it. Dead end without superadmin modem credentials, which Mundo Pacífico keeps proprietary.

### UPnP / NAT-PMP / PCP
ISP modem (Huawei HG5853SF on Mundo Pacífico's firmware) doesn't expose UPnP to the user tier.

### Hetzner / Oracle / AWS Free Tier as UDP relay
All work technically, all violate the "no monthly cost" + "no vendor lock-in" hard requirements. Oracle Free Tier ARM Ampere is the most defensible variant; we may still ship a Helm chart for it as an alternative deployment.

### Tailscale / Headscale + DERP
Tailscale Free supports 100 devices, free forever. Rejected because: (a) you depend on Tailscale.com staying alive and free; (b) the DERP transport is opaque to us — we can't add scenario-specific hooks; (c) Tailscale uses its own modified WG which has subtle differences from upstream.

### udp2raw + cloudflared TCP mode
Works but doubles encapsulation (UDP → fake TLS → TCP → cloudflared → TCP → ...). Latency penalty matched WSS, with more moving parts and CF Access free tier's 50-user cap as a hard ceiling.

### Cloudflare Workers as a UDP relay
Workers Free CPU-ms accounting makes sustained C2 traffic a time bomb. One noisy user can blow the daily budget and brick every other user until UTC midnight.

## Failure modes & recovery

| Failure                                  | What happens                                                                                  | Recovery                            |
|------------------------------------------|-----------------------------------------------------------------------------------------------|-------------------------------------|
| cloudflared restarts                     | WSS connection drops. Client logs `[wss] read: ...` and reconnects within 3s.                | Auto, no user action.               |
| Home ISP reboots router                  | Same as above plus DNS may need to repropagate. PersistentKeepalive=25s on WG re-handshakes.  | Auto, ~30s downtime.                |
| Student switches NAT (laptop → phone hotspot) | WSS reconnects on new source IP. WG roaming handles it as long as the peer pubkey stays the same. | Auto.                               |
| Server-side WG kernel restart            | All clients see UDP write timeouts. Next WS roundtrip triggers WG re-handshake.               | Auto, ~10s downtime.                |
| Server process panic                     | systemd restarts the process. WSS reconnects.                                                  | systemd auto-restart.               |
| CDN drops the WS as idle                 | We hold WG PersistentKeepalive=25s so frames flow constantly. Cloudflare's idle timeout is 100s by default — we beat it. | Auto. |
| Long DNS TTL on the public hostname      | If you change the hostname's tunnel target, old clients keep reaching the old endpoint until DNS expires. | Use TTL ≤ 300s.                     |

## Hardening (production checklist)

- [ ] Server only listens on loopback. Public access goes through cloudflared. Verify with `ss -tlnp | grep arena-tunnel-server`.
- [ ] `--restrict-to` not applicable here (we don't proxy arbitrary targets; only WG). The `--wg` flag is the only mutable target.
- [ ] Run server as a non-root user. The server doesn't need any privileged capabilities.
- [ ] Per-peer WG configuration limits each client to a `/32` `AllowedIPs` so they can't impersonate each other inside the tunnel.
- [ ] MASQUERADE or static route + per-peer SNAT on the host, depending on whether you want per-peer source IPs in your downstream firewall logs.
- [ ] Set TUN MTU explicitly in your client config — don't let the OS guess.
- [ ] On Windows, ship `wintun.dll` next to the binary. The bundled `assets/wintun-amd64.dll` is signed by WireGuard Inc.

## Roadmap

- `v0.2`: optional preshared key on the WS handshake (`Sec-WebSocket-Protocol` header) so the CDN-fronted endpoint can reject non-clients before the WG handshake even runs.
- `v0.3`: Windows on ARM64 (wintun.dll for arm64 is shipping in 2026; we'll add it once it's stable upstream).
- `v0.4`: optional HTTP/3 (QUIC) transport variant for environments where WSS gets hairpinned by deep packet inspection.
- `v1.0`: freeze the wire protocol. Document it in an RFC-style spec so third parties can build compatible clients/servers.
