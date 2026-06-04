# byoc2-tunnel

WireGuard-over-WebSocket tunnel for Adversario Arena's BYOC2 (Bring Your Own CobaltStrike) tier.

Two binaries, both pure Go (CGO disabled, statically linked):

- **`server/`** — WebSocket↔UDP forwarder. Listens HTTP, upgrades to WSS, shovels binary frames between the WS connection and a local UDP socket (typically the WireGuard kernel interface on the same host).
- **`client/`** (a.k.a. `arena-byoc`) — Single-binary student client. Embeds [wireguard-go](https://git.zx2c4.com/wireguard-go) for the WG protocol, [gorilla/websocket](https://github.com/gorilla/websocket) for transport. Creates a TUN device, configures WG via in-process IPC, wraps WG UDP through WSS to the server. Credentials are baked at compile-time via `-ldflags -X` so the student downloads a single binary and runs it with zero configuration.

## Why this exists

Adversario Arena runs out of a home network in Chile behind CGNAT — no public IPv4. CobaltStrike beacon callbacks need a stable, reachable ingress. Options ruled out:

| Option | Why not |
|---|---|
| VPS rental | Diego rejected monthly rental cost |
| Cloudflare Spectrum (UDP proxy) | $200+/mo, enterprise tier |
| Tailscale | Vendor lock-in, depends on tailscale.com being alive |
| Native WireGuard with port-forward | CGNAT ISP, no public v4; ISP modem v6 firewall blocks inbound |
| Hardware UART hack on the ISP modem | Possible, but invasive |

The remaining viable path: tunnel WireGuard's UDP datagrams **inside binary WebSocket frames** and let Cloudflare's free tier proxy them. Cloudflare proxies WS natively, no Spectrum needed. The server runs on a local LAN host (arena-manager); a cloudflared tunnel exposes it as `wg-byoc.adversario.cl:443`.

Latency cost: ~80–150 ms one-way from most of LATAM via the CF route. Acceptable for C2 callbacks with `sleep ≥ 30s`.

## Architecture

```
Student box                         Cloudflare                arena-manager (private)
─────────────                       ──────────                ──────────────────────
arena-byoc binary                                             byoc2-tunnel-server
   ├─ wireguard-go (TUN)                                          ↑
   └─ WSS dialer ─────────► wss://wg-byoc.... ─► cloudflared ─►   │  HTTP/WS upgrade
                                                                  ▼
                                                              wg-byoc kernel iface
                                                                  ↓
                                                              MASQUERADE → OPNsense
                                                              → scenario VLANs
```

Inside one binary WebSocket frame = exactly one WireGuard UDP datagram. No framing on top. The server dials UDP to its `--wg` target (default `127.0.0.1:51820`, the kernel WG socket) on each new WS connection so WireGuard sees a distinct UDP source per concurrent student.

Credentials embedded in the client at build time (via `-ldflags`):

- `main.privKeyB64` — base64 WireGuard private key for this student
- `main.serverPubKeyB64` — base64 WireGuard server public key
- `main.tunnelIP` — assigned tunnel IP (e.g. `10.201.0.5`)
- `main.serverHost` — WSS endpoint hostname (e.g. `wg-byoc.adversario.cl`)

## Build

### Server

```bash
cd server
go build -o byoc2-tunnel-server
./byoc2-tunnel-server --listen 127.0.0.1:8888 --wg 127.0.0.1:51820
```

Flags:

- `--listen` — HTTP bind address (default `127.0.0.1:8888`). Use loopback because cloudflared terminates TLS upstream.
- `--wg` — UDP target where unwrapped WG datagrams go (default `127.0.0.1:51820`).
- `--idle-timeout` — drop a UDP tunnel after N idle (default `5m`).

### Client (generic)

```bash
cd client
go build -o arena-byoc
./arena-byoc -priv <b64> -pub <b64> -ip 10.201.0.5 -host wg-byoc.adversario.cl
```

Flags (override the baked values):

- `-priv` — student WG private key (base64)
- `-pub` — server WG public key (base64)
- `-ip` — student's assigned tunnel IP
- `-host` — WSS server hostname
- `-v` — verbose WireGuard logs

### Client (per-student baked binary)

The intended distribution model. Use the helper script:

```bash
./build.sh \
  "<priv-b64>" \
  "<server-pub-b64>" \
  "10.201.0.5" \
  "wg-byoc.adversario.cl" \
  linux amd64 \
  ./arena-byoc-linux-amd64
```

The arena-manager API calls this on every `POST /api/byoc2/enroll` to produce a per-student, per-platform binary that needs zero runtime configuration. Cross-compiles to:

- linux/amd64, linux/arm64
- darwin/amd64, darwin/arm64
- windows/amd64

`assets/wintun-amd64.dll` is bundled into the Windows download ZIP because Windows requires the [wintun](https://www.wintun.net/) driver to create TUN devices.

## Run (client)

```bash
# Linux / macOS — needs root for /dev/net/tun
sudo ./arena-byoc

# Windows — needs Administrator; wintun.dll must sit next to the .exe
.\arena-byoc-windows-amd64.exe
```

Expected log:

```
[tun] creating device "arena-byoc"
[+] WG up: tunnelIP=10.201.0.5 server=wg-byoc.adversario.cl local-udp-port=43902
[wss] dialing wss://wg-byoc.adversario.cl/tunnel
[wss] connected
```

After connect, a network interface named `arena-byoc` exists with IP `10.201.0.5/24`. Ping the gateway:

```bash
ping 10.201.0.1
```

To route specific subnets through the tunnel (e.g. scenario VLANs):

```bash
sudo ip route add 10.128.130.0/24 dev arena-byoc
```

## Wire protocol

Trivial. One binary WS frame = one UDP datagram, both directions.

- Client → server: each `binary` frame is delivered verbatim to the configured UDP target (default the local kernel WG socket).
- Server → client: each UDP datagram received is delivered verbatim as one `binary` frame.

Text frames are ignored. No framing on top of the WS frames. The MTU is whatever WireGuard sets on the TUN (`1380` by default in this client) minus standard WG overhead.

No multiplexing — one WS connection = one tunnel. Multiple students get separate WS connections.

## Files

```
byoc2-tunnel/
├── README.md          ← you are here
├── build.sh           ← per-student baked-binary build helper
├── server/
│   ├── go.mod
│   ├── go.sum
│   └── main.go        ← 152 LOC server
├── client/
│   ├── go.mod
│   ├── go.sum
│   └── main.go        ← ~400 LOC client (wireguard-go + WSS)
└── assets/
    └── wintun-amd64.dll  ← required for Windows TUN
```

## License

Released under AGPL-3.0 alongside the rest of the open-sourced subset of Adversario Arena. See `../../LICENSE` if present.

Forks must remain open. The tunnel transport is intentionally minimal and unopinionated; if you want to lift it for your own self-hosted setup, you only need `server/`, `client/`, and `build.sh` — they're standalone with no Adversario-specific code.
