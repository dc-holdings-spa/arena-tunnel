// arena-byoc — single-binary BYOC2 client.
//
// Two ways to ship credentials:
//
//   1. Browser pairing (the new default UX):
//        $ arena-byoc
//        → prints a 6-char code, opens https://arena.adversario.cl/byoc2/connect?code=...
//        → user authorizes in the browser, binary polls /api/byoc2/pair/poll
//        → creds are written to ~/.config/arena-byoc/config.json (0600)
//        → subsequent runs read that file and skip the browser flow.
//
//   2. Legacy bake-at-build (still supported for headless / CI):
//        go build -ldflags "-X main.privKeyB64=... -X main.serverPubKeyB64=...
//                           -X main.tunnelIP=... -X main.serverHost=..."
//      or use the supplied build.sh, which writes a generated init() file.
//      Either way, baked creds win over any on-disk config.
//
// The binary creates a userspace WireGuard device on a TUN interface and
// shovels WG UDP traffic over WSS to <serverHost>/tunnel. Run as root
// (Linux/macOS) or Administrator (Windows) — TUN needs CAP_NET_ADMIN.

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Baked at compile-time via -ldflags -X. Empty on a stock binary.
// build.sh injects these by generating an init() file at build time.
var (
	privKeyB64      = "" // peer (student) WG private key
	serverPubKeyB64 = "" // arena WG server public key
	tunnelIP        = "" // e.g. "10.201.0.5"
	serverHost      = "wg-byoc.adversario.cl"
	tunnelName      = "arena-byoc"

	// version is overridden via -ldflags -X main.version=...
	version = "dev"
)

// defaultArenaBaseURL is where the binary talks to the control plane
// for pairing / status / logout. Override via --arena or ARENA_BYOC_URL.
const defaultArenaBaseURL = "https://arena.adversario.cl"

func b64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode b64: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func runShovel(ctx context.Context, udpConn *net.UDPConn, wsURL string) {
	for ctx.Err() == nil {
		dialer := websocket.DefaultDialer
		dialer.HandshakeTimeout = 15 * time.Second
		log.Printf("[wss] dialing %s", wsURL)
		ws, resp, err := dialer.Dial(wsURL, nil)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			log.Printf("[wss] dial failed status=%d err=%v — retry 3s", status, err)
			select {
			case <-time.After(3 * time.Second):
			case <-ctx.Done():
				return
			}
			continue
		}
		log.Printf("[wss] connected")
		runOneTunnel(ctx, udpConn, ws)
		log.Printf("[wss] connection closed — reconnecting")
	}
}

// wssReadTimeout is how long we wait for any inbound frame (data or pong)
// before declaring the connection dead. Must be > wssKeepaliveInterval.
const (
	wssKeepaliveInterval = 45 * time.Second
	wssReadTimeout       = 90 * time.Second
)

// runOneTunnel runs the bidirectional shovel until either side dies, then returns.
func runOneTunnel(ctx context.Context, udpConn *net.UDPConn, ws *websocket.Conn) {
	defer ws.Close()
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Reset read deadline on every pong so the keepalive goroutine below
	// keeps the connection alive through Cloudflare's idle-timeout window.
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(wssReadTimeout))
	})
	ws.SetReadDeadline(time.Now().Add(wssReadTimeout))

	// Keepalive: send a WebSocket ping every 45 s. Cloudflare drops idle
	// WebSocket connections after ~100 s; 45 s leaves comfortable headroom.
	go func() {
		ticker := time.NewTicker(wssKeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := ws.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-subCtx.Done():
				return
			}
		}
	}()

	// Track WG's local UDP source so we know where to deliver WSS->UDP replies.
	var wgPeer *net.UDPAddr
	peerCh := make(chan *net.UDPAddr, 1)

	// UDP -> WSS
	go func() {
		defer cancel()
		buf := make([]byte, 65535)
		for {
			n, peer, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("[udp] read: %v", err)
				return
			}
			if wgPeer == nil {
				wgPeer = peer
				select {
				case peerCh <- peer:
				default:
				}
			}
			ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				// Suppress noise when the connection was closed intentionally
				// (e.g. Cloudflare 300s hard-reset → reconnect in progress).
				if subCtx.Err() == nil {
					log.Printf("[wss] write: %v", err)
				}
				return
			}
		}
	}()

	// WSS -> UDP
	go func() {
		defer cancel()
		for {
			typ, data, err := ws.ReadMessage()
			if err != nil {
				log.Printf("[wss] read: %v", err)
				return
			}
			if typ != websocket.BinaryMessage {
				// ping/pong/text frames — pong handler already reset deadline
				continue
			}
			// Wait for WG peer to be known (it dials us with the first packet)
			if wgPeer == nil {
				select {
				case wgPeer = <-peerCh:
				case <-subCtx.Done():
					return
				case <-time.After(30 * time.Second):
					log.Printf("[udp] no WG peer seen yet, dropping inbound")
					continue
				}
			}
			if _, err := udpConn.WriteToUDP(data, wgPeer); err != nil {
				log.Printf("[udp] write: %v", err)
				return
			}
		}
	}()

	<-subCtx.Done()
}

// Routes pushed through the tunnel automatically. Covers the entire
// scenario VLAN supernet (10.128.0.0/9) so students can reach every
// scenario without remembering to add routes by hand. The tunnel
// network (10.201.0.0/16) is implicit from the address assignment.
var pushRoutes = []string{
	"10.128.0.0/9",
}

func configureTUN(ipStr string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("interface config only implemented for linux (PR welcome)")
	}
	// Set address. /16 so the whole tunnel pool (10.201.0.0/16, widened from
	// /24) is on-link — the server gateway 10.201.0.1 and any peer /32 sit in
	// the same supernet regardless of which /24 this client's IP landed in.
	if err := exec.Command("ip", "addr", "add", ipStr+"/16", "dev", tunnelName).Run(); err != nil {
		return fmt.Errorf("ip addr add: %w", err)
	}
	// Bring up
	if err := exec.Command("ip", "link", "set", tunnelName, "up").Run(); err != nil {
		return fmt.Errorf("ip link set up: %w", err)
	}
	// Install routes
	for _, r := range pushRoutes {
		// Replace, not add, so re-running over a partial config is safe.
		if err := exec.Command("ip", "route", "replace", r, "dev", tunnelName).Run(); err != nil {
			log.Printf("[route] failed to install %s: %v", r, err)
		} else {
			log.Printf("[route] %s via %s", r, tunnelName)
		}
	}
	return nil
}

func teardownTUN() {
	if runtime.GOOS == "linux" {
		for _, r := range pushRoutes {
			exec.Command("ip", "route", "del", r, "dev", tunnelName).Run()
		}
		exec.Command("ip", "link", "set", tunnelName, "down").Run()
		exec.Command("ip", "addr", "flush", "dev", tunnelName).Run()
	}
}

// ---------------- entry point + subcommand dispatch ----------------

// rootFlags holds everything parsed from the command line. We use a
// single flag set rather than per-subcommand sets so the legacy
// `arena-byoc -priv ... -pub ...` syntax keeps working without forcing
// the user to remember which subcommand it lived under.
type rootFlags struct {
	subcommand string

	// global / cross-cutting
	arena      string
	configPath string
	noBrowser  bool
	forcePair  bool
	keepServer bool // logout --keep-server
	token      string

	// legacy override
	priv string
	pub  string
	ip   string
	host string

	verbose bool
}

func parseArgs() *rootFlags {
	fs := flag.NewFlagSet("arena-byoc", flag.ExitOnError)
	rf := &rootFlags{}

	fs.StringVar(&rf.arena, "arena", "", "Override arena base URL (env: ARENA_BYOC_URL).")
	fs.StringVar(&rf.configPath, "config", "", "Override config file path (env: ARENA_BYOC_CONFIG).")
	fs.BoolVar(&rf.noBrowser, "no-browser", false, "Do not try to launch a browser; print code+URL only.")
	fs.BoolVar(&rf.forcePair, "force-pair", false, "Ignore cached config and re-pair.")
	fs.BoolVar(&rf.keepServer, "keep-server", false, "(logout) Only wipe local config; do not call /peer/revoke.")
	fs.StringVar(&rf.token, "token", "", "Headless: exchange one-shot token for creds.")

	fs.StringVar(&rf.priv, "priv", "", "override baked priv key (b64) — headless")
	fs.StringVar(&rf.pub, "pub", "", "override baked server pub key (b64) — headless")
	fs.StringVar(&rf.ip, "ip", "", "override baked tunnel IP — headless")
	fs.StringVar(&rf.host, "host", "", "override baked server host — headless")
	fs.BoolVar(&rf.verbose, "v", false, "verbose WG logs")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usageText)
		fs.PrintDefaults()
	}

	// Pull the optional subcommand off os.Args before flag parsing,
	// so `arena-byoc logout --keep-server` and `arena-byoc -v` both work.
	args := os.Args[1:]
	if len(args) > 0 && !isFlagLike(args[0]) {
		switch args[0] {
		case "logout", "status", "pair", "version", "help":
			rf.subcommand = args[0]
			args = args[1:]
		case "--help", "-h":
			fs.Usage()
			os.Exit(ExitOK)
		}
	}
	if err := fs.Parse(args); err != nil {
		// flag.ExitOnError already printed; defensive exit.
		os.Exit(ExitFatalRuntime)
	}

	// Environment fallbacks for the two URL-ish settings.
	if rf.arena == "" {
		if env := os.Getenv("ARENA_BYOC_URL"); env != "" {
			rf.arena = env
		} else {
			rf.arena = defaultArenaBaseURL
		}
	}
	return rf
}

func isFlagLike(s string) bool {
	return len(s) > 0 && s[0] == '-'
}

const usageText = `arena-byoc — BYOC2 client tunnel for Arena.

Usage:
  arena-byoc [flags]              Pair if needed, then run tunnel.
  arena-byoc pair [--force]       Force the browser-pairing flow.
  arena-byoc logout [--keep-server]
                                  Wipe local config; revoke peer server-side.
  arena-byoc status               Show stored identity + ping arena.
  arena-byoc version              Print build version.
  arena-byoc help                 Print this message.

Flags:
`

// dispatchSubcommand fans the parsed flags out to the right entry point.
// Returns the desired process exit code.
func dispatchSubcommand(ctx context.Context, rf *rootFlags) int {
	switch rf.subcommand {
	case "version":
		fmt.Printf("arena-byoc %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return ExitOK
	case "help":
		fmt.Fprint(os.Stdout, usageText)
		return ExitOK
	case "logout":
		return runLogout(ctx, rf)
	case "status":
		return runStatus(ctx, rf)
	case "pair":
		// `pair` is just "default with forcePair=true" — fall through.
		rf.forcePair = true
		return runDefault(ctx, rf)
	default:
		return runDefault(ctx, rf)
	}
}

// runDefault is the BOOTSTRAP → PAIR-if-needed → CONNECT path.
func runDefault(ctx context.Context, rf *rootFlags) int {
	// 1. Legacy headless overrides win — never read or write the config file.
	if rf.priv != "" || rf.pub != "" || rf.ip != "" || rf.host != "" {
		return runConnect(ctx, rf, &Config{
			Version:      ConfigSchemaVersion,
			PrivateKey:   pick(rf.priv, privKeyB64),
			ServerPubKey: pick(rf.pub, serverPubKeyB64),
			TunnelIP:     pick(rf.ip, tunnelIP),
			ServerHost:   pick(rf.host, serverHost),
		})
	}

	// 2. Baked-at-build creds (from build.sh's generated init) — also skip the file.
	if privKeyB64 != "" && serverPubKeyB64 != "" && tunnelIP != "" {
		return runConnect(ctx, rf, &Config{
			Version:      ConfigSchemaVersion,
			PrivateKey:   privKeyB64,
			ServerPubKey: serverPubKeyB64,
			TunnelIP:     tunnelIP,
			ServerHost:   serverHost,
		})
	}

	// 3. Headless --token: claim straight from server, persist, connect.
	if rf.token != "" {
		path, err := ResolveConfigPath(rf.configPath)
		if err != nil {
			log.Printf("[config] resolve: %v", err)
			return ExitFatalRuntime
		}
		c := newHTTPClient()
		claimed, code, err := claimByToken(ctx, c, pairOptions{
			ArenaBaseURL: rf.arena,
			ConfigPath:   path,
			ClientVer:    version,
		}, rf.token)
		if err != nil {
			log.Printf("[pair] %v", err)
			return code
		}
		cfg := &Config{
			Version:      ConfigSchemaVersion,
			TunnelIP:     claimed.TunnelIP,
			PrivateKey:   claimed.PrivateKey,
			ServerPubKey: claimed.ServerPubKey,
			ServerHost:   claimed.ServerHost,
			UserEmail:    claimed.UserEmail,
			PairedAt:     time.Now().UTC().Format(time.RFC3339),
			ArenaBaseURL: rf.arena,
			DeviceID:     claimed.DeviceID,
		}
		if err := SaveConfig(path, cfg); err != nil {
			log.Printf("[config] save: %v (tunnel will still start)", err)
		}
		return runConnect(ctx, rf, cfg)
	}

	// 4. Normal path: load from disk, maybe pair, then connect.
	path, err := ResolveConfigPath(rf.configPath)
	if err != nil {
		log.Printf("[config] resolve: %v", err)
		return ExitFatalRuntime
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		log.Printf("[config] read %s: %v", path, err)
		if os.IsPermission(err) {
			return ExitConfigPermDenied
		}
		return ExitFatalRuntime
	}

	if rf.forcePair || cfg == nil || !cfg.Complete() {
		fresh, exitCode, perr := PairAndPersist(ctx, pairOptions{
			ArenaBaseURL: rf.arena,
			ConfigPath:   path,
			ClientVer:    version,
			NoBrowser:    rf.noBrowser,
		})
		if perr != nil {
			log.Printf("[pair] %v", perr)
			return exitCode
		}
		cfg = fresh
	}

	// Pre-flight: check the stored peer is still active before bringing up
	// the tunnel. Catches the case where the peer was revoked server-side
	// while the binary was not running (e.g. admin revoke, re-pair from
	// another machine). Wipe config + re-pair rather than starting a
	// zombie tunnel that silently drops all traffic.
	if cfg.ArenaBaseURL != "" {
		revoked, err := pingC2State(ctx, cfg.ArenaBaseURL, cfg.RevocationToken, cfg.PrivateKey)
		if err != nil {
			log.Printf("[preflight] status check failed (%v) — proceeding anyway", err)
		} else if revoked {
			log.Println("[!] stored peer has been revoked — wiping config and re-pairing.")
			_ = WipeConfig(path)
			fresh, exitCode, perr := PairAndPersist(ctx, pairOptions{
				ArenaBaseURL: cfg.ArenaBaseURL,
				ConfigPath:   path,
				ClientVer:    version,
				NoBrowser:    rf.noBrowser,
			})
			if perr != nil {
				log.Printf("[pair] %v", perr)
				return exitCode
			}
			cfg = fresh
		}
	}

	return runConnect(ctx, rf, cfg)
}

// runConnect is the CONNECT state: stand up WG + TUN + WSS shovel and
// block on SIGINT.
func runConnect(ctx context.Context, rf *rootFlags, cfg *Config) int {
	if cfg.PrivateKey == "" || cfg.ServerPubKey == "" || cfg.TunnelIP == "" {
		log.Printf("[connect] missing creds (priv/pub/ip)")
		return ExitFatalRuntime
	}
	host := cfg.ServerHost
	if host == "" {
		host = serverHost // package default ("wg-byoc.adversario.cl")
	}

	privHex, err := b64ToHex(cfg.PrivateKey)
	if err != nil {
		log.Printf("[connect] priv key: %v", err)
		return ExitFatalRuntime
	}
	srvHex, err := b64ToHex(cfg.ServerPubKey)
	if err != nil {
		log.Printf("[connect] srv pub: %v", err)
		return ExitFatalRuntime
	}

	log.Printf("[tun] creating device %q", tunnelName)
	tdev, err := tun.CreateTUN(tunnelName, 1380)
	if err != nil {
		log.Printf("[tun] create: %v (run as root?)", err)
		return ExitFatalRuntime
	}

	level := device.LogLevelError
	if rf.verbose {
		level = device.LogLevelVerbose
	}
	logger := device.NewLogger(level, "[wg] ")

	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("[udp] listen: %v", err)
		dev.Close()
		tdev.Close()
		return ExitFatalRuntime
	}
	localPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	ipcConfig := fmt.Sprintf(
		"private_key=%s\n"+
			"listen_port=0\n"+
			"public_key=%s\n"+
			"endpoint=127.0.0.1:%d\n"+
			"allowed_ip=0.0.0.0/0\n"+
			"persistent_keepalive_interval=25\n",
		privHex, srvHex, localPort)
	if err := dev.IpcSet(ipcConfig); err != nil {
		log.Printf("[wg] ipc set: %v", err)
		udpConn.Close()
		dev.Close()
		tdev.Close()
		return ExitFatalRuntime
	}
	if err := dev.Up(); err != nil {
		log.Printf("[wg] device up: %v", err)
		udpConn.Close()
		dev.Close()
		tdev.Close()
		return ExitFatalRuntime
	}

	if err := configureTUN(cfg.TunnelIP); err != nil {
		log.Printf("[tun] config: %v", err)
		udpConn.Close()
		dev.Close()
		tdev.Close()
		return ExitFatalRuntime
	}
	defer teardownTUN()

	log.Printf("[+] arena-byoc %s", version)
	log.Printf("[+] WG up: tunnelIP=%s server=%s local-udp-port=%d", cfg.TunnelIP, host, localPort)
	if cfg.UserEmail != "" {
		log.Printf("[+] identity: %s", cfg.UserEmail)
	}

	shovelCtx, cancel := context.WithCancel(ctx)
	wsURL := (&url.URL{Scheme: "wss", Host: host, Path: "/tunnel"}).String()
	go runShovel(shovelCtx, udpConn, wsURL)

	// Poll /api/users/me/c2-state every 60 s with the revocationToken Bearer.
	// Two jobs in one call:
	//   1. Bumps Byoc2Peer.lastCliFetchAt so the dashboard shows LIVE (not OFFLINE).
	//   2. Detects server-side revocation — if byoc2.status == "revoked", exit.
	// Falls back to pubkey-based /peer/status when no revocationToken is stored
	// (legacy configs from before v1.6.0).
	if cfg.ArenaBaseURL != "" {
		go func() {
			ticker := time.NewTicker(60 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					revoked, err := pingC2State(shovelCtx, cfg.ArenaBaseURL, cfg.RevocationToken, cfg.PrivateKey)
					if err != nil {
						continue // transient — ignore, try next tick
					}
					if revoked {
						log.Println("[!] peer revoked server-side — shutting down. Run `arena-byoc pair` to re-pair.")
						cancel()
						return
					}
				case <-shovelCtx.Done():
					return
				}
			}
		}()
	}

	<-shovelCtx.Done()
	log.Println("[!] shutdown requested")
	cancel()
	dev.Close()
	tdev.Close()
	udpConn.Close()
	time.Sleep(300 * time.Millisecond)
	log.Println("[!] bye")
	return ExitOK
}

// runLogout — wipe local config, best-effort revoke server-side.
func runLogout(ctx context.Context, rf *rootFlags) int {
	path, err := ResolveConfigPath(rf.configPath)
	if err != nil {
		log.Printf("[logout] resolve config path: %v", err)
		return ExitFatalRuntime
	}
	cfg, lerr := LoadConfig(path)
	if lerr != nil && !os.IsNotExist(lerr) {
		log.Printf("[logout] read %s: %v", path, lerr)
	}
	if cfg == nil {
		fmt.Println("No config to remove.")
		return ExitOK
	}

	// Best-effort server-side revoke.
	if !rf.keepServer {
		arena := cfg.ArenaBaseURL
		if arena == "" {
			arena = rf.arena
		}
		if err := bestEffortRevoke(ctx, arena, cfg.PrivateKey); err != nil {
			fmt.Fprintf(os.Stderr, "[warn] could not revoke server-side: %v\n", err)
		}
	}

	if err := WipeConfig(path); err != nil {
		fmt.Fprintf(os.Stderr, "[logout] could not wipe %s: %v\n", path, err)
		return ExitConfigUnlinkFailed
	}
	fmt.Println("Logged out. Config wiped.")
	return ExitOK
}

// bestEffortRevoke posts the peer pubkey to /api/byoc2/peer/revoke.
// The server is expected to mark the peer revoked. Auth is by pubkey
// ownership — the server already knows which user owns which key.
func bestEffortRevoke(ctx context.Context, arena, privB64 string) error {
	if privB64 == "" {
		return nil
	}
	pubB64, err := derivePubKey(privB64)
	if err != nil {
		return err
	}
	endpoint, err := joinURL(arena, "/api/byoc2/peer/revoke")
	if err != nil {
		return err
	}
	c := newHTTPClient()
	body := map[string]string{"publicKey": pubB64}
	resp, err := doJSON(ctx, c, "POST", endpoint, userAgent(version), body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server HTTP %d", resp.StatusCode)
	}
	return nil
}

// runStatus — print stored identity + ping arena for liveness.
func runStatus(ctx context.Context, rf *rootFlags) int {
	path, err := ResolveConfigPath(rf.configPath)
	if err != nil {
		log.Printf("[status] resolve config path: %v", err)
		return ExitFatalRuntime
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		log.Printf("[status] read %s: %v", path, err)
		return ExitFatalRuntime
	}
	if cfg == nil {
		fmt.Println("Not paired. Run `arena-byoc` to pair.")
		return ExitFatalRuntime
	}

	fmt.Printf("config:       %s\n", path)
	fmt.Printf("identity:     %s\n", cfg.UserEmail)
	fmt.Printf("tunnel ip:    %s\n", cfg.TunnelIP)
	fmt.Printf("server host:  %s\n", cfg.ServerHost)
	fmt.Printf("paired at:    %s\n", cfg.PairedAt)
	if cfg.DeviceID != "" {
		fmt.Printf("device id:    %s\n", cfg.DeviceID)
	}

	arena := cfg.ArenaBaseURL
	if arena == "" {
		arena = rf.arena
	}
	state, perr := fetchPeerStatus(ctx, arena, cfg.PrivateKey)
	if perr != nil {
		fmt.Printf("arena state:  (unreachable: %v)\n", perr)
		return ExitOK
	}
	fmt.Printf("arena state:  %s\n", state)
	if state == "revoked" {
		fmt.Println("Run `arena-byoc pair --force` to re-pair.")
		return ExitPairInitFailed
	}
	return ExitOK
}

// pingC2State calls GET /api/users/me/c2-state with a Bearer revocationToken.
// Two effects: bumps lastCliFetchAt (→ dashboard shows LIVE) and returns
// revoked=true when the peer has been revoked server-side.
// Falls back to fetchPeerStatus (pubkey) when no revocationToken is available.
func pingC2State(ctx context.Context, arena, revToken, privB64 string) (revoked bool, err error) {
	if revToken == "" {
		// Legacy config — fall back to pubkey-based check.
		status, e := fetchPeerStatus(ctx, arena, privB64)
		return status == "revoked", e
	}
	endpoint, e := joinURL(arena, "/api/users/me/c2-state")
	if e != nil {
		return false, e
	}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if e != nil {
		return false, e
	}
	req.Header.Set("Authorization", "Bearer "+revToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent(version))
	resp, e := newHTTPClient().Do(req)
	if e != nil {
		return false, e
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		// Token revoked or expired — treat as revoked peer.
		return true, nil
	}
	if resp.StatusCode >= 400 {
		return false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var body struct {
		Byoc2 *struct {
			Status string `json:"status"`
		} `json:"byoc2"`
	}
	if e := json.NewDecoder(resp.Body).Decode(&body); e != nil {
		return false, e
	}
	return body.Byoc2 != nil && body.Byoc2.Status == "revoked", nil
}

// fetchPeerStatus calls /api/byoc2/peer/status?pubkey=<b64> with a short
// timeout. Returns the textual state ("active"/"revoked"/"unknown") or
// an error if the server can't be reached.
func fetchPeerStatus(ctx context.Context, arena, privB64 string) (string, error) {
	if privB64 == "" {
		return "unknown", nil
	}
	pubB64, err := derivePubKey(privB64)
	if err != nil {
		return "", err
	}
	endpoint, err := joinURL(arena, "/api/byoc2/peer/status")
	if err != nil {
		return "", err
	}
	endpoint += "?pubkey=" + url.QueryEscape(pubB64)

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent(version))
	resp, err := newHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "unknown", nil
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode status: %w", err)
	}
	if body.Status == "" {
		return "unknown", nil
	}
	return body.Status, nil
}

// derivePubKey converts a base64 WireGuard private key into its
// corresponding base64 public key via curve25519 scalar mult.
func derivePubKey(privB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return "", fmt.Errorf("decode priv: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("priv key wrong length: %d", len(raw))
	}
	var priv [32]byte
	copy(priv[:], raw)
	// WG private-key clamping: same bit-twiddle as RFC 7748 / wg-quick genkey.
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("curve25519: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

func main() {
	rf := parseArgs()

	// Root context cancelled on SIGINT/SIGTERM, so PAIR loops and the
	// CONNECT shovel both exit cleanly without process-wide signal magic.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	code := dispatchSubcommand(ctx, rf)
	os.Exit(code)
}

func pick(override, baked string) string {
	if override != "" {
		return override
	}
	return baked
}
