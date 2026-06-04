// arena-byoc — single-binary BYOC2 client.
// - Creates a userspace WireGuard device on a TUN interface
// - Wraps WG UDP traffic over WSS to wg-byoc.adversario.cl/tunnel
// - All credentials baked in at compile time via -ldflags -X
//
// Run as root (Linux/macOS) or Administrator (Windows). TUN needs CAP_NET_ADMIN.
//
// Compile (per-student):
//   go build -ldflags "
//     -X main.privKeyB64=<peer-priv-b64>
//     -X main.serverPubKeyB64=<server-pub-b64>
//     -X main.tunnelIP=10.201.0.5
//     -X main.serverHost=wg-byoc.adversario.cl
//   " -o arena-byoc

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Baked at compile-time via -ldflags -X
var (
	privKeyB64      = "" // peer (student) WG private key
	serverPubKeyB64 = "" // arena WG server public key
	tunnelIP        = "" // e.g. "10.201.0.5"
	serverHost      = "wg-byoc.adversario.cl"
	tunnelName      = "arena-byoc"
)

// CLI overrides (useful for testing without re-compile)
var (
	flagPriv = flag.String("priv", "", "override baked priv key (b64)")
	flagPub  = flag.String("pub", "", "override baked server pub key (b64)")
	flagIP   = flag.String("ip", "", "override baked tunnel IP")
	flagHost = flag.String("host", "", "override baked server host")
	verbose  = flag.Bool("v", false, "verbose WG logs")
)

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

// runOneTunnel runs the bidirectional shovel until either side dies, then returns.
func runOneTunnel(ctx context.Context, udpConn *net.UDPConn, ws *websocket.Conn) {
	defer ws.Close()
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

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
				log.Printf("[wss] write: %v", err)
				return
			}
		}
	}()

	// WSS -> UDP
	go func() {
		defer cancel()
		for {
			ws.SetReadDeadline(time.Now().Add(2 * time.Minute))
			typ, data, err := ws.ReadMessage()
			if err != nil {
				log.Printf("[wss] read: %v", err)
				return
			}
			if typ != websocket.BinaryMessage {
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

func configureTUN(ipStr string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("interface config only implemented for linux (PR welcome)")
	}
	// Set address
	if err := exec.Command("ip", "addr", "add", ipStr+"/24", "dev", tunnelName).Run(); err != nil {
		return fmt.Errorf("ip addr add: %w", err)
	}
	// Bring up
	if err := exec.Command("ip", "link", "set", tunnelName, "up").Run(); err != nil {
		return fmt.Errorf("ip link set up: %w", err)
	}
	return nil
}

func teardownTUN() {
	if runtime.GOOS == "linux" {
		exec.Command("ip", "link", "set", tunnelName, "down").Run()
		exec.Command("ip", "addr", "flush", "dev", tunnelName).Run()
	}
}

func main() {
	flag.Parse()

	priv := pick(*flagPriv, privKeyB64)
	srv := pick(*flagPub, serverPubKeyB64)
	ip := pick(*flagIP, tunnelIP)
	host := pick(*flagHost, serverHost)

	if priv == "" || srv == "" || ip == "" {
		log.Fatalf("missing creds: priv=%q srv=%q ip=%q (compile with -ldflags or pass -priv/-pub/-ip)", priv, srv, ip)
	}

	privHex, err := b64ToHex(priv)
	if err != nil {
		log.Fatalf("priv key: %v", err)
	}
	srvHex, err := b64ToHex(srv)
	if err != nil {
		log.Fatalf("srv pub: %v", err)
	}

	// Open TUN
	log.Printf("[tun] creating device %q", tunnelName)
	tdev, err := tun.CreateTUN(tunnelName, 1380)
	if err != nil {
		log.Fatalf("tun create: %v", err)
	}

	// WireGuard logger
	level := device.LogLevelError
	if *verbose {
		level = device.LogLevelVerbose
	}
	logger := device.NewLogger(level, "[wg] ")

	// WG device with default UDP bind (we let WG pick a local port)
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	// Local UDP listener that WG will dial as its peer endpoint.
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("udp listen: %v", err)
	}
	localPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	// IPC config
	ipcConfig := fmt.Sprintf(
		"private_key=%s\n"+
			"listen_port=0\n"+
			"public_key=%s\n"+
			"endpoint=127.0.0.1:%d\n"+
			"allowed_ip=0.0.0.0/0\n"+
			"persistent_keepalive_interval=25\n",
		privHex, srvHex, localPort)
	if err := dev.IpcSet(ipcConfig); err != nil {
		log.Fatalf("ipc set: %v", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatalf("device up: %v", err)
	}

	// Configure TUN address + bring up at the OS level
	if err := configureTUN(ip); err != nil {
		log.Fatalf("tun config: %v", err)
	}
	defer teardownTUN()

	log.Printf("[+] WG up: tunnelIP=%s server=%s local-udp-port=%d", ip, host, localPort)

	// Start WSS shovel
	ctx, cancel := context.WithCancel(context.Background())
	wsURL := (&url.URL{Scheme: "wss", Host: host, Path: "/tunnel"}).String()
	go runShovel(ctx, udpConn, wsURL)

	// Wait for SIGINT
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("[!] shutdown requested")
	cancel()
	dev.Close()
	tdev.Close()
	udpConn.Close()
	time.Sleep(300 * time.Millisecond)
	log.Println("[!] bye")
}

func pick(override, baked string) string {
	if override != "" {
		return override
	}
	return baked
}
