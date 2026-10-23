// byoc2-tunnel-server — replaces wstunnel on arena-manager.
// Listens HTTP/8888, upgrades to WSS on /tunnel, forwards binary frames as
// UDP packets to the local WireGuard server (127.0.0.1:51820 by default).
//
// Protocol: each binary WebSocket frame = one UDP datagram. No framing on top.
// Cloudflared terminates TLS upstream; this server is plain HTTP on loopback.
//
// Connection lifecycle (enterprise-grade separation):
//
//   WebSocket lifetime  ← governed by server-initiated ping/pong only.
//                         UDP idle never kills the WS connection; operators
//                         can connect their TS hours before a beacon checks in.
//
//   UDP session         ← ephemeral per-WS-connection UDP socket to WireGuard.
//                         Idle is logged but the socket is kept open until
//                         the WS closes (avoiding a re-dial on first beacon).
//
//   Hard cap            ← -max-age (default 24 h) forcibly closes stale
//                         connections regardless of ping health, bounding
//                         leaked goroutines and ephemeral UDP sockets.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// newSessionID returns a random, non-secret 8-hex id used to correlate
// every log line of one WSS session (#2607 D0).
func newSessionID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%x", time.Now().UnixNano()&0xffffffff)
	}
	return hex.EncodeToString(b[:])
}

var (
	listenAddr    = flag.String("listen", "127.0.0.1:8888", "HTTP listen address")
	wgTarget      = flag.String("wg", "127.0.0.1:51820", "WireGuard server UDP target")
	pingInterval  = flag.Duration("ping-interval", 30*time.Second, "server→client WebSocket ping interval")
	pongTimeout   = flag.Duration("pong-timeout", 90*time.Second, "WebSocket close if pong not received within N")
	udpIdleLog    = flag.Duration("udp-idle-log", 5*time.Minute, "log a warning after N idle (no WG traffic); tunnel stays up")
	maxAge        = flag.Duration("max-age", 24*time.Hour, "hard cap on tunnel lifetime regardless of health")
	managerURL    = flag.String("manager-url", "", "arena-manager peer-event URL (optional, e.g. http://localhost:3000/api/internal/byoc2/peer-event)")
	statsInterval = flag.Duration("stats-interval", 60*time.Second, "sanitized per-session stats line interval")
)

// activeConns tracks open tunnel count for /healthz.
var activeConns atomic.Int64

var peerEventClient = &http.Client{Timeout: 5 * time.Second}

// notifyManager fires a peer-event callback to arena-manager. Fire-and-forget:
// a failed callback is logged but never blocks or kills the tunnel.
func notifyManager(event, arenaToken string) {
	if *managerURL == "" || arenaToken == "" {
		return
	}
	body, err := json.Marshal(map[string]string{"token": arenaToken, "event": event})
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, *managerURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("[peer-event] build request failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := peerEventClient.Do(req)
	if err != nil {
		log.Printf("[peer-event] %s callback failed: %v", event, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[peer-event] %s callback returned %d", event, resp.StatusCode)
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true }, // CF locks down access upstream
}

type tunnel struct {
	ws         *websocket.Conn
	udp        *net.UDPConn
	clientIP   string
	arenaToken string // from X-Arena-Token header; empty when not supplied
	sessionID  string // random non-secret id for log correlation (#2607 D0)
	openedAt   time.Time
	once       sync.Once
	done       chan struct{}

	// stats — updated atomically, read by /healthz handler and the
	// periodic stats line. frames* counted per direction so a session
	// with bytes but no frames (or the reverse) is visible in logs.
	bytesWGIn   atomic.Int64 // client→WG (WS→UDP direction)
	bytesWGOut  atomic.Int64 // WG→client (UDP→WS direction)
	framesWGIn  atomic.Int64
	framesWGOut atomic.Int64
}

func newTunnel(ws *websocket.Conn, udp *net.UDPConn, clientIP, arenaToken string) *tunnel {
	return &tunnel{
		ws:         ws,
		udp:        udp,
		clientIP:   clientIP,
		arenaToken: arenaToken,
		sessionID:  newSessionID(),
		openedAt:   time.Now(),
		done:       make(chan struct{}),
	}
}

// statsLine renders one sanitized periodic/closing stats record.
func (t *tunnel) statsLine(prefix string) string {
	return fmt.Sprintf("%s session=%s client=%s age=%s ws→udp frames=%d bytes=%d udp→ws frames=%d bytes=%d",
		prefix, t.sessionID, t.clientIP,
		time.Since(t.openedAt).Round(time.Second),
		t.framesWGIn.Load(), t.bytesWGIn.Load(),
		t.framesWGOut.Load(), t.bytesWGOut.Load(),
	)
}

// statsLoop emits a sanitized stats line every statsInterval so a slow
// data-plane recovery is visible while it happens, not only at close.
func (t *tunnel) statsLoop() {
	ticker := time.NewTicker(*statsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			log.Print(t.statsLine("[stats]"))
		case <-t.done:
			return
		}
	}
}

func (t *tunnel) close() {
	t.once.Do(func() {
		close(t.done)
		_ = t.udp.Close()
		_ = t.ws.Close()
		activeConns.Add(-1)
		log.Print(t.statsLine("[-] tunnel close"))
		go notifyManager("disconnected", t.arenaToken)
	})
}

// pingLoop sends server-initiated WebSocket pings on a fixed interval.
// This is the SOLE source of truth for WebSocket liveness — UDP traffic (or lack
// thereof) has zero influence on whether the connection stays up.
func (t *tunnel) pingLoop() {
	defer t.close()
	ticker := time.NewTicker(*pingInterval)
	maxTimer := time.NewTimer(*maxAge)
	defer ticker.Stop()
	defer maxTimer.Stop()
	for {
		select {
		case <-ticker.C:
			_ = t.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := t.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("[ping] write failed client=%s: %v", t.clientIP, err)
				return
			}
		case <-maxTimer.C:
			log.Printf("[max-age] hard cap reached client=%s age=%s", t.clientIP, *maxAge)
			return
		case <-t.done:
			return
		}
	}
}

// wsToUDP reads binary frames from the WebSocket and writes them as UDP datagrams
// to the WireGuard server. The read deadline is maintained exclusively via the
// pong handler — it is reset on every pong, not on every frame, so that a beacon
// that goes silent doesn't affect the connection.
func (t *tunnel) wsToUDP() {
	defer t.close()
	t.ws.SetReadLimit(4 * 1024 * 1024)

	// Reset the read deadline each time a pong arrives in response to our ping.
	// If pongs stop arriving (client gone / network split), the deadline expires
	// and we tear down cleanly.
	t.ws.SetPongHandler(func(string) error {
		return t.ws.SetReadDeadline(time.Now().Add(*pongTimeout))
	})
	// Seed the deadline: first ping won't fire for pingInterval seconds.
	// Give the client pingInterval + pongTimeout to send the first keepalive.
	if err := t.ws.SetReadDeadline(time.Now().Add(*pingInterval + *pongTimeout)); err != nil {
		return
	}

	for {
		typ, data, err := t.ws.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("[ws→udp] read error client=%s: %v", t.clientIP, err)
			}
			return
		}
		if typ != websocket.BinaryMessage {
			// ping/pong/text — pong handler already reset deadline; skip.
			continue
		}
		if _, err := t.udp.Write(data); err != nil {
			log.Printf("[ws→udp] udp write session=%s client=%s: %v", t.sessionID, t.clientIP, err)
			return
		}
		t.bytesWGIn.Add(int64(len(data)))
		t.framesWGIn.Add(1)
	}
}

// udpToWS reads UDP datagrams from WireGuard and writes them as binary WebSocket
// frames. UDP idle (no WG traffic) is logged but does NOT close the tunnel —
// the WebSocket stays up so an operator can leave the binary running for hours
// before a beacon appears.
func (t *tunnel) udpToWS() {
	defer t.close()
	buf := make([]byte, 65535)
	lastActivity := time.Now()
	idleLogged := false

	for {
		select {
		case <-t.done:
			return
		default:
		}

		// Short UDP read deadline so we can check t.done frequently and emit
		// the idle-log at the right time without blocking indefinitely.
		_ = t.udp.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := t.udp.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Check for idle-log threshold without closing the tunnel.
				if !idleLogged && time.Since(lastActivity) >= *udpIdleLog {
					log.Printf("[udp→ws] idle for %s (no WG traffic) client=%s — tunnel stays up",
						*udpIdleLog, t.clientIP)
					idleLogged = true
				}
				continue
			}
			// Real UDP error (socket closed by our own close() call or OS error).
			select {
			case <-t.done:
				// Expected: tunnel was closed by pingLoop/wsToUDP.
			default:
				log.Printf("[udp→ws] udp read error client=%s: %v", t.clientIP, err)
			}
			return
		}

		lastActivity = time.Now()
		idleLogged = false

		_ = t.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := t.ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
			log.Printf("[udp→ws] ws write session=%s client=%s: %v", t.sessionID, t.clientIP, err)
			return
		}
		t.bytesWGOut.Add(int64(n))
		t.framesWGOut.Add(1)
	}
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade failed: %v", err)
		return
	}

	wgAddr, err := net.ResolveUDPAddr("udp", *wgTarget)
	if err != nil {
		log.Printf("resolve wg target: %v", err)
		_ = ws.Close()
		return
	}
	udp, err := net.DialUDP("udp", nil, wgAddr)
	if err != nil {
		log.Printf("dial wg: %v", err)
		_ = ws.Close()
		return
	}

	clientIP := r.Header.Get("CF-Connecting-IP")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	arenaToken := r.Header.Get("X-Arena-Token")

	t := newTunnel(ws, udp, clientIP, arenaToken)
	activeConns.Add(1)
	// The UDP local port is what WireGuard learns as this session's peer
	// endpoint — log it so a stale-endpoint association is diagnosable.
	log.Printf("[+] tunnel open session=%s client=%s wg=%s udp_local=%s token=%v",
		t.sessionID, clientIP, wgAddr, udp.LocalAddr(), arenaToken != "")
	go notifyManager("connected", arenaToken)

	go t.pingLoop()
	go t.wsToUDP()
	go t.udpToWS()
	go t.statsLoop()

	// Block until all goroutines have signalled done.
	<-t.done
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ok active=%d\n", activeConns.Load())
}

func main() {
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", handleTunnel)
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", 404)
	})
	log.Printf("byoc2-tunnel-server listening on %s, wg=%s ping=%s pong-timeout=%s udp-idle-log=%s max-age=%s",
		*listenAddr, *wgTarget, *pingInterval, *pongTimeout, *udpIdleLog, *maxAge)
	if err := http.ListenAndServe(*listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}
