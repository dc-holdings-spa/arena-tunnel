// byoc2-tunnel-server — replaces wstunnel on arena-manager.
// Listens HTTP/8888, upgrades to WSS on /tunnel, forwards binary frames as
// UDP packets to the local WireGuard server (127.0.0.1:51820 by default).
//
// Protocol: each binary WebSocket frame = one UDP datagram. No framing on top.
// Cloudflared terminates TLS upstream; this server is plain HTTP on loopback.

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	listenAddr = flag.String("listen", "127.0.0.1:8888", "HTTP listen address")
	wgTarget   = flag.String("wg", "127.0.0.1:51820", "WireGuard server UDP target")
	idleTO     = flag.Duration("idle-timeout", 5*time.Minute, "drop UDP conn after N idle")
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true }, // CF will lock down access
}

// activeConns: per-tunnel UDP socket. Each WSS connection gets its own ephemeral
// UDP socket so WG sees distinct source addresses (won't muddle peers).
type tunnel struct {
	ws   *websocket.Conn
	udp  *net.UDPConn
	once sync.Once
	done chan struct{}
}

func (t *tunnel) close() {
	t.once.Do(func() {
		close(t.done)
		t.udp.Close()
		t.ws.Close()
	})
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("upgrade failed: %v", err)
		return
	}

	wgAddr, err := net.ResolveUDPAddr("udp", *wgTarget)
	if err != nil {
		log.Printf("resolve wg target: %v", err)
		ws.Close()
		return
	}

	udp, err := net.DialUDP("udp", nil, wgAddr)
	if err != nil {
		log.Printf("dial wg: %v", err)
		ws.Close()
		return
	}

	t := &tunnel{ws: ws, udp: udp, done: make(chan struct{})}
	defer t.close()

	clientIP := r.Header.Get("CF-Connecting-IP")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	log.Printf("[+] tunnel open client=%s wg=%s", clientIP, wgAddr)

	go t.wsToUDP()
	t.udpToWS()

	log.Printf("[-] tunnel close client=%s", clientIP)
}

// wsToUDP: read binary frames from WS, write as UDP datagrams to WG.
func (t *tunnel) wsToUDP() {
	defer t.close()
	t.ws.SetReadLimit(4 * 1024 * 1024) // big enough for jumbo frames if any
	for {
		t.ws.SetReadDeadline(time.Now().Add(2 * (*idleTO)))
		typ, data, err := t.ws.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				if err != io.EOF {
					log.Printf("ws read: %v", err)
				}
			}
			return
		}
		if typ != websocket.BinaryMessage {
			continue
		}
		if _, err := t.udp.Write(data); err != nil {
			log.Printf("udp write: %v", err)
			return
		}
	}
}

// udpToWS: read UDP datagrams from WG, write as binary frames to WS.
func (t *tunnel) udpToWS() {
	defer t.close()
	buf := make([]byte, 65535)
	for {
		t.udp.SetReadDeadline(time.Now().Add(*idleTO))
		n, err := t.udp.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				log.Printf("udp idle timeout, closing tunnel")
			} else {
				log.Printf("udp read: %v", err)
			}
			return
		}
		t.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := t.ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
			log.Printf("ws write: %v", err)
			return
		}
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "ok")
}

func main() {
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", handleTunnel)
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", 404)
	})
	log.Printf("byoc2-tunnel-server listening on %s, forwarding to wg=%s", *listenAddr, *wgTarget)
	if err := http.ListenAndServe(*listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}
