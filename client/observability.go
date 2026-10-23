// Sanitized per-session observability for the tunnel shovel (#2607 D0).
//
// Everything logged from these helpers is safe to persist on student
// machines: random non-secret session ids, counters, timestamps and
// state names. Never payloads, keys, tokens or addresses beyond the
// sanitized local/remote port metadata already emitted by the shovel.
//
// The states below are OBSERVED facts, not WireGround truth: the client
// cannot see inside the wireguard-go device, so "handshake" claims are
// deliberately avoided (audit point 2). What we can prove from this side:
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// tunnelMetrics counts one shovel session, both directions.
// up   = client → server (UDP→WSS: local WG traffic toward the terminador)
// down = server → client (WSS→UDP: return traffic re-injected locally)
type tunnelMetrics struct {
	framesUp   atomic.Int64
	bytesUp    atomic.Int64
	framesDown atomic.Int64
	bytesDown  atomic.Int64

	// firstUpMs/firstDownMs: unix-ms of the first packet seen in each
	// direction; 0 = not seen yet. These derive the observed states.
	firstUpMs   atomic.Int64
	firstDownMs atomic.Int64
}

// Observed data-plane states (audit: honest vocabulary, no WireGuard
// internals claimed from outside the device).
const (
	stateControlConnected  = "CONTROL CONNECTED"
	stateLocalWgPacketSeen = "LOCAL_WG_PACKET_SEEN"
	stateNoReturnTraffic   = "NO_RETURN_TRAFFIC"
	stateBidirectionalSeen = "BIDIRECTIONAL_OBSERVED"

	// dataPlaneDegradedAfter bounds how long a session may sit with
	// outbound-only traffic before the observed state flips to
	// NO_RETURN_TRAFFIC. Matches the ≤90 s readiness criterion from #2607.
	dataPlaneDegradedAfter = 90 * time.Second

	// degradedPollInterval is how often the transition watcher re-checks
	// the state. Must stay well under dataPlaneDegradedAfter so the
	// NO_RETURN_TRAFFIC transition is logged within ~bound+poll, not at
	// the next stats tick (audit point 7).
	degradedPollInterval = 5 * time.Second
)

// markUp records one outbound datagram. Returns true when this was the
// first outbound packet of the session.
func (m *tunnelMetrics) markUp(n int) bool {
	now := time.Now().UnixMilli()
	m.framesUp.Add(1)
	m.bytesUp.Add(int64(n))
	return m.firstUpMs.CompareAndSwap(0, now)
}

// markDown records one inbound frame. Single mutation point for the
// counter AND the first-frame timestamp (audit point 1: exactly one
// mutation per frame). Returns true when this was the first inbound
// frame of the session.
func (m *tunnelMetrics) markDown(n int) bool {
	now := time.Now().UnixMilli()
	m.framesDown.Add(1)
	m.bytesDown.Add(int64(n))
	return m.firstDownMs.CompareAndSwap(0, now)
}

// dataPlaneState derives the current observed state from first-packet
// timestamps. now is injected so tests can fast-forward.
func (m *tunnelMetrics) dataPlaneState(now time.Time) string {
	upMs := m.firstUpMs.Load()
	downMs := m.firstDownMs.Load()
	switch {
	case upMs == 0:
		// No local WG traffic yet: control channel may be up, WG not started.
		return stateControlConnected
	case downMs == 0:
		if now.UnixMilli()-upMs > dataPlaneDegradedAfter.Milliseconds() {
			return stateNoReturnTraffic
		}
		return stateLocalWgPacketSeen
	default:
		return stateBidirectionalSeen
	}
}

// snapshot renders one sanitized stats line body (no timestamps inside;
// the log package prefixes its own).
func (m *tunnelMetrics) snapshot(sessionID string, now time.Time) string {
	upMs, downMs := m.firstUpMs.Load(), m.firstDownMs.Load()
	var upSince, downSince string
	if upMs > 0 {
		upSince = time.Since(time.UnixMilli(upMs)).Round(time.Second).String()
	}
	if downMs > 0 {
		downSince = time.Since(time.UnixMilli(downMs)).Round(time.Second).String()
	}
	return fmt.Sprintf(
		"session=%s up_frames=%d up_bytes=%d up_first=%s down_frames=%d down_bytes=%d down_first=%s state=%s",
		sessionID,
		m.framesUp.Load(), m.bytesUp.Load(), orNever(upSince),
		m.framesDown.Load(), m.bytesDown.Load(), orNever(downSince),
		m.dataPlaneState(now),
	)
}

func orNever(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

// newSessionID returns a random, non-secret 8-hex id used to correlate
// log lines of one WSS session. The SAME id is sent to the terminador in
// the X-Arena-Session header so both ends log one shared correlation id
// (audit point 3).
func newSessionID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand failing is effectively impossible on supported platforms;
		// fall back to a time-derived id rather than crashing the tunnel.
		return fmt.Sprintf("t%x", time.Now().UnixNano()&0xffffffff)
	}
	return hex.EncodeToString(b[:])
}

// reasonBox captures why a shovel session ended, for the reconnect log.
type reasonBox struct {
	mu  sync.Mutex
	set bool
	s   string
}

func (r *reasonBox) setf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.set {
		r.s = fmt.Sprintf(format, args...)
		r.set = true
	}
}

func (r *reasonBox) get() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.set {
		return "unknown"
	}
	return r.s
}

// sanitizeReason neutralizes every control character (CR, tabs, escapes —
// anything below 0x20 plus DEL) so a hostile or garbled error string can
// never inject log lines, then bounds the length (audit point 8).
func sanitizeReason(err error) string {
	if err == nil {
		return "nil"
	}
	var b strings.Builder
	for _, r := range err.Error() {
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 160 {
			break
		}
	}
	return b.String()
}
