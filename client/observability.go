// Sanitized per-session observability for the tunnel shovel (#2607 D0).
//
// Everything logged from these helpers is safe to persist on student
// machines: random non-secret session ids, counters, timestamps and
// state names. Never payloads, keys, tokens or addresses beyond the
// sanitized local/remote port metadata already emitted by the shovel.
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
	// direction; 0 = not seen yet. These define the data-plane states.
	firstUpMs   atomic.Int64
	firstDownMs atomic.Int64
}

// Data-plane states, in the vocabulary required by #2607. They are
// deliberately separate from control-plane (WSS) liveness.
const (
	stateControlConnected  = "CONTROL CONNECTED"
	stateWgHandshake       = "WG HANDSHAKE"
	stateDataPlaneReady    = "DATA PLANE READY"
	stateDataPlaneDegraded = "DATA PLANE DEGRADED"

	// dataPlaneDegradedAfter bounds how long a session may sit with
	// outbound-only traffic before the stats line reports DEGRADED.
	// Matches the ≤90 s readiness criterion from #2607.
	dataPlaneDegradedAfter = 90 * time.Second
)

func (m *tunnelMetrics) markUp(n int) {
	now := time.Now().UnixMilli()
	m.framesUp.Add(1)
	m.bytesUp.Add(int64(n))
	m.firstUpMs.CompareAndSwap(0, now)
}

func (m *tunnelMetrics) markDown(n int) {
	now := time.Now().UnixMilli()
	m.framesDown.Add(1)
	m.bytesDown.Add(int64(n))
	m.firstDownMs.CompareAndSwap(0, now)
}

// dataPlaneState derives the current state from first-packet timestamps.
// now is injected so tests can fast-forward; degradedAfter bounds how
// long a session may sit below bidirectional before we call it DEGRADED.
func (m *tunnelMetrics) dataPlaneState(now time.Time, degradedAfter time.Duration) string {
	upMs := m.firstUpMs.Load()
	downMs := m.firstDownMs.Load()
	switch {
	case upMs == 0:
		// No local WG traffic yet: control channel may be up, WG not started.
		return stateControlConnected
	case downMs == 0:
		if now.UnixMilli()-upMs > degradedAfter.Milliseconds() {
			return stateDataPlaneDegraded
		}
		return stateWgHandshake
	default:
		return stateDataPlaneReady
	}
}

// snapshot renders one sanitized stats line body (no timestamps inside;
// the log package prefixes its own).
func (m *tunnelMetrics) snapshot(sessionID string, now time.Time, degradedAfter time.Duration) string {
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
		m.dataPlaneState(now, degradedAfter),
	)
}

func orNever(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

// newSessionID returns a random, non-secret 8-hex id used to correlate
// log lines across a single WSS session lifetime.
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

// sanitizeReason keeps reconnect reasons free of remote frames: keep the
// error class (close/read/write + err.Error truncated), drop nothing else
// since gorilla errors already carry no payloads.
func sanitizeReason(err error) string {
	if err == nil {
		return "nil"
	}
	s := err.Error()
	if len(s) > 160 {
		s = s[:160]
	}
	return strings.ReplaceAll(s, "\n", " ")
}
