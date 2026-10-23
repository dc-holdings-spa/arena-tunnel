package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewSessionIDShapeAndUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		id := newSessionID()
		if len(id) != 8 || strings.Trim(id, "0123456789abcdef") != "" {
			t.Fatalf("session id %q is not 8 lowercase hex chars", id)
		}
		if seen[id] {
			t.Fatalf("duplicate session id %q", id)
		}
		seen[id] = true
	}
}

// Audit point 1: one frame counted exactly once, and the first-frame
// signal derives from that same mutation.
func TestMarkDownCountsExactlyOnceAndSignalsFirst(t *testing.T) {
	m := &tunnelMetrics{}
	if !m.markDown(10) {
		t.Fatal("first markDown must report first=true")
	}
	if m.markDown(10) || m.markDown(10) {
		t.Fatal("subsequent markDown must report first=false")
	}
	if m.framesDown.Load() != 3 || m.bytesDown.Load() != 30 {
		t.Fatalf("counters = %d/%d, want 3/30", m.framesDown.Load(), m.bytesDown.Load())
	}
	if !m.markUp(5) || m.markUp(5) {
		t.Fatal("markUp first-frame contract broken")
	}
	if m.framesUp.Load() != 2 || m.bytesUp.Load() != 10 {
		t.Fatalf("up counters = %d/%d, want 2/10", m.framesUp.Load(), m.bytesUp.Load())
	}
}

// Audit point 2: honest observed states; point 7: the 90 s bound flips
// the state at the bound itself (polled every 5 s in production).
func TestDataPlaneObservedStates(t *testing.T) {
	m := &tunnelMetrics{}
	now := time.Now()

	if got := m.dataPlaneState(now); got != stateControlConnected {
		t.Fatalf("fresh session = %q, want %q", got, stateControlConnected)
	}

	m.markUp(120)
	if got := m.dataPlaneState(now.Add(89 * time.Second)); got != stateLocalWgPacketSeen {
		t.Fatalf("up-only at 89s = %q, want %q", got, stateLocalWgPacketSeen)
	}
	if got := m.dataPlaneState(now.Add(90*time.Second + 1*time.Millisecond)); got != stateNoReturnTraffic {
		t.Fatalf("up-only past bound = %q, want %q", got, stateNoReturnTraffic)
	}

	m.markDown(200)
	if got := m.dataPlaneState(now.Add(10 * time.Minute)); got != stateBidirectionalSeen {
		t.Fatalf("bidirectional session = %q, want %q", got, stateBidirectionalSeen)
	}
}

// Audit point 7: the poll cadence must keep detection within ~bound+poll,
// not bound+statsTick.
func TestDegradedPollCadenceBoundsDetection(t *testing.T) {
	if degradedPollInterval > dataPlaneDegradedAfter/6 {
		t.Fatalf("poll %s too coarse for a %s bound", degradedPollInterval, dataPlaneDegradedAfter)
	}
}

func TestMetricsSnapshotSanitized(t *testing.T) {
	m := &tunnelMetrics{}
	m.markUp(100)
	m.markUp(50)
	m.markDown(75)
	line := m.snapshot("abcd1234", time.Now())
	for _, want := range []string{
		"session=abcd1234",
		"up_frames=2 up_bytes=150",
		"down_frames=1 down_bytes=75",
		"state=BIDIRECTIONAL_OBSERVED",
		"down_first=",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("snapshot %q missing %q", line, want)
		}
	}
}

func TestReasonBoxFirstReasonWins(t *testing.T) {
	r := &reasonBox{}
	r.setf("wss read: %s", "boom")
	r.setf("later: %s", "ignored")
	if got := r.get(); got != "wss read: boom" {
		t.Fatalf("first reason must win, got %q", got)
	}
	empty := &reasonBox{}
	if got := empty.get(); got != "unknown" {
		t.Fatalf("empty reason = %q, want unknown", got)
	}
}

// Audit point 8: every control character must be neutralized — a forged
// error must not be able to forge log lines or smuggle escapes.
func TestSanitizeReasonNeutralizesAllControls(t *testing.T) {
	cases := map[string]string{
		"a\nb":      "a b",
		"a\rb":      "a b",
		"a\tb":      "a b",
		"a\x1b[2Jb": "a [2Jb",
		"a\x00b":    "a b",
		"a\x7fb":    "a b",
		"plain":     "plain",
	}
	for in, want := range cases {
		if got := sanitizeReason(errors.New(in)); got != want {
			t.Fatalf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
	if len(sanitizeReason(errors.New(strings.Repeat("x", 500)))) > 160 {
		t.Fatal("length bound must hold")
	}
	if sanitizeReason(nil) != "nil" {
		t.Fatal("nil error must render as nil")
	}
	// Unicode passes through untouched.
	if got := sanitizeReason(errors.New("cañón")); got != "cañón" {
		t.Fatalf("unicode mangled: %q", got)
	}
}
