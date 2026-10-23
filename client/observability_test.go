package main

import (
	"errors"
	"fmt"
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

func TestMetricsDataPlaneStates(t *testing.T) {
	m := &tunnelMetrics{}
	now := time.Now()

	if got := m.dataPlaneState(now, dataPlaneDegradedAfter); got != stateControlConnected {
		t.Fatalf("fresh session = %q, want %q", got, stateControlConnected)
	}

	// First local WG packet: handshake state, not degraded before the bound.
	m.markUp(120)
	if got := m.dataPlaneState(now.Add(30*time.Second), dataPlaneDegradedAfter); got != stateWgHandshake {
		t.Fatalf("up-only within bound = %q, want %q", got, stateWgHandshake)
	}
	// Past the bound with no return traffic: degraded.
	if got := m.dataPlaneState(now.Add(2*time.Minute), dataPlaneDegradedAfter); got != stateDataPlaneDegraded {
		t.Fatalf("up-only past bound = %q, want %q", got, stateDataPlaneDegraded)
	}

	// Return traffic arrives: ready, and it stays ready even if quiet later
	// (first-packet timestamps are what count).
	m.markDown(200)
	if got := m.dataPlaneState(now.Add(10*time.Minute), dataPlaneDegradedAfter); got != stateDataPlaneReady {
		t.Fatalf("bidirectional session = %q, want %q", got, stateDataPlaneReady)
	}
}

func TestMetricsSnapshotSanitized(t *testing.T) {
	m := &tunnelMetrics{}
	m.markUp(100)
	m.markUp(50)
	m.markDown(75)
	line := m.snapshot("abcd1234", time.Now(), dataPlaneDegradedAfter)
	for _, want := range []string{
		"session=abcd1234",
		"up_frames=2 up_bytes=150",
		"down_frames=1 down_bytes=75",
		"state=DATA PLANE READY",
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

func TestSanitizeReasonBoundsAndFlattens(t *testing.T) {
	long := errors.New(strings.Repeat("x", 500))
	got := sanitizeReason(long)
	if len(got) != 160 {
		t.Fatalf("truncated reason length = %d, want 160", len(got))
	}
	if sanitizeReason(errors.New("a\nb")) != "a b" {
		t.Fatal("newline must be flattened")
	}
	if sanitizeReason(nil) != "nil" {
		t.Fatal("nil error must render as nil")
	}
	if len(fmt.Sprint(sanitizeReason(errors.New("ok")))) < 2 {
		t.Fatal("short reasons pass through")
	}
}
