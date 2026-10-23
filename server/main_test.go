package main

import (
	"strings"
	"sync"
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

func TestStatsLineCarriesBothDirections(t *testing.T) {
	tun := newTunnel(nil, nil, "203.0.113.9", "")
	tun.bytesWGIn.Add(1500)
	tun.framesWGIn.Add(2)
	tun.bytesWGOut.Add(900)
	tun.framesWGOut.Add(1)

	line := tun.statsLine("[stats]")
	for _, want := range []string{
		"session=" + tun.sessionID,
		"client=203.0.113.9",
		"ws→udp frames=2 bytes=1500",
		"udp→ws frames=1 bytes=900",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("stats line %q missing %q", line, want)
		}
	}
}

// The counters must be race-free under concurrent producers: run with
// `go test -race` (CI does).
func TestCountersConcurrent(t *testing.T) {
	tun := newTunnel(nil, nil, "c", "")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				tun.bytesWGIn.Add(10)
				tun.framesWGIn.Add(1)
				tun.bytesWGOut.Add(20)
				tun.framesWGOut.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := tun.framesWGIn.Load(); got != 8000 {
		t.Fatalf("framesWGIn = %d, want 8000", got)
	}
	if got := tun.bytesWGIn.Load(); got != 80000 {
		t.Fatalf("bytesWGIn = %d, want 80000", got)
	}
}

func TestOpenedAtSet(t *testing.T) {
	tun := newTunnel(nil, nil, "c", "")
	if time.Since(tun.openedAt) > time.Second {
		t.Fatal("openedAt must be initialized to now")
	}
}
