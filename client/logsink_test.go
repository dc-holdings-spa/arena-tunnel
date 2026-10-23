package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingSinkRotatesBySizeAndKeepsBound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arena-tunnel-task.log")
	sink, err := newRotatingSink(path, 64, 3)
	if err != nil {
		t.Fatal(err)
	}

	// Write enough lines to force several rotations with keep=3.
	for i := 0; i < 40; i++ {
		if _, err := sink.Write([]byte(strings.Repeat("a", 16) + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	_ = sink.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}

	// Live file plus at most `keep` rotated ones.
	allowed := map[string]bool{
		"arena-tunnel-task.log":   true,
		"arena-tunnel-task.log.1": true,
		"arena-tunnel-task.log.2": true,
		"arena-tunnel-task.log.3": true,
	}
	for _, n := range names {
		if !allowed[n] {
			t.Fatalf("unexpected rotated file %q (keep=3 must bound the set)", n)
		}
	}

	// No individual file may exceed the rotation threshold by much (one
	// line can straddle the check, so allow one line of slack).
	for _, n := range names {
		st, err := os.Stat(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() > 64+18 {
			t.Fatalf("%s grew to %d bytes past the cap", n, st.Size())
		}
	}

	// The live file must still be appendable after rotation.
	sink2, err := newRotatingSink(path, 64, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink2.Write([]byte("tail-line\n")); err != nil {
		t.Fatal(err)
	}
	_ = sink2.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), "tail-line\n") {
		t.Fatalf("reopened sink must append, got %q", data)
	}
}

func TestDurableLogPathIsPerUser(t *testing.T) {
	p, err := durableLogPath()
	if err != nil {
		t.Skipf("no per-user state dir on this host: %v", err)
	}
	if !strings.HasSuffix(p, "arena-tunnel-task.log") {
		t.Fatalf("unexpected log name %q", p)
	}
	if strings.Contains(p, "ProgramData") || strings.HasPrefix(p, "/var/log") {
		t.Fatalf("log must live in per-user state, got %q", p)
	}
}
