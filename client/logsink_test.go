package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRotatingSinkRotatesBySizeAndKeepsBound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arena-tunnel-task.log")
	sink, err := newRotatingSink(path, 64, 3)
	if err != nil {
		t.Fatal(err)
	}

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
	allowed := map[string]bool{
		"arena-tunnel-task.log":   true,
		"arena-tunnel-task.log.1": true,
		"arena-tunnel-task.log.2": true,
		"arena-tunnel-task.log.3": true,
	}
	for _, e := range entries {
		if !allowed[e.Name()] {
			t.Fatalf("unexpected rotated file %q (keep=3 must bound the set)", e.Name())
		}
		st, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() > 64+18 {
			t.Fatalf("%s grew to %d bytes past the cap", e.Name(), st.Size())
		}
	}

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

// Audit point 5: Windows rename fails when the destination exists. The
// rotation must still succeed because every destination is removed first;
// if rotation truly cannot proceed, the sink must truncate instead of
// growing without bound.
func TestRotatingSinkSurvivesWindowsRenameSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arena-tunnel-task.log")

	renamed := 0
	oldRename := osRename
	osRename = func(src, dst string) error {
		renamed++
		if _, err := os.Stat(dst); err == nil {
			return fmt.Errorf("windows: cannot create %s already exists", dst)
		}
		return os.Rename(src, dst)
	}
	defer func() { osRename = oldRename }()

	sink, err := newRotatingSink(path, 64, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		if _, err := sink.Write([]byte(strings.Repeat("b", 16) + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	_ = sink.Close()

	if renamed == 0 {
		t.Fatal("test never exercised a rotation")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > 64+18 {
		t.Fatalf("live log grew to %d bytes — unbounded growth under Windows semantics", st.Size())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) > 4 {
		t.Fatalf("keep bound violated: %d files", len(entries))
	}
}

func TestRotatingSinkTruncatesWhenRotationIsImpossible(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arena-tunnel-task.log")

	oldRename := osRename
	osRename = func(src, dst string) error { return fmt.Errorf("locked") }
	defer func() { osRename = oldRename }()

	sink, err := newRotatingSink(path, 64, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		if _, err := sink.Write([]byte(strings.Repeat("c", 16) + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	_ = sink.Close()

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > 64+18 {
		t.Fatalf("rotation permanently failing must truncate, not grow: %d bytes", st.Size())
	}
}

// Audit (second round): the production logger is a MultiWriter that
// contains the sink — a log.Printf from inside Write's lock deadlocks.
// Reproduce the EXACT production wiring, force rename failure, and prove
// the write path terminates.
func TestRotatingSinkNoDeadlockUnderProductionLogger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arena-tunnel-task.log")

	oldRename := osRename
	osRename = func(src, dst string) error { return fmt.Errorf("locked") }
	defer func() { osRename = oldRename }()

	sink, err := newRotatingSink(path, 64, 3)
	if err != nil {
		t.Fatal(err)
	}
	restore := log.Writer()
	log.SetOutput(io.MultiWriter(io.Discard, sink))
	defer func() { log.SetOutput(restore) }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 80; i++ {
			// This is the recursive path: logger → sink.Write → rotation
			// failure → (previously log.Printf → logger → sink.Write…).
			log.Printf("line %d", i)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("sink.Write deadlocked under the production MultiWriter logger")
	}
	_ = sink.Close()
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
