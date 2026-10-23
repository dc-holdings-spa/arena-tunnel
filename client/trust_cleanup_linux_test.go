//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupPlatformArenaTrustIsExactAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	owned := filepath.Join(dir, "arena-adaptix-teamserver.crt")
	foreign := filepath.Join(dir, "foreign.crt")
	if err := os.WriteFile(owned, []byte("owned"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}

	originalPath, originalRun := arenaTrustPath, runTrustCommand
	t.Cleanup(func() { arenaTrustPath, runTrustCommand = originalPath, originalRun })
	arenaTrustPath = owned
	calls := 0
	runTrustCommand = func(name string, args ...string) error {
		calls++
		if name != "update-ca-certificates" {
			t.Fatalf("unexpected command %q", name)
		}
		return nil
	}

	if err := cleanupPlatformArenaTrust(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatalf("owned trust still exists: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign trust was touched: %v", err)
	}
	if calls != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls)
	}

	if err := cleanupPlatformArenaTrust(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("idempotent cleanup refreshed trust: calls=%d", calls)
	}
}

func TestCleanupArenaTrustOnlyAfterConfirmedRevocation(t *testing.T) {
	original := platformArenaTrustCleanup
	t.Cleanup(func() { platformArenaTrustCleanup = original })
	calls := 0
	platformArenaTrustCleanup = func() error { calls++; return nil }

	cleanupArenaTrustIfRevoked(false) // transient status/network failure
	if calls != 0 {
		t.Fatalf("transient state triggered cleanup: calls=%d", calls)
	}

	cleanupArenaTrustIfRevoked(true)
	if calls != 1 {
		t.Fatalf("confirmed revocation cleanup calls=%d, want 1", calls)
	}
}
