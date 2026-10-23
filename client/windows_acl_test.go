//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// effectiveSDDL asks the OS itself for the SDDL of path via PowerShell —
// independent of the x/sys version we build against, so the assertion
// exercises the real on-disk ACL.
func effectiveSDDL(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-Acl -LiteralPath '"+path+"').Sddl").Output()
	if err != nil {
		t.Fatalf("Get-Acl(%s): %v", path, err)
	}
	return strings.TrimSpace(string(out))
}

// Audit (second round): prove the owner-only DACL on real Windows — the
// effective SDDL of the created log dir and file must not grant broad
// groups (everyone / authenticated / built-in users), and the DACL must
// be protected (no inherited ACEs re-adding access).
func TestRotatingSinkAppliesOwnerOnlyDACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arena-tunnel-task.log")

	sink, err := newRotatingSink(path, 4096, 3)
	if err != nil {
		t.Fatalf("sink with owner ACL failed: %v", err)
	}
	defer sink.Close()

	for _, target := range []string{dir, path} {
		sddl := effectiveSDDL(t, target)
		if !strings.Contains(sddl, "D:P") { // protected DACL flag, not an unrelated P elsewhere
			t.Fatalf("%s DACL not protected (inherited ACEs may re-add access): %s", target, sddl)
		}
		for _, forbidden := range []string{"WD", "AU", "BU"} { // everyone, authenticated, built-in users
			// An allow ACE is shaped `(A;flags;rights;object;inherit;trustee)`;
			// matching `(A;;<trustee>` misses normal rights such as FA and
			// would let `(A;;FA;;;WD)` pass. Trustee is the final field.
			if strings.Contains(sddl, ";;;"+forbidden+")") {
				t.Fatalf("%s DACL grants group %s: %s", target, forbidden, sddl)
			}
		}
	}
}

// Audit (second round): rotation must work against the REAL Windows
// rename semantics (no injection here): archives shift, growth stays
// bounded, the sink stays usable.
func TestRotatingSinkRotatesOnRealWindowsRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arena-tunnel-task.log")

	sink, err := newRotatingSink(path, 64, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		if _, err := sink.Write([]byte(strings.Repeat("w", 16) + "\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	_ = sink.Close()

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > 64+18 {
		t.Fatalf("live log unbounded: %d bytes", st.Size())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) > 4 {
		t.Fatalf("keep bound violated: %d files", len(entries))
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotation never produced an archive: %v", err)
	}
}
