//go:build linux
// +build linux

package main

// Kill switch — Linux implementation.
//
// Threat model (post-2026-08-07 rework, Diego): what the kill switch
// actually needs to prevent is a scenario-bound packet leaking OUT
// non-tunnel interfaces if the tunnel drops. It does NOT need to
// blackhole the operator's general internet — that was the v1.4.0
// design and it made the client unusable as a background service
// (git push, browser, apt update all silently dropped as soon as
// systemd brought the tunnel up).
//
// New semantics: the ARENA_KILLSWITCH chain drops any packet whose
// destination lives in the scenario CIDR (10.128.0.0/9) and whose
// egress interface is NOT the arena-tunnel tun device. Everything
// else — public internet, LAN, DNS — passes untouched. Tunnel drops
// mean scenario traffic goes to /dev/null (correct: better a black
// hole than a leaked source IP), but the operator's real box stays
// online.
//
// Chain is spliced at the top of OUTPUT so it runs before any
// user-installed rules. Install-time FLUSH + REBUILD is idempotent.
//
// Requires CAP_NET_ADMIN — the arena-tunnel binary runs as root
// under systemd via install.sh's generated unit.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const killSwitchChain = "ARENA_KILLSWITCH"

// armedMarkerPath returns the path of a small marker file we drop while
// the kill switch is armed. If it survives a subsequent process crash
// we run teardown at startup so the student can reach the network again
// — otherwise they are permanently locked out with no way to redownload
// arena-tunnel or ask for help.
func armedMarkerPath() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "arena-tunnel", "killswitch.armed")
}

// recoverKillSwitchIfLeftArmed is called at the top of every arena-tunnel
// startup. Safe to call unconditionally; no-op when nothing is armed.
func recoverKillSwitchIfLeftArmed() {
	if _, err := os.Stat(armedMarkerPath()); err == nil {
		_ = teardownKillSwitch()
		_ = os.Remove(armedMarkerPath())
	}
}

// installKillSwitch idempotently builds the ARENA_KILLSWITCH chain and
// splices it at the top of OUTPUT. Called once after WireGuard adapter
// is up.
//
// allowedHosts is retained in the signature for wire compatibility with
// existing call sites (main.go) but is no longer read — the new
// semantics don't need a whitelist. The scenario-CIDR-only rule set
// leaves public egress alone, so there's nothing to whitelist against.
func installKillSwitch(tunnelName string, allowedHosts []string) error {
	_ = allowedHosts // retained for signature compat; unused post-rework

	// 1. Ensure chain exists, then flush it.
	//    `iptables -N X` returns non-zero if the chain already exists,
	//    so swallow the error; the follow-up flush is authoritative.
	_ = exec.Command("iptables", "-N", killSwitchChain).Run()
	if err := exec.Command("iptables", "-F", killSwitchChain).Run(); err != nil {
		return fmt.Errorf("iptables -F %s: %w", killSwitchChain, err)
	}

	// 2. The rule. `! -o <tun>` matches packets whose egress interface is
	//    anything OTHER than the tunnel. Combined with `-d 10.128.0.0/9`
	//    it catches only the specific failure mode we care about: a
	//    scenario-bound packet trying to leave via the physical NIC
	//    because the tunnel is down / routes flapped. Everything else —
	//    public internet, LAN, DNS, github, apt mirrors — is untouched.
	//    The chain implicitly RETURNs after this rule, so packets that
	//    don't match fall through to the rest of OUTPUT unchanged.
	rules := [][]string{
		{"-d", "10.128.0.0/9", "!", "-o", tunnelName, "-j", "DROP"},
	}

	// 3. Apply.
	for _, r := range rules {
		args := append([]string{"-A", killSwitchChain}, r...)
		if err := exec.Command("iptables", args...).Run(); err != nil {
			return fmt.Errorf("iptables %s: %w", strings.Join(args, " "), err)
		}
	}

	// 4. Splice the chain at the top of OUTPUT. If already present,
	//    delete first so we don't stack duplicates on re-install.
	_ = exec.Command("iptables", "-D", "OUTPUT", "-j", killSwitchChain).Run()
	if err := exec.Command("iptables", "-I", "OUTPUT", "1", "-j", killSwitchChain).Run(); err != nil {
		return fmt.Errorf("iptables -I OUTPUT: %w", err)
	}

	// Drop an armed-marker so the next startup can recover from a
	// hard crash. Best-effort — if the write fails the kill switch
	// still enforces, we just lose the recovery beacon.
	_ = os.MkdirAll(filepath.Dir(armedMarkerPath()), 0o755)
	_ = os.WriteFile(armedMarkerPath(), []byte("armed"), 0o644)

	return nil
}

// teardownKillSwitch removes the ARENA_KILLSWITCH chain. Called only on
// `arena-tunnel uninstall` or a clean SIGTERM — NEVER on a network drop.
func teardownKillSwitch() error {
	_ = exec.Command("iptables", "-D", "OUTPUT", "-j", killSwitchChain).Run()
	_ = exec.Command("iptables", "-F", killSwitchChain).Run()
	_ = exec.Command("iptables", "-X", killSwitchChain).Run()
	_ = os.Remove(armedMarkerPath())
	return nil
}

// detectResolvers + detectLocalCIDRs removed 2026-08-07 — the new
// scenario-CIDR-only kill switch (see installKillSwitch above) does
// not need a DNS/LAN whitelist because it never touches public egress
// in the first place. The Windows implementation has its own copies
// of these helpers.
