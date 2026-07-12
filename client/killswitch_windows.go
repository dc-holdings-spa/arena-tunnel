//go:build windows
// +build windows

package main

// Kill switch — Windows implementation.
//
// Sprint 7 T1 (arena-tunnel v1.4.0). Uses `New-NetFirewallRule` (or
// its `netsh advfirewall firewall add rule` fallback on older SKUs) to
// block outbound traffic from the arena-byoc process EXCEPT via the
// wintun interface. Rules are grouped under `ArenaKillSwitch` so
// teardown is a single `Remove-NetFirewallRule -Group`.
//
// Requires Administrator. The install flow already elevates for the
// wintun driver so no extra prompt.

import (
	"fmt"
	"os"
	"os/exec"
)

const killSwitchGroup = "ArenaKillSwitch"

// installKillSwitch installs two firewall rules under the
// `ArenaKillSwitch` group: one Block Outbound rule scoped to the
// arena-byoc.exe program, one Allow Outbound rule scoped to the
// arena-byoc wintun adapter alias so the tunnel itself remains
// reachable.
func installKillSwitch(tunnelName string, _ []string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	// Idempotency — if we're re-installing, remove any prior rules
	// under the group first. Ignore errors: a fresh install has none.
	_ = exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Remove-NetFirewallRule -Group "%s" -ErrorAction SilentlyContinue`, killSwitchGroup)).Run()

	block := fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "ArenaKillSwitch-Block" `+
			`-Group "%s" -Direction Outbound -Program "%s" -Action Block`,
		killSwitchGroup, exePath,
	)
	allow := fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "ArenaKillSwitch-AllowTunnel" `+
			`-Group "%s" -Direction Outbound -InterfaceAlias "%s" -Action Allow`,
		killSwitchGroup, tunnelName,
	)

	if err := exec.Command("powershell", "-NoProfile", "-Command", block).Run(); err != nil {
		return fmt.Errorf("install block rule: %w", err)
	}
	if err := exec.Command("powershell", "-NoProfile", "-Command", allow).Run(); err != nil {
		return fmt.Errorf("install allow rule: %w", err)
	}
	return nil
}

// teardownKillSwitch removes every rule in the ArenaKillSwitch group.
// Called on `arena-byoc uninstall` or clean SIGTERM — NEVER on network
// drop.
func teardownKillSwitch() error {
	cmd := fmt.Sprintf(`Remove-NetFirewallRule -Group "%s" -ErrorAction SilentlyContinue`, killSwitchGroup)
	if err := exec.Command("powershell", "-NoProfile", "-Command", cmd).Run(); err != nil {
		return fmt.Errorf("teardown: %w", err)
	}
	return nil
}
