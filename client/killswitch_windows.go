//go:build windows
// +build windows

package main

// Kill switch — Windows implementation.
//
// arena-tunnel v1.4.0. Same semantic as the Linux impl: block ALL
// outbound traffic except:
//   1. traffic exiting the arena-tunnel wintun adapter
//   2. traffic to loopback
//   3. traffic to the scenario VLAN CIDR (10.128.0.0/9)
//   4. traffic to the local LAN CIDRs detected at install time
//   5. traffic to the resolved IPs of the ARENA control-plane host + the
//      Cloudflare edges backing wg-byoc.adversario.cl
//
// The previous impl scoped a `-Program` block to arena-tunnel.exe only —
// that blocked the tunnel client from talking to the LAN but left
// Chrome / Firefox / anything-else free to leak the student's real IP
// to the scenario target. That is the exact scenario a kill switch
// has to prevent, so the first cut was a semantic no-op.
//
// This rewrite mirrors the Linux design: flip the Windows Firewall
// outbound default to Block, then add a group of Allow rules that
// carve out precisely the destinations the student needs. Group name
// is `ArenaKillSwitch` so teardown is a one-liner.
//
// Ordering: RESOLVE arena hosts + enumerate LAN CIDRs BEFORE flipping
// the default to Block; a post-flip DNS lookup would fall in a hole.
// Then add every Allow rule, then flip.
//
// Requires Administrator. The install flow already elevates for the
// wintun driver so there's no extra prompt.

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const killSwitchGroup = "ArenaKillSwitch"

// armedMarkerPath returns the path to a small file we drop while the
// kill switch is armed. Presence-on-startup means the previous session
// crashed without teardown and we have to unlock the student before
// doing anything else — otherwise they are permanently locked out with
// no way to reach arena.adversario.cl to redownload or ask for help.
func armedMarkerPath() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "arena-tunnel", "killswitch.armed")
}

// recoverKillSwitchIfLeftArmed is called at the top of every arena-tunnel
// startup. If we find a stale armed-marker, we teardown the firewall
// state so the student can reach the network again — this is the ONLY
// recovery path for a hard-crash-while-armed scenario. Safe to call
// even when nothing is armed; no-op in that case.
func recoverKillSwitchIfLeftArmed() {
	if _, err := os.Stat(armedMarkerPath()); err == nil {
		_ = teardownKillSwitch()
		_ = os.Remove(armedMarkerPath())
	}
}

// installKillSwitch enforces the Windows Firewall outbound policy.
// Called once after the WireGuard adapter is up.
func installKillSwitch(tunnelName string, allowedHosts []string) error {
	// 1. Resolve control-plane hosts BEFORE we start blocking. Once
	//    default outbound is Block, subsequent DNS goes into a hole.
	var arenaIPs []string
	for _, host := range allowedHosts {
		ips, err := net.LookupIP(host)
		if err != nil {
			continue // best-effort — a hostname miss is not fatal
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				arenaIPs = append(arenaIPs, ip.String())
			}
		}
	}

	// 2. Enumerate local LAN CIDRs. Same as the Linux impl — keeps
	//    a student's ssh-to-home-NAS and RDP workflows alive.
	lanCIDRs := detectLocalCIDRs(tunnelName)

	// 3. Clean any leftover rules under our group (idempotency).
	_ = ps(fmt.Sprintf(
		`Remove-NetFirewallRule -Group "%s" -ErrorAction SilentlyContinue`, killSwitchGroup))

	// 4. Add Allow rules FIRST so the moment we flip default to Block
	//    the carve-outs are already in place.
	if err := ps(fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "ArenaKS-AllowTunnel" -Group "%s" `+
			`-Direction Outbound -InterfaceAlias "%s" -Action Allow -Profile Any -Enabled True`,
		killSwitchGroup, tunnelName,
	)); err != nil {
		return fmt.Errorf("allow tunnel: %w", err)
	}

	if err := ps(fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "ArenaKS-AllowLoopback" -Group "%s" `+
			`-Direction Outbound -RemoteAddress 127.0.0.0/8 -Action Allow -Profile Any -Enabled True`,
		killSwitchGroup,
	)); err != nil {
		return fmt.Errorf("allow loopback: %w", err)
	}

	if err := ps(fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "ArenaKS-AllowScenario" -Group "%s" `+
			`-Direction Outbound -RemoteAddress 10.128.0.0/9 -Action Allow -Profile Any -Enabled True`,
		killSwitchGroup,
	)); err != nil {
		return fmt.Errorf("allow scenario: %w", err)
	}

	for i, cidr := range lanCIDRs {
		if err := ps(fmt.Sprintf(
			`New-NetFirewallRule -DisplayName "ArenaKS-AllowLAN-%d" -Group "%s" `+
				`-Direction Outbound -RemoteAddress %s -Action Allow -Profile Any -Enabled True`,
			i, killSwitchGroup, cidr,
		)); err != nil {
			return fmt.Errorf("allow LAN %s: %w", cidr, err)
		}
	}

	for i, ip := range arenaIPs {
		if err := ps(fmt.Sprintf(
			`New-NetFirewallRule -DisplayName "ArenaKS-AllowArena-%d" -Group "%s" `+
				`-Direction Outbound -RemoteAddress %s -Action Allow -Profile Any -Enabled True`,
			i, killSwitchGroup, ip,
		)); err != nil {
			return fmt.Errorf("allow arena IP: %w", err)
		}
	}

	// 5. Flip default outbound to Block. From this line forward the
	//    only outbound that succeeds is via our Allow rules.
	if err := ps(
		`Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block`,
	); err != nil {
		return fmt.Errorf("set default outbound block: %w", err)
	}

	// 6. Verify the flip actually took effect. Set-NetFirewallProfile
	//    can silently return success even when the caller lacks the
	//    privileges to mutate the Windows Firewall (WinRM sessions,
	//    unelevated interactive shells). Reading the profile back
	//    tells us for sure — if it still says Allow, the kill switch
	//    is a lie and we surface a hard error so the CLI can bail out
	//    before we mislead the student's chip into showing PROTECTED.
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`(Get-NetFirewallProfile -Name Public).DefaultOutboundAction`).Output()
	if err != nil {
		return fmt.Errorf("verify default outbound: %w", err)
	}
	if !strings.Contains(strings.ToLower(strings.TrimSpace(string(out))), "block") {
		return fmt.Errorf("default outbound still not Block (got %q) — arena-tunnel.exe is not running elevated. Re-launch PowerShell as Administrator", strings.TrimSpace(string(out)))
	}

	// 7. Drop an armed-marker so a subsequent crash-recovery pass can
	//    tell we were armed. Best-effort: if the marker fails to write
	//    the kill switch still works, we just lose the recovery beacon.
	_ = os.MkdirAll(filepath.Dir(armedMarkerPath()), 0o755)
	_ = os.WriteFile(armedMarkerPath(), []byte("armed"), 0o644)

	return nil
}

// teardownKillSwitch restores the default outbound policy AND removes
// every rule under the ArenaKillSwitch group. Called only on
// `arena-tunnel uninstall` or a clean SIGTERM — NEVER on a network drop.
func teardownKillSwitch() error {
	// Restore default outbound BEFORE removing our allow rules, so
	// there is no instant during teardown where the student is fully
	// locked out.
	_ = ps(`Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow`)
	_ = ps(fmt.Sprintf(
		`Remove-NetFirewallRule -Group "%s" -ErrorAction SilentlyContinue`, killSwitchGroup))
	_ = os.Remove(armedMarkerPath())
	return nil
}

// detectLocalCIDRs enumerates every non-tunnel non-loopback interface's
// IPv4 CIDR. The result feeds the allow list so the student's home LAN
// stays reachable while the kill switch is armed.
func detectLocalCIDRs(tunnelName string) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var cidrs []string
	for _, iface := range ifaces {
		name := strings.ToLower(iface.Name)
		if iface.Name == tunnelName || strings.Contains(name, "loopback") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipn, ok := addr.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			cidrs = append(cidrs, ipn.String())
		}
	}
	return cidrs
}

// ps runs a PowerShell command with -NoProfile and returns any error
// from the process. Stdout/stderr are discarded — the caller only
// cares whether the rule mutation succeeded.
func ps(cmd string) error {
	return exec.Command("powershell", "-NoProfile", "-Command", cmd).Run()
}
