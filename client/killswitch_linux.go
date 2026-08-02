//go:build linux
// +build linux

package main

// Kill switch — Linux implementation.
//
// Sprint 7 T1 (arena-tunnel v1.4.0). Installs an iptables chain named
// ARENA_KILLSWITCH that DROPs every outbound unicast packet except:
//   1. traffic exiting the arena-tunnel tun device
//   2. traffic to loopback
//   3. traffic to the scenario VLAN CIDR (10.128.0.0/9)
//   4. traffic to the local LAN CIDRs detected at install time
//   5. traffic to the resolved IPs of the ARENA control-plane host + the
//      Cloudflare edges backing wg-byoc.adversario.cl
//
// The chain is spliced at the top of OUTPUT so it runs before any
// user-installed rules. At install time we FLUSH + REBUILD idempotently
// so a re-run picks up refreshed resolver results.
//
// Requires CAP_NET_ADMIN. The wrapper `arena-tunnel` binary is invoked as
// root during install so no extra privilege escalation is needed.

import (
	"bufio"
	"fmt"
	"net"
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
func installKillSwitch(tunnelName string, allowedHosts []string) error {
	// 1. Ensure chain exists, then flush it.
	//    `iptables -N X` returns non-zero if the chain already exists,
	//    so swallow the error; the follow-up flush is authoritative.
	_ = exec.Command("iptables", "-N", killSwitchChain).Run()
	if err := exec.Command("iptables", "-F", killSwitchChain).Run(); err != nil {
		return fmt.Errorf("iptables -F %s: %w", killSwitchChain, err)
	}

	// 2. Allow tunnel + loopback + scenario VLAN.
	rules := [][]string{
		{"-o", tunnelName, "-j", "ACCEPT"},
		{"-o", "lo", "-j", "ACCEPT"},
		{"-d", "10.128.0.0/9", "-j", "ACCEPT"},
	}

	// 3. Detect local LAN CIDRs and add allow rules for each. Keeps a
	//    student's ssh-to-home-NAS and remote-desktop workflows alive.
	for _, cidr := range detectLocalCIDRs(tunnelName) {
		rules = append(rules, []string{"-d", cidr, "-j", "ACCEPT"})
	}

	// 3b. Detect DNS resolvers from /etc/resolv.conf. If the student's
	//     laptop points at their home router (typically 192.168.1.1)
	//     the LAN allow already covers it. But cloud VMs, cafe Wi-Fi
	//     captive portals, and containers routinely ship explicit
	//     public resolvers like 1.1.1.1 or 8.8.8.8 — DROPping those
	//     kills DNS entirely and every subsequent hostname lookup
	//     (including the WSS reconnect to wg-byoc.adversario.cl) hangs.
	//     Allow them on UDP + TCP 53 only, not blanket egress.
	for _, dns := range detectResolvers() {
		rules = append(rules, []string{"-p", "udp", "-d", dns, "--dport", "53", "-j", "ACCEPT"})
		rules = append(rules, []string{"-p", "tcp", "-d", dns, "--dport", "53", "-j", "ACCEPT"})
	}

	// 4. Resolve + allow the control-plane hosts. Resolves once at
	//    install time; if the DNS answers rotate we re-install on next
	//    startup so the rules stay accurate.
	for _, host := range allowedHosts {
		ips, err := net.LookupIP(host)
		if err != nil {
			continue // best-effort — a hostname miss is not fatal
		}
		for _, ip := range ips {
			// iptables is IPv4-only. Cloudflare-fronted hosts (like
			// arena.adversario.cl) resolve to both AAAA and A; passing
			// a v6 address to iptables makes it exit 2 and abort the
			// whole install, taking every prior rule down with it.
			// Skip v6 silently — the v4 record is enough because the
			// tunnel is IPv4 anyway.
			if ip.To4() == nil {
				continue
			}
			rules = append(rules, []string{"-d", ip.String(), "-j", "ACCEPT"})
		}
	}

	// 5. Drop everything else.
	rules = append(rules, []string{"-j", "DROP"})

	// 6. Apply the rules in order.
	for _, r := range rules {
		args := append([]string{"-A", killSwitchChain}, r...)
		if err := exec.Command("iptables", args...).Run(); err != nil {
			return fmt.Errorf("iptables %s: %w", strings.Join(args, " "), err)
		}
	}

	// 7. Splice the chain at the top of OUTPUT. If already present,
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

// detectResolvers reads /etc/resolv.conf and returns the IPv4
// addresses of the DNS resolvers the system is configured to use.
// systemd-resolved's `127.0.0.53` (or `127.0.0.54`) is treated as
// loopback and skipped — the LAN allow list already permits any
// LAN-local resolver, and loopback is covered by its own rule.
func detectResolvers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[1])
		if ip == nil || ip.To4() == nil {
			continue // v6 handled by ip6tables in a future round
		}
		if ip.IsLoopback() {
			continue // covered by the "-o lo" rule already
		}
		out = append(out, ip.String())
	}
	return out
}

// detectLocalCIDRs enumerates every interface's IPv4 CIDR, excluding
// the tunnel device (already covered) and loopback. The result feeds
// the allow list so the student's home LAN stays reachable.
func detectLocalCIDRs(tunnelName string) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var cidrs []string
	for _, iface := range ifaces {
		if iface.Name == tunnelName || iface.Name == "lo" {
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
