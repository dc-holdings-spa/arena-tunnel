//go:build linux
// +build linux

package main

// Kill switch — Linux implementation.
//
// Sprint 7 T1 (arena-tunnel v1.4.0). Installs an iptables chain named
// ARENA_KILLSWITCH that DROPs every outbound unicast packet except:
//   1. traffic exiting the arena-byoc tun device
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
// Requires CAP_NET_ADMIN. The wrapper `arena-byoc` binary is invoked as
// root during install so no extra privilege escalation is needed.

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

const killSwitchChain = "ARENA_KILLSWITCH"

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

	// 4. Resolve + allow the control-plane hosts. Resolves once at
	//    install time; if the DNS answers rotate we re-install on next
	//    startup so the rules stay accurate.
	for _, host := range allowedHosts {
		ips, err := net.LookupIP(host)
		if err != nil {
			continue // best-effort — a hostname miss is not fatal
		}
		for _, ip := range ips {
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

	return nil
}

// teardownKillSwitch removes the ARENA_KILLSWITCH chain. Called only on
// `arena-byoc uninstall` or a clean SIGTERM — NEVER on a network drop.
func teardownKillSwitch() error {
	_ = exec.Command("iptables", "-D", "OUTPUT", "-j", killSwitchChain).Run()
	_ = exec.Command("iptables", "-F", killSwitchChain).Run()
	_ = exec.Command("iptables", "-X", killSwitchChain).Run()
	return nil
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
