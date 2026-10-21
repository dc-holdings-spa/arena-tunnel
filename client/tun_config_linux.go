//go:build linux

package main

import (
	"fmt"
	"log"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

// configureTUN assigns the tunnel IP + /16 mask and installs the pushed
// routes over the interface using iproute2. /16 mask is deliberate — the
// whole tunnel pool (10.201.0.0/16, widened from /24) is on-link, so the
// server gateway 10.201.0.1 and any peer /32 sit in the same supernet
// regardless of which /24 this client's IP landed in.
func configureTUN(_ tun.Device, ipStr string, profile *networkProfile) error {
	if err := exec.Command("ip", "addr", "add", ipStr+"/16", "dev", tunnelName).Run(); err != nil {
		return fmt.Errorf("ip addr add: %w", err)
	}
	if err := exec.Command("ip", "link", "set", tunnelName, "up").Run(); err != nil {
		return fmt.Errorf("ip link set up: %w", err)
	}
	for _, r := range networkProfileRouteCIDRs(profile) {
		// Replace, not add, so re-running over a partial config is safe.
		if err := exec.Command("ip", "route", "replace", r, "dev", tunnelName).Run(); err != nil {
			return fmt.Errorf("install route %s: %w", r, err)
		}
		log.Printf("[route] %s via %s", r, tunnelName)
	}
	return nil
}

func configureTunnelDNS(_ tun.Device, profile *networkProfile) error {
	return configureLinuxDNS(profile)
}

func reconcileTUN(_ tun.Device, previous, next *networkProfile) error {
	previousRoutes := networkRouteSet(previous)
	nextRoutes := networkRouteSet(next)
	// Withdraw old authorization first. A failed add therefore narrows access.
	for route := range previousRoutes {
		if _, keep := nextRoutes[route]; keep {
			continue
		}
		if err := exec.Command("ip", "route", "del", route, "dev", tunnelName).Run(); err != nil {
			log.Printf("[route] failed to withdraw %s: %v", route, err)
		}
	}
	for route := range nextRoutes {
		if _, exists := previousRoutes[route]; exists {
			continue
		}
		if err := exec.Command("ip", "route", "replace", route, "dev", tunnelName).Run(); err != nil {
			return fmt.Errorf("install route %s: %w", route, err)
		}
	}
	return configureLinuxDNS(next)
}

func configureLinuxDNS(profile *networkProfile) error {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return fmt.Errorf("resolvectl is required for scoped Arena DNS: %w", err)
	}
	args := append([]string{"dns", tunnelName}, profile.DNS.Servers...)
	if out, err := exec.Command("resolvectl", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("resolvectl dns: %w (%s)", err, string(out))
	}
	domain := ""
	if profile.DNS.RouteAll {
		domain = "~."
	}
	if out, err := exec.Command("resolvectl", "domain", tunnelName, domain).CombinedOutput(); err != nil {
		_ = exec.Command("resolvectl", "revert", tunnelName).Run()
		return fmt.Errorf("resolvectl domain: %w (%s)", err, string(out))
	}
	if out, err := exec.Command("resolvectl", "default-route", tunnelName, "yes").CombinedOutput(); err != nil {
		_ = exec.Command("resolvectl", "revert", tunnelName).Run()
		return fmt.Errorf("resolvectl default-route: %w (%s)", err, string(out))
	}
	return nil
}

func teardownTUN(_ tun.Device, profile *networkProfile) {
	_ = exec.Command("resolvectl", "revert", tunnelName).Run()
	for _, r := range networkProfileRouteCIDRs(profile) {
		exec.Command("ip", "route", "del", r, "dev", tunnelName).Run()
	}
	exec.Command("ip", "link", "set", tunnelName, "down").Run()
	exec.Command("ip", "addr", "flush", "dev", tunnelName).Run()
}
