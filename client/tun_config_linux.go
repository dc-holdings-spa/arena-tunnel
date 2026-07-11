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
func configureTUN(_ tun.Device, ipStr string) error {
	if err := exec.Command("ip", "addr", "add", ipStr+"/16", "dev", tunnelName).Run(); err != nil {
		return fmt.Errorf("ip addr add: %w", err)
	}
	if err := exec.Command("ip", "link", "set", tunnelName, "up").Run(); err != nil {
		return fmt.Errorf("ip link set up: %w", err)
	}
	for _, r := range pushRoutes {
		// Replace, not add, so re-running over a partial config is safe.
		if err := exec.Command("ip", "route", "replace", r, "dev", tunnelName).Run(); err != nil {
			log.Printf("[route] failed to install %s: %v", r, err)
		} else {
			log.Printf("[route] %s via %s", r, tunnelName)
		}
	}
	return nil
}

func teardownTUN(_ tun.Device) {
	for _, r := range pushRoutes {
		exec.Command("ip", "route", "del", r, "dev", tunnelName).Run()
	}
	exec.Command("ip", "link", "set", tunnelName, "down").Run()
	exec.Command("ip", "addr", "flush", "dev", tunnelName).Run()
}
