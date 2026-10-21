//go:build !linux && !windows

package main

import (
	"fmt"
	"runtime"

	"golang.zx2c4.com/wireguard/tun"
)

func configureTUN(_ tun.Device, _ string, _ *networkProfile) error {
	return fmt.Errorf("interface config not implemented for %s (PR welcome)", runtime.GOOS)
}

func reconcileTUN(_ tun.Device, _, _ *networkProfile) error { return nil }

func configureTunnelDNS(_ tun.Device, _ *networkProfile) error { return nil }

func teardownTUN(_ tun.Device, _ *networkProfile) {}
