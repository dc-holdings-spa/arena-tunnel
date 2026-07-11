//go:build !linux && !windows

package main

import (
	"fmt"
	"runtime"

	"golang.zx2c4.com/wireguard/tun"
)

func configureTUN(_ tun.Device, _ string) error {
	return fmt.Errorf("interface config not implemented for %s (PR welcome)", runtime.GOOS)
}

func teardownTUN(_ tun.Device) {}
