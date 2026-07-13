//go:build !linux && !windows
// +build !linux,!windows

package main

// Kill switch — unsupported platform stub.
//
// Sprint 7 T1. macOS + *BSD are not covered by the initial v1.4.0
// rollout. The client still runs — it just can't arm the kill switch,
// and the heartbeat reports `armed: false` so the RTaaS chip renders
// UNPROTECTED rather than PROTECTED.

import "fmt"

func installKillSwitch(_ string, _ []string) error {
	return fmt.Errorf("kill switch not supported on this OS")
}

func teardownKillSwitch() error {
	return nil
}

// recoverKillSwitchIfLeftArmed is a no-op on unsupported platforms —
// there is no armed state to recover from because installKillSwitch
// always fails first.
func recoverKillSwitchIfLeftArmed() {}
