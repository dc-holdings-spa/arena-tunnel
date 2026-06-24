//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

var pidFilePath = filepath.Join(os.TempDir(), "arena-byoc.pid")

// processExists returns true when a process with the given PID is running.
// Uses kill(2) signal 0 — no signal is delivered, just checks existence.
func processExists(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
