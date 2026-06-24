//go:build windows

package main

import (
	"os"
	"path/filepath"
)

var pidFilePath = filepath.Join(os.TempDir(), "arena-byoc.pid")

// processExists returns true when a process with the given PID is running.
// On Windows, reliable existence checks require cgo (OpenProcess). Without
// it, OpenProcess-equivalent isn't available, so we treat any parsed PID as
// stale. Worst case: two instances start briefly — acceptable for the Windows
// use case (operator VMs rarely run duplicate instances).
func processExists(_ int) bool {
	return false
}
