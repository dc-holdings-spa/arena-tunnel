//go:build !linux && !windows

package main

func cleanupPlatformArenaTrust() error { return nil }
