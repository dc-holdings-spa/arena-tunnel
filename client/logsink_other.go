//go:build !windows

package main

// restrictToOwner is a no-op off Windows: the 0600/0700 modes passed to
// os.OpenFile/MkdirAll are the native owner-only guarantee there.
func restrictToOwner(path string) error { return nil }
