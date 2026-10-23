//go:build windows

package main

import "os/exec"

func cleanupPlatformArenaTrust() error {
	// Fixed program and script: no server or user-controlled values are ever
	// interpolated. Remove only certificates tagged by the official installer.
	const script = `$store = New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine'); try { $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite); @($store.Certificates | Where-Object { $_.FriendlyName -eq 'Arena Adaptix TeamServer' }) | ForEach-Object { $store.Remove($_) } } finally { $store.Close() }`
	return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Run()
}
