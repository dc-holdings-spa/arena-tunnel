//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
)

var arenaTrustPath = "/usr/local/share/ca-certificates/arena-adaptix-teamserver.crt"
var runTrustCommand = func(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func cleanupPlatformArenaTrust() error {
	err := os.Remove(arenaTrustPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return runTrustCommand("update-ca-certificates")
}
