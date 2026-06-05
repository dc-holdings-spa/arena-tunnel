// config.go — on-disk pairing state for arena-byoc.
//
// Path resolution (first match wins):
//   1. $ARENA_BYOC_CONFIG (explicit override).
//   2. $XDG_CONFIG_HOME/arena-byoc/config.json (if set).
//   3. linux/bsd: $HOME/.config/arena-byoc/config.json
//      darwin:    $HOME/Library/Application Support/arena-byoc/config.json
//      windows:   %APPDATA%\arena-byoc\config.json  (fallback %USERPROFILE%\.arena-byoc\config.json)
//   4. cwd/arena-byoc.json (last-resort, with stderr warning).
//
// Permissions: dir 0700, file 0600 on unix. Atomic write via tmp + rename.
// Schema version 1: any version mismatch or parse error is treated as
// "no config" so the caller re-pairs without prompting.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// ConfigSchemaVersion is the on-disk schema version. Bump on breaking changes.
const ConfigSchemaVersion = 1

// Config is the persisted pairing state.
type Config struct {
	Version      int    `json:"version"`
	TunnelIP     string `json:"tunnelIp"`
	PrivateKey   string `json:"privateKey"`
	ServerPubKey string `json:"serverPubKey"`
	ServerHost   string `json:"serverHost"`
	UserEmail    string `json:"userEmail"`
	PairedAt     string `json:"pairedAt"`
	ArenaBaseURL string `json:"arenaBaseURL,omitempty"`
	DeviceID     string `json:"deviceId,omitempty"`
}

// Complete reports whether Config carries the minimum fields required to
// bring up the tunnel. Missing fields => treat as no-config.
func (c *Config) Complete() bool {
	if c == nil {
		return false
	}
	return c.Version == ConfigSchemaVersion &&
		c.TunnelIP != "" &&
		c.PrivateKey != "" &&
		c.ServerPubKey != "" &&
		c.ServerHost != ""
}

// ResolveConfigPath returns the final on-disk location for the config file.
// If override is non-empty it is used verbatim.
func ResolveConfigPath(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if env := os.Getenv("ARENA_BYOC_CONFIG"); env != "" {
		return env, nil
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "arena-byoc", "config.json"), nil
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// Degraded fallback: keep next to cwd. We still want SOMETHING.
		fmt.Fprintln(os.Stderr, "[warn] $HOME unresolvable, persisting config to ./arena-byoc.json")
		return "arena-byoc.json", nil
	}

	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "arena-byoc", "config.json"), nil
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return filepath.Join(appdata, "arena-byoc", "config.json"), nil
		}
		return filepath.Join(home, ".arena-byoc", "config.json"), nil
	default:
		return filepath.Join(home, ".config", "arena-byoc", "config.json"), nil
	}
}

// LoadConfig reads + parses the file at path. Returns (nil, nil) if the
// file does not exist — first-run is not an error. A parse or version
// mismatch is also folded into (nil, nil) after a warning, because we
// would rather re-pair than block on stale junk. Genuine I/O errors
// (permission denied etc.) surface as the second return.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		fmt.Fprintf(os.Stderr, "[warn] ignoring corrupt config at %s (%v); will re-pair\n", path, err)
		return nil, nil
	}
	if c.Version != ConfigSchemaVersion {
		fmt.Fprintf(os.Stderr, "[warn] ignoring config at %s with unknown version %d; will re-pair\n", path, c.Version)
		return nil, nil
	}
	return &c, nil
}

// SaveConfig writes the config atomically. Parent dir is created with 0700,
// file written with 0600 via O_CREAT|O_EXCL on a tmp sibling, then renamed.
func SaveConfig(path string, c *Config) error {
	if c == nil {
		return errors.New("nil config")
	}
	if c.Version == 0 {
		c.Version = ConfigSchemaVersion
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')

	tmp := path + ".tmp"
	// Best-effort cleanup of a stale tmp left behind by a previous crash.
	_ = os.Remove(tmp)

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open tmp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("sync tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// WipeConfig overwrites the file with zeros then unlinks it. Best-effort
// scrub of the private key from disk; on most filesystems the zero pass
// hits the same blocks because the file is tiny (< 1 page).
func WipeConfig(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	// Overwrite. Ignore truncate errors — we still unlink afterwards.
	if f, oerr := os.OpenFile(path, os.O_WRONLY, 0o600); oerr == nil {
		zeros := make([]byte, st.Size())
		_, _ = f.Write(zeros)
		_ = f.Sync()
		_ = f.Close()
	}
	return os.Remove(path)
}
