// Durable, size-rotated log sink for long-running client processes
// (#2607 D0). Scheduled-task runs have no stdout/stderr attached, so the
// durable bootstrap was blind after a reboot. Every long-running mode now
// tees the standard log to %LOCALAPPDATA%/arena-tunnel (Windows) or
// $XDG_STATE_HOME/arena-tunnel (elsewhere), rotating by size so a stuck
// loop can never fill the disk.
//
// ACL note (audit point 4): on Windows, POSIX modes on OpenFile/MkdirAll
// do NOT set a private DACL. restrictToOwner() (logsink_windows.go)
// applies an explicit owner-only protected DACL to the directory and the
// file; other platforms use 0600/0700 which is the native guarantee.
// No tokens, keys or cookies are ever logged by the client.
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

const (
	logMaxBytes = 5 << 20 // rotate at 5 MiB
	logKeep     = 3       // arena-tunnel-task.log, .1, .2, .3
)

// osRename/osRemove are indirections so tests can simulate Windows
// rename semantics (fails when the destination exists) on Linux
// (audit point 5).
var (
	osRename = os.Rename
	osRemove = os.Remove
)

// durableLogPath returns the per-user log location.
func durableLogPath() (string, error) {
	if runtime.GOOS == "windows" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			return "", fmt.Errorf("LOCALAPPDATA unset")
		}
		return filepath.Join(base, "arena-tunnel", "arena-tunnel-task.log"), nil
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "arena-tunnel", "arena-tunnel-task.log"), nil
}

// rotatingSink is an io.Writer that rotates its file by size.
type rotatingSink struct {
	path    string
	maxSize int64
	keep    int

	f  *os.File
	n  int64
	mu chan struct{} // buffered(1) semaphore used as a lock
}

func newRotatingSink(path string, maxSize int64, keep int) (*rotatingSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := restrictToOwner(filepath.Dir(path)); err != nil {
		// Non-fatal: the path is already per-user; keep going but record it.
		log.Printf("[log] owner ACL on %s failed: %v", filepath.Dir(path), err)
	}
	s := &rotatingSink{path: path, maxSize: maxSize, keep: keep, mu: make(chan struct{}, 1)}
	s.mu <- struct{}{}
	if err := s.open(false); err != nil {
		return nil, err
	}
	if err := restrictToOwner(path); err != nil {
		log.Printf("[log] owner ACL on %s failed: %v", path, err)
	}
	return s, nil
}

func (s *rotatingSink) open(truncate bool) error {
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if truncate {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(s.path, flags, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	s.f, s.n = f, st.Size()
	return nil
}

// rotate deletes the oldest archive first, then shifts .1→.2→.3 and
// renames the live file to .1. Windows rename does NOT replace an
// existing destination, so every destination is explicitly removed
// before its rename (audit point 5); errors are propagated instead of
// being silently ignored.
func (s *rotatingSink) rotate() error {
	if err := osRemove(fmt.Sprintf("%s.%d", s.path, s.keep)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove oldest archive: %w", err)
	}
	for i := s.keep - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", s.path, i)
		dst := fmt.Sprintf("%s.%d", s.path, i+1)
		if err := osRename(src, dst); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("shift %s: %w", src, err)
		}
	}
	if err := osRename(s.path, s.path+".1"); err != nil {
		return fmt.Errorf("archive live log: %w", err)
	}
	return nil
}

func (s *rotatingSink) Write(p []byte) (int, error) {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()

	if s.n+int64(len(p)) > s.maxSize {
		_ = s.f.Close()
		if err := s.rotate(); err != nil {
			// Rotation failed (e.g. a rotated file locked by a backup
			// scanner). Bounded growth beats silent inflation: truncate
			// the live file and keep the sink usable, loudly.
			log.Printf("[log] rotation failed (%v) — truncating %s to stay bounded", err, s.path)
			if err := s.open(true); err != nil {
				return 0, err
			}
		} else if err := s.open(false); err != nil {
			return 0, err
		}
	}
	n, err := s.f.Write(p)
	s.n += int64(n)
	return n, err
}

func (s *rotatingSink) Close() error {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()
	return s.f.Close()
}

// installDurableLog tees the standard logger to the rotating sink and
// returns a closer. Failure to open the sink is non-fatal: we log to
// stderr and keep running (a read-only profile must not kill the tunnel).
func installDurableLog() io.Closer {
	path, err := durableLogPath()
	if err != nil {
		log.Printf("[log] durable log unavailable: %v", err)
		return nil
	}
	sink, err := newRotatingSink(path, logMaxBytes, logKeep)
	if err != nil {
		log.Printf("[log] durable log unavailable at %s: %v", path, err)
		return nil
	}
	log.SetOutput(io.MultiWriter(os.Stderr, sink))
	log.Printf("[log] durable log at %s (rotate %d bytes, keep %d)", path, logMaxBytes, logKeep)
	return sink
}
