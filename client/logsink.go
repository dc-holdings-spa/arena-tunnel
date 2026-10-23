// Durable, size-rotated log sink for long-running client processes
// (#2607 D0). Scheduled-task runs have no stdout/stderr attached, so the
// durable bootstrap was blind after a reboot. Every long-running mode now
// tees the standard log to %LOCALAPPDATA%/arena-tunnel (Windows) or
// $XDG_STATE_HOME/arena-tunnel (elsewhere), rotating by size so a stuck
// loop can never fill the disk.
//
// Files are created 0600 — owner-only on Windows (the interactive user
// running the task) and on Unix. No tokens, keys or cookies are ever
// logged by the client; the sink itself adds no content.
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
	logKeep     = 3       // arena-tunnel.log, .1, .2, .3
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
	s := &rotatingSink{path: path, maxSize: maxSize, keep: keep, mu: make(chan struct{}, 1)}
	s.mu <- struct{}{}
	if err := s.open(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *rotatingSink) open() error {
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
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

// rotate shifts arena-tunnel-task.log.(keep-1) → .keep, ..., .1 → .2,
// then renames the live file to .1.
func (s *rotatingSink) rotate() {
	_ = s.f.Close()
	for i := s.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", s.path, i), fmt.Sprintf("%s.%d", s.path, i+1))
	}
	_ = os.Rename(s.path, s.path+".1")
}

func (s *rotatingSink) Write(p []byte) (int, error) {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()

	if s.n+int64(len(p)) > s.maxSize {
		s.rotate()
		if err := s.open(); err != nil {
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
