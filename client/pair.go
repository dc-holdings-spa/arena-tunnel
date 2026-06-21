// pair.go — Tailscale-style browser pairing for arena-byoc.
//
// Flow:
//   1. Generate a 6-char human-friendly code (Crockford-ish alphabet,
//      no 0/1/I/O/L confusables).
//   2. POST  {arena}/api/byoc2/pair/init  {code, version, hostname, os, arch}
//      → 200 {code, claimUrl, expiresAt} — server mints the code
//   3. Print code + URL to stdout, try to open the URL in the user's
//      default browser. Browser open failure is non-fatal.
//   4. Poll GET {arena}/api/byoc2/pair/poll?code=<code> every 2s for up
//      to 10 minutes.
//      - 202 → still pending, keep polling.
//      - 200 → claimed; body has full creds (tunnelIp, privateKey, ...).
//      - 410 → user clicked Cancel.
//      - 404 → code expired or never existed.
//      - 5xx / net err → exponential backoff up to 30s, exit after 30
//        consecutive failures.
//   5. Persist claimed creds via SaveConfig.
//
// Headless --token short-circuit:
//   GET {arena}/api/byoc2/pair/claim?token=<one-shot> → same 200 body
//   shape as the poll-claimed response. Used by Ansible/cloud-init.

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Pairing exit codes (kept in sync with the README + errorHandling table).
const (
	ExitOK                    = 0
	ExitFatalRuntime          = 1
	ExitPairInitFailed        = 2
	ExitUserCancelled         = 3
	ExitExpiredOrNotFound     = 4
	ExitNetworkBudgetExceeded = 5
	ExitPairWallClockTimeout  = 6
	ExitConfigPermDenied      = 7
	ExitConfigUnlinkFailed    = 8
	ExitSignal                = 130
)

// pairingAlphabet excludes 0/1/I/O/L — the usual confusables. 32 chars
// gives 32^6 ≈ 1.07B codes; plenty for a 10-minute one-shot.
const pairingAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

const (
	pollIntervalDefault = 2 * time.Second
	pollPerRequestTO    = 10 * time.Second
	pollWallClockMax    = 10 * time.Minute
	pollNetMaxFailures  = 30
	pollNetMaxBackoff   = 30 * time.Second

	httpClientTimeout = 15 * time.Second
)

// generatePairingCode returns a length-N string from pairingAlphabet,
// drawn via crypto/rand so a noisy student running it twice still gets
// independent codes.
func generatePairingCode(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = pairingAlphabet[int(b)%len(pairingAlphabet)]
	}
	return string(out), nil
}

// pairInitRequest is the body POSTed to /api/byoc2/pair/init.
// The code is NOT supplied by the client: since the v2 lifecycle the server
// mints it and rejects any client-supplied code (CLIENT_CODE_REJECTED).
type pairInitRequest struct {
	ClientVersion string `json:"clientVersion"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
}

// pairInitResponse is the JSON returned by /api/byoc2/pair/init on 200.
// `code` is the server-minted pairing code we poll + open the browser with.
type pairInitResponse struct {
	Code      string `json:"code"`
	ClaimURL  string `json:"claimUrl"`
	ExpiresAt string `json:"expiresAt"`
}

// pairClaimedResponse is what /pair/poll returns on 200 and what
// /pair/claim returns on the headless path.
type pairClaimedResponse struct {
	TunnelIP     string `json:"tunnelIp"`
	PrivateKey   string `json:"privateKey"`
	ServerPubKey string `json:"serverPubKey"`
	ServerHost   string `json:"serverHost"`
	UserEmail    string `json:"userEmail"`
	DeviceID     string `json:"deviceId,omitempty"`
}

// pairOptions packages everything pair flow callers may want to tweak.
type pairOptions struct {
	ArenaBaseURL string
	ConfigPath   string
	ClientVer    string
	NoBrowser    bool
}

// newHTTPClient builds the shared client used by every pairing call.
// We pin a hard timeout — pair init / claim should be sub-second; poll
// is bounded by pollPerRequestTO via Request context.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpClientTimeout,
	}
}

func userAgent(ver string) string {
	if ver == "" {
		ver = "dev"
	}
	return fmt.Sprintf("arena-byoc/%s (%s/%s)", ver, runtime.GOOS, runtime.GOARCH)
}

// doJSON is a tiny helper for "POST JSON, get JSON or status code".
// It returns the http.Response so callers can branch on .StatusCode and
// drain the body themselves; we only attach the right headers + UA.
func doJSON(ctx context.Context, c *http.Client, method, urlStr, ua string, in any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("marshal: %w", err)
		}
		body = strings.NewReader(string(raw))
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", ua)
	return c.Do(req)
}

// pairInit POSTs to /api/byoc2/pair/init. The SERVER mints the pairing code
// (client-supplied codes are rejected since the v2 lifecycle); we read it back
// from the response and return it for the poll + browser steps.
func pairInit(ctx context.Context, c *http.Client, opts pairOptions) (string, *pairInitResponse, error) {
	hostname, _ := os.Hostname()
	reqBody := pairInitRequest{
		ClientVersion: opts.ClientVer,
		Hostname:      hostname,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
	}

	endpoint, err := joinURL(opts.ArenaBaseURL, "/api/byoc2/pair/init")
	if err != nil {
		return "", nil, err
	}

	resp, err := doJSON(ctx, c, http.MethodPost, endpoint, userAgent(opts.ClientVer), reqBody)
	if err != nil {
		return "", nil, fmt.Errorf("pair/init: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := readSnippet(resp.Body, 512)
		return "", nil, fmt.Errorf("pair/init: HTTP %d: %s", resp.StatusCode, snippet)
	}
	var out pairInitResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", nil, fmt.Errorf("pair/init decode: %w", err)
	}
	if out.Code == "" {
		return "", nil, errors.New("pair/init: server did not return a pairing code")
	}
	return out.Code, &out, nil
}

// joinURL is a tolerant URL joiner. opts.ArenaBaseURL may or may not have
// a trailing slash; the path may or may not have a leading one.
func joinURL(base, path string) (string, error) {
	if base == "" {
		return "", errors.New("empty arena base URL")
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse base: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")
	return u.String(), nil
}

// readSnippet drains up to n bytes for inclusion in an error message.
// Never returns more than n bytes; safe to splice into logs.
func readSnippet(r io.Reader, n int) string {
	buf := make([]byte, n)
	read, _ := io.ReadFull(io.LimitReader(r, int64(n)), buf)
	return strings.TrimSpace(string(buf[:read]))
}

// pairPoll runs the polling loop. On success returns the claimed creds.
// On failure returns an error AND a recommended exit code (one of the
// Exit* constants), so main() can map directly to os.Exit.
func pairPoll(ctx context.Context, c *http.Client, opts pairOptions, code string) (*pairClaimedResponse, int, error) {
	endpoint, err := joinURL(opts.ArenaBaseURL, "/api/byoc2/pair/poll")
	if err != nil {
		return nil, ExitFatalRuntime, err
	}
	// Build once; we just reset the query string each loop iteration.
	pollURL := endpoint + "?code=" + url.QueryEscape(code)
	ua := userAgent(opts.ClientVer)

	deadline := time.Now().Add(pollWallClockMax)
	netFailures := 0

	for {
		if ctx.Err() != nil {
			return nil, ExitSignal, ctx.Err()
		}
		if time.Now().After(deadline) {
			return nil, ExitPairWallClockTimeout,
				errors.New("timed out waiting for authorization (10m wall-clock)")
		}

		// Per-request context so a slow server can't pin the whole poll loop.
		reqCtx, cancel := context.WithTimeout(ctx, pollPerRequestTO)
		resp, err := doJSON(reqCtx, c, http.MethodGet, pollURL, ua, nil)
		cancel()

		if err != nil {
			if isTransientNetErr(err) {
				netFailures++
				if netFailures >= pollNetMaxFailures {
					return nil, ExitNetworkBudgetExceeded,
						fmt.Errorf("network error budget exhausted (%d failures): %w", netFailures, err)
				}
				sleep := backoffFor(netFailures)
				if !sleepCtx(ctx, sleep) {
					return nil, ExitSignal, ctx.Err()
				}
				continue
			}
			return nil, ExitFatalRuntime, fmt.Errorf("pair/poll: %w", err)
		}

		switch resp.StatusCode {
		case http.StatusOK: // 200 — claimed
			var out pairClaimedResponse
			err := json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if err != nil {
				return nil, ExitFatalRuntime, fmt.Errorf("pair/poll decode: %w", err)
			}
			return &out, ExitOK, nil

		case http.StatusAccepted: // 202 — pending
			resp.Body.Close()
			netFailures = 0
			if !sleepCtx(ctx, pollIntervalDefault) {
				return nil, ExitSignal, ctx.Err()
			}
			continue

		case http.StatusGone: // 410 — cancelled in browser
			resp.Body.Close()
			return nil, ExitUserCancelled, errors.New("authorization cancelled in browser")

		case http.StatusNotFound: // 404 — expired / never existed
			resp.Body.Close()
			return nil, ExitExpiredOrNotFound, errors.New("pairing code expired or unknown; re-run to start over")

		default:
			if resp.StatusCode >= 500 && resp.StatusCode < 600 {
				resp.Body.Close()
				netFailures++
				if netFailures >= pollNetMaxFailures {
					return nil, ExitNetworkBudgetExceeded,
						fmt.Errorf("server 5xx budget exhausted at %d", resp.StatusCode)
				}
				sleep := backoffFor(netFailures)
				if !sleepCtx(ctx, sleep) {
					return nil, ExitSignal, ctx.Err()
				}
				continue
			}
			snippet := readSnippet(resp.Body, 256)
			resp.Body.Close()
			return nil, ExitFatalRuntime, fmt.Errorf("pair/poll: unexpected HTTP %d: %s", resp.StatusCode, snippet)
		}
	}
}

// isTransientNetErr is the "should I back off and retry?" predicate.
// Anything in net.Error (including *url.Error wrapping net dial timeouts)
// counts. Context cancellation does NOT — those are handled separately.
func isTransientNetErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	return false
}

// backoffFor returns min(2s * 2^(failures-1), pollNetMaxBackoff).
func backoffFor(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	// Cap shift to avoid overflow on absurd inputs.
	shift := failures - 1
	if shift > 6 {
		shift = 6
	}
	d := pollIntervalDefault << shift
	if d > pollNetMaxBackoff {
		d = pollNetMaxBackoff
	}
	return d
}

// sleepCtx sleeps for d unless ctx is cancelled first. Returns true on
// natural wake, false on cancellation.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// claimByToken is the headless --token short-circuit. Same response
// shape as poll/200, so callers can plug it into the same persist path.
func claimByToken(ctx context.Context, c *http.Client, opts pairOptions, token string) (*pairClaimedResponse, int, error) {
	endpoint, err := joinURL(opts.ArenaBaseURL, "/api/byoc2/pair/claim")
	if err != nil {
		return nil, ExitFatalRuntime, err
	}
	endpoint += "?token=" + url.QueryEscape(token)
	resp, err := doJSON(ctx, c, http.MethodGet, endpoint, userAgent(opts.ClientVer), nil)
	if err != nil {
		return nil, ExitNetworkBudgetExceeded, fmt.Errorf("pair/claim: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var out pairClaimedResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, ExitFatalRuntime, fmt.Errorf("pair/claim decode: %w", err)
		}
		return &out, ExitOK, nil
	case http.StatusNotFound:
		return nil, ExitExpiredOrNotFound, errors.New("token expired or already claimed")
	default:
		snippet := readSnippet(resp.Body, 256)
		return nil, ExitFatalRuntime, fmt.Errorf("pair/claim: HTTP %d: %s", resp.StatusCode, snippet)
	}
}

// openBrowser tries to spawn the platform-default browser, detached.
// Failure is signalled by error return; callers should treat that as
// non-fatal and just print the URL.
//
// Special cases:
//   - SSH session (SSH_CONNECTION / SSH_CLIENT set): refuse, force print-only.
//   - linux with no DISPLAY and no WAYLAND_DISPLAY: refuse.
//   - WSL (uname -r contains "microsoft"): prefer wslview if present.
func openBrowser(rawurl string) error {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_CLIENT") != "" {
		return errors.New("SSH session detected")
	}

	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd", "netbsd":
		if runtime.GOOS == "linux" {
			if isWSL() {
				return openBrowserWSL(rawurl)
			}
			if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
				return errors.New("no DISPLAY/WAYLAND_DISPLAY")
			}
		}
		return spawnDetached(exec.Command("xdg-open", rawurl))
	case "darwin":
		return spawnDetached(exec.Command("open", rawurl))
	case "windows":
		// `start` is a cmd.exe builtin; the empty quoted "" is the
		// window title placeholder so URLs with spaces parse correctly.
		return spawnDetached(exec.Command("cmd", "/c", "start", "", rawurl))
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func spawnDetached(cmd *exec.Cmd) error {
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap async so we don't leave a zombie around.
	go func() { _ = cmd.Wait() }()
	return nil
}

// isWSL detects WSL by reading /proc/sys/kernel/osrelease and checking
// for "microsoft" (case-insensitive). Cheaper + more reliable than
// shelling out to `uname -r`.
func isWSL() bool {
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(raw)), "microsoft")
}

// openBrowserWSL prefers wslview (part of wslu); if absent, falls back
// to invoking the Windows-side `cmd.exe /c start` via interop, which
// works on WSL2 by default.
func openBrowserWSL(rawurl string) error {
	if path, err := exec.LookPath("wslview"); err == nil {
		return spawnDetached(exec.Command(path, rawurl))
	}
	if path, err := exec.LookPath("cmd.exe"); err == nil {
		return spawnDetached(exec.Command(path, "/c", "start", "", rawurl))
	}
	return errors.New("no wslview or cmd.exe on PATH")
}

// PairAndPersist orchestrates the full PAIR flow:
//   init → print code + URL → openBrowser → poll → SaveConfig.
// Returns the new Config (also written to disk) and a recommended exit
// code. The exit code is only meaningful when err != nil.
func PairAndPersist(ctx context.Context, opts pairOptions) (*Config, int, error) {
	c := newHTTPClient()
	code, initRes, err := pairInit(ctx, c, opts)
	if err != nil {
		return nil, ExitPairInitFailed, err
	}

	// Prefer the server-supplied claimUrl (relative, e.g. "/byoc2/connect?code=…");
	// otherwise build one from the base URL + the minted code. Either way the
	// code is the server's, not a client invention.
	authURL := ""
	if initRes.ClaimURL != "" {
		if base, perr := url.Parse(opts.ArenaBaseURL); perr == nil {
			if ref, rerr := url.Parse(initRes.ClaimURL); rerr == nil {
				authURL = base.ResolveReference(ref).String()
			}
		}
	}
	if authURL == "" {
		if u, jerr := joinURL(opts.ArenaBaseURL, "/byoc2/connect"); jerr == nil {
			authURL = u + "?code=" + url.QueryEscape(code)
		}
	}

	fmt.Println()
	fmt.Println("====================================================")
	fmt.Println("  Arena BYOC2 — Pair this device")
	fmt.Println("====================================================")
	fmt.Printf("  Code:    %s\n", code)
	fmt.Printf("  URL:     %s\n", authURL)
	fmt.Println("  Open the URL in your browser, sign in, and click")
	fmt.Println("  'Authorize this device' to continue.")
	fmt.Println("====================================================")
	fmt.Println()

	if !opts.NoBrowser {
		if err := openBrowser(authURL); err != nil {
			fmt.Fprintf(os.Stderr, "[info] could not auto-open browser (%v) — paste the URL above\n", err)
		}
	}

	claimed, exitCode, err := pairPoll(ctx, c, opts, code)
	if err != nil {
		return nil, exitCode, err
	}

	cfg := &Config{
		Version:      ConfigSchemaVersion,
		TunnelIP:     claimed.TunnelIP,
		PrivateKey:   claimed.PrivateKey,
		ServerPubKey: claimed.ServerPubKey,
		ServerHost:   claimed.ServerHost,
		UserEmail:    claimed.UserEmail,
		PairedAt:     time.Now().UTC().Format(time.RFC3339),
		ArenaBaseURL: opts.ArenaBaseURL,
		DeviceID:     claimed.DeviceID,
	}

	if err := SaveConfig(opts.ConfigPath, cfg); err != nil {
		// Non-fatal: connect anyway, just warn that next launch will re-pair.
		fmt.Fprintf(os.Stderr, "[warn] failed to persist config to %s: %v\n", opts.ConfigPath, err)
		fmt.Fprintln(os.Stderr, "[warn] tunnel will come up but you'll need to re-pair next launch.")
	} else {
		fmt.Printf("[+] paired as %s (tunnel ip %s); config saved to %s\n",
			cfg.UserEmail, cfg.TunnelIP, opts.ConfigPath)
	}
	return cfg, ExitOK, nil
}
