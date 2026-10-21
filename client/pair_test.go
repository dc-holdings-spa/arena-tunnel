package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPairPollKeepsRequestContextAliveWhileReadingReadyResponse(t *testing.T) {
	want := pairClaimedResponse{
		TunnelIP:     "10.201.0.5",
		PrivateKey:   "private-key",
		ServerPubKey: "server-public-key",
		ServerHost:   "wg-byoc.adversario.cl",
		UserEmail:    "student@example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		// Model a real HTTP/2 response where headers arrive before the JSON
		// body. Cancelling the request immediately after Client.Do returns
		// makes the subsequent decoder fail with context.Canceled.
		time.Sleep(25 * time.Millisecond)
		if err := json.NewEncoder(w).Encode(want); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer server.Close()

	got, exitCode, err := pairPoll(context.Background(), server.Client(), pairOptions{
		ArenaBaseURL: server.URL,
		ClientVer:    "test",
	}, "HAQQBW")
	if err != nil {
		t.Fatalf("pairPoll returned error: %v", err)
	}
	if exitCode != ExitOK {
		t.Fatalf("exit code = %d, want %d", exitCode, ExitOK)
	}
	if got == nil || got.TunnelIP != want.TunnelIP || got.ServerHost != want.ServerHost {
		t.Fatalf("pairPoll response = %#v, want tunnel IP %q and host %q", got, want.TunnelIP, want.ServerHost)
	}
}
