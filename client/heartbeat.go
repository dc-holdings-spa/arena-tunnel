package main

// Kill-switch heartbeat.
//
// Sprint 7 T1. POSTs the client's kill-switch status to the RTaaS
// server every 60s while the tunnel is up. Payload matches the
// server-side reader (`apps/arena-manager/lib/byoc2/kill-switch-cache.ts`)
// + endpoint (`POST /api/byoc2/kill-switch-heartbeat`).
//
// Best-effort — a hiccup logs and moves on; the chip on the server
// side ages out to `armed: false` after the 90s TTL if we truly can't
// reach the server.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const (
	heartbeatInterval = 60 * time.Second
	heartbeatTimeout  = 5 * time.Second
)

type heartbeatPayload struct {
	PeerID              string `json:"peerId"`
	KillSwitchArmed     bool   `json:"killSwitchArmed"`
	KillSwitchInstallAt string `json:"killSwitchInstalledAt,omitempty"`
}

// startHeartbeat launches a goroutine that posts to the RTaaS server
// every 60s until ctx is cancelled. Should be called AFTER the tunnel
// is up and either after installKillSwitch succeeds (armed=true) or
// after the caller opts out via -kill-switch=false (armed=false).
func startHeartbeat(ctx context.Context, arenaBaseURL, peerID, agentToken string, armed bool) {
	installedAt := time.Now().UTC().Format(time.RFC3339)
	url := arenaBaseURL + "/api/byoc2/kill-switch-heartbeat"

	go func() {
		client := &http.Client{Timeout: heartbeatTimeout}
		post := func() {
			body, err := json.Marshal(heartbeatPayload{
				PeerID:              peerID,
				KillSwitchArmed:     armed,
				KillSwitchInstallAt: installedAt,
			})
			if err != nil {
				return
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+agentToken)
			resp, err := client.Do(req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[heartbeat] post failed: %v\n", err)
				return
			}
			_ = resp.Body.Close()
		}

		post()
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				post()
			}
		}
	}()
}
