package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// c2StateSlotView mirrors the relevant subset of Byoc2C2View returned by
// GET /api/users/me/c2-state. Only fields we display are declared.
type c2StateSlotView struct {
	TunnelIp    string `json:"tunnelIp"`
	CoverDomain string `json:"coverDomain"`
	RedirectorSlots []struct {
		IpAddress *string `json:"ipAddress"`
		SniHost   string  `json:"sniHost"`
		IsPrimary bool    `json:"isPrimary"`
		Status    string  `json:"status"`
	} `json:"redirectorSlots"`
	ListenerConfig *struct {
		BindIp          string `json:"bindIp"`
		BindPort        int    `json:"bindPort"`
		HmacCookieName  string `json:"hmacCookieName"`
		HmacCookieValue string `json:"hmacCookieValue"`
	} `json:"listenerConfig"`
}

// fetchC2Slot calls /api/users/me/c2-state with the stored revocation token
// and returns the byoc2 sub-object. Returns nil when unavailable (no token,
// unreachable server, revoked peer) — callers treat nil as "no banner".
func fetchC2Slot(ctx context.Context, cfg *Config) *c2StateSlotView {
	if cfg.ArenaBaseURL == "" || cfg.RevocationToken == "" {
		return nil
	}
	endpoint, err := joinURL(cfg.ArenaBaseURL, "/api/users/me/c2-state")
	if err != nil {
		return nil
	}
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+cfg.RevocationToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent(version))
	resp, err := newHTTPClient().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	var body struct {
		Byoc2 *c2StateSlotView `json:"byoc2"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	return body.Byoc2
}

const bannerWidth = 62

func bannerLine(left, right string) string {
	content := fmt.Sprintf("  %-18s %s", left, right)
	if len(content) > bannerWidth {
		content = content[:bannerWidth]
	}
	return fmt.Sprintf("│%-*s│", bannerWidth, content)
}

func bannerFull(text string) string {
	content := "  " + text
	if len(content) > bannerWidth {
		content = content[:bannerWidth]
	}
	return fmt.Sprintf("│%-*s│", bannerWidth, content)
}

func bannerSep() string {
	return "├" + strings.Repeat("─", bannerWidth) + "┤"
}

// printC2Banner fetches slot info from the arena API and prints a formatted
// connection summary to stdout. Non-fatal — if the fetch fails we skip silently.
func printC2Banner(ctx context.Context, cfg *Config) {
	slot := fetchC2Slot(ctx, cfg)
	if slot == nil {
		return
	}

	var edgeIp, sniHost string
	for _, s := range slot.RedirectorSlots {
		if s.IsPrimary {
			if s.IpAddress != nil {
				edgeIp = *s.IpAddress
			}
			sniHost = s.SniHost
			break
		}
	}
	if sniHost == "" {
		sniHost = slot.CoverDomain
	}

	top := "┌" + strings.Repeat("─", bannerWidth) + "┐"
	bot := "└" + strings.Repeat("─", bannerWidth) + "┘"

	fmt.Println()
	fmt.Println(top)
	fmt.Println(bannerFull("ARENA BYOC2 // SLOT ACTIVO"))
	fmt.Println(bannerSep())
	fmt.Println(bannerLine("TUNNEL IP", slot.TunnelIp))
	if edgeIp != "" {
		fmt.Println(bannerLine("EDGE IP", edgeIp))
	}
	if slot.ListenerConfig != nil {
		fmt.Println(bannerSep())
		fmt.Println(bannerFull("// LISTENER CONFIG"))
		fmt.Println(bannerLine("BIND IP", slot.ListenerConfig.BindIp))
		fmt.Println(bannerLine("PORT", fmt.Sprintf("%d", slot.ListenerConfig.BindPort)))
	}
	if sniHost != "" {
		fmt.Println(bannerSep())
		fmt.Println(bannerFull("// SNI / COBERTURA"))
		fmt.Println(bannerFull(sniHost))
	}
	if slot.ListenerConfig != nil && slot.ListenerConfig.HmacCookieName != "" {
		fmt.Println(bannerSep())
		fmt.Println(bannerFull("// HMAC COOKIE"))
		fmt.Println(bannerLine("nombre", slot.ListenerConfig.HmacCookieName))
		fmt.Println(bannerLine("valor", slot.ListenerConfig.HmacCookieValue))
	}
	fmt.Println(bot)
	fmt.Println()
}