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
	TunnelIp        string `json:"tunnelIp"`
	CoverDomain     string `json:"coverDomain"`
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

type c2StateView struct {
	Mode    string `json:"mode"`
	Managed *struct {
		C2 *struct {
			IPAddress string `json:"ipAddress"`
			Framework string `json:"framework"`
			Status    string `json:"status"`
		} `json:"c2"`
		Operator *struct {
			ID string `json:"id"`
		} `json:"operator"`
	} `json:"managed"`
	Byoc2 *c2StateSlotView `json:"byoc2"`
}

// fetchC2State calls /api/users/me/c2-state with the stored revocation token
// and returns the managed + tunnel subsets needed by the banner. It returns
// nil when unavailable; callers treat that as a non-fatal "no banner" state.
func fetchC2State(ctx context.Context, cfg *Config) *c2StateView {
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
	var body c2StateView
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	if body.Byoc2 == nil {
		return nil
	}
	return &body
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

func renderC2Banner(state *c2StateView) string {
	if state == nil || state.Byoc2 == nil {
		return ""
	}
	slot := state.Byoc2

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

	remoteOperator := state.Managed != nil &&
		state.Managed.C2 != nil &&
		strings.EqualFold(state.Managed.C2.Framework, "adaptix") &&
		state.Managed.Operator == nil

	var out strings.Builder
	fmt.Fprintln(&out, top)
	if remoteOperator {
		fmt.Fprintln(&out, bannerFull("ARENA // REMOTE OPERATOR"))
	} else {
		fmt.Fprintln(&out, bannerFull("ARENA TUNNEL // PEER ACTIVO"))
	}
	fmt.Fprintln(&out, bannerSep())
	fmt.Fprintln(&out, bannerLine("TUNNEL IP", slot.TunnelIp))
	if remoteOperator {
		teamserverIP := strings.Split(state.Managed.C2.IPAddress, "/")[0]
		fmt.Fprintln(&out, bannerSep())
		fmt.Fprintln(&out, bannerFull("// ADAPTIX TEAMSERVER ADMINISTRADO"))
		fmt.Fprintln(&out, bannerLine("CONTROL", teamserverIP+":4321/adaptix-ts"))
		fmt.Fprintln(&out, bannerLine("LISTENER", "arena-https (Arena)"))
	}
	if edgeIp != "" {
		fmt.Fprintln(&out, bannerLine("EDGE IP", edgeIp))
	}
	if !remoteOperator && slot.ListenerConfig != nil {
		fmt.Fprintln(&out, bannerSep())
		fmt.Fprintln(&out, bannerFull("// LISTENER CONFIG"))
		fmt.Fprintln(&out, bannerLine("BIND IP", slot.ListenerConfig.BindIp))
		fmt.Fprintln(&out, bannerLine("PORT", fmt.Sprintf("%d", slot.ListenerConfig.BindPort)))
	}
	if sniHost != "" {
		fmt.Fprintln(&out, bannerSep())
		fmt.Fprintln(&out, bannerFull("// SNI / COBERTURA"))
		fmt.Fprintln(&out, bannerFull(sniHost))
	}
	if !remoteOperator && slot.ListenerConfig != nil && slot.ListenerConfig.HmacCookieName != "" {
		fmt.Fprintln(&out, bannerSep())
		fmt.Fprintln(&out, bannerFull("// HMAC COOKIE"))
		fmt.Fprintln(&out, bannerLine("nombre", slot.ListenerConfig.HmacCookieName))
		fmt.Fprintln(&out, bannerLine("valor", slot.ListenerConfig.HmacCookieValue))
	}
	fmt.Fprintln(&out, bot)
	return out.String()
}

// printC2Banner fetches slot info from the arena API and prints a formatted
// connection summary to stdout. Non-fatal — if the fetch fails we skip silently.
func printC2Banner(ctx context.Context, cfg *Config) {
	state := fetchC2State(ctx, cfg)
	if rendered := renderC2Banner(state); rendered != "" {
		fmt.Printf("\n%s\n", rendered)
	}
}
