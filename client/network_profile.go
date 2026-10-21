package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"sort"
	"time"
)

const arenaResolverIP = "10.130.50.254"

type networkRoute struct {
	CIDR         string `json:"cidr"`
	Kind         string `json:"kind"`
	DeploymentID string `json:"deploymentId,omitempty"`
}

type networkDNS struct {
	Servers  []string `json:"servers"`
	RouteAll bool     `json:"routeAll"`
}

type networkProfile struct {
	Version int            `json:"version"`
	Routes  []networkRoute `json:"routes"`
	DNS     networkDNS     `json:"dns"`
}

func fetchNetworkProfile(ctx context.Context, cfg *Config) (*networkProfile, error) {
	if cfg.ArenaBaseURL == "" || cfg.RevocationToken == "" {
		return nil, fmt.Errorf("missing Arena URL or pairing token; run `arena-tunnel pair --force`")
	}
	endpoint, err := joinURL(cfg.ArenaBaseURL, "/api/users/me/c2-state")
	if err != nil {
		return nil, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.RevocationToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent(version))
	resp, err := newHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Arena network profile HTTP %d", resp.StatusCode)
	}
	var body struct {
		NetworkProfile *networkProfile `json:"networkProfile"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if body.NetworkProfile == nil {
		return nil, fmt.Errorf("Arena did not issue an active network profile")
	}
	if err := validateNetworkProfile(body.NetworkProfile); err != nil {
		return nil, fmt.Errorf("refusing unsafe Arena network profile: %w", err)
	}
	return body.NetworkProfile, nil
}

func validateNetworkProfile(profile *networkProfile) error {
	if profile == nil || profile.Version != 1 {
		return fmt.Errorf("unsupported profile version")
	}
	if len(profile.Routes) == 0 || len(profile.Routes) > 64 {
		return fmt.Errorf("invalid route count %d", len(profile.Routes))
	}
	scenarioRange := netip.MustParsePrefix("10.128.0.0/16")
	teamserverRange := netip.MustParsePrefix("10.130.50.0/24")
	resolverRoute := netip.MustParsePrefix(arenaResolverIP + "/32")
	seen := make(map[string]struct{}, len(profile.Routes))
	hasResolverRoute := false
	for _, route := range profile.Routes {
		prefix, err := netip.ParsePrefix(route.CIDR)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return fmt.Errorf("invalid or non-canonical route %q", route.CIDR)
		}
		if _, exists := seen[prefix.String()]; exists {
			return fmt.Errorf("duplicate route %s", prefix)
		}
		seen[prefix.String()] = struct{}{}
		switch route.Kind {
		case "scenario":
			if prefix.Bits() < scenarioRange.Bits() || !scenarioRange.Contains(prefix.Addr()) {
				return fmt.Errorf("scenario route outside approved range: %s", prefix)
			}
		case "teamserver":
			if prefix.Bits() != 32 || !teamserverRange.Contains(prefix.Addr()) || prefix.Addr().String() == arenaResolverIP {
				return fmt.Errorf("invalid TeamServer route: %s", prefix)
			}
		case "resolver":
			if prefix != resolverRoute {
				return fmt.Errorf("invalid resolver route: %s", prefix)
			}
			hasResolverRoute = true
		default:
			return fmt.Errorf("unknown route kind %q", route.Kind)
		}
	}
	if !hasResolverRoute || !profile.DNS.RouteAll || len(profile.DNS.Servers) != 1 || profile.DNS.Servers[0] != arenaResolverIP {
		return fmt.Errorf("DNS must use only the authorized Arena resolver")
	}
	return nil
}

func networkProfileRouteCIDRs(profile *networkProfile) []string {
	routes := make([]string, 0, len(profile.Routes))
	for _, route := range profile.Routes {
		routes = append(routes, route.CIDR)
	}
	sort.Strings(routes)
	return routes
}

func networkRouteSet(profile *networkProfile) map[string]struct{} {
	out := make(map[string]struct{}, len(profile.Routes))
	for _, route := range networkProfileRouteCIDRs(profile) {
		out[route] = struct{}{}
	}
	return out
}

func networkProfilesEqual(a, b *networkProfile) bool {
	return reflect.DeepEqual(a, b)
}
