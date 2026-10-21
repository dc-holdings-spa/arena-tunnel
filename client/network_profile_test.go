package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func validNetworkProfile() *networkProfile {
	return &networkProfile{
		Version: 1,
		Routes: []networkRoute{
			{CIDR: "10.128.42.0/24", Kind: "scenario", DeploymentID: "dep-nightfall"},
			{CIDR: "10.130.50.31/32", Kind: "teamserver"},
			{CIDR: "10.130.50.254/32", Kind: "resolver"},
		},
		DNS: networkDNS{Servers: []string{arenaResolverIP}, RouteAll: true},
	}
}

func TestValidateNetworkProfile(t *testing.T) {
	if err := validateNetworkProfile(validNetworkProfile()); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}

	cases := map[string]func(*networkProfile){
		"broad route":            func(p *networkProfile) { p.Routes[0].CIDR = "10.128.0.0/9" },
		"foreign private route":  func(p *networkProfile) { p.Routes[0].CIDR = "10.131.0.0/16" },
		"non canonical route":    func(p *networkProfile) { p.Routes[0].CIDR = "10.128.42.17/24" },
		"wrong TeamServer":       func(p *networkProfile) { p.Routes[1].CIDR = "10.130.60.31/32" },
		"wrong DNS":              func(p *networkProfile) { p.DNS.Servers = []string{"8.8.8.8"} },
		"missing resolver route": func(p *networkProfile) { p.Routes = p.Routes[:2] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			profile := validNetworkProfile()
			mutate(profile)
			if err := validateNetworkProfile(profile); err == nil {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
}

func TestFetchNetworkProfileUsesBearerAndRejectsMissingProfile(t *testing.T) {
	var gotAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{"networkProfile": validNetworkProfile()})
	}))
	defer server.Close()

	profile, err := fetchNetworkProfile(context.Background(), &Config{
		ArenaBaseURL:    server.URL,
		RevocationToken: "secret-token",
	})
	if err != nil {
		t.Fatalf("fetchNetworkProfile: %v", err)
	}
	if gotAuthorization != "Bearer secret-token" || profile.Version != 1 {
		t.Fatalf("unexpected auth/profile: %q %#v", gotAuthorization, profile)
	}

	emptyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"networkProfile": nil})
	}))
	defer emptyServer.Close()
	if _, err := fetchNetworkProfile(context.Background(), &Config{
		ArenaBaseURL:    emptyServer.URL,
		RevocationToken: "secret-token",
	}); err == nil {
		t.Fatal("missing profile must fail closed")
	}
}
