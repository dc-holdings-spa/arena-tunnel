package main

import (
	"strings"
	"testing"
)

func TestRenderRemoteOperatorBanner(t *testing.T) {
	state := &c2StateView{Byoc2: &c2StateSlotView{
		TunnelIp:    "10.201.0.44",
		CoverDomain: "student.r.adversario.cl",
	}}
	state.Managed = &struct {
		C2 *struct {
			IPAddress string `json:"ipAddress"`
			Framework string `json:"framework"`
			Status    string `json:"status"`
		} `json:"c2"`
		Operator *struct {
			ID string `json:"id"`
		} `json:"operator"`
	}{}
	state.Managed.C2 = &struct {
		IPAddress string `json:"ipAddress"`
		Framework string `json:"framework"`
		Status    string `json:"status"`
	}{IPAddress: "10.130.50.111/24", Framework: "adaptix", Status: "active"}

	rendered := renderC2Banner(state)
	for _, expected := range []string{
		"ARENA // REMOTE OPERATOR",
		"10.130.50.111:4321/adaptix-ts",
		"arena-https (Arena)",
		"student.r.adversario.cl",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("banner missing %q:\n%s", expected, rendered)
		}
	}
	for _, forbidden := range []string{"BYOC2", "HMAC COOKIE", "BIND IP"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("Remote Operator banner contains legacy %q:\n%s", forbidden, rendered)
		}
	}
}

func TestRenderLegacyTunnelBanner(t *testing.T) {
	state := &c2StateView{Byoc2: &c2StateSlotView{
		TunnelIp: "10.201.0.55",
		ListenerConfig: &struct {
			BindIp          string `json:"bindIp"`
			BindPort        int    `json:"bindPort"`
			HmacCookieName  string `json:"hmacCookieName"`
			HmacCookieValue string `json:"hmacCookieValue"`
		}{BindIp: "10.201.0.55", BindPort: 443, HmacCookieName: "cookie", HmacCookieValue: "value"},
	}}
	rendered := renderC2Banner(state)
	if !strings.Contains(rendered, "ARENA TUNNEL // PEER ACTIVO") ||
		!strings.Contains(rendered, "HMAC COOKIE") {
		t.Fatalf("legacy banner lost compatibility:\n%s", rendered)
	}
}
