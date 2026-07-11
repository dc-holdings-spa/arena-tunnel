//go:build windows

package main

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// configureTUN drives the wintun adapter's IP + routes through the NDIS
// LUID exposed by wireguard-go's NativeTun. netsh / Get-NetAdapter can't
// see a wintun adapter — it's owned by the calling process, not
// registered as a normal Windows connection — so external tools noop
// silently. winipcfg talks to iphlpapi.dll directly and matches how the
// official WireGuard for Windows client configures its own tunnels.
//
// The /16 mask mirrors the Linux impl: the tunnel pool (10.201.0.0/16)
// is on-link, so the server gateway 10.201.0.1 is reachable no matter
// which /24 the client landed in.
func configureTUN(tdev tun.Device, ipStr string) error {
	nt, ok := tdev.(*tun.NativeTun)
	if !ok {
		return fmt.Errorf("configureTUN: expected *tun.NativeTun, got %T", tdev)
	}
	luid := winipcfg.LUID(nt.LUID())

	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return fmt.Errorf("parse tunnel ip %q: %w", ipStr, err)
	}
	prefix := netip.PrefixFrom(ip, 16)
	routes := make([]*winipcfg.RouteData, 0, len(pushRoutes))
	for _, r := range pushRoutes {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			log.Printf("[route] skip bad prefix %s: %v", r, err)
			continue
		}
		// NextHop 0.0.0.0 = on-link route (routed via interface directly,
		// no gateway). Matches wireguard-windows tunnel/addressconfig.go.
		routes = append(routes, &winipcfg.RouteData{
			Destination: p,
			NextHop:     netip.IPv4Unspecified(),
			Metric:      0,
		})
	}

	// Config order mirrors wireguard-windows tunnel/addressconfig.go:
	//   1. SetRoutesForFamily
	//   2. SetIPAddressesForFamily  (retry if it collides with a leftover
	//      IP from a previous run that never got flushed)
	//   3. IPInterface(family) → tweak flags → Set() — this last Set()
	//      is what actually activates the IPv4 binding on the adapter;
	//      without it the address is registered but not "connected" and
	//      packets never route through it.
	// Each of those calls can return ERROR_NOT_FOUND right after adapter
	// creation while the NDIS layer is still wiring up — retry the whole
	// block up to 15 times with a 1 s backoff.
	const maxAttempts = 15
	var configErr error
retryLoop:
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			log.Printf("[tun] retry %d/%d after: %v", attempt, maxAttempts, configErr)
			time.Sleep(time.Second)
		}

		// AddRoute one-by-one instead of SetRoutesForFamily. Reasons:
		//   - SetRoutesForFamily flushes first, which nukes any route
		//     the caller may already depend on if we ever retry;
		//   - a leftover route from a previous run comes back as
		//     ERROR_OBJECT_ALREADY_EXISTS, which we can treat as a
		//     no-op instead of aborting the batch.
		var routeErr error
		for _, rd := range routes {
			err := luid.AddRoute(rd.Destination, rd.NextHop, rd.Metric)
			if err == nil || err == windows.ERROR_OBJECT_ALREADY_EXISTS {
				continue
			}
			routeErr = fmt.Errorf("add route %s: %w", rd.Destination, err)
			break
		}
		if routeErr != nil {
			configErr = routeErr
			if errors.Is(routeErr, windows.ERROR_NOT_FOUND) {
				continue
			}
			return configErr
		}

		addrs := []netip.Prefix{prefix}
		err := luid.SetIPAddressesForFamily(windows.AF_INET, addrs)
		if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
			// Old IP still bound from a previous run — flush and retry.
			_ = luid.FlushIPAddresses(windows.AF_INET)
			err = luid.SetIPAddressesForFamily(windows.AF_INET, addrs)
		}
		if err != nil {
			configErr = fmt.Errorf("set ip address: %w", err)
			if err == windows.ERROR_NOT_FOUND {
				continue
			}
			return configErr
		}

		ipif, err := luid.IPInterface(windows.AF_INET)
		if err != nil {
			configErr = fmt.Errorf("get ip interface: %w", err)
			if err == windows.ERROR_NOT_FOUND {
				continue
			}
			return configErr
		}
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		if err := ipif.Set(); err != nil {
			configErr = fmt.Errorf("activate ip interface: %w", err)
			if err == windows.ERROR_NOT_FOUND {
				continue
			}
			return configErr
		}

		configErr = nil
		break retryLoop
	}
	if configErr != nil {
		return fmt.Errorf("configure interface: %w", configErr)
	}

	for _, r := range pushRoutes {
		log.Printf("[route] %s via %s", r, tunnelName)
	}
	return nil
}

// teardownTUN flushes IPs + routes. Wintun tears the adapter down when
// the owning process exits, so this is best-effort cleanup for the
// long-running -no-browser path where the process may re-enter its
// connect loop without exiting.
func teardownTUN(tdev tun.Device) {
	nt, ok := tdev.(*tun.NativeTun)
	if !ok {
		return
	}
	luid := winipcfg.LUID(nt.LUID())
	_ = luid.FlushRoutes(windows.AF_INET)
	_ = luid.FlushIPAddresses(windows.AF_INET)
}
