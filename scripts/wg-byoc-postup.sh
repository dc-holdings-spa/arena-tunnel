#!/bin/bash
# wg-byoc PostUp hook — strict firewall for student BYO-C2 tunnel.
#
# Goal: allow wg-byoc clients to reach scenario + ops networks
# (10.128.0.0/9) only. Block all access to management networks
# (192.168.1.0/24 manager/runner/OPNsense/prism-server, 10.130.0.0/16),
# and block lateral P2P between students (wg-byoc -> wg-byoc).
#
# Idempotent: removes any pre-existing rules with the same shape before
# adding, so re-running it on a partially-applied state is safe.
#
# Invoked from /etc/wireguard/wg-byoc.conf PostUp.
# Mirror lives in /tmp/arena-tunnel/scripts/ (public repo) — keep in sync.
#
# ---------------------------------------------------------------------------
# IMPORTANT: NO NAT / MASQUERADE here. PURE FORWARDING ONLY.
# ---------------------------------------------------------------------------
# Earlier versions of this script MASQUERADEd 10.201.0.X -> 192.168.1.10
# so OPNsense (the next hop towards scenarios) would see a single
# in-scope source. That broke EVERYTHING attribution-related:
#
#   * Scenarios saw one IP for all BYOC2 students -> per-student OPSEC dies.
#   * OpsecAlert cascade (SNI > cookie > WG tunnel IP > destination > source >
#     sole-enrolled, see lib/opsec/alert-processor.ts) collapsed to the last
#     two steps for BYOC2 traffic.
#   * Detection CMS filter by student, Blue Team bot DMs, achievement unlocks,
#     and engagement-report PDFs all misattributed to the wrong student.
#
# Fix: keep the WG tunnel source IP (10.201.0.X) end-to-end. arena-manager
# routes the packet to OPNsense (192.168.1.80); a static route 10.201.0.0/24
# -> 192.168.1.10 on OPNsense (managed by lib/firewall/opnsense.ts
# ensureByoc2RoutingAndRules) ensures the return path. Scenarios now see
# the real per-student source IP and the cascade works as designed.
#
# net.ipv4.ip_forward=1 must be enabled on this host (sysctl). The kernel
# does the forwarding for us; we only police it with the FORWARD rules
# below.
# ---------------------------------------------------------------------------

set -euo pipefail

IFACE="${1:-wg-byoc}"

# Public-ish networks reachable from the manager that students MUST NOT touch.
MGMT_NETS=(
  "192.168.1.0/24"   # manager (.10), runner (.20), OPNsense (.80), prism-server (.220)
  "10.130.0.0/16"    # management VLANs (PRISM, internal services)
)

# Networks students ARE allowed to reach (scenarios + ops VLANs).
ALLOWED_NETS=(
  "10.128.0.0/9"
)

# --- Helpers -----------------------------------------------------------------

# Run iptables idempotently: delete the rule first (ignore errors), then add.
ipt_replace() {
  iptables -D "$@" 2>/dev/null || true
  iptables -A "$@"
}

ipt_replace_insert() {
  # Same as above but inserts at the top of the chain (priority).
  iptables -D "$@" 2>/dev/null || true
  iptables -I "$@"
}

# --- 0. Scrub any legacy MASQUERADE rules from prior versions ----------------
# Belt-and-braces: if this host was running an older postup that installed
# NAT, sweep those rules out so a partial upgrade can't leave traffic being
# silently rewritten. Safe to run on a clean host (no-ops if nothing matches).
EXT_IFACE="${EXT_IFACE:-eth0}"
for net in "${ALLOWED_NETS[@]}"; do
  iptables -t nat -D POSTROUTING -s 10.201.0.0/24 -d "$net" -o "$EXT_IFACE" -j MASQUERADE 2>/dev/null || true
done

# --- 1. Block wg-byoc -> wg-byoc (student P2P) -------------------------------
# Must be the FIRST rule on FORWARD so it takes precedence over allows.
ipt_replace_insert FORWARD -i "$IFACE" -o "$IFACE" -j DROP

# --- 2. Block wg-byoc -> management networks ---------------------------------
# Inserted high in the chain so they fire before the allow rule below.
for net in "${MGMT_NETS[@]}"; do
  ipt_replace_insert FORWARD -i "$IFACE" -d "$net" -j DROP
done

# --- 3. Allow wg-byoc -> scenario/ops networks -------------------------------
for net in "${ALLOWED_NETS[@]}"; do
  ipt_replace FORWARD -i "$IFACE" -d "$net" -j ACCEPT
done

# --- 4. Allow return traffic (established/related) ---------------------------
ipt_replace FORWARD -o "$IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# --- 5. Allow scenarios -> WG clients (return path for BYOC2 beacons) -------
# The return route 10.201.0.0/24 -> 192.168.1.10 on OPNsense lands packets
# on this host's WAN-facing iface; we have to forward them out wg-byoc.
# Without this rule the kernel default-policy on FORWARD drops them and CS
# beacons hang. statetype=NEW is fine because conntrack rule above catches
# subsequent packets.
for net in "${ALLOWED_NETS[@]}"; do
  ipt_replace FORWARD -s "$net" -o "$IFACE" -j ACCEPT
done

# --- 6. Default-deny for the interface ---------------------------------------
# Anything wg-byoc -> not-allowed-net falls through to this.
ipt_replace FORWARD -i "$IFACE" -j DROP

exit 0
