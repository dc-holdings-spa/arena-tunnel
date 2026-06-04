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

# Outbound interface for NAT (toward scenario VLANs via OPNsense .80).
EXT_IFACE="${EXT_IFACE:-eth0}"

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

# --- 5. Default-deny for the interface ---------------------------------------
# Anything wg-byoc -> not-allowed-net falls through to this.
ipt_replace FORWARD -i "$IFACE" -j DROP

# --- 6. NAT (MASQUERADE) only for allowed scenario traffic out eth0 ----------
# Scoped to the allowed nets — we do NOT MASQUERADE arbitrary destinations.
for net in "${ALLOWED_NETS[@]}"; do
  iptables -t nat -D POSTROUTING -s 10.201.0.0/24 -d "$net" -o "$EXT_IFACE" -j MASQUERADE 2>/dev/null || true
  iptables -t nat -A POSTROUTING -s 10.201.0.0/24 -d "$net" -o "$EXT_IFACE" -j MASQUERADE
done

exit 0
