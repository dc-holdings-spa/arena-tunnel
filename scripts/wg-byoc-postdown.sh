#!/bin/bash
# wg-byoc PostDown hook — tear down the rules wg-byoc-postup.sh created.
#
# Best-effort: each delete is wrapped so a missing rule doesn't abort the
# whole cleanup. wg-quick down should never fail because of leftover state.
#
# Invoked from /etc/wireguard/wg-byoc.conf PostDown.
# Mirror lives in /tmp/arena-tunnel/scripts/ (public repo) — keep in sync.
#
# NOTE: NAT/MASQUERADE was REMOVED from postup (see comment block in
# wg-byoc-postup.sh). We still try to delete the legacy NAT rule here so
# `wg-quick down && wg-quick up` cleanly migrates an older host to the
# new pure-forwarding model without leaving the rewrite rule behind.

set -u

IFACE="${1:-wg-byoc}"

MGMT_NETS=(
  "192.168.1.0/24"
  "10.130.0.0/16"
)

ALLOWED_NETS=(
  "10.128.0.0/9"
)

EXT_IFACE="${EXT_IFACE:-eth0}"

ipt_del() {
  iptables -D "$@" 2>/dev/null || true
}

# Mirror of postup, in reverse order.

# Legacy NAT (removed in current postup, but still try to clean up an
# older deployment that may have it loaded).
for net in "${ALLOWED_NETS[@]}"; do
  iptables -t nat -D POSTROUTING -s 10.201.0.0/24 -d "$net" -o "$EXT_IFACE" -j MASQUERADE 2>/dev/null || true
done

# 6. Default-deny
ipt_del FORWARD -i "$IFACE" -j DROP

# 5. Scenarios -> WG clients return-path
for net in "${ALLOWED_NETS[@]}"; do
  ipt_del FORWARD -s "$net" -o "$IFACE" -j ACCEPT
done

# 4. Return traffic
ipt_del FORWARD -o "$IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# 3. Allow scenario/ops
for net in "${ALLOWED_NETS[@]}"; do
  ipt_del FORWARD -i "$IFACE" -d "$net" -j ACCEPT
done

# 2. Mgmt blocks
for net in "${MGMT_NETS[@]}"; do
  ipt_del FORWARD -i "$IFACE" -d "$net" -j DROP
done

# 1. P2P block
ipt_del FORWARD -i "$IFACE" -o "$IFACE" -j DROP

exit 0
