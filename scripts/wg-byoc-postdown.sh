#!/bin/bash
# wg-byoc PostDown hook — tear down the rules wg-byoc-postup.sh created.
#
# Best-effort: each delete is wrapped so a missing rule doesn't abort the
# whole cleanup. wg-quick down should never fail because of leftover state.
#
# Invoked from /etc/wireguard/wg-byoc.conf PostDown.
# Mirror lives in /tmp/arena-tunnel/scripts/ (public repo) — keep in sync.

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

# 6. NAT
for net in "${ALLOWED_NETS[@]}"; do
  iptables -t nat -D POSTROUTING -s 10.201.0.0/24 -d "$net" -o "$EXT_IFACE" -j MASQUERADE 2>/dev/null || true
done

# 5. Default-deny
ipt_del FORWARD -i "$IFACE" -j DROP

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
