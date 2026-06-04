#!/bin/bash
# Build per-student arena-byoc binary with baked credentials.
# Used by arena-manager API to generate downloads on-demand.
#
# Usage:
#   ./build.sh <priv-b64> <server-pub-b64> <tunnel-ip> <server-host> <goos> <goarch> <out>
#
# Example:
#   ./build.sh "yA5R..." "aRd6..." 10.201.0.5 wg-byoc.adversario.cl linux amd64 /tmp/arena-byoc

set -euo pipefail

PRIV="$1"
SRV_PUB="$2"
TUN_IP="$3"
SRV_HOST="$4"
GOOS_="$5"
GOARCH_="$6"
OUT="$7"

CLIENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/client" && pwd)"

LDFLAGS="
  -s -w
  -X main.privKeyB64=$PRIV
  -X main.serverPubKeyB64=$SRV_PUB
  -X main.tunnelIP=$TUN_IP
  -X main.serverHost=$SRV_HOST
"

cd "$CLIENT_DIR"
CGO_ENABLED=0 GOOS="$GOOS_" GOARCH="$GOARCH_" \
    go build -ldflags "$LDFLAGS" -o "$OUT" ./...

echo "Built: $OUT ($GOOS_/$GOARCH_)"
