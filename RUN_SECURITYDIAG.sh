#!/usr/bin/env sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CAMPAIGN="${1:-repo}"
exec python3 "$HERE/securitydiag.py" run "$CAMPAIGN"
