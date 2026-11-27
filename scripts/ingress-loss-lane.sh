#!/usr/bin/env bash
# Run from a dedicated checkout on a claimed lane slot.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "${LANE_SLOT:-}" in 0|2|3) ;; *) echo "set LANE_SLOT to a claimed slot (0, 2 or 3)" >&2; exit 2 ;; esac
: "${INGRESS_LOSS_EVIDENCE:?set INGRESS_LOSS_EVIDENCE to a new absolute directory}"
[[ "$INGRESS_LOSS_EVIDENCE" = /* ]] || exit 2
mkdir "$INGRESS_LOSS_EVIDENCE"
export CARGO_BUILD_JOBS=4 GOFLAGS="${GOFLAGS:-} -p=4"
export M2_PROFILE2=1 Q3_B1=1 M2_RUN_LOG_DIR="$INGRESS_LOSS_EVIDENCE/nodes"
export INGRESS_LOSS_LANE=1 Q4_SHIM_DIR="$INGRESS_LOSS_EVIDENCE" Q4_ROOT_BIN="$INGRESS_LOSS_EVIDENCE/bin/ubft"
export INGRESS_LOSS_LOAD_BIN="$INGRESS_LOSS_EVIDENCE/bin/ingress-loss-load"
export ROOT_LOG_LEVEL=debug EVM_VALIDATOR_LOG_LEVEL=debug
mkdir "$INGRESS_LOSS_EVIDENCE/bin"
go build -p 4 -tags q4shim -o "$Q4_ROOT_BIN" ./cli/ubft
go build -p 4 -o "$INGRESS_LOSS_LOAD_BIN" ./scripts/ingress-loss-load
exec bash scripts/reth-paired-devnet.sh 5 1
