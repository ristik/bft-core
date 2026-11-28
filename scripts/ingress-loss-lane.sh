#!/usr/bin/env bash
# Run from a dedicated checkout on a claimed lane slot.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/lib/portable.sh
case "${LANE_SLOT:-}" in 0|2|3) ;; *) echo "set LANE_SLOT to a claimed slot (0, 2 or 3)" >&2; exit 2 ;; esac
: "${INGRESS_LOSS_EVIDENCE:?set INGRESS_LOSS_EVIDENCE to a new absolute directory}"
[[ "$INGRESS_LOSS_EVIDENCE" = /* ]] || exit 2
mkdir "$INGRESS_LOSS_EVIDENCE"
export CARGO_BUILD_JOBS=4 GOFLAGS="${GOFLAGS:-} -p=4"
export M2_PROFILE2=1 Q3_B1=1 M2_RUN_LOG_DIR="$INGRESS_LOSS_EVIDENCE/nodes"
export INGRESS_LOSS_LANE=1 Q4_SHIM_DIR="$INGRESS_LOSS_EVIDENCE" Q4_ROOT_BIN="$INGRESS_LOSS_EVIDENCE/bin/ubft"
export INGRESS_LOSS_LOAD_BIN="$INGRESS_LOSS_EVIDENCE/bin/ingress-loss-load"
export ROOT_LOG_LEVEL=debug EVM_VALIDATOR_LOG_LEVEL=debug
BFT_SOURCE_COMMIT=$(git -C "$PWD" rev-parse --verify HEAD)
export BFT_SOURCE_COMMIT
mkdir -p build "$INGRESS_LOSS_EVIDENCE/bin"
go build -p 4 -buildvcs=true -o build/ubft ./cli/ubft
go build -p 4 -buildvcs=true -tags q4shim -o "$Q4_ROOT_BIN" ./cli/ubft
go build -p 4 -buildvcs=true -o "$INGRESS_LOSS_LOAD_BIN" ./scripts/ingress-loss-load
{
  printf 'bft source commit=%s\n' "$BFT_SOURCE_COMMIT"
  for binary in build/ubft "$Q4_ROOT_BIN" "$INGRESS_LOSS_LOAD_BIN"; do
    sha=$(p_sha256 "$binary" | cut -d' ' -f1)
    build_id=$(go tool buildid "$binary")
    printf '%s sha256=%s go-build-id=%s\n' "$binary" "$sha" "$build_id"
  done
} | tee "$INGRESS_LOSS_EVIDENCE/build-identity.txt"
exec bash scripts/reth-paired-devnet.sh 5 1
