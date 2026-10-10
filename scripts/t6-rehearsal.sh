#!/usr/bin/env bash
# T6 is a harness rehearsal only. Production addresses, fees, and pins remain owner inputs.
set -euo pipefail

SOURCE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
AGRE_ROOT=$(cd "$SOURCE_ROOT/.." && pwd)
LOCK_SCRIPT=$AGRE_ROOT/briefs/devnet-lock.sh
SCRIPT_PATH=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
EVIDENCE_DIR=${T6_EVIDENCE_DIR:-$AGRE_ROOT/briefs/devnet-runs/t6-rehearsal-$(date -u +%Y%m%dT%H%M%SZ)}
T6_BFT_COMMIT=${T6_BFT_COMMIT:-$(git -C "$SOURCE_ROOT" rev-parse HEAD)}
T6_BFT_REMOTE=${T6_BFT_REMOTE:-$(git -C "$SOURCE_ROOT" remote get-url origin)}
T6_BFT_REF=${T6_BFT_REF:-t6/rehearsal-harness}
# the Ureth carrying the fresh-B1 profile (the one the H3, M2 and F8 lanes run)
T6_URETH_COMMIT=${T6_URETH_COMMIT:-9623b82748ad02ea4038d3d1ce7391f1cfe1c856}
T6_URETH_REMOTE=${T6_URETH_REMOTE:-https://github.com/ristik/ureth.git}
T6_CONTRACTS_COMMIT=${T6_CONTRACTS_COMMIT:-e7eb3216549b772a9e1df2b1214976d7dd9e6e62}
# The four allocation contracts are rebuilt from their e7eb3216 source commit. The registry is not: the fresh-B1 registry (layout 3) is generated in code
# from the profile, and T6 verifies the deployed genesis against an independent regeneration (b1genesis --verify), not against a contracts rebuild.
T6_CONTRACTS_REMOTE=${T6_CONTRACTS_REMOTE:-https://github.com/ristik/unicity-pos-contracts.git}
T6_RUST_TOOLCHAIN=${T6_RUST_TOOLCHAIN:-1.97.1}

if [ "${T6_LOCKED:-0}" != 1 ]; then
  [ -x "$LOCK_SCRIPT" ] || { echo "FAIL: devnet lock helper missing at $LOCK_SCRIPT" >&2; exit 1; }
  exec "$LOCK_SCRIPT" "T6 placeholder-manifest rehearsal" env \
    T6_LOCKED=1 T6_EVIDENCE_DIR="$EVIDENCE_DIR" T6_BFT_COMMIT="$T6_BFT_COMMIT" \
    T6_BFT_REMOTE="$T6_BFT_REMOTE" T6_BFT_REF="$T6_BFT_REF" T6_URETH_COMMIT="$T6_URETH_COMMIT" \
    T6_URETH_REMOTE="$T6_URETH_REMOTE" T6_CONTRACTS_COMMIT="$T6_CONTRACTS_COMMIT" \
    T6_CONTRACTS_REMOTE="$T6_CONTRACTS_REMOTE" T6_RUST_TOOLCHAIN="$T6_RUST_TOOLCHAIN" \
    "$SCRIPT_PATH" "$@"
fi

mkdir -p "$EVIDENCE_DIR"
exec > >(tee -a "$EVIDENCE_DIR/t6-rehearsal.log") 2>&1

ISOLATION_ROOT=
FRESH_REPO=
FRESH_CONTRACTS=
URETH_BIN=
FAILURE=0
# Evidence mode: the clean source build is the only mode that produces evidence. T6_URETH_BIN (a prebuilt Ureth, DEVELOPMENT iterations only) is
# checked against the pin but skips the cold build, and marks the run as NOT EVIDENCE everywhere it is recorded.
T6_RUN_MODE="clean build (evidence run)"
if [ -n "${T6_URETH_BIN:-}" ]; then T6_RUN_MODE="DEVELOPMENT OVERRIDE: prebuilt Ureth ${T6_URETH_BIN}: NOT EVIDENCE"; fi
printf 'T6 run mode: %s\n' "$T6_RUN_MODE" | tee "$EVIDENCE_DIR/run-mode.txt"

pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; }
trap 'status=$?; fail "step failed at line ${LINENO} (exit $status)"; exit "$status"' ERR
run_step() {
  local label=$1
  shift
  printf '\nSTEP: %s\n' "$label"
  "$@"
  pass "$label"
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

require_free_kb() {
  local minimum_kb=$1 purpose=$2 available_kb
  available_kb=$(df -Pk "$ISOLATION_ROOT" | awk 'NR==2 {print $4}')
  printf 'disk available before %s: %s KiB\n' "$purpose" "$available_kb" | tee -a "$EVIDENCE_DIR/disk-before.txt"
  if [ "$available_kb" -lt "$minimum_kb" ]; then
    fail "only $available_kb KiB free before $purpose; need at least $minimum_kb KiB"
    return 1
  fi
}

capture_partial() {
  local source=$1 destination=$2
  [ -d "$source" ] || return 0
  mkdir -p "$destination"
  python3 - "$source" "$destination" <<'PY'
import shutil,sys
from pathlib import Path
source,destination=map(Path,sys.argv[1:])
for path in source.rglob("*"):
      if path.is_file() and (path.suffix == ".log" or path.name in {
        "t6-contract-actions.json", "f7-lock-pin.json", "operator-status.json",
        "t6-wallet-finalized-before-handoff.json", "t6-wallet-finalized-after-restore.json",
        "t6-f7-verify.json", "t6-trust-base-epoch1.json", "t6-f7-locked.cbor", "t6-finality-monitor.jsonl",
      }):
        target=destination/path.relative_to(source)
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(path,target)
PY
}

# The isolated checkout's Go module cache is read-only, so a plain rm -rf leaves it behind (17 GB had piled up in
# TMPDIR); make it writable first. A failing run keeps its checkout for inspection; a passing run never does.
remove_isolation_root() {
  [ -n "${ISOLATION_ROOT:-}" ] && [ -d "$ISOLATION_ROOT" ] || return 0
  chmod -R u+w "$ISOLATION_ROOT" 2>/dev/null || true
  rm -rf "$ISOLATION_ROOT"
}

on_exit() {
  local status=$?
  if [ "$status" -eq 0 ]; then remove_isolation_root; fi
  if [ "$status" -ne 0 ]; then
    if [ -n "$FRESH_REPO" ]; then capture_partial "$FRESH_REPO/test-nodes" "$EVIDENCE_DIR/partial-test-nodes" || true; fi
    printf 'T6 harness rehearsal: FAIL (exit %s)\nRun mode: %s\n\n' "$status" "$T6_RUN_MODE" >"$EVIDENCE_DIR/run-summary.md"
    printf 'Isolated checkout: %s\nBFT commit: %s\nUreth commit: %s\nContracts commit: %s\n' \
      "${ISOLATION_ROOT:-not-created}" "$T6_BFT_COMMIT" "$T6_URETH_COMMIT" "$T6_CONTRACTS_COMMIT" \
      >>"$EVIDENCE_DIR/run-summary.md"
    printf '\n**Production T6 rerun is pending owner parameters.**\n' >>"$EVIDENCE_DIR/run-summary.md"
    python3 - "$EVIDENCE_DIR" <<'PY'
import hashlib,sys
from pathlib import Path
root=Path(sys.argv[1])
# t6-rehearsal.log is excluded: the harness writes to it after this point (the remaining PASS lines), so a hash taken here could never match.
with (root/"SHA256SUMS").open("w",encoding="utf-8") as out:
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name not in ("SHA256SUMS", "t6-rehearsal.log"):
            out.write(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}\n")
PY
    printf '\nFAIL: T6 harness stopped with exit %s. Isolated checkout: %s\n' "$status" "${ISOLATION_ROOT:-not-created}" >&2
  fi
}
trap on_exit EXIT

new_isolated_checkout() {
  local available_kb
  ISOLATION_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/t6-rehearsal.XXXXXX")
  available_kb=$(df -Pk "$ISOLATION_ROOT" | awk 'NR==2 {print $4}')
  printf 'disk available before clean build: %s KiB\n' "$available_kb" | tee "$EVIDENCE_DIR/disk-before.txt"
  if [ "$available_kb" -lt 5500000 ]; then
    fail "less than 5.5 GiB free for the clean source build; no build started"
    return 1
  fi
  mkdir -p "$ISOLATION_ROOT/home" "$ISOLATION_ROOT/cache/go-build" \
    "$ISOLATION_ROOT/cache/gomod" "$ISOLATION_ROOT/cache/gopath" \
    "$ISOLATION_ROOT/cache/cargo" "$ISOLATION_ROOT/cache/rustup" \
    "$ISOLATION_ROOT/cache/xdg" "$ISOLATION_ROOT/cache/foundry" "$ISOLATION_ROOT/bin"
  FRESH_REPO=$ISOLATION_ROOT/bft-core
  git clone --no-hardlinks --no-tags "$T6_BFT_REMOTE" "$FRESH_REPO" >"$EVIDENCE_DIR/clone.log" 2>&1
  git -C "$FRESH_REPO" fetch --no-tags origin "$T6_BFT_REF" >>"$EVIDENCE_DIR/clone.log" 2>&1
  git -C "$FRESH_REPO" checkout --detach "$T6_BFT_COMMIT" >>"$EVIDENCE_DIR/clone.log" 2>&1
  [ "$(git -C "$FRESH_REPO" rev-parse HEAD)" = "$T6_BFT_COMMIT" ] || return 1
  [ -z "$(git -C "$FRESH_REPO" status --porcelain)" ] || return 1
  [ ! -e "$FRESH_REPO/build/ubft" ] && [ ! -d "$FRESH_REPO/test-nodes" ] || {
    fail "clean clone unexpectedly contains build or lane data"; return 1;
  }
  export HOME="$ISOLATION_ROOT/home"
  export GOCACHE="$ISOLATION_ROOT/cache/go-build"
  export GOMODCACHE="$ISOLATION_ROOT/cache/gomod"
  export GOPATH="$ISOLATION_ROOT/cache/gopath"
  export CARGO_HOME="$ISOLATION_ROOT/cache/cargo"
  export RUSTUP_HOME="$ISOLATION_ROOT/cache/rustup"
  export XDG_CACHE_HOME="$ISOLATION_ROOT/cache/xdg"
  export FOUNDRY_CACHE_PATH="$ISOLATION_ROOT/cache/foundry"
  export GOFLAGS=-mod=readonly
  printf 'fresh BFT commit=%s\nremote=%s\nref=%s\n' "$T6_BFT_COMMIT" "$T6_BFT_REMOTE" "$T6_BFT_REF" >"$EVIDENCE_DIR/source-pin.txt"
  pass "clean BFT clone pinned at $T6_BFT_COMMIT; HOME and Go/Rust/Foundry caches are isolated"
}

build_bft_tools() {
  cd "$FRESH_REPO"
  mkdir -p build
  go build -o build/ubft ./cli/ubft
  go build -o build/f7-mintproof-extract ./scripts/f7-mintproof-extract
  go build -o build/f7-mintproof-verify ./scripts/f7-mintproof-verify
  go build -o build/evmtx ./scripts/evmtx
  go build -o build/b1genesis ./scripts/b1genesis
  pass "fresh ubft, F7 extractor/verifier, transaction signer and B1 genesis verifier compiled with isolated Go caches"
}

install_pinned_foundry() {
  local asset digest archive
  case "$(uname -s)-$(uname -m)" in
    Darwin-x86_64|Darwin-amd64)
      asset=foundry_v1.8.3_darwin_amd64.tar.gz
      digest=1b469229681b31e3c66a07132811b99460b2874a0a48de3b29500234454f47b8
      ;;
    *) fail "no pinned Foundry release asset is configured for $(uname -s)-$(uname -m)"; return 1 ;;
  esac
  archive=$ISOLATION_ROOT/cache/$asset
  curl -fsSL "https://github.com/foundry-rs/foundry/releases/download/v1.8.3/$asset" -o "$archive"
  [ "$(sha256 "$archive")" = "$digest" ] || { fail "pinned Foundry release SHA-256 mismatch"; return 1; }
  tar -xzf "$archive" -C "$ISOLATION_ROOT/bin"
  export PATH="$ISOLATION_ROOT/bin:$PATH"
  forge --version | tee "$EVIDENCE_DIR/foundry-version.txt"
  grep -q 'Version: 1.8.3' "$EVIDENCE_DIR/foundry-version.txt" || {
    fail "installed forge does not report pinned version v1.8.3"; return 1;
  }
  printf 'Foundry release=v1.8.3\nFoundry asset=%s\nFoundry asset sha256=%s\nFoundry forge sha256=%s\n' \
    "$asset" "$digest" "$(sha256 "$ISOLATION_ROOT/bin/forge")" >>"$EVIDENCE_DIR/source-pin.txt"
  pass "Foundry v1.8.3 installed from its pinned published macOS artifact"
}

build_pinned_contracts() {
  FRESH_CONTRACTS=$ISOLATION_ROOT/unicity-pos-contracts
  git clone --no-hardlinks --no-tags "$T6_CONTRACTS_REMOTE" "$FRESH_CONTRACTS" >"$EVIDENCE_DIR/contracts-clone.log" 2>&1
  git -C "$FRESH_CONTRACTS" checkout --detach "$T6_CONTRACTS_COMMIT" >>"$EVIDENCE_DIR/contracts-clone.log" 2>&1
  git -C "$FRESH_CONTRACTS" submodule update --init --recursive >>"$EVIDENCE_DIR/contracts-clone.log" 2>&1
  [ "$(git -C "$FRESH_CONTRACTS" rev-parse HEAD)" = "$T6_CONTRACTS_COMMIT" ] || return 1
  (cd "$FRESH_CONTRACTS" && forge build --force)
  python3 "$FRESH_REPO/scripts/t6/verify-contract-build.py" \
    --manifest "$FRESH_REPO/registrygenesis/testdata/allocation-build-v1.example.json" \
    --bft-root "$FRESH_REPO" --contracts-root "$FRESH_CONTRACTS" \
    --contracts-commit "$T6_CONTRACTS_COMMIT" --skip-registry | tee "$EVIDENCE_DIR/contracts-rebuild.log"
  printf 'contracts commit=%s\nforge version=%s\n' "$T6_CONTRACTS_COMMIT" "$(forge --version | head -1)" >>"$EVIDENCE_DIR/source-pin.txt"
}

build_pinned_ureth() {
  cd "$FRESH_REPO"
  local pathBeforeCargo=$PATH rustupBin
  if [ -n "${T6_URETH_BIN:-}" ]; then
    # DEVELOPMENT iterations only: a prebuilt binary whose reported commit equals the pin replaces the cold build. It is verified, never trusted,
    # and the run is recorded as NOT EVIDENCE (run-mode.txt, source-pin.txt, run-summary.md).
    [ -x "$T6_URETH_BIN" ] || { fail "T6_URETH_BIN=$T6_URETH_BIN is not an executable file"; return 1; }
    . scripts/lib/reth-pin.sh
    urethPinVerifyBinary "$T6_URETH_BIN" "$T6_URETH_COMMIT" || { fail "T6_URETH_BIN does not report the pinned commit $T6_URETH_COMMIT: refusing the override"; return 1; }
    cp "$T6_URETH_BIN" "$ISOLATION_ROOT/bin/unicity-reth"
    URETH_BIN=$ISOLATION_ROOT/bin/unicity-reth
    export URETH_BIN
    printf 'ureth commit=%s\nureth binary=%s\nureth binary sha256=%s\n' "$T6_URETH_COMMIT" "$URETH_BIN" "$(sha256 "$URETH_BIN")" >>"$EVIDENCE_DIR/source-pin.txt"
    "$URETH_BIN" --version >"$EVIDENCE_DIR/ureth-version.txt" 2>&1
    { go version; rustc --version 2>&1 || true; cargo --version 2>&1 || true; } >"$EVIDENCE_DIR/compiler-toolchains.txt"
    printf 'RUN MODE: %s\n' "$T6_RUN_MODE" >>"$EVIDENCE_DIR/source-pin.txt"
    printf 'WARNING: %s\n' "$T6_RUN_MODE" >&2
    return 0
  fi
  require_free_kb 4500000 "cold Ureth build" || return 1
  . scripts/lib/reth-pin.sh
  URETH_PIN_COMMIT=$T6_URETH_COMMIT
  URETH_PIN_REPO=$T6_URETH_REMOTE
  URETH_PIN_LOCAL=$ISOLATION_ROOT/no-local-ureth-allowed
  URETH_PIN_CACHE_DIR=$ISOLATION_ROOT/cache/ureth-pin
  URETH_BIN=
  command -v rustup >/dev/null 2>&1 || { fail "rustup is unavailable for the isolated toolchain install"; return 1; }
  rustupBin=$(command -v rustup)
  mkdir -p "$CARGO_HOME/bin"
  cp "$rustupBin" "$CARGO_HOME/bin/rustup"
  ln -sf rustup "$CARGO_HOME/bin/cargo"
  ln -sf rustup "$CARGO_HOME/bin/rustc"
  export PATH="$CARGO_HOME/bin:$PATH"
  export RUSTUP_TOOLCHAIN=$T6_RUST_TOOLCHAIN
  "$CARGO_HOME/bin/rustup" toolchain install "$T6_RUST_TOOLCHAIN" --profile minimal
  require_free_kb 5000000 "Ureth compilation after isolated toolchain install" || return 1
  URETH_PIN_COMMIT=$URETH_PIN_COMMIT URETH_PIN_REPO=$URETH_PIN_REPO \
    URETH_PIN_LOCAL=$URETH_PIN_LOCAL URETH_PIN_CACHE_DIR=$URETH_PIN_CACHE_DIR \
    urethPinResolve "$ISOLATION_ROOT/bin" | tee "$EVIDENCE_DIR/ureth-build.log"
  URETH_BIN=$ISOLATION_ROOT/bin/unicity-reth
  urethPinVerifyBinary "$URETH_BIN" "$T6_URETH_COMMIT"
  export URETH_BIN
  printf 'ureth commit=%s\nureth binary=%s\nureth binary sha256=%s\n' \
    "$T6_URETH_COMMIT" "$URETH_BIN" "$(sha256 "$URETH_BIN")" >>"$EVIDENCE_DIR/source-pin.txt"
  "$URETH_BIN" --version >"$EVIDENCE_DIR/ureth-version.txt" 2>&1
  {
    go version
    rustc --version
    cargo --version
  } >"$EVIDENCE_DIR/compiler-toolchains.txt"
  printf 'Rust toolchain pin=%s\n' "$T6_RUST_TOOLCHAIN" >>"$EVIDENCE_DIR/source-pin.txt"
  rm -rf "$URETH_PIN_CACHE_DIR/target" "$URETH_PIN_CACHE_DIR/unicity-reth-src-$T6_URETH_COMMIT"
  # Cargo registry and rustup toolchains are fresh per this rehearsal. The verified client is
  # self-contained, so release those isolated build caches before the Solidity and devnet builds.
  rm -rf "$CARGO_HOME" "$RUSTUP_HOME"
  PATH=$pathBeforeCargo
  export PATH
  unset RUSTUP_TOOLCHAIN CARGO_HOME RUSTUP_HOME
  local available_kb
  available_kb=$(df -Pk "$ISOLATION_ROOT" | awk 'NR==2 {print $4}')
  printf 'disk available after Ureth build and target cleanup: %s KiB\n' "$available_kb" >>"$EVIDENCE_DIR/disk-before.txt"
}

run_paired_t6() {
  cd "$FRESH_REPO"
  require_free_kb 2500000 "paired T6 network rehearsal" || return 1
  # the single B1 layout: one profile derived from the shard configuration and the root trust base, registry layout 3, the Q3 flow for every handoff
  export Q3_B1=1 H3_SLOT_LAYOUT=3 EVM_OPERATOR_STATUS_RPC=1
  # the testnet profile's churn budget (owner decision 19, briefs/p85-churn-bound-note.md): D <= 1/2, committed in the genesis configuration (the DEV default,
  # 1/4, admits no replacement of one of four). The rotation replaces one of four (D = 1/2) and the lane shows a candidate beyond the budget refused.
  export EVM_PARTITION_PARAMS_EXTRA=${EVM_PARTITION_PARAMS_EXTRA:-continuity_max_distance=1/2}
  # the single B1 layout, as in scripts/m2-lane.sh: the B1 profile, the layout-3 slot names, the shard nodes' operator endpoint
  export Q3_B1=1 H3_SLOT_LAYOUT=3 EVM_OPERATOR_STATUS_RPC=1
  export POST_M2A_MODE=t6 POST_M2A_CHAIN_ID=1337
  export POST_M2A_URETH_BIN="$URETH_BIN" POST_M2A_URETH_COMMIT="$T6_URETH_COMMIT"
  export M2_PROFILE2=1 SIGNING=authority M2A_FINAL_RESTORE=1
  export M2_RUN_LOG_DIR="$EVIDENCE_DIR/paired-node-logs"
  # one key-replacing coupled rotation (s=1) after the existing checks; the validators stop and restart on purpose, so the journal bound is raised
  export T6_COUPLED_ROTATION=${T6_COUPLED_ROTATION:-1} EVM_JOURNAL_CANDIDATES=${EVM_JOURNAL_CANDIDATES:-256}
  bash ./scripts/reth-paired-devnet.sh 4 20 2>&1 | tee "$EVIDENCE_DIR/paired-lane.log"
  grep -q "T6 coupled rotation s=1: authority-backed" "$EVIDENCE_DIR/paired-lane.log" || [ "${T6_COUPLED_ROTATION:-1}" != 1 ] || { fail "the coupled rotation step did not pass"; return 1; }
  pass "paired network completed placeholder claims, WUCT wrap/unwrap, treasury withdrawal, handoffs, restore, finality checks, and a coupled key-replacing rotation"
}

# The deployed genesis (the chain spec every execution client ran) carries exactly the registry the pinned source generates: regenerated by the freshly built
# b1genesis from the profile, the root trust base and the full shard configuration the chain was made from, then compared (code and every storage word).
verify_b1_registry() {
  cd "$FRESH_REPO"
  local out=$EVIDENCE_DIR/b1-registry-verify.txt
  build/b1genesis --verify test-nodes/evm-genesis-finalized-funded.json --profile test-nodes/b1-profile.json \
    --root-genesis test-nodes/trust-base.json --shard-conf "test-nodes/shard-conf-8_0.json" 2>&1 | tee "$out"
  [ "${PIPESTATUS[0]}" = 0 ] && grep -q 'the deployed registry account matches the regeneration' "$out" || { fail "the deployed registry differs from its regeneration"; return 1; }
  cp test-nodes/b1-profile.json "$EVIDENCE_DIR/b1-profile.json"
}

extract_verify_f7() {
  cd "$FRESH_REPO"
  local pin trust bundle verifier_output
  pin=test-nodes/post-m2a-evidence/f7-lock-pin.json
  trust=test-nodes/post-m2a-evidence/t6-trust-base-epoch1.json
  bundle=test-nodes/post-m2a-evidence/t6-f7-locked.cbor
  verifier_output=test-nodes/post-m2a-evidence/t6-f7-verify.json
  [ -s "$pin" ] && [ -s "$trust" ] && [ -s "$bundle" ] && [ -s "$verifier_output" ] || {
    fail "pre-handoff F7 pin, epoch-1 trust base, bundle, or verifier output is missing"; return 1;
  }
  python3 - "$pin" "$verifier_output" <<'PY' || return 1
import json,sys
pin=json.load(open(sys.argv[1],encoding="utf-8"))
result=json.load(open(sys.argv[2],encoding="utf-8"))
if result.get("status")!="PASS" or result.get("trustBaseEpoch")!=1:
    raise SystemExit("pre-handoff offline F7 verifier result is not a PASS for epoch 1")
if result.get("blockHash","").lower()!=pin["blockHash"].lower():
    raise SystemExit("pre-handoff F7 verification block hash differs from the certified receipt pin")
PY
  pass "pre-handoff F7 archive bundle, receipt pin, and epoch-1 verification output agree"
  if command -v sandbox-exec >/dev/null 2>&1; then
    env -i PATH="$PATH" sandbox-exec -p '(version 1) (allow default) (deny network*)' \
      build/f7-mintproof-verify --bundle "$bundle" --trust-base "$trust" --mode locked \
      >"$EVIDENCE_DIR/f7-verify.json"
    pass "retained F7 verification rerun in a network-denied macOS sandbox"
  else
    env -i PATH="$PATH" HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 \
      ALL_PROXY=http://127.0.0.1:9 build/f7-mintproof-verify --bundle "$bundle" \
      --trust-base "$trust" --mode locked >"$EVIDENCE_DIR/f7-verify.json"
    pass "retained F7 verification rerun with network-stripped environment"
  fi
  pass "F7 bundle verified again from captured files without consulting the archive or RPC"
  cp "$bundle" "$EVIDENCE_DIR/f7-locked.cbor"
  cp "$trust" "$EVIDENCE_DIR/trust-base-epoch1.json"
  cp "$pin" "$EVIDENCE_DIR/f7-lock-pin.json"
  cp "$verifier_output" "$EVIDENCE_DIR/f7-pre-handoff-verify.json"
}

collect_evidence() {
  cd "$FRESH_REPO"
  mkdir -p "$EVIDENCE_DIR/paired-evidence"
  cp registrygenesis/testdata/allocation-build-v1.example.json "$EVIDENCE_DIR/placeholder-manifest.json"
  cp test-nodes/post-m2a-allocation-build-v1.json test-nodes/evm-genesis-finalized-funded.json \
    "$EVIDENCE_DIR/paired-evidence/"
  cp -R test-nodes/post-m2a-evidence "$EVIDENCE_DIR/paired-evidence/"
  [ ! -d test-nodes/h3 ] || cp -R test-nodes/h3 "$EVIDENCE_DIR/paired-evidence/coupled-rotation"
  python3 - "$FRESH_REPO/test-nodes" "$EVIDENCE_DIR/node-logs" <<'PY'
import shutil,sys
from pathlib import Path
source,destination=map(Path,sys.argv[1:])
destination.mkdir(parents=True,exist_ok=True)
for path in source.rglob("*"):
    if path.is_file() and path.suffix == ".log":
        target=destination/path.relative_to(source)
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(path,target)
PY
  printf 'run mode: %s\n' "$T6_RUN_MODE" >"$EVIDENCE_DIR/run-pins.txt"
  printf 'bft commit: %s\nureth commit: %s\ncontracts commit: %s\nplaceholder manifest SHA-256: %s\n' \
    "$T6_BFT_COMMIT" "$T6_URETH_COMMIT" "$T6_CONTRACTS_COMMIT" \
    "$(sha256 "$EVIDENCE_DIR/placeholder-manifest.json")" >>"$EVIDENCE_DIR/run-pins.txt"
  printf 'T6 harness rehearsal: PASS\nRun mode: %s\n\n' "$T6_RUN_MODE" >"$EVIDENCE_DIR/run-summary.md"
  printf 'Source pins and binary hash: `run-pins.txt` and `source-pin.txt`.\n' >>"$EVIDENCE_DIR/run-summary.md"
  printf 'Paired lane: `paired-lane.log`; node logs and per-step contract/RPC evidence are under `node-logs/` and `paired-evidence/`.\n' >>"$EVIDENCE_DIR/run-summary.md"
  printf 'F7 proof: `f7-lock-pin.json`, `f7-locked.cbor`, `f7-verify.json`.\n\n' >>"$EVIDENCE_DIR/run-summary.md"
  printf '**Production T6 rerun is pending owner parameters** for the production manifest, addresses, fees, and approved pins.\n' >>"$EVIDENCE_DIR/run-summary.md"
  python3 - "$EVIDENCE_DIR" <<'PY'
import hashlib,sys
from pathlib import Path
root=Path(sys.argv[1])
# t6-rehearsal.log is excluded: the harness writes to it after this point (the remaining PASS lines), so a hash taken here could never match.
with (root/"SHA256SUMS").open("w",encoding="utf-8") as out:
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name not in ("SHA256SUMS", "t6-rehearsal.log"):
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            out.write(f"{digest}  {path.relative_to(root)}\n")
PY
  pass "T6 logs, pins, manifest, wallet reads, and F7 bundle hashes recorded under $EVIDENCE_DIR"
}

cleanup_isolated_build() {
  remove_isolation_root
  printf 'disk available after isolated checkout/cache cleanup:\n' >"$EVIDENCE_DIR/disk-after-cleanup.txt"
  df -h "$AGRE_ROOT" >>"$EVIDENCE_DIR/disk-after-cleanup.txt"
  python3 - "$EVIDENCE_DIR" <<'PY'
import hashlib,sys
from pathlib import Path
root=Path(sys.argv[1])
# t6-rehearsal.log is excluded: the harness writes to it after this point (the remaining PASS lines), so a hash taken here could never match.
with (root/"SHA256SUMS").open("w",encoding="utf-8") as out:
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name not in ("SHA256SUMS", "t6-rehearsal.log"):
            out.write(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}\n")
PY
  ISOLATION_ROOT=
  FRESH_REPO=
  pass "isolated clone and caches removed after evidence capture"
}

write_prerehearsal_pins() {
  cd "$FRESH_REPO"
  local manifest hash
  manifest=registrygenesis/testdata/allocation-build-v1.example.json
  hash=$(sha256 "$manifest")
  printf 'bft commit=%s\nbft remote=%s\nbft ref=%s\nbft ubft sha256=%s\n' \
    "$T6_BFT_COMMIT" "$T6_BFT_REMOTE" "$T6_BFT_REF" "$(sha256 build/ubft)" >"$EVIDENCE_DIR/source-pin.txt"
  printf 'run mode=%s\n' "$T6_RUN_MODE" >>"$EVIDENCE_DIR/source-pin.txt"
  printf 'f7 extractor sha256=%s\nf7 verifier sha256=%s\nevmtx sha256=%s\n' \
    "$(sha256 build/f7-mintproof-extract)" "$(sha256 build/f7-mintproof-verify)" \
    "$(sha256 build/evmtx)" >>"$EVIDENCE_DIR/source-pin.txt"
  printf 'ureth commit=%s\nureth binary=%s\nureth binary sha256=%s\n' \
    "$T6_URETH_COMMIT" "$URETH_BIN" "$(sha256 "$URETH_BIN")" >>"$EVIDENCE_DIR/source-pin.txt"
  cat "$EVIDENCE_DIR/ureth-version.txt" >>"$EVIDENCE_DIR/source-pin.txt"
  printf 'contracts commit=%s\ncontracts manifest sha256=%s\n' \
    "$(git -C "$FRESH_CONTRACTS" rev-parse HEAD)" "$hash" >>"$EVIDENCE_DIR/source-pin.txt"
  printf 'Foundry forge sha256=%s\n' "$(sha256 "$ISOLATION_ROOT/bin/forge")" >>"$EVIDENCE_DIR/source-pin.txt"
  cat "$EVIDENCE_DIR/compiler-toolchains.txt" >>"$EVIDENCE_DIR/source-pin.txt"
  printf 'Foundry release=v1.8.3\nFoundry macOS asset sha256=1b469229681b31e3c66a07132811b99460b2874a0a48de3b29500234454f47b8\n' \
    >>"$EVIDENCE_DIR/source-pin.txt"
  cat "$EVIDENCE_DIR/foundry-version.txt" >>"$EVIDENCE_DIR/source-pin.txt"
}

printf 'T6 rehearsal evidence directory: %s\n' "$EVIDENCE_DIR"
printf 'BFT pin: %s\nUreth pin: %s\nContracts pin: %s\n' "$T6_BFT_COMMIT" "$T6_URETH_COMMIT" "$T6_CONTRACTS_COMMIT"
run_step "fresh clone and isolated HOME/cache setup" new_isolated_checkout
run_step "fresh pinned Ureth source build" build_pinned_ureth
run_step "fresh BFT and F7 tool build" build_bft_tools
run_step "isolated pinned Foundry release install" install_pinned_foundry
run_step "contracts e7eb3216 source rebuild and manifest artifact match" build_pinned_contracts
run_step "source, binary, and manifest pins" write_prerehearsal_pins
run_step "paired T6 rehearsal with handoffs and documented restore" run_paired_t6
run_step "deployed B1 registry equals its independent regeneration (code and storage)" verify_b1_registry
run_step "retain and recheck pre-handoff offline F7 bundle" extract_verify_f7
run_step "evidence and SHA-256 manifest" collect_evidence
run_step "isolated build cleanup and final evidence hashes" cleanup_isolated_build
pass "T6 placeholder harness run complete [$T6_RUN_MODE]; production rerun pending owner parameters"
