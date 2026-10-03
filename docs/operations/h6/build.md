# Build and verify the rehearsal artifacts

Return to [entry point](README.md). Run these commands in Bash. Stop at any
nonzero command. Use `set -eo pipefail`; helper libraries support Bash 3.2 but
some assume variables are initialized, so do not add `set -u` to the manual shell.

## Supported rehearsal host and prerequisites

The concrete platform is macOS **15.8.1 (24H32), x86_64**, with Unix sockets,
`lsof`, `sandbox-exec`, Xcode command-line C/C++ tools and libclang (Rust/RocksDB).
Linux/arm64 ports of this guide are unvalidated; T6's pinned Foundry installer
explicitly only accepts Darwin amd64. Install **Go 1.27.1**, **Rust/Cargo 1.97.1**
via rustup, **Foundry 1.8.3**, and **Solidity 0.8.37** (downloaded by Forge).
Solidity settings are Cancun, via-IR, optimizer 200, no metadata hash/CBOR trailer;
keep the pinned `foundry.toml`. Go's module language minimum is 1.24, not the
compiler pin. Ureth's minimum Rust is 1.95, not the rehearsal compiler pin.

Host versions inspected for this guide: Bash 5.3.15, Python 3.14.7, Git 2.56.0,
GitHub CLI 2.102.0, jq 1.7.1-apple, Apple clang 17.0.0
(clang-1700.6.4.2). Use those versions for the initial reproduction.
Also require GitHub CLI authenticated for the repositories,
`curl`, `jq`, `openssl`, `shasum`, `make`, `tar`, `ps`, and `lsof`. These are host
tools rather than consensus artifacts: record their exact installed versions
below; differing host utilities require repeating this guide's checks. Reserve
at least 30 GiB free for parallel source/build caches and 16 GiB RAM as a planning
budget, not a measured capacity guarantee. T6's smaller staged disk guards do not
cover keeping both upgrade binaries and all build caches.

```sh
set -eo pipefail
# Start in the checkout containing this guide and its thin operator adapter.
export H6_GUIDE="$(pwd)"
test -f "$H6_GUIDE/scripts/h6/prepare-handoff.py"
# Choose an absolute directory on your host; this example is under your home.
export H6_BASE="$HOME/h6-rehearsal"
mkdir -p "$H6_BASE"
export H6_BASE="$(cd "$H6_BASE" && pwd -P)"
# 0: dedicated host, no lock. 1: shared host, use the repository lock helper.
export H6_SHARED_HOST=0
export H6_RUN="$H6_BASE/runs/h6-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$H6_RUN"
chmod 700 "$H6_RUN"
export H6_BFT=624620c334006e2c8fe1b920a4b0a90c67cbbfd7
export H6_OLD=5f3bb7e4ee9f82e70630e5c4b73783e7a392a7d3
export H6_NEW=b4e7cb0ace07eee70e753241e0139c4d42b516d4
export H6_ALLOC=e7eb3216549b772a9e1df2b1214976d7dd9e6e62
export H6_REGISTRY=ce3e40b479de0a0ef8787d8830ba77189aa11171
export H6_AGG=dd5b1406a17fdeb415799045c5e81609619a870a
export H6_SRC="$H6_BASE/h6-private-$(basename "$H6_RUN")"
test ! -e "$H6_SRC"
git clone https://github.com/ristik/bft-core.git "$H6_SRC"
git -C "$H6_SRC" checkout --detach "$H6_BFT"
test "$(git -C "$H6_SRC" rev-parse HEAD)" = "$H6_BFT"
cd "$H6_SRC"
export GOCACHE="$H6_RUN/cache/go"
export GOTOOLCHAIN=go1.27.1
export RUSTUP_TOOLCHAIN=1.97.1
rustup toolchain install 1.97.1 --profile minimal
{ sw_vers; uname -m; go version; rustc --version; cargo --version;
  git --version; gh --version; python3 --version; jq --version;
  curl --version; openssl version; make --version; clang --version;
  xcode-select -p; df -h .; } > "$H6_RUN/host.txt" 2>&1
make build
for tool in evmtx f7-mintproof-extract f7-mintproof-verify h4-restore-pin; do
  go build -o "build/$tool" "./scripts/$tool"
done
go version -m build/ubft > "$H6_RUN/ubft-build.txt"
build/ubft --help > "$H6_RUN/ubft-help.txt"
for command in 'shard-node restore' 'shard-node status' 'root handoff abort' \
  'root handoff evm-pop' 'signing-authority advance-epoch' 'engine-api genesis'; do
  build/ubft $command --help >> "$H6_RUN/ubft-help.txt"
done
```

Check `vcs.revision` and `vcs.modified=false` in `ubft-build.txt`. An old local
`build/ubft` can lack restore, status or handoff entirely; a directory name or
checkout HEAD does not prove the binary pin.

## Ureth: build both sides of the upgrade

```sh
mkdir -p "$H6_RUN/bin"
cp "$H6_GUIDE/scripts/h6/prepare-handoff.py" "$H6_RUN/bin/prepare-handoff.py"
cp "$H6_GUIDE/scripts/h6/run-h3.sh" "$H6_RUN/bin/run-h3.sh"
git -C "$H6_GUIDE" rev-parse HEAD > "$H6_RUN/documentation-revision.txt"
shasum -a 256 "$H6_RUN/bin/prepare-handoff.py" "$H6_RUN/bin/run-h3.sh" \
  "$H6_GUIDE/scripts/h6/devnet-lock.sh" > "$H6_RUN/helper.sha256"
for pin in "$H6_OLD" "$H6_NEW"; do
  git clone https://github.com/ristik/ureth.git "$H6_RUN/ureth-$pin"
  git -C "$H6_RUN/ureth-$pin" fetch origin "$pin"
  git -C "$H6_RUN/ureth-$pin" checkout --detach "$pin"
  test "$(git -C "$H6_RUN/ureth-$pin" rev-parse HEAD)" = "$pin"
  (cd "$H6_RUN/ureth-$pin" && cargo build --locked --release -p unicity-reth) \
    2>&1 | tee "$H6_RUN/ureth-$pin-build.log"
  cp "$H6_RUN/ureth-$pin/target/release/unicity-reth" "$H6_RUN/bin/ureth-$pin"
done
. scripts/lib/reth-pin.sh
urethPinVerifyBinary "$H6_RUN/bin/ureth-$H6_OLD" "$H6_OLD"
urethPinVerifyBinary "$H6_RUN/bin/ureth-$H6_NEW" "$H6_NEW"
```

`urethPinVerifyBinary` checks the full `Commit SHA:` line, not the semver string
(`scripts/lib/reth-pin.sh:242`). Do not use stock reth. Keep the build logs and
binary hashes; a hash calculated after building records provenance, but is not
independent approval of that artifact. A second operator compares hashes with
the approved build manifest before launch.

## Contracts and aggregator

Install the exact T6 Foundry release (source: `scripts/t6-rehearsal.sh:163`):

```sh
curl -fL --output "$H6_RUN/foundry.tar.gz" \
  https://github.com/foundry-rs/foundry/releases/download/v1.8.3/foundry_v1.8.3_darwin_amd64.tar.gz
printf '%s  %s\n' 1b469229681b31e3c66a07132811b99460b2874a0a48de3b29500234454f47b8 \
  "$H6_RUN/foundry.tar.gz" | shasum -a 256 -c -
tar -xzf "$H6_RUN/foundry.tar.gz" -C "$H6_RUN/bin"
export PATH="$H6_RUN/bin:$PATH"
forge --version | tee "$H6_RUN/foundry-version.txt"
forge --version | grep 'Version: 1.8.3'
git clone https://github.com/ristik/unicity-pos-contracts.git "$H6_RUN/contracts"
for pin in "$H6_ALLOC" "$H6_REGISTRY"; do
  git -C "$H6_RUN/contracts" checkout --detach "$pin"
  git -C "$H6_RUN/contracts" submodule update --init --recursive
  (cd "$H6_RUN/contracts" && forge build --force)
  if [ "$pin" = "$H6_ALLOC" ]; then opts=(--skip-registry);
  else opts=(--registry-layout 2 --registry-only); fi
  python3 scripts/t6/verify-contract-build.py \
    --manifest registrygenesis/testdata/allocation-build-v1.example.json \
    --bft-root "$H6_SRC" --contracts-root "$H6_RUN/contracts" \
    --contracts-commit "$pin" "${opts[@]}" | tee "$H6_RUN/contracts-$pin.log"
done
git clone https://github.com/ristik/rugregator.git "$H6_RUN/rugregator"
git -C "$H6_RUN/rugregator" checkout --detach "$H6_AGG"
(cd "$H6_RUN/rugregator" && cargo build --locked --release -p uni-aggregator --bin aggregator)
export RUGREGATOR_SOURCE="$H6_RUN/rugregator"
export RUGREGATOR_BIN="$RUGREGATOR_SOURCE/target/release/aggregator"
shasum -a 256 build/ubft "$H6_RUN/bin/ureth-"* "$RUGREGATOR_BIN" \
  registrygenesis/seal-registry-v2.json > "$H6_RUN/artifacts.sha256"
shasum -a 256 -c "$H6_RUN/artifacts.sha256"
```

The allocation and registry sources deliberately have different pins; rebuilding
only the older allocation tree cannot establish the layout-2 registry hash.
Build failures are STOP conditions, not reasons to substitute a newer compiler
or dependency lockfile. Capture submodule SHAs and Forge compiler output too.
All source pins above were resolved with Git when writing this guide. The BFT
pin is the source baseline; the documentation PR is not an execution upgrade.
