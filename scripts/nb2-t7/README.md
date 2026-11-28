# NB2 v1.1 paired smoke lane

Run this in a dedicated bft-core checkout on the dev server. It takes a lane slot,
starts MongoDB and the four paired validators, enrolls their signing authorities,
and enables signed UTB history at genesis. On exit it stops the processes and
MongoDB it owns and releases the slot. The launcher requires a fresh checkout
without `test-nodes`. Keep the run's output outside that checkout.

Use [pins.json](pins.json) for the release inputs. Clone the pinned contracts,
plug-in, Ureth and aggregator repositories separately. Use Linux, Go, Node 22, Forge
and Cast 1.8.1, and solc 0.8.37. Build at most four jobs in parallel.

```sh
# In the pinned unicity-pos-contracts checkout.
git submodule update --init --recursive
forge build --force --use /path/to/solc-0.8.37 -j 4

# In the pinned aggregator-go checkout.
CGO_ENABLED=1 go build -p 4 -trimpath -o /path/to/bin/aggregator ./cmd/aggregator

# In the pinned Ureth checkout, or use its attested executable.
cargo build --locked --release -j 4 -p unicity-reth

# In the dedicated bft-core checkout, with all paths absolute.
GOFLAGS=-p=4 make build
go build -p 4 -o build/utb-evidence ./scripts/utb-evidence
NB2_CONTRACTS=/path/to/contracts NB2_PLUGIN=/path/to/plug-ins \
NB2_URETH_SOURCE=/path/to/ureth-source NB2_LANE_SLOT=2 \
AGG_BIN=/path/to/bin/aggregator URETH_BIN=/path/to/ureth \
NB2_OUT=/path/to/new/smoke-evidence scripts/nb2-t7/run.sh
```

The launcher builds the plug-in from a Git archive of the pinned commit in a
fresh directory before acquiring a slot. It installs from the tracked lockfile,
records the generated files in `plugin-lib.sha256`, and removes the build tree
after the lane stops.

Use a free private slot 0 or 2. The launcher defaults to slot 2 and takes its
claim before starting MongoDB. The driver authenticates UTB history under the
deployed genesis pin and waits for finalized B1 import of every required signer
epoch before broadcasting a return. The resulting descriptors bind the
imported-tip verifier and the wallet build.

The smoke lane deploys the full production graph at K=64/B=16. It checks the T3/T4
artifact hashes and the registry runtime, then binds the deployed runtime hashes in
Γ and the dependency pins. Creation uses the testnet package's retry-aware Cast
path. The paired genesis funds the development sender. The recipient accounts and
the vault use test value.

The default workload deposits 100 wei, splits the root into 40 and 60 wei branches,
pays the first by ordinary redeem, transfers the second to another holder, and
pays it by recovered redeem after receipt-chained packets. The driver uses the
merged T2/T5 plug-in for signatures, verification, proof acquisition and recovery
packets. It compares each deposit, progress, completion and payout log in full
against the certified receipt and checks custody and recipient balances. The evidence
directory contains Γ, dependency descriptors, build hashes, exact calldata, signed
lineages, packet checkpoints, mined receipts, and canonical receipt proofs with
transaction hashes, resulting block hashes/heights, transaction indices and
receipt-local log indices.

The driver takes these workload parameters.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NB2_ROUTE` | `both` | Use both payouts from one split or use `recovered` to dedicate the deposit to the recovery workload. |
| `NB2_TRANSFERS` | `1` | Number of ordinary holder transfers on the recovered branch, 0 through 600. |
| `NB2_SPLIT_DEPTH` | `1` for both, `0` for recovered | Total ancestors split along the recovered branch up to 20. Extra splits leave one-wei sibling balances outstanding. |
| `NB2_PACKET_OPERATIONS` | `2` | Maximum cut size, 1 through 16. A cut shrinks to fit the hard transport caps. Use 1 for the one-source control. |
| `NB2_RECEIPT_PRIMARY_RPC` | local validator | Loopback receipt source, checked against the paired genesis. |
| `NB2_RECEIPT_ALT_RPC` | unset | Comma-separated loopback alternatives tried when receipts are missing, pruned, not yet certified or over a provider's response limit. |

For a post-T6 scenario, set `NB2_SCENARIO_DRIVER` to an absolute executable path.
It receives the evidence directory, the lane RPC URL and the aggregator URL as
arguments after the pinned contracts deploy. It starts with a fresh vault and
can drive the load generator and separate signer, relayer and archive processes.
The built-in smoke is the default scenario.

The driver checks the finalized imported tip through the local paired validator. The T7
launcher enables replicated shard archives so long runs can pass the default
256-block live journal bound. It retains the full execution proof sources.

## Qualification measurements

Use the same setup and a new output directory per generation.

| Variable | Workload |
| --- | --- |
| `NB2_QUALIFY_COSTS=1` | Exercise all three application-sized lineages through payout. Use `NB2_QUALIFY_CASE=transfer-600`, `transfer-600-split-1` or `split-20` to run one. |
| `NB2_QUALIFY_CUSTODY=1` | Pay 129 one-wei returns across two rotations, refuse the first payment on both routes, authenticate the mined failed retry, and race independently funded ordinary and recovered bidders for the last payment. |
| `NB2_QUALIFY_OFFLINE=1 NB2_QUALIFY_CASE=transfer-600-split-1 NB2_PACKET_OPERATIONS=16` | Stop the wallet after persisting its signed burn. Certify it in a relayer, checkpoint after 336 operations and stop the preferred archive. Seal two real segments, restore Progress from a second validator and settle the recovered burn after folding those seals. |

On the offline workload, set `NB2_ARCHIVE_SEGMENTS` for the number of real
seals and `NB2_ARCHIVE_WINDOW` for the number of segments prepared in each
window. Each new window uses the previously certified head for its burn
anchors. Use `NB2_QUALIFY_CASE=archive-only` for the short-lineage control.
At 1,026 segments or more the runner checks that both eligible ordinary
transactions exceed the signed-byte cap before payout. Use at least 2,080
segments for the short-lineage control at the 524,288-byte cap. Set
`NB2_OFFLINE_PEAK=1 NB2_ARCHIVE_SEGMENTS=12 NB2_LOAD_SKEW=1` to restore
from the late checkpoint during a concentrated load window. It uses separate
load and relayer payers and records seal arrivals and backlog during each
advance.

Set `NB2_OFFLINE_EXTERNAL=1` to run settlement from another device over
loopback forwarding. After the holder exits and the preferred archive stops,
the launcher writes `.offline-handoff` with the private scratch path. The
device needs the signed burn backup, its certified bytes, the deployment and
checkpoint evidence, and a funded relayer key. Omit the holder's spending key.
Run the driver with `NB2_RESUME_STAGE=settle` and the alternate archive. Copy
the resulting settlement evidence back before removing the handoff marker.

Set `NB2_LOAD_SEGMENTS=12 NB2_LOAD_SKEW=1` on the custody workload for
concentrated bucket traffic and simultaneous gap advancement. Set
`NB2_COMPARE_SINGLE_SOURCE=1 NB2_PACKET_OPERATIONS=16` on the smoke workload
to compare the same lineage and terminal verdict with one-source and packed cuts.

These runs use disposable value and a wallet input marked for measurement. The
driver records the wallet's admission result separately from the explicitly
authorised test burn. Private wallet files and the signed handoff live in the
driver's private scratch directory. The offline run covers two real seals.
Qualification of the peak window and oversized archive history requires further
measurements.

During a run, `probe-qualification.py RUN LANE RECEIPT_PATH` checks the chain
identity, graph and proof settings on all four validators, then reads that raw
transaction by block hash and index through the public relay. Pass a mined
failed receipt path to exercise the failed-retry read.

`check-qualification.py --repo BFT_CORE --ureth URETH --artifacts FORGE_OUT --plugin PLUGIN --ureth-bin URETH_BIN
--output MANIFEST RUN...` rederives artifact, domain and pin digests and indexes
the public evidence. It records test measurements. Fundable fee and peak-window
envelopes need measured bounds for the combined qualification workloads.

## Private ERC20 qualification

Start the same launcher under nohup with `NB2_LANE_SLOT=wait`,
`NB2_LANE_OWNER=nb2-1038-qual` and `NB2_QUALIFY_ERC20=1`. The launcher
waits for slot 0 or 2 and claims one before starting the lane. Use the
existing UCT build inputs above. Also set:

- `NB2_ERC20_CONTRACTS` to the clean #107 merge checkout `de62921f1` with
  the ERC20 production artifacts in `out`.
- `NB2_ERC20_PLUGIN` to the clean #99 merge checkout `43c4535de` after
  `npm ci` and `npm run build`.
- `NB2_ERC20_ORACLE_SOURCE` to the clean #1338 checkout and
  `NB2_ERC20_ORACLE_REV` to its full revision. Use the landed merge when
  available. Run the Go oracle from the selected checkout before starting
  the lane.

To use slot 3, enter a separate network namespace with only loopback up
and set its ephemeral port range to 40000–60999. Run the launcher as the
lane user with `NB2_LANE_SLOT=3` and `NB2_HOST_NETNS` set to the original
namespace identity from `readlink /proc/self/ns/net`. Stage the pinned
MongoDB image's `mongod` and `mongosh` binaries and its image reference
in `NB2_MONGO_BIN_DIR`. Populate the npm cache before entering the
namespace and set `npm_config_offline=true` inside it. The normal slot
lock is shared with the host and the listener checks run in the namespace.

After the UCT control the runner deploys two disposable tokens with separate
vaults. Both use authenticated activation evidence and the TypeScript wallet.
The wallet input keeps funding qualification false. The private scenario
authorizes test locks and burns after recording the wallet's admission refusal.
The fee token charges one unit on a delegated deposit and exercises expensive
work below the vault's token call caps. Each asset runs two nested splits,
ordinary and recovered payouts, a recipient block and an independent retry.
The holder exits before the signed backup is certified. The recovered payout
restores a Progress receipt after the preferred archive stops.

The fee scenario defaults to 72 real seals, including a checkpoint at 64
folded gaps. Set `NB2_ERC20_FEE_SEGMENTS=12` for a shorter rehearsal.
Counters, raw signed transactions, receipts, authenticated log locators,
costs and backlog observations are written inside the run directory. The
observed packet sizes and fee schedule do not qualify a general resource bound.

## Focused regressions

Run these from bft-core on the dev server. They do not acquire a slot or start
MongoDB. The TypeScript test uses the pinned SDK build and exercises its
receipt-trie check after a primary HTTP 413.

```sh
python3 scripts/nb2-t7/lane_test.py -v
review=$(mktemp -d)
trap 'rm -rf -- "$review"' EXIT
bash scripts/nb2-t7/build-plugin.sh "$NB2_PLUGIN" "$(jq -r .plugin scripts/nb2-t7/pins.json)" "$review/plugin"
printf '%s\n' '{"type":"module"}' >"$review/package.json"
ln -s "$review/plugin/packages/native-bridge-plugin/lib" "$review/sdk"
cp scripts/nb2-t7/{receipt,receipt.test}.ts "$review/"
"$review/plugin/node_modules/.bin/tsx" --test "$review/receipt.test.ts"
```
