# NB2 v1.1 paired smoke lane

Run this in a dedicated bft-core checkout on the dev server. It takes a lane slot,
starts MongoDB and the four paired validators, enrolls their signing authorities,
and enables signed UTB history at genesis. On exit it stops the processes and
MongoDB it owns and releases the slot. The launcher requires a fresh checkout
without `test-nodes`. Keep the run's output outside that checkout.

Use [pins.json](pins.json) for the release inputs. Clone the pinned contracts,
plug-in and aggregator repositories separately. Use Linux, Go, Node 22, Forge
and Cast 1.8.1, and solc 0.8.37. Build at most four jobs in parallel.

```sh
# In the pinned unicity-pos-contracts checkout.
git submodule update --init --recursive
forge build --force --use /path/to/solc-0.8.37 -j 4

# In the pinned aggregator-go checkout.
CGO_ENABLED=1 go build -p 4 -trimpath -o /path/to/bin/aggregator ./cmd/aggregator

# In the pinned native-bridge-plugins checkout.
npm ci
npm run build

# In the pinned Ureth checkout, or use its attested executable.
cargo build --locked --release -j 4 -p unicity-reth

# In the dedicated bft-core checkout, with all paths absolute.
GOFLAGS=-p=4 make build
go build -p 4 -o build/utb-evidence ./scripts/utb-evidence
NB2_CONTRACTS=/path/to/contracts NB2_PLUGIN=/path/to/plug-ins \
AGG_BIN=/path/to/bin/aggregator URETH_BIN=/path/to/ureth \
NB2_OUT=/path/to/new/smoke-evidence scripts/nb2-t7/run.sh
```

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
| `NB2_RECEIPT_ALT_RPC` | unset | Comma-separated loopback alternatives tried on missing, pruned or not-yet-certified receipts. |

For a post-T6 scenario, set `NB2_SCENARIO_DRIVER` to an absolute executable path.
It receives the evidence directory, the lane RPC URL and the aggregator URL as
arguments after the pinned contracts deploy. It starts with a fresh vault and
can drive the load generator and separate signer, relayer and archive processes.
The built-in smoke is the default scenario.

The current driver uses the local paired validator as its origin authority. The
T6 journal and load scenarios will exercise offline handoff, paid-ID eviction,
sustained sealing and the measured release envelope. The default smoke keeps the
segment at zero and does not claim those qualification results.
