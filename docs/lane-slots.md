# Lane slots: several devnet lanes on one host

`LANE_SLOT=N` (0..3, default 0) moves **every** listening port of `scripts/reth-paired-devnet.sh`, `helper.sh`, `scripts/lib/*.sh` and the step and acceptance
scripts by `N * 1000`. Slot 0 is the historical layout, unchanged (CI lanes keep it). `LANE_PORT_BASE=N` (0..17000) is an explicit offset instead of
`LANE_SLOT * 1000`, for a host that needs another layout; it wins over the slot. `scripts/lib/lane-slot.sh` holds the table and exports `LANE_PORT_OFFSET`;
python helpers (`d1-monitor.py`, `d2c-fault-control.py`, `m1-fee-accounting.py`, `post-m2a-t4-rpc-capture.py`) read it from the environment.

| what | slot 0 | slot 1 (+1000) |
|---|---|---|
| reth eth / engine / devp2p (per validator, +i-1) | 18545 / 18551 / 30401 | 19545 / 19551 / 31401 |
| root p2p / root RPC (+i-1) | 26662 / 25866 | 27662 / 26866 |
| shard p2p / dissemination / RPC (+i-1) | 28111 / 28211 / 28311 | 29111 / 29211 / 29311 |
| aggregator HTTP / its BFT p2p (+k-1) | 3001 / 29101 | 4001 / 30101 |
| MongoDB replica set (`scripts/ci/mongo-up.sh`) | 27117 | 28117 |
| D2C proxies, section-3 negative rethS, F8 HTTP, f6b/f6c acceptance lanes | see `scripts/lib/lane-slot.sh` | +1000 |
| docker testnet package (`deploy/testnet/generate.py --port-offset 1000`) | 8545 / 8088 / 9090 | 9545 / 9088 / 10090 |

`scripts/lane-slot.sh selftest` also starts the same command lines in two scratch trees and checks that every process lookup (`owned_pids`: command and cwd) sees only its own tree, and that no lane library or step file uses a bare `pgrep -f` pattern. It checks that no port collides within a slot, across slots 0..3, or with the docker package's 8545/8088/8090/9090.
Per-validator counts are 6 (reth, shard) and 8 (roots); a lane with more must stay on slot 0. Linux hands out ephemeral ports from 32768, so slot 3's
devp2p ports (33xxx) can meet an outgoing connection: prefer slots 0..2.

Paths: `test-nodes/` (including the signing-authority sockets `test-nodes/authN/*.sock`) is relative to the tree, so **each lane needs its own tree copy**.
`M2_RUN_LOG_DIR` defaults to a timestamped directory with a `-slotN` suffix off slot 0; give each lane its own evidence directory.

## Host lock and helper

`scripts/lane-slot.sh acquire|release|status|ports|mongo|selftest`. The lock is `~/host-lock/slot-N.txt` (owner, tmux, tree, ports, start); `acquire` picks the
lowest free slot (or `--slot N`), creates the lock atomically and refuses an occupied one. It prints the slot:

```
export LANE_SLOT=$(scripts/lane-slot.sh acquire --owner VT-07 --tmux vt07)
scripts/lane-slot.sh mongo up ~/lane-mongo     # only for lanes with the aggregator (VR_AGG=1, UTB)
./scripts/reth-paired-devnet.sh 4 10
scripts/lane-slot.sh mongo down ~/lane-mongo; scripts/lane-slot.sh release
```

The helper kills nothing and does not detect a dead owner; release a stale lock with `release --force` after checking the owner's processes.
