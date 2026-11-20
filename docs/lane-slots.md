# Lane slots: several devnet lanes on one host

`LANE_SLOT=N` (0..3, default 0) moves **every** listening port of `scripts/reth-paired-devnet.sh`, `helper.sh`, `scripts/lib/*.sh` and the step and acceptance
scripts by `N * 1000`. Slot 0 is the historical layout, unchanged (CI lanes keep it). There is no other offset knob (a custom offset would bypass the lock's reservation). `scripts/lib/lane-slot.sh` holds the table and exports `LANE_PORT_OFFSET`;
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

`scripts/lane-slot.sh selftest` (`scripts/lane-slot-selftest.sh`) checks the table, that no lane script holds a raw historical port literal (every port goes through `LANE_PORT_OFFSET`; a line that must says `lane-port-ok`), the lock protocol (one winner, exact claim on release, a delayed duplicate release cannot remove a newer claim, the ephemeral-range refusal), and also starts the same command lines in two scratch trees and checks that every process lookup (`owned_pids`: command and cwd) sees only its own tree, and that no lane library or step file uses a bare `pgrep -f` pattern. It checks that no port collides within a slot, across slots 0..3, or with the docker package's 8545/8088/8090/9090.
Per-validator counts are 6 (reth, shard) and 8 (roots); a lane with more must stay on slot 0. The aggregator's port is slot-derived and nothing else
(an `AGG_PORT` that differs from the slot's value is refused).

**Ephemeral ports.** Linux hands out outgoing-connection ports from `ip_local_port_range` (32768..60999 by default), and a listener there can lose its port
to one. `acquire --profile P` (default `paired-default`; also `f6b`, `f6c`, `seed`, `f8`, comma-separable) hard-checks every listener the profile starts
(the table's classes: `core`; `neg` = the section-3 negative clients the default paired invocation starts; `f6c`, `seed`, `f8`) against the range and
`ip_local_reserved_ports`, and refuses slots 1..3 on a conflict. On a default host slot 3 is refused (reth devp2p 33401..), slots 1 and 2 are not. **Slot 0 is
exempt**: its historical ports have run for months and CI depends on them (f6c and seed listen in the range there). Every slot is covered instead by a **bind
preflight**: right before a root, shard node (P2P and RPC), reth (the paired lane's, section 3's negative clients, F6B's and F6C's, the F6B bystanders), the F6C root and
shard nodes, or the aggregator starts (`lane_port_preflight`, `scripts/lib/lane-slot.sh`), it probes by an actual bind of PORT on the address the service binds (TCP, `SO_REUSEADDR` as the Go
and Rust listeners set it), which also catches a socket that is bound but not listening. The lanes run reth with `--disable-discovery`, so no UDP listener is probed.
The probe binds the address the service binds: loopback for the Go nodes and the reth RPC ports, the wildcard `0.0.0.0` for reth's P2P port (the lanes pass `--port` without `--addr`), because a listener on another local address conflicts with a wildcard bind but not with a loopback one. A node just stopped may still hold its port for a moment: the probe retries for 5 s, then fails with a clear message. **The preflight cannot reserve a port**: another
process can take it between the probe and the service's own bind, and that bind failure still fails the lane.

Paths: `test-nodes/` (including the signing-authority sockets `test-nodes/authN/*.sock`) is relative to the tree, so **each lane needs its own tree copy**.
`M2_RUN_LOG_DIR` and the VR `VR_EVIDENCE` default to a directory with a `-slotN` suffix off slot 0.

## Host lock and helper

`scripts/lane-slot.sh acquire|release|status|ports|mongo|selftest`. The lock is `~/host-lock/slot-N.txt` (owner, tmux, tree, token, profile, ports, start), written
and removed only while holding one host-wide `flock(1)` on `~/host-lock/.lanes.lock` (acquire, release and status each take it for their whole critical section,
including the check that a token is unique across all slots; the kernel drops it when the holder dies, so there is nothing to clean up after a killed helper).
A claim is written to `slot-N.txt.tmp.PID` and renamed into place, so an acquire interrupted at any point leaves no partial claim (a temp file at most, which the next `acquire` or `status` removes under the lock), and the slow children of the helper run with the lock fd closed. `acquire` generates the claim token (a uuid; `--token` gives one), prints `SLOT TOKEN`, picks the lowest free slot (or `--slot N`) and refuses an occupied slot.
`release` needs the same `--owner` and the claim's `--token`, so a delayed duplicate release cannot remove a newer claim; `--force` skips both after you checked the
owner's processes. `status` also flags a lock whose tmux session (exact name) is gone. Needs `flock` (util-linux), i.e. Linux.

Launcher: the same owner and token on acquire and release, an aborting acquire, the assignment apart from the `export`, the lane as a child that a TERM, INT or HUP
of the launcher is forwarded to and waited for (further signals during that cleanup are ignored) (a background lane ignores SIGINT, so the launcher sends it TERM), and the Mongo teardown and the release only after the
lane has exited, never while it runs:

```
set -e
owner=VT-07
claim=$(scripts/lane-slot.sh acquire --owner "$owner" --tmux vt07)   # aborts here when acquire fails
read -r slot token <<<"$claim"; export LANE_SLOT=$slot
lane=
stop_lane() { [ -z "$lane" ] || { kill -TERM "$lane" 2>/dev/null; wait "$lane" 2>/dev/null || true; lane=; }; }
cleanup() {
  trap '' INT TERM HUP     # a repeated signal during the wait must not cut the cleanup short
  stop_lane; scripts/lane-slot.sh mongo down ~/lane-mongo || true
  scripts/lane-slot.sh release --owner "$owner" --token "$token"
}
trap cleanup EXIT
trap 'exit 143' INT TERM HUP     # the EXIT trap above stops the lane first
scripts/lane-slot.sh mongo up ~/lane-mongo     # only for lanes with the aggregator (VR_AGG=1, UTB)
./scripts/reth-paired-devnet.sh 4 10 &
lane=$!; rc=0; wait "$lane" || rc=$?; lane=; exit "$rc"
```

The helper kills nothing and does not detect a dead owner; release a stale lock with `release --force` after checking the owner's processes.
