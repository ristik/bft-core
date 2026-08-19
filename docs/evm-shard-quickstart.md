# EVM shard quickstart

Clone to a certifying 4-validator EVM shard, `--executor fake`, no reth required. Every command
below is copy-pasteable as written and has been run verbatim from a clean checkout. If a step needs
explaining beyond what's here, that's a bug in the scripts, not a gap in this doc — see
`docs/troubleshooting.md` if something doesn't match what you see.

Needs: Go 1.24+, a C compiler, nothing else. Run everything from the repository root.

## 1. Build and generate the topology

```bash
./setup-evm-nodes.sh -r 3 -v 4
```

This builds `ubft`, then generates: 3 root-chain node identities, 4 shard-validator identities, one
shard conf (partition 8, `proof_type=exec`, `chain_id=31337`), and a reth-compatible
`test-nodes/evm-genesis.json` derived from that shard conf (unused for `--executor fake`, but
generated regardless so the same layout works for `--executor engine-api` later — see §5). All of it
lands in `test-nodes/`, which the next commands assume exists.

## 2. Start everything

```bash
./start-evm.sh -r -a -e fake -v 4
```

`-r` starts the 3 root nodes; `-a` starts the 4 shard validators against them, using the deterministic
in-memory `fake` executor (no execution client to run). The two are ordered correctly by the script
itself — it pauses briefly between them so the validators' first handshake lands after the root
chain's own consensus has caught up on the freshly-registered shard, not before.

## 3. Confirm it's certifying

```bash
for i in 1 2 3 4; do
  echo -n "evm$i: "
  grep -c 'accepted certificate' "test-nodes/evm$i/debug.log" 2>/dev/null || echo 0
done
```

Expect a nonzero, growing count for all four. **The first certificate can take up to roughly a
minute to appear** — this is expected, not a hang; see `docs/troubleshooting.md`'s "first launch
takes a while to start certifying" entry for why. If you want to watch it happen live instead of
polling:

```bash
tail -f test-nodes/evm1/debug.log
```

Look for a line like:

```
msg="accepted certificate" class=valid partitionRound=3 rootRound=17 nextRound=4 nextLeader=16Uiu2HAm...
```

`class=valid` and a growing `partitionRound` is a shard actually reaching quorum, round after round —
that's the destination. `class=repeat` shows up occasionally too (a round that didn't reach quorum in
time, retried) — expected background noise, not a fault, and self-resolves within a round or two.

## 4. Watch leadership rotate, or knock a validator over

```bash
grep 'leader=true' test-nodes/evm*/debug.log | tail -8
```

Different validators should appear as leader across recent rounds. To see the fault-tolerance this
buys you, try what `scripts/chaos-evm.sh` formalizes: stop one validator and confirm the other three
keep certifying without it.

```bash
kill "$(cat test-nodes/evm1/pid)"
sleep 10
grep -c 'accepted certificate' test-nodes/evm2/debug.log   # keeps growing — quorum is 3 of 4
```

Restart it the same way the scripts do — same command, same home directory, picks up from its last
persisted certificate rather than starting over:

```bash
source helper.sh
start_one_evm_validator 1 4 8 "$(boot_node test-nodes/root1 "$rootPortStart")" fake
```

For the fuller set of failure scenarios (kill-leader, a longer cold restart, a corrupted certificate
store), run `./scripts/chaos-evm.sh` — it does exactly this, with assertions, end to end.

## 5. Stop everything

```bash
./stop-evm.sh -a
```

Leaves `test-nodes/` on disk — `./start-evm.sh -r -a -e fake -v 4` again resumes the same shard from
where it left off (each validator persists its last certificate; see `docs/shard-protocol.md` §7).
To start completely fresh, re-run `./setup-evm-nodes.sh -r 3 -v 4` first, which clears and
regenerates `test-nodes/`.

## What's next

- **A real execution client instead of `fake`**: `--executor engine-api` drives reth over the
  standard Engine API — see `docs/engine-api-adapter.md` for the flags, and the genesis file this
  step already generated (`test-nodes/evm-genesis.json`) is what reth needs to start from. This
  quickstart doesn't cover starting reth itself; that's environment-specific (a reth binary, its own
  datadir per validator, static-peer configuration — see `docs/engine-api-adapter.md` §5).
- **Preflight checks before debugging by hand**: `./build/ubft shard-node doctor` (see
  `docs/engine-api-adapter-plan.md` §8) runs the same checks that, left unchecked, tend to produce
  "rounds stop certifying" as their only symptom.
- **The protocol this is all built on**: `docs/shard-protocol.md`.
- **Building a different `Executor`**: `docs/shard-node.md`.
