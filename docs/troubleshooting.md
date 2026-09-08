# Troubleshooting

Keyed by symptom, not cause — the same symptom (rounds stop certifying, repeat UCs) can come from
several different, unrelated problems, and staring at consensus internals is rarely how you find out
which one you have. `./build/ubft shard-node doctor` (see `docs/engine-api-adapter-plan.md` §8) runs
the checks that discriminate between most of the causes below; run it before anything here if you
haven't already.

## Contents

- [First launch takes up to a minute to start certifying](#first-launch-takes-up-to-a-minute-to-start-certifying)
- [Rounds stop certifying / repeat UCs every round](#rounds-stop-certifying--repeat-ucs-every-round)
- [One validator never reaches quorum](#one-validator-never-reaches-quorum)
- [A shard-node process refuses to start: "unmarshaling stored certificate"](#a-shard-node-process-refuses-to-start-unmarshaling-stored-certificate)
- [`trust-base generate` fails: "genesis trust base epoch must be 1"](#trust-base-generate-fails-genesis-trust-base-epoch-must-be-1)
- [An `engine-api` executor reports SYNCING and never recovers](#an-engine-api-executor-reports-syncing-and-never-recovers)
- [Engine API startup fails closed](#engine-api-startup-fails-closed)
- [A restarted validator follows the shard but never submits again](#a-restarted-validator-follows-the-shard-but-never-submits-again)
- [A validator refuses to build a round: `no-anchor`, `continuity-gap`, `anchor-mismatch`, `head-identity-mismatch`](#a-validator-refuses-to-build-a-round-no-anchor-continuity-gap-anchor-mismatch-head-identity-mismatch)

---

## First launch takes up to a minute to start certifying

**Symptom:** right after `start-evm.sh -r -a` (or the equivalent hand-run commands), a shard
validator's log shows `"shard node starting"` and then nothing — no `"accepted certificate"` — for
what feels like too long. The corresponding root node's log, at `DEBUG`, shows repeated:

```
msg="processing *handshake.Handshake" err="reading partition 00000008 certificate: unknown partition 00000008 shard "
```

**This is expected, self-healing behavior, not a hang.** Registering a shard conf with a root node
(the `curl -X PUT .../api/v1/configurations` inside `start_root_nodes`) returns success as soon as
it's durably written to that root node's own configuration store — but the root chain's *live*
consensus state, which is what a validator's handshake is actually checked against
(`rootchain/consensus/consensus_manager.go`'s `ShardInfo`), only picks up a newly-registered shard a
handful of root rounds later. A validator whose first handshake lands in that window gets rejected,
and only retries on its own 30-second inactivity timeout (`shardnode/bftclient.go`) — so recovery can
take one or two multiples of 30s in the worst case, observed up to roughly a minute in practice.

`start-evm.sh` and `scripts/chaos-evm.sh` both already pause briefly (`wait_for_root_chain_settle` in
`helper.sh`) between starting root nodes and starting validators specifically to make this rare — but
that pause is a mitigation, not a guarantee, since there's no API to poll "is this shard actually
live yet" (only "was it accepted for storage"). If you're driving `shard-node run` by hand rather than
through the scripts, give the root chain a few seconds after registering the shard conf before
starting validators against it, and don't be alarmed if the very first certificate takes a little
longer than every one after it.

**When to actually worry:** if it's been several minutes with zero certificates and zero further log
activity on the validator side, that's not this — move on to the next section.

## Rounds stop certifying / repeat UCs every round

Several unrelated causes produce the identical symptom (`class=repeat` in every accepted-certificate
log line, no `class=valid` ever). In rough order of likelihood:

1. **Fewer than quorum validators are actually running.** Count them: `ps -eaf | grep 'shard-node run'
   | grep -v grep | wc -l`. A 4-validator shard tolerates exactly one fault — two down stalls it.
2. **T2 doesn't leave enough margin over the root chain's block rate.** `doctor`'s "timing sanity"
   check catches this directly; the shard conf's `--t2-timeout` needs to comfortably exceed the root
   round cadence, or every round risks timing out before quorum forms even with everyone healthy.
3. **A validator's `InputRecord` diverges from what the others are submitting** — see the next
   section.
4. **This is the "first launch" delay above**, if it's early and hasn't gone on for more than a
   minute or two.

## One validator never reaches quorum

**Symptom:** the shard as a whole is certifying fine (other validators show `class=valid`), but one
specific validator's log shows an error, not a normal round submission — typically one of:

- `"executor head diverges from certified state"` (in `reconcile`) — this validator's `Executor` is
  not tracking the same state the rest of the shard agreed on. If it's an in-memory `fake` executor
  and the process was restarted after real (non-quiet) rounds happened, this is expected and *not*
  recoverable for `fake` specifically — it has no persistence to recover from (see
  `docs/adr/0001-executor-boundary.md`, and `shardnode/round_recovery_test.go` for the in-process
  scenario that *is* recoverable, using a stub with real persistence). For `engine-api`/reth, this
  means reth itself lost the block (disk issue, wrong datadir, wrong instance) — that's the "recovery
  beyond same-host executor durability" gap the build plan documents as deliberately out of scope.
- `"executor rejected its own round N block"` — this validator's own `Executor.Verify` disagrees with
  what it (or the leader) just built. For `engine-api`, check `docs/engine-api-adapter.md` §2's
  derivation table field by field; `engineapi.VerifyPayloadFields`'s error message names the exact
  field that diverged.
- No error at all, just silence, and its log never shows this validator as `nextLeader` — check
  `--bootnodes` includes every sibling validator's address (dissemination is a full mesh, not just
  root-chain connectivity — see `shardnode/net_dissemination.go`), and that its own address in
  `--address` is actually reachable at the port it advertises.
- `"trust base network id ... != shard conf network id"` or a rejected epoch on handshake — the trust
  base and shard conf were generated for different networks/epochs; `doctor`'s "trust base" check
  catches this directly.

## A shard-node process refuses to start: "unmarshaling stored certificate"

**Symptom:** `shard-node run` exits immediately, logging an error unmarshaling
`<home>/shard-node-luc.json`.

This is the framework refusing to silently treat a corrupted certificate store as "nothing persisted
yet" — see `shardnode/store.go`'s `LoadLUC`. A genuinely fresh node has no such file at all (that's
handled, not an error); a file that exists but fails to parse means something wrote garbage to it
(disk corruption, a manual edit, a `SaveLUC` interrupted mid-write in a way its atomic rename didn't
prevent). Restore the file from a backup if you have one, or — if this validator's certified state can
be re-derived from a peer or the root chain's own record of what it last certified — delete the file
and let it resume as a fresh node (framework-side; whether the `Executor`'s own state also needs
attention depends on which executor it is). `scripts/chaos-evm.sh`'s last scenario exercises exactly
this failure mode against a live process.

## `trust-base generate` fails: "genesis trust base epoch must be 1"

If you're running `init_root_nodes` (or anything that calls `trust-base generate --epoch 0`) on a
checkout that predates this branch's tooling, that command needs `--epoch 1` — the genesis trust
base's epoch must be 1, not 0, and `--epoch 0` is rejected outright by current validation. Already
fixed in `helper.sh` on this branch; only relevant if you're comparing against an older copy.

## An `engine-api` executor reports SYNCING and never recovers

Not something this environment could live-verify (no reth binary available — see the build plan §10),
so treat this entry as informed by the Engine API spec and this adapter's own design rather than an
observed incident. `SYNCING` from `engine_newPayloadV3`/`forkchoiceUpdatedV3` means reth doesn't have
the payload's parent block locally. Persisting past `Round.awaitTimeout`'s retry budget
(`Round.verifyWithRetry`, `docs/engine-api-adapter.md` §3) generally means reth is missing more than
one block, not just racing dissemination by a few hundred milliseconds — check:

- reth's own sync status (`eth_syncing`) and devp2p peer count — see `docs/engine-api-adapter.md` §5
  for why devp2p, not the Unicity-side dissemination, is what backfills a validator that fell behind
  the *certified* chain.
- That this reth instance's genesis hash matches every other validator's (`doctor`'s "genesis
  agreement" check) — a validator on a different chain will report `SYNCING`/reject everything
  forever, not just transiently.

## Engine API startup fails closed

`Adapter.CheckCapabilities` (also `doctor`'s "engine link" and "capability set" checks) refuses to
start against an execution client that doesn't speak exactly the V3 method set this adapter requires,
or whose chain spec schedules a fork past Cancun. See `docs/engine-api-adapter.md` §4 for why that's
deliberate rather than a bug to work around — the fix is regenerating `genesis.json` via
`ubft engine-api genesis` (not hand-editing a fork schedule) and/or checking the reth build's own
version against what V3 requires, not loosening the check.

## A restarted validator follows the shard but never submits again

Expected, deliberate, and temporary — not a bug to work around. A shard node that resumed from a
persisted certificate logs, once:

```
resumed from a persisted certificate: this node follows and reconciles but will NOT vote until the
monotonic signing record (#105) exists
```

and its health endpoint reports `"voting": false` with that reason. It still receives and verifies
certificates, maintains its execution anchor, reconciles its executor to the certified head and
reports status; it contributes no certification requests.

Why: authenticating a checkpoint proves it genuine, not current. An older checkpoint verifies
perfectly, and resuming from one rolls this node's observation cursor backwards — so it could
re-enter a partition round it has already voted in and sign a second, different statement for it.
Nothing in the file, the certificates or the executor can rule that out; closing it needs a
monotonic, crash-safe record of the highest round this node has signed in, which is issue #105. See
`docs/design/f6b-quiet-uc-recovery.md` §6.1 and §8.

What to do: nothing to the node — it will not vote again in this process, and restarting it does not
help. Plan around it operationally. Shard quorum is `n/2+1`, so keep enough
validators that your expected number of restarts stays inside that margin; exceeding it stalls
certification until #105 lands. `scripts/chaos-evm.sh` had to move from 4 validators to 7 for
exactly this reason.

**Do not delete the checkpoint to get the node voting again.** It works, and it is the one thing
that must not be done: a node started with no persisted certificate has no non-equivocation
authority at all, so it will vote in whatever round arrives next — including one it has already
signed in. That is the exact hazard the gate exists for, reached by a shorter route.

## A validator refuses to build a round: `no-anchor`, `continuity-gap`, `anchor-mismatch`, `head-identity-mismatch`

Four distinct refusals, all meaning "this node will not sign a round it cannot prove it is standing
in the right place for". Each names its row in `docs/design/f6b-quiet-uc-recovery.md` §4, so the
message tells you which one you have:

- **`no-anchor`** — this process has not observed a state-changing certificate, so it cannot say
  which certified block produced the state it is being asked to build on. Ordinary right after a
  restart (see the entry above). It resolves on its own once a non-quiet certificate arrives,
  provided the executor can then be reconciled.
- **`continuity-gap`** — this node DID hold a certified block and then lost the thread of evidence
  for it: a partition round it never saw, or a certificate at a state that block cannot explain. A
  state root that still matches proves nothing here, because a missed interval can return to the
  same state root behind a different block. Unlike `no-anchor` this does not clear by waiting —
  the node has missed certified history and needs to resync.
- **`anchor-mismatch`** — this node holds a certified block, but it produced a different state from
  the one this round builds on. It has missed certified history. It needs to resync; do not try to
  force the commit.
- **`head-identity-mismatch`** — the executor's state root matches the certified one, but its head
  is a *different block*. Two blocks can share a post-state, so this is a real divergence that state
  comparison alone would not have caught, and it does not clear by waiting: the executor is on a
  block the root chain did not certify. Resync the execution client against the certified chain.

In all four the node abstains — it does not build, does not submit, and does not apply anything —
so it is safe to leave running while you investigate. `head_diverged`, `recovery_*` and `identity_*`
appear as reasons on the IR-divergence metric if you would rather alert on them than grep logs.
