# H6: rehearse a private paired PoA network

This guide starts with empty node directories and ends with an evidence bundle for
[H6, issue 23](https://github.com/ristik/bft-core/issues/23). It is a private,
single-host rehearsal. All funds and keys are disposable. It is not approval to
launch public balances. The commands below have been checked against the source
and a freshly built CLI; this documentation change has **not** run a live rehearsal.

## Read and execute in order

1. [Build the pinned tools](build.md). Keep build evidence outside `test-nodes/`.
2. [Set up the manual network](network.md). Run the upgrade and abort procedures
   in [scenarios.md](scenarios.md) on this network, then stop it.
3. Run the fresh H3 lane and T6 lane in [scenarios.md](scenarios.md). These create
   separate networks, replace their checkout's `test-nodes/`, and stop their
   authorities at exit. Never run them against the manual network's live homes.
4. Complete [evidence and acceptance](evidence.md), including the independent
   operator record. A lane PASS alone does not close H6.

The manual route uses documented calls into `helper.sh` and
`scripts/lib/m2-handoff-lib.sh`; you do not need to read those files. The H3 and T6
entry points already automate the other procedures; a thin H3 supervisor drains
extra children at final teardown. There is no new daemon or
replacement consensus/recovery implementation in this kit.

## Lock and workspace

Choose `H6_BASE` in [build.md](build.md): it is the absolute directory for your
clones, caches and evidence on **your own host**. `H6_GUIDE` points to the checkout
containing this guide and the operator helpers. No external workspace is needed.
On a dedicated host no lock is needed. Leave `H6_SHARED_HOST=0` (the default).
On a shared host set `H6_SHARED_HOST=1`; all operators sharing the fixture ports
must agree on the same `H6_BASE`, since the optional lock is `$H6_BASE/.h6-devnet-lock`.
The repository provides `scripts/h6/devnet-lock.sh` for that case.

After the build, start the manual-network shell with the selected policy:

```sh
if [ "$H6_SHARED_HOST" = 1 ]; then
  bash "$H6_GUIDE/scripts/h6/devnet-lock.sh" 'H6 independent operator' \
    bash --noprofile --norc
else
  bash --noprofile --norc
fi
```

Keep that shell open for the entire manual network lifetime, including teardown.
Run H3/T6 from the parent shell after it exits; scenarios.md applies the same
optional lock policy. Never acquire the lock recursively, remove a live lock,
use machine-wide `pkill`, or use another operator's checkout. The lock is a
shared-host scheduling mechanism, not signing-key fencing. An interrupted lock
holder can leave the lock directory: confirm its recorded PID and all network
processes have stopped before manually removing that directory. There is no
automatic stale-lock takeover.

The pinned H3 and T6 entry points have developer-workspace lock defaults that
are **not repository dependencies**. The commands in scenarios.md bypass those
defaults with `H3_LANE_LOCKED=1` and `T6_LOCKED=1`, respectively, after selecting
dedicated-host execution or acquiring the repository-provided lock. These flags
skip the lanes' lock lookup; they do not acquire a lock themselves. H3's existing
“devnet lock acquired” log line is not proof of locking when that lookup is bypassed.

Use the isolated clone made in build.md. `make clean` and `setup-evm-nodes.sh`
delete `test-nodes/`; run setup exactly once per disposable clone. Restart is a
separate operation. Save evidence before teardown, and keep credentials private.

## Which procedures are authoritative?

| Existing section | Use from this guide |
|---|---|
| [M2: Shared preflight and evidence](../m2-runbook.md#shared-preflight-and-evidence), [Checks and stop conditions](../m2-runbook.md#6-checks-and-stop-conditions) | Mandatory checks before/after each operation. |
| [M2: Supported-version matrix](../m2-runbook.md#supported-version-matrix) | Support limit; scenarios.md adds one candidate, coordinated Ureth upgrade, conditional on its pair tests. |
| [M2: Planned root-key rotation](../m2-runbook.md#1-planned-root-key-rotation) | Trust verification and surviving-authority advancement semantics; use the coupled H3 lane for actual layout-2 key replacement. |
| [H3: Rules](../h3-evm-assignment-runbook.md#rules), sections 1–4, [Before H](../h3-evm-assignment-runbook.md#before-h-abort-and-retry), [After H](../h3-evm-assignment-runbook.md#after-h-the-successors-cannot-acknowledge), [Operator guards](../h3-evm-assignment-runbook.md#operator-guards) | Coupled root/EVM replacement, PoPs, acknowledgement and supersession. |
| [Abort: Before submitting](../root-handoff-abort.md#before-submitting), [Submit and wait](../root-handoff-abort.md#submit-and-wait), [After committed Abort](../root-handoff-abort.md#after-committed-abort), [The EVM is frozen from Prepare](../root-handoff-abort.md#the-evm-is-frozen-from-prepare) | Exact-target Abort semantics; the manual recipe supplies a deliberately interrupted proposal. |
| [M2: Replace a validator after complete disk loss](../m2-runbook.md#3-replace-a-validator-after-complete-disk-loss), including “After restore” and “A validator behind the pruned hot-journal window” | Restore checks and refusal handling. |
| [M2: Archive-replica maintenance](../m2-runbook.md#4-archive-replica-maintenance), including “Replacing a configured archive replica” | One replica at a time, acknowledgement and frontier rules. |
| [M2: Shard-node restart after handoffs](../m2-runbook.md#5-shard-node-restart-after-handoffs) | Authority-preserving restart semantics; network.md supplies concrete process commands. |
| [Bootstrap pin: Pin contents](../bootstrap-trust-pin.md#pin-contents), “Authorization and distribution”, “Bootstrap and verification”, “Sequence, refresh and expiry policy”, “Failure handling”, “Owner and external actions” | Distribution/freshness policy; does not grant recovery authority or make a copied receipt fresh. |
| [F9: Journal settings](../f9-resource-limits.md#journal-settings), “Measurements”, “Initial operating thresholds”, “Remaining evidence” | Resource budgets and their measured limits. |

For this fixture, network.md supersedes the M2 assumption that a network already
exists and its deployment-specific systemd placeholders. The H3 lane supersedes
root-only key replacement examples on layout 2. Do not copy a local `--key-conf`
PoP example for an authority-held key: the lane uses `evm-pop --authority-socket`
and `--authority-credential`. M2's statement that the lane does not advance
authorities is stale for this source pin: `scripts/lib/m2-handoff-lib.sh:223`
and `scripts/h3-assignment-steps.sh:557` do so. Live independent evidence remains
required. This guide does not supersede the existing safety/STOP conditions.

## Recovery authority and OWNER decisions

The operator may stop/reconnect shard and execution processes, use a surviving
authority, and request certified handoffs with authorized old-quorum approval.
An operator credential is not permission to edit history. A lost authority key
cannot be recovered from disk; a restarted authority has a new key. Keep live
authorities outside the validator disk-loss domain. Whole-host loss is outside
this single-host fixture's survivable fault model.

**Unsupported:** rolling/mixed BFT versions; rolling execution activation;
layout-1 to layout-2 migration; downgrade over newly written state; resurrection
of an authority from snapshots; automatic authority restart; public RPC exposure;
production/multi-host capacity claims. A coordinated BFT upgrade that kills its
in-memory authorities is not the Ureth-only upgrade rehearsed here.

**OWNER:** approve interruption objectives before running, appoint the human
second operator, approve exact production artifacts, network/chain identities,
validator membership/weights, custody, allocations, fees, bootstrap pin authority,
fencing, host placement and support/escalation contacts. No fixture value below
is a production recommendation. Authority-loss and clone/power-loss acceptance
added in the issue discussion must remain separately open unless demonstrated;
this live-authority fixture cannot claim durable authority recovery.
