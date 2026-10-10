# H6: rehearse a private PoA network

H6 ([issue 23](https://github.com/ristik/bft-core/issues/23)) asks a second operator to stand up the network from the written
procedures alone and to exercise the operations that matter: key rotation, restore, abort, version activation.

**The rehearsal is setting up the testnet.** Follow [testnet/OPERATOR.md](../testnet/OPERATOR.md) (build the pinned images, generate
a generation, verify, restart, back up and restore, reset) and record every gap as a documentation defect
(OPERATOR.md section 9). That page owns setup, verification, routine operations and troubleshooting of the container stack;
nothing is repeated here.

What the container stack does not support yet (OPERATOR.md section 6) is exercised on the native lanes, on the fresh-B1 layout
(registry layout 3, one handoff flow: the Q3 flow). These pages cover only that:

- [scenarios.md](scenarios.md): the native lanes, what each one proves and the commands.
- [evidence.md](evidence.md): what to record, the interruption objectives, the acceptance map, refusals and what to do.

Procedures the lanes follow: [H3 runbook](../h3-evm-assignment-runbook.md) (coupled root/EVM rotation, joiners, supersession),
[M2 runbook](../m2-runbook.md) (handoffs, restore after disk loss, archive replicas),
[Abort](../root-handoff-abort.md), [bootstrap pin](../bootstrap-trust-pin.md), [resource limits](../f9-resource-limits.md).

## Rules for every native lane

- Disposable keys and funds only. A lane PASS is developer evidence; H6 closes on the independent operator's record, not on a PASS.
- Run a lane from its own fresh checkout: lanes delete and recreate `test-nodes/`. Never run one against another network's live homes.
- One devnet at a time on a host: the fixture ports are fixed. On a shared host take the repository lock
  (`scripts/h6/devnet-lock.sh`) and never remove a live lock or use a machine-wide `pkill`; set `H3_LANE_LOCKED=1` (or `T6_LOCKED=1`)
  only when you hold it or the host is yours, since those flags skip the lane's own lock lookup rather than acquire one.
- A signing authority's key exists only in memory. Never restart an authority to "repair" anything; a lost authority key is not
  recoverable and ends that validator's signing permission.
- Evidence is the lane's own log: the wrapper's final PASS line, no `FAIL:` line, and the head SHAs it prints. An exit status alone is not.

## Out of scope

Rolling or mixed BFT versions, rolling execution activation, any migration of an older registry layout, downgrade over newly written
state, resurrecting an authority from a snapshot, automatic authority restart, public RPC exposure beyond OPERATOR.md's, and
production capacity claims. The OWNER decides interruption objectives, the human second operator, production artifacts and
identities, validator membership and weights, custody, fees, the bootstrap pin authority, fencing, host placement and
escalation contacts; no fixture value here is a production recommendation.
