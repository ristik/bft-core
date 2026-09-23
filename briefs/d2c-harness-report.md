# D2-C fault harness report

Run one case at a time from this checkout. Lane commands use the shared port lock:

```sh
/Users/risto/uni/agre/briefs/devnet-lock.sh dev env \
  D2C_SCENARIO=pair-term \
  URETH_BIN=/Users/risto/uni/agre/ureth/target/release/unicity-reth \
  D2C_PERSISTENCE_THRESHOLD=64 ./scripts/d2c-fault-harness.sh
```

The harness has controllers for pair SIGTERM/SIGKILL, ureth-only SIGKILL, all-pair SIGKILL,
leader-pair SIGKILL, bounded proof RPC outage/corruption, deletion of a certified execution-journal
candidate, and a retained-datadir restart using a different genesis. Scenario logs end in a
`D2C[...]` verdict line. The journal negative removes the certified B5 candidate keyed by its exact
block hash from validator 1's configured-progress v2 Bolt journal, then restarts that validator.
The wrong-genesis negative changes the chain ID in the genesis file while reusing validator 1's
retained reth datadir.

## Current run classifications

| Scenario | Verdict | Evidence |
|---|---|---|
| pair-term (current rerun) | INCONCLUSIVE: setup did not reach B5 | The transaction was mined and the four reth clients advanced, but validator 1 did not log `accepted certificate` within the 180s bootstrap window. The SIGTERM controller was never called. [Log](d2c-harness/20260923T170615Z-pair-term.log) |
| proof-outage (current rerun) | INCONCLUSIVE: setup did not reach B5 | Proxy started and routed validator 1 RPC; the transaction was mined, but validator 1 did not log `accepted certificate` within 180s. No outage was injected, so this run provides no SYNCING/re-drive classification. [Log](d2c-harness/20260923T171036Z-proof-outage.log) |
| proof-corrupt | NOT rerun after lock coordination | The earlier run exited during topology setup before proof mutation. Current proxy startup is confirmed by the proof-outage setup, but corruption behavior remains unverified. [Earlier log](d2c-harness/20260923T164220Z-proof-corrupt.log) |
| missing-body | Hook wired; not run | Requires reaching certified B5 before editing the journal. The current bootstrap stall prevents exercising it. |
| wrong-genesis | Hook wired; not run | Requires reaching certified B5 before reusing the retained datadir with the altered genesis. The current bootstrap stall prevents exercising it. |
| pair-kill, ureth-kill, all-kill, leader-kill | Wired; not run in this pass | Each needs a fresh lane run that reaches B5. |

An earlier pre-D2-A/proxy-controller run did inject the proof outage, restore forwarding, and then stall
with validator 1 at B6 (`status syncing`) while the other clients reached B48. That is historical
injection evidence, not a result from the current rerun or current D2-A journal-enabled lane. It
supports no stronger conclusion than that this older setup did not re-drive/catch up; D2-B is still
needed for recovery. [Earlier log](d2c-harness/20260923T163626Z-proof-outage.log)

The two current reruns used fresh test-node trees and the shared lock wrapper. Their failure happened
before the B5 hook, with repeated block certification requests but no accepted certificate logged by
validator 1. This bootstrap behavior must be resolved before the requested post-D2-A classifications
can be established. No scenario with a pre-injection setup failure is counted as expected SYNCING.

## #244 reviewer follow-up

The default D1 lane now fails on every executor divergence recovery warning when restart-probe mode is
off. Probe mode still restricts an allowed warning to restarted validator 1 after its restart boundary
and requires a same-hash recovery before the next warning or process boundary. The authority rerun
reached B5, restarted validator 1, then stalled before B6 with heads `[5, 33, 33, 33]`; the strict
same-hash checker rejected the recovery sequence. This is recorded for the reviewer at
`/Users/risto/uni/agre/briefs/d2c-authority-postfix.log`.
