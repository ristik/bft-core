# D2-B execution recovery (M1)

An Engine API seal shard uses `--execution-journal` in fresh D2 state. The journal's verified certificates, not the executor's latest payload, select the certified execution target. On startup and after executor identity loss, the recovery owner checks head and finalized identities, replays the ordered certified suffix when needed, and withholds Build and signing until the head exactly matches the certified anchor. It revalidates readiness under the finality gate before a child Build or signature. Recovery never lowers executor finality or finalizes a speculative suffix.

If the local journal lacks certified bodies, the node asks configured shard validators for the exact suffix between its retained anchor and certified target. `/unicity/shard-journal-suffix/1.0.0` is a bounded libp2p request/response protocol, separate from consensus messages and the F7 archive. Peers supply bytes only. Before journal admission, the node authenticates original and resulting UC/TR pairs, checks the raw execution header hash and parent linkage, and runs adapter `Verify`. Requests and responses have frame, block, byte, peer, and deadline limits. There is no discovery or retention guarantee.

## Operator state

`/api/v1/health` reports `executionRecovery` as `ready`, `unready`, or `stopped`, with `executionRecoveryDetail` naming the current cause. `unready` covers retryable executor RPC and identity loss. `stopped` is latched for the process lifetime after a terminal finalized-branch conflict, a bounded recovery or journal capacity failure, or failed admission of a newer certificate after bounded peer catch-up. A stopped node refuses subsequent Build and signing; restart only after the cause has been resolved and the durable journal inspected. The Prometheus counter `shardnode.execution_recovery.stops` records stop events. This is the M1 stop state; there is no special process exit code.

`--evidence-recover` is refused with `--execution-journal` because that older recovery path does not use journal admission. Serving authenticated anchor evidence remains available independently.

The capped journal currently re-verifies its full retained history per certificate. This cost is a follow-up for a later incremental verifier and does not weaken M1 admission checks.
