# The root builds the Retirement itself (X4, arch's design `briefs/x4-retirement-control-design.md`)

An identity leaves the validator set by its owner's on-chain `requestRetirement(id)`. Nothing else is needed from an operator: a root that runs with
`--pos-deployment` **and** `--pos-evm-rpc` builds the `Retirement` control itself, as the proposer, against the EVM state its selected proposal parent certified.
The acceptance rules are unchanged (`storage/pos_control.go`: `certifiedState`, `VerifyRetirement`, the liability anchor, the in-flight handoff and acknowledgement
exclusion). `POST /api/v1/pos/control` stays for explicit submissions.

## What a root does

1. **Discovery** (`rootchain/posretire`). Every root polls its execution client for custody's `RetirementRequested(uint64 indexed id, uint64 generation)`,
   up to the head with no confirmation depth (the EVM shard makes no blocks while idle, so a depth would stall a request on a quiet chain; certified blocks are final and a proof at a certified block, never the log, authorizes), rescanning the last 8 blocks before a persisted cursor. The cursor and the pending `(id, generation)` set live in `$UBFT_HOME/pos-retirements.json`
   (atomic writes by a single background writer, never on the consensus loop; a file that cannot be read stops the node rather than forgetting requests; a write that fails or is lost in a crash only costs a rediscovery from the older cursor, and an ended request that comes back is ended again by the next committed observation, a repeated Retirement being a no-op in the executor). Logs are scheduling hints only: a proof authorizes, a log does not.
   Work is always keyed by `(id, generation)`: a request cannot be reset within a generation, a new generation never reuses an old proof.
2. **Preparation** (off the consensus loop). When a block is added to the tree it is the candidate parent of the next proposal. `Prepare(parent)` starts, for at most
   4 pending requests and with at most 4 proofs in flight, a witness build (`evmstate.BuildRetirementWitness`: the custody and registry slots the verifier reads,
   the deployment bindings included, one `eth_getProof` call per account for the fixed slots) at the **block hash** the parent certified, within 5 s. The result is
   cached by (EVM state root, block hash, id, generation); a request that is not retirable at that parent (not yet requested at the certified state, live exposure, lot references, records not caught up)
   **stays pending for a later parent however long that takes** (a stalled EVM certification keeps the same old root for any number of rounds); the outcome is remembered
   per (parent, request) so the same parent is not proved again. The only proven endings are the registry showing the generation retired (a generation advances only after its
   predecessor was retired, so a superseded request ends there too) and a committed Retirement.
3. **Proposal.** The leader adds, after the mandatory closures and any submitted control, up to 4 Retirements **prepared for exactly its parent**, in ascending
   `(id, generation)`, stamped with the block's epoch and round. Each is trial-executed with the whole block; the witness is retained before the proposal is signed; a
   Retirement the root state refuses (liability anchor not reached, in-flight handoff, record cap) is left out of this proposal and never blocks it. Nothing waits for
   a proof: one that is not ready is for a later parent.
4. **Voters** fetch the retained witness by hash (existing path) and judge it against the same parent tuple as always. The child may certify a newer EVM block: that
   does not change the parent tuple of its Retirement, and no EVM production pause is needed. A quiet parent round keeps the state root and has no block hash: the control
   then names the zero block hash and the proof is fetched at the block that certified that root.
5. **Cleanup.** A request ends when a *committed* block has ordered its Retirement (`RetirementCommitted`), or the registry shows it retired. A Retirement already ordered
   on the proposing branch is not proposed again.

## Status

The proposer path has been exercised in unit tests against the real executor and store, not live: the X4 live lane (two exits, continuous EVM production, `retirement proof ready` latency and tuples recorded) is the end-to-end evidence and has to pass before this counts as done.

## Liveness and what it assumes

Retirement is optional, closure is not: a proposal never fails for lack of a Retirement. Inclusion needs the proof service to answer within the time between a block being
proposed and the next leader proposing on it (roughly a round trip), and an honest leader; under continuous EVM production a proof that arrives one block late is for the
wrong parent and the request waits for the next. The X4 live lane records proof latency, the parent tuple and the ordered/imported anchors for this reason.

## Flags

`--pos-evm-rpc URL` is now also accepted without an election in the deployment (it then only enables the Retirement builder); with an election it is still required.
