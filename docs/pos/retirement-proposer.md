# The root builds the Retirement itself (X4, arch's design `briefs/x4-retirement-control-design.md`)

An identity leaves the validator set by its owner's on-chain `requestRetirement(id)`. Nothing else is needed from an operator: a root that runs with
`--pos-deployment` **and** `--pos-evm-rpc` builds the `Retirement` control itself, as the proposer, against the EVM state its selected proposal parent certified.
The acceptance rules are unchanged (`storage/pos_control.go`: `certifiedState`, `VerifyRetirement`, the liability anchor, the in-flight handoff and acknowledgement
exclusion). `POST /api/v1/pos/control` stays for explicit submissions.

## What a root does

1. **Discovery** (`rootchain/posretire`). Every root polls its execution client for custody's `RetirementRequested(uint64 indexed id, uint64 generation)`,
   Confirmations (8) blocks behind the head, from a persisted cursor. The cursor and the pending `(id, generation)` set live in `$UBFT_HOME/pos-retirements.json`
   (atomic writes; a file that cannot be read stops the node rather than forgetting requests). Logs are scheduling hints only: a proof authorizes, a log does not.
   Work is always keyed by `(id, generation)`: a request cannot be reset within a generation, a new generation never reuses an old proof.
2. **Preparation** (off the consensus loop). When a block is added to the tree it is the candidate parent of the next proposal. `Prepare(parent)` starts, for at most
   4 pending requests and with at most 4 proofs in flight, a witness build (`evmstate.BuildRetirementWitness`: the custody and registry slots the verifier reads,
   the deployment bindings included, one `eth_getProof` call per account for the fixed slots) at the **block hash** the parent certified, within 5 s. The result is
   cached by (EVM state root, block hash, id, generation); a request that is not retirable at that parent (live exposure, lot references, records not caught up) stays
   pending for a later parent, one retired in the registry is complete, one never requested at the certified states after 200 observations was superseded.
3. **Proposal.** The leader adds, after the mandatory closures and any submitted control, up to 4 Retirements **prepared for exactly its parent**, in ascending
   `(id, generation)`, stamped with the block's epoch and round. Each is trial-executed with the whole block; the witness is retained before the proposal is signed; a
   Retirement the root state refuses (liability anchor not reached, in-flight handoff, record cap) is left out of this proposal and never blocks it. Nothing waits for
   a proof: one that is not ready is for a later parent.
4. **Voters** fetch the retained witness by hash (existing path) and judge it against the same parent tuple as always. The child may certify a newer EVM block: that
   does not change the parent tuple of its Retirement, and no EVM production pause is needed. A quiet parent round keeps the state root and has no block hash: the control
   then names the zero block hash and the proof is fetched at the block that certified that root.
5. **Cleanup.** A request ends when a *committed* block has ordered its Retirement (`RetirementCommitted`), or the registry shows it retired. A Retirement already ordered
   on the proposing branch is not proposed again.

## Liveness and what it assumes

Retirement is optional, closure is not: a proposal never fails for lack of a Retirement. Inclusion needs the proof service to answer within the time between a block being
proposed and the next leader proposing on it (roughly a round trip), and an honest leader; under continuous EVM production a proof that arrives one block late is for the
wrong parent and the request waits for the next. The X4 live lane records proof latency, the parent tuple and the ordered/imported anchors for this reason.

## Flags

`--pos-evm-rpc URL` is now also accepted without an election in the deployment (it then only enables the Retirement builder); with an election it is still required.
