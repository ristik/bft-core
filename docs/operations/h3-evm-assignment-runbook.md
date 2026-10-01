# Changing the EVM validator assignment (H3)

Applies to a profile-2 root chain whose EVM shard was generated with `--registry-layout 2` (the M3
launch genesis). A chain generated with layout 1 cannot change its EVM assignment and cannot be migrated.
Design: [h3-evm-assignment.md](../design/h3-evm-assignment.md). The lane that exercises this end to end is
a separate step; this is the procedure it follows.

## Rules

- **One change at a time.** The EVM assignment and the root members change in separate handoffs. A
  proposal carrying `--next-evm-assignment` whose `--next-trust-base` also changes root members is refused.
- **Every handoff advances the root epoch**, including an EVM-only rotation with identical root keys.
  `--next-trust-base` is therefore the current trust base at the next epoch. Publish that trust base:
  offline verifiers need the body for each rotation's root epoch.
- **Acknowledge before the next handoff.** While the installed assignment has no certified
  acknowledgement only a supersession (below) may follow.
- **Every successor key proves possession**, retained keys included, over the exact context of this
  attempt. A proof cannot be reused for another attempt, predecessor or frozen parent.

## 1. Choose the frozen parent and read the context

```sh
build/ubft root handoff evm-context \
  --root-rpc REPLACE_LOCAL_OLD_VALIDATOR_RPC \
  --frozen-parent REPLACE_CERTIFIED_EVM_PARENT_HASH \
  --out context.json
```

`context.json` carries the network, the predecessor root body, the attempt (an aborted attempt n makes
the next one n+1: collect proofs again), the frozen parent, the installed PDR and whether its
acknowledgement is pending. Also confirm the successor nodes can restore the parent from the archive in
time; possession is not availability.

## 2. Collect proofs of possession (offline, by each successor key holder)

`validators.json` is a JSON array of `{ "nodeId", "sigKey", "stake": 1 }` (sorted by node id, unique ids and
keys, at most 64).

```sh
build/ubft root handoff evm-pop --context context.json --validators validators.json \
  --node-id REPLACE_NODE_ID --key-conf REPLACE_KEY_CONF > REPLACE_NODE_ID-pop.json
```

The command refuses a key that is not the node's successor key.

## 3. Assemble the assignment

```sh
build/ubft root handoff evm-assemble --context context.json --validators validators.json \
  --pops a-pop.json,b-pop.json,c-pop.json --out assignment.json
```

It checks every proof under the context before writing the file and prints the assignment hash to compare
out of band.

## 4. Propose

```sh
build/ubft root handoff propose \
  --next-trust-base next-trust-base-epoch-N+1.json \
  --next-evm-assignment assignment.json \
  --frozen-parent REPLACE_CERTIFIED_EVM_PARENT_HASH \
  --root-rpc REPLACE_ROOT1,REPLACE_ROOT2,REPLACE_ROOT3
```

A bad or missing proof, a stale installed assignment, a combined root change or a pending
acknowledgement is refused **before** any endorsement is signed. After H commits, restart the root
validators with `--install-handoff-epoch N+1` as for any handoff; each fetches the bundle (delivery
protocol `/unicity/root-handoff-bundle/2.0.0`), which carries the candidate, and derives and installs the
configuration before it serves a block. The successor EVM set restores the parent and certifies the
acknowledgement block; ordinary transactions resume after it. Aggregator shards keep certifying throughout.

## Before H: abort and retry

`build/ubft root handoff abort` (see [root-handoff-abort.md](root-handoff-abort.md)) discards the pending
assignment only. Retry with attempt+1: fresh context, fresh proofs, possibly a different assignment. Only the
committed attempt's assignment is ever installed.

## After H: the successors cannot acknowledge

If enough successor nodes are unavailable after H, the EVM shard waits: root progress and aggregators are
unaffected and no certified block is rolled back. Replace the unacknowledged assignment:

```sh
build/ubft root handoff evm-assemble ... --supersede --out supersede.json   # context read after the stall
build/ubft root handoff propose ... --next-evm-assignment supersede.json --frozen-parent <the same P>
```

The candidate must extend the committed chain this validator has derived (the same P, the superseded H
and the acknowledged base), and the previous set's late acknowledgement is refused because only the newest
installed set is in the shard trust base. One folded acknowledgement summarizes up to 64 consecutive
committed steps.

## Operator guards

- `PUT /api/v1/configurations` refuses the EVM shard's configuration after genesis; the derived index is
  written only from committed history.
- A root node restart repairs the derived index before it loads blocks. If committed history is missing the
  node refuses to start rather than use the genesis or retired configuration; restore the handoff bundles
  (archive replicas) and restart.
- Offline verification of a mint after a rotation needs only the bundle (version 2, carrying the PDR), the
  expected claim, the genesis pin and the trust base for the UC's root epoch.
