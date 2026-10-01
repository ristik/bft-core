# Changing the EVM validator assignment (H3)

Applies to a profile-2 root chain whose EVM shard was generated with `--registry-layout 2` (the M3
launch genesis). A chain generated with layout 1 cannot change its EVM assignment and cannot be migrated.
Design: [h3-evm-assignment.md](../design/h3-evm-assignment.md). The lane that exercises this end to end is
a separate step; this is the procedure it follows.

## Rules

- **Validator-set changes are always coupled.** One handoff changes the root committee and the EVM assignment
  together: every successor root entity has exactly one delegated EVM validator (same weight, a different key),
  declared in `--bindings`. An EVM-only change (EVM validators change, root committee unchanged) is refused, and on a
  chain whose EVM shard configuration carries `validator_coupling=true` a root-only committee change is refused too
  (by every root validator at block validation, not only by the CLI). Keeping the committee and the EVM validators
  identical (a configuration-only boundary) is allowed.
- **Every handoff advances the root epoch**, including a configuration-only boundary with identical root keys.
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
# bindings.json: [{"rootNodeId": "<root entity>", "evmNodeId": "<its delegated EVM validator>"}, ...], one per successor root member
build/ubft root handoff evm-assemble --context context.json --validators validators.json \
  --pops a-pop.json,b-pop.json,c-pop.json --bindings bindings.json --out assignment.json
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

A bad or missing proof, a stale installed assignment, an assignment not coupled to `--next-trust-base` or a pending
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
