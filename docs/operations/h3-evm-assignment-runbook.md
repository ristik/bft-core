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

## 1. Read the context

```sh
build/ubft root handoff evm-context \
  --root-rpc REPLACE_LOCAL_OLD_VALIDATOR_RPC \
  --out context.json
```

`context.json` carries the network, the predecessor root body, the attempt (an aborted attempt n makes
the next one n+1: collect proofs again; so is a Prepare whose freeze lapsed), the installed PDR and whether its
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
  --root-rpc REPLACE_ROOT1,REPLACE_ROOT2,REPLACE_ROOT3
```

`propose` plans the handoff, has the root order a Prepare (which freezes the EVM and binds the frozen parent) and
then collects the endorsements of that Prepare-bound state; it waits for the Prepare (`--prepare-timeout`, default 60 s)
and needs no parent. If the Prepare gets no Freeze within 24 root rounds the freeze lapses, the EVM certifies again and
the attempt is dead: read the context again (attempt+1) and re-run it.

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
build/ubft root handoff propose ... --next-evm-assignment supersede.json
```

The candidate must extend the committed chain this validator has derived (the Prepare-bound P, the superseded H
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

## Aggregator node-key replacement in the same handoff

A handoff may also replace the node keys (validators only) of existing aggregator shards: no `proof_type` or other setting
changes, no aggregator freeze, one change per shard, at most 8 per handoff. The EVM/aggregator keys and the root keys are
distinct everywhere: no root key may be any entity's EVM key.

1. Read the context as above (`evm-context`): every new aggregator key proves possession over the same attempt context.
2. For each new aggregator key, run on its holder: `build/ubft root handoff evm-pop --context context.json --validators agg-validators.json
   --node-id AGG_NODE --key-conf AGG_KEYS --installed AGG_INSTALLED_SHARD_CONF.json` (the shard's currently installed
   configuration, not the EVM one).
3. `build/ubft root handoff shard-assemble --context context.json --installed AGG_INSTALLED_SHARD_CONF.json --validators agg-validators.json
   --pops agg-pop.json --out change.json`.
4. Add `--changes change.json[,change2.json]` to `evm-assemble` and propose as usual. Every root validator refuses, before it
   endorses and again at block validation, a change that does not replace exactly the shard's installed configuration, that
   changes anything but validators and epoch, that targets the EVM or control partition, or whose shard still has an
   unacknowledged earlier replacement.

At the first new-root block the new keys install, the shard's technical record advances to the new epoch and the root sends a
repeat certificate; the retired key's requests are refused from that block. The aggregator restarts with its new key and resumes
from that repeat certificate. A supersession carries no aggregator changes (those of the superseded H are already active), so
while an EVM acknowledgement is pending an aggregator key change must wait for it.

`PUT /api/v1/configurations` is refused under the unified profile, and a root restarted with an edited shard configuration
file (any partition) is refused: after genesis every configuration comes from committed handoff history.

**Liveness corner.** While an EVM acknowledgement is pending only a supersession is admitted, and a supersession carries no
aggregator changes, so a stuck acknowledgement also blocks an emergency aggregator key rotation until it is acknowledged or
superseded.

**Retired-key window.** A request signed by a key retired by an activated handoff is ignored by every root from the activation
block on (the executed shard state, not the last committed one, decides membership); it is never certified. This covers the EVM
shard's retired keys as well.

**Genesis files.** After genesis the shard configuration set is fixed: a root accepts only a byte-equal reload of its genesis
entries (any other epoch, keys, activation round, partition or shard is refused), and refuses to start if a stored shard's
configuration hash differs from the one committed history derives. Before the first start, check every genesis shard
configuration file against the pinned T1 manifest hash: a fresh database accepts the set it is given.
