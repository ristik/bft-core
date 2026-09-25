# M2 WP1: trust history and execution identity contract

Status: PR 1 encoding contract and vectors. No runtime trust transition or store migration is enabled here.

This applies [D3 §4](d3-weighted-consensus-trust-base.md#4-versioned-trust-base-identity-v2),
[D4 §§1–3](d4-epoch-handoff-state-machine.md#1-phases), and D-M2-4 in
`briefs/m2-decisions.md`. D3 and D4 are accepted designs per
`docs/pos/m0-acceptance.md`; their model APIs do not themselves authenticate a live handoff.

## Trust-base body and lineage

The existing `RootTrustBaseV1` remains version 1. Its `SigBytes()` excludes only
`Signatures`; its `Hash()` includes them. Legacy bytes and fixtures must stay
unchanged. The first v2 predecessor is
`SHA-256(CBOR(["UNICITY_TRUSTBASE_V1_TO_V2", networkId, v1Epoch,
v1HashIncludingSigs]))`, where the hash is from the exact v1 anchor. It is not
the raw v1 hash or a re-encoding of a v1 object. Each later predecessor is the
previous v2 body identity. Epochs advance by exactly one, with one network
context throughout; a missing, forged, or reordered body fails lineage
validation. This follows [D3 §4, First v1 → v2 transition](d3-weighted-consensus-trust-base.md#first-v1--v2-transition)
and [D4 §5](d4-epoch-handoff-state-machine.md#5-candidate-binding-cancellation-disposition).

The v2 body is deterministic CBOR, with shortest unsigned integers, definite
arrays, byte strings for hashes/keys, and UTF-8 text for IDs. The normative
field order is:

```
[2, networkId, epoch, earliestActivation,
 [[stakingID, nodeID, consensusKey, weight], ...],
 rootThreshold, stateSummary, changeRecordHash, predecessorHash]
```

Members are sorted bytewise by `nodeID` for the body. Empty or absent
`stateSummary` and `changeRecordHash` are CBOR null under D3 `optBytes`;
validating their provenance is a separate handoff admission check. `consensusKey` is a
33-byte compressed secp256k1 key; node IDs, staking IDs, and consensus keys
are individually unique. `rootThreshold = floor(2 * sum(weight) / 3) + 1`.
`BodyID = SHA-256(CBOR(body))`. Signatures on the current body and the
old-quorum endorsement witness are outside this hash; all valid quorum subsets
therefore name one body ID. Key possession, root ordering, and proof of the
endorsement quorum are separate admission checks, not inferred from the hash.
These rules implement [D3 §§3–4](d3-weighted-consensus-trust-base.md#4-versioned-trust-base-identity-v2).

For the enabled M2 PoA profile, every member weight must be exactly 1. D3's
weighted model describes later Q-path activation; its arithmetic does not
enable unequal-weight M2 assignments. A structurally valid weighted D3 body
with weight 2 is refused by this M2 contract.

## Actual activation and intervals

The body records `earliestActivation = A_min`, the bound known at Freeze.
The actual `A*` is fixed only by the old-quorum Commit. Its separate
`ActivatedTrustBase` record carries `{bodyIdentity, epochStart: A*,
activationCommitID}`. In a runtime consumer, the commit ID must resolve to
a finalized, authenticated D4 root commit for the exact body and boundary.
A 32-byte ID alone is not that proof. This contract's interval checks and
vectors are inert until the verifier is wired in PR 2 and activation in WP3.
See [D3 §4, activation](d3-weighted-consensus-trust-base.md#earliestactivation-vs-the-actual-boundary-a-joint-with-d4)
and [D4 §§1–3](d4-epoch-handoff-state-machine.md#3-authorisation-function-the-safety-core).

A historical store records contiguous half-open intervals `[start,end)` for
the v1 anchor and every activated v2 body. Before the first handoff, the
durable v1 anchor is `["UNICITY_V1_TRUST_ANCHOR_INTERVAL", 1, networkId,
epoch, v1HashIncludingSigs, start, null]` in deterministic CBOR. Closing it
replaces `null` with the authenticated first A*. The anchor is pinned to the
exact v1 hash including signatures. `start` for each v2 interval must
be the authenticated `A*`, at least the body's `A_min`; the prior end must
equal this start, and start must be below end. The active-epoch mapping by root round uses these
intervals, never `A_min`. This round-to-active-epoch mapping is not a signer
resolver for historical UCs: a suffix UC may carry the old root epoch at a
round at or above `A*`; verification selects its trust base by the UC's
`rootEpoch`. The durable activated-interval record is
`["UNICITY_ACTIVATED_TRUST_INTERVAL", 1, bodyIdentity, A*,
activationCommitID, end]` in deterministic CBOR; `end` is an unsigned
round for closed intervals and CBOR null for the open-ended current interval.
The open interval may only be last. The non-final-open check is redundant
with contiguous boundaries and retained as defense in depth. The body is
stored alongside the interval and checked against its ID. It refuses a partial,
overlapping, gapped, or
out-of-context chain rather than selecting a convenient entry. Epoch lookup
must validate the same lineage and activated record. No local REST insertion
or clock passage activates a body.
`rootinput/v2.go` transition refusal remains until WP3.

## Execution configuration identity

The existing v1 `ExecutionConfigIdentity` hashes the chain/fork schedule from
`registrygenesis/genesisjson.go:389`, but omits the companion fee parameters and
the CLI's `--engine-fee-collector` (`cli/ubft/cmd/shard_node_run.go:675`).
A v2 identity hashes deterministic CBOR in this exact order:

```
["UNICITY_EXECUTION_CONFIG_V2", 2, legacyExecutionConfigIdentity,
 maxGas, systemGas, baseFeeFloor, elasticity, changeDenominator,
 feeCollector20]
```

The legacy 32-byte identity binds the existing chain ID and supported fork
schedule without altering the old encoding. The five fee fields are the
companion `BlockProfile` values; `feeCollector20` is the exact 20-byte EVM
address. The supported profile requires positive fields, `systemGas < maxGas`,
`baseFeeFloor <= 2^62`, elasticity 2, and ordinary capacity divisible by 2.
The inert encoder hashes the supplied collector bytes, including zero. The
PR 2 runtime binder must refuse an unset zero collector and obtain the address
from checked configuration. Changing any fee field or collector changes the v2 ID.
The runtime binder reads the checked profile and collector from ureth over
the JWT-authenticated Engine connection, then compares the pinned identity
on restore. The journal descriptor uses payload version 3 when this ID is
present; a legacy descriptor is incompatible and refused.
On first initialization the JWT-protected companion is the source of the five
fee fields; only the collector is compared with the local setting. The first
accepted profile is pinned in the descriptor, so an incorrect companion at
initialization can establish an incorrect identity. Recovery compares the
entire pinned identity. A new Engine connection must repeat that comparison
before executing or signing with the replacement companion. The adapter
rechecks the pin before each later authenticated Engine RPC, including after
an HTTP reconnect.

Old descriptors and stores carry v1 identities and lack these fields. They
must not be silently reinterpreted as v2 or opened for M2 execution. An
incompatible store is refused; recovery uses the authenticated restore route
from D-M2-4. PR 1 adds only an inert encoding API and independent fixtures;
PR 2 owns the versioned store refusal and restore enforcement.

Reproduce: `python3 m2contract/generate_vectors.py --check` and
`go test ./m2contract ./evmroot ./registrygenesis`.
