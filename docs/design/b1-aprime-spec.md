# B1 A′ specification and Go oracle (PR1a)

This is the inactive, pure slice of B1 #62, from `briefs/b1-design-v4.md`
(SHA-256 `e94c681529201bce9c945809f6154a99252f208b958f9f1d3889eb37d61e0713`).
Its immutable design anchors are bft-core `c57f012af8284cab214353841070ce368c6b001e`,
ureth `7e76c4e5d74ebb4fd88548d350d7229160b634df`, and bft-go-base
`01ab63a83bf5`. None of these fixtures authenticates a block or enables a builtin.

## Storage and projection

`b1state` is the model of the fresh registry at
`0xff00000000000000000000000000000000000002`. Fixed slots use
`keccak256(UTF8("unicity.seal-registry/" || name))`. `OperationalSlots()`
preserves the operational field names and meanings, omitting `layoutVersion`.
The live proof reader, runtime and genesis exporter are deferred to PR1b/PR3.
There is no new layout selector or old-format B1 parser.

Six B1 fixed words are `b1.network`, `b1.wCert`, `b1.profileHash`,
`b1.initialized`, `b1.head`, `b1.count`. Queue slots are
`keccak256(abi.encode(F("b1.queue"),uint256(i)))` for `i<K=W_cert+1`.
Epoch zero is occupied when count says so. Empty queues reset head to zero.
Entries use `keccak256(abi.encode(F("b1.entry"),epoch,field))`:

| Field | Meaning |
| --- | --- |
| 0–3 | present=1, native bodyKind, bodyID, activationCommitID |
| 4–7 | actual start, exclusive end (zero if open), hasEnd, signingScheme |
| 8–10 | signingConfigHash, memberCount, checked totalWeight |

Members use `keccak256(abi.encode(F("b1.member"),epoch,index,field))`.
Fields 0–7 are ID byte length, four ID words, two compressed-key words,
and weight. Bytes are left aligned with zero right padding. Integers are
zero extended. At most 64 members, 128 UTF-8 bytes per nonempty ID, unique
IDs and compressed secp256k1 points, positive weights, and a checked u64 total
are admitted. IDs sort by their raw bytes. Full members are stored.
An entry plus queue occupies at most 524 addressed words; B1 occupies
at most `6+524*K` words. Deletion clears metadata, populated members and queue.

`Select` derives half-open intervals from actual starts in complete,
genesis-rooted history, frozen at origin O. It retains exactly
`start<=O && (end==null || end>max(0,O-W_cert))`. Future-known activations
cannot close the origin tail. The boundary-crossing predecessor survives;
end=L expires. No internal epoch may be missing. `Delta` compares the entire
parent projection, including identity/configuration/members, then derives
new surviving epochs and the first actual successor's start as oldTipEnd.
Expired intermediate epochs are authenticated upstream and never materialized.
These exported model inputs are not authentication capabilities.

`Ring.Apply` copies the parent, prunes before appending, closes only a retained
old tip, and returns a disposable result. `Changes.Final` records final slot
values; `Changes.Trace` preserves every clear and insertion, including a queue
slot cleared and reused in one prefix. A final state diff cannot measure gross
work. `WriteAllowance` is a conservative profile calculation, never EVM gas.

The storage vector explicitly includes genesis queue/member words and the
pre-first-import operational origin zeros. Assigned root epoch is distinct.
The first-prefix bootstrap admission rules remain PR1b work.

## Canonical Update, profile and staged accounting

Update, entry and member are exact CBOR arrays, using core deterministic
encoding, with no maps/tags/indefinite lengths. The Update array is:

```
["UNICITY_B1_UPDATE", network, rootGenesisID, executionChainID,
 profileHash, parentHash, blockNumber, originEpoch, originRound,
 originIdentity, priorTipEpoch, oldTipEndOrNull, newEntries]
```

An entry is `[epoch,bodyKind,bodyID,activationCommitID,start,endOrNull,
signingScheme,signingConfigHash,members]`; a member is `[nodeID,key,weight]`.
Network is u16; executionChainID and other integers are u64; hashes are bstr32; keys bstr33.
Entries sort by epoch and adjacent live entries have adjacent epochs/intervals.
Each entry is <=16384 bytes; Update <=`4096+16384*K`; tokens <=`32+266*K`.
The schema has five containers at most, below depth 16. Decode/re-encode must
agree byte-for-byte. SHA256(Update) is the proposed root-input field.
`CheckBindings` compares candidate parent/height/origin exactly; it establishes
no BFT provenance or authenticated parent state.

The executable profile commitment is SHA256 of a core deterministic 28-item
array: the domain `UNICITY_B1_PROFILE`; network, W, deltaEV, deltaHold,
systemGas, forcedGas, maxGas, ordinaryCapacity, restGas, companionBytes,
otherCompanionBytes, K, C_max, token_max; rootGenesisID, executionChainID,
runtimeHash, compilerHash (executionChainID is u64; the other three are bstr32); seven bounds (64,128,16384,16,262144,24576,32768);
and the two exact policy strings in `Profile.Hash`. All runtime, compiler and
G_rest values in the vectors are explicitly synthetic. Final artifacts and
measured prices are not available. Missing pins are refused by the model.

The model checks `W<=deltaEV<deltaHold`, checked bounds, transport space
alongside other admitted fields, budget partition, and the envelope
`155936+15626944*K+G_rest`. Before allocation-free Update scanning it reserves
`2000+16*C`; after scanning it reserves `1000*T` before allocation, point
parsing, hashing or semantic checks. `SystemGas` adds admission, gross open
and gross finalize. No deletion refund funds another operation. Actual opcode
metering, outcome commitment and header/replay accounting belong to PR4.
These model inequalities do not certify any actual runtime or genesis budget.

## Caller oracle and vectors

`b1ref` accepts only `1:u8 | 0:u8 | count:u16 | Claim[count]`, in big endian.
Claim is partition:u32, shardLength:u16, shard bytes, configuration/state/IR
hashes (32 each), UC length:u32, UC bytes. UC count is one; shared count is
1–8. No authority view or authority hash is caller supplied. Claims must be
strictly increasing by (partition,shard bytes); disorder/duplication is false.

Full structural scanning precedes all semantic returns, registry access,
point parsing, hashing and native decoding. Null/empty path and signature
collections preserve their bytes and mean zero items. Null required objects,
path items, sibling hashes and signature values are malformed. Wrong signature
length or v outside {0,1} is malformed; accepted lengths with invalid scalars,
high-s or bad signatures are false. Unequal complete seals fail before crypto,
with S=max signature count. Malformed last claims override earlier false ones.
Native tagged signing bytes/folds and IR hash binding are preserved.

The explicit Registry is a simulation of already admitted EVM state. An absent
epoch is false; missing/invalid common state or impossible entry invariants is
`ErrInfrastructure`, distinct from caller exceptional halt. Phase 1 is false.
Weighted quorum is `total-(total-1)/3`; every supplied signer is checked, and
an invalid/unknown extra fails after an otherwise sufficient quorum.

Full candidate caller charge is
`60000+16*B+64000+6000*S+2000*N+250*P+1117700`, capped conservatively at
6,412,004. The first debit precedes allocation-free scanning; the second
precedes decoding/crypto. Malformed/OOG consume forwarded gas. Infrastructure
errors have no EVM result (`Run` reports used=0). RSMT is unchanged, stateless,
and does not authenticate its caller-supplied root; its maximum is 264,522.

`b1ref/b1gen` independently constructs native CBOR, trees and real signatures
without importing the oracle. `b1state/testdata/generate.go` independently
constructs the profile/Update bytes, commitments and storage slots without
importing `b1state`. Reproduce with:

```
GOCACHE=/private/tmp/gocache-b1pr1 go test ./b1ref -run TestGeneratorDeterministic -update
GOCACHE=/private/tmp/gocache-b1pr1 go run ./b1state/testdata/generate.go > b1state/testdata/projection.json
GOCACHE=/private/tmp/gocache-b1pr1 go test ./b1state ./b1ref ./b1ref/b1gen -count=1
GOCACHE=/private/tmp/gocache-b1pr1 python3 b1state/testdata/guard_mutations.py
```

## Explicit follow-up gates

PR1b must consume PR3's final pinned runtime/compiler/allocation/slot exports
and bounded G_rest, replace the existing deployment's registry proof/genesis
exports together, authenticate every intervening body/activation/supersession
and coupled assignment, derive explicit legacy/genesis configuration and retain
historical signing dispatch. It must bind canonical Update into the single
root input and durable companion, compare exact bytes/hash against a proven
parent on each pair's build/import/replay/recovery path, and validate the final
transport/system/ordinary capacity combination. Fixture injection cannot
replace these gates. No independent Rust lineage/old-Commit verifier is added.

PR4 must wire journal reads and normal warmth/revert behavior into every
execution/RPC/trace factory, disable stateful result caching, execute the
privileged prefix and gross accounting with the pinned runtime, and complete
actual STATICCALL/two-pair rotation/reorg/restart/replay acceptance plus the
x86-64/arm64 measurements. None of PR1a, PR1b or fixtures alone closes #62.

S1 at 0x0103 remains inactive. Its existing caller-view oracle is a separate
experimental relation, not an A′ authority source. B1's pruned window cannot
serve arbitrary historical voting evidence; S1 needs a separately accepted
committed source and retention horizon before integration. No ambient archive
lookup or fallback to current keys is introduced.
