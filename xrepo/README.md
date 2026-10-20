# Cross-repository consistency suite (bft-core <-> unicity-pos-contracts)

The root (this repository, Go) and custody/election (unicity-pos-contracts, Solidity) must agree on every identifier, digest and
record encoding that crosses between them. On 2026-10-11 four P85 lane runs were lost to disagreements no unit test saw, because each
side's tests used its own values for the other side's words. This suite pins the agreement with shared files and makes both CIs fail
when either side moves.

## How it works

- `fixtures.json` lists every shared file: its path in each repository, which side **produces** it, and the producer/consumer pair it
  pins. The file must be byte-identical in both repositories.
- The producer's own tests fail when the committed file is not what it produces now (Go: an `*_UPDATE`/write flag per generator;
  Solidity: `P85_WRITE_FIXTURES=true`, and every fixture test compares the committed file with what the contracts produce).
- The consumer's tests fail when it no longer accepts or reproduces the file.
- `check.py` compares the copies. Each repository pins a commit of the other (`fixtures.json` here, `xrepo/bft-core-pin.json` there)
  and its CI runs `check.py` against a checkout at that commit.

The `heads` job (after a merge to `integration/enshrined-evm`) and the contracts' `xrepo-heads` workflow (on `main` and daily) compare the
two branch heads instead of the pins, because a pin may name a pull-request commit whose counterpart never merged.

So a change on either side fails that side's own test first, and after regenerating, fails the copy check until the other repository
has the new file and the pin is moved.

## The scenario files (new with this suite)

One fixture set, the contracts' own published election result (`publication.json`), is taken through the histories the P85 lane runs:

| File | Producer | What it holds |
|---|---|---|
| `testdata/go-records.json` | bft-core (`XREPO_UPDATE=1 go test ./xrepo`) | The records the root's projection (`rootrecords.State`) emits, with the ids the root names and the digests it derives from the identity records: **recovery** (Closure of G, Closure of the Reserved J, RecoveryAck, Closure of K), **ack** (Closure of G, Ack, Closure of J), **session-closed**; and after each record, what the root holds |
| `testdata/custody-view.json` | contracts (`XRepoRecords.t.sol`) | Custody's state after applying those records verbatim, as custody reports it |
| `testdata/go-retirement.json` | bft-core (`XREPO_UPDATE=1 go test ./xrepo`) | The acknowledged history (Closure of G, Ack, Closure of J) followed by the **Retirements** of identities 1 and 2, whose reference digests are the evmassign model (`evmassign.ExposureID`/`ExposureChainStep`) of custody's exposure-chain storage word, which a root reads from custody's storage proof, with the registry's closed epoch of each record; and two conflicting scheme 2 root votes of identity 1's root key in J's epoch, built by the root's statement derivation (`types.DomainBoundStatement`) and signed by the root's signer |
| `testdata/genesis/contracts-genesis.json` | bft-core (`XREPO_UPDATE=1 go test ./cli/ubft/cmd -run ContractsGenesisInput`) | What `ubft pos-relayer genesis --out-contracts` writes for the committed plan, trust base and FULL shard configuration |

Tests here: `xrepo/consistency_test.go`, `xrepo/retirement_test.go` and `cli/ubft/cmd/pos_relayer_xrepo_test.go`. Tests there: `test/p85/XRepoRecords.t.sol`
(custody accepts the records with no word replaced, its state matches after every record, and the three disagreements of
2026-10-11 are each refused as one changed word) and `test/p85/XRepoGenesis.t.sol` (the genesis script deploys from the file and
custody holds the genesis assignment under the file's id) and `test/p85/XRepoRetirement.t.sol` (each record is imported by a
SealRegistry round and applied by custody verbatim; the retired identity's lot is held by the Go-signed equivocation charged to its
historical exposure, the clean lot matures and is claimed, and after settlement the held lot matures less its penalty and is claimed).

## Coverage

Producer -> consumer pairs that are pinned (file in `fixtures.json`):

| Pair | Direction | Since |
|---|---|---|
| Primary assignment id from the election result; identity records; exposure and key digests; possession proofs; publication slots | contracts -> Go | before (publication.json) |
| Exposure ids, exposure/key digests, exposure chains for genesis, primary, quantized, recovery assignments | contracts -> Go | before (custody-digests.json) |
| Storage slots of the custody and registry getters the root proves | contracts -> Go | before |
| Weight quantization | contracts -> Go (and ureth) | before |
| Record envelope, record id, payload shapes, closure repeat/conflict | Go -> contracts | before, with the Closure and Retirement digest words REPLACED by custody's own in the replay |
| Registry import calls and companions | Go -> contracts | before |
| Continuity and selection | Go -> contracts | before |
| **Closure of the genesis assignment: digests the root derives under the genesis id, accepted verbatim** (the id in the scenario is the contracts' fixture value; that the root DERIVES the deployed id is the genesis row below, with its own plan) | Go -> contracts | this suite |
| **Closure of a primary assignment named by its result-derived id (not its assignment hash), Reserved (staged) and Active.** J's id is read from the root's rule: a primary candidate naming the fixture's result is committed into a real `Orchestration` store and the scenario uses `CustodyAssignmentID` of that epoch (`roots_rule_test.go`), so a root that names a primary by its hash (run 27, #577) fails the golden test | Go -> contracts | this suite |
| **RecoveryAck: the recovery assignment id the root announces, J's and K's offsets, rounds and epochs; K's digests under K's own id** | Go -> contracts | this suite |
| **Ack and SessionClosed payloads and their effect** | Go -> contracts | this suite |
| **Custody's resulting state (ids, digests, states, H rounds, closure anchors, offsets, session outcome) equals the root's model** | contracts -> Go | this suite |
| **Retirement with the real reference digest, through the SealRegistry, to maturity and claim, with one held and one clean lot** | Go -> contracts | this suite |
| **A root-signed equivocation of a retired generation's key, attributed to its historical exposure** | Go -> contracts | this suite |
| **The contracts genesis input: field names and types, and the genesis assignment id = the root's custody key of the genesis epoch over the FULL configuration** | Go -> contracts | this suite |

## Evidence parity and remaining boundaries

Evidence digest parity now has a shared corpus: core #654 (`f07468a552`) and
contracts #46 (`0ede785663`). `s1ref/testdata/evidence-digest-corpus-v1.json`
is copied through `fixtures.json` to contracts and consumed by
`test/p85/EvidenceDigest.t.sol`. The contract rebuilds canonical scheme-2
VoteInfo/VotePreimage CBOR, verifies SHA-256 vote signatures and the separate
native seal signature for committing votes, and admits the Go-generated pairs.
The earlier Keccak/ABI root digest mismatch is fixed. This proves the root
signature/codec boundary, not third-party evidence collection or a live
slashing exercise. `testdata/go-retirement.json` adds one root-signed pair
(the root's statement derivation and signer) by the key of a generation that
retired before the evidence was submitted: the contracts charge it to the
historical exposure, hold that lot and debit it on settlement
(`XRepoRetirement.t.sol`). Rotation through an Ack is still not combined with
it. The EVM-domain codec remains undefined, and `Evidence.submitEvmEvidence`
is fail-closed: it always reverts with `EvmEvidenceUndefined`.

Still not covered by the lifecycle replay suite:

- **Closure witness / handoff checkpoint path** (the root's own retained bundle, #563): Go-internal and Go <-> execution client; it
  has no Solidity consumer. Not part of this suite.
- **The registry (SealRegistry) as the record source of the other histories.** `XRepoRecords.t.sol` uses the test record source
  (`MockRootRecords`); only the retirement case imports through the registry. The registry import is pinned separately as well
  (root-records-import-vectors.json).
- **The value of the recovery assignment id.** The rule is checked on the store (a recovery epoch is keyed by its assignment hash), but the id in the vectors is a label: K's hash covers the shard configuration, and the contracts' fixture has identities and a result, not a root shard configuration. Custody takes K's id from the RecoveryAck as an opaque word, so the pair that matters (K's digests under the announced id) is covered.
- **A second election after the first resolves**, more than one pending handoff besides primary plus recovery, and key rotation
  through an Ack.
- **ureth.** The execution client's hook is a third consumer of several of these files; it is not checked here.

## When the other repository's main moves

A merge to unicity-pos-contracts `main` that regenerates a contracts-produced fixture (`publication.json` changes whenever the deployed code does)
makes the copies here stale, and blocks every open paired PR, until someone syncs. **The author of the producing change syncs, in the same sitting, in
this order:** (1) merge the producer's change; (2) in the consuming repository, copy the file (`check.py --sync`), make its tests pass and move its pin
to the producer's MERGED commit, and merge that; (3) in the producer's repository, move its pin to the consumer's merged commit. The same holds in the
other direction for a file this repository produces. A paired PR that is open when this happens is updated from both mains first and then synced the
same way; its two halves merge one right after the other, contracts first, so that no third change lands between them.

## Changing a shared word

1. Change the producer and regenerate its file (the producer's test names the flag).
2. Run `python3 xrepo/check.py --bft-core . --contracts <checkout> --sync` to copy it to the consumer, and make the consumer's tests pass.
3. Open a PR in each repository. Each PR's pin points at a commit of the other that holds the same files (a PR head is fine).
