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

So a change on either side fails that side's own test first, and after regenerating, fails the copy check until the other repository
has the new file and the pin is moved.

## The scenario files (new with this suite)

One fixture set, the contracts' own published election result (`publication.json`), is taken through the histories the P85 lane runs:

| File | Producer | What it holds |
|---|---|---|
| `testdata/go-records.json` | bft-core (`XREPO_UPDATE=1 go test ./xrepo`) | The records the root's projection (`rootrecords.State`) emits, with the ids the root names and the digests it derives from the identity records: **recovery** (Closure of G, Closure of the Reserved J, RecoveryAck, Closure of K), **ack** (Closure of G, Ack, Closure of J), **session-closed**; and after each record, what the root holds |
| `testdata/custody-view.json` | contracts (`XRepoRecords.t.sol`) | Custody's state after applying those records verbatim, as custody reports it |
| `testdata/genesis/contracts-genesis.json` | bft-core (`XREPO_UPDATE=1 go test ./cli/ubft/cmd -run ContractsGenesisInput`) | What `ubft pos-relayer genesis --out-contracts` writes for the committed plan, trust base and FULL shard configuration |

Tests here: `xrepo/consistency_test.go` and `cli/ubft/cmd/pos_relayer_xrepo_test.go`. Tests there: `test/p85/XRepoRecords.t.sol`
(custody accepts the records with no word replaced, its state matches after every record, and the three disagreements of
2026-10-11 are each refused as one changed word) and `test/p85/XRepoGenesis.t.sol` (the genesis script deploys from the file and
custody holds the genesis assignment under the file's id).

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
| **Closure of the genesis assignment: id and digests the root derives, accepted verbatim** | Go -> contracts | this suite |
| **Closure of a primary assignment named by its result-derived id (not its assignment hash), Reserved (staged) and Active** | Go -> contracts | this suite |
| **RecoveryAck: the recovery assignment id the root announces, J's and K's offsets, rounds and epochs; K's digests under K's own id** | Go -> contracts | this suite |
| **Ack and SessionClosed payloads and their effect** | Go -> contracts | this suite |
| **Custody's resulting state (ids, digests, states, H rounds, closure anchors, offsets, session outcome) equals the root's model** | contracts -> Go | this suite |
| **The contracts genesis input: field names and types, and the genesis assignment id = the root's custody key of the genesis epoch over the FULL configuration** | Go -> contracts | this suite |

Not covered:

- **Evidence (slashing).** No shared vector, and by reading the two sides do not agree: `Evidence.sol` verifies
  `keccak256(abi.encode(VOTE_DOMAIN, network, domain, keccak256(key), epoch, round, payload))`, while the root signs the SHA-256 of
  a CBOR preimage (`rootchain/consensus/votesig`). A root's vote signature cannot satisfy `submitEvidence` as written. This needs a
  design decision, not a test.
- **Retirement record with the real reference digest end to end.** The exposure chain value is pinned (custody-digests.json) and the
  record shape is replayed (root-records-vectors.json), but no Go-produced Retirement is applied verbatim: it needs a generation with
  every exposure released.
- **Closure witness / handoff checkpoint path** (the root's own retained bundle, #563): Go-internal and Go <-> execution client; it
  has no Solidity consumer. Not part of this suite.
- **The registry (SealRegistry) as the record source.** The replay uses the test record source (`MockRootRecords`), as the other
  custody tests do; the registry import is pinned separately (root-records-import-vectors.json).
- **A second election after the first resolves**, more than one pending handoff besides primary plus recovery, and key rotation
  through an Ack.
- **ureth.** The execution client's hook is a third consumer of several of these files; it is not checked here.

## Changing a shared word

1. Change the producer and regenerate its file (the producer's test names the flag).
2. Run `python3 xrepo/check.py --bft-core . --contracts <checkout> --sync` to copy it to the consumer, and make the consumer's tests pass.
3. Open a PR in each repository. Each PR's pin points at a commit of the other that holds the same files (a PR head is fine).
