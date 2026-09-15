# F4c (#12): parent-registry proof reader

Issue: #12. Base: `integration/enshrined-evm` at `580fcaef`. Status: **implementation unit, inert**. Normative
source: `docs/design/f4a-seal-registry-contract.md` (#153) §7, with the review decisions of its §14.

The package `registryproof` answers #153 §7.1: what the SealRegistry held after an authenticated EVM parent
block. It verifies supplied evidence and returns a typed snapshot. It does not acquire evidence, store or
serve witnesses, choose a parent, or wire anything into a node. Nothing in production imports it
(`registryproof/inert_test.go`).

## 1. Interface

| Item | Meaning |
| --- | --- |
| `Context` | the configured pins: `a_sr`, `registryCodeHash`, `genesisCommitment`, `fullShardConfHash`, shard and root epochs, `evmGenesisHash`. All come from configuration verified by the #153 §5.3 startup check, never from the execution client |
| `Verify(ctx, parentHash, Evidence)` | §7.3 steps 1 to 7. `parentHash` is a 32-byte hash the caller has already authenticated as the certified parent; a block number or tag is not representable |
| `Evidence` | RLP header, account proof nodes, and exactly 22 storage proofs in §4.2 order. It has no field for an RPC summary value |
| `EvidenceFromGetProof` | arranges an `eth_getProof` result by storage key; summary fields are not decoded |
| `Snapshot` | opaque: an unexported record of the verified values, never changed after `Verify` returns. Accessors `ParentHash()`, `Number()`, `StateRoot()`, `Genesis()` and `LastAppliedRootRound()` (`clock.rootRound`) return copies; the zero `Snapshot` is not `Valid()` |
| `Fields` | a copy of every §4.2 field and the provenance, returned by `Snapshot.Fields()`. It holds only arrays, integers and booleans, and no function accepts it, so editing it changes no decision |
| `GenesisParentEligible` | the §7.3 E1 to E4 rule, separate from verification. It reads the snapshot's verified record, refuses the zero `Snapshot`, and requires the recorded parent hash to equal the `evmGenesisHash` `Verify` compared it with |

## 2. Refusals

Each §7.5 refusal is a distinct error, wrapped so `errors.Is` reaches it.

| Error | Raised when |
| --- | --- |
| `ErrUnavailable` | the evidence is empty: no header and no proofs. Partial evidence is invalid, not unavailable |
| `ErrBounds` | a §3 bound is exceeded, or the storage proof count is not 22; decided from lengths only |
| `ErrContext` | the context names another registry address or has a zero pin, or `parentHash` is zero |
| `ErrHeaderHash` | `Keccak-256(header bytes)` differs from `parentHash`; checked before the header is decoded |
| `ErrHeaderShape` | the header is not canonical RLP, lacks a Shanghai or Cancun field, or carries a later-fork field |
| `ErrAccountProof` | `trie.VerifyProof` fails for `Keccak-256(a_sr)`, or the proven account is not canonical RLP |
| `ErrCodeHash` | the proven account's code hash differs from the pin, or the proof shows no account |
| `ErrStorageProof` | `trie.VerifyProof` fails for a field's key, or an `eth_getProof` result has a missing, extra, duplicate or unknown key |
| `ErrValue` | a present value is not a minimal non-zero RLP string of at most 32 bytes, a scalar exceeds `uint64`, `certified.hasBlockHash` is not 0 or 1, a null block hash is not the zero word, or `phase` is neither 1 nor 2 |
| `ErrNotInitialized` | `layoutVersion` or `genesisCommitment` is zero |
| `ErrConfiguration` | layout version, genesis commitment, configuration hash or an epoch differs from the pins; a v1 cursor (`transition.cursor`, `inbox.consumed`) is non-zero (§10); the configured genesis is not block 0 or its storage is not exactly §5.4; or a block 0 is not the configured genesis |
| `ErrNotFinalized` | `phase` is open, or a non-genesis parent has `outcomes.round != round.authorized` or a zero `outcomes.commitment` |

A trie path the proof shows absent decodes to the zero word, and only after the step 5 checks pass. A
storage trie whose root is the empty-trie root proves every key absent by the root alone.

## 3. Bounds

#153 §14 left the numbers to this unit. They are checked while the evidence is copied into memory the
caller cannot reach, before any node is hashed or decoded.

| Bound | Value | Derivation |
| --- | --- | --- |
| header | 1,024 bytes | a Cancun header with the 32-byte `extraData` D1 uses is under 600 bytes (the anvil vector's is 577) |
| nodes per proof | 65 | every node on a path consumes at least one of the 64 key nibbles except the final leaf, so no valid path is longer |
| bytes per node | 1,024 | the largest node in a hashed-key trie is a full branch of 16 hash references and an empty value, 532 bytes |
| total | 256 KiB | 23 paths; the fixture's evidence over a 65-account state is 11.5 KiB, and the bound leaves more than an eightfold margin for a deep account path |
| storage proofs | exactly 22 | the §4.2 key list |

The work these bounds allow is at most 23 × 65 Keccak-256 hashes over at most 256 KiB, and the same number of
node decodings.

## 4. Proof verification and the dependency review (#153 §13 item 11)

Owner decision on #12: wrap go-ethereum's `trie.VerifyProof` at the pinned `v1.14.11`, as #153 decided,
rather than maintain a separate Merkle-Patricia walker. The wrapper supplies an owned, bounded, in-memory
map from the locally computed `Keccak-256` of each supplied node to that node. `VerifyProof` looks nodes up
by hash, so a node that does not hash to the reference its parent names is never found. The wrapper owns
the block, account, keys, bounds, absence handling and decoding.

**Link delta.** Measured with `go list -deps` against `./cli/ubft` at `580fcaef`:

- `ubft` today: 867 packages, unchanged by this unit because nothing imports `registryproof`.
- `rlp`, `crypto`, `common` and `common/hexutil` of go-ethereum are already linked into `ubft` (through
  `bft-go-base/crypto`), so header and account decoding add nothing.
- Importing `registryproof` from a production package would add 176 non-standard-library packages from 28
  modules not linked today: 19 go-ethereum packages (`trie`, `triedb`, `core/rawdb`, `core/types`,
  `ethdb/leveldb`, `ethdb/pebble`, `metrics`, `log`, `params`, `crypto/kzg4844` and others) and, among the
  largest, cockroachdb pebble (33 packages), mmcloughlin/addchain (22), cockroachdb/errors (19), goleveldb
  (12), consensys/gnark-crypto (12), cockroachdb/redact (10), crate-crypto/go-ipa (8) and getsentry/sentry-go (6).
- **Binary size.** A program with `ubft`'s `main` (`cmd.New(observability.NewFactory())`) builds to
  55,316,920 bytes on darwin/amd64; the same program that also references `registryproof.Verify` builds to
  64,268,912 bytes, 8.95 MB (16%) larger.
- **Startup.** Three runs each of a probe that only links `registryproof` against an empty program, both
  sleeping 200 ms, took 0.27, 0.22 and 0.23 s against 0.21, 0.20 and 0.20 s. That is a rough indication
  of tens of milliseconds of initialization on this host, not a benchmark.
- **cgo.** Three of those packages contain C code: `DataDog/zstd` (a vendored zstd), pebble's
  `internal/manual`, and gopsutil's `cpu`. `ubft` already builds with cgo (`go-ethereum/crypto/secp256k1`,
  `elastic/gosigar`).
- `go.mod`: `github.com/ethereum/go-ethereum` and `github.com/holiman/uint256` become direct requirements at
  their existing versions; `go mod tidy` adds the new modules as indirect. No existing requirement changes
  version.

**Licences.** go-ethereum's library packages are LGPL-3.0 (`COPYING.LESSER`); this unit links more of them
than the existing `crypto` import does, and bft-core is Apache-2.0. The 28 other modules are BSD
(pebble, goleveldb, snappy, flock, zstd, gopsutil, go-sysconf, addchain, bitset, pkg/errors, go-internal,
tmplfunc), MIT (sentry-go, tablewriter, go-runewidth, uniseg, kr/pretty, kr/text) or Apache-2.0
(cockroachdb errors, fifo, logtags, redact, tokenbucket; gnark-crypto, bavard, go-kzg-4844; go-ipa is dual
MIT or Apache-2.0). Whether the LGPL-3.0 linking obligations are acceptable for the distributed `ubft` binary
is an owner decision before a production call site is added; this unit adds none.

**Package initialization.** Linking the package runs these newly linked `init` functions in every process
that includes it, whether or not a proof is ever verified:

- `github.com/shirou/gopsutil/cpu` (linked through go-ethereum `metrics`) calls `Times(false)` and
  `Times(true)` from `init`. On Linux that reads `/proc/stat` (under `HOST_PROC` when set) at process
  start; on macOS it queries host CPU times. It also reads `SC_CLK_TCK` through `go-sysconf`. This is the
  only initialization found that performs I/O.
- go-ethereum `metrics` reads the `GETH_METRICS` environment variable and scans `os.Args` for a `metrics`
  flag, setting an in-memory `Enabled` flag. `ubft` has no flag of that name today; adding one later would
  also switch on go-ethereum's in-process metrics collection.
- go-ethereum `metrics/debug` allocates a slice, `log` installs a discard logger, and `trie/utils` decodes a
  fixed verkle curve point.
- `mattn/go-runewidth` (through pebble's `tablewriter`) reads `RUNEWIDTH_EASTASIAN` and the locale
  environment variables.
- The remaining `init` functions set in-memory state only: gnark-crypto (BLS12-381 field and curve
  constants, and its curve configuration registry), go-verkle and go-ipa (field constants), pebble
  (`batch.go`, `sstable`, skiplist internals), goleveldb (`leveldb/key.go`), cockroachdb/errors (error
  type and protobuf decoder registration), gogo/protobuf `types` and `golang.org/x/text` (table
  registration). None opens a file or connection.
- The `kzg4844` trusted setup (447 KB) is embedded in the binary and parsed lazily under `sync.Once` only
  when a KZG function is called. The cgo `c-kzg` backend requires the `ckzg` build tag and is not linked.

A probe program that only links `registryproof` shows one goroutine after initialization, the same as an
empty program, so no initialization starts a goroutine. No database is opened: `VerifyProof` reaches
`ethdb.KeyValueReader` only through the wrapper's map.

A smaller proof-only dependency is a possible later, separately reviewed reduction unit.

## 5. Evidence in the tests

- **Fixture tries.** `fixture_test.go` builds state and storage tries with go-ethereum's `trie` package, takes
  proofs with `Trie.Prove` and headers with `types.Header`, for the #153 §9 history: genesis, block 1
  (round 1), block 2 (round 2) and block 3 (round 4 after the round-3 repeat). The code hash is the merged
  registry artifact's.
- **Independent vector.** `testdata/anvil-registry-proof.json`, generated by `testdata/anvil-vector.sh` with
  anvil 1.8.1 (alloy-trie and revm), carries the merged registry runtime code at `a_sr` with the §9.4
  post-state, one mined Cancun block, its raw header and the `eth_getProof` result requested by block hash.
- One-element changes to the header, account proof and storage proofs; summary fields rewritten in a real
  response; proven absence versus truncation; each bound; each decoding rule; genesis; the §9.2a
  initial-timeout parent through E1 to E4; and replay of round 2 against block 1 while the head is block 3.

Neither source is evidence that `eth_getProof` history is available on a running reth node. The proof
window, retention and acquisition remain #153 §8, F6 (#14) and F7 (#15).

## 6. Not in this unit

No RPC client, no retained-witness store, no call site in `rootinput`, `shardnode`, `engineapi` or the CLI,
no genesis generation, no activation, no `v0` removal and no WithSealV1 advertisement. #10, #11 and #12 stay
open.
