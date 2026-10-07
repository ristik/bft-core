# Later amendment: whole-token native bridge profile (B2 #63 / B4 #65, PR1)

Status: proposed normative amendment for the private development bridge, delivered by B2 #63 PR 1/n. Source design:
`briefs/bridge-b2b4-design-v2.md` (SOUND at its v2 re-check). This is a Markdown amendment, not a recompiled yellowpaper:
the seven `.tex` files and `repair.patch` stay as the snapshot. Read the snapshot, then accepted amendments, then this text
for the passages it names. Where they differ, this text governs for the **whole-token native UCT profile** only.

Nothing here activates in production. No native precompile, vault, gas price or benchmark acceptance is claimed; the
reference oracle is `bridgeprofile/` and its golden manifest is `bridgeprofile/testdata/bridge-pr1-vectors-v1.json`.

## A. Superseded passages (each checked against the snapshot text)

| Where (snapshot) | Snapshot says | Governs now (this profile) |
|---|---|---|
| `appendix-bridging.tex` §Cryptographic Primitives, "Nullifier accumulator" and "Batch insertion is ordered" (:23–:34) | An authenticated nullifier set with non-membership witnesses, inserted in order. | No accumulator and no ordered witnesses. Replay is a **nonce-keyed spent mapping** (section D). |
| `appendix-bridging.tex` Settlement, `ensure(x.A_old = A)` "the entire replay guard" (:251), Security Properties "Replay-freeness" (:282), Enshrined Settlement "Concurrent proofs against an old nullifier root require rebasing" (:369) | Replay guard is the accumulator root; concurrent proofs need rebasing. | Replay guard is `spentNullifier[n] == 0`; concurrent redemptions of different nonces do not conflict and need no rebasing. A second redemption of the same nonce fails with an already-redeemed outcome regardless of its nullifier. |
| `appendix-bridging.tex` Lock Operation (:62–:66), `d = H(LOCK_DOMAIN, χ, a_V, n, K)` | Digest binds chain, vault, nonce and the lock record. | `d = H(C("UNICITY_BR_LOCK", b(cfg), n, K))` where `cfg = H(Cfg)` (section C). This is an intentional tightening: the digest binds the full network, execution, verifier and profile identities as well as chain and vault. Contract and both SDKs use exactly this formula. |
| `appendix-token.tex` Mint Transaction (:160–:173) and Transfer Transaction (:180–:194), untagged six- and five-field tables | Untagged payload tables with the timeout `τ_Q` and a transmitted source hash and unlocking argument. | The adopted wire bytes are the pinned J/R serialization (section B): tagged, literal version `1`, reconstructed transfer source and owner, no timeout field. One parser; no layout version. |
| `appendix-token.tex` Signature Format (:276) "`V` is a 1-byte recovery identifier" | Does not say how `V` is used. | `V` is used: the signer is recovered and must equal the expected key (section B, "Unlock rule"). |
| `appendix-bridging.tex` Enshrined Settlement (:317–:319) "no split, merge or arbitrary mint-reason extension" | Restriction stated. | Enforced by the exact shapes below: one mint kind (tag 39049), fixed `data`, `null` intermediate data, one terminal burn. |

Passages checked and **left as they are**: the enshrined backing reason is already the CBOR array `(1, χ, a_V, a_A, n)`
under tag 39049 (`appendix-bridging.tex` :336) and is adopted unchanged; the return reason tag 39048 and its eleven fields
(:134–:150); the nullifier derivation shape `H(NUL_DOMAIN, h_cfg, btid)` (:157–:169, with the exact bytes below);
the storage layout interface of :325–:331; custody accounting `0 ≤ P ≤ D ≤ L` (:371–:379).

## B. Exact bytes

Notation: `C(...)` deterministic CBOR of the displayed array; `tag(t,x)` a CBOR tagged item; `H` raw SHA-256;
`b(x)` a byte string; `I(h) = 0x0000 || h`. Domain literals are ASCII **byte strings**. Integers use the shortest CBOR
unsigned encoding. Amounts are positive minimal big-endian byte strings of at most 32 bytes. No indefinite items, text
strings, maps, floats, booleans, duplicate fields, extra fields, trailing bytes or normalisation on decode.

| Object | Encoding |
|---|---|
| Predicate | `tag(39032,[1,b(encode_uint(type)),b(params)])`; signature type 1 with params a valid compressed secp256k1 key (33 bytes, prefix 02 or 03); burn type 2 with params exactly 32 bytes. The code bytes are `01`/`02`, never a text name. |
| Mint `M` | `tag(39041,[1,network,P0,b(salt32),b(type32),b(justification),b(data)])`; this profile requires non-null justification and data. |
| Transfer `T` | `tag(39045,[1,Pnext,b(mask32),dataOrNull])`; the source hash and source predicate are reconstructed, not on the wire. |
| Certification data `CD` | `tag(39031,[1,Psource,b(sourceHash32),b(txHash32),b(unlock65)])`. |
| `id` | `H(C(b(salt),network))`. |
| Mint source `h0` | `H(C(b(id),b(H("TOKENID"))))`. |
| Universal minter key | scalar `H(C(b("I_AM_UNIVERSAL_MINTER_FOR_"),b(id)))`; must be a valid secp256k1 scalar (1 ≤ k < n), else the mint is rejected. |
| Output state | `H(C(b(I(sourceHash)),b(mask)))`; the mint mask is `id`. |
| `txHash` | `H(exact tagged transaction bytes)`. |
| `sid` | `H(C(Psource,b(sourceHash32)))`, the predicate nested as a tagged item. |
| Unlock message | `H(C(b(sourceHash32),b(txHash32)))`, no extra prehash. |

**Unlock rule (mint and every transfer).** The unlock is exactly 65 bytes `r||s||id`; `1 ≤ r < n`; `1 ≤ s ≤ n/2`;
`id ∈ {0,1,2,3}`. Recover the signer from the message and `(r,s,id)`; recovery must succeed and equal the reconstructed
source key; then verify `(r,s)` against that key. Ids 2 and 3 are accepted only when recovery succeeds and matches.
The supplied id and a high-`s` signature are never normalised. A range check on the id is not sufficient. B1 seal
signatures keep their separate rule (optional suffix 0/1 ignored) and are not changed by this text.
Regression vector over the generator point: source hash `01`×32, tx hash `02`×32, key
`0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`, digest
`ab8c3e2ae6d6b14a5f9c7a1f3003ca5b8ebcf3d9cba43e45b16bdb222213588a`,
`r=7303acb5b7bab8529f540716e3bb91c02edfd535950b0a81efc558dc39589e4c`,
`s=615c4a64d26e3f07cbbcc8cce562e26319aa91ec6e9a59167e05b8da3eb15c7f`: `r||s||01` accepts, `r||s||00` rejects.

**Profile (selected by Cfg).**

* Type `ty = H(C("UNICITY_NATIVE_WHOLE",network,b(executionGenesis),b(vault)))`;
  asset `aid = H(C("UNICITY_NATIVE_UCT",network,b(executionGenesis)))` (`network` is a uint).
* Mint payload `data = C(b(aid),b(amount))`, exactly one asset. Intermediate transfers carry `data = null` (not the empty
  string). Only the final transfer carries data.
* Mint justification, carried as bytes: `tag(39049,[1,chainId,b(vault),b(zeroAddress),n])`, `n ≥ 1`, matching Cfg.
  Tag 39047, null, split reasons and every other kind are rejected.
* Salt at nonce `n`: `salt = H(C("UNICITY_BR_SALT",b(cfg),n))`; the mint salt must be exactly this value.
* Return reason `R = tag(39048,[1,chainId,b(vault),b(zeroAddress),b(ty),b(aid),b(recipient20),b(amount),b(zeroAddress),b(empty),0])`;
  the last three slots are fixed (no fee recipient, no fee, no deadline). The final transfer's data is exactly `R` and its
  recipient predicate is `Burn(H(R))` with the raw 32-byte hash as parameters. `recipient` is nonzero and not the vault;
  `amount` equals the whole genesis amount. The burn spends a signature-owned state and is terminal.
* Nullifier: `btid = H(C("unicity-burn-transition:v1",b(sid_burn),b(txHash_burn)))`,
  `eta = H(C("UNICITY_BR_NUL",b(cfg),b(btid)))`; `eta` and the lock digest are nonzero.
* Direct limits (DEV-DEFAULT, test ceilings, not a claim that the maximum fits a block): at most 64 transfers including
  the burn (at most 65 leaves), 64 KiB semantic input, 256 KiB envelope, CBOR depth ≤ 16, ≤ 32768 items. An over-limit
  input is a budget outcome with no state effect.

## C. Configuration, policy and envelope

`Cfg = C("UNICITY_BR_CFG",network,rootGenesis,chainId,executionGenesis,evmPartition,evmShard,vault,zeroAddress,ty,aid,
semanticProfileHash,tokenVerifierAddress,tokenVerifierCodeHash,b1ProfileHash,aggregatorPolicyHash)`, `cfg = H(Cfg)`.
`network`, `chainId`, `evmPartition` are uints (uint16, u64, u32); every other field is a byte string of fixed width:
32 bytes for the genesis, type, asset and hash fields, 20 for the address fields, native canonical shard bytes for
`evmShard`. (The design fixed the field list and the uint widths; the byte-string widths are a PR1 decision recorded here.)

`Policy = C("UNICITY_BR_AGG_ONE",aggregatorPartition,b(0x80),b(aggregatorShardConfHash))`: the shard is exactly the one
byte `80` (the native empty prefix), never the empty string; at most 128 bytes; decode then re-encode must equal the
input; `aggregatorPolicyHash = H(exact bytes)`. The aggregator partition differs from `Cfg.evmPartition`.

The proof envelope is `abi.encode(bytes policyBody, bytes history, Anchor[] anchors, LeafProof[] leafProofs)` with
`Anchor = (uint32 partition, bytes shard, bytes32 shardConfHash, bytes32 expectedStateRoot, bytes32 expectedIRHash, bytes uc)`
and `LeafProof = (uint16 anchorIndex, bytes32 bitmap, bytes32[] siblings)`. Decoding is canonical: re-encoding must
reproduce the input (rejecting noncanonical offsets, padding, aliases and trailing data), and declared counts are bounded
before allocation. Before any B1 call the composing verifier: (1) hashes the supplied body and compares it with
`Cfg.aggregatorPolicyHash` **before interpreting it**; (2) decodes it; (3) requires exactly one anchor whose tuple equals
`(aggregatorPartition,0x80,aggregatorShardConfHash)`; (4) requires every leaf proof's `anchorIndex = 0` and exactly one
leaf proof per exported leaf. A caller-supplied anchor table never chooses its own admission. Multi-shard routing, shard
splits and changed configuration are rejected until a separately reviewed B3 policy exists.

History projection (proof transport, not a token identity): `C([M,CD0],[[T1,CD1],...])` holding the unchanged tagged
transactions and certification data. Mutable certificates, leaf paths and EVM storage witnesses travel separately.

The kernel relation (`prepareLock`, `mint`, `return`) reconstructs every source state and owner, compares each `CD` with
the reconstruction byte for byte, recomputes `txHash` and `sid`, checks the unlock rule, rejects repeated sids and exports
every leaf `(sid,txHash)` in order. It never asserts inclusion, lock existence or aggregator admission.

## D. Vault replay and storage

Replay is a plain mapping keyed by the lock nonce: `spentNullifier[n]` goes from zero to `eta` once. One nonce binds one
token and amount, so competing burns with different `eta` contend on the same word. Permanent lock digests are never
deleted. Storage layout (full 32-byte words): slot 0 `lastNonce`, 1 `locked`, 2 `credited`, 3 `paid`, 4 `entered`,
5 `mapping(uint256=>bytes32) lockDigest`, 6 `mapping(uint256=>bytes32) spentNullifier`, 7 `mapping(address=>uint256)
claimable`. Logical slot `keccak256(abi.encode(key, base))`; trie key `keccak256(logical slot)`; account key
`keccak256(vault)`; stored values are canonical minimal RLP integers, left-padded to recover the bytes32 digest.

## E. Fixture published by this PR

A DEV fixture, not a production parameter (`bridgeprofile/build.go: NewFixture`): chain ID 31337, aggregator partition
11, EVM partition 7.

| Item | Value |
|---|---|
| Aggregator shard configuration hash | `c20ce7724f24578d66aebec43c08ef934f89bb4841b8756a0deca9af3c2104fc` |
| Exact policy bytes | `8452554e49434954595f42525f4147475f4f4e450b41805820c20ce7724f24578d66aebec43c08ef934f89bb4841b8756a0deca9af3c2104fc` |
| `aggregatorPolicyHash` | `b4e8d3d97dd64a7e1cb64198e8120aa72c029ff19bc88afd3ccd95002992b4fb` |
| `cfg = H(Cfg)` | `eed3d0a507e02bf8a73f5895701361110a9b4eaf4c3dd54307c8ec08b48ed6cf` |
| EVM configuration pin | partition 7, shard `80`; authenticated from the pinned execution genesis at activation, not by this PR |

The values above are regenerated by `go test ./bridgeprofile -update` and checked by `TestGoldenManifest`.

## F. Companion revisions and conformance

| Repository | Revision |
|---|---|
| bft-core oracle | this PR, `bridgeprofile/` |
| state-transition-sdk-rust (R) | base `7ed017effd4bd0a201ab2a9ef36793cb9924a048`, companion commit `366952967a5ae9ce1f1636ad6817745034e1dbd1` |
| state-transition-sdk-js (J) | base `ca0361bfc12deb7240d41d183e027f0603b3692b`, companion commit `5af57b0e9d6aba6a5dd0e304c73b901e75577adb` |

The golden manifest has 99 vectors across derivation, unlock, policy, envelope, prepare-lock, history and wire families.
The Go oracle, R and J each replay every vector with the exact sentinel reason. Independently, R and J construct the
`return-valid-{0,1,2,16}` histories with their own transaction, certification-data and signer types and reproduce the
oracle's bytes, signatures included. Reading one golden file in three languages is conformance; the independent
construction is the cross-check of bytes.

The R and J generic token verifiers are not changed: R's generic `Signature::verify` still ignores the recovery byte
(true/true on the regression vector); the bridge path implements the rule above (true/false). J's generic path already binds
the recovery byte through `SigningService.verifyWithPublicKey`; its bridge path adds the explicit scalar and id checks.

## G. What this amendment does not do

No native kernel at 0x0104, no B1 integration, no vault or composing verifier, no EVM backing-witness assembly, no gas
price and no activation. Measured oracle timings are reported in the PR; they price nothing. B3 multi-shard lineage, B5 public
proof service and B7/B8 public exit remain their own gates.
