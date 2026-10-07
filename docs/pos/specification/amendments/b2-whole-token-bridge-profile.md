# Later amendment: whole-token native bridge profile (B2 #63 / B4 #65), rebased on SDK 3.0.1

Status: proposed normative amendment for the private development bridge, B2 #63 PR 2/n: the rebase of PR 1 onto the
state-transition SDKs v3.0.1. Source design: `briefs/nbp-design.md` (the native-bridge-plugins design delta, which supersedes
the conflicting bytes of `briefs/bridge-b2b4-design-v2.md`; greenroom: no pre-3.0 decoder, migration or compatibility). This is a Markdown amendment, not a recompiled yellowpaper:
the seven `.tex` files and `repair.patch` stay as the snapshot. Read the snapshot, then accepted amendments, then this text
for the passages it names. Where they differ, this text governs for the **whole-token native UCT profile** only.

Nothing here activates in production. No native precompile, vault, gas price or benchmark acceptance is claimed; the
reference oracle is `bridgeprofile/`. It is an independent executable oracle and corpus *generator*, not a golden-file authority: the
sole normative bytes and released vectors live in `native-bridge-plugins/protocol/`, and `go run ./cmd/gencorpus -out DIR`
writes the candidate tree (`bridgeprofile/testdata/corpus-candidate.digest` pins its content address until the merged protocol
commit is pinned).

## A. Superseded passages (each checked against the snapshot text)

| Where (snapshot) | Snapshot says | Governs now (this profile) |
|---|---|---|
| `appendix-bridging.tex` §Cryptographic Primitives, "Nullifier accumulator" and "Batch insertion is ordered" (:23–:34) | An authenticated nullifier set with non-membership witnesses, inserted in order. | No accumulator and no ordered witnesses. Replay is a **nonce-keyed spent mapping** (section D). |
| `appendix-bridging.tex` Settlement, `ensure(x.A_old = A)` "the entire replay guard" (:251), Security Properties "Replay-freeness" (:282), Enshrined Settlement "Concurrent proofs against an old nullifier root require rebasing" (:369) | Replay guard is the accumulator root; concurrent proofs need rebasing. | Replay guard is `spentNullifier[n] == 0`; concurrent redemptions of different nonces do not conflict and need no rebasing. A second redemption of the same nonce fails with an already-redeemed outcome regardless of its nullifier. |
| `appendix-bridging.tex` Lock Operation (:62–:66), `d = H(LOCK_DOMAIN, χ, a_V, n, K)` | Digest binds chain, vault, nonce and the lock record. | `d = H(C("UNICITY_BR_LOCK", b(cfg), n, K))` where `cfg = H(Cfg)` (section C). This is an intentional tightening: the digest binds the full network, execution, verifier and profile identities as well as chain and vault. Contract and both SDKs use exactly this formula. |
| `appendix-token.tex` Mint Transaction (:160–:173) and Transfer Transaction (:180–:194), untagged six- and five-field tables | Untagged payload tables with the timeout `τ_Q` and a transmitted source hash and unlocking argument. | The adopted wire bytes are the SDK 3.0.1 serialization (section B): tagged, literal version `2` for mint, transfer, certification data and token, a trailing nullable deadline `e` (the snapshot's timeout role), reconstructed transfer source and owner. One parser; no layout version. The earlier text of this amendment ("literal version 1, no timeout field") is withdrawn: pre-3.0 shapes are rejected, not migrated. |
| `appendix-token.tex` Signature Format (:276) "`V` is a 1-byte recovery identifier" | Does not say how `V` is used. | `V` is used: the signer is recovered and must equal the expected key (section B, "Unlock rule"). |
| `appendix-bridging.tex` Enshrined Settlement (:317–:319) "no split, merge or arbitrary mint-reason extension" | Restriction stated. | Enforced by the exact shapes below: one mint kind (tag 39049), fixed `data`, `null` intermediate data, one terminal burn. |

| `appendix-bridging.tex` :336 enshrined backing reason `(1, χ, a_V, a_A, n)` under tag 39049 | A pointer-only reason. | Superseded: tag 39049 body version **2**, `(2, χ, a_V, a_A, n, LockProof)`, with the complete Unicity-certified EVM account/storage proof embedded (section B). The pre-3.0 pointer-only reason is rejected. |
| The earlier RSMT leaf statement "value = txHash / 34-byte imprint" | Leaf value is the transaction hash. | The certified leaf value is `v = H(C(b(txHash32), t))` with the reference time `t`; the raw 32 bytes go to RSMT membership. |

Passages checked and **left as they are**: the return reason tag 39048 and its eleven fields
(:134–:150); the nullifier derivation shape `H(NUL_DOMAIN, h_cfg, btid)` (:157–:169, with the exact bytes below);
the storage layout interface of :325–:331; custody accounting `0 ≤ P ≤ D ≤ L` (:371–:379).

## B. Exact bytes

Notation: `C(...)` deterministic CBOR of the displayed array; `tag(t,x)` a CBOR tagged item; `H` raw SHA-256;
`b(x)` a byte string; `I(h) = 0x0000 || h`; `e` is null or an integer in `[1,2^64-1]`; `t` is a u64 Unix-seconds reference time.
Domain literals are ASCII **byte strings**. Integers use the shortest CBOR unsigned encoding. Amounts are positive minimal
big-endian byte strings of at most 32 bytes. No indefinite items, text strings, maps, floats, booleans, duplicate fields, extra
fields, trailing bytes or normalisation on decode (the opaque native certificate inside an SDK inclusion proof is the one place
a map appears, and only the oracle's whole-token codec reads it). `NATIVE_BRIDGE_PROTO_VERSION = 2`.

| Object | Encoding |
|---|---|
| Predicate | `tag(39032,[1,b(encode_uint(type)),b(params)])`; signature type 1 with params a valid compressed secp256k1 key (33 bytes, prefix 02 or 03); burn type 2 with params exactly 32 bytes. Unchanged. |
| Mint `M` | `tag(39041,[2,network,P0,b(salt32),b(type32),b(justification),b(data),e])` (arity 8); this profile requires non-null justification and data. |
| Transfer `T` | `tag(39045,[2,Pnext,b(mask32),dataOrNull,e])` (arity 5); source hash and owner are reconstructed. |
| Certification data `CD` | `tag(39031,[2,Psource,b(sourceHash32),b(txHash32),e,b(unlock65)])` (arity 6, deadline before the unlock); `e` must equal the transaction's, including null. |
| Inclusion proof | `tag(39033,[1,CD,t,b(bitmap32‖siblings32…),UC])` (arity 5, version stays 1); every certified-leaf field is mandatory; a pending response is not a proof. |
| Token | `tag(39040,[2,[M,proof0],[[T1,proof1],…]])`; a certified transaction is exactly two elements; there is no separate reference-time slot. |
| `txHash` | `H(exact tagged M/T bytes)`; it now commits the deadline. `sid`, `h0`, output state, minter key and unlock message formulas are unchanged. |
| Certified leaf | `v = H(C(b(txHash32),t))`. Neither `txHash` alone nor a 34-byte imprint is the value. |
| `id`, `h0`, universal minter, output state, `sid`, unlock message | unchanged: `id=H(C(b(salt),network))`; `h0=H(C(b(id),b(H("TOKENID"))))`; minter scalar `H(C(b("I_AM_UNIVERSAL_MINTER_FOR_"),b(id)))`; output state `H(C(b(I(sourceHash)),b(mask)))`; `sid=H(C(Psource,b(sourceHash32)))`; message `H(C(b(sourceHash32),b(txHash32)))`. |

**Deadlines.** Constructors default to null; explicit deadlines are allowed throughout. For explicit `e`, `t < e` (equality
rejects). Null is never synthesised into a value. No check uses a clock, the EVM block time or the current root round; an old
transaction never expires because a later certificate is newer. Reference times are checked against the anchor's authenticated
InputRecord timestamp in the composition (section C), never against a caller-supplied scalar.

**Unlock rule (mint and every transfer).** Unchanged: exactly 65 bytes `r||s||id`; `1 ≤ r < n`; `1 ≤ s ≤ n/2`; `id ∈ {0..3}`;
recover and require equality with the reconstructed source key, then verify. The review's regression vector over `G` (source hash
`01`×32, tx hash `02`×32, key `0279be66…1798`, digest `ab8c3e2a…588a`,
`r=7303acb5…9e4c`, `s=615c4a64…5c7f`): `r||s||01` accepts, `r||s||00` rejects. The SDKs' generic verification is not relied on
(the Rust one ignores the recovery byte); B1 seal-signature rules are separate.

**Profile (selected by Cfg).**

* Identity family `unicity-native`. With `D = networkDecimal ":" rootGenesisHex ":" executionGenesisHex ":" chainIdDecimal ":" zeroAddressHex`
  (no leading zeros, lowercase 64-character genesis hex, 40 zero characters for the native asset, no `0x`):
  `ty = SHA256("unicity-bridge:unicity-native:" ‖ D)`, `aid = SHA256("unicity-bridge-coin:unicity-native:" ‖ D)`. The vault is
  not an input: replacement vaults represent the same asset and each has its own cfg, salt and lock.
* Value envelope: genesis `data = tag(39050,[1,[[b(aid32),b(amount)]],null])`: one inline asset, no memo, no extra asset.
  Intermediate transfers carry `data = null`; only the final transfer carries data (the return reason).
* Lock reason `J = tag(39049,[2,chainId,b(vault),b(zeroAddress),n,LockProof])`, `n ≥ 1`, carried as the mint's justification
  bytes, matching Cfg. `LockProof = [1,b(cfg32),b(trustBaseId32),b(evmPDR),b(evmUC),b(headerRLP),[b(accountNodeRLP)…],[b(storageNodeRLP)…]]`
  with exact arities 8 and the two node lists non-empty. Tag 39047, null, the pre-3.0 pointer-only v1 reason, receipt
  alternatives and every other kind are rejected. The relation scans the whole J within its bounds and binds `cfg`; it does not
  claim to authenticate the historical backing (offline verification, below, belongs to the plug-ins and the oracle's
  `VerifyMintBacking`).
* Salt at nonce `n`: `salt = H(C("UNICITY_BR_SALT",b(cfg),n))`; the mint salt must be exactly this value.
* Return reason `R = tag(39048,[1,chainId,b(vault),b(zeroAddress),b(ty),b(aid),b(recipient20),b(amount),b(zeroAddress),b(empty),0])`
  (unchanged; the last three slots are fixed: no fee token, no fee, no deadline, and are distinct from a request's `expiresAt`).
  The final transfer's data is exactly `R` and its predicate is `Burn(H(R))`. `recipient` is nonzero and not the vault; `amount`
  equals the whole genesis amount.
* Nullifier: `btid = H(C("unicity-burn-transition:v1",b(sid_burn),b(txHash_burn)))`, `eta = H(C("UNICITY_BR_NUL",b(cfg),b(btid)))`;
  `eta` excludes referenceTime, paths, anchor round, unlock representation and submitter.
* Direct limits (DEV-DEFAULT, test ceilings, intersected not additive): at most 64 transfers including the burn (65 leaves),
  **128 KiB** semantic input, 256 KiB envelope, CBOR depth ≤ 16, ≤ 32768 items, ≤ 2048 cumulative path steps. Embedded evidence:
  J ≤ 64 KiB; UC ≤ 16 KiB; PDR ≤ 16 KiB; header ≤ 2 KiB; ≤ 65 nodes per MPT, each ≤ 1 KiB, both lists ≤ 24 KiB; RLP depth ≤ 16;
  anchor InputRecord ≤ 512 bytes. All are checked before allocation or crypto; over-bound evidence is a budget outcome and never
  triggers an online fallback.

**Offline lock-proof verification (oracle: `VerifyMintBacking`).** Supported profile: one explicitly provisioned, fixed SDK
root trust base for both ordinary inclusion proofs and the embedded EVM UC, **unit-weight validators, one fixed epoch/committee,
SDK count quorum** (`quorumThreshold = N − (N−1)/3` for N distinct validators). Installation (`LoadTrustInput`) rejects every other
configuration (non-unit weight, another threshold, no epoch, duplicate nodes); weights are never flattened into unit weights.
Using only the token, that one installed document `B` (the SDK's JSON representation, pinned by the manifest) and the pinned
deployment (the shard genesis configuration and the vault runtime code hash): `J.trustBaseId = SHA256(B)` of the installed bytes
(an integrity binding, not authentication of the base); the seal's network and root epoch equal the base's and its root round is
at least `epochStartRound` (scope guards that reject use outside the fixed profile, not epoch evolution); the UC verifies under the
base with the SDK's own verification, unchanged; the carried PDR is canonical, hashes to the UC's configuration commitment and
changes no non-membership setting of the pinned genesis, with PDR epoch = IR epoch; `keccak256(headerRLP) = InputRecord.blockHash`
and `header.stateRoot = InputRecord.hash` under the pinned header profile; the vault account is proven by a strict MPT walk under
the state root with its code hash equal to the pin; the lock word at `keccak256(keccak256(abi.encode(n,5)))` is proven under the
account's storage root and equals the digest reconstructed from the actual mint. The MPT walk rejects non-canonical RLP, hash
references to nodes that must be embedded, unconsumed or over-consumed keys and every duplicate, unused or out-of-order node.
There is no mint-proof circularity: the lock digest commits cfg, nonce, amount, ID and recipient, not J or the mint hash. The
oracle renders `B` (`RenderTrustBaseJSON`) exactly as the pinned JS SDK 3.0.1 emits it (decimal-string numbers, unprefixed
lower-case hex, null absent hashes) and `LoadTrustInput` parses that form; native-bridge-plugins' `tools/sdk_trust_fixture.mjs --corpus`
requires every trust document of the corpus to be byte-identical to the SDK's own emission, and the Rust SDK 3.0.1 `from_json`
parses the same bytes. The pinned `B` is published as `config/sdk-root-trust-base.json` with its provenance.

**DEFERRED: common SDK trust-base work (ristik/bft-core#421), unsupported in the current bridge profile.** Epoch changes,
appended trust-base records, caller-driven retrieval of newer bases, arbitrary weights such as `(98,1,1)`, mixed
historical/current committees, interval closure, old-J validity through rotation and full B1/SDK seal-signature acceptance parity
are deferred. They are neither passing coverage nor activation prerequisites of this amendment; the oracle builds no weighted
verifier, epoch resolver, handoff verifier, trust history or epoch bundle, and tests only the rejection of non-unit configuration
and of epoch mismatch. A different epoch or base is unsupported and never silently installed; J is immutable after certification and
aggregator refresh stays within the one pinned base, preserving M/T, CD and the original `t`. SDK/native signature-acceptance
differences (TS binds the recovery parity; Rust's explicit-key seal check does not; B1 accepts 64-byte seals and an ignored 0/1
suffix) are recorded limitations; the strict token-unlock rule above is separate and unchanged.

## C. Configuration, policy, projection, result and envelope

`Cfg` is unchanged in field order: `C("UNICITY_BR_CFG",network,rootGenesis,chainId,executionGenesis,evmPartition,evmShard,vault,
zeroAddress,ty,aid,semanticProfileHash,tokenVerifierAddress,tokenVerifierCodeHash,b1ProfileHash,aggregatorPolicyHash)`, `cfg = H(Cfg)`;
`ty` and `aid` are the derived identifiers above and are recomputed by the kernel. The protocol version change changes cfg, salts,
token identity and lock digest globally; old locks and tokens are not reinterpreted.

`Policy = C("UNICITY_BR_AGG_ONE",aggregatorPartition,b(0x80),b(aggregatorShardConfHash))` is unchanged (shard exactly the byte
`80`, at most 128 bytes, aggregator partition differs from `Cfg.evmPartition`, `aggregatorPolicyHash = H(exact bytes)`).

**Projection (proof versus projection arities).** The B2 history is `C([M,CD0,t0],[[T1,CD1,t1],…])`. These are *projection*
tuples (arity 3), not SDK certified-transaction tuples (arity 2: `[tx, proof]`). The kernel strictly decodes the whole SDK token
before export (`ProjectToken`), takes every `t` solely from its proof, reconstructs transactions, sources and CDs, applies the
deadline equality and `t < e`, validates the strict unlocks and profile, rejects repeated SIDs, computes `v` and exports the
ordered leaves `(sid, txHash, referenceTime, leafValue)`. All projected times are untrusted until the leaf value is proven under
an admitted root. Aggregator refresh keeps `M`/`T`, CD, J and the original `t` byte for byte and only rebuilds paths against a
newer root.

**Kernel at the ABI.** Input `abi.encode(uint8 operation,bytes Cfg,bytes payload)` (0 prepareLock with payload
`C(n,b(amount),P0)`, 1 mint, 2 return). Output `abi.encode(bytes32("UNICITY_TOKEN_SEMANTICS"),bool valid,Result)`,
`Result = (cfg,nonce,amount,tokenId,salt,firstPredicateHash,lockDigest,releaseTo,nullifier,Leaf[])`,
`Leaf = (bytes32 sid,bytes32 txHash,uint64 referenceTime,bytes32 leafValue)`. A successful output is **448 + 128·m** bytes (m
leaves); timestamp words need zero high padding; `valid=false` is the all-zero empty Result. The oracle's provisional split: a
relation that does not hold is `valid=false`; malformed or over-budget input halts.

**Envelope.** `abi.encode(bytes policyBody, bytes history, Anchor[] anchors, LeafProof[] leafProofs)` with
`Anchor = (uint32 partition, bytes shard, bytes32 shardConfHash, bytes32 expectedStateRoot, bytes32 expectedIRHash, bytes uc, bytes inputRecord)` and
`LeafProof = (uint16 anchorIndex, bytes32 bitmap, bytes32[] siblings)`. `inputRecord` is the exact canonical native InputRecord
opening committed by `expectedIRHash`. Decoding is canonical (re-encoding reproduces the input) and counts are bounded before
allocation.

**Composition (oracle: `Compose`).** (1) framing, budgets, Cfg; (2) the policy body is hashed against `Cfg.aggregatorPolicyHash`
*before* it is interpreted, then exactly one anchor must equal the authenticated tuple; (3) the kernel result; (4) one leaf proof
per leaf, every `anchorIndex = 0`; (5) B1 0x0100 authenticates `(expectedStateRoot, expectedIRHash)`; (6) only then is the opening
trusted: `H(inputRecord) = expectedIRHash`, it decodes as `tag(39002,[1,round,epoch,previousHash,stateHash,summary,timestamp,blockHash,fees,executedTransactionsHash])`
under B1's field, null, width and canonical rules, its `stateHash` equals `expectedStateRoot`, and every leaf satisfies
`referenceTime ≤ timestamp`; (7) one B1 0x0102 call per ordered leaf with the same authenticated root, the raw 32-byte
`leafValue` and exactly its path. All-or-nothing. **B1 needs no change for SDK 3.0.1:** its primitives are generic
key/value membership and native UC/IR claims.

## D. Vault replay and storage (unchanged)

Replay is a plain mapping keyed by the lock nonce: `spentNullifier[n]` goes from zero to `eta` once. Permanent lock digests are
never deleted. Storage layout (full 32-byte words): slot 0 `lastNonce`, 1 `locked`, 2 `credited`, 3 `paid`, 4 `entered`,
5 `mapping(uint256=>bytes32) lockDigest`, 6 `mapping(uint256=>bytes32) spentNullifier`, 7 `mapping(address=>uint256) claimable`.
Logical slot `keccak256(abi.encode(key, base))`; trie key `keccak256(logical slot)`; account key `keccak256(vault)`; stored values are
canonical minimal RLP integers, left-padded to recover the bytes32 digest.

## E. Candidate corpus and fixture

`go run ./cmd/gencorpus -out DIR` writes the `protocol/vectors/{config,wire,unlock,policy,lock,history,proof,return,vault}/cases.json`
tree, `config/fixtures.json`, `config/semantic-profile.json` (a byte copy of native-bridge-plugins `protocol/profile-v2.json`) and the
pinned SDK trust document with its provenance; the output is deterministic. VERSION, `provenance.json` and the digests are added
by `tools/vectors.py seal`, which records the generator commit. Every case
carries its input bytes, operation, auxiliary inputs and the expected status, error family, exact sentinel name, relation result
with leaves `(sid,txHash,t,v)` and the canonical kernel output. `Replay` is the executable definition of each op; the Go test
replays every case from the generated files alone. All fixture values are DEV inputs (chain ID 31337, EVM partition 7, aggregator
partition 11, network 3). The 120 cases of the pre-3.0 manifest are retained by ID as mapped regression coverage (one case,
`derive-n160`, becomes `derive-n47` because its nonce is a cfg-dependent search); their bytes are not promised unchanged.

## F. Companion revisions

| Repository | Revision |
|---|---|
| bft-core oracle and corpus generator | this PR, `bridgeprofile/` |
| state-transition-sdk-js | v3.0.1 `f5f0737306901215860aa920a6ab570b699efba8` |
| state-transition-sdk-rust | v3.0.1 `635011b3d7066db6f3296e9cb8d2f24d4bd1fec7` |
| unicity-bridge (pattern and identifier precedent only) | `deb2b86c0a1fa0398928cb88caac9feccda6f4e9` |
| native-bridge-plugins | owns the normative bytes and the released corpus; independent TS and Rust SDK-based constructors reproduce the positive histories |

The abandoned pre-3.0 companion adapters (`sdk-js-bridge1`, `sdk-rust-bridge1`) are reference material only. The SDKs are neither
forked nor patched. JS v3.0.1 enforces the InputRecord timestamp bound; the inspected Rust v3.0.1 does not, so the Rust wrapper
and the composition add it. External verification wrappers (`NativeBridgeTokenVerifier`, `verify_native_token`) compose normal SDK
verification with the strict checks above.

## G. What this amendment does not do

No native kernel at 0x0104, no B1 integration, no vault or composing contract, no gas price and no activation. Measured oracle
timings are reported in the PR; they price nothing. B3 multi-shard lineage, B5 public proof service and B7/B8 public exit remain
their own gates.
