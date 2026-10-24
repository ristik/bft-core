# Bridge split lineage — protocol 6 specification

Status: development, unactivated. Normative for the Go oracle (`bridgeprofile`), the ureth B2/0x0105 port (PR3a), the contract result
ABI (PR3b) and the plug-ins (PR4). Design rationale: `briefs/bridge-split-tokens-analysis.md`. Plan: `briefs/bridge-split-plan.md`.

## 1. Scope

A token minted from a bridge lock can be split (burn-and-mint, SDK `TokenSplit`) any number of times. This protocol lets **one part**
be redeemed against the **original lock**.

In: one asset, a single-parent chain of any depth, redemption of a whole part. Out: joins, several locks or assets, partial burns of a
part (to redeem 3 of 10, split 3+7, then redeem the 3), fees, ZK.

`SplitProtoVersion = 6`. Protocol 5 (`NativeBridgeProtoVersion`) refuses every split and stays byte-for-byte unchanged in this
package; a fresh deployment replaces it (nothing is upgraded in place). Depth 0 of protocol 6 is an ordinary full redemption.

## 2. Wire formats (the SDK's, unchanged)

- **Manifest** `tag(39046, [b(root32)])`. One root: the bridge admits one asset. The burn transfer's data is exactly this item and its
  recipient is `Burn(SHA-256(manifest))`.
- **Sum tree** per asset, keyed by child token ID: leaf `SHA-256(0x10 || key || data || u256(v))`, node
  `SHA-256(0x11 || depth || hL || u256(sL) || hR || u256(sR))`, sums checked in 256 bits, amounts `1 <= v < 2^256`. `data` is the output
  commitment below. A key's side at a node is bit `depth` of the key, MSB first.
- **Allocation proof** leaf-first `[[depth, b(hash32), b(sum)], ...]`: at most 256 steps, depths strictly decreasing in `0..255`, sums
  minimal positive big-endian of at most 32 bytes. The empty proof is the one-leaf tree. Verification returns the reconstructed root sum.
- **Output commitment** `SHA-256(CBOR([b("UNICITY_SPLIT_OUTPUT"), b(sourceId), network, b(encodedRecipient), b(salt), b(childId), b(type),
  b(exactMintDataBytes)]))` — the child mint without its justification. `encodedRecipient` is the predicate item `tag(39032, ...)`.
- **Split justification** `tag(39044, [token, [proof]])`, `token` the complete burned parent SDK token (`tag(39040, ...)`) as an inline
  item, exactly one proof (one asset). The justification bytes are the child mint's `justification` field and are committed by the
  child's mint hash; **an ancestor's embedded inclusion proofs are never rewritten** (witnesses are refreshed in the envelope).

The Go oracle's sum tree, proofs, manifest and commitment are checked byte-for-byte against the Rust SDK
(`TestSumTreeMatchesRustSDK`, vector from `state-transition-sdk-rust` `7ed017e`). JS parity is PR2.

## 3. The relation

`VerifyLineageReturn(cfg, history)`. `history` is the redeemed part's compact B2 projection (unchanged format). Its ancestry is read
from the exact justification bytes of its mint; nothing is duplicated into independent history blobs.

1. **Walk** (part to root). While the mint justification is a split reason (`tag 39044`): decode it strictly, decode the embedded token
   strictly (`DecodeToken`), project it, continue with the parent. A lock reason (`tag 39049`) ends the walk at the root. Any other
   justification: `ErrMintJustif`.
2. **Verify** root first, one shared set of state IDs for the whole lineage (a repeated state anywhere, including a child reusing an
   ancestor's token ID: `ErrRepeatedSID`). For each token: the existing mint and transfer checks (network, type, signature recipient,
   exact single-asset data, certified transition and unlock for every step, intermediate transfers signature-owned with null data). The
   root's mint is the lock reason with the derived salt; a child's salt is free and its ID is `H(C(salt, network))`.
   Every token needs at least one transfer (its terminal burn).
3. **Terminal transfer.** Of every token but the part: `Burn(H(manifest))` with the manifest as data (`ErrSplitBurn`, `ErrSplitManifest`;
   a return reason is not a manifest, so a token cannot be both returned and split). Of the part: the return burn of the protocol 5
   rules with the amount equal to the **part's** amount (`ErrReturnAmount` for any other).
4. **Edge** (parent to child): the child's proof verifies for key = child ID, data = commitment(parent ID, child mint), value = child
   amount against the parent's manifest root (`ErrSplitProof`), and the reconstructed root sum equals the parent's authenticated amount
   (`ErrSplitSum`). Network and type equality with the parent follow from both being checked against `cfg`.

No time ordering between levels is required: each leaf is witnessed against its own seal (`ErrIRTime` per leaf as in protocol 5).

## 4. Leaves and witnesses

Leaves are exported root-first: for each token (root, ..., part) its mint leaf, then its transfers in order, the terminal burn last.
`L = sum over tokens (1 + transfers)`; with depth `d` and `T` ordinary transfers, `L = 2d + 2 + T`. The envelope ABI is **unchanged**
(`policyBody, history, anchors, leafProofs`); `leafProofs` has one entry per leaf in this order, `PlanAnchors` as in protocol 5. The
`history` field is the part's projection only.

## 5. Result (BRIDGE_COMPOSE_V2)

Marker `bytes32("UNICITY_BRIDGE_COMPOSE_V2")`, fifteen words, status table = protocol 5's with the split reasons appended:

| word | field | meaning |
|---|---|---|
| 0 | marker | |
| 1 | status | 0 ok; table in `config/compose-status-v2.json` |
| 2 | cfg | |
| 3 | nonce | **root** lock nonce |
| 4 | amount | **root** lock amount — the amount `lockDigest` commits; never the part's |
| 5 | tokenId | root token ID |
| 6 | salt | root salt |
| 7 | firstPredicateHash | root's first owner |
| 8 | lockDigest | root lock digest (`LockDigest` over the root amount) |
| 9 | releaseTo | the part's return recipient |
| 10 | nullifier | the part's final burn nullifier (`H(UNICITY_BR_NUL, cfg, burnId)`) |
| 11 | leafCount | `L` of the whole lineage |
| 12 | partTokenId | the redeemed token (`== tokenId` at depth 0) |
| 13 | partAmount | its whole amount (`== amount` at depth 0) |
| 14 | splitDepth | `d`; 0 is an ordinary redemption |

New statuses, appended in this order: `ErrSplitJustif`, `ErrSplitProofCount`, `ErrSplitProofShape`, `ErrSplitManifest`, `ErrSplitBurn`,
`ErrSplitProof`, `ErrSplitSum`, then `ErrCertScan` and `ErrCertSigLength`: the strict decode of an embedded ancestor token scans each
of its certificates (outside the native/SDK codec intersection is a status, never an unmapped error; protocol 5 projections carry no
certificates). The standalone kernel 0x0104 and `prepareLock` are unchanged and depth 0 only; the mint operation of
0x0105 refuses a split reason (`ErrMintJustif`).

**Vault rules assumed by the result** (PR3b): the stored digest equals `lockDigest`; `amount == lockedAmount[nonce]`;
`0 < partAmount <= lockedAmount - redeemedAmount`; `spentPart[nonce][partTokenId] == 0`, then store `nullifier`; credit `partAmount`
only; the part key comes from the verified result, never from the caller.

## 6. Work charges

The protocol 5 schedule (`100000 + 2B + 20J + 16000L + 6000Q + 29900E + 2000A + 250P + 50K*ceil(log2 K)`) applies with `L` the whole
lineage, plus, each charged before the work it pays for, in walk order: `16 * len(outer mint)`; for each split justification descended
into `16 * len(justification)`, then `20 * items`, then `16000 * (1 + transfers)` of the parent; for each edge
`20000 + 1500 * steps`. The byte term makes the quadratic re-hashing of nested prefixes visible: `W = sum of nested bytes`.

These are trial values. The oracle's estimate (`TestNativeComposeV2GasByDepth`, structural embedded proofs, one seal, 2-owner tokens):

| depth | leaves | input B | gas |
|---|---|---|---|
| 0 | 3 | 4,736 | 216,496 |
| 1 | 6 | 7,968 | 382,158 |
| 2 | 9 | 11,264 | 587,850 |
| 8 | 27 | 31,616 | 2,649,096 |
| 32 | 99 | 116,992 | 25,013,536 |

Depth 32 is admitted: there is **no depth, transfer-count or gas cap** (owner §36); depth is bounded only by size (the 2 MiB envelope and
`MaxTokenBytes` for each nested token) and by the gas the caller supplies. The port must not add a separate cap.
The oracle decodes each nested token twice (the justification scan, then `DecodeToken`) but charges its items once; the native port
scans once and charges the same single scan (ureth#84 does).

**Native timing (ureth#84, release build, one machine, median of 30).** `run_v2` through the Rust verifier with the corpus claim
verdict (no EVM context and no registry journal: not the precompile provider), so the lineage relation, the anchor and input-record scans and the RSMT memberships are timed; B1's certificate verification
is not (the V1 bench covers it). Inputs are the oracle's depth chains (2-owner tokens, one seal, structural embedded proofs); the gas
differs slightly from the table above because the keys differ.

| depth | leaves | input B | gas | median | ns/gas |
|---|---|---|---|---|---|
| 0 | 3 | 4,736 | 216,496 | 1.72 ms | 7.9 |
| 1 | 6 | 7,968 | 382,158 | 3.50 ms | 9.1 |
| 2 | 9 | 11,328 | 588,478 | 5.07 ms | 8.6 |
| 8 | 27 | 31,552 | 2,648,468 | 15.6 ms | 5.9 |
| 32 | 99 | 117,088 | 25,014,478 | 59.4 ms | 2.4 |

The same machine runs revm's SHA256 precompile over 64 KiB at 15.2 ns/gas. The schedule is therefore not under-priced against SHA256
at any depth, and grows more conservative with depth (the 16 gas/byte nested-prefix term). The cost per leaf is flat at about 0.58 ms
(signature recovery and hashing), which the 16,000-gas leaf term alone does not cover; the other terms carry the total. **No constant
is retuned**: the schedule stays as trial values. Still to measure before activation: a depth sweep through the production provider
with the real registry in the journal (the V1 `bench` example with cases from the Go `genbench`), and the fan-outs 2/16/256 (a
fan-out only changes the proof steps, 1,500 gas each). Wallets price from the full estimate before burning.

## 7. Corpus

`testdata/split-corpus` (format `native-bridge-split-vectors/1`, `BuildSplitCorpus`), separate from the sealed protocol 5 corpus:
`sum-tree` (trees of 1..256 leaves, depth 255, builder refusals, proof and codec negatives, commitment vectors), `lineage` (depth 0,
1 with both siblings, 2, 3, 8, fan-out 16 and 256, real and structural embedded proofs, refreshed witnesses, 28 negatives) and
`native` (BRIDGE_COMPOSE_V2 twins, exact/short gas, ABI halt) and `mutation` (one real-proof depth-2 input and 400 seeded 1-3 byte patches with the oracle's status and gas, so a second implementation is compared on malformed embedded tokens, proofs and certificates). The generator asserts every negative fails for exactly its named
reason. Regenerate with `BRIDGEPROFILE_UPDATE_SPLIT_CORPUS=1 go test ./bridgeprofile -run TestSplitCorpus`. PR5 seals and imports it.

## 8. Open items

- Measured native constants (PR3a; what is measured and what is still to measure is in section 6); JS and Rust SDK byte parity and pinned revisions (PR2); fail-closed issuance policies, envelope
  witness refresh and durable split/burn/mint recovery in the plug-ins (PR4).
- Cross-SDK vectors (`state-transition-sdk-js#11` `tests/fixtures/bridge-split/v1`) to be replayed against this oracle before PR5.
