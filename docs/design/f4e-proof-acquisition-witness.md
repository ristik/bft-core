# F4e (#12): exact-block proof acquisition and witness capture

Issue: #12. Base: `integration/enshrined-evm` at `1f1e126e`. Status: **measurement and inert implementation**.
Normative source: `docs/design/f4a-seal-registry-contract.md` (#153) §7 and §8.

This unit measures when the pinned reth serves historical registry proofs, and adds the package
`registrywitness`. The package acquires the evidence for an exact authenticated parent hash, accepts it only
through `registryproof.Verify`, and keeps `witness(B)` in memory for the child of B. Nothing in production
imports it (`registrywitness/inert_test.go`). Durable retention, restart and archive serving are left to
separate units (§5).

## 1. Measured behaviour of the pinned reth

`registrywitness/testdata/reth-proof-window.sh` ran the local pinned build (`189c0df3`, reporting
`reth/v2.5.0-189c0df/x86_64-apple-darwin`). Each run used dev mode with a 2-second block time on the
`registrygenesis` vector genesis. It requested block 1 and genesis by hash while the head advanced. Each
`eth_getProof` call was bracketed by `eth_blockNumber`, and a sample was kept only when the head did not move
during the call. `testdata/reth-proof-window.json` records the result. The script follows the fail-closed rules
of the #157 evidence script.

| `--rpc.eth-proof-window` | `eth_getProof` by hash served at head distance | refused from distance |
| --- | --- | --- |
| 0 (default) | 0 | 1 |
| 3 | 0, 1, 2, 3 | 4 |

- **Refusal:** always JSON-RPC error `-32602 "distance to target block exceeds maximum proof window"`, the
  `ExceedsMaxProofWindow` check in `crates/rpc/rpc-eth-api/src/helpers/state.rs`
  (`best_number - block_number > window`).
- **After expiry:** `debug_getRawHeader` and `eth_getBlockByHash` for the same hash kept succeeding at every
  distance. Header availability says nothing about proof availability.
- **Unknown block hash:** `debug_getRawHeader` and `eth_getProof` return `-32001 "block not found: hash …"`;
  `eth_getBlockByHash` returns `null`.

**What this does not show.** The runs are dev mode on a default archive node. They cover neither pruned
nodes (`--full`, `--minimal`), where state history is also bounded by pruning, nor restarts, nor an Engine API
driven head.

**Consequence.** With the default window, `witness(B)` can be acquired only while B is the client's head. A
node that has not captured it before the next block is imported cannot acquire it from that client. #153 §8.2
already requires a deployment to choose a non-zero window for its execution lag and to retain the witness.
The measurement confirms the rule and gives the exact refusal the acquisition code classifies.

## 2. Acquisition

`Acquire(ctx, caller, registryproof.Context, parent)` performs, naming the block only by hash:

1. `debug_getRawHeader(parent)`;
2. `eth_getProof(a_sr, the 22 keys in §4.1 order, {"blockHash": parent})`;
3. `registryproof.EvidenceFromGetProof`, then `registryproof.Verify` under the caller's context.

A `Witness` is returned only after step 3 succeeds. Failures fall into two classes, and neither falls back to
the head, a block number or a zero cursor:

| Class | Cases |
| --- | --- |
| `ErrUnavailable` (also `registryproof.ErrUnavailable`) | proof-window refusal; unknown block; `null` header or proof; any other JSON-RPC error; transport failure or non-200 status; cancelled or expired context (the context error stays in the chain) |
| `ErrInvalid` | a response that is not a JSON-RPC 2.0 object, has neither result nor error, or exceeds `MaxResponseBytes`; a header that is not hex; a proof that does not decode or does not match the key list or address; any `registryproof.Verify` refusal (another block's header or proof, wrong code hash, not finalized, and the rest), which stays in the chain |

`MaxResponseBytes` is 600 KiB, read through a limited reader: registryproof's 256 KiB node bound doubled for hex,
plus the envelope and keys.

## 3. Witness capture

`Store` keeps at most a configured number of witnesses in memory, keyed by the parent hash:

- `Capture` refuses a `Witness` not produced by `Acquire`, and re-verifies it under the store's own context. A
  witness verified under another deployment's context is not retained.
- `ForChild(parent)` re-verifies the retained evidence on every call (§7.5: retained material is an input
  only after re-verification) and returns its snapshot. A parent with no retained witness is `ErrUnavailable`,
  even when witnesses for other parents are held.
- When full, the least recently captured witness is dropped and becomes unavailable. Re-capturing a parent
  makes it the newest.
- `AcquireAndCapture` retains nothing when acquisition fails.
- `Witness` is opaque; its evidence accessor returns copies.

## 4. Tests

- **Recorded reth responses:** the genesis responses from `registrygenesis/testdata`, and the in-window, refused
  and unknown-block responses from the measurement, replayed through stand-in JSON-RPC servers. Genesis
  verifies. The window refusal and unknown blocks are unavailable. Dev-mined block 1 is authentic, but its
  registry was never finalized, so it is invalid, not unavailable. Block 1's evidence offered for genesis is
  refused by header hash.
- **Requests:** every request names the block by hash, with no number or tag.
- **Unavailable cases:** window, unknown block, null header, null proof, internal error, HTTP 500, connection
  refused, cancellation, timeout, and a caller that does not wrap the context error (cancellation is still
  reported).
- **Invalid cases:** non-hex header; another block's header and proof, with a different state; right header with
  another block's proof; emptied account proof; foreign address; missing storage proof; wrong result type;
  non-JSON-RPC, version-less and result-less responses; oversized response, and an oversized body that never
  ends (cut at the bound rather than read to the timeout); another deployment's context; zero parent (no request
  is made). Where two checks could refuse the same response, the case asserts the message of the one it targets.
- **Store:** unknown parent, no substitution, zero witness, failed acquisition, other context, copy isolation,
  re-verification on use, eviction order, capacity, concurrent use under `-race`.
- **Measurement script, offline:** stand-in reth, curl and lsof; the stand-in head advances by call count, so the
  script's bracketing and boundary checks run deterministically. The honest run publishes a measurement with
  both boundaries for windows 0 and 1. Each refusal exits non-zero with its targeted message, leaves the
  previous file byte-identical and leaves no temporary file. Cases: unpinned binary, answering endpoint
  before start, node exit, foreign listener, a proof served beyond the window, a proof served two blocks past
  the window while both boundaries look right, a head that never shows block 1 (boundary samples missing
  with no contradicting sample), an unexpected proof error, an error object without a code, a header lookup
  failing after expiry, a non-JSON-RPC head response, a header served for an unknown hash, and publication
  failure after validation. The stand-in head also moves during proof calls, so a sample taken without the
  head bracketing is detectable.

**Mutation check** (local, one mutation at a time, sources restored and compared after each).

| Target | Mutations | Killed at first | Killed in the end |
| --- | --- | --- | --- |
| `registrywitness.go` | 21 | 16 | 21 |
| `testdata/reth-proof-window.sh` | 12 | 9 | 12 |

- **Package survivors (5):** in each case another layer produced the same error class, so the tests did not observe the change. The tests added for them are:
  - a caller that does not wrap context errors;
  - asserting the non-hex header message;
  - a response without the `jsonrpc` version;
  - asserting the size-bound message;
  - an endless oversized body that only the limited reader stops before the timeout.
- **Script survivors (3):** each check's case was also refused by an overlapping check with the same message. The new stand-in behaviours make each check the only possible refusal:
  - an error object without a code;
  - a proof two blocks past the window;
  - a head that never shows block 1.

## 5. Ownership boundaries left open

These are proposed as separate reviewed units, not implemented here:

| Unit | Owns |
| --- | --- |
| #14 (F6) durable retention and restart | writing `witness(B)` in the same atomic write that records B's certified association; the published retention horizon; reloading after restart with re-verification; refusing readiness when the retained witness is missing |
| #15 (F7) archive serving and reacquisition | serving retained witnesses to other nodes; obtaining a witness after the client's window has passed; re-verifying a peer-served witness against the authenticated hash |
| node wiring (after #14) | capturing at commit, before the next block; the readiness gate for the child; the deployment's proof-window choice and rationale |

## 6. Not in this unit

No node, command or Engine API wiring, no durable store, no peer protocol, no deployment window choice, no
activation, `v0` removal or WithSealV1 advertisement. #10, #11 and #12 stay open.
