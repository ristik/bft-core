# DN-B stage 2: live private round trip (lock → mint → transfer → burn → redeem → claim)

Run 2026-10-08 on the B1/B2 paired devnet of stage 1 plus aggregator-go as a BFT shard. Raw evidence: [`evidence/round-trip-run.log`](evidence/round-trip-run.log),
[`evidence/round-trip-evidence.json`](evidence/round-trip-evidence.json), the deployment inputs beside them. The driver is
`tests/live/lane.ts` in ristik/native-bridge-plugins (PR "DN-B live lane driver"), the bring-up is `scripts/dnb-devnet.sh all`.

## Pins

| Component | Revision |
| --- | --- |
| ureth (release build, sha256 `5135a27d…a1d3`) | `634bcc28b2e38b5f8caa435e41bc1cb0a66bf958` (B1 PR4b + B2 0x0104) |
| bft-core | this branch (#470) |
| contracts (vault, verifier, registry) | `BridgeDeploy` script of unicity-pos-contracts#13 over `main` 6fc496f; registry runtime = bft-core `b1registry` (code hash `0x28ebc47d…`) |
| aggregator-go | `ae081651ac7443496b5397baa8748e0b4280ba72` **plus one dependency change**: `go mod edit -replace github.com/unicitynetwork/bft-core=<this checkout>; go mod tidy; go build ./cmd/aggregator` (sha256 `fbff4161…70b8d`). No source change was needed. |
| plug-ins | native-bridge-plugins `76040989` (TS plug-in used by the driver) |
| MongoDB | `mongo:7.0`, single-node replica set in colima (aggregator-go requires it) |

## What ran for real

* Four ureth + four shard validators + four profile-2 roots, fresh-B1 registry (layout 3, `W_cert = 15`: B1 authenticates a certificate only within
  `[registry clock − W_cert, clock]`, and the driver must submit the redemption while the anchor is in that window; root rounds are ≈ 0.9 s).
* aggregator-go (SDK3 leaf protocol) as partition 9, full range, a BFT shard of the live root chain. Mint, transfer and burn were certified by it.
* `BridgeVault`/`TokenVerifier` deployed by the contracts' `BridgeDeploy` script, which asserted `rootGenesis`, `executionGenesis` and `b1ProfileHash` equal the
  genesis' own and that the registry on the chain holds the genesis profile hash.
* The lock executed on the running chain (native 0x0104 prepare). The vault's stored lock digest equals the plug-in's independent derivation.
* The lock backing is an `eth_getProof` of the executed chain bound to the archived certificate of its block (not the oracle's synthetic proof).
* Redemption executed the vault against native B1 (0x0100, 0x0102) and B2 (0x0104): third-party submitter, certified recipient credited, recorded nullifier equals the
  plug-in's, claim paid the payee and left the vault at 0.

## Findings (all fixed or recorded)

1. B1 was not reachable from the `ubft` CLI at all (fixtures only); #470 adds it. The client profile check, `b1Update` (always on the wire) and the pair binding needed work
   that only a running pair showed.
2. **aggregator-go ae08165 cannot be a shard under `proof_type=aggregator_rsmt_v1`**: the root requires an SMT consistency proof with every non-empty request and
   aggregator-go sends none ("envelope truncated: missing leaf_count"). The lane runs the aggregator partition with no `proof_type` (m-of-n signatures only);
   rugregator runs under `aggregator_rsmt_v1`. Whether aggregator-go gains the proof is an aggregator-go decision.
3. aggregator-go's bft-core dependency (April) is wire-incompatible with the current root (`CertificationResponse` arity); a dependency bump fixes it.
4. aggregator-go refuses `SHARDING_MODE=bft-shard` for a single full-range shard; it runs `standalone` with BFT enabled.
5. **`W_cert` is a root-round window (≈ 16 s at 15)**: a redemption proof must be assembled and submitted within it, after the registry clock has reached the anchor round. A
   certificate newer than the clock is refused (`UCRejected`), so a client must read the clock before submitting. Transaction gossip is off in this stack: publish to every
   validator's pool, otherwise inclusion waits for the one validator's leader turn.
6. Profile `maxGas` for `W_cert = 15` is 276,547,540 (system reservation 269,547,540).
7. A previous 30-minute run stalled when the root consensus stopped ("proposal timestamp exceeds voter clock skew"); a fresh devnet did not reproduce it. Not investigated.

## Stage 3 additions: refusals, restart, measured gas

Evidence: [`evidence/cycle2-after-restarts.log`](evidence/cycle2-after-restarts.log), [`evidence/restart-sequence.out`](evidence/restart-sequence.out).

* Refusals by `eth_call` in the live window: a flipped certificate byte → `UCRejected` (`0x391d1053`); a claim by an uncredited account → `InsufficientCredit`; the same burn redeemed
  twice → `AlreadyRedeemed(nonce)` (`0xd36d946d`).
* Restart: after cycle 1 the aggregator-go process (state in MongoDB) and validator 2 (its ureth and shard node) were stopped (SIGTERM) and started again from their own state.
  All four ureth reached the same height (58 → 81 later), the restarted aggregator still served the previous token's state with its original CD and reference time
  (`tests/live/postcheck.ts`), and a second complete cycle (lock → … → claim) passed.
* Gas measured on the running chain (ureth, not revm): lock 272,164; redeem 1,835,321–1,887,252; claim 86,224. Block gas limit 276,547,540 (system 269,547,540, ordinary 7,000,000).
  The redemption landed 7–13 root rounds after the anchor (window 15).

## Not done

* **Reorg.** The pair's chain is certified by the BFT root; no EVM fork occurs in this configuration, and no fault harness (the d2c proxies) was pointed at the bridge. Unexercised.
* A malformed certificate's full cost (the ~6.4 M gas B1 burns on a halt) was measured in-process in PR6, not live. A flipped-byte eth_call returned a clean `UCRejected`.
* `aggregator_rsmt_v1` with aggregator-go (finding 2), W_cert > 15, weighted or rotating root epochs, public-network conditions, arm64 CPU budgets.
* The first 30-minute attempt stalled on root consensus (finding 7); it was not reproduced on three later fresh runs.

## Stage 4 (after #479, #471/#477 and ureth #59/#61): restart of everything, budgets, root liveness

Evidence: [`evidence/stage4-run.log`](evidence/stage4-run.log). Pins changed: ureth `9d61e63762a1b0863a3d54519e8de55310748f87` (#61, sha256 `7b…` of the pinned binary in /private/tmp/dnb-unicity-reth-9d61e637), bft-core integration at #479 plus this branch.

* **Root liveness.** With non-decreasing seal timestamps (#479) the root no longer stalls: two devnet runs of 25+ minutes passed round 796 and 822 with **0** `exceeds voter clock skew`
  rejections (the unfixed rule stopped at round 163). The final run logged 0 as well.
* **Interruption between redeem and claim.** All four shard validators and all four ureth were stopped at once and started from their own state (roots, aggregator-go and the four independent
  signing authorities kept running). Heights 32 → 34 on all four, the credit survived exactly once, the recorded nullifier survived, the old proof is refused, then claim paid.
  Needs `SIGNING=authority` and `--engine.persistence-threshold 0`: a restarted validator with a local signing key follows but does not vote (#105), and a ureth that persists only
  every 64 blocks loses everything on a full restart.
* **Budgets on the running chain** (ordinary capacity 7,000,000 gas): a redemption whose certificate has a corrupted first byte (malformed CBOR head) halts B1 and burns **6,792,431** gas
  of the submitter's 7,000,000; a corrupted middle byte (well-formed, bad signature) costs 1,753,601. A valid redemption costs about 1.85M.

Findings of this stage (cross-repo wire skew, fixed here): bft-core's codec sent `rootRecords` (optional) while ureth #59 requires `records`; the engine profile check, `b1Update`, the pair
binding and now the root-record import all needed matching fields. A B1 pair needs a `RecordsSource` since #471; this branch gives a chain with no P85 root source state an empty one
(`emptyRootRecords`, genesis UC time). A deployment with a root source state needs a real source (not written upstream yet).

Still not done: a reorg (no EVM fork occurs under BFT certification here), `aggregator_rsmt_v1` with aggregator-go.
