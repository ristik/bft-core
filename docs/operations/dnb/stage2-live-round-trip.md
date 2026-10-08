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
