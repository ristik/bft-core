# M0: implementable protocol baseline

Refs [#40](https://github.com/ristik/bft-core/issues/40). Evidence snapshot:
`a5bb862c3372ce4a1c6c8ca83103c40ae24125e8` on `integration/enshrined-evm`.
This record proposes closing the **design baseline** gate after independent review. It does not
accept M1, describe a rehearsed runtime release, authorize public deployment, or enable any feature.

## Accepted design evidence

The [2026-09-07 review decision](https://github.com/ristik/bft-core/issues/40#issuecomment-5568052411)
accepted all six design prerequisites and left only this consolidated readiness record outstanding.
The following exact merges, rather than stale `Proposed` labels in historical ADR introductions,
identify those accepted revisions. Subsequent amendments below remain part of the current baseline.

| Item | Accepted PR | Integration merge |
| --- | --- | --- |
| R0: integration/reference policy | [#76](https://github.com/ristik/bft-core/pull/76) | `f3c55ee477e650a606109274ffdf996694e1995f` |
| D1: canonical root input | [#77](https://github.com/ristik/bft-core/pull/77) | `a7858e96a358f53f9d64c0b057b47de03931c957` |
| D2: system calls, fee rules and minimal divergence | [#78](https://github.com/ristik/bft-core/pull/78) | `7eaf842a703f48dfa8cead52d7ac8662dc32c652` |
| D3: weighted quorum and trust identity | [#79](https://github.com/ristik/bft-core/pull/79) | `8f3318a41e771f37e053d5fbba5974870db729d4` |
| D4: handoff state machine | [#80](https://github.com/ristik/bft-core/pull/80) | `1297aaefd88bb7ed861a449d11aab702a89e4a1d` |
| D5: liability, retirement and forced inbox | [#81](https://github.com/ristik/bft-core/pull/81) | `aa71dcc0c92d10b4da7e1ddfe9fa035e933a2cf7` |
| D6: historical proof and custody | [#82](https://github.com/ristik/bft-core/pull/82) | `28459b85b4bfb0dafad34a5334bdd0e16a06ac68` |

The accepted [D2 deviation inventory](../design/d2-reth-system-call-fee-profile.md#3a-deviation-inventory-minimal-divergence-review)
compares simpler alternatives and bounds the audit surface. It retains standard transaction/receipt
tries, commits protocol outcomes in registry storage rather than a new header field, and uses explicit
versioned Engine siblings. This is an implementation contract, not evidence that those methods run today.

## Reproducible model and vector checks

At the snapshot above, the 2026-09-16 local run of
`GOCACHE=/tmp/agre-go-cache go test -p 1 ./evmroot/... -count=1` passed.
The tree was unchanged by the run. Every path below is pinned by that repository commit.

| Profile | Model/negative evidence | Retained vector artifact |
| --- | --- | --- |
| D1 | `evmroot` certificate-selection, valid quorum-subset and independent CBOR oracle tests | `evmroot/testdata/vectors.json` |
| D2 | `TestD2_*`, including exact gas reconciliation, reserved forced capacity and fee arithmetic | `evmroot/testdata/d2-vectors.json` |
| D3 | `TestD3_*`, including duplicate keys, minority weight, overflow and threshold checks | `evmroot/testdata/d3-vectors.json` |
| D4 | `TestD4_*`, including adversarial multi-replica safety and recovery models | `evmroot/testdata/d4-vectors.json` |
| D5 | `TestD5_*`, including refund revocation, capacity and liability boundaries | `evmroot/testdata/d5-vectors.json` |
| D6 | `TestD6_*`, including real signature/hash/path negatives and custody accounting | `evmroot/testdata/d6-vectors.json` |
| Configured-origin v2 amendment | `TestV2IndependentVectors` with separate Python encoder | `evmroot/testdata/v2-vectors.json` |

The D1 and v2 independent encoders and D2 arithmetic oracle supplement the checked golden model
outputs. This does not claim that every D-series model has a second complete implementation.
Model proofs are scoped to their stated assumptions; no new audit or real-client measurement was run
for this record. The repository build/vet and implementation tests recorded with #191 are separate
implementation evidence, not a substitute for these design checks. Hosted CI remains unavailable.

## Current amendments and boundaries

- [F4f / ADR 0010](../design/f4f-standard-genesis-json-bootstrap.md), accepted in #168 at
  `9addbc5d`, makes finalized standard genesis JSON the allocation/configuration source. The actual
  root certificate remains nil-state at bootstrap; it is not rewritten to certify the EVM genesis.
  #171 supplies the separately versioned v2 input API/vectors. Older v1 vectors remain historical
  conformance evidence and must not be interpreted as v2 activation.
- [F6c](../design/f6c-acceptance-ledger.md) records the accepted independent volatile signing authority
  and its process/backup premise. It does not prove disk durability or replacement-host key continuity.
- [F6f/F6g](../design/f6f-automatic-bootstrap-freshness.md) define automatic fresh root-quorum
  confirmation for bootstrap. Through #191, checked storage, consensus sampling/signing, committed
  cuts, bounded transport and requester are implemented as optional or inactive components. No node
  registers the requester or consumes its receipt as a bootstrap permission.
- The registry artifact, proof reader, genesis import and certified-progress stores are implementation
  prerequisites. Neither an artifact nor an opt-in witness capture path establishes D2 execution validity.

The runtime continues on its existing v0 execution path. There is no advertised canonical-v2 Engine
capability, no deployed D2 open/finalize execution path, and no public issuance, bridge or PoS activation.
Thus the enabled/disabled scope of this **design bundle** matches the evidence; there is no runtime
release rehearsal to claim at M0. Runtime rehearsal and exact deployable configurations belong to M1
and later gates.

## Readiness recommendation and remaining owners

M0's R0/D1–D6 prerequisites are accepted; the profiles, executable models, independent-vector evidence,
minimal-divergence decision and residual assumptions are now collected in one pinned record. The
recommendation is **M0 accepted for implementation**, subject to this record's independent review.
The reviewing agent acting under the owner's delegated review/merge workflow must record the final
decision on #40; this document alone closes nothing.

M1 (#41) remains open. Its critical path is F3 real execution (#11), F4 registry integration (#12), F2
live input verification (#10), F5 fee validity (#13), and F6 coherent first-certification/restart wiring
(#14/#167/#176), followed by one integrated private paired acceptance lane. F1 hosted evidence
(#9/#90/#100) remains separately outstanding. Full UC/root-state authentication, production weighted
quorums/handoff, real Ethereum historical proofs, enforced freshness, and paid FIFO/escrow/gas-reservation
integration remain with their implementation tickets, including I2 (#25) for deterministic FIFO execution
and capacity reservation. The models do not discharge those obligations.
