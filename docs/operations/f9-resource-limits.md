# F9 resource limits and evidence

This note publishes the measured F9 resource profile and initial operating thresholds. The runs used four validators on one host and are useful for setting alerts and journal bounds; they do not establish multi-host production capacity.

## Journal settings

For archive/recovery deployments, use an explicit journal candidate cap of 16, warn at 8 retained candidates, and treat 12 as urgent. The measured one-replica outage used 7 candidates in 45 seconds, so an explicit cap of 8 has little headroom. Keep the 64 MiB journal byte cap.

The generic `ubft shard-node run` flag defaults to 256 candidates and 64 MiB, as declared in `cli/ubft/cmd/shard_node_run.go`. This remains unchanged. The M2a paired-devnet helper uses its lane-only cap of 32 in `helper.sh` and the restore probe; preserve that override for restart and archive catch-up rehearsals. The operator runbook and eight-candidate test fixtures are updated to use 16 where they express the standard recovery cap.

## Measurements

Values are per process, sampled by the report collector; CPU, RSS and FD values are snapshots rather than continuous maxima.

| Stage | Height / archive records | Journal candidates / bytes | Frontier gap / replica lag | Archive bytes | CPU / RSS / FDs |
|---|---:|---:|---:|---:|---:|
| 2k steady | 2,022 / 2,022 per node | 3 / 18,933–20,032 B | 0–1 / 0–1 | 12,860,985 B per node | 9.8–11.5% / 63.2–64.9 MiB / 26–27 |
| One replica down for 45s | survivors reached 2,027 | 3–7 / 19,544–49,713 B | up to 5 / up to 5 | 12,886,527 B per node | 7.7–12.0% / 63.8–65.4 MiB / 25 |
| 4.7k load window | 4,709–4,710 / 4,711–4,716 | 3–4 / 18,936–30,295 B | up to 3 / up to 2 | 30,000,149–30,031,375 B per node | 9.6–12.7% / 79.4–84.6 MiB / 26–27 |
| 5k final | 5,003 / 5,005 per node | 2–6 / 11,576–39,796 B | 0–4 / 0–1 | 31,875,595 B per node | 10.2–12.6% / 82.1–87.4 MiB / 26 |

With validator 4 stopped, the other validators advanced. After restart it rejoined through height 2,037 and both durable replica acknowledgements reached the target 34 seconds after restart.

At 5,005 archive records, each node held 31,875,595 B, about 6,369 B per record. Linear planning gives about 168,000 retained records per GiB. This estimate does not model long-term pruning or production transaction mix.

Ordinary valid witnesses counted 2,981–5,003 verified and 5,959–10,016 cached per node in the final report. The collector reported p50 25 ms and p99 at most 100 ms. The valid-history binary did not expose downloaded-byte counters. In the malformed-proof run, the report counted one rejected invalid proof (30,937 B), 2,229,141 downloaded bytes across all four nodes, and 549,551 verified bytes per node; p50 was 25–50 ms and p99 at most 250 ms. The mutated proof was rejected as a header-hash mismatch; no snapshot derived from it was used, and the validator recovered without divergent commits.

## Initial operating thresholds

These recommendations use the measurements above with explicit headroom. They are operational alerts, not protocol-enforced limits.

| Signal | Initial threshold | Basis and response |
|---|---|---|
| Journal candidates | Configure 16 for the standard recovery profile; warn at 8; urgent at 12 | Observed maximum was 7 with a replica unavailable for 45 seconds. Keep the generic CLI default of 256 and M2a lane override of 32 distinct from this explicit profile. |
| Journal bytes | Keep hard cap 64 MiB; warn at 1 MiB; page at 8 MiB | Largest sampled usage was 49,713 B. |
| Tip-to-frontier gap | Warn above 8 blocks for 30 seconds; critical at 16 blocks or no progress for 60 seconds | Observed maximum was 5 during one-replica downtime and 4 at the 5k final sample. |
| Replica acknowledgement lag | Warn at 3 blocks for 30 seconds; critical at 8 blocks or no ack progress for 60 seconds | Observed maximum was 5 during the controlled outage; restart catch-up completed in 34 seconds. |
| Archive disk | Budget 6.4 KiB per retained record; alert at 70% volume use and expand before 85% | A 5k history used 31.9 MB per node. Keep at least 15% free for catch-up and compaction. |
| Process resources | Warn above 75% CPU sustained for 5 minutes, 256 MiB RSS, or 128 FDs | Samples stayed below 13% CPU, 88 MiB RSS and 27 FDs. Validate on production hardware and multiple hosts. |
| Witness verification | Alert if p99 exceeds 250 ms for 5 minutes; any accepted invalid proof is an incident | Valid p99 was at most 100 ms; malformed-proof p99 was at most 250 ms. Keep the current frame limit. |

## Large valid proof test and frame cap

`parentwitness/wire_test.go` builds a go-ethereum state trie with one million distinct 256-bit storage slots, each containing a nonzero 32-byte value, plus the registry fields. It derives the account and storage proofs from the built tries, RLP-encodes a Cancun header over the resulting state root, then runs the real `VerifyResponse` and `registryproof.Verify` path. The test repeats verification 20 times and records size and latency.

The measured response was 72,430 B (71,712 B evidence) against the 278,528 B frame cap, or 26.0% of the cap. The proofs contained 175 nodes total and at most 8 nodes for any one registry storage path. On Go 1.27.1 with the repository's go-ethereum v1.14.11 dependency, 20 verifications measured p50 974.365 µs and p99 2.052 ms. This is cryptographically valid evidence generated from an actual go-ethereum trie, but it did not approach the cap.

The verifier requests 28 fixed storage keys whose paths are Keccak hashes. One million filler slot keys spread through the secure trie, and Patricia path compression keeps each requested path short. Deliberately forcing deep branches for those fixed keys would require chosen-prefix Keccak preimages or an impractically larger state; this test does not use arbitrary, unlinked proof-node bytes to simulate that. The previous 267,110 B serializer fixture was size-only and is not a valid proof. Keep the existing 278,528 B response cap until a valid near-cap proof is produced.

## Evidence runs and pins

The raw logs and JSON reports are in the operator evidence workspace and are not committed in this PR:

- Valid 5k history, 2k and 4.7k reports, 45-second replica stop and restart/rejoin: `/Users/risto/uni/agre/briefs/devnet-runs/f9-load-valid-20260930T1258Z/`. Reports: `report-2k.json`, `report-replica4-down.json`, `report-5k-load.json`, `report-5k-final.json`; root traffic: `root-round-observations.json`.
- Malformed proof refusal and recovery: `/Users/risto/uni/agre/briefs/devnet-runs/f9-malformed-20260930T1315Z/`. Report: `report.json`; rejection and recovery trace: `lane.log`.
- Valid-lane BFT source pin: `f2a20bde62a4ef4a1f98758df63c29cbbfe65a02`; binary SHA-256: `e073accc9cca4b4494cc43ef30b99d94bd25ace9e1969d34ff9bff5489dcb1e9`.
- Malformed-lane BFT source pin: `6b0eb5dd4ce1062fb46c6db206e673cbfec2f6af`; binary SHA-256: `cdfcc73afbcf20babff58aef1bdb822c671f9ad0ef1f3379af2b0ff8a3d7bc83`.
- Ureth source pin for both runs: `055a314f759f78f045d55ceddfeb7e14b3b6a2f7`; binary SHA-256: `b6a70b4293a1c18d7304b2e3d806ce0fb7f90dfcb2e64f60ab6f4d9c2e8a55b7`.
- Reporter source head: `6b0eb5dd4ce1062fb46c6db206e673cbfec2f6af`.

## Remaining evidence

- The valid trie test is large but not near the cap. Its one-million-slot state is the largest valid state built for this test; the frame limit remains conservative relative to this proof. The synthetic serializer fixture is not cryptographic evidence.
- Certification-pause timestamps were unavailable because these F9 lanes did not perform a handoff or epoch transition. The planned H6 rehearsal will record the handoff pause.
- The 5k run used four validators on one host. Treat the resource thresholds as starting alerts until multi-host measurements are available.
