# NB2 continuation v1.1 vectors

The protocol and independent fixture pins are in [the frozen specification](../../docs/design/nb2-continuation-v1.1.md). The binary golden files are listed in `MANIFEST`. The independent producer has no dependency on the bridge verifier.

```sh
go run ./nb2ref/cmd/nb2flatgold /tmp/nb2-flat-golden
NB2_FLAT_VECTOR_OUT=/tmp/nb2-flat-traces go test -count=1 ./nb2ref -run '^TestFlat' -skip '^TestFlatPublished'
go test -count=1 ./nb2ref/... ./docs/design/models/nb2settlement
```

The signed expectation producer in `nb2ref/flat_expect_test.go` computes checkpoint bytes, SID and claim roots, event data and the final verdict from the signed recipe before the Go verifier runs. Its recursive sparse-tree builder takes complete leaf sets and does not use packet openings. Cold outcomes and adjacent archive heads have separate expected-value checks.

The signed fixture corpus uses the same `gamma.bin`, generation salt and dependency digest for every case. Each lineage directory contains exact E, the UTB bundle, certificate-authority registry words and the independent consensus pins used to verify them, S, the page root and the six-word verdict. Held evidence has an empty verdict. Its 129-byte `holding.bin` is owner33, state32, tokenID32 and amount32, concatenated.

A decompressed `trace.bin.gz` contains records to EOF. Each record contains six fields in order, prefixed by their four-byte big-endian lengths.

1. Canonical `run(bytes)` calldata with the opened pages, SID and claim witnesses.
2. Incoming 290-byte state, empty on Start.
3. Outgoing 290-byte state, empty on Complete.
4. The two exact event topics concatenated.
5. The event ABI data.
6. The canonical CBOR receipt proof for that result.

A Complete record has no successor state or digest. The terminal operation remains in calldata. Raw signed mints, transfers and certificates are recoverable directly from the framed evidence. Cold-call fixtures contain canonical calldata and either the emitted event/proof or the custody state before and after the call. Each refusal contains its original calldata, stage and last usable predecessor. A nonempty predecessor has a linked `retry-calldata.bin` that must succeed using that exact receipt. A permanently invalid child can be retried with a cut before the child to certify only the valid prefix. Recovered settlement refusals also include `custody-before.json` for the rollback check. Precise test-registry words describe a deterministic chain-free authority fixture. They are evidence for replaying these vectors, independent of production trust configuration.


Cold custody prestates are reached from genesis by a target deposit and a
separate deposit funding one-unit background redemptions. The custody harness
treats background ordinary verdicts as certified and executes
the shared §6 payment and seal paths. Identifier derivation includes both
segment and slot, so sealed segments and the live buffers have disjoint paid
IDs. Setup checks the resulting heads against an independent fold. Published
events retain the target deposit as context and include the logs from the
test call. Historical background logs and background recipient balances are
outside that observation.
