# NB2 continuation v1.1 vectors

The protocol and independent fixture pins are in [the frozen specification](../../docs/design/nb2-continuation-v1.1.md). The binary golden files are listed in `MANIFEST`. The independent producer has no dependency on the bridge verifier.

```sh
go run ./nb2ref/cmd/nb2flatgold /tmp/nb2-flat-golden
NB2_FLAT_VECTOR_OUT=/tmp/nb2-flat-traces go test -count=1 ./nb2ref -run '^TestFlat'
go test -count=1 ./nb2ref/... ./docs/design/models/nb2settlement
```

The signed fixture corpus uses the same `gamma.bin`, generation salt and dependency digest for every case. Each lineage directory contains exact E, the UTB bundle, certificate-authority registry words and the independent consensus pins used to verify them, S, the page root and the six-word verdict. Held evidence has an empty verdict.

A decompressed `trace.bin.gz` contains records to EOF. Each record contains six fields in order, prefixed by their four-byte big-endian lengths.

1. Canonical `run(bytes)` calldata with the opened pages, SID and claim witnesses.
2. Incoming 290-byte state, empty on Start.
3. Outgoing 290-byte state, empty on Complete.
4. The two exact event topics concatenated.
5. The event ABI data.
6. The canonical CBOR receipt proof for that result.

A Complete record has no successor state or digest. The terminal operation remains in calldata. Raw signed mints, transfers and certificates are recoverable directly from the framed evidence. Cold-call fixtures contain canonical calldata and either the emitted event/proof or the custody state before and after the call. Precise test-registry words describe a deterministic chain-free authority fixture. They are evidence for replaying these vectors, independent of production trust configuration.
