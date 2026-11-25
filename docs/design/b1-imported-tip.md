# B1 certificate admission at the imported tip

Execution revision 2 implements the imported-tip relation at the existing `CERT_BATCH_V2` address 0x0100. Given pinned,
initialized registry state in phase 2, a seal of epoch `e` and root round `r` must satisfy:

```text
genesisEpoch <= e <= importedTipEpoch
start[e] <= r
e < importedTipEpoch implies r < end[e] == start[e+1]
```

The writer installs contiguous epochs and sets each exclusive end to the next epoch's start in the same update. The reader
validates every requested in-range authority, including that historical entries are closed and the tip is open. A missing or
malformed in-range entry is a registry error. An epoch ahead of the tip is unavailable. Certificate binding and native weighted
quorum verification still apply. Genesis may be epoch zero and is sufficient before the first D1 observation.

The D1 observation and readiness words retain their writer meaning, including the ready parent's required equality of usable
epoch and imported tip, clock monotonicity, and the guard against closing the earlier origin at or below its observed round. B1
reads these words for their existing EVM storage-warming effect. Their values play no part in certificate verification. Registry
layout, update and call encodings, and the gas schedule are unchanged.

The open tip has no authenticated end until the next epoch is installed. During import lag, verifying against that tip relies on
the assumption that a retired quorum cannot certify new claims. The live handoff replay qualifies the transition for the
coordinated release.

The canonical differential corpus is [b1-vectors-anyage.json](../../b1ref/testdata/b1-vectors-anyage.json). Regenerate it with
`go test ./b1ref -run '^TestGeneratorDeterministic$' -update` and copy it byte-for-byte to ureth's corresponding fixture.
