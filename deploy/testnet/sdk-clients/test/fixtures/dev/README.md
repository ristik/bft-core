# Shared dev trust-base fixture

The same three files are in ristik/state-transition-sdk-rust `e2e/dev/`. They come from the Go generator
(`../v1/generator`, `go run . -out ../utb-vectors-v1.json -dev-out ../dev`), from the same chain as the v1 vectors:

- `bft-trustbase.dev.genesis.json`: the epoch-1 genesis in bft-go-base's own JSON form (`json.MarshalIndent` of
  `RootTrustBaseV2`: its field order, `0x` hex, an absent hash as `""`, `signatures` null).
- `bft-trustbase.dev.genesis.entryid`: its EntryID (hex), the pin.
- `bft-trustbase.dev.bundle.cbor`: the release bundle of epochs 1..4 (tag 39015), byte-identical to the vectors'
  `bundle.complete`.

Test data for local and e2e use, never a real network's trust base.
