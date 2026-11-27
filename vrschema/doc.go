// Package vrschema is the reference for the validator registry schema v1 (VT-16, ristik/bft-core#1156).
//
// It freezes every encoding and constant that bft-core (Go), unicity-pos-contracts (Solidity) and ureth (Rust) must agree on for the
// ValidatorRegistry (VR) generation: VR's ERC-7201 storage and the liability-holder layout, the packed election-module returns and
// their exact-length decoding, the output record and its state codes, the governed change kinds and their payloads, root-record kinds
// 6 to 8, the VR-mode root controls, candidate v6 and Freeze v5, the handoff view protocol envelopes and the backoff state machine, the
// activation schedule and the fee profile F(N).
//
// The normative text is docs/design/validator-registry/schema-v1.md; the design it freezes is the approved VT-01 consolidation. Every
// function here is pure and deterministic: no clock, no I/O, no randomness. The shared vectors in testvectors/validator-registry are
// generated from this package (go generate ./vrschema) and TestVectorsAreCommitted requires the checked-in files to be byte-identical
// to a fresh generation.
//
// Later Go code (VT-02 tooling, VT-05a admission, VT-05b and VT-09 handoff, VT-15 records) builds on these definitions instead of
// re-deriving them, so this package is kept minimal: encoders, strict decoders, digests, and the pure transition and arithmetic
// functions the vectors exercise.
package vrschema

//go:generate go run ./cmd/vrvectors -out ../testvectors/validator-registry
