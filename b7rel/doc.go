// Package b7rel freezes the proof-system-independent relation interface of the B7 succinct redemption fallback
// (briefs/b7-succinct-fallback-design.md, steps 1 and 2): the candidate resource limits and the relation ID derived from them,
// the per-epoch trust commitment C_e that the seal registry caches, and the canonical public journal a proof commits to.
// It is the Go reference; the Solidity adapter and the Rust guest replay testdata/b7-relation-vectors-v1.json.
// Nothing here activates a proof system or changes the direct path.
package b7rel
