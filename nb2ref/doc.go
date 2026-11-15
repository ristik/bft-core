// Package nb2ref is the independent Go reference of the native bridge v2 relation (docs/design/native-bridge-v2.md, NB2-01
// #1097; this package is NB2-03 #1099) and the generator of the one vector file the TypeScript, Rust and Solidity
// implementations consume by digest. With pooled custody there is no per-deposit backstop, so this reference and its negative
// vectors are the main defense against a verifier bug.
//
// It is separate from bridgeprofile (protocol 6/7), which keeps building until NB2-10 (#1106) removes it. The strict CBOR
// scanner, RLP reader, MPT walk, trust-base history, certificate scan, SDK token codec and split primitives are copied from
// bridgeprofile and adapted to the v2 rule names.
//
//   - Origin (deposit.go): Γ and D (config.go), the wallet secret and rho, J and its DepositProof (arity 6, no PDR), the EVM
//     UC under the historical authority of its seal epoch for exactly Γ's partition and shard, the pinned header, the
//     receipt-trie path keyed by RLP(txIndex), typed and legacy receipts, status, the exact Deposited log from the vault,
//     the secret opening, salt, type, owner and data of the root mint.
//   - Lineage and return (verify.go, split.go, token.go): every token of the walk, its unlocks and inclusion proofs (each UC
//     under its own epoch, the state ID inside the UC's shard, RSMT membership, reference time), split burns, allocation
//     proofs and sums, a parent that cannot both split and return, the return burn and the verdict (D, eta, a, asset,
//     recipient, amount). The check order is frozen in verify.go.
//   - Segments (segment.go): the sorted circular-gap tree, gap proofs, the archive chain, the wallet's proof builder and its
//     SegmentSealed log check; seal receipts and the burn index (wallet.go).
//   - Vault model (vault.go): the packed accounting word, position-tag buffers, rotation and sealing, deposit and redeem in
//     the frozen order, against an unbounded paid-set reference that never calls the gap verifier (model.go).
//
// Every rejection rule of section 14 is one sentinel (errors.go); errors.Is matches exactly the rules an error names. A test
// seam (disabled) switches one rule's sentinel off at every site bearing its name; TestDisableEachCheck shows, for every rule
// outside its listed decoder, semantic, redundant, arithmetic and wallet exemptions, one negative vector that then passes. That
// is one load-bearing example per rule, not a site-by-site mutation proof.
//
// The vector file is regenerated, reproducibly, by
//
//	go run ./nb2ref/cmd/nb2vectors -out <native-bridge-plugins>/protocol/vectors/nb2
//
// and testdata/nb2-vectors.json.sha256 pins its digest. Production fixes (K, B) = (64, 16) (#1098); the token vectors use it,
// and the segment and vault vectors mostly use the test build (K = 4, 8).
package nb2ref
