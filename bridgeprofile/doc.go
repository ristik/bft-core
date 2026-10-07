// Package bridgeprofile is the Go reference ("oracle") and candidate-corpus
// generator for the B2/B4 whole-token native bridge profile rebased on the
// state-transition SDKs v3.0.1 (briefs/nbp-design.md): the strict SDK 3.0.1 token,
// inclusion-proof, transaction and certification bytes with deadlines, the
// embedded Unicity-certified EVM lock proof (version 2 lock reason) and its
// offline verification, the identifiers of the unicity-native family, the value
// envelope, the kernel ABI result, the anchor InputRecord opening and its time
// check in the composition, and the corpus generator (cmd/gencorpus). The exact
// token bytes, the immutable configuration Cfg, the one-shard aggregator
// policy carrier and its ABI envelope, the cfg-bound lock digest, salt/token
// ID/burn-reason derivations, the vault storage-slot derivations, the compact
// history projection and the pure token-semantics relation (prepareLock, mint,
// return) that the later native kernel at 0x0104 will implement.
//
// The relation is the narrow part the design assigns to the kernel: it
// reconstructs every source state, checks each unlock by recovering the signer
// from the supplied recovery ID and requiring equality with the reconstructed
// source key before verifying the compact signature, and exports every leaf
// obligation. It does not check inclusion, the lock's existence or aggregator
// admission; those belong to the composing verifier.
//
// Nothing here activates in production and no native precompile, vault or gas
// price is implied. Prices in this package do not exist; measured costs are
// produced by the benchmarks and reported in the PR.
package bridgeprofile
