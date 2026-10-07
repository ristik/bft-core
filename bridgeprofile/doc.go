// Package bridgeprofile is the Go reference ("oracle") for the B2/B4 whole-token
// bridge profile of briefs/bridge-b2b4-design-v2.md, slice PR1: the exact
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
