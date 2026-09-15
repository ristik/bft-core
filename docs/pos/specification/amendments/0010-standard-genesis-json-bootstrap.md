# Later amendment: standard JSON genesis and configured bootstrap

Status: proposed by #167 unit 1; decision [ADR 0010](../../../adr/0010-standard-genesis-json-bootstrap.md).
Detailed implementation contract: [F4f](../../../design/f4f-standard-genesis-json-bootstrap.md).

## Provenance and application order

The seven adjacent historical `.tex` files remain the exact output of the snapshot's `repair.patch` applied
to upstream `3da5c235427941c135f03779ca9e5d47611769b7`. This amendment is later text, not part of that patch
and not published upstream. Read the snapshot first, then accepted D1–D6/F-series amendments, then this
amendment for its explicitly identified genesis/bootstrap scope once accepted. Other rules remain unchanged.
The old 166-page compilation is evidence for the snapshot only; this Markdown amendment is not a newly
compiled yellowpaper. An upstream publication unit must port these changes and record its own build evidence.

## Replacement: appendix-evm.tex, Genesis State, opening paragraph

The finalized standard reth genesis JSON is the single source of execution genesis: native account balances,
account nonces, bytecode, storage, supported header parameters and execution chain/fork settings. Contract and
EOA allocations together equal the initial native supply exactly. Public allocation values and any bootstrap
EOA funding require their own disclosed deployment decision; this amendment chooses none. Preparation must
not silently overwrite an operator allocation at a reserved system address. The runtime validates the same
finalized JSON supplied to the execution client without changing it. Predeploy bytecode, storage, addresses,
fork rules and build artifacts remain reproducible. The trusted operator-provisioned JSON authenticates genesis configuration. Derived identity metadata binds
the finalized genesis and execution configuration; optional externally supplied pins are consistency checks,
not a second required authority or source of allocations/settings.

## Replacement: appendix-evm.tex, Seal Transaction, genesis paragraph

Execution genesis is installed from trusted configuration with the initial registry assignment and empty
cursors. A configuration-authenticated GenesisOrigin binds its block hash, state root and execution context.
It is not a root certificate. The genuine initial root UC/TR supplies assignment and root authority while its
signed execution-state fields remain null. Genesis authentication is an explicit rule, not a fabricated quorum
signature or a rewrite of signed state. The first ordinary block executes the mandatory system operations
using an explicitly versioned bootstrap input; installation itself is not a payload round.

## Addition: appendix-evm.tex, Certification Request

For the bounded configured-origin profile, the first BCR preserves the root bootstrap's null previous certified
state while executing against the configured genesis parent. The first block certificate commits its actual
block and resulting state; it permanently supersedes bootstrap even when execution state equals genesis.
Subsequent ordinary records obey the existing extension and quiet-round constraints. A timeout repeat does
not create a block or fill in a missing certified state. Root-input v2 preserves the actual initial, first-certified
and ordinary statement shapes as specified in F4f; absent certified state is never silently replaced by the
configured execution state. Proven-mode verification must also bind the effective execution parent and may
not skip a required proof because the signed previous-state field is null.

## Addition: evm-partition.tex, Seal Feed

Before the first execution result is certified, the feed carries the real bootstrap origin without claiming
that the root has certified genesis state. The execution parent is authenticated separately by configured
genesis. The v2 privileged projection represents absent certified state explicitly; it does not confer certified
status on the configured state. Ordinary block certification ends this bootstrap eligibility. Missing records,
a reset executor or replay of an old initial certificate cannot restore it; replacement or rolled-back local
state requires independently authenticated current history before readiness can be established.

## Scope/version note

This amendment does not enable root-input v2, change generic root initialization, select issuance amounts,
or waive mandatory system execution or signing authority. Existing v1 artifacts remain v1. Coordinated
Go/client/projection/companion and persistence/readiness evidence is required before activation. The initial
configured-origin profile is attested, shard epoch 0 with one configured root epoch, and the explicitly
supported execution fork schedule; other initial epochs and proven-mode bootstrap are refused pending their
own reviewed contracts. JSON ingestion support alone does not establish those execution guarantees.
