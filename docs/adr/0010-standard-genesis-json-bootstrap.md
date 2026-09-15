# ADR 0010: standard genesis JSON and configured execution origin

Status: proposed; #167 unit 1. Date: 2026-09-16.

## Context

The owner requires standard reth genesis JSON to supply execution genesis, including native UCT allocations.
The existing registry-only generator omits those allocations. Separately, the root's genuine initial UC has
nil state, while the earlier F4/F6 design expected an S0-valued genesis UC that the root does not produce.

## Decision

Adopt [F4f](../design/f4f-standard-genesis-json-bootstrap.md): prepare a finalized standard JSON file while
preserving user allocations and validating reserved addresses; validate that same file without modifying it
at runtime. Derive its full execution identity from trusted operator configuration outside the configuration hash cycle;
allow optional external consistency pins without requiring a second settings source.

Configuration authenticates B0/S0 through a distinct GenesisOrigin. Genuine UC/TR evidence authenticates
assignment and root progress, without changing its signed nil-state fields. Root-input v2 explicitly represents
bootstrap, first-certified and ordinary origins and their privileged projection. Ordinary certification
permanently supersedes bootstrap, including the first same-execution-state transition. Generic root bootstrap
and the signing-restart restriction remain unchanged.

## Consequences

The importer can be implemented and measured as an inactive API first. v2 derivation, companions, execution
projection and readiness/progress persistence require separate reviewed implementation and version evidence.
No activation, allocation amounts, automatic migration or completed F4/F6 claim follows from this decision.
A root initial-state field is unnecessary and would expand consensus/configuration scope; putting the final
state/header commitment into the existing full configuration also creates a hash cycle. Fabricating or
rewriting a genesis UC is rejected because configuration trust and signed certification are distinct.

The historical yellowpaper snapshot and repair patch remain unchanged. The explicit later
[specification amendment](../pos/specification/amendments/0010-standard-genesis-json-bootstrap.md) supplies
replacement/additional wording and application order; it is not evidence of upstream publication.
