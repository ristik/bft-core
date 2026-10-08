# Yellowpaper review snapshot

These seven LaTeX files are the repaired working specification used to write this backlog.
They are a review baseline, not an assertion that the D1-D6 implementation profiles are frozen.

Upstream repository: https://github.com/unicitynetwork/unicity-yellowpaper-tex
Base revision: `3da5c235427941c135f03779ca9e5d47611769b7`.
`repair.patch` contains the original seven-file change from that revision. The adjacent files
now include later amendments and are not reproduced by that historical patch alone. Other
sections and LaTeX assets come from the base.
To reproduce the historical snapshot, check out that revision in an isolated checkout and apply `repair.patch`, then
run `latexmk -pdf -interaction=nonstopmode -halt-on-error unicity-yellowpaper.tex`.
The source compiled to 166 pages on 2026-09-05; pre-existing horizontal overflow warnings remain.

This copy makes issue references available before upstream publication. Maintain the Yellowpaper
upstream; replace this snapshot with an accepted upstream commit reference once published.
Record every later normative change in an ADR and update affected issues, vectors and release gates.
Do not silently edit one copy while leaving implementers to infer which version applies.

## Later amendments

[ADR 0010 / #167 genesis amendment](amendments/0010-standard-genesis-json-bootstrap.md) records
replacement/additional wording for standard reth genesis JSON and configuration-authenticated bootstrap.
It is a separate proposed normative amendment, with explicit application order and implementation gates.
That amendment did not edit the seven `.tex` files or `repair.patch`; the historical compilation claim applies
only to the original snapshot. No upstream publication or new LaTeX build is claimed.

[ADR 0012 / owner decisions of 2026-10-01](amendments/0012-validator-entity-model.md) records the validator-entity model:
weights only at the root/validator level (EVM mirrors, aggregator shards unweighted), root-key-only identity, coupled
validator-set changes, positive proofs only, the deferred forced-inclusion track, centrally run aggregator shards without
consistency proofs, epoch-boundary root-ordered aggregator reconfiguration and the move of broad F7 to the bridge track.
It is a separate accepted amendment with its own supersession table; that amendment did not edit the seven `.tex` files.

[B2 #63 PR 1 / whole-token bridge profile](amendments/b2-whole-token-bridge-profile.md) records the exact token bytes, the
cfg-bound lock digest, the one-shard aggregator policy and ABI envelope, the unlock rule that binds the recovery ID and the
nonce-keyed spent mapping that replaces the nullifier accumulator for the private whole-token native UCT bridge. It is a
separate proposed amendment with its own supersession table; that amendment did not edit the seven `.tex` files. Nothing in it
activates in production.

[ADR 0013 / #479 root-time semantics](../../adr/0013-root-time-semantics.md) records non-decreasing
UC seconds with independent consensus ordering, authentication and conditional clock guarantees.
It directly updates `bft.tex` (UC seal timestamps) and `governance.tex` (checkpoint protection),
and is applied after the earlier amendments. Those current files therefore differ from
`repair.patch`. The consumer audit is [here](../../design/root-time-consumers.md). Validation
of the amended time section is separate from the historical 166-page build; no updated full
Yellowpaper compilation is claimed.
