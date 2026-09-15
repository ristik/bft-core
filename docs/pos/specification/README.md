# Yellowpaper review snapshot

These seven LaTeX files are the repaired working specification used to write this backlog.
They are a review baseline, not an assertion that the D1-D6 implementation profiles are frozen.

Upstream repository: https://github.com/unicitynetwork/unicity-yellowpaper-tex
Base revision: `3da5c235427941c135f03779ca9e5d47611769b7`.
`repair.patch` contains exactly the seven-file change from that revision; the adjacent files
contain their resulting full contents. Other sections and LaTeX assets come from the base.
To reproduce, check out that revision in an isolated checkout and apply `repair.patch`, then
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
The seven `.tex` files and `repair.patch` above remain unchanged; the historical compilation claim applies
only to that snapshot. No upstream publication or new LaTeX build is claimed.
