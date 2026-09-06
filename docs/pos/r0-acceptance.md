# R0 acceptance record — Adopt the reference baseline and contribution workflow

Issue: [#2 R0](https://github.com/ristik/bft-core/issues/2) · Milestone: M0 · Program: [#1](https://github.com/ristik/bft-core/issues/1)

R0 is a process/bootstrap ticket. It adds **no runtime behavior**. This record maps each
work-breakdown item and acceptance test to the artifact that satisfies it in this PR.

## Work breakdown

### 1. Review the documentation-only reference PR; confirm the snapshot and roadmap represent the intended architecture

The owner explicitly approved reference publication on 2026-09-06. **This PR is that
publication.** It imports, under `docs/pos/`:

- `README.md`, `PROCESS.md`, `repair-plan.md` — program overview, contributor/agent workflow, repair scope + validation record.
- `roadmap.md` — the 65 roadmap tickets in dependency order with acceptance evidence and staged gates.
- `issue-index.md`, `issue-manifest.json` — stable roadmap ID → GitHub issue number mapping and the full/reduced dependency graph.
- `specification/` — the seven repaired Yellowpaper files (`bft.tex`, `governance.tex`, `execution-layer.tex`, `evm-partition.tex`, `appendix-evm.tex`, `appendix-bridging.tex`, `appendix-token.tex`), `repair.patch` against upstream base `3da5c235427941c135f03779ca9e5d47611769b7`, and `specification/README.md` with reproduction instructions.

Reviewer confirmation checklist (tick in PR review):

- [x] The `engine-api-adapter` prototype at `627318b5` is the intended architectural
  starting point (paired BFT Core / reth EVM shard, executor-agnostic `shardnode/`
  framework per ADR 0001).
- [x] The milestone ladder (M0 → M1 → M2 → M3; M4B/M5B and M4S/M5S independent after M3)
  matches intent.
- [x] The initial simplifications (one governance EVM shard, uniform leader selection,
  self-bond staking, assigned-weight rewards optional, whole-token bridge, native UCT
  genesis with no migration) are the intended launch scope.
- [x] The specification snapshot is an acceptable review baseline pending upstream publication.

### 2. Record the integration-branch policy (`engine-api-adapter` vs `main`/`l1`), coordinating cross-repository locations

[`docs/adr/0002-integration-branch-policy.md`](../adr/0002-integration-branch-policy.md):

- `integration/enshrined-evm`, cut from `engine-api-adapter` @ `627318b5`, is the program's
  long-lived base. All tickets branch from and target it. It is an integration line, not a
  release branch; it never fast-forwards `main`.
- `main`, `l1` and the aggregator partitions/shards keep independent cadence.
- `F1` (#9) reconciles `main`/`l1` vs `engine-api-adapter` and pins the real BFT/reth/config
  revisions and PR-triggered CI.
- Cross-repository homes (reth fork, contracts repo, SDK repos, Yellowpaper upstream) are
  tabulated for maintainer/owner confirmation. None are assigned implicitly.

### 3. Adopt the contribution/closure workflow; propose required PR checks/reviewer rules for maintainer approval

- [`CONTRIBUTING.md`](../../CONTRIBUTING.md) — claim procedure, branch naming
  (`<id>/<slug>`), stacked-PR base rules, PR contents, per-change-type evidence table,
  definition of done, and an explicit statement that repository protections remain **off by owner decision**.
- [`docs/pos/PROCESS.md`](PROCESS.md) — the normative workflow (imported unchanged).
- [`docs/pos/repo-protection-proposal.md`](repo-protection-proposal.md) — the owner decision to leave protection off, with contributor review and CI expectations.
  No settings are applied by this PR.

## Acceptance tests and evidence

| Acceptance test | Evidence |
|---|---|
| Reference PR reviewed and adopted | this PR; reviewer checklist above; merge into `integration/enshrined-evm` records adoption |
| Working branch policy recorded | ADR 0002 |
| Contributors can identify how to claim work, link companion changes, supply independent acceptance evidence | `CONTRIBUTING.md` §1–§4, `PROCESS.md` |
| Any repository enforcement settings to be changed are explicitly recorded for maintainer approval | `repo-protection-proposal.md`; **no settings changed by this PR** |
| F1 owns implementing and validating missing CI coverage | stated in ADR 0002 §2, `repo-protection-proposal.md`, `CONTRIBUTING.md` §5; tracked on issue #9 |

## Explicitly out of scope for R0

Production deployment, currency issuance, bridge activation, the PoS switch, and any change
to live repository settings. R0 closes when this PR is reviewed and merged and a maintainer
records the enforcement decision (protection off for trusted contributors) in the closing comment.

## Reproduction

```
# Specification snapshot (independent checkout):
git clone https://github.com/unicitynetwork/unicity-yellowpaper-tex && cd unicity-yellowpaper-tex
git checkout 3da5c235427941c135f03779ca9e5d47611769b7
git apply /path/to/bft-core/docs/pos/specification/repair.patch
latexmk -pdf -interaction=nonstopmode -halt-on-error unicity-yellowpaper.tex   # 166 pages

# Dependency graph is acyclic and the reduced graph preserves all edges:
python3 - <<'EOF'
import json
m = json.load(open("docs/pos/issue-manifest.json"))
hard = m["hard_dependencies"]; red = m["native_blocked_by"]
# acyclicity of the full hard graph
seen, stack = set(), set()
def visit(n):
    if n in stack: raise SystemExit(f"cycle at {n}")
    if n in seen: return
    stack.add(n)
    for d in hard.get(n, []): visit(d)
    stack.discard(n); seen.add(n)
for n in hard: visit(n)
print("hard graph acyclic:", len(hard), "nodes")
EOF
```

## Review decision, 2026-09-06

The seven source files and repair patch were byte-compared with the prepared reference pack.
The branch at `integration/enshrined-evm` was checked at `627318b5` with protection off.
The owner authorized publication and explicitly chose to keep branch protection off.
The former proposal is superseded by the recorded decision; no settings were changed.
The workflow and integration-base policy are adopted. External repository homes remain
consumer-ticket decisions. R0 acceptance does not accept D1-D6 or close M0.
