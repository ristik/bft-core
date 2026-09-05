# Repository enforcement proposal (for maintainer approval)

Status: **proposed, not configured.** R0 (issue #2) requires that any repository enforcement
change be recorded explicitly for a maintainer to apply. Nothing in this file is active.
Contributors self-enforce `CONTRIBUTING.md` until a maintainer applies the settings below.

`F1` (issue #9) owns turning the "required status checks" list into real PR-triggered CI and
a pinned real-reth integration lane; this document only names what should be required.

## 1. Protected branches

| Branch | Rule |
|---|---|
| `main` | already the default branch; unchanged by this program. Program work never targets it directly. |
| `integration/enshrined-evm` | new protection, see below |
| `l1` | unchanged |

### `integration/enshrined-evm` protection (proposed)

- Require a pull request before merging. No direct pushes.
- Require **1** approving review from someone other than the author; require the CODEOWNER
  for the touched area when `CODEOWNERS` is added (see §4). Design (`D*`) and consensus
  changes require a reviewer with the matching protocol expertise named in the ticket.
- Dismiss stale approvals on new commits.
- Require branches to be up to date before merging.
- Require all **required status checks** (§3) to pass.
- Require conversation resolution before merging.
- Require linear history (squash or rebase merges only).
- Restrict who can push to the branch to the maintainer team.
- Do **not** allow force pushes or deletion.
- Include administrators in the above (no bypass).

## 2. Pull-request settings

- Allow squash and rebase merges; disable merge commits (keeps the integration line linear
  and each ticket a reviewable unit).
- Auto-delete head branches after merge.
- Default PR template: require issue link, behavioral change, validation commands + output,
  affected versions, migration/activation notes, cross-repo companion links. (Add
  `.github/pull_request_template.md` — not included in this PR.)

## 3. Required status checks (target set — `F1` implements and wires)

Current CI (`.github/workflows/ci.yml`, `on: [push]`) runs but is **not** PR-gated and the
FFI legs are disabled. Proposed required checks on PRs into `integration/enshrined-evm`:

| Check | Source | Notes |
|---|---|---|
| `build` | `make build` | already exists |
| `vet` | `go vet ./...` | already exists (in `test` job) |
| `test` | `make test` (`-count=1`) | already exists |
| `build-with-ffi` | `make build-with-ffi` | currently `if: false`; `F1` decides whether to require |
| `test-with-ffi` | `make test ZKVERIFIER_FFI=1` | currently `if: false`; `F1` decides |
| `gosec` | `make gosec` | exists as `analyze`, currently `continue-on-error: true`; make blocking |
| `evm-shard-chaos` | `scripts/chaos-evm.sh` | fake-executor only — **not** real-reth evidence; keep, label clearly |
| `evm-shard-compose-e2e` | `docker-compose.evm.yml` | fake-executor only — same caveat |
| `real-reth-integration` | **new, `F1` owns** | pinned reth fork revision; the only lane that counts as real EVM execution evidence |
| `spec-refs` | **new** | fails if an issue/ADR references a spec section that no longer exists after a normative change |

Trigger change: add `pull_request:` to the workflow `on:` list (keep `push:` for branch
CI). `F1` PR makes these blocking.

## 4. Reviewer rules

- Add `CODEOWNERS` mapping: `rootchain/consensus/**`, `network/protocol/**` →
  consensus reviewers; `shardnode/**`, `engineapi/**` → adapter reviewers;
  `docs/pos/**`, `docs/adr/**` → maintainers; contract paths (once a contracts repo is
  named) → contract owners.
- A `D*` ticket PR needs review from a protocol reviewer who is not the author.
- A milestone **gate** issue is closed only with a named maintainer decision recorded in
  the closing comment, in addition to the sub-issue evidence.

## 5. Labels and automation (optional, non-blocking)

- Keep GitHub-native `blocked by` relationships authoritative for readiness; do **not**
  maintain a hand-edited `ready`/`blocked` label as the source of truth.
- Optional: a workflow that comments the unmet prerequisites when a PR references an issue
  whose blockers are still open. Advisory only.

## Application checklist for the maintainer

- [ ] Confirm `integration/enshrined-evm` base branch (ADR 0002) and cut it from `627318b5`.
- [ ] Apply the `integration/enshrined-evm` protection rule in §1.
- [ ] Apply PR settings in §2; add PR template.
- [ ] Add `pull_request:` trigger to CI; mark §3 "already exists" checks required.
- [ ] Add `CODEOWNERS` (§4).
- [ ] Leave §3 "new" checks to `F1`; track under issue #9.
- [ ] Record the approval (date, maintainer) in the R0 closing comment.
