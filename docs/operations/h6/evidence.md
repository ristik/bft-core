# Evidence, interruption and acceptance

Return to the [entry point](README.md). Approval rests on the run's own artifacts, not on this page or on a developer's PASS message.
For the container stack, record what [OPERATOR.md section 9](../testnet/OPERATOR.md#9-rehearsal-evidence-to-record) lists; this page adds what
the native lanes need.

## What to keep

Per run: the documentation revision and the checkout's `git rev-parse HEAD`; Ureth and rugregator commits and binary SHA-256s (the lane's `heads.txt`
and `pins.txt`); `lane.log` whole; the evidence directory the lane wrote (`h3/`, `nodes/`, `f8/`); every command with its exit code and UTC time;
the signing authorities' status before and after each operation (generation, reserved round, fingerprint, `faulted`/`keyLost`); the offline-proof
inputs (bundle, expected claim, PDR, genesis configuration and every epoch trust base) so the verifier can be rerun in a network-denied process.
Make a SHA-256 inventory after collection. Publish only an allowlisted copy: omit `keys.json`, JWTs, client and operator credentials, private state and
environment dumps (hashes do not redact secrets).

A monetary history anchor is cheap and decisive for execution-version activation and restores: before the operation, save every finalized block
through the tip with its full receipts (hash, `stateRoot`, `receiptsRoot`, transactions), and require the same bytes at the same heights afterwards
on every execution client. An Ethereum receipt alone is not certification: the finalized tip must also have a matching `certificate admitted` line in each
shard log.

## Interruption objectives

OWNER approves the objectives before the run. Proposed defaults for a dedicated host: at most 40 s certification pause for an ordinary handoff;
120 s for a coordinated execution stop, swap and restart; 180 s to restore one validator and resume its signing. Keep the cluster's service
interruption and a single node's restore time separate. The latter two are provisional budgets, not measurements.

Measure from outside: poll every execution client's `finalized` block (about every 0.5 s, UTC and monotonic timestamps) through the operation without
resetting the clock, record errors as observations, and compute from the last distinct certified block before the operation to the first distinct one after,
on each affected validator; report the worst validator and the cluster's gap, and require three further advancing samples and a successful certified paid
transaction. Missing endpoints or missing certificates mean **unmeasured**, never zero. The lanes' own pause lines (`m2_measure_pause`, T6) measure the
old-epoch to new-epoch log gap only: keep that number, and do not substitute it for the other operations.

## Acceptance map

| H6 requirement | Evidence required |
|---|---|
| Fresh reproducible setup | OPERATOR.md run by someone other than the author: pins, image IDs, manifest, identity check, certified heights twice. |
| Key rotation | H3 lane: the joiner steps, the committed coupled change, authority advances, retired-key refusal, new-epoch paid certificate. A configuration-only boundary is not rotation. |
| Joiner behind the chain | H3 lane step s=2: the joiner's restore from a retained validator's archive and its readiness before the Commit. |
| Archive-backed restore | H3 retained-node loss and the M2 lane restore: pin UC/TR, genesis anchor, body identity per Q3 activation, replay log, equal block, state and receipt roots, the same authority lifetime, a greater reserved round. |
| Interrupted handoff | H3: the EVM stalls after a committed H while roots and aggregators move; the derived recovery K extends it; the late acknowledgement is refused. |
| Execution-version activation | Manual procedure (scenarios.md section 5) with its anchors; no lane exists. |
| Abort before and after H | Not rehearsed on this layout until the manual helper is ported (scenarios.md section 6); record as such. |
| Interruption objectives | Observer data, boundaries and PIDs, per-node and cluster durations against the approved objectives. |
| Certified history verifiable | Saved receipts and roots unchanged; archived UC/TR and handoff chain; the F7 proof re-verified offline by the second operator. |
| No certified monetary reorg | Fixed-height comparisons and a monotonic finalized observer; preserve the stopped state if recovery cannot be proved. |
| Execution by a non-author | A named human second operator, the documentation revision, transcript and defects. The author's source checks are not independent acceptance. |
| Authority loss and freshness (issue discussion) | Unsupported here (same-key resurrection is refused); needs separate evidence for certified replacement, clone fencing, expired receipts and storage faults. Do not mark issue 23 complete from the lanes alone. |

## Refusals: stop at the first unexplained one

| Diagnostic or record | Action |
|---|---|
| `invalid epoch transition encoding` | Wrong Ureth for this layout; there is no migration. Recreate a disposable network; never rewrite live genesis. |
| `signing-unsupported-version` | Client and service protocol mismatch: stop the client, restore matching artifacts without touching the live authority. |
| `signing-enrollment-incomplete` | A pending authority issues no session before its enrollment names its key (a joiner before the Commit): start its staging-only node without one; enroll after the Commit. |
| `restore trust anchor is not the genesis root epoch` | Supply the epoch-1 anchor; keep the current BodyID separately. |
| `no archived verified-trust body identity for epoch N` (`h4-restore-pin`) | A Q3 activation is not archived as a bundle: name it with `H4_RESTORE_BODY_IDS="N=<hex>"` from the activation record. |
| `archive wiring: archive peer is not allowed` | The serving validator has not installed (or been staged with) the assignment that names the joiner. Retry on fresh paths once it logs `handoff activated`. |
| `root-record import missing ... recordsfeed: the root log is unavailable` | The roots serve records to the installed members and the staged successor only; stage the candidate on the incumbents first. |
| `retained prefix is shorter than the checkpoint's and could not be fetched` | A joiner root must follow the chain (`--install-handoff-epoch` of the installed epoch) before its own install, and be in the staged successor committee. |
| `frontier: wrong context or configured replicas` / `replica pair change must retain one acknowledging replica` | Change one replica at a time and keep the acknowledged peer; a node refuses to name a replica its installed assignment does not contain. |
| `candidate lacks its retained authorizing or resulting certificate`, `no certified association` | Compare the prune frontier with the local archive tip; beyond the window the recovery is an archive restore. |
| `root handoff: the Prepare lapsed before it was endorsed`, `phase=lapsed` | The attempt is dead; wait for the terminal state and rebuild the candidate and receipts for the next attempt. Not Abort evidence. |
| `too late` | The matching H already committed: no cancellation. Install the successor or supersede with the derived recovery K. |
| `ErrHandoffNeedsV3Plan` | A V2 plan on a V3 chain: use `q3-candidate`, receipts and `propose --readiness-receipts` (or `propose --q3` for the exact recovery). |
| `local operator access required`, `application/json without Origin required` | Use loopback or a control tunnel and the provided CLI; do not weaken the endpoint's checks. |
| `authority ... exited during startup`, `keyLost`, `faulted` | Preserve logs, fence the validator, escalate. No restart or key import restores the old signing permission. |

Also: [bootstrap failure handling](../bootstrap-trust-pin.md#failure-handling) and [M2 stop conditions](../m2-runbook.md#6-checks-and-stop-conditions).
Escalation records need the artifact pins, run ID, last certified tip and the exact refusal, without credentials; OWNER supplies the contact.

## Independent execution

A fresh agent with no repository context may follow only these pages, the linked runbooks, documented `--help`, command output and generated
artifacts. Missing variables, unexplained flags, hidden files, manual source edits, undocumented recovery choices, stale evidence passing checks or author
intervention are **documentation defects**: stop that scenario, record the defect, fix the page and repeat on a fresh disposable fixture. A fresh agent
is a usability test; the human second operator appointed by OWNER is still needed for acceptance.
