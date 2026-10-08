# ADR 0013: Root time is non-decreasing seconds plus consensus position

## Status

Accepted design, documenting the owner's root-time decision and the already merged
[bft-core #479](https://github.com/ristik/bft-core/pull/479) (`e261a488`). This ADR adds no code,
wire format, timestamp unit, consensus rule or vector change beyond that implementation.
It supersedes #447's strict whole-second increase and any claim that nominal round pacing
alone supplies a minimum real-time protection window.

## Decision and guarantees

A certified block carries two independent coordinates: its consensus position under the
protocol's epoch/round ordering and its authenticated Unix timestamp in whole seconds.
On the selected committed lineage, positions strictly advance and timestamps never decrease.
An honest proposer uses `max(local_seconds, authenticated_parent_time)`. A live voter requires
`timestamp >= parent_time` and `timestamp <= local_seconds + 30`, in addition to the existing
consensus rules. Equal seconds are valid. Timestamps are not block identities.

The [root specification](../pos/specification/bft.tex), section `sec:root-time-semantics`, gives
notation, premises and short arguments for strict history ordering, time non-decrease, the
conditional future bound `T(B) <= t_cert + eps + Delta`, no rate-induced inflation, and
conditional timestamp liveness. The [assignment design](../design/h3-evm-assignment.md#root-uc-time-445-corrected-by-479)
provides a Markdown statement of the same contract.

The protocol provides a strictly ordered committed history with an authenticated,
non-decreasing physical-time annotation. Consensus position determines ordering; timestamps
support time-based predicates. Timestamp advancement is independent of block production rate.
Certified timestamps have a bounded future offset under explicit honest-clock assumptions,
while freshness and eventual time advancement depend on consensus progress.

## Authentication, history and activation

Preserve timestamp-bound votes/QCs, native commit seals, proof verification before recovery
writes, executed QC-parent lookup, and the old committed floor across epoch anchors. A TC,
restart, recovery or clock rollback does not reset time. Historical verification has no
current-clock cutoff; successful authentication does not retroactively establish a live
clock-admission bound for genesis or legacy history. A live refusal after completed replay
is not a persistence fault. DEV validators activate #479 together because strict-increase
validators reject equal-second proposals, even though #479 changes no wire encoding.

## Consumer obligations and limits

- Use consensus position and ancestry for order. Round differences can include skipped rounds;
  they are neither elapsed seconds nor committed-block counts.
- Preserve EVM header time as a separate derived clock. Its strict increase can lead wall time
  and does not inherit the root future bound.
- An absolute threshold `T(B) >= D` proves only `t_cert >= D - (Delta + eps)` under the stated
  premises. `T(B) < D` proves no real-time upper bound because certified time may be stale.
- A relative gate `T(B) >= T(A) + d` needs a separate premise `T(A) >= t_A - sigma` to prove
  even `t_cert - t_A >= d - sigma - (Delta + eps)`. Without bounded anchor staleness, neither
  a UC-time delay nor adding the 30-second tolerance proves a positive real-time hold.
- **T2 is a root-consensus liveness parameter, not a wall-clock guarantee.** A shard's configured T2 duration is converted to a
  threshold of root rounds (`BlockRate/2` per round) and evaluated by the root's own progress: a repeat UC is issued when the root has
  advanced that many rounds without a certification request from the shard. Elapsed real seconds are neither measured nor promised;
  if a deployment needs T2 to mean elapsed real time, that is a separate timing-rule change, and changing one constant is not a proof.
- **Client request expiry (`expiresAt`, TTL) is measured in protocol time**: the authenticated UC/reference seconds of the round that
  processes the request, with the exclusive comparison `t < deadline` against the leaf's own pinned reference time. It is not a wall
  clock and not an EVM or round clock: during a stall or while certified time is stale, a request does not expire promptly, and a
  service that wants a real-time timeout must define one separately without rewriting historical leaf time. The same holds for the
  native bridge's explicit deadlines.
- A checkpoint-staleness safety policy must use an independently enforced, authenticated
  real-time protection floor. Round-period multiplication remains advisory. #85's UC-seconds
  timeFloor cannot be treated as that enforced real-time floor without the missing premise.

The [consumer audit](../design/root-time-consumers.md) pins source revisions, affected
file/line locations, equality compatibility, guarantee gaps and minimal dispatch actions.
No consumer code is fixed by this documentation change.

## Documents amended and validation obligations

- `docs/pos/specification/bft.tex`: replace strict-increase wording with the semi-formal contract.
- `docs/design/h3-evm-assignment.md`: align the root UC-time rule and custody clock claims.
- `docs/pos/specification/governance.tex`: remove a real-time-floor inference from round pacing.
- `docs/pos/specification/README.md`: distinguish the historical patch/build from current files.
- `docs/design/root-time-consumers.md`: record the audit and follow-up work for dispatch.

The original `repair.patch` remains a historical artifact, not a reproduction of the amended
sources. No full Yellowpaper rebuild is implied. Runtime release validation must preserve
#479's subsecond/equality regression, future-bound edges, rollback/retry checks, authenticated
recovery and epoch-floor cases. Joined consumer coverage should include unchanged UC seconds
with advancing rounds/records, and distinguish UC deadlines from EVM and wall-clock time.
