# Root timing under weighted stake and larger committees

Measurements for [#973](https://github.com/ristik/bft-core/issues/973) use
integration base `ce3c579f5d3d39aecf8386f69f93c76fe8601b41`. The fixtures
run an activated reputation epoch with a 10 s local timeout, 900 ms block
rate and S = 256. The stores are durable on both transports. The host runs
use one process with production libp2p over loopback and ext4 stores on
dev-server slot 0.
The laptop runs use the in-memory network. Integration advanced to
`9d5e5a63d` during the runs. The new consensus-manager change adds a
round accessor. The fixture patch combines cleanly with that tip, and
the timings refer to the measured revision above.

The weighted runs use stakes (3,2,2,2,2) in sorted NodeID order. The returner
is the next light member after the stopped member. The warm committee has
stake 9 and the responsive committee after the stop has stake 8 or 9, with
full-committee quorum 8. The test reuses gate 7's single authenticated repeat,
stale held request and fresh follow-up. It withholds the returner's votes
during the covered stretch, except for the repeat. The scripted shard submits
directly to the root manager on both transports and waits at least one round
before resubmitting after the repeat.

The larger rows use unit stake, first with one (7 and 16) or two (32) roots
absent at the end of the sorted order. At the change, those roots return
and every third member of the old responsive set stops, starting at index 0.
The old and current responsive sets both meet the full-committee quorum.
An exact old-quorum row starts with only quorum weight online and spaces the
same number of stops across that old set. Each old QC then needs all of its
voters. Its stale table has at most two consecutive live leaders. The 7, 16
and 32 rows use same-size genesis committees, preserving all root and EVM
bindings at activation. The initial four-root-to-larger attempt failed the
existing continuity checks before timing began.

The larger rows reuse gate 9's EVM shard and three RSMT shards, with 1,000
new leaves per default proof batch. One-stage time starts when the fixture
begins stopping the outgoing roots. On libp2p the endpoint is the first
validator receipt of the fresh certificate for each shard. In memory the
endpoint is the watched root's durable certificate. Rescue time runs from
the first observed unknown-leader round to the next observed commit at the
watched root. In the recorded runs, both round observers started after the
stops, returns and proof diagnostics, and the rescue poll ran in the proof
submission loop. The recorded rescue observations cover that post-setup
window through fresh certification. The current fixture starts both
observers before the first stop and polls for rescue independently of proof
submission. The committed head is timestamped after its read returns. The
rescue window closes when the submission loop records the last watched-root
certificate, and samples whose reads finish after that cutoff are discarded.
The selector is checked for every recovery-run owner through one cycle and
at its repeat.

## Weighted five-root results

The recovery cycle is 1,280 rounds on every run. D is the stopped member, X
the returner. Each placement has one run per transport. The two-stage
comparison uses `46T + 8rho + 822tau + R` from
the four-root gate 7 evidence in #886. The table substitutes each sample's
maximum observed known certified round (rho), maximum observed unknown round
(tau), and scripted resubmission delay (R). An observed pass against this
comparison does not establish the expression as a bound for arbitrary
weighted committees. [Gate 7 and gate 9 evidence](https://github.com/ristik/bft-core/issues/886#issuecomment-6720964789)

| Transport and stop | Rounds from X's return to repeat commit + fresh submission to certificate | Held to certified | X returned to certified | rho max | tau p95 / max | R | Comparison | Observed verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Libp2p, heavy (index 0) | 505 + 2 | 95.623 s | 281.678 s | 0.510 s | 64.22 / 165.53 ms | 65 ms | 600.210 s | Pass |
| Libp2p, light (index 1) | 250 + 4 | 42.115 s | 249.975 s | 0.503 s | 53.81 / 76.90 ms | 33 ms | 527.272 s | Pass |
| In memory, heavy (index 0) | 505 + 2 | 385.955 s | 581.775 s | 1.159 s | 782.56 / 974.44 ms | 392 ms | 1,270.651 s | Pass |
| In memory, light (index 1) | 250 + 4 | 214.485 s | 433.494 s | 2.111 s | 1,132.29 / 1,310.86 ms | 731 ms | 1,555.148 s | Pass |

The heavy stop crossed D's run at round 283 and committed the repeat in X's
run starting at 539. The light stop reached a live run at 283. The
comparisons use the unrounded timing observations. Held-to-certified
headroom against the sampled comparison was 504.587 s, 485.157 s, 884.696 s
and 1,340.663 s in table order. Both host samples exceeded the original
50 ms tau premise at p95.

| Transport and stop | Unknown-leader intervals, half-open round ranges |
|---|---|
| Libp2p, heavy | [58, 283) for 10.064 s and [287, 539) for 12.897 s |
| Libp2p, light | [57, 283) for 9.534 s |
| In memory, heavy | [58, 283) for 142.986 s and [287, 539) for 163.648 s |
| In memory, light | [57, 283) for 174.157 s |

## Larger equal-stake committees

Each row is one run. The one-stage comparison takes the slowest of the
four shards' first fresh certificates. Rescue includes dead recovery runs
between unknown intervals. “Unexercised” means the poll saw no
unknown-leader round during the recorded post-setup window.

| Transport and roots | Quorum before and after the stop | Recovery cycle | First fresh certificate per shard, slowest (≤ 360 s) | First observed unknown to next observed commit (≤ 75 s) |
|---|---|---:|---|---|
| Libp2p, 7 | 6 → 5 online, quorum 5 | 1,792 rounds | 285.452 s, pass by 74.548 s | 67.362 s, pass by 7.638 s |
| In memory, 7 | 6 → 5 online, quorum 5 | 1,792 rounds | 91.215 s, pass by 268.785 s | Unexercised |
| Libp2p, 16 | 15 → 11 online, quorum 11 | 4,096 rounds | 354.793 s, pass by 5.207 s | Unexercised |
| In memory, 16 | 15 → 11 online, quorum 11 | 4,096 rounds | 106.162 s, pass by 253.838 s | Unexercised |
| Libp2p, 16, exact old quorum | 11 → 11 online, quorum 11 | 4,096 rounds | 746.732 s, **fail** | 117.008 s, **fail** |
| Libp2p, 32 | 30 → 22 online, quorum 22 | 8,192 rounds | 221.341 s, pass by 138.659 s | Unexercised |
| Libp2p, 32, exact old quorum | 22 → 22 online, quorum 22 | 8,192 rounds | 1,509.208 s, **fail** | 260.157 s, **fail** |

| Transport and roots | Unknown-leader intervals, half-open round ranges |
|---|---|
| Libp2p, 7 | [88, 291) for 10.942 s and [295, 547) for 15.273 s |
| In memory, 7 | No unknown-leader interval in 12 observed rounds |
| Libp2p, 16 | No unknown-leader interval in 54 observed rounds |
| In memory, 16 | No unknown-leader interval in 14 observed rounds |
| Libp2p, 16, exact old quorum | [158, 327) for 29.795 s and [331, 583) for 45.482 s |
| Libp2p, 32 | No unknown-leader interval in 27 observed rounds |
| Libp2p, 32, exact old quorum | [286, 391) for 62.941 s and [395, 647) for 154.605 s |

The seven-root libp2p sample had 25 full timers (252.284 s) and 455
unknown rounds (about 26.2 s, p95 76.74 ms by the 5 ms polling trace).
The first observed unknown round was 218.083 s after the stop. The laptop's
corresponding run certified during its post-setup window. The two runs
differ in host, transport and certificate endpoint. The spare-voter
16-root libp2p run spent 343.090 s in
34 full-timer rounds before the certificates. The spare-voter 32-root
libp2p run spent 217.181 s in 21 full-timer rounds and certified after
27 observed rounds.

The first observed unknown round in the exact-quorum 16-root run was 629.738 s
after the stop. It logged 65 full timers (666.925 s in all) and 421
unknown rounds (p95 261.76 ms). The rescue crossed the four-round run of
the stopped first recovery owner before reaching the next owner. The
360 s target was already missed before the rescue began.

The first observed unknown round in the exact-quorum 32-root run was 1,249.098 s
after the stop. It logged 123 full timers (1,281.733 s in all) and 357
unknown rounds (p95 910.96 ms). Both exact-quorum runs certified on the
first live recovery run after the stopped first owner. The seven-root
libp2p run was the only observed rescue pass above five roots. The single
spare-voter libp2p run at each of 7, 16 and 32 roots met the one-stage target
with the margins shown above. The 16- and 32-root spare-voter runs had no
observed unknown-leader interval in the post-setup window.

## Scope of the timings

For the historical equal-stake controls at S = 256, #886 measured
four-root rescue at 59.6–60.4 s. The five-root libp2p check measured
21.0–42.2 s for first fresh certificates and observed zero unknown-leader
windows. [Small-committee verdict](https://github.com/ristik/bft-core/issues/886#issuecomment-6727511100)

The legacy four-root in-memory control on this laptop completed both
rescue and certification. It took 284.536 s from first unknown to commit
and 436.776 s from its historical stop-and-return time origin to the
certificate. Both exceed the host targets.

The two-stage samples cover two weighted placements and a scripted
resubmission. They do not establish the real-shard R or cover a shard
leader that is unavailable at the repeat. The larger samples exercise
selected quorum-preserving stops with one pending transition per shard.
The choice of transport, local disk and process scheduling all affect
elapsed time. Multi-host timing, other phases, delivery after loss of
all ingress copies, and sustained post-recovery certification remain open.

The 32-root row exercises the native coupled fixture. B1 admission
has a separate 16-member ceiling.
[Assignment limits](https://github.com/ristik/bft-core/blob/ce3c579f5d3d39aecf8386f69f93c76fe8601b41/evmassign/assignment.go#L61-L68)

## Reproduction and evidence

Both test entry points are opt-in. On the dev server, reserve one private
lane slot before the libp2p runs. Use a directory on the disk being measured
for `TMPDIR`. Repeat the weighted command with dead index 1, and the larger
command with sizes 16 and 32. The exact old-quorum command covers the
32-root run recorded at 34m35s. Set `BFT_973_MEMBERS=16` for the other
exact old-quorum row. The in-memory rows omit
`BFT_TRACE_TRANSPORT`. The measurement fixtures report deadline misses
and continue until certification or the test timeout. A Go test PASS
records fixture completion. The timing verdicts are in the tables above.

```sh
CARGO_BUILD_JOBS=4 GOMAXPROCS=4 BFT_TRACE_TRANSPORT=libp2p \
  BFT_973_WEIGHTED=1 BFT_TRACE_DEAD=0 \
  go test -p 4 -v -count=1 -timeout=30m ./rootchain/consensus \
  -run '^TestWeightedTwoStageTiming$'

CARGO_BUILD_JOBS=4 GOMAXPROCS=4 BFT_TRACE_TRANSPORT=libp2p \
  BFT_973_LARGER=1 BFT_973_MEMBERS=7 \
  go test -p 4 -v -count=1 -timeout=30m ./rootchain/consensus \
  -run '^TestLargerCommitteeRescueTiming$'

CARGO_BUILD_JOBS=4 GOMAXPROCS=4 BFT_TRACE_TRANSPORT=libp2p \
  BFT_973_LARGER=1 BFT_973_MEMBERS=32 BFT_973_EXACT_QUORUM=1 \
  go test -p 4 -v -count=1 -timeout=38m ./rootchain/consensus \
  -run '^TestLargerCommitteeRescueTiming$'
```

Host logs and lane launcher output are in `~/evidence/973-timing/`.
Weighted rows are `libp2p-weighted-{0,1}.log`. Successful larger setup uses
the `matched-*.log` series. Exact old-quorum rows use
`BFT_973_EXACT_QUORUM=1` and the `exact-*.log` series. Laptop logs are in
`briefs/973-evidence/` in the task workspace. Both paths used
`GOMAXPROCS=4`. The server used Go 1.27.3 on Linux and the laptop
used Go 1.27.4 on macOS.
