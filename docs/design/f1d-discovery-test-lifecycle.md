# F1d: libp2p discovery test lifecycle

Issue: [#100](https://github.com/ristik/bft-core/issues/100). Parent F1 ([#9](https://github.com/ristik/bft-core/issues/9)).

## 1. What was reported, and what was actually found

#100 was opened for two timeouts observed in CI: `TestBootstrapNodes` at `network/peer_test.go:110`
and `TestProvidesAndDiscoverNodes` at `:276`, both "Condition never satisfied". The ticket is explicit
that a timeout is not a diagnosis, and that the leaked `bootstrapNode` is a lead rather than an
established cause.

Investigating produced **one defect with a complete causal chain, and one that remains open**. They
are reported separately because only the first is explained.

### 1.1 Explained and fixed: a leaked DHT panics the package

Running the package repeatedly reproduces a failure that is not a timeout at all:

```
panic: Log in goroutine after TestBootstrapNodes has completed:
       DBG network/peer.go:366 peer 16Uiu2HAm1aKN… removed from routing table

network.newDHT.func1                     network/peer.go:366
kbucket.(*RoutingTable).removePeer       table.go:397
kbucket.(*RoutingTable).RemovePeer       table.go:368
dht.(*IpfsDHT).peerStoppedDHT            dht.go:724
dht.(*query).queryPeer                   query.go:429
created by dht.(*query).spawnQuery
```

**The chain, end to end:**

1. `TestBootstrapNodes` creates `bootstrapNode` with `NewPeer(ctx, …)` where `ctx` is
   `context.Background()`, and — unlike `peer1` and `peer2` — never closes it.
2. `NewPeer` passes that context to `newDHT`, so the DHT's lifetime is bounded only by `Close()`.
   With no `Close()` and no cancellable context, its query workers run for the rest of the package.
3. `newDHT` installs a routing-table `PeerRemoved` callback that logs through the logger it was
   built with — which is `logger.New(t)`, bound to **that test's** `testing.T`.
4. When the test ends, `peer1` and `peer2` are closed. The leaked node's in-flight query notices a
   peer has stopped, `peerStoppedDHT` removes it from the routing table, and the callback logs.
5. The `testing.T` is complete, so the testing package panics — taking the **whole package** down,
   not just this test.

The timing is what makes it reliable rather than exotic: the leaked node is *provoked* by its peers
shutting down, so the panic lands just after the test that leaked it.

### 1.2 Not explained: the reported timeouts

Fixing the leaks removed the timeouts in every run measured here, but **that is not a proof**, and it
is not claimed as one:

- The panic aborts the package the moment it fires, so a run that panics never reaches the later
  tests. Comparing "panicking baseline" against "clean fixed build" cannot separate "the timeouts
  were caused by the leak" from "the timeouts simply had fewer opportunities to occur".
- The measured sample is small (§3) and the failures are timing-dependent by nature.

A plausible mechanism connects them — a leaked DHT server still answers queries and can be inserted
into a later test's routing table, which would break an assertion on an **exact** table size — but it
is untested and stated here only as a hypothesis. The diagnostics in §2 exist so that the next
occurrence decides it rather than requiring another investigation from scratch.

## 2. Making the negative case informative

Every one of these assertions was `require.Eventually(… Size() == N …)`, whose entire failure output
is "Condition never satisfied". That cannot distinguish the two interesting cases:

- the table is **short** — the peer was never reached; or
- the table is **long** — something not created by this test got in, which is the signature of
  cross-test contamination.

`requireRoutingTable` replaces those waits and, on failure, prints for every peer the test knows
about: routing-table size and mode, each member with its `Connectedness`, every expected peer that is
**missing** together with whether we are even connected to it and how many of its addresses we know,
and every peer we are connected to that is **not** in the table. A short table and a long table now
produce visibly different reports.

## 3. Measurements

Each run is the full `network` package with a fresh build, on the F1 development host (12 CPUs).

| Build | Runs | Result |
| --- | --- | --- |
| Pristine baseline (`origin/integration/enshrined-evm`) | `-count=10` requested | **panic** — §1.1, aborting the run at 121.8s |
| Baseline leaks restored, diagnostics kept | `-count=10` requested | **panic** — §1.1, aborting at 121.1s. Confirms the panic is not an artefact of the diagnostics |
| Leaks fixed | `-count=10` | **pass, 199.3s — all 10 completed** |
| Leaks fixed | `-count=5` | pass, 94.9s |
| `TestBootstrapNodes` alone | `-count=20` | pass, 11.3s |
| Both named tests alone, under 10 busy cores | `-count=10` | pass — CPU load alone does not reproduce it |
| Leaks fixed, shuffled | `-shuffle=on -count=3` | pass, 61.3s |
| Both named tests, race detector | `-race -count=3` | pass, 5.2s, no data race |

**The iteration counts are not comparable, and should not be read as if they were.** A panic aborts
the process, so the baseline rows never reached ten iterations — they stopped part-way, at roughly
the elapsed time where the fixed build was around its sixth. What the rows establish is that the
baseline *cannot complete* the run and the fixed build does; they do not establish a per-iteration
failure rate for either.

The isolation runs matter: the named tests do **not** fail alone even on a deliberately loaded
machine, but the package fails. That is what moved the investigation from "slow host" to
"cross-test lifetime", and it is why raising a budget again would have been the wrong repair.

### 3.1 The timeout, measured after the leak fix

The panic used to abort every long run, so the timeouts had few opportunities to appear. With the
leaks fixed the package completes, and the question "do the timeouts still happen?" became
measurable. Two sweeps, both on the merged fix, both with the §2 diagnostics armed:

| Conditions | Iterations | Failures | Diagnostic dumps |
| --- | --- | --- | --- |
| 12 cores (`GOMAXPROCS` unset), 6 × `-count=6` | 36 | **0** | 0 |
| 2 cores (`GOMAXPROCS=2`), 4 × `-count=5` | 20 | **0** | 0 |
| | **56** | **0** | **0** |

The second sweep restricts Go execution parallelism with `GOMAXPROCS=2`. This is a useful
additional scheduling control, not an emulation of the CI environment: it does not reproduce the
runner's OS, CPU quota, networking, or competing workloads. Loading the 12-core machine with ten
busy cores had also failed to reproduce the timeout (§3). Neither reported sweep produced a failure.
An independent review control, `GOMAXPROCS=2 go test ./network -count=3`, also passed all three
iterations (56.8 seconds) on the review host.

**What this does and does not establish.** It does not prove the timeouts are gone; 56 passes cannot
prove the absence of a timing failure, and #100 says so explicitly. What it does establish is that
they were **not reproduced in these local sweeps** of repetition and Go execution parallelism.
This does not establish that other local schedules cannot reproduce them, or that they are fixed.

It also means the next occurrence, wherever it happens, will arrive with the routing/connection state
attached (§2) rather than as "Condition never satisfied". That was the point of the diagnostics: the
boundary stays open, but it is now decidable on first sight rather than requiring this investigation
to be repeated.

## 4. What changed

Test-only. No production lifecycle change, and no assertion weakened:

- Every peer created in `network/peer_test.go` is now closed — `bootstrapNode` in `TestBootstrapNodes`
  and in `TestProvidesAndDiscoverNodes`, `bootstrapNode2` in
  `TestBootstrap_OneBootStrapConnectionFails_StillOK`, `peer1` in `TestBootstrap_AllConnectionsFail`
  and in `TestAnnounceAddrs`.
- The two discovery tests build their peers from a cancellable context cancelled on cleanup, so the
  DHT workers created from it are bounded by the test rather than by the process.
- The waits assert the same conditions with the same budgets; only the failure reporting changed.

**No timeout was raised.** The 8×`WaitDuration` budget in `TestProvidesAndDiscoverNodes` is left
exactly as it was.

## 5. Open

- **The timeout cause (§1.2), still unresolved.** 56 post-fix iterations across two core counts
  produced no failure (§3.1), so these sweeps did not reproduce it — which is not the same as
  fixed. The evidence to decide it is collected automatically on the next occurrence.
- `newDHT`'s routing-table callback logs through a caller-supplied logger with no lifetime relation
  to the DHT. In production that is harmless; in tests it converts any leaked peer into a package
  panic. Whether the callback should be silenced at `Close`, or the logger's lifetime tied to the
  DHT's, is a **production** lifecycle question and is deliberately not changed here — #100 requires
  any production change to be separately explained and tested.
