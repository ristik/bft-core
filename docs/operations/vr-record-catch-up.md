# VR root-record catch-up: the testnet operating limit

Audience: operators of a validator-registry (VR) generation, the VT-12 monitoring pack and the VT-13 handbook. Status: managed-testnet limit for the
PoS-capable VR build at H = 16 (bft-core#1214, #1217; reviewed by astra, rounds 1 to 3). It is an operating limit, not a protocol rule.

## What the protocol bounds and what it does not

- The root projects at most **32 records per root block**.
- One EVM block imports into the SealRegistry the records of one root input (at most 32) and the records hook then applies at most **H = 16**
  of them: `applyRootRecords(min(16, available))`, followed by `elect`. An election is reserved only when VR is caught up with the registry.
- The protocol does **not** enforce a rate over time. Producing 32 records in every root block is legal and would never be served at 16 per EVM
  block. Everything below is a limit operators keep the network inside of.

## The limit, in eligible EVM blocks

An *eligible* EVM block is one the network actually produced, with the hooks running. Missed, stalled or frozen blocks provide no service and do
not count. The limit counts **all projected records**: handoff records (Ack, RecoveryAck, Boundary, OutputRejected, SessionClosed), Closures,
HolderRetirements and any other kind. Nothing is exempt.

Over any rolling window of **ten eligible EVM blocks**:

- at most **4 projected records per eligible block** steady, that is 40 records, plus
- **one extra burst of at most 32 records** (one full root block), that is at most **72 arrivals**,
- against **160 application slots** (10 blocks x H = 16) when work is available.

That leaves a service surplus of 88 slots per window and bounds the accumulated backlog to one burst plus the import cap plus the steady
arrivals. If the published limit applies only to background traffic, budget the handoff records separately and on top: the qualification test
adds them (an election's Ack, Boundary and incumbent Closure) to the stream.

Planning assumptions behind the numbers, not guarantees: an EVM block about every **10 s** and a root round about every **1 s**, so about 10 root
blocks per EVM block. The limit is tight in those terms: 72 arrivals per ten EVM blocks is 0.72 per root block on average, a steady 1.6 per root
block already saturates 16 per EVM block, and the protocol's 32 per root block can be sustained for about 5% of root blocks. If the EVM block
interval grows or blocks are missed, the arrivals allowed per wall-clock second shrink proportionally.

## What to monitor

Four counters, sampled **at the same point** (for example the end of each EVM block), exported together:

| counter | meaning |
|---|---|
| root target | records the root has projected |
| SealRegistry imported count | records the registry holds (`recordCount`) |
| VR cursor | `recordCursor` of VR |
| custody cursor | `recordCursor` of custody (holder 0 of a PoS generation) |

Derived: **import lag** = target - imported, **application lag** = imported - VR cursor, and the **signed** custody difference = custody cursor - VR
cursor. Custody may legitimately finish a block **ahead** of VR, because anyone can apply imported records directly to custody and the adapter
handles that ordering; a custody lead alone needs no intervention. Compare the counters directly or the signed difference, never "any non-zero
difference". Also record the **eligible-block cadence** (blocks per minute, gaps), the VR **module health**
(Healthy / Faulted / Stalled / Inconsistent), and the election state (due, reserved, open output).

The qualification run observed peaks of 91 (import lag), 64 (application lag) and 75 (backlog). They were taken at different points in the block
and are fixture observations, **not alarm thresholds**.

## Alerts

- The rolling arrival limit is violated: more than 72 projected records in ten eligible blocks, or sustained arrivals above the steady rate.
- Import lag or application lag **persists after a burst**: not back to zero within the drain time of the burst (about 2 to 4 blocks at H = 16 for
  a 32-record burst plus the steady arrivals) and still shrinking only slowly.
- VR cursor or custody cursor makes no progress while the imported count moves.
- Custody is **persistently behind** the prefix VR has delivered (custody cursor below the VR cursor across several blocks, not a transient
  within one block).
- A module-health **transition** (Healthy to anything else).
- Module health is anything other than Healthy.
- An election is due and not reserved while VR is caught up (the election is skipped, not delayed, if the hook budget is short).
- The eligible-block cadence falls below plan (missed or frozen blocks).

## Pacing guidance

- Pace **discretionary record-producing operations** (exits and retirement requests, joins, closures you trigger, repairs) so the rolling limit
  holds; spread them, do not batch them into one root block.
- Keep import and application running; do not pause the hooks to "save" load.
- Only `mature` checks `RecordsPending`: it requires custody's cursor to equal the registry's imported count and no pending assignment, so a
  `mature` that reverts with `RecordsPending` is retried after catch-up. `requestRetirement` and `bond` do not check the cursor (rebonding a
  retiring identity with open lots fails with `GenerationClosing`, which is unrelated to catch-up). The qualification test acts only in
  caught-up blocks; that was a fixture choice, not a rule.
- A HolderRetirement is valid once per (holder, identity, generation), must be requested, and is accepted when its record progress is **equal
  to or above** the liability anchor; it is **not** bounded in lifetime by the live-index limit of 8 (maturing a lot frees an index slot, new
  registrations allocate identities), only per identity and generation. Count retirements in the arrival budget.
- After a burst, a freeze, or any lag, **verify cursor convergence (all four counters equal) and election resumption before restoring normal
  load**: the due election must reserve in the block in which VR catches up.

## Evidence

Two runs of `PosCatchUp.t.sol`, both with all four counters separate and equal at the end:

- the **at-the-limit** run counts every record (background, handoff Ack/Boundary/Closure, and each exit's 16 Closures, one HolderRetirement and
  16 Closures) inside the allowance of 4 per eligible block plus one 32-record burst per ten, and asserts the rolling ten-block budget of 72 on
  every block; three successive identities exit and 19 elections complete;
- the **overload** run does not respect the limit: it projects four background records per block and a scheduled 32-record burst every tenth
  block, and on top of that the handoff records and the exits' 33-record sequences. It shows the lifecycle survives and converges under extra
  load; it is not a qualification of the limit.


- Gas pins: H = 16, HookRecordGas 4,963,432, ElectGas 11,995,799, hook envelope 91,560,711 (bft-core#1214).
- Both runs use a 55-record initial backlog, elections on the cadence, and custody retirement facts checked for each exit (lot matured and claimed).
