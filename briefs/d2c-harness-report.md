# D2-C fault harness report

The harness is env-selected and runs one scenario per invocation:

```sh
D2C_SCENARIO=pair-term URETH_BIN=/Users/risto/uni/agre/ureth/target/release/unicity-reth \
  D2C_PERSISTENCE_THRESHOLD=64 ./scripts/d2c-fault-harness.sh
```

Each invocation writes a timestamped log under `briefs/d2c-harness/` and finishes with a
`D2C[scenario]` verdict. `pair-term` runs the existing authority-mode D2-C restart probe, which
restarts only validator 1's shard process. It is deliberately classified as expected-fail for
the requested pair fault; the probe does not stop or restart reth. The other process faults have
no injection/relaunch hook on this branch and are recorded as expected-fail without claiming they
were exercised. The missing-body case is gated on D2-A's journal.

The real baseline run used the pinned ureth binary (commit
`32e1f2fc769dfeddc18dce600e82331c8ed6279e`, SHA-256
`112234b775cf674c253e603a5d095634ce6aea88143451a1d459156dca6fd936`) and four external
signing authorities. It certified B1–B10 on all four reth clients. Validator 1 restarted its
shard process after B5, retained its authority PID/key/session, submitted five later requests,
appeared in six root quorum proofs, and accepted five later certificates. No unresolved divergence
was logged. The engine persistence threshold was set to 64 blocks and logged at startup. Since the
probe left reth running, it did not measure reth replay lag.

| Scenario | Result | Classified reason |
|---|---|---|
| pair-term | EXPECTED-FAIL | Existing probe restarts shard only; pair SIGTERM/relaunch is not exercised. Baseline itself reached B10; see timestamped pair-term log. |
| pair-kill | EXPECTED-FAIL | Process fault hook absent on D2-C branch; SIGKILL pair and retained-data relaunch were not run. |
| ureth-kill | EXPECTED-FAIL | Process fault hook absent on D2-C branch; ureth-only SIGKILL while shard stays live was not run. |
| all-kill | EXPECTED-FAIL | Process fault hook absent on D2-C branch; four-pair kill/relaunch was not run. |
| leader-kill | EXPECTED-FAIL | No proposal-time leader detection or pair-kill hook on D2-C branch. |
| proof-outage | EXPECTED-FAIL | No local proof RPC proxy or outage injection hook on D2-C branch. |
| proof-corrupt | EXPECTED-FAIL | No proof mutation hook on D2-C branch; no no-sign/no-commit evidence collected. |
| missing-body | EXPECTED-FAIL | Needs D2-A durable journal entry to delete and target for recovery. |
| wrong-genesis | EXPECTED-FAIL | No retained-state restart hook for this case; existing startup identity checks are not a wrong-genesis recovery test. |

The timestamped logs for the eight unrun fault injections contain their explicit expected-fail
verdicts. The pair-term log contains the full B1–B10 baseline and the shard-only probe evidence.
No Go source was changed. No Go recovery behavior was inferred from an unrun fault.

## Follow-up hooks needed for full acceptance

- Add scenario hooks to stop/relaunch owned shard and reth PIDs while preserving datadirs and
  authorities; detect and kill the current leader while a proposal is in flight.
- Add a local JSON-RPC proxy for `debug_getRawHeader` and `eth_getProof` that can time out or
  mutate response bytes for one validator, then restore forwarding.
- After D2-A lands, remove a journal body at a certified target and restart against it.
- For every SIGKILL recovery, record the certified target and each reth head immediately after
  relaunch, then verify continuation through at least B10 and show nonzero lag at least once.
- Rebase this branch when #239/#244 merge, then run the complete scenario matrix against D2-A/B.
