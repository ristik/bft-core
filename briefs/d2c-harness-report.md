# D2-C fault harness report

Run one case per invocation:

```sh
D2C_SCENARIO=pair-term URETH_BIN=/Users/risto/uni/agre/ureth/target/release/unicity-reth \
  D2C_PERSISTENCE_THRESHOLD=64 ./scripts/d2c-fault-harness.sh
```

The harness injects the process faults at certified B5. It has process controllers for
`pair-term`, `pair-kill`, `ureth-kill`, `all-kill`, and `leader-kill`. SIGKILL scenarios record
reth heads immediately after relaunch and their lag against the B5 certified target. The controller
restores/checks the static reth peer mesh before the monitor tests continuation. A local JSON-RPC
proxy now supports bounded outage and proof-byte corruption for `debug_getRawHeader` and
`eth_getProof`; those cases have not yet been run. The missing-body test needs D2-A's journal.

Two pair-term runs reached B5, sent SIGTERM to shard 1 and reth 1, and relaunched them. Both
reported reth1 at B5 immediately after relaunch while the other reth clients were at B7, so the
observed B5 lag was zero. The restarted shard repeatedly logged `status syncing` for certified
blocks, then the monitor stalled before B6 while the other clients advanced to B38/B43. Those runs
also showed reth1 with `connected_peers=0` after restart; they cannot distinguish D2-A/B recovery
behavior from missing reth peer connectivity. A third run with a peer restoration check failed
inside that controller before shard restart; its captured log does not include the subprocess
diagnostic. The monitor now preserves that diagnostic for subsequent runs. These attempts remain
inconclusive. They do show the stricter same-block lane-check rejecting warnings without matching
recovery.

The 15:50 and 15:52 timestamped scaffold logs and the 16:26 one-line proof logs predate the
process/proxy controllers; they are not fault-injection evidence.

| Scenario | Result | Classified reason |
|---|---|---|
| pair-term | INCONCLUSIVE | Two SIGTERM pair restarts ran but reth1 had zero connected peers and stayed at B5; shard logged certified blocks as unavailable (`status syncing`) and the monitor stalled before B6. A third run failed the peer restoration check before shard restart. Repeat with child diagnostics now preserved. |
| pair-kill | NOT RUN | SIGKILL pair controller is wired; needs an execution with peer restoration verified. |
| ureth-kill | NOT RUN | Ureth-only SIGKILL controller is wired; needs an execution. |
| all-kill | NOT RUN | Four-pair SIGKILL controller is wired; needs an execution. |
| leader-kill | NOT RUN | Controller detects `leader=true` on a proposal round after B5, then kills that pair; needs an execution. |
| proof-outage | INCONCLUSIVE | The proxy dropped two `debug_getRawHeader` calls for 10s, restored forwarding, and B6 was observed on all validators. The monitor stalled before B7 with reth1 at B6 while the other clients reached B48; validator 1 reported the next certified block unavailable (`status syncing`). The lane's final divergence scan then hit a shell syntax error because its script was edited during the live run. Repeat with the current clean `bash -n` version. See the 16:36 proof-outage log. |
| proof-corrupt | INCONCLUSIVE | The lane exited with status 143 during topology setup, before starting the proxy or mutating proof bytes. A different paired-devnet lane was active in another worktree at the same time; rerun when its shared ports are free. See the 16:42 proof-corrupt log. |
| missing-body | EXPECTED-FAIL | Needs D2-A durable journal entry and target. |
| wrong-genesis | EXPECTED-FAIL | Retained-state wrong-genesis restart hook is not implemented; startup identity checks do not cover this case. |

The pinned ureth binary is commit `32e1f2fc769dfeddc18dce600e82331c8ed6279e`, SHA-256
`112234b775cf674c253e603a5d095634ce6aea88143451a1d459156dca6fd936`. Each run logs
`--engine.persistence-threshold 64`. No SIGKILL replay has yet shown nonzero lag. No Go source was
changed.

## Remaining acceptance work

- Repeat pair-term after verifying the reth mesh reconnects; then run pair-kill, ureth-kill,
  all-kill, and leader-kill through B10.
- Add a local proxy that can drop `debug_getRawHeader`/`eth_getProof` for a bounded period and flip
  bytes for the corrupt case; verify automatic continuation or named fail-closed behavior.
- After D2-A lands, remove a certified journal body and test retained-state recovery; add the
  wrong-genesis restart case.
- Show nonzero lag and automatic replay for at least one SIGKILL run after D2-A/B.
