# X4 shadow comparison adapter (step A)

`briefs/x4-shadow-campaign-design.md` section 2. For a devnet that carries the staking modules but does NOT run the authoritative election hook, the adapter
compares the real `ElectionPolicy.elect` with an independent reference, at identical inputs, on certified state.

| file | role |
|---|---|
| `capture.py` | the complete bounded eligibility inputs at ONE `finalized` block, by `eth_call`/`eth_getStorageAt`/`eth_getCode` at that block number; records the block number, hash and state root |
| `fork.py` | forks exactly that block with `anvil` (one disposable fork per sample), impersonates the system caller only inside the fork, runs the real `elect(origin)` (an `eth_call` for the outcome, then a transaction for the effects), reads the result, kills the fork. Refuses to write unless the fork is the loopback anvil this process spawned, on the pinned chain id, serving the pinned block hash |
| `reference.py` | the independent reference: eligibility, weights, snapshot digest, ranking, greedy selection with the continuity predicates, quantization, the reservation preconditions and every commitment word, from the raw inputs. Pure Python, its own keccak (`keccak.py`); validated against `continuity/testdata/{selection,continuity}-vectors.json` |
| `compare.py` | the field-by-field comparison and the coverage class of an observation |
| `report.py` | the coverage accounting and the PASS / INCOMPLETE / FAIL rule |
| `adapter.py` | `run` (sample, write `manifest.json`, `observations.jsonl`, `events.jsonl`, `raw/`, `report.json`, `REPORT.md`, `SHA256SUMS`), `replay` (recompute the reference over recorded inputs) |
| `test_shadow.py` | the self-tests (CI: `x4-shadow-selftest`) |

```
python3 scripts/shadow/adapter.py run --rpc http://127.0.0.1:18545 --deployment test-nodes/p85/genesis/deployment.json --out OUT --cadence 60 --samples 90
python3 scripts/shadow/adapter.py replay --recorded OUT
python3 scripts/shadow/test_shadow.py
```

Needs `anvil` (Foundry) and Python 3 only. **What a PASS is:** zero divergence between the contract's output and the reference's at the compared fields (outcome, refusal
reason, ordered frozen members with weights and binding hashes, custody's reservation, result, snapshot, policy, predecessor, K and contracts commitments), with every
scheduled sample accounted for, at least 24 due comparisons, at least two observed cases each of a valid changed candidate, an unchanged candidate and a
deliberate refusal, and at least one refusal beyond the churn bound. **What it is not:** the election runs on an anvil fork, not on ureth (no enshrined hook, no
precompiles), so this is a comparison, not consensus evidence. The origin passed to `elect` is the registry's stored origin identity at the pinned block (the
hook passes the block's own origin; they coincide except in a block that changes the origin).
