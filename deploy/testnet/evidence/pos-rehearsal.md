# PoS profile rehearsal evidence (TN-S #430, P8-TEST #437), runner, 2026-10-22 to 2026-10-24

What this is: the GitHub Actions runs of `testnet-rehearsal.yml` that exercised the PoS generation (`generate.py --pos`) on containers. **Runner evidence, never the host's:** `ubuntu-22.04`, one Docker daemon, four validator entities (root, shard node, execution client, signing authority each) and one aggregator on one machine, genesis identities at unit weight, disposable keys. The stage definitions are `deploy/testnet/rehearse.py` (`POS_STAGES`), `pos_owner.py`, `pos_sample.py`, `pos_crash.py`; the commands to reproduce are in `.github/workflows/testnet-rehearsal.yml` (`pos_stages` input; the default list is the one that passes). The pins of a run are `deploy/testnet/pins.json` at its head SHA; at the time of writing: `bft` 6ec52a81, `ureth` d41d5310, `contracts` ec69d8f0.

## Runs that passed (run id, head, stages)

| run | head | what it showed |
|---|---|---|
| 39766250487 | 818ee8b1b (tn1/pos-1) | first start on the PoS genesis, the 5a smoke: contracts' code at the deployed addresses, election clock rises, no revert (#768). Limits then: `recordCursor == recordCount` was 0 == 0, election not due |
| 39911010502 | 6916fbcba (tn1/pos-6-proof) | the first handoff of the same four entities at unit weights, epoch 1 to 2: proposal, propose, install barrier, activation gate, authority advance, paid work (`pos-election` ... `pos-advance`) |
| 40003458692 | 926fd9d09 (tn1/pos-9) | all PoS stages through `pos-handoff-2` (the second handoff, epoch 2 to 3: install over the epoch-2 stores, activation, paid work) |
| 40025132181 | f8706fa7e (tn1/pos-12) | adds `pos-recreate`: one root recreated from `compose.yaml` alone, no install flag; the three live roots advanced rounds with another root stopped |
| 40038068832 | ab3282c2a (tn1/pos-13) | adds `pos-too-late` (Abort after H refused by every root; no Abort record, no epoch move); the full table of OPERATOR 5b rehearsed on a runner |
| 40063422404 | 23a1ed717 (dev3/pos-owner) | the whole list incl. `pos-owner`: a paid reward claim (half, then the rest, of a 257,750,000,000,000,000 wei credit; exact recipient and pool deltas; refused further claim and claim without credit) and an exit declaration (`NotOwner`, `RetirementRequested`, `RetirementAlreadyRequested`, `GenerationClosing`, `mature` refused by `LotStillReferenced`, nothing released) |
| 40065780609 | 5e4397c49 (dev3/pin-contracts-72) | the same list on the contracts pin ec69d8f0 (contracts#72); **attempt 1 failed at `pos-restart`** ("survivor 1 mines it with validator 2 down: not within 240 s"), unexplained, passed on a rerun of the failed job |
| 40070707716 | e1adbd177 (dev3/pos-owner) | `pos-observe` and `pos-owner` together in the combined list (#834) |
| 40075138164 | 87a015020 (dev3/pos-observe-health) | `up, identity, first-tx, pos-observe`: the sampler with its health wait (#838) |

`pos-observe` (the sampler for two samples, no alert) and its first live run, which failed on a 429 burst and was fixed (#833), are in the PRs. Stage-level results are in each run's artifact `testnet-rehearsal-pos-evidence` (`result.json`, `rehearsal.log`, `compose-logs.txt`); artifacts expire after 90 days, so the table above is the durable record.

## Runs that failed on purpose (opt-in stages, not in the default list)

`pos-crash*` (SIGKILL of one entity's containers): bft-core issue #843 lists the nine runs, the exact commands and the persistence-threshold experiment. In short: whenever the execution client is killed the entity does not recover (epochs 1, 2, 3); killing only the shard node or only the root recovers. Not resolved; a product question.

## Not shown (and where it stays open)

Unequal weights and a joiner (dev's series), overbound mode (native lane), whole-host reboot, a 24 h observation (the sampler exists; only short runner runs were made), resource figures at exact test values (the host's), the public network, a second operator following the procedures, that a restarted root VOTES (an advancing head shows it follows the chain, not that it signs; 3 of 4 certify without it). OPERATOR 5b stays DRAFT until a second operator has run it.
