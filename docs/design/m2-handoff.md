# M2 WP3 handoff contract

Status: inert API and model tests. The normative transition is [D4](d4-epoch-handoff-state-machine.md), including its reconfiguration suffix and v2.1 errata. This note maps that design to the root and EVM child work. `rootinput/v2.go` still refuses runtime transitions.

## Control record and old proof

`P_CTL = 0xFFFFFFFF` is the frozen rightmost UnicityTree leaf. It is root-maintained control state, never a shard or UC destination. Its canonical value contains the record bytes and original order round `o`, along with network, old epoch, attempt, predecessor body, phase and previous control digest. The record payload excludes its own ID, signatures and proof. The D4 RecordID hashes canonical record bytes, including `o`; the WP3 envelope is version 2. WP1's trust-base body encoding is unchanged.

A handoff proof carries `{profile, record, ControlState, path_CTL, QC(c+1) [, QC_c], full snapshot}`. The verifier fixes both the path leaf key and IMT lookup key to `P_CTL`, reconstructs `R_H`, and verifies the old set's commit-capable `QC(c+1)`: its `VoteInfo.ParentRoundNumber = c`, `LedgerCommitInfo.RootChainRoundNumber = c` is nonzero, and its committed state root is `R_H`. The voting root is also `R_H`; this binds the identity suffix. `c >= o`, and `QC_c` is optional. The old trust base is independently authenticated and in force for the signer epoch. A signed root QC authenticates the execution state, not arbitrary block payload bytes. The real adapter must put the control leaf into the state tree and verify its path; the current root connects ancestry by parent round and state root, rather than a signed block hash.

The `handoff` verifier returns typed `{context, kind, recordID, orderRound, commitSealRound, stateRoot, controlDigest, signerEpoch}`. The machine checks those fields against the record and keeps the verified result through Finalize. Bootstrap takes the next trust-base body, derives the canonical epoch genesis, and compares its exact bytes with the supplied anchor. It also binds the verified record to the machine's committed record and permits only idempotent reinstallation before activation. The old-set interface verifies ordering, endorsement and finality; a separate new-epoch interface verifies the EVM acknowledgement. The fake test verifier admits only configured `(kind, ID)` pairs. These interfaces do not implement runtime QC signatures.

## Suffix, genesis and consumers

On a branch containing committed H, old voters reject later proposals with payload, scheduled config activation, timeout, nextEpoch or any hidden state change. Empty old suffix rounds can continue to certify and eventually prove H; every such transition preserves `R_H`. There is no old round fence. A later suffix QC can mint another valid old UC for the same shard state, so consumers must classify it using the authenticated snapshot rather than assume a unique terminal UC.

The verified checkpoint derives typed `EpochGenesis G` and `GenesisID`, with anchor slot `A*−1`. After importing the full snapshot and durable auxiliary state, the new pacemaker starts at fixed `A*` even if the old proof seal round `c >= A*`. The anchor is never an ordinary commit subject. New timeout and recovery paths must retain typed anchor evidence; old QCs cannot advance the new pacemaker. Ordinary new blocks commit only consecutive ordinary new parents. The first new leader follows D4's deterministic fallback until certified new history suffices for reputation selection.

All UC consumers compare authenticated `(rootEpoch, rootRound)` lexicographically. Before proof installation, a potentially terminal old same-IR UC at round `>= o` is deferred without timeout or revert until the snapshot classifies it. Once installed, every old UC is historical only, even before new certification is ready. A valid new `(e+1,A*)` succeeds an old `(e,c)` even when `c > A*`. Shard state continuity, canonical IR equality, and one-time transition installation survive restart. Successor uniqueness across attempts depends on the root's ordered control state, not this per-attempt machine alone.

## EVM acknowledgement and child work

`SealRegistry.open` executes the authenticated transition and acknowledgement first in the successor's first block. It binds the frozen certified EVM parent, successor TR, commit ID, FrozenID and root context before user transactions. The successor extends exactly that parent. Existing `SealRegistry.open` rejects root-epoch changes and transitions, so both **ureth and contracts** must change. Readiness and replay must enforce the same ordering and parent checks.

- Root child PR: add the P_CTL leaf and checkpoint encoding, enforce the suffix in `BlockStore.Add`, reject anchor commits, support typed anchor TC/recovery and leader fallback.
- Consumer child PR: use `(epoch, round)` ordering in shardnode, ureth and SealRegistry, with the terminal-repeat rule and persisted transition floor.
- EVM acknowledgement child PR: update SealRegistry and ureth for first-block `open`, frozen-parent/TR binding and readiness.
- Recovery child PR: verify each inherited LastCR UC with lineage-verified `GetByEpoch(uc.GetRootEpoch())`; historical proof never grants current authority.

The runtime gate requires real secp256k1 proof vectors and the child integrations. WP3's independent CBOR vectors and tests exercise only the inert contract.
