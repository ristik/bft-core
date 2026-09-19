# F6h (#14): durable certificate checkpoint writes

Issue: #14, the deferral recorded in the code at `shardnode/store.go:35` ("Durable write ordering and
fault injection remain F6 (#14) — a rename is not an fsync"). Base: `integration/enshrined-evm` at
`7f93e995` (#198). Ledger: `f6-acceptance-ledger.md` §2.3, §2.4 and §3.

## 1. What is wrong

`FileStore.SaveLUC` writes a temporary file in the target's directory, closes it, and renames it over
the target. The rename is atomic, so no reader ever sees a half-written checkpoint, and that is what
the existing comment claims. It is not durable: neither the file's data nor the directory entry the
rename creates is synced, so a power loss shortly after a successful `SaveLUC` can lose the write
entirely.

The consequence is worse than returning an older certificate. If the directory entry is lost, the
file is absent, and `LoadLUC` treats an absent file as a clean fresh start (`store.go`, the
`os.ErrNotExist` branch). A node that has been certifying for weeks then comes back looking brand
new, which is the outcome the store's own error text calls out as the thing to avoid: "starting
without it means voting from genesis".

What this is not: a double-signing hole. Under the accepted F6c profile the non-equivocation
authority is the separate signing process and its in-memory record, which refuses a second candidate
for an assigned round regardless of what the shard's files say, and a process restored from a
persisted certificate is non-voting except through that authority. The harm here is to restoration
and liveness, not to safety. #14 owns the work anyway, and `f6c-signing-state-contract.md` assigns it
by name: "Full block/UC/TR persistence and its storage-failure tests remain #14's work."

`certifiedstore` already does this correctly. This unit brings the checkpoint store up to the same
standard; it changes nothing else.

## 2. The write sequence

`SaveLUC` becomes, in order:

1. create the temporary file in the target's directory, as now;
2. write the encoded checkpoint;
3. **sync the temporary file**, so its data is durable before anything names it;
4. close it;
5. rename it over the target, as now;
6. **sync the parent directory**, so the entry the rename created is durable.

Any step failing returns an error and leaves the existing file untouched; the existing deferred
`os.Remove` still clears the temporary file. Step 3 before step 5 is the order that matters: a
durable entry pointing at data that is not yet durable is the one arrangement that can produce a
file which exists and does not parse.

## 3. Why the directory sync is separate

A rename changes a directory entry, and syncing the file does not sync the directory that names it.
This is the same gap `certifiedstore.Open` closes for its own backend, recorded there as "bbolt syncs
the pages of the file it creates but never the directory that names the file". On macOS `os.File.Sync`
issues `F_FULLFSYNC`, so no platform-specific code is needed on either path.

## 4. A deliberate duplication

The sync helpers mirror `certifiedstore`'s `syncDirectory`, including its injectable-variable shape,
and are **not** shared. `shardnode` must not import `certifiedstore`: the dependency runs the other
way and the reach guards enforce it. Keeping the same shape means a later extraction into a shared
internal package is mechanical. Extracting it now would mean changing a merged durability path and the
fault-injection hook its tests replace, which is not worth doing inside this unit. The duplication is
recorded here rather than left to be discovered.

## 5. Fault injection

The checkpoint names, each a point `SaveLUC` passes exactly once:

`before-write`, `after-write`, `after-file-sync`, `after-close`, `after-rename`, `after-dir-sync`.

Two classes, mirroring `certifiedstore/fault_test.go` and `certifiedstore/kill_test.go`, which are
the strongest evidence in F6 and the pattern to follow rather than invent alongside:

- **Injected failure.** At each checkpoint, `SaveLUC` fails. Afterwards `LoadLUC` returns either the
  certificate that was there before or the one being written, never an error and never a damaged
  file, and no temporary file is left in the directory.
- **Process kill.** A child process is SIGKILLed at each checkpoint and the real file is reopened in
  the parent. The same assertion holds. Only `after-dir-sync` is required to show the new
  certificate; every earlier checkpoint may show either, and the test states which.

The point of the second class is that it is the only one that exercises a lost write rather than a
restarted process. An in-process injected error proves the error path; it does not prove durability.

## 6. Not in this unit

- Fault positions 1 (before proposal submission) and 5 (before execution commit) from the ledger's
  §2.4 table. They are round-level cuts and are separate work.
- The association of the replay cursor and the canonical inputs with the certified head
  (ledger §2.2), which needs those two terms defined before it can be claimed or denied.
- Migrating `certifiedstore` onto a shared helper (§4).
- Any change to `LoadLUC`'s refusals, the legacy-JSON decision or the checkpoint format.

## 7. Tests

| Test | Covers |
| --- | --- |
| `TestSaveLUCSyncsTheFileAndTheDirectory` | both syncs happen, in the order of §2, on an ordinary save |
| `TestSaveLUCFailuresLeavePriorOrNewState` | §5 class 1: each checkpoint fails in turn; the prior or the new certificate loads, no temporary file survives |
| `TestSaveLUCProcessKilledAtEachCheckpoint` | §5 class 2: SIGKILL at each checkpoint, the real file reopened in the parent |
| `TestSaveLUCFailedSyncIsAnError` | a failing file sync and a failing directory sync each fail the save rather than being ignored, and the prior file is intact |
| `TestSaveLUCLeavesNoTemporaryFileBehind` | the ordinary path and every failure path clear the temporary file |
