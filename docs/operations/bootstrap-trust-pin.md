# M3 bootstrap trust-pin policy (H5 policy only)

**Policy draft, not a new checkpoint format or a production authorization.** The
owner decision is D-M2-1 in `briefs/m2-decisions.md`: a checkpoint authority must
be provisioned independently, or the new pin must be authenticated by a currently
trusted pin; sequence numbers are monotonic; pins expire and refresh; and key
governance is documented. The owner has deferred any new serialized checkpoint
format until after M3. This draft therefore uses the existing trust-base, UC, TR
and BodyID inputs. Source references below are from bft-core
`33799c95f58e1eb92376898502e1b6a1e52a9a3a`.

## Pin contents

A restore pin is the following operator-approved tuple, distributed as existing
files and CLI arguments rather than a new envelope:

1. **Root trust base.** The `RootTrustBaseV1` JSON file supplied by `--trust-base`.
   Keep the exact bytes and calculate the 32-byte trust BodyID. For the currently
   used V1 restore path, the value is `RootTrustBaseV1.Hash(crypto.SHA256)`, which
   includes the trust-base signatures. For a profile-2 epoch, use the BodyID
   returned by the verified epoch history for the UC's epoch. `--trust-body-id`
   is the existing 0x-prefixed value (`trust_base.go:229-245`,
   `shard_node_run.go:443-449,825-833`,
   `shardnode/trustbase_history.go:145-159`; the lane extractor computes the V1
   hash at `scripts/h4-restore-pin/main.go:53-59`).
2. **Certified head UC and TR.** `--tip-uc` is canonical CBOR for the latest
   certified `UnicityCertificate`; `--tip-tr` is canonical CBOR for that UC's
   `TechnicalRecord`. These files, the UC root epoch and root round, and the
   expected deployment context form one indivisible pair. The current restore
   loader caps each file at 1 MiB and rejects noncanonical CBOR
   (`cli/ubft/cmd/shard_node_restore.go:12-47`).
3. **External approval metadata.** In the controlled change record, not in a new
   checkpoint file: authority identity/key version, monotonically increasing
   sequence, issue and expiry times, deployment/network identifier, partition,
   shard, full shard-configuration hash, genesis identity, the trust BodyID, UC
   epoch/round, and file digests. The independent operator record must say which
   prior pin authorized this one. Use UTC timestamps. The metadata binds the
   approval to the exact CLI inputs; it does not replace their cryptographic
   verification.

The archive is a source of candidate records, never an authority for this tuple.
Do not accept a trust base, trust BodyID, or approval metadata learned only from
the archive, execution peer, or validator being restored.

## Authorization and distribution

The checkpoint authority is an out-of-band trust-distribution role. Its key is
not a root validator key, does not create a root quorum certificate, and cannot
change the trust base. Root trust-base authenticity remains governed by the
signatures and transition rules already verified by `ubft trust-base verify`
(`cli/ubft/cmd/trust_base.go:179-214`). For V1 trust bases after epoch 1, provide
the complete contiguous trust-base sequence to that command; its verifier sorts
by epoch and verifies each entry against the preceding entry. A single non-genesis
V1 file is not a substitute for that history.

The owner/governance process must name the initial checkpoint authority and
record its key fingerprint, custody, replacement, revocation and dual-control
rules. Until that is approved, use only an already trusted pin distributed by
the existing authorized operations process. Distribute the trust-base, UC, TR
and approval record through authenticated, access-controlled configuration
management, independently of archive replication. Record the recipient, time,
sequence, file digests and acknowledgment. A checksum detects transfer damage;
it does not authenticate the sender.

## Bootstrap and verification

For a fresh validator joining the live network, provision the approved trust base
and full shard configuration through the deployment channel. Run the existing
trust-base verification command with the genesis and each consecutive V1 trust
base needed to reach the selected epoch:

```sh
build/ubft trust-base verify \
  --trust-base REPLACE_TRUST_BASE_EPOCH_1_JSON \
  --trust-base REPLACE_TRUST_BASE_EPOCH_2_JSON
```

Supply one `--trust-base` per required epoch; omit the second only when epoch 1 is
the selected trust base. The running shard accepts a single configured trust-base
anchor and uses its verified handoff history for profile 2
(`cli/ubft/cmd/shard_node_run.go:436-455`). A fresh genesis deployment must also
compare the trust BodyID and shard/genesis configuration to the independently
approved deployment record; a chain or network ID alone does not establish the
execution genesis (`shard_node_run.go:301-315`).

For an empty or restored validator that must replay existing certified history,
use the existing `ubft shard-node restore` path, not a new bootstrap command. Its
pin-related inputs are:

```text
--trust-base REPLACE_TRUST_BASE_JSON
--full-shard-conf REPLACE_FULL_SHARD_CONFIGURATION_JSON
--tip-uc REPLACE_APPROVED_TIP_UC_CBOR
--tip-tr REPLACE_APPROVED_TIP_TR_CBOR
--trust-body-id 0xREPLACE_64_HEX_DIGITS
```

The deployment's normal key, P2P, executor, archive and surviving-signing-authority
options are also required. Restore refuses existing BFT journal/history files and
local-key restore; it requires the surviving signing authority and the pin flags
(`cli/ubft/cmd/shard_node_run.go:280-291,365-379`). The V1 path compares the
supplied BodyID to the configured trust-base hash. With profile-2 history enabled,
the node catches up verified handoffs first and compares the BodyID for the UC's
own root epoch (`shard_node_run.go:443-449,811-845`).

The restore path then authenticates the UC/TR observation in the local network,
partition, shard and shard-configuration context. It checks the TR and its hash
against the UC, selects the trust base by the UC's epoch, verifies the UC, and
rejects a non-current epoch for a current observation
(`rootinput/v2.go:193-234`; `archivewiring/restore.go:63-71`). Restored local
certificates use the same UC verification and the locally configured shard hash,
not an expectation taken from the pin (`shardnode/node.go:383-419`). Archive
records are replayed only after this pinned tip is authenticated.

The existing `scripts/h4-restore-pin` is a lane helper that selects a record from
a local archive and prints a V1 BodyID; it is not an independently authorized
checkpoint producer (`scripts/h4-restore-pin/main.go:18-72`,
`scripts/h4-restore-probe.sh:56-73`). Until H5's later implementation PR, an
operator must obtain and approve the UC/TR pair through a separately controlled
process. Do not turn the helper's archive scan into a trust decision.

## Sequence, refresh and expiry policy

- Assign each approved pin a sequence strictly greater than the last accepted
  sequence for that deployment. Reject a lower sequence. A repeated sequence is
  allowed only for byte-identical trust-base, UC, TR and approval metadata; a
  same-sequence change is a conflict and requires a new sequence and approval.
- Before the current pin expires, the authorized authority (or the currently
  trusted pin under the approved governance process) approves a replacement tuple
  with a later certified UC/TR and a future expiry. Verify the trust base and
  BodyID, then verify the UC/TR using the configured context. Publish the exact
  files and metadata as one change, obtain acknowledgments from all operators
  responsible for bootstrap/restore, and retain the prior pin for audit. Never
  overwrite bytes under an existing sequence.
- A pin is usable for a new bootstrap, restore or rejoin only before its recorded
  expiry. Compare against a reliable UTC clock. If the clock is untrusted, expiry
  cannot be established and bootstrap/restore stops. Expiry of an onboarding pin
  does not itself stop a validator already operating under its live root trust;
  it prevents new use of stale recovery material.
- If refresh is late, the authority is unreachable, or the old pin is revoked,
  stop new bootstrap/restore. Wait for a newly approved pin. Do not extend expiry
  locally, roll back sequence, trust a newer archive record, or accept a pin from
  the peer that is being restored.

No existing CLI enforces the external sequence or expiry metadata. H5 policy is
therefore not complete for production until the owner selects the authority,
expiry duration and refresh lead time, and the later H5 implementation adds the
producer/verifier plus replay, expiry and wrong-context refusal tests. This policy
does not authorize automatic #176 freshness rollout.

## Failure handling

| Failure | Required response |
|---|---|
| Trust-base JSON, BodyID or file digest mismatch | Reject the pin; reacquire through the authorized distribution path. |
| Missing/invalid quorum signatures or missing intermediate V1 trust base | Reject; do not treat the latest trust base as self-authenticating. |
| UC/TR cannot decode canonically, TR does not hash to the UC, UC signature/context fails, or epoch history lacks the UC epoch | Stop restore/bootstrap. Do not use a replica's copy as a replacement trust anchor. |
| Network, partition, shard, configuration hash or genesis identity mismatch | Reject the pin and investigate configuration; do not edit the expected context to fit it. |
| Sequence rollback, same-sequence conflict, expired pin or uncertain clock | Refuse new bootstrap/restore and request an authorized refresh. |
| Archive unavailable, replica acknowledgments missing, or replay/catch-up incomplete | Leave the validator non-ready and non-signing; restore only after authenticated records and catch-up complete. |
| Signing authority unavailable or its persisted high-water/readiness check fails | Stop restore; do not substitute a local key or reset high-water. |

## Owner and external actions

- **Owner:** name the checkpoint authority, approve its key custody/rotation and
  revocation process, and set the expiry duration and refresh lead time before M3.
- **Operations:** choose and document the authenticated distribution system and
  evidence/acknowledgment retention; keep it independent of archive replicas.
- **H5 implementation:** add a bounded producer/verifier and machine-enforced
  sequence/expiry/replay/context refusals only after the owner settles those
  policy parameters. This document does not define a new serialization format.
- **External reviewer:** review the resulting policy and offline restore/bootstrap
  evidence; no checkpoint-authority signoff is implied here.
