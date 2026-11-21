# Foundation handbook

The Foundation owns the Validator Registry governance workflow. The default governor is a three-of-five multisig. Signers independently check the chain ID, multisig, nonce, decoded call and intended effect. Keep signer keys offline. Any funded account can submit a complete approval bundle or execute a matured queue item.

## Governing a generation

In a private working directory, set `RPC_URL`, `CHAIN_ID` and the paths for your signer and sender keys. Exchange the proposal and approval files through the Foundation's approval process. For a single committee-limit proposal, the flow is:

```bash
ubft governance propose committee-limits --rpc "$RPC_URL" --n-min 4 --n-target 5 --n-max 5 --out proposal.json
read -rp 'Signer slot assigned by the coordinator (1, 2 or 3): ' SIGNER_SLOT
ubft governance sign --proposal proposal.json --signer-key "$SIGNER_KEY" --chain-id "$CHAIN_ID" \
  --out "approval-$SIGNER_SLOT.json"
ubft governance aggregate --rpc "$RPC_URL" --proposal proposal.json \
  --approval approval-1.json --approval approval-2.json --approval approval-3.json --out bundle.json
ubft governance execute --rpc "$RPC_URL" --bundle bundle.json --sender-key "$SENDER_KEY"
ubft governance list --rpc "$RPC_URL"
read -rp 'Queued change ID from its receipt: ' CHANGE_ID
ubft governance execute --rpc "$RPC_URL" --change "$CHANGE_ID" --sender-key "$SENDER_KEY"
ubft governance list --rpc "$RPC_URL" --change "$CHANGE_ID"
```

The coordinator gives the three signers distinct slots and collects their approval files under the same filenames. Wait for both certified-time and progress delays before executing the queue item. Check for Scheduled, then Bound, then the applied state and its effect. Queued or Scheduled items can be cancelled through the same multisig proposal flow. A bound change is committed to its boundary. Approvals remain executable until the nonce is consumed. Coordinate a nonce burn through the multisig if approvals at that nonce must be withdrawn.

For fees, propose `fee-params` with the floor in wei, the change denominator and the collector address. Confirm the effective EVM block and the old and new settings with validator status. For limits, check the measured module caps and a viable committee and quorum before proposing a change. In **PoA only**, use `propose admit` and `propose confirm-exit` for the ordinary operator lifecycle. PoS delegation admission and retirement use P85 custody and elections.

## Confirm admission windows

For a PoS application, confirm the successor shard epoch and the cutoff for the next election from the current certified state. Check that there is time to complete registration, bond and delegation before the election takes its snapshot. If an existing result excludes the applicant, let that result resolve and give the operator a new window. If the already registered authority missed the planned assignment, check active and frozen membership before coordinating its replacement binding.

## Schedule activations

Set `RULE` to the release's rule name, `RELEASE_DIGEST` to its 32-byte 0x-prefixed digest, and `ROOT_EPOCH` to the proposed activation epoch. The VT-07 release provides this governance builder.

```bash
ubft governance propose schedule-activation --rpc "$RPC_URL" --rule "$RULE" \
  --release-digest "$RELEASE_DIGEST" --root-epoch "$ROOT_EPOCH" --not-before-in 2h \
  --out activation-proposal.json
```

Review the rule, release identifier, earliest certified time and target root epoch against the current schedule and cutoff. Publish the matching signed release and its component checksums before the epoch. Verify the queue, the latched schedule and operator readiness with `validator upgrade` on that release. Coordinate a supported activation before the cutoff. Follow [upgrade alert runbooks](monitoring/runbooks.md#unicityupgraderequired) for a missing or unsupported rule.

## Roll out a compatible hotfix

Build from the generation's deployed source pin with only the approved fix. Verify that the patch applies cleanly, run the affected tests, and publish a separate versioned artifact with a SHA-256 manifest. Announce the source pin, hotfix commit, manifest digest, affected services and rollback binary through the authenticated release channel. Use the activation procedure above for changes to consensus rules.

Before restarting a root, check the current committee, quorum weight, recent committed rounds and shard certification. Pick a quiet window between handoffs. Confirm that the roots staying online have enough voting weight to make quorum. Stage the verified binary first. Restart one affected root with its existing arguments, home and keys. Keep its paired shard, execution client and authority running.

Check that the restarted root rejoins the current epoch, submits votes and appears in a new quorum certificate. Confirm that certification has advanced on a peer and that the public execution head is healthy before moving to the next root. Record the before and after process IDs, binary digest, epochs and quorum certificates. If any check fails, pause the rollout and recover that root with the previously verified binary and the same state. Announce completion and the affected operator steps. [Stage an operator hotfix](validator-handbook.md#upgrade-to-a-hotfix-release)

## Release and publish seeds

Publish independently authenticated release checksums and the UTB genesis EntryID. Publish the genesis trust base, execution genesis, shard configuration, VR and B1 pins, activation bundles and peer addresses alongside each release. Export a seed from a synced validator's archive and its isolated UTB bundle listener. Serve the verified seed directory through a read-only endpoint, and check it by fetching from an operator network with the published pin. Keep enough archive data and handoff history available for a new node to catch up. See [Sync from a seed](sync-seed.md) and [root RPC exposure](root-rpc-exposure.md).
