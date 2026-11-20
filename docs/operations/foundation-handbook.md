# Foundation handbook

The Foundation owns the Validator Registry governance workflow. The default governor is a three-of-five multisig. Signers independently check the chain ID, multisig, nonce, decoded call and intended effect. Keep signer keys offline. Any funded account can submit a complete approval bundle or execute a matured queue item.

## Governing a generation

In a private working directory, set `RPC_URL`, `CHAIN_ID` and the paths for your signer and sender keys. Exchange the proposal and approval files through the Foundation's approval process. For a single committee-limit proposal, the flow is:

```bash
ubft governance propose committee-limits --rpc "$RPC_URL" --n-min 4 --n-target 5 --n-max 5 --out proposal.json
ubft governance sign --proposal proposal.json --signer-key "$SIGNER_KEY" --chain-id "$CHAIN_ID" --out approval.json
ubft governance aggregate --rpc "$RPC_URL" --proposal proposal.json \
  --approval approval-1.json --approval approval-2.json --approval approval-3.json --out bundle.json
ubft governance execute --rpc "$RPC_URL" --bundle bundle.json --sender-key "$SENDER_KEY"
ubft governance list --rpc "$RPC_URL"
read -rp 'Queued change ID from its receipt: ' CHANGE_ID
ubft governance execute --rpc "$RPC_URL" --change "$CHANGE_ID" --sender-key "$SENDER_KEY"
ubft governance list --rpc "$RPC_URL" --change "$CHANGE_ID"
```

The three signers provide separate approval files. Wait for both certified-time and progress delays before executing the queue item. Check for Scheduled, then Bound, then the applied state and its effect. Queued or Scheduled items can be cancelled through the same multisig proposal flow. A bound change is committed to its boundary. Approvals remain executable until the nonce is consumed. Coordinate a nonce burn through the multisig if approvals at that nonce must be withdrawn.

For fees, propose `fee-params` with the floor in wei, the change denominator and the collector address. Confirm the effective EVM block and the old and new settings with validator status. For limits, check the measured module caps and a viable committee and quorum before proposing a change. In **PoA only**, use `propose admit` and `propose confirm-exit` for the ordinary operator lifecycle. PoS delegation admission and retirement use P85 custody and elections.

## Schedule activations

Set `RULE` to the release's rule name, `RELEASE_DIGEST` to its 32-byte 0x-prefixed digest, and `ROOT_EPOCH` to the proposed activation epoch. The VT-07 release provides this governance builder.

```bash
ubft governance propose schedule-activation --rpc "$RPC_URL" --rule "$RULE" \
  --release-digest "$RELEASE_DIGEST" --root-epoch "$ROOT_EPOCH" --not-before-in 2h \
  --out activation-proposal.json
```

Review the rule, release identifier, earliest certified time and target root epoch against the current schedule and cutoff. Publish the matching signed release and its component checksums before the epoch. Verify the queue, the latched schedule and operator readiness with `validator upgrade` on that release. Coordinate a supported activation before the cutoff. Follow [upgrade alert runbooks](monitoring/runbooks.md#unicityupgraderequired) for a missing or unsupported rule.

## Release and publish seeds

Publish independently authenticated release checksums and the UTB genesis EntryID. Publish the genesis trust base, execution genesis, shard configuration, VR and B1 pins, activation bundles and peer addresses alongside each release. Export a seed from a synced validator's archive and its isolated UTB bundle listener. Serve the verified seed directory through a read-only endpoint, and check it by fetching from an operator network with the published pin. Keep enough archive data and handoff history available for a new node to catch up. See [Sync from a seed](sync-seed.md) and [root RPC exposure](root-rpc-exposure.md).
