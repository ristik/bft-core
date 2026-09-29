# Operator-triggered root handoff abort

This procedure requests the existing old-quorum Abort for one exact ordered
handoff attempt. Approval submission is not finality; the CLI returns success
only after it observes committed Abort status. The feature applies while
authenticated control is `prepared` or `endorsed`. It cannot cancel an idle,
unordered plan or reverse committed H.

## Before submitting

- Retain the exact target from the handoff operation: network ID, old root
  epoch, predecessor BodyID, attempt, and successor BodyID. Do not infer any
  field from the current round or a stale operator request.
- Verify the root validators are on the profile-2 branch and recovered to an
  authenticated control state. If state is unavailable, recover first.
- Reach each validator's loopback RPC through the deployment's controlled
  operator tunnel. The abort routes are not public RPC endpoints.
- Upgrade all old validators before use so each node understands the bounded
  abort-approval peer message.
- Confirm the requested target is still pre-H. If H has committed, stop: the
  ordered branch and ordinary BFT locks decide the result.

## Submit and wait

Replace every `REPLACE_...` value. IDs are 32-byte hex values with `0x` prefix.
List the loopback RPC URL for each reachable old validator. The CLI submits an
approval request to each endpoint; the consensus protocol uses the configured
old trust base's quorum threshold, not the count of URLs.

```sh
build/ubft root handoff abort \
  --network REPLACE_NETWORK_ID \
  --old-epoch REPLACE_OLD_EPOCH \
  --predecessor-body-id REPLACE_PREDECESSOR_BODY_ID \
  --attempt REPLACE_ATTEMPT \
  --next-body-id REPLACE_NEXT_BODY_ID \
  --root-rpc REPLACE_ROOT1_LOOPBACK_URL,REPLACE_ROOT2_LOOPBACK_URL,REPLACE_ROOT3_LOOPBACK_URL \
  --timeout 2m
```

On completion, retain the printed Abort record ID, ordered round, and committed
root block ID/round with the command transcript and validator logs. A timeout
means pending/unknown; query the same exact target again after confirming
validator recovery. Requests are idempotent. A response that says `too late`
means H is already committed; do not retry that attempt or claim it was
cancelled.

## After committed Abort

The Abort is a root-certified transition. The EVM shard resumes ordinary
certification through the root control path; no local pause switch or
SealRegistry transaction is issued. Resubmit any shard requests dropped while
the freeze was active. To retry the handoff, use exactly `attempt+1`, the same
network and predecessor, and a freshly observed certified EVM parent and
pre-freeze summary. Collect new approvals for the new attempt. Refuse retry if
the attempt would overflow.

## Evidence status

Automated unit and consensus tests cover target validation, signature
aggregation, plan-cache loss, Abort priority, and existing automatic abort
behavior. The H6 live acceptance is pending separately: it must demonstrate a
committed Abort, a paid transaction on real ureth after Abort, an attempt+1
handoff, and refusal of a request that races behind H. Do not treat this
document or a local approval response as that live evidence.
