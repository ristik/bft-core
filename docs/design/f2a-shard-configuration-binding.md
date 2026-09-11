# F2a (#134): binding certificates to the configured shard identity

A shard node accepts a Unicity Certificate as its own authority only if the certificate commits to the
shard configuration **this node was started with**. Partition and shard identifiers are not enough: a
correctly signed certificate from the same root quorum, for the same partition and shard, but issued
under a different shard configuration, is a certificate about a different chain, and must be refused
before it advances any cursor, reaches the executor, is retained as evidence, or authorizes a signature.

## Where the expected identity comes from

The shard configuration is a deployment input — `--shard-conf` — and its hash is computed with the
canonical `PartitionDescriptionRecord.Hash(crypto.SHA256)`, the same routine the root chain commits to
in `UnicityCertificate.ShardConfHash`. The node computes it once at startup and owns it: it is cloned
on the way in, so a caller mutating its slice afterwards cannot change what this node enforces.

It is never derived from anything under an adversary's influence: not from the received certificate,
not from a checkpoint on disk, not from a peer's evidence bundle, and not from the execution client.
Those are exactly the claims under test.

## Where it is enforced

One configured value reaches every path that turns a certificate into authority:

| path | enforcement |
| --- | --- |
| live delivery (`BFTClient.handleCertificationResponse`) | `UC.Verify(..., shardConfHash)` before classification, so a mismatch never becomes the cursor `luc`, never reaches the round driver and never advances the applied cursor |
| restored checkpoint (`verifyRestoredLUC`, from `New`) | before `SeedLUC`/`resumeFrom`, so a mismatched checkpoint stops the node instead of becoming its non-equivocation authority |
| anchor evidence recovery (`AnchorEvidenceContext`) | the same node-configured value, so enabling serving or recovery cannot introduce a second, different expected identity |

`UnicityCertificate.IsValid` compares the configuration hash **only when the caller supplies one**
(`shardConfHash != nil`): passing nil does not make the check lenient, it removes it. That is why the
deployed path requires the value rather than defaulting it, and why an absent or malformed configured
identity is a startup refusal rather than a silent fallback.

## Refusals

- **Wrong configuration**: refused with a diagnostic naming the configuration the certificate commits to
  and the one this node runs — distinguishable from a bad signature, a wrong partition or shard, and a
  bad inclusion path, because those are different situations for an operator.
- **No configured identity on the deployed path**: `New` refuses to build the node. The check applies
  whether or not `--evidence-serve`/`--evidence-recover` are set; recovery's own refusal for a missing
  hash remains, now fed from the node's configured value.

## Profile: one configuration, one epoch

This is the initial profile: a node runs exactly one shard configuration for its lifetime, and every
certificate it accepts must commit to that one. There is deliberately **no configuration-transition
acceptance rule** here — no "accept the next configuration", no history of past configurations, no
re-deriving the expected hash from a certificate that announces a change. A node whose deployment
changes configuration is restarted with the new `--shard-conf`, and a certificate for the other
configuration is refused in the meantime.

Dynamic configuration and epoch handoff belong to H1/H-series, and need their own reviewed source of
truth for what the current configuration is; inventing one here would recreate the gap this closes, by
letting the certificate stream decide which configuration is expected.

## What this does not do

It does not make the root chain's own recovery path configuration-aware
(`network/protocol/abdrc/recovery.go` verifies certificates it receives against the identifiers those
certificates carry). That is the root chain's state-recovery path, not the shard node's trust boundary,
and is left as it is. It does not change P-id or P-sign, the classification rules, epoch trust-base
lookup, or any timeout; a restored node remains non-voting under #105.
