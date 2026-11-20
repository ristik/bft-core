package seed

import (
	"bytes"
	"crypto"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/activationproof"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/utb"
)

// RestorePin is the exact input `shard-node restore` consumes from a seed: the checkpoint's canonical UC and TR bytes and the BodyID of the
// checkpoint epoch's trust base.
type RestorePin struct {
	UC, TR    []byte
	RootEpoch uint64
	BodyID    [32]byte
}

// ResolveRestorePin resolves the restore pin of a verified seed BEFORE any validator state is touched. The BodyID of the checkpoint's root epoch is
// derived from authenticated history, never from a file the seed carries and never assumed to be epoch 1's:
//
//   - epoch 1: the hash of the genesis trust base (the node's own V1 pin rule), after checking that the genesis trust base is the one the pinned UTB
//     genesis entry was built from (utb is true for a UTB deployment);
//   - a later epoch: the activation bundles (the roots' q3/bundle encoding, untrusted bytes) are verified from the genesis trust base by the same
//     lineage a signing authority builds, and the epoch's entry BodyID is that lineage's. The lineage's trust base for the epoch must also be the
//     one the seed's UTB history names (same members and weights), so the two authenticated histories agree.
//
// bundles must cover epochs 2..RootEpoch in order.
func ResolveRestorePin(v *Verified, genesis *types.RootTrustBaseV1, utbDeployment bool, bundles [][]byte, shardConf *types.PartitionDescriptionRecord) (*RestorePin, error) {
	epoch := v.UC.GetRootEpoch()
	if genesis == nil || genesis.Epoch != 1 {
		return nil, refuse("the genesis trust base (epoch 1) is required")
	}
	if uint64(genesis.NetworkID) != uint64(v.Bundle.Network) {
		return nil, refuse("the genesis trust base is of network %d, the seed's is %d", genesis.NetworkID, v.Bundle.Network)
	}
	// in a UTB deployment the genesis trust base must be the one the pinned UTB genesis entry was built from
	if utbDeployment {
		want, err := utb.BuildUnsigned(nil, utb.FromProjection(genesis))
		if err != nil {
			return nil, refuse("the genesis trust base does not build a UTB genesis entry: %v", err)
		}
		wantID, err := want.EntryID()
		if err != nil {
			return nil, err
		}
		gotID, err := v.Bundle.Entries[0].EntryID()
		if err != nil {
			return nil, err
		}
		if wantID != gotID {
			return nil, refuse("the genesis trust base is not the one the pinned UTB genesis entry was built from")
		}
	}
	trEpoch := v.TR.Epoch
	if shardConf != nil && trEpoch > shardConf.Epoch && epoch == 1 {
		return nil, refuse("supply the configuration for shard epoch %d: the checkpoint is of root epoch 1, so no activation can lead from epoch %d to it", trEpoch, shardConf.Epoch)
	}
	pin := &RestorePin{UC: bytes.Clone(v.Files[TipUCFile]), TR: bytes.Clone(v.Files[TipTRFile]), RootEpoch: epoch}
	if epoch == 1 {
		// whatever the deployment's profile, the checkpoint must verify against the supplied native genesis trust base itself
		if err := v.UC.Verify(quorumweight.Checked(genesis), crypto.SHA256, v.UC.GetPartitionID(), v.UC.GetShardID(), v.UC.ShardConfHash); err != nil {
			return nil, refuse("the checkpoint does not verify against the supplied genesis trust base: %v", err)
		}
		raw, err := genesis.Hash(crypto.SHA256)
		if err != nil {
			return nil, err
		}
		copy(pin.BodyID[:], raw)
		return pin, nil
	}
	lin, err := activationproof.NewLineage(genesis, utbDeployment)
	if err != nil {
		return nil, refuse("starting the history from the genesis trust base: %v", err)
	}
	var found bool
	var steps []confStep
	partition, shard := v.UC.GetPartitionID(), v.UC.GetShardID()
	for i, raw := range bundles {
		prev := lin
		next, step, err := lin.Extend(raw)
		if err != nil {
			return nil, refuse("activation bundle %d does not verify from the genesis: %v", i+1, err)
		}
		lin = next
		if !step.Replay && step.Epoch >= 2 {
			steps = append(steps, func(active []byte) ([]byte, *types.PartitionDescriptionRecord, error) {
				tr, err := activationproof.ShardTransition(prev, step, partition, shard, active)
				if err != nil {
					return nil, nil, err
				}
				return tr.NextConfHash, tr.Conf, nil
			})
		}
		if step.Epoch == epoch {
			pin.BodyID, found = step.Entry.BodyID(), true
		}
	}
	if !found {
		return nil, refuse("the activation bundles do not reach the checkpoint's root epoch %d (they end at epoch %d)", epoch, lin.Tip())
	}
	// the shard configuration the checkpoint's technical record names: carried from the supplied configuration through every verified activation
	// (the old committee's commit, the committed checkpoint against the active configuration, the committed candidate), and compared with the UC
	if shardConf != nil && trEpoch > shardConf.Epoch {
		h, err := resolveShardConf(shardConf, trEpoch, steps)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(h, v.UC.ShardConfHash) {
			return nil, refuse("the checkpoint certifies another shard configuration than the one the verified activations lead to at shard epoch %d", trEpoch)
		}
	}
	// the two authenticated histories must agree on the committee of the checkpoint's epoch
	tb, err := lin.Trust(epoch)
	if err != nil {
		return nil, err
	}
	var entry *types.RootTrustBaseV2
	for _, e := range v.Bundle.Entries {
		if e.Epoch == epoch {
			entry = e
		}
	}
	if entry == nil {
		return nil, refuse("the seed's history has no entry for epoch %d", epoch)
	}
	if err := sameCommittee(tb, entry); err != nil {
		return nil, err
	}
	return pin, nil
}

func sameCommittee(tb *types.RootTrustBaseV1, e *types.RootTrustBaseV2) error {
	if len(tb.RootNodes) != len(e.RootNodes) || tb.QuorumThreshold != e.QuorumThreshold {
		return refuse("the activation history and the seed's trust-base history disagree on the committee of epoch %d", e.Epoch)
	}
	for _, a := range tb.RootNodes {
		ok := false
		for _, b := range e.RootNodes {
			if a.NodeID == b.NodeID && a.Stake == b.Stake && bytes.Equal(a.SigKey, b.SigKey) {
				ok = true
			}
		}
		if !ok {
			return refuse("the activation history and the seed's trust-base history disagree on member %s of epoch %d", a.NodeID, e.Epoch)
		}
	}
	return nil
}

// confStep is one verified activation, as the shard sees it: given the configuration hash active before it, the hash certified from it and the
// activated configuration of a coupled change (nil for a root-only change, which keeps the configuration).
type confStep func(active []byte) (next []byte, conf *types.PartitionDescriptionRecord, err error)

// resolveShardConf carries the supplied configuration through the activations in order and returns the configuration hash of the shard epoch trEpoch.
// When the activations never reach that epoch, the operator must supply a configuration that does.
func resolveShardConf(supplied *types.PartitionDescriptionRecord, trEpoch uint64, steps []confStep) ([]byte, error) {
	active, err := supplied.Hash(crypto.SHA256)
	if err != nil {
		return nil, refuse("hashing the supplied shard configuration: %v", err)
	}
	for _, step := range steps {
		next, conf, err := step(active)
		if err != nil {
			return nil, refuse("the shard transition does not verify: %v", err)
		}
		active = next
		if conf != nil && conf.Epoch == trEpoch {
			return next, nil
		}
	}
	return nil, refuse("supply the configuration for shard epoch %d: the verified activations lead from the supplied epoch %d to no such epoch", trEpoch, supplied.Epoch)
}
