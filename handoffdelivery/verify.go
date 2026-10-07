// Package handoffdelivery verifies the native root handoff evidence fetched by
// a shard. A peer supplies bytes; the shard selects the old trust from its
// lineage-verified history and checks the complete checkpoint locally.
package handoffdelivery

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/types"
)

var ErrBundle = errors.New("handoff delivery: invalid committed bundle")

// Bundle is the complete data needed at a shard epoch boundary. The proof
// authenticates the control leaf, while the snapshot reconstructs all shard
// leaves under the same committed root.
type Bundle struct {
	_        struct{} `cbor:",toarray"`
	Proof    handoff.OldCommitProof
	Body     evmroot.TrustBaseBodyV2
	Snapshot *abdrc.CommittedBlock
	// Candidate is the H3 EVM assignment candidate preimage (successor PDR and
	// possession proofs), carried once. It is empty for a root-only handoff.
	Candidate []byte
}

// legacyBundle is the persisted shape before the candidate field existed.
type legacyBundle struct {
	_        struct{} `cbor:",toarray"`
	Proof    handoff.OldCommitProof
	Body     evmroot.TrustBaseBodyV2
	Snapshot *abdrc.CommittedBlock
}

// EncodeBundle writes the legacy shape for a root-only bundle, so its bytes are
// unchanged, and the candidate-carrying shape otherwise.
func EncodeBundle(b Bundle) ([]byte, error) {
	if len(b.Candidate) == 0 {
		return types.Cbor.Marshal(legacyBundle{Proof: b.Proof, Body: b.Body, Snapshot: b.Snapshot})
	}
	return types.Cbor.Marshal(b)
}

// DecodeBundle accepts exactly the two canonical persisted shapes and refuses
// everything else; a shape is never reinterpreted as the other.
func DecodeBundle(raw []byte) (Bundle, error) {
	var current Bundle
	if err := types.Cbor.Unmarshal(raw, &current); err == nil && len(current.Candidate) != 0 {
		if canonical, err := types.Cbor.Marshal(current); err == nil && bytes.Equal(canonical, raw) {
			return current, nil
		}
		return Bundle{}, ErrBundle
	}
	var old legacyBundle
	if err := types.Cbor.Unmarshal(raw, &old); err != nil {
		return Bundle{}, ErrBundle
	}
	if canonical, err := types.Cbor.Marshal(old); err != nil || !bytes.Equal(canonical, raw) {
		return Bundle{}, ErrBundle
	}
	return Bundle{Proof: old.Proof, Body: old.Body, Snapshot: old.Snapshot}, nil
}

type Verified struct {
	Genesis evmroot.EpochGenesis
	Record  handoff.VerifiedRecord
	Shard   abdrc.ShardInfo
	// NextConfHash is the full shard configuration hash the root certifies once this handoff activates: the
	// activated assignment's for an EVM assignment step, otherwise the unchanged expected hash.
	NextConfHash []byte
}

// Verify requires the caller's authenticated old trust base and exact local
// shard configuration hash. It does not trust any identity supplied by a peer.
func Verify(bundle Bundle, old *types.RootTrustBaseV1, partition types.PartitionID, shard types.ShardID, shardConfHash []byte) (Verified, error) {
	return VerifySigning(bundle, old, votesig.Config{Scheme: votesig.SchemeLegacy}, partition, shard, shardConfHash)
}

// VerifySigning is Verify by the rule of the old epoch: cfg is its signing configuration, and the commit QC of the proof must be in the
// wire form the configuration requires. Verify is VerifySigning in the legacy scheme, for the verifiers (shard-side history stores) that
// hold no signing configuration of their own.
func VerifySigning(bundle Bundle, old *types.RootTrustBaseV1, cfg votesig.Config, partition types.PartitionID, shard types.ShardID, shardConfHash []byte) (Verified, error) {
	v, err := handoff.VerifyOldCommitProofSigning(bundle.Proof, old, cfg)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: old commit: %v", ErrBundle, err)
	}
	verified := evmroot.VerifiedHandoff{RecordID: v.RecordID[:], Root: v.StateRoot[:],
		ControlDigest: v.ControlDigest[:], OrderRound: v.OrderRound,
		CommitSealRound: v.CommitSealRound, Epoch: v.SignerEpoch, Record: bundle.Proof.Record}
	g, err := evmroot.DeriveEpochGenesis(verified, bundle.Body)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: successor body: %v", ErrBundle, err)
	}
	// The successor body binds exactly one candidate. A handoff that changes only the root members has no delivered
	// preimage: its digest is recomputable from the body, so a candidate cannot be dropped from an assignment step.
	r := bundle.Proof.Record
	var digest [32]byte
	if len(bundle.Candidate) != 0 {
		digest = sha256.Sum256(bundle.Candidate)
	} else {
		var derr error
		if digest, derr = evmroot.D4OperatorCandidateDigest(bundle.Body.Members); derr != nil {
			return Verified{}, fmt.Errorf("%w: operator candidate: %v", ErrBundle, derr)
		}
	}
	if !bytes.Equal(bundle.Body.ChangeRecordHash, evmroot.D4CandidateContextHash(r.Network, r.PredecessorBodyID, r.Attempt, digest[:], bundle.Body.EarliestActivation)) {
		return Verified{}, fmt.Errorf("%w: candidate does not match the successor body's change record", ErrBundle)
	}
	nextConf := bytes.Clone(shardConfHash)
	if len(bundle.Candidate) != 0 {
		_, activated, derr := evmassign.ActivatedFromPreimage(bundle.Candidate, r.ActivationRound)
		if derr != nil {
			return Verified{}, fmt.Errorf("%w: candidate: %v", ErrBundle, derr)
		}
		if nextConf, derr = activated.Hash(crypto.SHA256); derr != nil || len(nextConf) != 32 {
			return Verified{}, fmt.Errorf("%w: activated configuration hash", ErrBundle)
		}
	}
	target, err := VerifySnapshot(bundle.Proof, v, bundle.Snapshot, partition, shard, shardConfHash)
	if err != nil {
		return Verified{}, err
	}
	return Verified{Genesis: g, Record: v, Shard: target, NextConfHash: nextConf}, nil
}

// VerifySnapshot checks the native recovery checkpoint of a handoff against the old committee's verified commit: the same QC, the
// control state the record committed, and the complete shard tree under the committed root, with the local shard's own
// configuration hash. It is the part of Verify that does not depend on the successor body's version, so the V2 and V3 bundles share it.
func VerifySnapshot(proof handoff.OldCommitProof, v handoff.VerifiedRecord, s *abdrc.CommittedBlock, partition types.PartitionID, shard types.ShardID, shardConfHash []byte) (abdrc.ShardInfo, error) {
	if s == nil || s.Block == nil || s.Control == nil || s.CommitQc == nil || s.CommitQc.LedgerCommitInfo == nil ||
		s.Block.Epoch != v.SignerEpoch || s.Block.Round != v.CommitSealRound || !s.Control.Matches(proof.Record) ||
		!bytes.Equal(s.Control.Digest(), v.ControlDigest[:]) || !bytes.Equal(s.CommitQc.LedgerCommitInfo.Hash, v.StateRoot[:]) {
		return abdrc.ShardInfo{}, ErrBundle
	}
	proofQC, err := types.Cbor.Marshal(proof.CommitQC)
	if err != nil {
		return abdrc.ShardInfo{}, err
	}
	snapshotQC, err := types.Cbor.Marshal(s.CommitQc)
	if err != nil || !bytes.Equal(proofQC, snapshotQC) {
		return abdrc.ShardInfo{}, ErrBundle
	}
	root, target, err := snapshotRoot(s, partition, shard)
	if err != nil || !bytes.Equal(root, v.StateRoot[:]) || target == nil ||
		!bytes.Equal(target.ShardConfHash, shardConfHash) {
		return abdrc.ShardInfo{}, ErrBundle
	}
	return *target, nil
}

func snapshotRoot(s *abdrc.CommittedBlock, partition types.PartitionID, shard types.ShardID) ([]byte, *abdrc.ShardInfo, error) {
	groups := make(map[types.PartitionID][]abdrc.ShardInfo)
	seen := make(map[types.PartitionShardID]struct{})
	var target *abdrc.ShardInfo
	for i := range s.ShardInfo {
		entry := &s.ShardInfo[i]
		key := types.PartitionShardID{PartitionID: entry.Partition, ShardID: entry.Shard.Key()}
		if entry.Partition == evmroot.D4ControlPartition || entry.IR == nil || len(entry.ShardConfHash) != 32 {
			return nil, nil, ErrBundle
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, nil, ErrBundle
		}
		stat := abhash.New(crypto.SHA256.New())
		stat.WriteRaw(entry.PrevEpochStat)
		stat.Write(entry.Stat)
		statHash, err := stat.Sum()
		if err != nil || !bytes.Equal(statHash, entry.IRTR.StatHash) {
			return nil, nil, ErrBundle
		}
		fees := abhash.New(crypto.SHA256.New())
		fees.WriteRaw(entry.PrevEpochFees)
		fees.Write(entry.Fees)
		feeHash, err := fees.Sum()
		if err != nil || !bytes.Equal(feeHash, entry.IRTR.FeeHash) {
			return nil, nil, ErrBundle
		}
		seen[key] = struct{}{}
		groups[entry.Partition] = append(groups[entry.Partition], *entry)
		if entry.Partition == partition && entry.Shard.Equal(shard) {
			target = entry
		}
	}
	if target == nil {
		return nil, nil, ErrBundle
	}
	leaves := []*types.UnicityTreeData{{Partition: evmroot.D4ControlPartition, ShardTreeRoot: s.Control.Digest()}}
	for partitionID, entries := range groups {
		scheme := make(types.ShardingScheme, 0, len(entries))
		inputs := make([]types.ShardTreeInput, 0, len(entries))
		for _, entry := range entries {
			if entry.Shard.Length() != 0 {
				scheme = append(scheme, entry.Shard)
			}
			trHash, err := entry.IRTR.Hash()
			if err != nil {
				return nil, nil, err
			}
			inputs = append(inputs, types.ShardTreeInput{Shard: entry.Shard, IR: entry.IR, TRHash: trHash,
				ShardConfHash: entry.ShardConfHash})
		}
		shardTree, err := types.CreateShardTree(scheme, inputs, crypto.SHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: shard tree: %v", ErrBundle, err)
		}
		leaves = append(leaves, &types.UnicityTreeData{Partition: partitionID, ShardTreeRoot: shardTree.RootHash()})
	}
	tree, err := types.NewUnicityTree(crypto.SHA256, leaves)
	if err != nil {
		return nil, nil, err
	}
	return tree.RootHash(), target, nil
}

// AssignmentStepOf derives the EVM assignment context of one verified bundle: from
// its candidate for an assignment handoff, from the checkpoint's own installed
// configuration for a root-only one. The candidate was bound by the old root
// quorum through the successor body, and its claim of the replaced assignment is
// checked against the verified checkpoint's shard, so a bundle cannot name an
// assignment the old committee never installed.
func AssignmentStepOf(b Bundle, v Verified) (handoff.AssignmentStep, error) {
	var step handoff.AssignmentStep
	if len(v.Shard.ShardConfHash) != 32 {
		return step, ErrBundle
	}
	installed := [32]byte(v.Shard.ShardConfHash)
	if len(b.Candidate) == 0 {
		step.OldShardEpoch, step.NewShardEpoch = v.Shard.IRTR.Epoch, v.Shard.IRTR.Epoch
		step.OldActiveConfHash, step.NewActiveConfHash = installed, installed
		return step, nil
	}
	c, err := evmassign.DecodeCandidate(b.Candidate)
	if err != nil {
		return step, errors.Join(ErrBundle, err)
	}
	succ, err := c.Successor()
	if err != nil {
		return step, errors.Join(ErrBundle, err)
	}
	activated, err := evmassign.Activate(succ, b.Proof.Record.ActivationRound)
	if err != nil {
		return step, errors.Join(ErrBundle, err)
	}
	newHash, err := evmassign.PDRHash(activated)
	if err != nil || len(c.OldActiveHash) != 32 || c.OldShardEpoch != v.Shard.IRTR.Epoch || [32]byte(c.OldActiveHash) != installed {
		return step, errors.Join(ErrBundle, errors.New("candidate does not replace the checkpoint's installed assignment"))
	}
	return handoff.AssignmentStep{Assignment: true, OldShardEpoch: c.OldShardEpoch, NewShardEpoch: succ.Epoch,
		OldActiveConfHash: installed, NewActiveConfHash: newHash}, nil
}

// AssignmentValidators is the validator set and shard epoch of the EVM assignment a bundle's candidate installs, for a bundle that
// carries one (ok false for a root-only handoff, which leaves the shard's validators unchanged). The candidate is the one the verified
// successor body binds (Verify checked it), so call this on a verified bundle.
func AssignmentValidators(b Bundle) (epoch uint64, validators []*types.NodeInfo, ok bool, err error) {
	activated, ok, err := AssignmentConf(b)
	if err != nil || !ok {
		return 0, nil, false, err
	}
	return activated.Epoch, activated.Validators, true, nil
}

// AssignmentConf is the full shard configuration the EVM assignment of a bundle activates (validators, keys, parameters), for a bundle
// that carries one. Its hash is the NextConfHash Verify checked against the root-certified change record, so call this on a verified
// bundle and compare the hash with the configuration hash installed for the epoch before relying on any field of it.
func AssignmentConf(b Bundle) (*types.PartitionDescriptionRecord, bool, error) {
	if len(b.Candidate) == 0 {
		return nil, false, nil
	}
	_, activated, err := evmassign.ActivatedFromPreimage(b.Candidate, b.Proof.Record.ActivationRound)
	if err != nil {
		return nil, false, errors.Join(ErrBundle, err)
	}
	return activated, true, nil
}
