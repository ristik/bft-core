package handoff

import (
	"bytes"
	"crypto"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-core/evmroot"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/tree/imt"
	"github.com/unicitynetwork/bft-go-base/types"
)

// OldCommitProof authenticates the control leaf under a commit-capable old QC.
// Its trust base must come from an independently verified old-epoch lineage.
type OldCommitProof struct {
	_           struct{} `cbor:",toarray"`
	Profile     uint64
	Record      evmroot.OrderedHandoffRecord
	Control     evmroot.ControlState
	ControlPath *types.UnicityTreeCertificate
	CommitQC    *rctypes.QuorumCert
	OptionalQC  *rctypes.QuorumCert
}

func verifyOldQC(qc *rctypes.QuorumCert, tb *types.RootTrustBaseV1) error {
	if qc == nil || qc.VoteInfo == nil || qc.LedgerCommitInfo == nil || qc.GetRound() <= rctypes.GenesisRootRound || len(qc.Signatures) == 0 {
		return ErrProof
	}
	if qc.VoteInfo.GetVersion() != 1 || qc.LedgerCommitInfo.GetVersion() != 1 || qc.VoteInfo.Timestamp < types.GenesisTime || qc.LedgerCommitInfo.Timestamp < types.GenesisTime {
		return ErrProof
	}
	if err := qc.IsValid(); err != nil {
		return fmt.Errorf("%w: %v", ErrProof, err)
	}
	h, err := qc.VoteInfo.Hash(crypto.SHA256)
	if err != nil || !bytes.Equal(h, qc.LedgerCommitInfo.PreviousHash) {
		return ErrProof
	}
	bs, err := qc.LedgerCommitInfo.SigBytes()
	if err != nil {
		return ErrProof
	}
	var weight uint64
	for id, signature := range qc.Signatures {
		stake, err := tb.VerifySignature(bs, signature, id)
		if err != nil || math.MaxUint64-weight < stake {
			return ErrProof
		}
		weight += stake
	}
	if weight < tb.QuorumThreshold {
		return ErrProof
	}
	return nil
}

func VerifyOldCommitProof(p OldCommitProof, tb *types.RootTrustBaseV1, expected ...Context) (VerifiedRecord, error) {
	if len(expected) > 1 {
		return VerifiedRecord{}, ErrProof
	}
	zero := make([]byte, 32)
	if tb == nil || p.Profile != evmroot.D4Profile || !p.Record.Valid() || p.Record.Network != uint64(tb.NetworkID) || p.Record.Epoch != tb.Epoch || !p.Control.Matches(p.Record) || len(p.Control.PreviousDigest) != 32 || bytes.Equal(p.Record.FrozenID, zero) || bytes.Equal(p.Record.NextBodyID, zero) || bytes.Equal(p.Record.SuccessorTRHash, zero) {
		return VerifiedRecord{}, ErrProof
	}
	if len(expected) == 1 {
		c := expected[0]
		if c.Network != p.Record.Network || c.Epoch != p.Record.Epoch || c.Attempt != p.Record.Attempt || !bytes.Equal(c.Predecessor[:], p.Record.PredecessorBodyID) || p.Record.ActivationRound < c.MinActivation {
			return VerifiedRecord{}, ErrProof
		}
	}
	if p.ControlPath == nil || p.ControlPath.Partition != evmroot.D4ControlPartition || p.ControlPath.Version != 1 {
		return VerifiedRecord{}, ErrProof
	}
	digest := p.Control.Digest()
	hasher := abhash.New(crypto.SHA256.New())
	hasher.Write(digest)
	leafHash, err := hasher.Sum()
	if err != nil {
		return VerifiedRecord{}, ErrProof
	}
	path := []*imt.PathItem{imt.NewPathItem(evmroot.D4ControlPartition.Bytes(), leafHash)}
	for _, step := range p.ControlPath.HashSteps {
		if step == nil || step.Key == evmroot.D4ControlPartition {
			return VerifiedRecord{}, ErrProof
		}
		path = append(path, step.ToIMTPathItem())
	}
	root, err := imt.IndexTreeOutput(path, evmroot.D4ControlPartition.Bytes(), crypto.SHA256)
	if err != nil {
		return VerifiedRecord{}, ErrProof
	}
	qc := p.CommitQC
	if qc == nil || qc.VoteInfo == nil || qc.LedgerCommitInfo == nil {
		return VerifiedRecord{}, ErrProof
	}
	c := qc.LedgerCommitInfo.RootChainRoundNumber
	if c == 0 || c < p.Record.OrderedRound || c == math.MaxUint64 || qc.GetRound() != c+1 || qc.GetParentRound() != c || qc.VoteInfo.Epoch != p.Record.Epoch || qc.VoteInfo.Timestamp == 0 || qc.LedgerCommitInfo.NetworkID != tb.NetworkID || qc.LedgerCommitInfo.Epoch != p.Record.Epoch || qc.LedgerCommitInfo.Timestamp == 0 || qc.LedgerCommitInfo.Timestamp > qc.VoteInfo.Timestamp || !bytes.Equal(qc.LedgerCommitInfo.Hash, root) || !bytes.Equal(qc.VoteInfo.CurrentRootHash, root) {
		return VerifiedRecord{}, ErrProof
	}
	if err := verifyOldQC(qc, tb); err != nil {
		return VerifiedRecord{}, err
	}
	if p.OptionalQC != nil {
		if p.OptionalQC.VoteInfo == nil || p.OptionalQC.GetRound() != c || p.OptionalQC.VoteInfo.Epoch != p.Record.Epoch || p.OptionalQC.VoteInfo.Timestamp != qc.LedgerCommitInfo.Timestamp || !bytes.Equal(p.OptionalQC.VoteInfo.CurrentRootHash, root) {
			return VerifiedRecord{}, ErrProof
		}
		if err := verifyOldQC(p.OptionalQC, tb); err != nil {
			return VerifiedRecord{}, err
		}
	}
	var out VerifiedRecord
	if len(expected) == 1 {
		out.Context = expected[0]
	}
	out.Kind = "commit"
	out.RecordID = [32]byte{}
	copy(out.RecordID[:], p.Record.ID())
	out.OrderRound, out.CommitSealRound = p.Record.OrderedRound, c
	copy(out.StateRoot[:], root)
	copy(out.ControlDigest[:], digest)
	out.SignerEpoch = p.Record.Epoch
	return out, nil
}
