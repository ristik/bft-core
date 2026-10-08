package handoff

import (
	"bytes"
	"crypto"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
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

// ControlRoot is the unicity tree root the control leaf of this control state and its path lead to: the root a certificate or a commit
// seal of the block that carried the control must name.
func ControlRoot(control *evmroot.ControlState, certificate *types.UnicityTreeCertificate) ([]byte, error) {
	if control == nil || certificate == nil || certificate.Partition != evmroot.D4ControlPartition || certificate.Version != 1 {
		return nil, ErrProof
	}
	hasher := abhash.New(crypto.SHA256.New())
	hasher.Write(control.Digest())
	leafHash, err := hasher.Sum()
	if err != nil {
		return nil, ErrProof
	}
	path := []*imt.PathItem{imt.NewPathItem(evmroot.D4ControlPartition.Bytes(), leafHash)}
	for _, step := range certificate.HashSteps {
		if step == nil || step.Key == evmroot.D4ControlPartition {
			return nil, ErrProof
		}
		path = append(path, step.ToIMTPathItem())
	}
	root, err := imt.IndexTreeOutput(path, evmroot.D4ControlPartition.Bytes(), crypto.SHA256)
	if err != nil {
		return nil, ErrProof
	}
	return root, nil
}

// verifyOldQC verifies a commit QC of the old epoch by that epoch's own rule: cfg is the old epoch's signing configuration, and the
// certificate must be in the wire form it requires. A zero configuration is the legacy one.
func verifyOldQC(qc *rctypes.QuorumCert, tb *types.RootTrustBaseV1, cfg votesig.Config) error {
	if qc == nil || qc.VoteInfo == nil || qc.LedgerCommitInfo == nil || qc.GetRound() <= rctypes.GenesisRootRound || len(qc.Signatures) == 0 {
		return ErrProof
	}
	if cfg.Scheme == votesig.SchemeDomainBound {
		// a scheme 2 certificate has no vote info timestamp; its seal still carries one, and both signature maps are verified, strictly
		if qc.LedgerCommitInfo.GetVersion() != 1 || qc.LedgerCommitInfo.Timestamp < types.GenesisTime {
			return ErrProof
		}
		if err := qc.VerifyScheme(tb, cfg); err != nil {
			return fmt.Errorf("%w: %w", ErrProof, err)
		}
		return nil
	}
	if qc.Scheme != 0 && qc.Scheme != votesig.SchemeLegacy {
		return fmt.Errorf("%w: %w: certificate is scheme %d, its epoch requires scheme 1", ErrProof, votesig.ErrScheme, qc.Scheme)
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
	if _, err := quorumweight.VerifySignedStrict(tb, bs, qc.Signatures); err != nil {
		return ErrProof
	}
	return nil
}

// VerifyOldCommitProof verifies the proof with the old epoch in the legacy signing scheme (the default of every verifier that has no
// signing configuration of its own); VerifyOldCommitProofSigning takes the old epoch's configuration.
func VerifyOldCommitProof(p OldCommitProof, tb *types.RootTrustBaseV1, expected ...Context) (VerifiedRecord, error) {
	return VerifyOldCommitProofSigning(p, tb, votesig.Config{Scheme: votesig.SchemeLegacy}, expected...)
}

// VerifyOldCommitProofSigning is VerifyOldCommitProof by the rule of the old epoch: cfg is that epoch's signing configuration, and its
// commit QC (and the optional one) must be in the wire form the configuration requires.
func VerifyOldCommitProofSigning(p OldCommitProof, tb *types.RootTrustBaseV1, cfg votesig.Config, expected ...Context) (VerifiedRecord, error) {
	domainBound := cfg.Scheme == votesig.SchemeDomainBound
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
	root, err := ControlRoot(&p.Control, p.ControlPath)
	if err != nil {
		return VerifiedRecord{}, err
	}
	qc := p.CommitQC
	if qc == nil || qc.VoteInfo == nil || qc.LedgerCommitInfo == nil {
		return VerifiedRecord{}, ErrProof
	}
	// the certificate must be in the wire form the old epoch signs with, before anything else about it is read
	if want := cfg.Scheme; (want == votesig.SchemeDomainBound) != (qc.Scheme == votesig.SchemeDomainBound) {
		return VerifiedRecord{}, fmt.Errorf("%w: %w: commit QC is scheme %d, its epoch requires scheme %d", ErrProof, votesig.ErrScheme, max(qc.Scheme, 1), max(want, 1))
	}
	c := qc.LedgerCommitInfo.RootChainRoundNumber
	if c == 0 || c < p.Record.OrderedRound || c == math.MaxUint64 || qc.GetRound() != c+1 || qc.GetParentRound() != c || qc.VoteInfo.Epoch != p.Record.Epoch || (!domainBound && (qc.VoteInfo.Timestamp == 0 || qc.LedgerCommitInfo.Timestamp > qc.VoteInfo.Timestamp)) || qc.LedgerCommitInfo.NetworkID != tb.NetworkID || qc.LedgerCommitInfo.Epoch != p.Record.Epoch || qc.LedgerCommitInfo.Timestamp == 0 || !bytes.Equal(qc.LedgerCommitInfo.Hash, root) || !bytes.Equal(qc.VoteInfo.CurrentRootHash, root) {
		return VerifiedRecord{}, ErrProof
	}
	if err := verifyOldQC(qc, tb, cfg); err != nil {
		return VerifiedRecord{}, err
	}
	if p.OptionalQC != nil {
		if p.OptionalQC.VoteInfo == nil || p.OptionalQC.GetRound() != c || p.OptionalQC.VoteInfo.Epoch != p.Record.Epoch || (!domainBound && p.OptionalQC.VoteInfo.Timestamp != qc.LedgerCommitInfo.Timestamp) || !bytes.Equal(p.OptionalQC.VoteInfo.CurrentRootHash, root) {
			return VerifiedRecord{}, ErrProof
		}
		if err := verifyOldQC(p.OptionalQC, tb, cfg); err != nil {
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
	copy(out.ControlDigest[:], p.Control.Digest())
	out.SignerEpoch = p.Record.Epoch
	return out, nil
}
