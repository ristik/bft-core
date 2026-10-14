package storage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// ErrUTBBinding is returned by ProcessQc for a certificate of a UTB epoch whose trust-base endorsement is not the one the locally executed committed
// state implies. The certificate is neither inserted nor committed, so nothing is published or installed from it.
var ErrUTBBinding = errors.New("certificate endorsement does not match the committed state")

// ErrUTBAlreadyCommitted is returned by HandoffCommittedAt for a round below the tree's committed root: it was bound when it committed and its block is no
// longer held, so a certificate that commits it has nothing left to bind or to retain; the commit itself refuses it (ErrCommitFailed), as it always did.
var ErrUTBAlreadyCommitted = errors.New("the committed round is below the committed root")

// UTBBinding is the contextual check of a certificate before it is applied: the cryptographic checks of the certificate do not authorize a state
// transition without the execution context that says whether, and which, successor entry it must carry.
type UTBBinding func(qc *rctypes.QuorumCert) error

// NewUTBBinding builds the check. cfgOf is the authenticated signing configuration of an epoch; entryOf resolves the committed round of a committing
// certificate to the unsigned successor entry the locally executed state implies (nil when it holds no outgoing handoff). In an epoch configured
// with Config.UTB a committing certificate must carry exactly that entry and no certificate may carry an entry the state does not imply; an epoch
// not configured for it is not constrained here.
func NewUTBBinding(cfgOf func(epoch uint64) (votesig.Config, error), entryOf func(committed *rctypes.RoundInfo, epoch uint64) ([]byte, error)) UTBBinding {
	return func(qc *rctypes.QuorumCert) error {
		if qc == nil || qc.VoteInfo == nil || qc.LedgerCommitInfo == nil || qc.GetRound() == rctypes.GenesisRootRound {
			return nil
		}
		cfg, err := cfgOf(qc.VoteInfo.Epoch)
		if err != nil {
			return fmt.Errorf("%w: signing configuration of epoch %d: %w", ErrUTBBinding, qc.VoteInfo.Epoch, err)
		}
		if !cfg.UTB {
			return nil
		}
		seal := qc.LedgerCommitInfo
		var want []byte
		if seal.RootChainRoundNumber != 0 {
			committed := &rctypes.RoundInfo{RoundNumber: seal.RootChainRoundNumber, Epoch: seal.Epoch, CurrentRootHash: seal.Hash, Timestamp: seal.Timestamp}
			if want, err = entryOf(committed, qc.VoteInfo.Epoch); errors.Is(err, ErrUTBAlreadyCommitted) {
				return err // not a refusal: ProcessQc skips the binding and the retention and lets the commit decide
			} else if err != nil {
				return fmt.Errorf("%w: committed round %d: %v", ErrUTBBinding, seal.RootChainRoundNumber, err)
			}
		}
		switch {
		case want == nil && qc.UTB != nil:
			return fmt.Errorf("%w: round %d carries an endorsement, the committed state holds no outgoing handoff", ErrUTBBinding, qc.GetRound())
		case want != nil && qc.UTB == nil:
			return fmt.Errorf("%w: round %d commits the outgoing handoff without its endorsement", ErrUTBBinding, qc.GetRound())
		case want != nil && !bytes.Equal(want, qc.UTB.Unsigned):
			return fmt.Errorf("%w: round %d endorses another entry than the committed state implies", ErrUTBBinding, qc.GetRound())
		}
		return nil
	}
}

// ErrUTBRetention is returned by ProcessQc when the endorsed entry of a committing certificate cannot be made durable. The certificate is then neither
// inserted nor committed, so no commit is visible without its entry.
var ErrUTBRetention = errors.New("the endorsed trust-base entry cannot be retained")

// UTBRetention makes the endorsed entry of a committing certificate durable. It must be idempotent: a replayed certificate, or a later one that carries
// the same entry, is accepted.
type UTBRetention func(qc *rctypes.QuorumCert) error

// SetUTBRetention installs the retention applied before a committing certificate is inserted.
func (x *BlockStore) SetUTBRetention(r UTBRetention) { x.utbRetain = r }

// SetUTBBinding installs the check applied to every certificate before it is inserted or committed.
func (x *BlockStore) SetUTBBinding(b UTBBinding) { x.utbBinding = b }

// HandoffCommittedAt reports the committed handoff record held by the executed state of a round: ok is false when that state is not the committed
// terminal state of a handoff. The block must be the locally executed one the caller names: its epoch and executed state hash are compared, never taken
// from the caller's claim alone.
func (x *BlockStore) HandoffCommittedAt(round, epoch uint64, rootHash []byte) (record evmroot.OrderedHandoffRecord, ok bool, err error) {
	block, err := x.blockTree.FindBlock(round)
	if err != nil {
		if root := x.blockTree.Root(); root != nil && round < root.GetRound() {
			return record, false, fmt.Errorf("%w: round %d, root %d", ErrUTBAlreadyCommitted, round, root.GetRound())
		}
		return record, false, err
	}
	if block == nil || block.BlockData == nil || block.BlockData.Epoch != epoch || !bytes.Equal(block.RootHash, rootHash) {
		return record, false, fmt.Errorf("%w: round %d is not the executed block the caller names", ErrUTBBinding, round)
	}
	record, ok = committedRecord(block)
	return record, ok, nil
}
