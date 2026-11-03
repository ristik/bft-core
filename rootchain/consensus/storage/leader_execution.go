package storage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// ErrLeaderInputs is an epoch whose leader state cannot be derived: a ring with nobody to name its committee, or an unusable answer.
var ErrLeaderInputs = errors.New("leader state inputs unavailable")

// LeaderInputs is what execution reads about an epoch: whether it runs root-reputation-v1 and, if so, its committee in canonical order. It
// comes from the authenticated trust-base history, so every root executing a block derives the same leaf.
type LeaderInputs interface {
	LeaderCommittee(epoch uint64) (committee []string, reputation bool, err error)
}

// nextLeaderState is the leaf of newBlock, a child of parent (the frozen suffix does not come here). The epoch's first ordinary block
// starts a new ring whatever its parent, the anchor, kept: an anchor retains the outgoing certified root and cannot reset a leaf in place.
// Every later block appends the voters of the QC it carries. Only QC.Signatures count: SealSignatures, the author and the certificate that
// commits the block are not inputs.
func nextLeaderState(parent *ExecutedBlock, newBlock *rctypes.BlockData, bootstrapChild bool, leaders LeaderInputs) (*rctypes.LeaderState, error) {
	if bootstrapChild {
		if leaders == nil {
			return nil, nil
		}
		committee, reputation, err := leaders.LeaderCommittee(newBlock.Epoch)
		if err != nil {
			return nil, errors.Join(ErrLeaderInputs, err)
		}
		if !reputation {
			return nil, nil
		}
		return rctypes.NewLeaderState(newBlock.Anchor.GenesisID, newBlock.Epoch, newBlock.Anchor.Slot+1, uint64(len(committee)), newBlock.Round)
	}
	ring := parent.ShardState.Leader
	if ring == nil {
		return nil, nil
	}
	if leaders == nil {
		return nil, fmt.Errorf("%w: a ring and no committee for it", ErrLeaderInputs)
	}
	if newBlock.Qc == nil {
		return nil, fmt.Errorf("%w: block of round %d carries no QC", rctypes.ErrLeaderState, newBlock.Round)
	}
	committee, reputation, err := leaders.LeaderCommittee(ring.Epoch)
	if err != nil {
		return nil, errors.Join(ErrLeaderInputs, err)
	}
	if !reputation || uint64(len(committee)) != ring.Members {
		return nil, fmt.Errorf("%w: a ring of %d members and a committee of %d, reputation %t", ErrLeaderInputs, ring.Members, len(committee), reputation)
	}
	signers := make([]string, 0, len(newBlock.Qc.Signatures))
	for signer := range newBlock.Qc.Signatures {
		signers = append(signers, signer)
	}
	voters, err := rctypes.LeaderBitmap(committee, signers)
	if err != nil {
		return nil, err
	}
	return ring.Next(newBlock.Round, voters)
}

// validateLeaderState judges a restored head's leaf against the head itself, before the state root does: it belongs to the control state's
// epoch, and its last record is the head's block, or, in a closed epoch whose suffix copies the ring, the closing carrier.
func validateLeaderState(head *abdrc.CommittedBlock) error {
	ring := head.Leader
	if ring == nil {
		return nil
	}
	if head.Control == nil || ring.Epoch != head.Control.Epoch {
		return ErrNetworkProfile
	}
	if err := ring.Valid(); err != nil {
		return err
	}
	last := ring.Records[len(ring.Records)-1].Round
	switch {
	case head.Control.Phase == "committed":
		if last != head.Control.OrderedRound {
			return fmt.Errorf("%w: last record %d, the closing block %d", rctypes.ErrLeaderState, last, head.Control.OrderedRound)
		}
	case last != head.Block.GetRound():
		return fmt.Errorf("%w: last record %d, head %d", rctypes.ErrLeaderState, last, head.Block.GetRound())
	}
	return nil
}

// sameLeaderState is the frozen suffix's rule on the leaf: unchanged, byte for byte, because the block must keep its parent's root.
func sameLeaderState(parent, child *rctypes.LeaderState) error {
	if (parent == nil) != (child == nil) {
		return ErrHandoffSuffix
	}
	if parent == nil {
		return nil
	}
	a, err := parent.Digest()
	if err != nil {
		return err
	}
	b, err := child.Digest()
	if err != nil {
		return err
	}
	if !bytes.Equal(a, b) {
		return ErrHandoffSuffix
	}
	return nil
}
