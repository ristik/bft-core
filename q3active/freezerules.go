package q3active

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// ErrFreeze is returned by the V3 freeze rules for a body, predecessor or receipt set the old committee must not endorse.
var ErrFreeze = errors.New("q3active: V3 freeze refused")

// FreezeRules is storage.V3FreezeRules over the q3format body and receipt formats. It holds no state: a V3 body is validated in full
// by q3format, and the receipts are checked against the body they name.
type FreezeRules struct{}

var _ storage.V3FreezeRules = FreezeRules{}

// FreezeRules is the V3 rule set the old committee applies at Freeze. The runtime is the Q3 authority a manager is wired to, and the
// rules are not a property of one runtime, so this is a plain accessor.
func (*Runtime) FreezeRules() storage.V3FreezeRules { return FreezeRules{} }

func (FreezeRules) VerifyBody(raw []byte) (storage.V3Body, error) {
	b, err := q3format.DecodeBody(raw)
	if err != nil {
		return storage.V3Body{}, errors.Join(ErrFreeze, err)
	}
	members := make([]evmassign.RootMember, len(b.Members))
	for i, m := range b.Members {
		members[i] = evmassign.RootMember{NodeID: m.NodeID, Key: m.ConsensusKey, Weight: m.Weight}
	}
	return storage.V3Body{ID: b.Identity(), Network: b.Network, Epoch: b.Epoch, EarliestActivation: b.EarliestActivation, Members: members,
		StateSummary: b.StateSummary, ChangeRecordHash: b.ChangeRecordHash, PredecessorHash: b.PredecessorHash}, nil
}

func (FreezeRules) Prior(network, epoch, version uint64, identity []byte) ([]byte, error) {
	h, err := q3format.Prior{Network: network, Epoch: epoch, BodyVersion: version, Identity: identity}.Hash()
	if err != nil {
		return nil, errors.Join(ErrFreeze, err)
	}
	return h, nil
}

func (FreezeRules) VerifyReceipts(body, receipts []byte, attempt uint64, candidate []byte) error {
	b, err := q3format.DecodeBody(body)
	if err != nil {
		return errors.Join(ErrFreeze, err)
	}
	if len(candidate) != 32 {
		return fmt.Errorf("%w: candidate digest of %d bytes", ErrFreeze, len(candidate))
	}
	rs, err := q3format.DecodeReceipts(receipts)
	if err != nil {
		return errors.Join(ErrFreeze, err)
	}
	if err := q3format.VerifyReceipts(b, q3format.ContextFor(b, attempt, [32]byte(candidate)), rs); err != nil {
		return errors.Join(ErrFreeze, err)
	}
	return nil
}

// ProtocolConfig is the tuple of a V3 body planned on this history: the fixed Q3 rule set over its network and root genesis.
func (r *Runtime) ProtocolConfig() (q3format.ProtocolConfig, error) {
	h := r.History()
	if h == nil {
		return q3format.ProtocolConfig{}, ErrFreeze
	}
	return q3format.Q3Config(h.Network(), h.Genesis()), nil
}
