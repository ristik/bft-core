package certifiedstore

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// modeTrust is a trust source that knows the validation mode of each root epoch it holds, as q3active's guarded lookup does: an
// epoch it has no mode for is refused.
type modeTrust struct {
	multiTrust
	modes map[uint64]weightvalidation.Mode
}

func (m modeTrust) Mode(epoch uint64) (weightvalidation.Mode, error) {
	if mode, ok := m.modes[epoch]; ok {
		return mode, nil
	}
	return 0, errors.New("the epoch is not an installed activation")
}

// weightedAssignment is the rotated assignment of the deployment with the EVM validators weighing 6, 1 and 1, and the block that
// acknowledges it.
func (d *v2Deployment) weightedAssignment() (*types.PartitionDescriptionRecord, certifiedchain.Block) {
	d.t.Helper()
	validators := make([]*types.NodeInfo, 3)
	for i, w := range []uint64{6, 1, 1} {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(d.t, err)
		v, err := s.Verifier()
		require.NoError(d.t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(d.t, err)
		validators[i] = &types.NodeInfo{NodeID: string(rune('a' + i)), SigKey: pub, Stake: w}
	}
	succ, err := evmassign.NewSuccessor(d.chain.Full, validators)
	require.NoError(d.t, err)
	pdr, err := evmassign.Activate(succ, 40)
	require.NoError(d.t, err)
	hash, err := evmassign.PDRHash(pdr)
	require.NoError(d.t, err)
	ack := d.chain.ExecutedState(d.blocks[1], 2, 9, []byte("ack"), map[string]common.Hash{
		"assignment.epoch": w(1), "assignment.rootEpoch": w(2), "assignment.activeConfHash": common.Hash(hash),
		"transition.cursor": w(1), "transition.bodyID": w(7), "transition.genesisID": w(8), "transition.frozenID": w(9),
		"transition.commitID": w(10), "transition.frozenParent": common.Hash(d.blocks[1].Hash), "transition.successorTR": w(12), "origin.rootEpoch": w(2),
	})
	return pdr, ack
}

// A weighted validator set is certified data only under a root epoch the trust source holds as a verified activation: the mode comes
// from that source, never from the record, and a source that knows no modes (every legacy trust store) keeps the unit rules.
func TestAWeightedAssignmentIsAcceptedOnlyUnderAnActivatedRootEpoch(t *testing.T) {
	d := newV2Deployment(t)
	pdr, ack := d.weightedAssignment()
	uc, tr := d.certify(pdr, ack, d.blocks[1], 1, 1, 2) // certified by root epoch 2
	rec := d.record(ack, uc, tr, pdr)
	encode := func(trust TrustBases) error {
		c := d.ctx
		c.TrustBases = trust
		_, _, err := EncodeVerifiedRecord(context.Background(), c, rec)
		return err
	}
	base := d.ctx.TrustBases.(multiTrust)

	t.Run("an old client: a trust source with no modes keeps the unit rules", func(t *testing.T) {
		err := encode(base)
		require.ErrorIs(t, err, ErrWrongContext)
		require.ErrorContains(t, err, "configuration PDR")
	})
	t.Run("the root epoch is a verified weighted activation", func(t *testing.T) {
		require.NoError(t, encode(modeTrust{base, map[uint64]weightvalidation.Mode{1: weightvalidation.ModeUnit, 2: weightvalidation.ModeWeighted}}))
	})
	t.Run("the root epoch is a verified legacy epoch", func(t *testing.T) {
		err := encode(modeTrust{base, map[uint64]weightvalidation.Mode{2: weightvalidation.ModeUnit}})
		require.ErrorIs(t, err, ErrWrongContext)
	})
	t.Run("the weighted mode of another epoch is not the certificate's", func(t *testing.T) {
		err := encode(modeTrust{base, map[uint64]weightvalidation.Mode{1: weightvalidation.ModeWeighted}})
		require.ErrorIs(t, err, ErrEpoch, "the certificate's root epoch 2 has no mode in this source")
	})
	t.Run("a source that cannot tell is an error, not unit and not weighted", func(t *testing.T) {
		err := encode(modeTrust{base, nil})
		require.ErrorIs(t, err, ErrEpoch)
	})
	t.Run("a unit assignment is unchanged under a weighted epoch's source", func(t *testing.T) {
		uc, tr := d.certify(d.pdr[1], d.blocks[2], d.blocks[1], 1, 1, 2)
		c := d.ctx
		c.TrustBases = modeTrust{base, map[uint64]weightvalidation.Mode{2: weightvalidation.ModeWeighted}}
		_, _, err := EncodeVerifiedRecord(context.Background(), c, d.record(d.blocks[2], uc, tr, d.pdr[1]))
		require.NoError(t, err, "weights of one are valid under the weighted rules too")
	})
}
