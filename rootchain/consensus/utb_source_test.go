package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/q3format"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/utb"
)

type fakeHandoffState struct {
	record evmroot.OrderedHandoffRecord
	ok     bool
	err    error
	bodies map[string][]byte
	asked  []uint64
}

func (f *fakeHandoffState) HandoffCommittedAt(round, epoch uint64, rootHash []byte) (evmroot.OrderedHandoffRecord, bool, error) {
	f.asked = append(f.asked, round)
	return f.record, f.ok, f.err
}

func (f *fakeHandoffState) HandoffBody(id []byte) ([]byte, error) {
	b, ok := f.bodies[string(id)]
	if !ok {
		return nil, errors.New("no such body")
	}
	return b, nil
}

type utbMember struct {
	ws     evmroot.Member
	signer abcrypto.Signer
}

func utbCommittee(t *testing.T, n int) []utbMember {
	var out []utbMember
	for i := 0; i < n; i++ {
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{byte(i + 1)}, 32))
		require.NoError(t, err)
		v, _ := s.Verifier()
		pk, _ := v.MarshalPublicKey()
		pub, err := crypto.UnmarshalSecp256k1PublicKey(pk)
		require.NoError(t, err)
		id, err := peer.IDFromPublicKey(pub)
		require.NoError(t, err)
		out = append(out, utbMember{evmroot.Member{StakingID: fmt.Sprintf("s%d", i), NodeID: id.String(), ConsensusKey: pk, Weight: 1}, s})
	}
	return out
}

func weightSet(ms []utbMember) evmroot.WeightSet {
	var ws evmroot.WeightSet
	for _, m := range ms {
		ws = append(ws, m.ws)
	}
	return ws
}

func TestUTBSuccessorDerivesTheSameEntryFromV2AndQ3Bodies(t *testing.T) {
	ms := utbCommittee(t, 4)
	ws := weightSet(ms)
	state, change := bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
	pred := bytes.Repeat([]byte{5}, 32)
	v2 := evmroot.TrustBaseBodyV2{Version: evmroot.TrustBaseVersion, NetworkID: 5, Epoch: 2, EarliestActivation: 50, Members: ws, RootThreshold: 3, StateSummary: state, ChangeRecordHash: change, PredecessorHash: pred}
	var g [32]byte
	g[0] = 1
	v3 := q3format.BodyV3{Network: 5, Epoch: 2, EarliestActivation: 50, Members: ws, RootThreshold: 3, StateSummary: state, ChangeRecordHash: change, PredecessorHash: pred, Config: q3format.Q3ConfigUTB(5, g)}

	genesis, err := utb.BuildUnsigned(nil, utb.FromWeightSet(5, 1, 1, ws, 3, state, change))
	require.NoError(t, err)
	prev := func(epoch uint64) (*types.RootTrustBaseV2, error) {
		if epoch != 1 {
			return nil, errors.New("not finalized")
		}
		return genesis, nil
	}
	const activation = 120
	mk := func(id [32]byte, raw []byte) *fakeHandoffState {
		return &fakeHandoffState{ok: true, record: evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, ActivationRound: activation, NextBodyID: id[:], Kind: "commit"},
			bodies: map[string][]byte{string(id[:]): raw}}
	}
	id2, id3 := v2.Identity(), v3.Identity()
	committed := &drctypes.RoundInfo{RoundNumber: 7, Epoch: 1, CurrentRootHash: bytes.Repeat([]byte{1}, 32)}

	a, err := UTBSuccessor{State: mk(id2, v2.Encode()), Previous: prev}.Entry(committed, 1)
	require.NoError(t, err)
	b, err := UTBSuccessor{State: mk(id3, v3.Encode()), Previous: prev}.Entry(committed, 1)
	require.NoError(t, err)
	require.NotNil(t, a)
	require.Equal(t, a, b, "V2 and Q3 bodies give one entry")
	e, err := utb.DecodeUnsigned(a)
	require.NoError(t, err)
	require.EqualValues(t, activation, e.EpochStart, "the record's actual activation round")
	gid, _ := genesis.EntryID()
	require.Equal(t, gid[:], []byte(e.PreviousEntryID))

	t.Run("no outgoing handoff of this epoch", func(t *testing.T) {
		none := &fakeHandoffState{ok: false}
		got, err := UTBSuccessor{State: none, Previous: prev}.Entry(committed, 1)
		require.NoError(t, err)
		require.Nil(t, got)
		// the committed record of an earlier epoch still shows in a later epoch's control state: not this epoch's handoff
		later := mk(id2, v2.Encode())
		got, err = UTBSuccessor{State: later, Previous: prev}.Entry(committed, 2)
		require.NoError(t, err)
		require.Nil(t, got)
	})
	t.Run("fails closed", func(t *testing.T) {
		for name, s := range map[string]UTBSuccessor{
			"executed state unavailable": {State: &fakeHandoffState{err: errors.New("no such block")}, Previous: prev},
			"body not retained":          {State: &fakeHandoffState{ok: true, record: mk(id2, nil).record}, Previous: prev},
			"another body than the record names": {State: func() *fakeHandoffState {
				f := mk(id2, v3.Encode())
				return f
			}(), Previous: prev},
			"garbage body":       {State: mk(id2, []byte{1, 2, 3}), Previous: prev},
			"no finalized entry": {State: mk(id2, v2.Encode()), Previous: func(uint64) (*types.RootTrustBaseV2, error) { return nil, errors.New("missing") }},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := s.Entry(committed, 1)
				require.Error(t, err)
			})
		}
		_, err := UTBSuccessor{State: mk(id2, v2.Encode()), Previous: func(uint64) (*types.RootTrustBaseV2, error) { return nil, errors.New("missing") }}.Entry(committed, 1)
		require.ErrorIs(t, err, ErrUTBSuccessor)
	})
	t.Run("an activation round that is not later than the predecessor's start", func(t *testing.T) {
		f := mk(id2, v2.Encode())
		f.record.ActivationRound = genesis.EpochStart
		_, err := UTBSuccessor{State: f, Previous: prev}.Entry(committed, 1)
		require.ErrorIs(t, err, ErrUTBSuccessor)
	})
}
