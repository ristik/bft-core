package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

type noAuthority struct{}

func (noAuthority) VerifyClosure([]byte, uint64) (storage.ClosureFacts, error) {
	return storage.ClosureFacts{}, errors.New("not used")
}

var testDeployment = storage.PosDeployment{RootNetwork: 5}

func submissionCMs(t *testing.T) []*ConsensusManager {
	t.Helper()
	cms, rootNet := createConsensusManagers(t, 4, nil)
	rootNet.SetFirewall(func(_, _ peer.ID, _ any) bool { return true }) // nothing is delivered: the tests feed messages by hand
	for _, cm := range cms {
		cm.SetPosServices(&storage.PosServices{Deployment: testDeployment, Authority: noAuthority{}})
	}
	return cms
}

func retirement(witness []byte) drctypes.PosControl {
	return drctypes.PosControl{Network: testDeployment.RootNetwork, Op: drctypes.OpRetirement, Retire: &drctypes.RetireContext{},
		Data: make([]byte, 96), WitnessHash: sha256.Sum256(witness)}
}

func signed(t *testing.T, cm *ConsensusManager, c drctypes.PosControl) *abdrc.PosControlSubmissionMsg {
	t.Helper()
	domain, err := abdrc.PosControlSigningBytes(c)
	require.NoError(t, err)
	sig, err := cm.safety.signer.SignBytes(domain)
	require.NoError(t, err)
	return &abdrc.PosControlSubmissionMsg{Control: c, Signer: cm.id.String(), Signature: sig}
}

func TestSubmitPosControlSignsRetainsTheWitnessAndQueues(t *testing.T) {
	cms := submissionCMs(t)
	witness := []byte("a storage proof")
	c := retirement(witness)
	require.NoError(t, cms[0].SubmitPosControl(context.Background(), c, witness))
	require.Equal(t, 1, cms[0].posQueue.len())
	require.True(t, cms[0].blockStore.HasWitness(c.WitnessHash), "the submitter retains the witness the others pull")
	// the same submission again changes nothing
	require.NoError(t, cms[0].SubmitPosControl(context.Background(), c, witness))
	require.Equal(t, 1, cms[0].posQueue.len())
	// a witness that is not the committed one is refused before anything is signed or stored
	require.ErrorIs(t, cms[0].SubmitPosControl(context.Background(), c, []byte("another")), ErrPosSubmission)
}

func TestAReceivedSubmissionIsQueuedOnlyWhenSignedByARootValidatorAndWellFormed(t *testing.T) {
	cms := submissionCMs(t)
	good := retirement([]byte("w"))
	msg := signed(t, cms[0], good)
	require.NoError(t, cms[1].onPosControlSubmission(context.Background(), msg))
	require.Equal(t, 1, cms[1].posQueue.len())

	other := cms[2]
	cases := map[string]func() *abdrc.PosControlSubmissionMsg{
		"a tampered control": func() *abdrc.PosControlSubmissionMsg {
			m := signed(t, cms[0], good)
			m.Control.Data = bytes.Repeat([]byte{1}, 96)
			return m
		},
		"another signer than the signature's": func() *abdrc.PosControlSubmissionMsg {
			m := signed(t, cms[0], good)
			m.Signer = other.id.String()
			return m
		},
		"a signer outside the trust base": func() *abdrc.PosControlSubmissionMsg {
			signer, err := abcrypto.NewInMemorySecp256K1Signer()
			require.NoError(t, err)
			domain, _ := abdrc.PosControlSigningBytes(good)
			sig, err := signer.SignBytes(domain)
			require.NoError(t, err)
			return &abdrc.PosControlSubmissionMsg{Control: good, Signer: testPeer(t).String(), Signature: sig}
		},
		"no signature": func() *abdrc.PosControlSubmissionMsg { m := signed(t, cms[0], good); m.Signature = nil; return m },
		"a closure control": func() *abdrc.PosControlSubmissionMsg {
			c := drctypes.PosControl{Network: testDeployment.RootNetwork, Op: drctypes.OpCloseLiability, Close: &drctypes.CloseContext{ClosedEpoch: 2},
				Data: make([]byte, 192)}
			c.Data[56] = 1
			return signed(t, cms[0], c)
		},
		"an ordering position": func() *abdrc.PosControlSubmissionMsg {
			c := good
			c.OrderingRound = 4
			return signed(t, cms[0], c)
		},
		"another deployment": func() *abdrc.PosControlSubmissionMsg {
			c := good
			c.Network++
			return signed(t, cms[0], c)
		},
	}
	for name, build := range cases {
		cm := cms[3]
		require.ErrorIs(t, cm.onPosControlSubmission(context.Background(), build()), ErrPosSubmission, name)
		require.Zero(t, cm.posQueue.len(), name)
	}
	// a root without a deployment takes none
	bare, _ := createConsensusManagers(t, 4, nil)
	require.ErrorIs(t, bare[1].onPosControlSubmission(context.Background(), signed(t, bare[0], good)), ErrPosSubmission)
}

func TestTheSubmissionQueueIsBoundedDedupedAndExpires(t *testing.T) {
	var q posSubmissions
	mk := func(signer string, n byte, expires uint64) posSubmission {
		return posSubmission{signer: signer, key: []byte{n, byte(len(signer))}, expires: expires}
	}
	for i := 0; i < maxPosSubmissionsPerSigner; i++ {
		require.NoError(t, q.add(mk("a", byte(i), 100), 1))
	}
	require.ErrorIs(t, q.add(mk("a", 99, 100), 1), ErrPosSubmission, "one validator cannot fill the queue")
	require.NoError(t, q.add(mk("a", 0, 100), 1), "a repeat is not a new entry")
	require.Equal(t, maxPosSubmissionsPerSigner, q.len())
	for i := 0; q.len() < maxPosSubmissions; i++ {
		require.NoError(t, q.add(mk(string(rune('b'+i)), byte(i), 100), 1))
	}
	require.ErrorIs(t, q.add(mk("zz", 77, 100), 1), ErrPosSubmission, "the queue is bounded")
	require.Equal(t, maxPosSubmissions, q.len())
	// expiry makes room
	require.NoError(t, q.add(mk("zz", 77, 300), 101))
	require.Equal(t, 1, q.len())
	q.drop([]byte{77, 2})
	require.Zero(t, q.len())
}

func orderingFixture(t *testing.T, controls ...drctypes.PosControl) (*ConsensusManager, *drctypes.BlockData, []posSubmission) {
	t.Helper()
	cms := submissionCMs(t)
	x := cms[0]
	x.witnesses = func(context.Context, [32]byte, []peer.ID) ([]byte, error) { return nil, errors.New("unreachable") }
	block := &drctypes.BlockData{Epoch: 3, Round: 9, Author: x.id.String(), Payload: &drctypes.Payload{
		PosControls: []drctypes.PosControl{{Op: 99}}}} // a closure already in the block
	var subs []posSubmission
	for i, c := range controls {
		w := []byte{byte(i)}
		require.NoError(t, x.blockStore.StoreWitness(w))
		c.WitnessHash = sha256.Sum256(w)
		require.NoError(t, x.onPosControlSubmission(context.Background(), signed(t, cms[i%2], c)))
		subs = append(subs, posSubmission{})
	}
	return x, block, subs
}

func TestTheLeaderOrdersTheOldestControlTheRootStateAcceptsAndDropsTheRest(t *testing.T) {
	mk := func(b byte) drctypes.PosControl {
		c := retirement([]byte{b})
		c.Data[95] = b
		return c
	}
	x, block, _ := orderingFixture(t, mk(1), mk(2), mk(3))
	refused := errors.New("stale EVM state")
	var tried []byte
	x.orderSubmittedControlWith(context.Background(), block, func(b *drctypes.BlockData) error {
		last := b.Payload.PosControls[len(b.Payload.PosControls)-1]
		tried = append(tried, last.Data[95])
		require.EqualValues(t, 3, last.OrderingEpoch, "the control is stamped with the position of the block that orders it")
		require.EqualValues(t, 9, last.OrderingRound)
		if last.Data[95] == 1 {
			return refused
		}
		return nil
	})
	require.Equal(t, []byte{1, 2}, tried, "the first is refused and dropped, the second accepted, the third not tried")
	require.Len(t, block.Payload.PosControls, 2, "the closure is kept and exactly one submitted control follows it")
	require.EqualValues(t, 2, block.Payload.PosControls[1].Data[95])
	require.EqualValues(t, 9, block.Payload.PosControls[1].OrderingRound)
	require.Equal(t, 2, x.posQueue.len(), "the accepted control stays until it is committed (the proposal may be lost); the refused one is gone")
}

func TestARefusedTrialLeavesTheBlockUntouchedAndAtMostFourAreTried(t *testing.T) {
	var cs []drctypes.PosControl
	for i := 0; i < 6; i++ {
		c := retirement([]byte{byte(i)})
		c.Data[95] = byte(i + 1)
		cs = append(cs, c)
	}
	x, block, _ := orderingFixture(t, cs...) // two validators submit, so the per-validator cap of four is not what limits the trials
	trials := 0
	x.orderSubmittedControlWith(context.Background(), block, func(*drctypes.BlockData) error { trials++; return errors.New("no") })
	require.Equal(t, maxPosTrials, trials)
	require.Len(t, block.Payload.PosControls, 1, "nothing is appended when every candidate is refused")
	require.Equal(t, 2, x.posQueue.len(), "the four tried are dropped, the two beyond the bound wait for the next proposal")
}

func TestASubmitterThatCannotBePulledFromKeepsItsControlQueued(t *testing.T) {
	c := retirement([]byte("never stored"))
	cms := submissionCMs(t)
	x := cms[0]
	x.witnesses = func(context.Context, [32]byte, []peer.ID) ([]byte, error) {
		return nil, errors.New("submitter offline")
	}
	require.NoError(t, x.onPosControlSubmission(context.Background(), signed(t, cms[1], c)))
	block := &drctypes.BlockData{Epoch: 3, Round: 9, Author: x.id.String(), Payload: &drctypes.Payload{}}
	called := false
	x.orderSubmittedControlWith(context.Background(), block, func(*drctypes.BlockData) error { called = true; return nil })
	require.False(t, called, "no trial without the witness")
	require.Empty(t, block.Payload.PosControls)
	require.Equal(t, 1, x.posQueue.len(), "an unreachable submitter is not a verdict on the control")
}
