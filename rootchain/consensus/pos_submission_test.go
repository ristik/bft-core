package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync/atomic"
	"testing"
	"time"

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
	return signedFor(t, cm, c, cm.trustBase.Load().Epoch)
}

func signedFor(t *testing.T, cm *ConsensusManager, c drctypes.PosControl, epoch uint64) *abdrc.PosControlSubmissionMsg {
	t.Helper()
	domain, err := abdrc.PosControlSigningBytes(c, epoch)
	require.NoError(t, err)
	sig, err := cm.safety.signer.SignBytes(domain)
	require.NoError(t, err)
	return &abdrc.PosControlSubmissionMsg{Control: c, Epoch: epoch, Signer: cm.id.String(), Signature: sig}
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
	cms[1].witnesses = func(context.Context, [32]byte, []peer.ID, int) ([]byte, error) { return []byte("w"), nil }
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
			domain, _ := abdrc.PosControlSigningBytes(good, cms[3].trustBase.Load().Epoch)
			sig, err := signer.SignBytes(domain)
			require.NoError(t, err)
			return &abdrc.PosControlSubmissionMsg{Control: good, Epoch: cms[3].trustBase.Load().Epoch, Signer: testPeer(t).String(), Signature: sig}
		},
		"another epoch than this one": func() *abdrc.PosControlSubmissionMsg {
			return signedFor(t, cms[0], good, cms[3].trustBase.Load().Epoch+1)
		},
		"an old epoch replayed": func() *abdrc.PosControlSubmissionMsg {
			return signedFor(t, cms[0], good, cms[3].trustBase.Load().Epoch+7)
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
	// every rejection below must come from the check it names, not from a root that cannot fetch: cms[3] can
	cms[3].witnesses = func(context.Context, [32]byte, []peer.ID, int) ([]byte, error) { return []byte("w"), nil }
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
	x.witnesses = func(context.Context, [32]byte, []peer.ID, int) ([]byte, error) { return nil, errors.New("unreachable") }
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

// queued puts a submission straight into the queue, witness not held, as the intake does before its prefetch finished.
func queued(t *testing.T, x *ConsensusManager, c drctypes.PosControl) posSubmission {
	t.Helper()
	domain, err := abdrc.PosControlSigningBytes(c, 1)
	require.NoError(t, err)
	s := posSubmission{control: c, signer: x.id.String(), witness: c.WitnessHash, expires: 1 << 40, key: domain}
	require.NoError(t, x.posQueue.add(s, 0))
	return s
}

func TestBuildingAProposalNeverPullsAWitnessOverTheNetwork(t *testing.T) {
	cms := submissionCMs(t)
	x := cms[0]
	called := false
	x.witnesses = func(context.Context, [32]byte, []peer.ID, int) ([]byte, error) {
		called = true
		return nil, errors.New("no")
	}
	queued(t, x, retirement([]byte("not held")))
	block := &drctypes.BlockData{Epoch: 3, Round: 9, Author: x.id.String(), Payload: &drctypes.Payload{}}
	trialled := false
	start := time.Now()
	x.orderSubmittedControlWith(context.Background(), block, func(*drctypes.BlockData) error { trialled = true; return nil })
	require.Less(t, time.Since(start), 50*time.Millisecond)
	require.False(t, called, "no fetch on the consensus loop")
	require.False(t, trialled, "a submission without its witness is no candidate")
	require.Empty(t, block.Payload.PosControls)
	require.Equal(t, 1, x.posQueue.len(), "it waits for its prefetch")
}

func TestAnUnreachableSubmitterAddsNoLatencyToTheIntakeAndIsDropped(t *testing.T) {
	cms := submissionCMs(t)
	x := cms[1]
	x.params = &Parameters{LocalTimeout: 200 * time.Millisecond} // prefetch budget 100ms
	x.witnesses = func(ctx context.Context, _ [32]byte, _ []peer.ID, _ int) ([]byte, error) {
		<-ctx.Done() // accepts the stream and never answers
		return nil, ctx.Err()
	}
	c := retirement([]byte("never arrives"))
	start := time.Now()
	require.NoError(t, x.onPosControlSubmission(context.Background(), signed(t, cms[0], c)))
	require.Less(t, time.Since(start), 50*time.Millisecond, "the intake does not wait for the pull")
	require.Equal(t, 1, x.posQueue.len())
	require.Eventually(t, func() bool { return x.posQueue.len() == 0 }, 3*time.Second, 10*time.Millisecond,
		"a witness that cannot be had drops the submission")
	require.Zero(t, x.posPrefetching.Load())
}

func TestThePrefetchStoresTheWitnessWithinTheOpsBoundAndTheSubmissionBecomesACandidate(t *testing.T) {
	cms := submissionCMs(t)
	x := cms[1]
	witness := []byte("a storage proof")
	var bound atomic.Int64
	var asked atomic.Value
	x.witnesses = func(_ context.Context, h [32]byte, peers []peer.ID, maxBytes int) ([]byte, error) {
		bound.Store(int64(maxBytes))
		asked.Store(peers)
		return witness, nil
	}
	c := retirement(witness)
	require.NoError(t, x.onPosControlSubmission(context.Background(), signed(t, cms[0], c)))
	require.Eventually(t, func() bool { return x.blockStore.HasWitness(c.WitnessHash) }, 3*time.Second, 10*time.Millisecond)
	require.EqualValues(t, storage.MaxEVMWitnessBytes, bound.Load(), "a Retirement witness is bounded by the EVM proof bound, not the closure's")
	require.Equal(t, cms[0].id, asked.Load().([]peer.ID)[0], "the submitter is asked first")
	require.Equal(t, 1, x.posQueue.len())
	block := &drctypes.BlockData{Epoch: 3, Round: 9, Author: x.id.String(), Payload: &drctypes.Payload{}}
	x.orderSubmittedControlWith(context.Background(), block, func(*drctypes.BlockData) error { return nil })
	require.Len(t, block.Payload.PosControls, 1)

	// bytes that are not the committed witness are never stored, and the submission goes
	other := retirement([]byte("another proof"))
	x.witnesses = func(context.Context, [32]byte, []peer.ID, int) ([]byte, error) { return []byte("forged"), nil }
	require.NoError(t, x.onPosControlSubmission(context.Background(), signed(t, cms[0], other)))
	require.Eventually(t, func() bool { return x.posQueue.len() == 1 }, 3*time.Second, 10*time.Millisecond)
	require.False(t, x.blockStore.HasWitness(other.WitnessHash))
}

func TestWithoutAFetcherOrTheWitnessTheIntakeRefusesAndTheFetchesInFlightAreBounded(t *testing.T) {
	cms := submissionCMs(t)
	x := cms[1]
	x.witnesses = nil
	require.ErrorIs(t, x.onPosControlSubmission(context.Background(), signed(t, cms[0], retirement([]byte("w")))), ErrPosSubmission)
	require.Zero(t, x.posQueue.len())

	release := make(chan struct{})
	x.witnesses = func(ctx context.Context, _ [32]byte, _ []peer.ID, _ int) ([]byte, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("no")
	}
	x.params = &Parameters{LocalTimeout: 20 * time.Second}
	for i := 0; i < maxPosPrefetches; i++ {
		c := retirement([]byte{byte(i)})
		c.Data[95] = byte(i)
		signer := cms[2]
		if i >= maxPosSubmissionsPerSigner {
			signer = cms[3]
		}
		require.NoError(t, x.onPosControlSubmission(context.Background(), signed(t, signer, c)))
	}
	c := retirement([]byte("one too many"))
	require.ErrorIs(t, x.onPosControlSubmission(context.Background(), signed(t, cms[3], c)), ErrPosSubmission)
	close(release)
	require.Eventually(t, func() bool { return x.posPrefetching.Load() == 0 && x.posQueue.len() == 0 }, 3*time.Second, 10*time.Millisecond)
}
