package consensus

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// #1319: the leader orders the PoP request of the committed opening's intent once, and attaches to an Expired rejection the miss
// certificates it holds that alone reach the quorum, before the same rejection without them.

func TestOrderPoPRequestOncePerIntent(t *testing.T) {
	w := newVRWorld(t)
	o := opening(w.d, 0, 30, 20, true)
	v := &vrHandoff{svc: vrschedule.NewService(vrschedule.ServiceConfig{Self: "x"}), opening: func() (storage.VROpening, bool, error) { return o, true, nil }}
	x := vrManager(v)
	trialErr := error(nil)
	trial := func(*rctypes.BlockData) error { return trialErr }
	requests := func(b *rctypes.BlockData) [][32]byte {
		var out [][32]byte
		for _, c := range b.Payload.PosControls {
			if c.Op == rctypes.OpPoPRequest {
				out = append(out, c.Request.IntentDigest)
			}
		}
		return out
	}
	block := func() *rctypes.BlockData { return &rctypes.BlockData{Epoch: 1, Round: 40, Payload: &rctypes.Payload{}} }

	b := block()
	x.orderPoPRequestWith(context.Background(), b, trial)
	require.Equal(t, [][32]byte{w.d}, requests(b))
	require.Equal(t, uint64(40), b.Payload.PosControls[0].OrderingRound)

	trialErr = errors.New("refused")
	b = block()
	x.orderPoPRequestWith(context.Background(), b, trial)
	require.Empty(t, requests(b), "a refused trial orders nothing")
	trialErr = nil

	r, err := vrschedule.PoPRequestOf(w.in, w.d, 1)
	require.NoError(t, err)
	o.State.Request = &r
	b = block()
	x.orderPoPRequestWith(context.Background(), b, trial)
	require.Empty(t, requests(b), "the intent's request is committed")
	o.State.Request = nil

	o.IntentOK = false
	b = block()
	x.orderPoPRequestWith(context.Background(), b, trial)
	require.Empty(t, requests(b), "no derivable intent")
	o.IntentOK = true

	b = block()
	b.Payload.HandoffRecords = [][]byte{{1}}
	x.orderPoPRequestWith(context.Background(), b, trial)
	require.Empty(t, requests(b), "a handoff record is ordered")
}

func TestARejectionCarriesTheCertificatesThatStandAlone(t *testing.T) {
	w := newVRWorld(t)
	r, err := vrschedule.PoPRequestOf(w.in, w.d, 1)
	require.NoError(t, err)
	r.Deadline = 100
	svc := vrschedule.NewService(vrschedule.ServiceConfig{Self: "x"})
	c := w.committed(0)
	c.Request, c.Progress, c.ProgressOK = &r, 5, true
	svc.Update(c)
	digest, err := r.Digest()
	require.NoError(t, err)
	state := func(i, id uint64) {
		msg, err := vrschema.MissStatementBytes(digest, id)
		require.NoError(t, err)
		sig, err := w.Members[i].RK.Signer.SignBytes(msg)
		require.NoError(t, err)
		o, err := svc.OfferMiss(w.Members[i].Root, vrschedule.MissMessage{Request: digest, StakingID: id, Sig: sig})
		require.NoError(t, err)
		require.Equal(t, vrschedule.Retained, o)
	}
	for _, i := range []uint64{1, 2, 4} {
		state(i, 3) // quorum 3 of the four incumbents
	}
	state(1, 5) // short of it

	o := opening(w.d, 0, 30, 20, true)
	o.State.Request = &r
	v := &vrHandoff{svc: svc, opening: func() (storage.VROpening, bool, error) { return o, true, nil }}
	x := vrManager(v)
	tb := &types.RootTrustBaseV1{Epoch: 1}
	for i := uint64(1); i <= 4; i++ {
		tb.RootNodes = append(tb.RootNodes, &types.NodeInfo{NodeID: w.Members[i].Root, SigKey: w.Members[i].RK.Pub, Stake: 1})
	}
	x.trustBase.Store(tb)

	expired := rctypes.PosControl{Registry: true, Op: rctypes.OpRejectResult, Reject: &rctypes.RejectContext{Attempt: r.Attempt},
		Data: vrschema.OutputRejected{ResultID: w.R, Reason: vrschema.RejExpired, ReadyBitmap: 0b0111}.Encode()}
	got, extra := x.withMissCertificates([]rctypes.PosControl{expired})
	require.Equal(t, 1, extra)
	require.Len(t, got, 2, "with the certificates first, then the ordinary rejection")
	require.Len(t, got[0].Reject.Misses, 1)
	require.EqualValues(t, 3, got[0].Reject.Misses[0].StakingID)
	require.Len(t, got[0].Reject.Misses[0].Sigs, 3)
	require.Nil(t, got[1].Reject.Misses)
	require.Nil(t, expired.Reject.Misses, "the candidate itself is unchanged")

	other := expired
	other.Reject = &rctypes.RejectContext{Attempt: r.Attempt + 1}
	got, _ = x.withMissCertificates([]rctypes.PosControl{other})
	require.Len(t, got, 1, "another attempt than the request's")
	invalidated := expired
	invalidated.Data = vrschema.OutputRejected{ResultID: w.R, Reason: vrschema.RejInvalidated}.Encode()
	got, _ = x.withMissCertificates([]rctypes.PosControl{invalidated})
	require.Len(t, got, 1, "not an expiry")
	x.trustBase.Store(&types.RootTrustBaseV1{Epoch: 2, RootNodes: tb.RootNodes})
	got, _ = x.withMissCertificates([]rctypes.PosControl{expired})
	require.Len(t, got, 1, "a committee of another epoch than the request's")
}

// #1319 review P3-5 and P3-1: the leader keeps the signers the trust base recognizes with a valid statement and judges the quorum on what
// is left (one stale key does not cost the certificate), against the larger of the trust base's own threshold and Threshold(total).
func TestTheLeaderTrimsUnknownSignersAndUsesTheTrustBaseThreshold(t *testing.T) {
	w := newVRWorld(t)
	r, err := vrschedule.PoPRequestOf(w.in, w.d, 1)
	require.NoError(t, err)
	r.Deadline = 100
	svc := vrschedule.NewService(vrschedule.ServiceConfig{Self: "x"})
	c := w.committed(0)
	c.Request, c.Progress, c.ProgressOK = &r, 5, true
	svc.Update(c)
	digest, err := r.Digest()
	require.NoError(t, err)
	for i := uint64(1); i <= 4; i++ {
		msg, err := vrschema.MissStatementBytes(digest, 3)
		require.NoError(t, err)
		sig, err := w.Members[i].RK.Signer.SignBytes(msg)
		require.NoError(t, err)
		o, err := svc.OfferMiss(w.Members[i].Root, vrschedule.MissMessage{Request: digest, StakingID: 3, Sig: sig})
		require.NoError(t, err)
		require.Equal(t, vrschedule.Retained, o)
	}
	o := opening(w.d, 0, 30, 20, true)
	o.State.Request = &r
	x := vrManager(&vrHandoff{svc: svc, opening: func() (storage.VROpening, bool, error) { return o, true, nil }})
	tb := &types.RootTrustBaseV1{Epoch: 1}
	for i := uint64(1); i <= 4; i++ {
		key := w.Members[i].RK.Pub
		if i == 4 {
			key = w.Members[5].RK.Pub // a key the trust base holds for root 4 that did not sign
		}
		tb.RootNodes = append(tb.RootNodes, &types.NodeInfo{NodeID: w.Members[i].Root, SigKey: key, Stake: 1})
	}
	x.trustBase.Store(tb)
	ms := x.vrMissCertificates(w.R, r.Attempt)
	require.Len(t, ms, 1, "the certificate survives without the stale signer")
	require.Len(t, ms[0].Sigs, 3)
	tb.QuorumThreshold = 4
	require.Empty(t, x.vrMissCertificates(w.R, r.Attempt), "three signers are below the trust base's own threshold 4")
}
