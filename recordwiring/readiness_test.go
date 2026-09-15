package recordwiring_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/recordwiring"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/shardnode"
)

type readinessTrust []*types.RootTrustBaseV1

func (m readinessTrust) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	for _, tb := range m {
		if tb.GetEpoch() == epoch {
			return tb, nil
		}
	}
	return nil, fmt.Errorf("unknown root epoch %d", epoch)
}

func TestReadinessReverifiesDurableRecordAndExactObservedContinuity(t *testing.T) {
	h := newCaptureHarness(t, 2)
	h.publish(0, 1)
	h.exec.set(h.c.Blocks[1])
	source, sourceTR := h.c.Certificate(1)
	state := bytes.Clone(source.InputRecord.Hash)
	quietTR := &certification.TechnicalRecord{Round: 7, Epoch: source.InputRecord.Epoch, Leader: "leader",
		StatHash: bytes.Repeat([]byte{0xa1}, 32), FeeHash: bytes.Repeat([]byte{0xa2}, 32)}
	quietIR := &types.InputRecord{Version: 1, RoundNumber: sourceTR.Round, Epoch: source.InputRecord.Epoch,
		PreviousHash: state, Hash: state, SummaryValue: []byte{}, Timestamp: source.InputRecord.Timestamp + 1}
	quiet := h.c.Certify(h.c.Signer, quietIR, quietTR, source.GetRootRoundNumber()+1)

	obs, err := recordwiring.NewObservations(recordwiring.DefaultObservationLimits)
	require.NoError(t, err)
	require.NoError(t, obs.Observe(source, sourceTR))
	require.NoError(t, obs.Observe(quiet, quietTR))
	r, err := recordwiring.NewReadiness(h.d, h.store, h.exec, obs)
	require.NoError(t, err)
	p, err := r.Prepare(context.Background(), quiet)
	require.NoError(t, err)
	require.True(t, p.Valid())
	require.NoError(t, r.Revalidate(context.Background(), p, quiet))
	foreignObs, err := recordwiring.NewObservations(recordwiring.DefaultObservationLimits)
	require.NoError(t, err)
	require.NoError(t, foreignObs.Observe(source, sourceTR))
	require.NoError(t, foreignObs.Observe(quiet, quietTR))
	foreign, err := recordwiring.NewReadiness(h.d, h.store, h.exec, foreignObs)
	require.NoError(t, err)
	require.ErrorIs(t, foreign.Revalidate(context.Background(), p, quiet), recordwiring.ErrReadinessUnavailable,
		"equal store, executor, held certificate and observation version do not make another owner authoritative")
	mutated := *quiet
	mutatedIR := *quiet.InputRecord
	mutatedIR.Timestamp++
	mutated.InputRecord = &mutatedIR
	require.ErrorIs(t, r.Revalidate(context.Background(), p, &mutated), recordwiring.ErrReadinessUnavailable)

	// An authenticated certificate at the same round/state but naming a different block is not the
	// terminal statement this process observed. State equality cannot manufacture continuity.
	conflictIR := *quietIR
	conflictIR.PreviousHash = bytes.Repeat([]byte{0x44}, 32)
	conflictIR.Hash = state
	conflictIR.BlockHash = bytes.Repeat([]byte{0xcc}, 32)
	conflict := h.c.Certify(h.c.Signer, &conflictIR, quietTR, quiet.GetRootRoundNumber()+1)
	_, err = r.Prepare(context.Background(), conflict)
	require.ErrorIs(t, err, recordwiring.ErrContinuity)

	// A newer durable head invalidates the prepared result even if B's old record remains retained.
	h.publish(2)
	h.exec.set(h.c.Blocks[2])
	require.ErrorIs(t, r.Revalidate(context.Background(), p, quiet), recordwiring.ErrReadinessUnavailable)
}

func TestReadinessAuthenticatesThenRefusesAContinuityTailOutsideThePinnedRootEpoch(t *testing.T) {
	h := newCaptureHarness(t, 1)
	tb1, tb2 := *h.c.TrustBase, *h.c.TrustBase
	tb1.Epoch, tb2.Epoch = 1, 2
	cfg, genesisExec := configFor(t, h.c)
	cfg.TrustBases = readinessTrust{&tb1, &tb2}
	d, err := recordwiring.NewDeployment(context.Background(), cfg, genesisExec)
	require.NoError(t, err)
	source, sourceTR := h.c.Certificate(1)
	b := h.c.Blocks[1]
	require.NoError(t, h.store.Publish(context.Background(), d.StoreContext(), certifiedstore.Record{
		BlockHash: b.Hash, BlockNumber: b.Number, StateRoot: b.StateRoot, PartitionRound: b.Round,
		Certificate: source, Technical: sourceTR, Witness: b.Evidence,
	}))
	h.exec.set(b)
	state := bytes.Clone(source.InputRecord.Hash)
	tr := &certification.TechnicalRecord{Round: sourceTR.Round + 1, Epoch: 0, Leader: "leader",
		StatHash: bytes.Repeat([]byte{0xa1}, 32), FeeHash: bytes.Repeat([]byte{0xa2}, 32)}
	ir := &types.InputRecord{Version: 1, RoundNumber: sourceTR.Round, Epoch: 0,
		PreviousHash: state, Hash: state, SummaryValue: []byte{}, Timestamp: 2}
	held := h.c.Certify(h.c.Signer, ir, tr, source.GetRootRoundNumber()+1)
	var nodeID string
	for id := range held.UnicitySeal.Signatures {
		nodeID = id
	}
	held.UnicitySeal.Epoch, held.UnicitySeal.Signatures = 2, nil
	require.NoError(t, held.UnicitySeal.Sign(nodeID, h.c.Signer), "premise: epoch-2 certificate is genuinely signed")

	obs, err := recordwiring.NewObservations(recordwiring.DefaultObservationLimits)
	require.NoError(t, err)
	require.NoError(t, obs.Observe(source, sourceTR))
	require.NoError(t, obs.Observe(held, tr))
	r, err := recordwiring.NewReadiness(d, h.store, h.exec, obs)
	require.NoError(t, err)
	_, err = r.Prepare(context.Background(), held)
	require.ErrorIs(t, err, recordwiring.ErrContinuity)
	require.ErrorContains(t, err, "root epoch 2")
}

func TestGenesisPublicationRequiresRealConfigurationBoundCertification(t *testing.T) {
	h := newCaptureHarness(t, 1)
	genesis, tr := h.c.Certificate(0)
	require.Equal(t, h.c.Blocks[0].Evidence, h.d.GenesisEvidence())
	h.exec.set(h.c.Blocks[1])
	err := recordwiring.PublishGenesis(context.Background(), h.store, h.d, h.exec, h.gate, genesis, tr)
	require.ErrorIs(t, err, recordwiring.ErrReadinessUnavailable)
	_, err = h.store.Load(context.Background(), h.d.StoreContext())
	require.ErrorIs(t, err, certifiedstore.ErrNoRecord, "an executor that advanced cannot acquire a genesis record")
	h.exec.set(h.c.Blocks[0])
	require.NoError(t, recordwiring.PublishGenesis(context.Background(), h.store, h.d, h.exec, h.gate, genesis, tr))
	h.exec.set(h.c.Blocks[0])
	obs, err := recordwiring.NewObservations(recordwiring.DefaultObservationLimits)
	require.NoError(t, err)
	require.NoError(t, obs.Observe(genesis, tr))
	r, err := recordwiring.NewReadiness(h.d, h.store, h.exec, obs)
	require.NoError(t, err)
	p, err := r.Prepare(context.Background(), genesis)
	require.NoError(t, err)
	require.True(t, p.Valid())

	nilState := *genesis
	nilIR := *genesis.InputRecord
	nilIR.Hash, nilIR.PreviousHash = nil, nil
	nilState.InputRecord = &nilIR
	require.ErrorIs(t, recordwiring.PublishGenesis(context.Background(), h.store, h.d, h.exec, h.gate, &nilState, tr), recordwiring.ErrGenesisCertificate,
		"the current root initial UC is not repaired into registry genesis certification")

	blockNaming := *genesis
	blockIR := *genesis.InputRecord
	blockIR.BlockHash = bytes.Repeat([]byte{1}, 32)
	blockNaming.InputRecord = &blockIR
	require.ErrorIs(t, recordwiring.PublishGenesis(context.Background(), h.store, h.d, h.exec, h.gate, &blockNaming, tr), recordwiring.ErrGenesisCertificate)
}

func TestGenesisPreparationAppliesE1ThroughE4(t *testing.T) {
	for _, tc := range []struct {
		name       string
		heldRound  uint64
		authorized uint64
		want       error
	}{
		{"initial timeout authorizes round 4", 0, 4, nil},
		{"E1 refuses installation round zero", 0, 0, registryproof.ErrGenesisInstallation},
		{"E2 requires held round below authorization", 2, 2, registryproof.ErrNotGenesisHistory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCaptureHarness(t, 1)
			state := h.d.GenesisState().Bytes()
			ir := &types.InputRecord{Version: 1, RoundNumber: tc.heldRound, Epoch: 0,
				PreviousHash: state, Hash: state, SummaryValue: []byte{}, Timestamp: 1}
			tr := &certification.TechnicalRecord{Round: tc.authorized, Epoch: 0, Leader: "leader",
				StatHash: bytes.Repeat([]byte{0xa1}, 32), FeeHash: bytes.Repeat([]byte{0xa2}, 32)}
			uc := h.c.Certify(h.c.Signer, ir, tr, 10+tc.heldRound)
			require.NoError(t, recordwiring.PublishGenesis(context.Background(), h.store, h.d, h.exec, h.gate, uc, tr))
			loaded, err := h.store.Load(context.Background(), h.d.StoreContext())
			require.NoError(t, err)
			fields := loaded.Snapshot().Fields()
			require.True(t, fields.Genesis)
			require.EqualValues(t, 0, fields.RoundAuthorized, "E4 uses the verified record, not a caller assertion")
			require.EqualValues(t, 0, fields.CertifiedRound)
			require.EqualValues(t, 0, loaded.BlockNumber(), "E3 is the exact verified block zero")

			obs, err := recordwiring.NewObservations(recordwiring.DefaultObservationLimits)
			require.NoError(t, err)
			require.NoError(t, obs.Observe(uc, tr))
			r, err := recordwiring.NewReadiness(h.d, h.store, h.exec, obs)
			require.NoError(t, err)
			p, err := r.Prepare(context.Background(), uc)
			if tc.want == nil {
				require.NoError(t, err)
				require.True(t, p.Valid())
			} else {
				require.ErrorIs(t, err, tc.want)
				require.False(t, p.Valid())
			}
		})
	}
}

func TestObservationsRejectUnboundAndBoundMemory(t *testing.T) {
	h := newCaptureHarness(t, 1)
	uc, tr := h.c.Certificate(0)
	obs, err := recordwiring.NewObservations(recordwiring.ObservationLimits{MaxCertificates: 1, MaxBytes: 1 << 20})
	require.NoError(t, err)
	bad := *tr
	bad.Round++
	require.ErrorIs(t, obs.Observe(uc, &bad), recordwiring.ErrContinuity)
	require.NoError(t, obs.Observe(uc, tr))
	// Exact redelivery is idempotent and remains representable under a one-entry bound.
	require.NoError(t, obs.Observe(uc, tr))

	_, err = recordwiring.NewObservations(recordwiring.ObservationLimits{})
	require.ErrorIs(t, err, recordwiring.ErrObservationBound)
	_ = shardnode.DefaultAnchorEvidenceLimits // pins the shared 512/1MiB profile in this composition test.
}
