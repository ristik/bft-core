package consensus

import (
	"bytes"
	"context"
	"crypto"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestQ3InstallRejectsFabricatedSupersession(t *testing.T) {
	for _, fabricated := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal coupled activation", true: "nothing pending"}[fabricated], func(t *testing.T) {
			opts := q3fixture.Options{Assignment: true}
			if fabricated {
				opts.MutateCandidate = func(c *evmassign.Candidate) {
					c.Supersedes = &evmassign.Supersession{SupersededH: make([]byte, 32), BaseRootEpoch: 1, BaseShardEpoch: 0, BaseActiveHash: make([]byte, 32), ChainLen: 1, ChainCommitment: make([]byte, 32)}
				}
			}
			f := q3fixture.New(t, opts)
			r := newQ3Replica(t, f, f.NewNodes[0])
			r.mustOpen(true)
			t.Cleanup(r.close)
			require.NoError(t, r.rt.Recover(context.Background()))
			err := r.rt.Activate(context.Background(), r.bundle())
			if !fabricated {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, storage.ErrSupersessionInvalid)
			require.ErrorIs(t, err, storage.ErrNothingToSupersede)
			require.ErrorIs(t, err, ErrQ3Candidate)
			_, err = r.trust.GetByEpoch(2)
			require.ErrorIs(t, err, tbstore.ErrNotFound)
			require.Nil(t, r.manager.epochAnchor)
			require.Error(t, r.rt.Admit(2))
		})
	}
}

// All evidence is committed by the proper old committee, including each isolated
// mutation. The install must reconstruct the pending chain rather than trusting it.
func TestSuccessiveCoupledSupersessionInstall(t *testing.T) {
	cases := map[string]func(*evmassign.Supersession){
		"valid":                 nil,
		"wrong H":               func(s *evmassign.Supersession) { s.SupersededH[0] ^= 1 },
		"wrong base root":       func(s *evmassign.Supersession) { s.BaseRootEpoch++ },
		"wrong base shard":      func(s *evmassign.Supersession) { s.BaseShardEpoch++ },
		"wrong base hash":       func(s *evmassign.Supersession) { s.BaseActiveHash[0] ^= 1 },
		"wrong commitment":      func(s *evmassign.Supersession) { s.ChainCommitment[0] ^= 1 },
		"wrong length":          func(s *evmassign.Supersession) { s.ChainLen++ },
		"omitted supersession":  nil,
		"missing retained link": nil,
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := q3fixture.New(t, q3fixture.Options{Assignment: true})
			r := newQ3Replica(t, f, f.NewNodes[0])
			r.mustOpen(true)
			t.Cleanup(r.close)
			require.NoError(t, r.rt.Recover(context.Background()))
			require.NoError(t, r.rt.Activate(context.Background(), r.bundle()))
			anchor := r.manager.epochAnchor
			_, err := r.manager.blockStore.Add(&rctypes.BlockData{Version: 2, Round: 7, Epoch: 2, Payload: &rctypes.Payload{Version: 2}, Anchor: anchor}, nil)
			require.NoError(t, err)
			first, err := r.manager.blockStore.Block(7)
			require.NoError(t, err)
			key := types.PartitionShardID{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}.Key()}
			pending := first.ShardState.States[key]
			require.EqualValues(t, 1, pending.TR.Epoch)
			require.EqualValues(t, 0, pending.IR.Epoch)
			configs, err := r.orchestration.ShardConfigs(7)
			require.NoError(t, err)
			chain, err := storage.CommittedChain(r.orchestration, key.PartitionID, types.ShardID{}, 0)
			require.NoError(t, err)
			binding, err := chain.Supersession()
			require.NoError(t, err)
			if mutate != nil {
				mutate(binding)
			}
			second := q3fixture.New(t, q3fixture.Options{After: f, Assignment: true, Installed: configs[key], ShardState: pending, MutateCandidate: func(c *evmassign.Candidate) {
				if name != "omitted supersession" {
					c.Supersedes = binding
				}
			}})
			if name == "missing retained link" {
				// A fresh block store with the same authenticated checkpoint and derived index
				// has no retained first candidate. The index alone is never authority.
				empty, dbErr := storage.NewBoltStorage(filepath.Join(t.TempDir(), "empty.db"))
				require.NoError(t, dbErr)
				t.Cleanup(func() { require.NoError(t, empty.Close()) })
				r.manager.blockStore, err = storage.NewFromState(crypto.SHA256, f.Snapshot, empty, r.orchestration, r.manager.log, storage.ProfileHandoff)
				require.NoError(t, err)
			}
			err = r.rt.Activate(context.Background(), q3active.Bundle{Envelope: second.EnvelopeBytes, Snapshot: second.Snapshot, Candidate: second.Candidate})
			if name == "valid" {
				require.NoError(t, err)
				require.NoError(t, r.rt.Admit(3))
				confs, err := r.orchestration.ShardConfigs(15)
				require.NoError(t, err)
				require.EqualValues(t, 2, confs[key].Epoch)
				r.restart()
				require.NoError(t, r.rt.Admit(3))
				require.EqualValues(t, 3, r.manager.epochAnchor.Epoch)
				// The retained pair reconstructs both links; the two-step profile admits no third transition, so the chain stops here.
				chain, err := storage.CommittedChain(r.orchestration, key.PartitionID, types.ShardID{}, 0)
				require.NoError(t, err)
				require.Len(t, chain.Steps, 2)
				require.ErrorIs(t, storage.CheckSupersessionChainLength(len(chain.Steps)), storage.ErrSupersessionChainTooLong)
				return
			}
			if name == "omitted supersession" {
				require.ErrorIs(t, err, storage.ErrAssignmentAckPending)
			} else {
				require.ErrorIs(t, err, storage.ErrSupersessionInvalid)
			}
			if name == "missing retained link" {
				require.ErrorIs(t, err, storage.ErrAssignmentHistory)
			}
			_, err = r.trust.GetByEpoch(3)
			require.ErrorIs(t, err, tbstore.ErrNotFound)
			require.Equal(t, anchor, r.manager.epochAnchor)
			require.Error(t, r.rt.Admit(3))
		})
	}
}

func runtimeRequestHistory(t *testing.T, r *q3Replica) *q3active.RequestHistory {
	t.Helper()
	h, err := r.rt.RequestHistory(q3active.RequestHistoryConfig{Candidates: r.manager.blockStore, Anchor: func(types.PartitionID, types.ShardID) (*types.PartitionDescriptionRecord, error) {
		return r.f.ShardConf, nil
	}, HashAlg: crypto.SHA256, Network: q3fixture.Network, Version: 1})
	require.NoError(t, err)
	return h
}

type substitutedCandidate []byte

func (c substitutedCandidate) HandoffCandidate([]byte) ([]byte, error) { return c, nil }

func TestRequestHistoryAuthenticatesBeforeFilteringShard(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
	c.activateAll()
	r := c.heavy()
	candidate, err := evmassign.DecodeCandidate(c.f.Candidate)
	require.NoError(t, err)
	successor, err := candidate.Successor()
	require.NoError(t, err)
	successor.PartitionID++
	candidate.Assignment, err = types.Cbor.Marshal(successor)
	require.NoError(t, err)
	preimage, err := candidate.Encode()
	require.NoError(t, err)
	h, err := r.rt.RequestHistory(q3active.RequestHistoryConfig{Candidates: substitutedCandidate(preimage), Anchor: func(types.PartitionID, types.ShardID) (*types.PartitionDescriptionRecord, error) {
		return c.f.ShardConf, nil
	}, HashAlg: crypto.SHA256, Network: q3fixture.Network, Version: 1})
	require.NoError(t, err)
	_, err = h.Chain(q3fixture.PartitionID, types.ShardID{})
	require.ErrorIs(t, err, q3active.ErrRequestHistory)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	require.False(t, bytes.Equal(preimage, c.f.Candidate))
}

func selectRuntimeRequestHistory(t *testing.T, r *q3Replica) *q3active.RequestHistory {
	t.Helper()
	h := runtimeRequestHistory(t, r)
	r.manager.irReqVerifier.SetRequestHistory(h)
	resolver, err := NewRequestViewResolver(h, crypto.SHA256, func(p types.PartitionID, s types.ShardID) (*storage.ShardInfo, []byte, *types.InputRecord, error) {
		state, err := r.manager.blockStore.GetState()
		if err != nil {
			return nil, nil, nil, err
		}
		id, err := state.CommittedHead.Block.Hash(crypto.SHA256)
		return r.manager.blockStore.ShardInfo(p, s), id, nil, err
	}, nil)
	require.NoError(t, err)
	r.manager.SetViewResolver(resolver)
	return h
}

// Selection is explicit test wiring before activation and on process startup.
// A real install must preserve it; signed weighted proofs then take the same
// collection/certification and follower execution paths across a durable restart.
func TestQ3InstallPreservesSelectedRequestHistory(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
	histories := make([]*q3active.RequestHistory, len(c.replicas))
	for i, r := range c.replicas {
		histories[i] = selectRuntimeRequestHistory(t, r)
	}
	anchor := c.activateAll()
	exercise := func(persist bool) {
		for i, r := range c.replicas {
			require.Same(t, histories[i], r.manager.irReqVerifier.RequestHistory())
			view, enabled, err := r.manager.RequestView(q3fixture.PartitionID, types.ShardID{})
			require.NoError(t, err)
			require.True(t, enabled)
			require.EqualValues(t, 9, view.TotalWeight())
			require.EqualValues(t, 5, view.Threshold())
			proof := func(heavy bool) *rctypes.IRChangeReq {
				tr := view.ExpectedTR()
				uc, err := view.PreviousUC()
				require.NoError(t, err)
				req := &rctypes.IRChangeReq{Partition: q3fixture.PartitionID, Shard: types.ShardID{}, CertReason: rctypes.Quorum}
				for _, id := range view.Context().NodeIDs() {
					w, err := view.SignerWeight(id)
					require.NoError(t, err)
					if (w == 6) != heavy {
						continue
					}
					bcr := &certification.BlockCertificationRequest{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}, NodeID: id, InputRecord: &types.InputRecord{
						Version: 1, Epoch: tr.Epoch, RoundNumber: tr.Round, PreviousHash: view.PreviousStateHash(), Hash: bytes.Repeat([]byte{0x81}, 32), BlockHash: bytes.Repeat([]byte{0x82}, 32), SummaryValue: []byte{3}, Timestamp: uc.UnicitySeal.Timestamp}}
					require.NoError(t, bcr.Sign(c.f.EVMSigners[id]))
					req.Requests = append(req.Requests, bcr)
				}
				return req
			}
			lights, heavy := proof(false), proof(true)
			_, err = r.manager.irReqVerifier.VerifyIRChangeReqView(view, lights)
			require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached)
			require.NoError(t, r.manager.bufferIRChange(heavy))
			block := func(req *rctypes.IRChangeReq) *rctypes.BlockData {
				return &rctypes.BlockData{Version: 2, Epoch: 2, Round: 7, Anchor: anchor, Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{req}}}
			}
			parent, err := r.manager.blockStore.Block(anchor.Slot)
			require.NoError(t, err)
			_, err = parent.Extend(block(lights), r.manager.irReqVerifier, r.orchestration, crypto.SHA256, r.manager.log)
			require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached)
			executed, err := parent.Extend(block(heavy), r.manager.irReqVerifier, r.orchestration, crypto.SHA256, r.manager.log)
			require.NoError(t, err)
			if persist {
				_, err = r.manager.blockStore.Add(block(heavy), r.manager.irReqVerifier)
				require.NoError(t, err)
			}
			shard := executed.ShardState.States[types.PartitionShardID{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}.Key()}]
			require.Equal(t, heavy.Requests[0].InputRecord, shard.IR, "each follower executes the signed heavy proof")
			require.EqualValues(t, 1, shard.IR.Epoch)
		}
	}
	exercise(false)
	for i, r := range c.replicas {
		r.close()
		r.mustOpen(true)
		histories[i] = selectRuntimeRequestHistory(t, r)
		require.NoError(t, r.rt.Recover(context.Background()))
		r.startConsensus()
	}
	exercise(true)
}
