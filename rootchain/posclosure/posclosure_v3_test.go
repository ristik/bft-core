package posclosure

import (
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

type witnessSource struct{ raw []byte }

func (s witnessSource) HandoffBundle(context.Context, uint64) (*handoffdelivery.Bundle, error) {
	return nil, handoffdelivery.ErrBundle // a V3 activation is not a V2 bundle (P85 run 22)
}
func (s witnessSource) ClosureWitness(context.Context, uint64) ([]byte, error) { return s.raw, nil }

// The mandatory CloseLiability after a Q3 handoff is built from a V3 witness, and the executor's verifier establishes the same closure
// from it: the V2 bundle path cannot represent the V3 body (P85 run 22: no closure witness, so no first block of epoch 2).
func TestAV3HandoffIsAClosureWitness(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	raw, err := handoffdelivery.EncodeWitnessV3(handoffdelivery.WitnessV3{Proof: f.Proof, Body: f.Body.Encode(), Snapshot: f.Snapshot, Candidate: f.Candidate})
	require.NoError(t, err)
	first := f.Snapshot.ShardInfo[0]
	conf, err := f.ShardConf.Hash(crypto.SHA256)
	require.NoError(t, err)
	hist := fixedHistory{old: f.Old, hash: conf, ids: []evmassign.Identity{testIdentity(1, 6), testIdentity(2, 1)}}
	auth := Authority{Verifier: handoffdelivery.ClosureVerifier{Partition: first.Partition, Shard: first.Shard, History: hist}}
	dep := storage.PosDeployment{RootNetwork: 5, Deployment: evmassign.Deployment{NetworkWord: [32]byte{1}, ChainID: [32]byte{31: 9}, Custody: [20]byte{19: 5}}}
	closed := f.Proof.Record.Epoch

	c, witness, err := Proposer{Source: witnessSource{raw}, Authority: auth, Deployment: dep}.Closure(closed, closed+1, 9)
	require.NoError(t, err)
	require.Equal(t, raw, witness)
	facts, err := auth.VerifyClosure(witness, closed)
	require.NoError(t, err)
	require.Equal(t, closed, facts.ClosedEpoch)
	require.Equal(t, f.Proof.Record.OrderedRound, facts.HRound)
	require.Equal(t, [32]byte(f.Proof.Record.ID()), facts.HRecordID)
	require.Equal(t, facts.BundleID, c.Close.BundleSemanticID)

	// each refusal differs from the control in one thing
	refuse := func(name string, w handoffdelivery.WitnessV3, epoch uint64) {
		t.Helper()
		bad, err := handoffdelivery.EncodeWitnessV3(w)
		require.NoError(t, err, name)
		_, err = auth.VerifyClosure(bad, epoch)
		require.ErrorIs(t, err, handoffdelivery.ErrClosure, name)
	}
	good := handoffdelivery.WitnessV3{Proof: f.Proof, Body: f.Body.Encode(), Snapshot: f.Snapshot, Candidate: f.Candidate}
	refuse("another closed epoch", good, closed+1)
	wrongBody := f.Body
	wrongBody.EarliestActivation++
	w := good
	w.Body = wrongBody.Encode()
	refuse("a body the record does not name", w, closed)
	w = good
	w.Candidate = []byte{1, 2, 3} // only the candidate binding sees it: the proof, body and checkpoint are the committed ones
	refuse("a candidate the body does not name", w, closed)
	w = good
	tampered := *f.Snapshot
	tampered.ShardInfo = append(tampered.ShardInfo[:0:0], f.Snapshot.ShardInfo...)
	// flip a bit of the committed hash: setting a fixed byte is a no-op for the 1 in 256 fixtures whose hash already starts with it (#776)
	tampered.ShardInfo[0].ShardConfHash = append([]byte(nil), f.Snapshot.ShardInfo[0].ShardConfHash...)
	tampered.ShardInfo[0].ShardConfHash[0] ^= 0xff
	require.NotEqual(t, f.Snapshot.ShardInfo[0].ShardConfHash, tampered.ShardInfo[0].ShardConfHash, "the tamper must change the committed hash")
	w.Snapshot = &tampered
	refuse("a checkpoint whose shard tree is not the committed one", w, closed)
	w = good
	w.Snapshot = nil
	refuse("no checkpoint", w, closed)
	w = good
	w.Body = []byte{1, 2, 3}
	refuse("an undecodable body", w, closed)
	// the same checkpoint and proof with the commit certificate unsigned: only the old committee's signatures distinguish it
	w = good
	unsigned := f.Proof
	qc := *f.Proof.CommitQC
	qc.Signatures, qc.SealSignatures = nil, nil
	unsigned.CommitQC = &qc
	snap := *f.Snapshot
	snapQC := *f.Snapshot.CommitQc
	snapQC.Signatures, snapQC.SealSignatures = nil, nil
	snap.CommitQc = &snapQC
	w.Proof, w.Snapshot = unsigned, &snap
	refuse("a commit certificate nobody signed", w, closed)
	w = good
	forged := f.Proof
	forged.Record.OrderedRound++
	w.Proof = forged
	refuse("a record the old committee did not sign", w, closed)
}
