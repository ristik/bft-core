package abdrc

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/utb"
)

// utbFixture is dbFixture with epoch 2 activated as a UTB epoch (scheme 2) and an unsigned epoch-3 entry the four members endorse.
func utbFixture(t *testing.T) (*dbFixture, []byte) {
	f := newDBFixture(t)
	f.cfg.UTB = true
	f.activate(t, 2)
	return f, f.entry(t, 3, 5)
}

// entry is a valid unsigned version-2 entry for the epoch after the vote's, with the fixture's four members.
func (f *dbFixture) entry(t *testing.T, epoch, network uint64) []byte {
	var nodes []*types.NodeInfo
	for _, id := range f.ids {
		v, _ := f.signers[id].Verifier()
		k, _ := v.MarshalPublicKey()
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: k, Stake: 1})
	}
	e := &types.RootTrustBaseV2{Version: 2, NetworkID: types.NetworkID(network), Epoch: epoch, EpochStart: 100, RootNodes: nodes, QuorumThreshold: 3,
		StateHash: bytes.Repeat([]byte{0x22}, 32), PreviousEntryID: bytes.Repeat([]byte{9}, 32)}
	b, err := e.SigBytes()
	require.NoError(t, err)
	return b
}

func (f *dbFixture) utbVote(t *testing.T, author string, committing bool, entry []byte) *VoteMsg {
	v := f.voteV2(t, author, 2, 12, committing, f.legacyQC(t, 1, 11))
	if entry != nil {
		require.NoError(t, v.SignUTB(f.signers[author], entry))
	} else {
		v.Envelope = votesig.EnvelopeUTB
	}
	return v
}

func TestUTBVoteVerifiesAndRoundTrips(t *testing.T) {
	f, entry := utbFixture(t)
	for name, v := range map[string]*VoteMsg{"endorsing": f.utbVote(t, "1", true, entry), "committing without a handoff": f.utbVote(t, "1", true, nil), "non-committing": f.utbVote(t, "1", false, nil)} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, v.Verify(f.store))
			raw, err := types.Cbor.Marshal(v)
			require.NoError(t, err)
			require.True(t, votesig.PeekEnvelopeUTB(raw))
			var back VoteMsg
			require.NoError(t, types.Cbor.Unmarshal(raw, &back))
			require.EqualValues(t, votesig.EnvelopeUTB, back.Envelope)
			require.EqualValues(t, votesig.SchemeDomainBound, back.Scheme)
			require.Equal(t, v.UTB, back.UTB)
			require.NoError(t, back.Verify(f.store))
		})
	}
}

func TestUTBEnvelopeFollowsTheEpochConfigurationOnly(t *testing.T) {
	f, entry := utbFixture(t)
	t.Run("a version 2 vote in a UTB epoch", func(t *testing.T) {
		v := f.voteV2(t, "1", 2, 12, true, f.legacyQC(t, 1, 11))
		require.ErrorIs(t, v.Verify(f.store), votesig.ErrEnvelope)
	})
	t.Run("a version 3 vote outside a UTB epoch", func(t *testing.T) {
		g := newDBFixture(t)
		g.activate(t, 2) // scheme 2, not UTB
		v := g.voteV2(t, "1", 2, 12, true, g.legacyQC(t, 1, 11))
		require.NoError(t, v.SignUTB(g.signers["1"], entry))
		require.ErrorIs(t, v.Verify(g.store), votesig.ErrEnvelope)
		v.UTB, v.Envelope = nil, votesig.EnvelopeUTB
		require.ErrorIs(t, v.Verify(g.store), votesig.ErrEnvelope)
	})
	t.Run("an endorsement cannot be marshalled outside the envelope", func(t *testing.T) {
		v := f.utbVote(t, "1", true, entry)
		v.Envelope = 0
		_, err := types.Cbor.Marshal(v)
		require.ErrorIs(t, err, votesig.ErrEnvelope)
	})
	t.Run("a nested or foreign envelope version", func(t *testing.T) {
		v := f.utbVote(t, "1", true, entry)
		raw, _ := types.Cbor.Marshal(v)
		nested, err := types.Cbor.Marshal(voteV3Wire{Version: 3, Inner: raw})
		require.NoError(t, err)
		var back VoteMsg
		require.ErrorIs(t, types.Cbor.Unmarshal(nested, &back), votesig.ErrEnvelope)
		foreign := bytes.Clone(raw)
		foreign[1] = 0x04
		require.Error(t, types.Cbor.Unmarshal(foreign, &back))
	})
}

func TestUTBVoteNegatives(t *testing.T) {
	f, entry := utbFixture(t)
	check := func(name string, mut func(v *VoteMsg), want error) {
		t.Run(name, func(t *testing.T) {
			v := f.utbVote(t, "1", true, entry)
			mut(v)
			require.ErrorIs(t, v.Verify(f.store), want)
		})
	}
	check("on a non-committing vote", func(v *VoteMsg) {
		*v = *f.utbVote(t, "1", false, nil)
		require.NoError(t, v.SignUTB(f.signers["1"], entry))
	}, votesig.ErrUTB)
	check("another author's signature", func(v *VoteMsg) { v.UTB.Signature = f.utbVote(t, "2", true, entry).UTB.Signature }, votesig.ErrUTB)
	check("a signature over other bytes", func(v *VoteMsg) { v.UTB.Signature = f.utbVote(t, "1", true, f.entry(t, 3, 6)).UTB.Signature }, votesig.ErrUTB)
	check("the vote's own signature as the endorsement", func(v *VoteMsg) { v.UTB.Signature = v.Signature }, votesig.ErrUTB)
	check("the seal signature as the endorsement", func(v *VoteMsg) { v.UTB.Signature = v.SealSignature }, votesig.ErrUTB)
	check("a short signature", func(v *VoteMsg) { v.UTB.Signature = v.UTB.Signature[:40] }, votesig.ErrUTB)
	check("another network's entry", func(v *VoteMsg) { *v = *f.utbVote(t, "1", true, f.entry(t, 3, 6)) }, votesig.ErrUTB)
	check("an entry of the wrong epoch", func(v *VoteMsg) { *v = *f.utbVote(t, "1", true, f.entry(t, 4, 5)) }, votesig.ErrUTB)
	check("the voting epoch's own entry", func(v *VoteMsg) { *v = *f.utbVote(t, "1", true, f.entry(t, 2, 5)) }, votesig.ErrUTB)
	check("garbage as the entry", func(v *VoteMsg) { *v = *f.utbVote(t, "1", true, []byte{1, 2, 3}) }, votesig.ErrUTB)
	check("a signed entry instead of the unsigned bytes", func(v *VoteMsg) {
		e, err := utb.DecodeUnsigned(entry)
		require.NoError(t, err)
		require.NoError(t, e.Sign("1", f.signers["1"]))
		signed, err := e.MarshalCBOR()
		require.NoError(t, err)
		*v = *f.utbVote(t, "1", true, signed)
	}, votesig.ErrUTB)
}

// qcFrom aggregates the votes the way the register does.
func (f *dbFixture) utbQC(t *testing.T, authors []string, committing bool, entry []byte) *drctypes.QuorumCert {
	var qc *drctypes.QuorumCert
	for _, a := range authors {
		v := f.utbVote(t, a, committing, entry)
		if qc == nil {
			qc = drctypes.NewQuorumCertificateFromVote(v.VoteInfo, v.LedgerCommitInfo, map[string]hex.Bytes{})
			qc.Scheme, qc.Envelope = votesig.SchemeDomainBound, votesig.EnvelopeUTB
			if committing {
				qc.SealSignatures = map[string]hex.Bytes{}
			}
			if entry != nil {
				qc.UTB = &drctypes.UTBCertificate{Unsigned: entry, Signatures: map[string]hex.Bytes{}}
			}
		}
		qc.Signatures[a] = v.Signature
		if committing {
			qc.SealSignatures[a] = v.SealSignature
		}
		if entry != nil {
			qc.UTB.Signatures[a] = v.UTB.Signature
		}
	}
	return qc
}

func TestUTBCertificateVerifiesAndRoundTrips(t *testing.T) {
	f, entry := utbFixture(t)
	for name, qc := range map[string]*drctypes.QuorumCert{
		"endorsing":                    f.utbQC(t, []string{"1", "2", "3"}, true, entry),
		"all four":                     f.utbQC(t, []string{"1", "2", "3", "4"}, true, entry),
		"committing without a handoff": f.utbQC(t, []string{"1", "2", "3"}, true, nil),
		"non-committing":               f.utbQC(t, []string{"1", "2", "3"}, false, nil),
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, qc.VerifyWith(f.store))
			raw, err := types.Cbor.Marshal(qc)
			require.NoError(t, err)
			require.True(t, votesig.PeekEnvelopeUTB(raw))
			var back drctypes.QuorumCert
			require.NoError(t, types.Cbor.Unmarshal(raw, &back))
			require.EqualValues(t, votesig.EnvelopeUTB, back.Envelope)
			require.Equal(t, qc.UTB, back.UTB)
			require.NoError(t, back.VerifyWith(f.store))
		})
	}
}

func TestUTBCertificateNegatives(t *testing.T) {
	f, entry := utbFixture(t)
	check := func(name string, mut func(qc *drctypes.QuorumCert), want error) {
		t.Run(name, func(t *testing.T) {
			qc := f.utbQC(t, []string{"1", "2", "3"}, true, entry)
			mut(qc)
			require.ErrorIs(t, qc.VerifyWith(f.store), want)
		})
	}
	check("a missing endorsement signer", func(qc *drctypes.QuorumCert) { delete(qc.UTB.Signatures, "3") }, votesig.ErrSignerSets)
	check("an endorsement by a non-voter", func(qc *drctypes.QuorumCert) {
		qc.UTB.Signatures["4"] = f.utbVote(t, "4", true, entry).UTB.Signature
		delete(qc.UTB.Signatures, "3")
	}, votesig.ErrSignerSets)
	check("one invalid endorsement among a quorum", func(qc *drctypes.QuorumCert) {
		qc.UTB.Signatures["3"] = f.utbVote(t, "3", true, f.entry(t, 3, 6)).UTB.Signature
	}, votesig.ErrUTB)
	t.Run("one invalid endorsement is refused even when the others exceed the threshold", func(t *testing.T) {
		qc := f.utbQC(t, []string{"1", "2", "3", "4"}, true, entry)
		qc.UTB.Signatures["4"] = f.utbVote(t, "4", true, f.entry(t, 3, 6)).UTB.Signature
		require.ErrorIs(t, qc.VerifyWith(f.store), votesig.ErrUTB)
	})
	t.Run("a properly endorsed entry of the wrong epoch or network", func(t *testing.T) {
		for name, e := range map[string][]byte{"epoch": f.entry(t, 4, 5), "network": f.entry(t, 3, 6), "voting epoch": f.entry(t, 2, 5)} {
			qc := f.utbQC(t, []string{"1", "2", "3"}, true, e)
			require.ErrorIs(t, qc.VerifyWith(f.store), votesig.ErrUTB, name)
		}
	})
	check("endorsements by the wrong members", func(qc *drctypes.QuorumCert) {
		qc.UTB.Signatures["1"], qc.UTB.Signatures["2"] = qc.UTB.Signatures["2"], qc.UTB.Signatures["1"]
	}, votesig.ErrUTB)
	check("another entry than the one endorsed", func(qc *drctypes.QuorumCert) { qc.UTB.Unsigned = f.entry(t, 3, 6) }, votesig.ErrUTB)
	check("an entry of the wrong epoch", func(qc *drctypes.QuorumCert) { qc.UTB.Unsigned = f.entry(t, 4, 5) }, votesig.ErrUTB)
	check("garbage as the entry", func(qc *drctypes.QuorumCert) { qc.UTB.Unsigned = []byte{1} }, votesig.ErrUTB)
	check("an endorsement on a non-committing certificate", func(qc *drctypes.QuorumCert) {
		*qc = *f.utbQC(t, []string{"1", "2", "3"}, false, nil)
		qc.UTB = &drctypes.UTBCertificate{Unsigned: entry, Signatures: map[string]hex.Bytes{"1": nil, "2": nil, "3": nil}}
	}, votesig.ErrUTB)
	check("a version 1/2 certificate in a UTB epoch", func(qc *drctypes.QuorumCert) { qc.Envelope, qc.UTB = 0, nil }, votesig.ErrEnvelope)
	t.Run("a version 3 certificate outside a UTB epoch", func(t *testing.T) {
		g := newDBFixture(t)
		g.activate(t, 2)
		qc := f.utbQC(t, []string{"1", "2", "3"}, true, entry)
		require.ErrorIs(t, qc.VerifyWith(g.store), votesig.ErrEnvelope)
	})
	t.Run("a duplicate endorsement signer is refused at decode", func(t *testing.T) {
		qc := f.utbQC(t, []string{"1", "2", "3"}, true, entry)
		raw, err := types.Cbor.Marshal(qc)
		require.NoError(t, err)
		sig := qc.UTB.Signatures["1"]
		one := append([]byte{0xa1, 0x61, '1', 0x58, byte(len(sig))}, sig...)
		// find the endorsement map (3 entries) and replace its first entry's key with the second's: a duplicate key
		two := append([]byte{0x61, '2', 0x58, byte(len(sig))}, qc.UTB.Signatures["2"]...)
		i := bytes.Index(raw, append([]byte{0xa3, 0x61, '1', 0x58, byte(len(sig))}, sig...))
		require.Positive(t, i)
		forged := bytes.Clone(raw)
		forged[i+2] = '2'
		_ = one
		_ = two
		var back drctypes.QuorumCert
		require.ErrorIs(t, types.Cbor.Unmarshal(forged, &back), votesig.ErrUTB)
	})
}
