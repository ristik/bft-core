package consensus

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/utb"
)

// A valid unsigned successor entry for epoch 2; the module signs the bytes it is given, so any valid entry will do.
func unsignedEntry(t *testing.T, salt byte) []byte {
	t.Helper()
	var members []utb.Member
	var nodes []*types.NodeInfo
	for i := 0; i < 4; i++ {
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{byte(i + 1)}, 32))
		require.NoError(t, err)
		v, _ := s.Verifier()
		pk, _ := v.MarshalPublicKey()
		nodes = append(nodes, &types.NodeInfo{NodeID: string(rune('a' + i)), SigKey: pk, Stake: 1})
		members = append(members, utb.Member{Key: pk, Weight: 1})
	}
	_ = nodes
	e := &types.RootTrustBaseV2{Version: 2, NetworkID: 5, Epoch: 2, EpochStart: 100, RootNodes: nodes, QuorumThreshold: 3,
		StateHash: bytes.Repeat([]byte{salt}, 32), PreviousEntryID: bytes.Repeat([]byte{9}, 32)}
	b, err := e.SigBytes()
	require.NoError(t, err)
	return b
}

type utbRig struct {
	*decisionRig
	scheme uint64
	entry  []byte
	calls  int
	srcErr error
	absent bool // the committed state holds no outgoing handoff
}

func newUTBRig(t *testing.T, scheme uint64) *utbRig {
	r := &utbRig{decisionRig: newDecisionRig(t), scheme: scheme}
	r.cfg.Scheme, r.cfg.UTB = scheme, true
	if scheme == votesig.SchemeLegacy {
		r.cfg.Genesis = [32]byte{}
	}
	r.entry = unsignedEntry(t, 0x22)
	return r
}

func (r *utbRig) source(withSource bool) SafetyOption {
	if !withSource {
		return func(*SafetyModule) {}
	}
	return WithUTB(func(c *drctypes.RoundInfo, epoch uint64) ([]byte, error) {
		r.calls++
		if r.srcErr != nil {
			return nil, r.srcErr
		}
		if r.absent {
			return nil, nil
		}
		return r.entry, nil
	})
}

func (r *utbRig) open(signer abcrypto.Signer, withSource bool) (*SafetyModule, storage.BoltDB) {
	r.closeDB()
	db, err := storage.NewBoltStorage(r.path, storage.WithNoSync())
	require.NoError(r.t, err)
	r.db = &db
	r.t.Cleanup(r.closeDB)
	m, err := NewSafetyModule(types.NetworkID(r.cfg.Network), "node1", signer, db,
		WithDomainBoundSigning(fixedSigning{cfg: r.cfg}, func(uint64) (CommittedBlockInfo, error) { return r.executed, nil }), r.source(withSource))
	require.NoError(r.t, err)
	return m, db
}

// both schemes: the endorsement is the voter's own signature over exactly the unsigned bytes, next to (independent of) the vote's signatures.
func TestCommittingVoteOfAUTBEpochCarriesTheEndorsement(t *testing.T) {
	for name, scheme := range map[string]uint64{"scheme 1": votesig.SchemeLegacy, "scheme 2": votesig.SchemeDomainBound} {
		t.Run(name, func(t *testing.T) {
			r := newUTBRig(t, scheme)
			m, db := r.open(r.signer, true)
			v, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.NoError(t, err)
			require.EqualValues(t, votesig.EnvelopeUTB, v.Envelope)
			require.NotNil(t, v.UTB)
			require.Equal(t, r.entry, []byte(v.UTB.Unsigned))
			ver, _ := r.signer.Verifier()
			require.NoError(t, ver.VerifyBytes(v.UTB.Signature, r.entry), "the endorsement is a signature over the unsigned entry bytes")
			if scheme == votesig.SchemeDomainBound {
				r.verifyVote(v)
				require.NotEqual(t, v.SealSignature, v.UTB.Signature, "a third, independent signature")
				require.NotEqual(t, v.Signature, v.UTB.Signature)
			} else {
				bs, _ := v.LedgerCommitInfo.SigBytes()
				require.NoError(t, ver.VerifyBytes(v.Signature, bs), "the scheme 1 signature over the seal bytes is unchanged")
			}
			d, err := db.Decision(storage.DecisionVote, 1, 5)
			require.NoError(t, err)
			require.NotNil(t, d, "the signed vote is recorded before it is returned")

			// the wire form is the version 3 envelope and round-trips
			raw, err := types.Cbor.Marshal(v)
			require.NoError(t, err)
			require.True(t, votesig.PeekEnvelopeUTB(raw))
			var back = *v
			back.Envelope, back.UTB = 0, nil
			require.NoError(t, types.Cbor.Unmarshal(raw, &back))
			require.EqualValues(t, votesig.EnvelopeUTB, back.Envelope)
			require.Equal(t, v.UTB, back.UTB)
		})
	}
}

func TestVotesWithoutAnOutgoingHandoffCarryNoEndorsementButStayInTheEnvelope(t *testing.T) {
	for name, scheme := range map[string]uint64{"scheme 1": votesig.SchemeLegacy, "scheme 2": votesig.SchemeDomainBound} {
		t.Run(name, func(t *testing.T) {
			r := newUTBRig(t, scheme)
			r.absent = true
			m, _ := r.open(r.signer, true)
			v, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.NoError(t, err)
			require.EqualValues(t, votesig.EnvelopeUTB, v.Envelope, "a UTB epoch's votes are all version 3")
			require.Nil(t, v.UTB)
			require.Equal(t, 1, r.calls)

			// a non-committing vote never asks for the entry
			r.calls = 0
			r.absent = false
			block, tc := r.nonCommittingBlock(8)
			v, err = m.MakeVote(block, hash32(2), nil, tc)
			require.NoError(t, err)
			require.EqualValues(t, votesig.EnvelopeUTB, v.Envelope)
			require.Nil(t, v.UTB)
			require.Zero(t, r.calls)
		})
	}
}

func TestNoEndorsementSourceMeansNoCommittingVote(t *testing.T) {
	for name, scheme := range map[string]uint64{"scheme 1": votesig.SchemeLegacy, "scheme 2": votesig.SchemeDomainBound} {
		t.Run(name, func(t *testing.T) {
			r := newUTBRig(t, scheme)
			m, db := r.open(r.signer, false)
			_, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.ErrorIs(t, err, ErrNoUTBSource)
			d, _ := db.Decision(storage.DecisionVote, 1, 5)
			require.Nil(t, d)

			r.srcErr = errors.New("handoff body not available")
			m, db = r.open(r.signer, true)
			_, err = m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.ErrorIs(t, err, ErrNotSafeToVote)
			d, _ = db.Decision(storage.DecisionVote, 1, 5)
			require.Nil(t, d, "fails closed: nothing signed or recorded")
		})
	}
}

// The endorsed entry is part of the one recorded statement: a restart returns the recorded message, and another entry for the same (epoch, round)
// is a second decision.
func TestEndorsedEntryIsPartOfTheDurableDecision(t *testing.T) {
	for name, scheme := range map[string]uint64{"scheme 1": votesig.SchemeLegacy, "scheme 2": votesig.SchemeDomainBound} {
		t.Run(name, func(t *testing.T) {
			r := newUTBRig(t, scheme)
			m, _ := r.open(r.signer, true)
			first, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.NoError(t, err)
			r.closeDB()

			restarted, _ := r.open(r.signer, true)
			again, err := restarted.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.NoError(t, err)
			require.Equal(t, first.UTB, again.UTB, "the recorded endorsement, not a fresh signature")
			require.Equal(t, first.Signature, again.Signature)

			r.entry = unsignedEntry(t, 0x44) // a different successor entry for the same committed round
			other, _ := r.open(r.signer, true)
			_, err = other.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.ErrorIs(t, err, storage.ErrDecisionConflict)

			// endorsing nothing after having endorsed is a different statement too
			r.absent = true
			none, _ := r.open(r.signer, true)
			_, err = none.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.ErrorIs(t, err, storage.ErrDecisionConflict)
		})
	}
}

// Nothing signed leaves the module that is not on disk: a failure while making the endorsement leaves no decision, and a crash after the record
// returns the recorded message on retry.
func TestEndorsementCrashSafety(t *testing.T) {
	for name, tc := range map[string]struct {
		scheme   uint64
		failFrom int // the SignBytes call that fails: the endorsement is the last one made
	}{"scheme 1": {votesig.SchemeLegacy, 2}, "scheme 2": {votesig.SchemeDomainBound, 3}} {
		t.Run(name, func(t *testing.T) {
			r := newUTBRig(t, tc.scheme)
			crashing := &crashingSigner{Signer: r.signer, failFrom: tc.failFrom}
			m, db := r.open(crashing, true)
			_, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.ErrorIs(t, err, errCrash)
			d, err := db.Decision(storage.DecisionVote, 1, 5)
			require.NoError(t, err)
			require.Nil(t, d, "the endorsement failed before the record: a retry is free")

			retry, _ := r.open(r.signer, true)
			v, err := retry.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
			require.NoError(t, err)
			require.NotNil(t, v.UTB)
		})
	}
	t.Run("crash after the record", func(t *testing.T) {
		r := newUTBRig(t, votesig.SchemeDomainBound)
		r.closeDB()
		db, err := storage.NewBoltStorage(r.path, storage.WithNoSync())
		require.NoError(t, err)
		r.db = &db
		t.Cleanup(r.closeDB)
		cs := &crashingStorage{BoltDB: db, failQc: true}
		m, err := NewSafetyModule(types.NetworkID(r.cfg.Network), "node1", r.signer, cs,
			WithDomainBoundSigning(fixedSigning{cfg: r.cfg}, func(uint64) (CommittedBlockInfo, error) { return r.executed, nil }), r.source(true))
		require.NoError(t, err)
		_, err = m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
		require.ErrorIs(t, err, errCrash)
		v, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
		require.NoError(t, err)
		require.NotNil(t, v.UTB, "the recorded message, endorsement included")
	})
}

// Epochs not configured for UTB keep their unchanged votes and never ask for an entry.
func TestVotesOutsideAUTBEpochAreUnchanged(t *testing.T) {
	r := newDecisionRig(t)
	calls := 0
	_, db := r.open(r.signer, r.scheme2())
	m, err := NewSafetyModule(types.NetworkID(r.cfg.Network), "node1", r.signer, db,
		WithDomainBoundSigning(r.scheme2(), func(uint64) (CommittedBlockInfo, error) { return r.executed, nil }),
		WithUTB(func(*drctypes.RoundInfo, uint64) ([]byte, error) { calls++; return []byte{1}, nil }))
	require.NoError(t, err)
	v, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.NoError(t, err)
	require.Zero(t, v.Envelope)
	require.Nil(t, v.UTB)
	require.Zero(t, calls)
	raw, _ := types.Cbor.Marshal(v)
	require.False(t, votesig.PeekEnvelopeUTB(raw))
}
