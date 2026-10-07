package storage

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// fakeV3 is a V3FreezeRules over opaque body bytes, so the storage rules are tested apart from the q3format codec (whose own tests build on
// this package). It records what the receipt gate was asked.
type fakeV3 struct {
	bodies      map[string]V3Body
	receiptsErr error
	asked       []struct {
		body, receipts, candidate []byte
		attempt                   uint64
	}
}

func (f *fakeV3) VerifyBody(raw []byte) (V3Body, error) {
	b, ok := f.bodies[string(raw)]
	if !ok {
		return V3Body{}, errors.New("unknown body")
	}
	return b, nil
}

func (f *fakeV3) Prior(network, epoch, version uint64, identity []byte) ([]byte, error) {
	h := sha256.Sum256(append([]byte{byte(network), byte(epoch), byte(version)}, identity...))
	return h[:], nil
}

func (f *fakeV3) VerifyReceipts(body, receipts []byte, attempt uint64, candidate []byte) error {
	f.asked = append(f.asked, struct {
		body, receipts, candidate []byte
		attempt                   uint64
	}{body, receipts, candidate, attempt})
	return f.receiptsErr
}

type v3Freeze struct {
	auth      *v1HandoffAuthority
	rules     *fakeV3
	signers   map[string]abcrypto.Signer
	tb        *types.RootTrustBaseV1
	predec    []byte
	rawBody   []byte
	body      V3Body
	candidate []byte
	parent    []byte
}

func newV3Freeze(t *testing.T) *v3Freeze {
	t.Helper()
	signers := map[string]abcrypto.Signer{}
	for _, id := range []string{"old-a", "old-b", "old-c", "old-d"} {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		signers[id] = s
	}
	tb := testtrustbase.NewTrustBaseFromSigners(t, signers).(*types.RootTrustBaseV1)
	predec, err := tb.Hash(crypto.SHA256)
	require.NoError(t, err)
	f := &v3Freeze{rules: &fakeV3{bodies: map[string]V3Body{}}, signers: signers, tb: tb, predec: predec,
		rawBody: []byte("v3-body"), candidate: bytes.Repeat([]byte{4}, 32), parent: bytes.Repeat([]byte{5}, 32)}
	link, err := f.rules.Prior(5, 1, 1, predec)
	require.NoError(t, err)
	f.body = V3Body{ID: sha256.Sum256(f.rawBody), Network: 5, Epoch: 2, EarliestActivation: 7, StateSummary: bytes.Repeat([]byte{3}, 32),
		ChangeRecordHash: evmroot.D4CandidateContextHash(5, predec, 0, f.candidate, 7), PredecessorHash: link}
	f.rules.bodies[string(f.rawBody)] = f.body
	f.auth = &v1HandoffAuthority{trust: tb, predecessor: predec, priorVersion: 1, v3: f.rules}
	return f
}

func (f *v3Freeze) record() evmroot.OrderedHandoffRecord {
	return evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, Attempt: 0, OrderedRound: 3, ActivationRound: 7, PredecessorBodyID: f.predec,
		NextBodyID: f.body.ID[:], FrozenID: evmroot.D4FrozenID(f.body.ID[:], f.body.StateSummary, f.parent, f.candidate, 0, f.predec),
		SuccessorTRHash: make([]byte, 32), Kind: "freeze"}
}

func (f *v3Freeze) companion(t *testing.T, r evmroot.OrderedHandoffRecord, signed ...string) []byte {
	t.Helper()
	message, err := EndorsementBytes(r)
	require.NoError(t, err)
	sigs := map[string]hex.Bytes{}
	for _, name := range signed {
		sig, err := f.signers[name].SignBytes(message)
		require.NoError(t, err)
		sigs[name] = sig
	}
	raw, err := (FreezeV3Authorization{Version: freezeV3Version, Body: f.rawBody, Parent: f.parent, Candidate: f.candidate, Receipts: []byte("receipts"), Signatures: sigs}).Bytes()
	require.NoError(t, err)
	return raw
}

func (f *v3Freeze) verify(t *testing.T, r evmroot.OrderedHandoffRecord, companion []byte) ([]byte, error) {
	t.Helper()
	return f.auth.VerifyFreeze(r, companion)
}

func TestV3FreezeIsAdmittedUnderTheWeightedRulesAndEveryRefusalIsItsOwn(t *testing.T) {
	f := newV3Freeze(t)
	r := f.record()
	parent, err := f.verify(t, r, f.companion(t, r, "old-a", "old-b", "old-c"))
	require.NoError(t, err, "the control: one valid V3 freeze")
	require.Equal(t, f.parent, parent)
	require.Len(t, f.rules.asked, 1)
	require.Equal(t, f.rawBody, f.rules.asked[0].body)
	require.Equal(t, []byte("receipts"), f.rules.asked[0].receipts)
	require.Equal(t, f.candidate, f.rules.asked[0].candidate)
	require.EqualValues(t, 0, f.rules.asked[0].attempt)

	refused := func(name string, cause error, mutate func(f *v3Freeze, r *evmroot.OrderedHandoffRecord) []byte) {
		t.Helper()
		g := newV3Freeze(t)
		rec := g.record()
		companion := mutate(g, &rec)
		_, err := g.verify(t, rec, companion)
		require.ErrorIs(t, err, ErrHandoffRecord, name)
		require.ErrorIs(t, err, cause, name)
		for _, other := range []error{ErrFreezeV3Disabled, ErrFreezeV3Body, ErrFreezeV3Predecessor, ErrFreezeV3Context, ErrFreezeV3Binding, ErrFreezeV3Receipts, ErrFreezeV3Quorum} {
			if other != cause {
				require.NotErrorIs(t, err, other, "%s must be exactly %v, not %v", name, cause, other)
			}
		}
	}
	good := func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		return g.companion(t, *rec, "old-a", "old-b", "old-c")
	}
	refused("rules not enabled", ErrFreezeV3Disabled, func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		g.auth.v3 = nil
		return good(g, rec)
	})
	refused("body does not decode", ErrFreezeV3Body, func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		delete(g.rules.bodies, string(g.rawBody))
		return good(g, rec)
	})
	refused("another successor epoch", ErrFreezeV3Body, func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		b := g.body
		b.Epoch = 3
		g.rules.bodies[string(g.rawBody)] = b
		return good(g, rec)
	})
	refused("another network", ErrFreezeV3Body, func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		b := g.body
		b.Network = 6
		g.rules.bodies[string(g.rawBody)] = b
		return good(g, rec)
	})
	refused("activation before the earliest", ErrFreezeV3Body, func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		rec.ActivationRound = 6
		return good(g, rec)
	})
	refused("another predecessor", ErrFreezeV3Predecessor, func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		b := g.body
		b.PredecessorHash = bytes.Repeat([]byte{9}, 32)
		g.rules.bodies[string(g.rawBody)] = b
		return good(g, rec)
	})
	refused("a version-3 body under a V3 epoch's authority must name V3 as its predecessor", ErrFreezeV3Predecessor, func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		g.auth.priorVersion = freezeV3Version // the body was built over a version-1 predecessor
		return good(g, rec)
	})
	refused("another candidate than the record's frozen identity", ErrFreezeV3Context, func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		rec.FrozenID = bytes.Repeat([]byte{8}, 32)
		return good(g, rec)
	})
	refused("another body identity", ErrFreezeV3Context, func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		rec.NextBodyID = bytes.Repeat([]byte{7}, 32)
		rec.FrozenID = evmroot.D4FrozenID(rec.NextBodyID, g.body.StateSummary, g.parent, g.candidate, 0, g.predec)
		return good(g, rec)
	})
	refused("readiness receipts refused", ErrFreezeV3Receipts, func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		g.rules.receiptsErr = errors.New("a member's receipt is missing")
		return good(g, rec)
	})
	refused("below the weighted quorum", ErrFreezeV3Quorum, func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		return g.companion(t, *rec, "old-a", "old-b")
	})
	refused("a signature over another record", ErrFreezeV3Quorum, func(g *v3Freeze, rec *evmroot.OrderedHandoffRecord) []byte {
		other := *rec
		other.Attempt = 1
		return g.companion(t, other, "old-a", "old-b", "old-c")
	})
}

func TestAV3EpochsCommitteeOrdersV3SuccessorsOnly(t *testing.T) {
	f := newV3Freeze(t)
	f.auth.priorVersion = freezeV3Version
	link, err := f.rules.Prior(5, 1, freezeV3Version, f.predec)
	require.NoError(t, err)
	f.body.PredecessorHash = link
	f.rules.bodies[string(f.rawBody)] = f.body
	r := f.record()
	_, err = f.auth.VerifyFreeze(r, f.companion(t, r, "old-a", "old-b", "old-c"))
	require.NoError(t, err, "control: a V3 successor of a V3 epoch")

	v2, err := (FreezeAuthorization{Version: 1, Body: []byte("v2"), Parent: f.parent, Candidate: f.candidate, Signatures: map[string]hex.Bytes{"old-a": {1}}}).Bytes()
	require.NoError(t, err)
	_, err = f.auth.VerifyFreeze(r, v2)
	require.ErrorIs(t, err, ErrHandoffRecord, "a V2 successor body of a V3 epoch is refused")
}

func TestV3FreezeCompanionIsCanonicalAndCarriesReceipts(t *testing.T) {
	f := newV3Freeze(t)
	r := f.record()
	raw := f.companion(t, r, "old-a", "old-b", "old-c")
	parsed, err := ParseFreezeCompanion(raw)
	require.NoError(t, err)
	require.EqualValues(t, freezeV3Version, parsed.Version)
	require.Equal(t, []byte("receipts"), parsed.Receipts)

	noReceipts, err := (FreezeV3Authorization{Version: freezeV3Version, Body: f.rawBody, Parent: f.parent, Candidate: f.candidate,
		Signatures: map[string]hex.Bytes{"old-a": {1}}}).Bytes()
	require.NoError(t, err)
	_, err = ParseFreezeCompanion(noReceipts)
	require.ErrorIs(t, err, ErrHandoffRecord, "a V3 companion without receipts")
	_, err = ParseFreezeCompanion(append(append([]byte(nil), raw...), 0))
	require.ErrorIs(t, err, ErrHandoffRecord, "trailing byte")
}

// A V3 freeze admitted by a block retains the body, the candidate (when coupled) and the readiness receipts under the successor body's
// identity, so the activation's evidence can be assembled from this node's own store.
func TestAdmittedV3FreezeRetainsBodyAndReceipts(t *testing.T) {
	f := newV3Freeze(t)
	s := profileStore(t)
	installTestFrozenShard(t, s, f.parent)
	s.handoffAuth = f.auth
	prepare := f.record()
	prepare.Kind, prepare.FrozenID, prepare.OrderedRound = "prepare", make([]byte, 32), 2
	addProfileBlock(t, s, 2, [][]byte{prepare.Bytes()})
	freeze := f.record()
	addProfileBlock(t, s, 3, [][]byte{freeze.Bytes(), f.companion(t, freeze, "old-a", "old-b", "old-c")})

	body, err := s.HandoffBody(freeze.NextBodyID)
	require.NoError(t, err)
	require.Equal(t, f.rawBody, body)
	receipts, err := s.HandoffReceipts(freeze.NextBodyID)
	require.NoError(t, err)
	require.Equal(t, []byte("receipts"), receipts)

	// a freeze the V3 rules refuse is not admitted and retains nothing
	g := newV3Freeze(t)
	g.rules.receiptsErr = errors.New("no receipt")
	s2 := profileStore(t)
	installTestFrozenShard(t, s2, g.parent)
	s2.handoffAuth = g.auth
	prepare2, freeze2 := g.record(), g.record()
	prepare2.Kind, prepare2.FrozenID, prepare2.OrderedRound = "prepare", make([]byte, 32), 2
	addProfileBlock(t, s2, 2, [][]byte{prepare2.Bytes()})
	block := freezeBlock(t, s2, 3, [][]byte{freeze2.Bytes(), g.companion(t, freeze2, "old-a", "old-b", "old-c")})
	_, err = s2.Add(block, nil)
	require.ErrorIs(t, err, ErrFreezeV3Receipts)
	none, err := s2.HandoffReceipts(freeze2.NextBodyID)
	require.NoError(t, err)
	require.Empty(t, none)
}

// freezeBlock is addProfileBlock without the admission: the caller adds it and inspects the refusal.
func freezeBlock(t *testing.T, s *BlockStore, round uint64, records [][]byte) *rctypes.BlockData {
	t.Helper()
	parent, err := s.Block(round - 1)
	require.NoError(t, err)
	return &rctypes.BlockData{Version: 2, Round: round, Epoch: 1, Payload: &rctypes.Payload{Version: 2, HandoffRecords: records},
		Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: round - 1, Epoch: 1, CurrentRootHash: parent.RootHash}}}
}
