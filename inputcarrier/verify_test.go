package inputcarrier_test

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/inputcarrier"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	testNetworkID   types.NetworkID   = 5
	testPartitionID types.PartitionID = 8
)

// trustBases is the verifier's own trust source. hook, when set, runs inside the lookup: the one
// point where Verify yields control to something the caller could use to change its inputs.
type trustBases struct {
	tb   *types.RootTrustBaseV1
	hook func()
}

func (s trustBases) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	if s.hook != nil {
		s.hook()
	}
	return s.tb, nil
}

/*
fixture is a four-node root quorum (quorum three) and one shard configuration, built the way
rootinput's own fixtures are: every certificate is genuinely signed and verified by the production
verifier. Nothing in it is a node's live state.
*/
type fixture struct {
	signers  []abcrypto.Signer
	nodeIDs  []string
	tb       *types.RootTrustBaseV1
	pdr      *types.PartitionDescriptionRecord
	confHash []byte
	parent   []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		pdr:    &types.PartitionDescriptionRecord{Version: 1, NetworkID: testNetworkID, PartitionID: testPartitionID, T2Timeout: 2500000000},
		parent: bytes.Repeat([]byte{0xa9}, 32),
	}
	for i := 0; i < 4; i++ {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		id, err := network.NodeIDFromPublicKeyBytes(pub)
		require.NoError(t, err)
		f.signers = append(f.signers, s)
		f.nodeIDs = append(f.nodeIDs, id.String())
	}
	tb, ok := testtrustbase.NewTrustBase(t, f.signers...).(*types.RootTrustBaseV1)
	require.True(t, ok)
	f.tb = tb
	h, err := f.pdr.Hash(crypto.SHA256)
	require.NoError(t, err)
	f.confHash = h
	return f
}

// cert builds a signed certificate certifying shard round `certified` and authorizing `authorized`,
// at root round `rootRound`, for configuration pdr, signed by signer 0 plus subset.
func (f *fixture) cert(t *testing.T, pdr *types.PartitionDescriptionRecord, certified, authorized, rootRound uint64, subset ...int) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	zero := make([]byte, 32)
	tr := &certification.TechnicalRecord{Round: authorized, Epoch: 0, Leader: "shard-leader", StatHash: zero, FeeHash: zero}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	ir := &types.InputRecord{
		Version: 1, RoundNumber: certified, Epoch: 0,
		PreviousHash: bytes.Repeat([]byte{0xa0}, 32), Hash: bytes.Repeat([]byte{0xa1}, 32),
		BlockHash: bytes.Repeat([]byte{0xb1}, 32), SummaryValue: []byte{}, Timestamp: 1,
	}
	uc := testcertificates.CreateUnicityCertificate(t, f.signers[0], ir, pdr, rootRound, make([]byte, 32), trHash)
	uc.UnicitySeal.NetworkID = testNetworkID
	uc.UnicitySeal.Signatures = nil
	require.NoError(t, uc.UnicitySeal.Sign(f.nodeIDs[0], f.signers[0]))
	for _, i := range subset {
		require.NoError(t, uc.UnicitySeal.Sign(f.nodeIDs[i], f.signers[i]))
	}
	return uc, tr
}

// baseContext is the verifier-owned context without the per-round pins.
func (f *fixture) baseContext(tb rootinput.TrustBases) rootinput.Context {
	return rootinput.Context{
		NetworkID: testNetworkID, PartitionID: testPartitionID, ShardID: types.ShardID{},
		ShardConfHash: f.confHash, TrustBases: tb,
	}
}

type historyEntry struct{ certified, authorized, rootRound uint64 }

/*
appliedCursor derives LastAppliedRootRound from a certified history this fixture applies in order,
through rootinput.Derive, starting from the authenticated genesis value 0 (F4a §5.4, §7.3). Each
applied round moves the cursor to its authorization's root round. It is never taken from observed
messages: a certificate the fixture holds but has not applied does not appear in history and does not
move the cursor.
*/
func (f *fixture) appliedCursor(t *testing.T, history []historyEntry) uint64 {
	t.Helper()
	cursor := uint64(0) // the authenticated genesis value, not a placeholder
	for _, h := range history {
		uc, tr := f.cert(t, f.pdr, h.certified, h.authorized, h.rootRound, 1, 2)
		c := f.baseContext(trustBases{tb: f.tb})
		c.Round, c.ParentHash, c.LastAppliedRootRound = h.authorized, f.parent, cursor
		res, err := rootinput.Derive(context.Background(), c, uc, tr)
		require.NoError(t, err, "fixture history entry %+v must authenticate", h)
		cursor = res.Authorizing.RootRound
	}
	return cursor
}

type scenario struct {
	f      *fixture
	ctx    rootinput.Context
	env    inputcarrier.Envelope
	header inputcarrier.Header
	uc     *types.UnicityCertificate
	tr     *certification.TechnicalRecord
}

func envelopeFor(t *testing.T, round uint64, blockHash []byte, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) inputcarrier.Envelope {
	t.Helper()
	ucb, err := types.Cbor.Marshal(uc)
	require.NoError(t, err)
	trb, err := types.Cbor.Marshal(tr)
	require.NoError(t, err)
	return inputcarrier.Envelope{Version: inputcarrier.Version, ShardRound: round, BlockHash: bytes.Clone(blockHash), Certificate: ucb, TechnicalRecord: trb}
}

// newScenario is the ordinary case: the history applied rounds 2 and 4 (cursor 40), and the block
// under test executes round 5, bound to a certificate at root round 50 certifying round 4.
func newScenario(t *testing.T) *scenario {
	t.Helper()
	f := newFixture(t)
	cursor := f.appliedCursor(t, []historyEntry{{1, 2, 20}, {3, 4, 40}})
	require.EqualValues(t, 40, cursor)

	uc, tr := f.cert(t, f.pdr, 4, 5, 50, 1, 2)
	c := f.baseContext(trustBases{tb: f.tb})
	c.Round, c.ParentHash, c.LastAppliedRootRound = 5, f.parent, cursor

	derived, err := rootinput.Derive(context.Background(), c, uc, tr)
	require.NoError(t, err)
	blockHash := bytes.Repeat([]byte{0xbb}, 32)
	return &scenario{
		f: f, ctx: c, uc: uc, tr: tr,
		env:    envelopeFor(t, 5, blockHash, uc, tr),
		header: inputcarrier.Header{Hash: blockHash, ParentHash: bytes.Clone(f.parent), ExtraData: bytes.Clone(derived.Commitment[:])},
	}
}

func TestVerify_AcceptsTheBoundEvidence(t *testing.T) {
	s := newScenario(t)
	res, err := inputcarrier.Verify(context.Background(), s.ctx, s.env, s.header)
	require.NoError(t, err)
	require.Equal(t, s.header.ExtraData, res.Commitment[:])
	require.EqualValues(t, 50, res.Authorizing.RootRound)

	// The envelope survives the transport's own encoding unchanged.
	b, err := inputcarrier.Encode(s.env, inputcarrier.DefaultLimits)
	require.NoError(t, err)
	decoded, err := inputcarrier.Decode(b, inputcarrier.DefaultLimits)
	require.NoError(t, err)
	_, err = inputcarrier.Verify(context.Background(), s.ctx, decoded, s.header)
	require.NoError(t, err)
}

func TestVerify_BindingRefusals(t *testing.T) {
	s := newScenario(t)
	_, err := inputcarrier.Verify(context.Background(), s.ctx, s.env, s.header)
	require.NoError(t, err, "premise")

	t.Run("envelope for another round", func(t *testing.T) {
		e := s.env
		e.ShardRound = 6
		_, err := inputcarrier.Verify(context.Background(), s.ctx, e, s.header)
		require.ErrorIs(t, err, inputcarrier.ErrEnvelopeBinding)
	})
	t.Run("envelope bound to another block", func(t *testing.T) {
		e := s.env
		e.BlockHash = bytes.Repeat([]byte{0xcc}, 32)
		_, err := inputcarrier.Verify(context.Background(), s.ctx, e, s.header)
		require.ErrorIs(t, err, inputcarrier.ErrEnvelopeBinding)
	})
	t.Run("header hash that is not 32 bytes", func(t *testing.T) {
		h := s.header
		h.Hash = h.Hash[:31]
		_, err := inputcarrier.Verify(context.Background(), s.ctx, s.env, h)
		require.ErrorIs(t, err, inputcarrier.ErrEnvelopeBinding)
	})
	t.Run("certificate bytes that are not canonical", func(t *testing.T) {
		e := s.env
		e.Certificate = append(bytes.Clone(e.Certificate), 0x00)
		_, err := inputcarrier.Verify(context.Background(), s.ctx, e, s.header)
		require.ErrorIs(t, err, inputcarrier.ErrMalformedEnvelope)
	})
	// A trailing byte is refused by the CBOR decoder itself. These encodings decode cleanly, so only
	// the canonical re-encoding check can refuse them.
	t.Run("certificate with a non-minimal integer", func(t *testing.T) {
		e := s.env
		e.Certificate = nonMinimalFirstElement(t, e.Certificate)
		require.NoError(t, types.Cbor.Unmarshal(e.Certificate, &types.UnicityCertificate{}), "premise: it decodes")
		_, err := inputcarrier.Verify(context.Background(), s.ctx, e, s.header)
		require.ErrorIs(t, err, inputcarrier.ErrMalformedEnvelope)
	})
	t.Run("technical record with a non-minimal integer", func(t *testing.T) {
		e := s.env
		e.TechnicalRecord = nonMinimalFirstElement(t, e.TechnicalRecord)
		require.NoError(t, types.Cbor.Unmarshal(e.TechnicalRecord, &certification.TechnicalRecord{}), "premise: it decodes")
		_, err := inputcarrier.Verify(context.Background(), s.ctx, e, s.header)
		require.ErrorIs(t, err, inputcarrier.ErrMalformedEnvelope)
	})
	t.Run("unknown envelope version", func(t *testing.T) {
		e := s.env
		e.Version = 2
		_, err := inputcarrier.Verify(context.Background(), s.ctx, e, s.header)
		require.ErrorIs(t, err, inputcarrier.ErrMalformedEnvelope)
	})
}

// nonMinimalFirstElement rewrites the first element of the first definite-length array in b, which
// must be a one-byte unsigned integer, into its two-byte non-minimal form. The value is unchanged, so
// the result decodes to the same structure but is not the canonical encoding.
func nonMinimalFirstElement(t *testing.T, b []byte) []byte {
	t.Helper()
	for i := 0; i < len(b)-1 && i < 8; i++ {
		if b[i] >= 0x81 && b[i] <= 0x97 && b[i+1] < 0x18 {
			out := append(bytes.Clone(b[:i+1]), 0x18, b[i+1])
			return append(out, b[i+2:]...)
		}
	}
	t.Fatalf("no array with a small first integer near the start of %x", b[:min(len(b), 8)])
	return nil
}

// TestVerify_RefusalsKeepTheirRootinputClass checks that evidence refusals reach the caller as the
// rootinput class they are, not as a carrier error (F2c §8).
func TestVerify_RefusalsKeepTheirRootinputClass(t *testing.T) {
	s := newScenario(t)

	t.Run("a certificate for another configuration", func(t *testing.T) {
		other := *s.f.pdr
		other.T2Timeout = 5000000000
		uc, tr := s.f.cert(t, &other, 4, 5, 50, 1, 2)
		_, err := inputcarrier.Verify(context.Background(), s.ctx, envelopeFor(t, 5, s.header.Hash, uc, tr), s.header)
		require.ErrorIs(t, err, rootinput.ErrUnauthenticated)
		require.NotErrorIs(t, err, inputcarrier.ErrEnvelopeBinding)
	})
	t.Run("a sub-quorum certificate", func(t *testing.T) {
		uc, tr := s.f.cert(t, s.f.pdr, 4, 5, 50)
		_, err := inputcarrier.Verify(context.Background(), s.ctx, envelopeFor(t, 5, s.header.Hash, uc, tr), s.header)
		require.ErrorIs(t, err, rootinput.ErrUnauthenticated)
	})
	t.Run("a certificate behind the applied cursor", func(t *testing.T) {
		uc, tr := s.f.cert(t, s.f.pdr, 4, 5, 30, 1, 2)
		_, err := inputcarrier.Verify(context.Background(), s.ctx, envelopeFor(t, 5, s.header.Hash, uc, tr), s.header)
		require.ErrorIs(t, err, rootinput.ErrNotPinned)
	})
	t.Run("a header naming another parent", func(t *testing.T) {
		h := s.header
		h.ParentHash = bytes.Repeat([]byte{0x55}, 32)
		_, err := inputcarrier.Verify(context.Background(), s.ctx, s.env, h)
		require.ErrorIs(t, err, rootinput.ErrBindingMismatch)
	})
	t.Run("a header whose extraData does not match", func(t *testing.T) {
		h := s.header
		h.ExtraData = bytes.Repeat([]byte{0x66}, 32)
		_, err := inputcarrier.Verify(context.Background(), s.ctx, s.env, h)
		require.ErrorIs(t, err, rootinput.ErrBindingMismatch)
	})
}

// TestVerify_AsymmetricDeliveryDoesNotReselect: a follower that also holds a later valid repeat for
// the same round still accepts the certificate the block binds, and cannot substitute its own.
func TestVerify_AsymmetricDeliveryDoesNotReselect(t *testing.T) {
	s := newScenario(t)
	repeatUC, repeatTR := s.f.cert(t, s.f.pdr, 4, 5, 60, 1, 3)
	repeat := envelopeFor(t, 5, s.header.Hash, repeatUC, repeatTR)

	c := s.ctx
	_, err := rootinput.Derive(context.Background(), c, repeatUC, repeatTR)
	require.NoError(t, err, "premise: the repeat is itself a valid authorization")

	_, err = inputcarrier.Verify(context.Background(), c, s.env, s.header)
	require.NoError(t, err, "the bound certificate is accepted whatever else the follower holds")

	_, err = inputcarrier.Verify(context.Background(), c, repeat, s.header)
	require.ErrorIs(t, err, rootinput.ErrBindingMismatch, "the repeat derives another commitment than the one the block carries")
}

// TestVerify_OwnsItsInputs changes the caller's envelope and header during the trust lookup, in both
// directions, and requires the verdict for the inputs as they arrived.
func TestVerify_OwnsItsInputs(t *testing.T) {
	t.Run("a valid header made invalid during the lookup is still accepted", func(t *testing.T) {
		s := newScenario(t)
		h := inputcarrier.Header{Hash: bytes.Clone(s.header.Hash), ParentHash: bytes.Clone(s.header.ParentHash), ExtraData: bytes.Clone(s.header.ExtraData)}
		e := s.env
		e.Certificate = bytes.Clone(s.env.Certificate)
		c := s.ctx
		c.TrustBases = trustBases{tb: s.f.tb, hook: func() {
			h.ParentHash[0] ^= 0xff
			h.ExtraData[0] ^= 0xff
			e.Certificate[len(e.Certificate)-1] ^= 0xff
		}}
		_, err := inputcarrier.Verify(context.Background(), c, e, h)
		require.NoError(t, err)
		require.NotEqual(t, s.header.ExtraData, h.ExtraData, "premise: the caller's slice really changed")
	})
	t.Run("an invalid header made valid during the lookup is still refused", func(t *testing.T) {
		s := newScenario(t)
		h := inputcarrier.Header{Hash: bytes.Clone(s.header.Hash), ParentHash: bytes.Clone(s.header.ParentHash), ExtraData: bytes.Repeat([]byte{0x66}, 32)}
		_, err := inputcarrier.Verify(context.Background(), s.ctx, s.env, h)
		require.ErrorIs(t, err, rootinput.ErrBindingMismatch, "premise: refused as it arrives")

		c := s.ctx
		c.TrustBases = trustBases{tb: s.f.tb, hook: func() { copy(h.ExtraData, s.header.ExtraData) }}
		_, err = inputcarrier.Verify(context.Background(), c, s.env, h)
		require.ErrorIs(t, err, rootinput.ErrBindingMismatch)
		require.Equal(t, s.header.ExtraData, h.ExtraData, "premise: the caller's slice really changed")
	})
}
