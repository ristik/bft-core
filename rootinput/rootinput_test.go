package rootinput

/*
#136 acceptance. Every certificate here is real: signed by a real root quorum over a real shard tree
and unicity tree, verified by the production verifier against a trust base the test owns. Nothing is a
caller-supplied "verified" flag, and no fixture asserts a refusal without first establishing that the
same inputs succeed when only the field under test is corrected — otherwise an unrelated failure could
satisfy the case.
*/

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmroot"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	testNetworkID   types.NetworkID   = 5
	testPartitionID types.PartitionID = 8
)

type stubTrustBases struct {
	tb  *types.RootTrustBaseV1
	err error
}

func (s stubTrustBases) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.tb, nil
}

type fixture struct {
	signers  []abcrypto.Signer
	nodeIDs  []string
	tb       *types.RootTrustBaseV1
	pdr      *types.PartitionDescriptionRecord
	confHash []byte
	parent   []byte
}

// newFixture builds a four-node root quorum. Quorum is 2/3+1, so three of the four signatures are
// needed — which is what makes two DIFFERENT valid signature subsets possible.
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

func (f *fixture) technical(round uint64) *certification.TechnicalRecord {
	zero := make([]byte, 32)
	return &certification.TechnicalRecord{Round: round, Epoch: 0, Leader: "shard-leader", StatHash: zero, FeeHash: zero}
}

// cert builds a genuinely signed certificate authorizing shard round `authorized`, certifying shard
// round `certified`, at root round `rootRound`, signed by the given signer indexes (a quorum subset).
func (f *fixture) cert(t *testing.T, certified, authorized, rootRound uint64, prev, state, block []byte, subset ...int) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	tr := f.technical(authorized)
	trHash, err := tr.Hash()
	require.NoError(t, err)
	ir := &types.InputRecord{
		Version: 1, RoundNumber: certified, Epoch: 0, PreviousHash: prev, Hash: state,
		BlockHash: block, SummaryValue: []byte{}, Timestamp: 1,
	}
	uc := testcertificates.CreateUnicityCertificate(t, f.signers[0], ir, f.pdr, rootRound, make([]byte, 32), trHash)
	f.sealWith(t, uc, subset...)
	return uc, tr
}

// sealWith seals the certificate the way a root chain does and signs it with signer 0 plus the given
// subset. The helper exists because the shared test-certificate builder leaves UnicitySeal.NetworkID
// unset and signs with a single signer, while a real seal names its network and carries a quorum —
// and because a case that tampers with sealed content must re-seal, or it would fail as a bad
// signature rather than for the reason it is testing.
func (f *fixture) sealWith(t *testing.T, uc *types.UnicityCertificate, subset ...int) {
	t.Helper()
	uc.UnicitySeal.NetworkID = testNetworkID
	uc.UnicitySeal.Signatures = nil
	require.NoError(t, uc.UnicitySeal.Sign(f.nodeIDs[0], f.signers[0]))
	for _, i := range subset {
		require.NoError(t, uc.UnicitySeal.Sign(f.nodeIDs[i], f.signers[i]))
	}
}

func (f *fixture) context() Context {
	return Context{
		NetworkID: testNetworkID, PartitionID: testPartitionID, ShardID: types.ShardID{},
		ShardConfHash: f.confHash, TrustBases: stubTrustBases{tb: f.tb},
		Round: 5, ParentHash: f.parent, LastAppliedRootRound: 40,
	}
}

// successful builds the ordinary case: shard round 4 certified with a block, authorizing round 5.
func (f *fixture) successful(t *testing.T) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	return f.cert(t, 4, 5, 50, bytes.Repeat([]byte{0xa0}, 32), bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xb1}, 32), 1, 2)
}

func TestDerive_AcceptsTheConfiguredCertificate(t *testing.T) {
	f := newFixture(t)
	uc, tr := f.successful(t)

	res, err := Derive(context.Background(), f.context(), uc, tr)
	require.NoError(t, err)

	require.Equal(t, uint64(evmroot.ProfileVersion), res.Input.Version)
	require.EqualValues(t, testNetworkID, res.Input.NetworkID)
	require.EqualValues(t, testPartitionID, res.Input.PartitionID)
	require.EqualValues(t, 5, res.Input.Round, "the authorized round is the one the caller pinned")
	require.EqualValues(t, 0, res.Input.CertifiedEpoch)
	require.EqualValues(t, 0, res.Input.AuthorizedEpoch)
	require.Equal(t, f.parent, res.Input.ParentHash, "h_parent is the pinned certified parent")
	require.Empty(t, res.Input.Transitions, "no committed bodies are pending in the supported profile")
	require.Equal(t, evmroot.EpochNormal, res.Input.EpochBoundary())

	// The commitment is what the model computes over the canonical encoding, recomputed here rather
	// than read back from the result.
	require.Equal(t, res.Input.Encode(), res.Encoded)
	require.Equal(t, res.Input.ExtraData(), res.Commitment)
	require.NoError(t, res.Input.Validate())
}

// TestDerive_AlternateQuorumSubsetsAgree is acceptance 1: the same certified statement authenticated by
// two different valid signature subsets must produce byte-identical canonical input and commitment.
// Signatures live only in the witness.
func TestDerive_AlternateQuorumSubsetsAgree(t *testing.T) {
	f := newFixture(t)
	prev, state, block := bytes.Repeat([]byte{0xa0}, 32), bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xb1}, 32)

	ucA, trA := f.cert(t, 4, 5, 50, prev, state, block, 1, 2) // signers 0,1,2
	ucB, trB := f.cert(t, 4, 5, 50, prev, state, block, 1, 3) // signers 0,1,3

	require.NotEqual(t, ucA.UnicitySeal.Signatures, ucB.UnicitySeal.Signatures, "the fixture must really use different subsets")
	require.Len(t, ucA.UnicitySeal.Signatures, 3)
	require.Len(t, ucB.UnicitySeal.Signatures, 3)

	a, err := Derive(context.Background(), f.context(), ucA, trA)
	require.NoError(t, err, "subset A must be a valid quorum")
	b, err := Derive(context.Background(), f.context(), ucB, trB)
	require.NoError(t, err, "subset B must be a valid quorum")

	require.Equal(t, a.Encoded, b.Encoded, "canonical input must not depend on which quorum subset signed")
	require.Equal(t, a.Commitment, b.Commitment)
	require.Equal(t, a.Authorizing.OriginID, b.Authorizing.OriginID)
	require.NotEqual(t, a.Certificate.UnicitySeal.Signatures, b.Certificate.UnicitySeal.Signatures,
		"the witnesses differ — which is the point: signatures are not part of the commitment")
}

// TestDerive_IndependentCBOROracle is the other half of acceptance 1. The oracle array is assembled
// from the CERTIFICATE, the TECHNICAL RECORD and the CONTEXT — not from the derived result — so it
// checks which value the derivation put in which position as well as the encoding, and it is encoded
// by bft-go-base's fxamacker core-deterministic encoder, the independent implementation the accepted
// model cross-checks against.
func TestDerive_IndependentCBOROracle(t *testing.T) {
	f := newFixture(t)
	uc, tr := f.successful(t)
	c := f.context()
	res, err := Derive(context.Background(), c, uc, tr)
	require.NoError(t, err)

	trHash, err := tr.Hash()
	require.NoError(t, err)
	oracle := []any{
		uint64(evmroot.ProfileVersion),
		uint64(testNetworkID), uint64(testPartitionID), types.ShardID{}.Bytes(),
		c.Round,              // n — the round the caller pinned
		uc.InputRecord.Epoch, // e_cert
		tr.Epoch,             // e_auth
		c.ParentHash,         // h_parent — the pinned certified parent
		[]any{ // O_-
			uint64(uc.UnicitySeal.NetworkID), uc.UnicitySeal.RootChainRoundNumber, uc.UnicitySeal.Epoch,
			uc.UnicitySeal.Timestamp, []byte(uc.UnicitySeal.Hash),
			[]any{
				uc.InputRecord.RoundNumber, uc.InputRecord.Epoch, []byte(uc.InputRecord.PreviousHash),
				[]byte(uc.InputRecord.Hash), uc.InputRecord.Timestamp, []byte(uc.InputRecord.BlockHash),
			},
			trHash, []byte(uc.ShardConfHash),
		},
		[]any{tr.Round, tr.Epoch, tr.Leader, []byte(tr.StatHash), []byte(tr.FeeHash)}, // TE_-
		[]any{}, // D — none pending
	}
	want, err := types.Cbor.Marshal(oracle)
	require.NoError(t, err)
	require.Equal(t, want, res.Encoded, "canonical encoding disagrees with the independent CBOR oracle")

	sum := crypto.SHA256.New()
	sum.Write(want)
	require.Equal(t, sum.Sum(nil), res.Commitment[:], "extraData must be SHA-256 over those bytes")
}

// TestPublishedVectorsUseTheSameCommitmentRule ties this package to the accepted D1 golden vectors
// without circularity: the vectors are generated by the model and byte-compared by the model's own
// suite (evmroot.TestVectorsMatchGolden), so what is worth checking here is that the rule this
// derivation applies — extraData = SHA-256 over the canonical encoding — is the rule those published
// bytes were produced under, and that the profile version agrees.
func TestPublishedVectorsUseTheSameCommitmentRule(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "evmroot", "testdata", "vectors.json"))
	require.NoError(t, err)
	var vectors struct {
		ProfileVersion uint64 `json:"profile_version"`
		RootInputs     []struct {
			Name      string `json:"name"`
			CBOR      string `json:"cbor"`
			ExtraData string `json:"extra_data"`
		} `json:"root_inputs"`
	}
	require.NoError(t, json.Unmarshal(raw, &vectors))
	require.EqualValues(t, evmroot.ProfileVersion, vectors.ProfileVersion)
	require.NotEmpty(t, vectors.RootInputs)

	for _, v := range vectors.RootInputs {
		t.Run(v.Name, func(t *testing.T) {
			encoded, err := hex.DecodeString(v.CBOR)
			require.NoError(t, err)
			want, err := hex.DecodeString(v.ExtraData)
			require.NoError(t, err)
			sum := crypto.SHA256.New()
			sum.Write(encoded)
			require.Equal(t, want, sum.Sum(nil), "published extra_data is not SHA-256 over the published canonical bytes")
		})
	}
}

// TestDerive_RoundTypes covers the supported D1 round types, including a quiet round whose block hash
// is null and a repeat at a higher root round.
func TestDerive_RoundTypes(t *testing.T) {
	f := newFixture(t)
	state := bytes.Repeat([]byte{0xa1}, 32)

	t.Run("quiet round: h == h' and the block hash is null", func(t *testing.T) {
		uc, tr := f.cert(t, 4, 5, 50, state, state, nil, 1, 2)
		res, err := Derive(context.Background(), f.context(), uc, tr)
		require.NoError(t, err)
		require.Empty(t, res.Input.Origin.IR.BlockHash)
	})

	t.Run("a repeat at a higher root round derives, and the older one is refused once applied", func(t *testing.T) {
		prev, block := bytes.Repeat([]byte{0xa0}, 32), bytes.Repeat([]byte{0xb1}, 32)
		older, trOld := f.cert(t, 4, 5, 50, prev, state, block, 1, 2)
		repeat, trNew := f.cert(t, 4, 5, 57, prev, state, block, 1, 2)

		c := f.context()
		first, err := Derive(context.Background(), c, older, trOld)
		require.NoError(t, err)
		later, err := Derive(context.Background(), c, repeat, trNew)
		require.NoError(t, err)
		require.NotEqual(t, first.Encoded, later.Encoded, "the root origin differs: the repeat is a later root authorization")

		// Once the seal-registry cursor has moved past the older certificate, binding it is stale.
		c.LastAppliedRootRound = 57
		_, err = Derive(context.Background(), c, older, trOld)
		require.ErrorIs(t, err, ErrNotPinned)
		_, err = Derive(context.Background(), c, repeat, trNew)
		require.NoError(t, err, "the current certificate still derives")
	})
}

// TestDerive_Refusals is acceptance 2: each failure mode fails for its own reason, and each fixture's
// premise is established by showing the corrected input succeeds.
func TestDerive_Refusals(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	t.Run("premise: the unmodified fixture derives", func(t *testing.T) {
		uc, tr := f.successful(t)
		_, err := Derive(ctx, f.context(), uc, tr)
		require.NoError(t, err)
	})

	t.Run("sub-quorum seal", func(t *testing.T) {
		uc, tr := f.cert(t, 4, 5, 50, bytes.Repeat([]byte{0xa0}, 32), bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xb1}, 32))
		require.Len(t, uc.UnicitySeal.Signatures, 1, "one of four is below the 2/3+1 quorum")
		_, err := Derive(ctx, f.context(), uc, tr)
		require.ErrorIs(t, err, ErrUnauthenticated)
	})

	t.Run("forged signature", func(t *testing.T) {
		uc, tr := f.successful(t)
		for id := range uc.UnicitySeal.Signatures {
			uc.UnicitySeal.Signatures[id] = bytes.Repeat([]byte{0x01}, 64)
			break
		}
		_, err := Derive(ctx, f.context(), uc, tr)
		require.ErrorIs(t, err, ErrUnauthenticated)
	})

	t.Run("sealed root does not match the certified inclusion path", func(t *testing.T) {
		// The seal is re-signed after the tamper, so the quorum is genuine and the failure is the
		// path evaluation — not a signature that no longer matches.
		uc, tr := f.successful(t)
		uc.UnicitySeal.Hash = bytes.Repeat([]byte{0x09}, 32)
		f.sealWith(t, uc, 1, 2)
		require.NoError(t, uc.UnicitySeal.Verify(f.tb), "the quorum itself must still be valid")
		_, err := Derive(ctx, f.context(), uc, tr)
		require.ErrorIs(t, err, ErrUnauthenticated)
		require.ErrorContains(t, err, "does not match")
	})

	t.Run("the technical record is not the one the certificate commits to", func(t *testing.T) {
		uc, _ := f.successful(t)
		other := f.technical(5)
		other.Leader = "someone-else"
		_, err := Derive(ctx, f.context(), uc, other)
		require.ErrorIs(t, err, ErrUnauthenticated)
		require.ErrorContains(t, err, "commits to")
	})

	t.Run("wrong configured shard configuration", func(t *testing.T) {
		uc, tr := f.successful(t)
		c := f.context()
		c.ShardConfHash = bytes.Repeat([]byte{0xee}, 32)
		_, err := Derive(ctx, c, uc, tr)
		require.ErrorIs(t, err, ErrUnauthenticated)
	})

	t.Run("wrong configured partition", func(t *testing.T) {
		uc, tr := f.successful(t)
		c := f.context()
		c.PartitionID = testPartitionID + 1
		_, err := Derive(ctx, c, uc, tr)
		require.ErrorIs(t, err, ErrUnauthenticated)
	})

	t.Run("wrong configured network", func(t *testing.T) {
		uc, tr := f.successful(t)
		c := f.context()
		c.NetworkID = testNetworkID + 1
		_, err := Derive(ctx, c, uc, tr)
		require.ErrorIs(t, err, ErrWrongContext)
	})

	t.Run("unknown root epoch", func(t *testing.T) {
		uc, tr := f.successful(t)
		c := f.context()
		c.TrustBases = stubTrustBases{err: errors.New("unknown epoch")}
		_, err := Derive(ctx, c, uc, tr)
		require.ErrorIs(t, err, ErrUnauthenticated)
	})

	t.Run("wrong pinned round", func(t *testing.T) {
		uc, tr := f.successful(t)
		c := f.context()
		c.Round = 6 // the certificate authorizes 5
		_, err := Derive(ctx, c, uc, tr)
		require.ErrorIs(t, err, ErrNotPinned)
	})

	t.Run("stale against the seal-registry cursor", func(t *testing.T) {
		uc, tr := f.successful(t)
		c := f.context()
		c.LastAppliedRootRound = 51 // the certificate's root round is 50
		_, err := Derive(ctx, c, uc, tr)
		require.ErrorIs(t, err, ErrNotPinned)
	})

	t.Run("unsupported: pending committed bodies", func(t *testing.T) {
		uc, tr := f.successful(t)
		c := f.context()
		c.TransitionsPending = true
		_, err := Derive(ctx, c, uc, tr)
		require.ErrorIs(t, err, ErrUnsupported)
		require.ErrorContains(t, err, "H-series")
	})

	t.Run("unsupported: epoch handoff", func(t *testing.T) {
		// The technical record authorizes the successor epoch while the certified IR belongs to the
		// outgoing one — structurally valid in D1, unauthenticable here.
		tr := f.technical(5)
		tr.Epoch = 1
		trHash, err := tr.Hash()
		require.NoError(t, err)
		ir := &types.InputRecord{
			Version: 1, RoundNumber: 4, Epoch: 0,
			PreviousHash: bytes.Repeat([]byte{0xa0}, 32), Hash: bytes.Repeat([]byte{0xa1}, 32),
			BlockHash: bytes.Repeat([]byte{0xb1}, 32), SummaryValue: []byte{}, Timestamp: 1,
		}
		uc := testcertificates.CreateUnicityCertificate(t, f.signers[0], ir, f.pdr, 50, make([]byte, 32), trHash)
		f.sealWith(t, uc, 1, 2)

		_, err = Derive(ctx, f.context(), uc, tr)
		require.ErrorIs(t, err, ErrUnsupported)
		require.ErrorContains(t, err, "handoff")
	})

	t.Run("unsupported: genesis installation", func(t *testing.T) {
		uc, tr := f.successful(t)
		c := f.context()
		c.Round = 0
		_, err := Derive(ctx, c, uc, tr)
		require.ErrorIs(t, err, ErrUnsupported)
		require.ErrorContains(t, err, "round 0")
	})

	t.Run("incomplete context", func(t *testing.T) {
		uc, tr := f.successful(t)
		for _, tc := range []struct {
			name  string
			mutTo func(*Context)
		}{
			{"no trust base source", func(c *Context) { c.TrustBases = nil }},
			{"no configured configuration hash", func(c *Context) { c.ShardConfHash = nil }},
			{"malformed configured configuration hash", func(c *Context) { c.ShardConfHash = []byte{0x01} }},
			{"no pinned parent", func(c *Context) { c.ParentHash = nil }},
			{"malformed pinned parent", func(c *Context) { c.ParentHash = []byte{0x01} }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := f.context()
				tc.mutTo(&c)
				_, err := Derive(ctx, c, uc, tr)
				require.ErrorIs(t, err, ErrContextIncomplete)
			})
		}
		_, err := Derive(ctx, f.context(), nil, tr)
		require.ErrorIs(t, err, ErrContextIncomplete)
		_, err = Derive(ctx, f.context(), uc, nil)
		require.ErrorIs(t, err, ErrContextIncomplete)
	})
}

// TestDerive_OwnsItsInputs is acceptance 4: mutating anything the caller passed, after a successful
// derivation, changes neither the retained verified representation nor the commitment.
func TestDerive_OwnsItsInputs(t *testing.T) {
	f := newFixture(t)
	uc, tr := f.successful(t)
	c := f.context()

	res, err := Derive(context.Background(), c, uc, tr)
	require.NoError(t, err)
	encoded := bytes.Clone(res.Encoded)
	commitment := res.Commitment
	retainedState := bytes.Clone(res.Certificate.InputRecord.Hash)
	retainedLeader := res.Technical.Leader

	uc.InputRecord.Hash[0] ^= 0xff
	uc.ShardConfHash[0] ^= 0xff
	tr.Leader = "someone-else"
	c.ShardConfHash[0] ^= 0xff
	c.ParentHash[0] ^= 0xff

	require.Equal(t, encoded, res.Encoded, "the canonical bytes are the derivation's own")
	require.Equal(t, commitment, res.Commitment)
	require.True(t, bytes.Equal(retainedState, res.Certificate.InputRecord.Hash), "the retained certificate is a copy")
	require.Equal(t, retainedLeader, res.Technical.Leader)
	require.Equal(t, encoded, res.Input.Encode(), "re-encoding the retained input reproduces the same bytes")
}

// TestDerive_SameForBuilderFollowerAndReplay is acceptance 5: three call shapes, one pinned set of
// inputs, identical results — with no ambient state involved.
func TestDerive_SameForBuilderFollowerAndReplay(t *testing.T) {
	f := newFixture(t)
	uc, tr := f.successful(t)

	// Builder: derives while proposing, from its own configuration and cursor.
	builder, err := Derive(context.Background(), f.context(), uc, tr)
	require.NoError(t, err)

	// Follower: validates a leader's block against the certificate the block bound. It does not
	// re-pick a certificate; it is handed the bound one.
	follower, err := Derive(context.Background(), f.context(), uc, tr)
	require.NoError(t, err)

	// Replay: the same pinned inputs long afterwards, from a fresh context value.
	replayCtx := f.context()
	replay, err := Derive(context.Background(), replayCtx, uc, tr)
	require.NoError(t, err)

	require.Equal(t, builder.Encoded, follower.Encoded)
	require.Equal(t, builder.Encoded, replay.Encoded)
	require.Equal(t, builder.Commitment, follower.Commitment)
	require.Equal(t, builder.Commitment, replay.Commitment)
	require.Equal(t, builder.Authorizing, replay.Authorizing)
}
