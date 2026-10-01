package mintproof

import (
	"bytes"
	gocrypto "crypto"
	"testing"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func rotatedPDR(t *testing.T, genesis *types.PartitionDescriptionRecord, mutate func(*types.PartitionDescriptionRecord)) *types.PartitionDescriptionRecord {
	t.Helper()
	key := func(id string) *types.NodeInfo {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		return &types.NodeInfo{NodeID: id, SigKey: pub, Stake: 1}
	}
	succ, err := evmassign.NewSuccessor(genesis, []*types.NodeInfo{key("v-a"), key("v-b"), key("v-c")})
	require.NoError(t, err)
	if mutate != nil {
		mutate(succ)
	}
	pdr, err := evmassign.Activate(succ, 40)
	require.NoError(t, err)
	return pdr
}

type v2Fixture struct {
	f      proofFixture
	pdr    *types.PartitionDescriptionRecord
	bundle MintReasonBundleV2
	raw    []byte
	trust  types.RootTrustBase
	claim  ExpectedClaim
}

// newV2Fixture certifies the block under the rotated assignment at shard epoch 1 and root epoch 2.
func newV2Fixture(t *testing.T, mutatePDR func(*types.PartitionDescriptionRecord), shardEpoch uint64) v2Fixture {
	t.Helper()
	probe := newProofFixture(t, []uint64{gethtypes.ReceiptStatusSuccessful, gethtypes.ReceiptStatusSuccessful}, false, false)
	pdr := rotatedPDR(t, probe.chain.Full, mutatePDR)
	f := newProofFixtureWith(t, []uint64{gethtypes.ReceiptStatusSuccessful, gethtypes.ReceiptStatusSuccessful}, false, false,
		&variant{pdr: pdr, shardEpoch: shardEpoch, rootEpoch: 2})
	req := f.request
	req.ConfigPDR = pdr
	bundle, err := ExtractV2(f.store, req)
	require.NoError(t, err)
	raw, err := bundle.MarshalCBOR()
	require.NoError(t, err)
	tb := *f.chain.TrustBase
	tb.NetworkID, tb.Epoch = 3, 2 // an EVM-only rotation advances the root epoch with identical root keys
	claim := f.claim
	claim.ShardConf = [32]byte{}
	claim.Pin = GenesisPin{Genesis: f.chain.Full}
	return v2Fixture{f: f, pdr: pdr, bundle: bundle, raw: raw, trust: &tb, claim: claim}
}

func TestPDRBundleVerifiesOfflineForTheRotatedAssignment(t *testing.T) {
	v := newV2Fixture(t, nil, 1)
	require.NoError(t, Verify(v.raw, v.trust, v.claim, DefaultLimits()))
	h, err := v.pdr.Hash(gocrypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, h, v.bundle.Context.ShardConf[:], "the bundle's configuration is the carried PDR's hash")

	absent, err := ExtractV2(v.f.store, ExtractRequest{Archive: v.f.request.Archive, Absence: true, ConfigPDR: v.pdr})
	require.NoError(t, err)
	absentRaw, err := absent.MarshalCBOR()
	require.NoError(t, err)
	noEvent := v.claim
	noEvent.MatchLog = func(*gethtypes.Log) bool { return false }
	require.NoError(t, Verify(absentRaw, v.trust, noEvent, DefaultLimits()), "absence verifies the same way")

	t.Run("exact historical pin narrows acceptance", func(t *testing.T) {
		narrowed := v.claim
		narrowed.ShardConf = [32]byte(h)
		require.NoError(t, Verify(v.raw, v.trust, narrowed, DefaultLimits()))
		narrowed.ShardConf = [32]byte{1}
		err := Verify(v.raw, v.trust, narrowed, DefaultLimits())
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "exact historical pin")
	})
	t.Run("the caller's trust base must be the UC's root epoch", func(t *testing.T) {
		stale := *v.f.chain.TrustBase
		stale.NetworkID, stale.Epoch = 3, 1
		require.ErrorIs(t, Verify(v.raw, &stale, v.claim, DefaultLimits()), ErrInvalid)
	})
	t.Run("a deployment pin is required", func(t *testing.T) {
		unpinned := v.claim
		unpinned.Pin = GenesisPin{}
		err := Verify(v.raw, v.trust, unpinned, DefaultLimits())
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "no genesis pin")
	})
	t.Run("a legacy bundle is not reinterpreted as the latest assignment", func(t *testing.T) {
		legacy := v.bundle.MintReasonBundleV1
		legacy.Context.ShardConf = [32]byte(v.f.claim.ShardConf)
		raw, err := legacy.MarshalCBOR()
		require.NoError(t, err)
		require.ErrorIs(t, Verify(raw, v.trust, v.f.claim, DefaultLimits()), ErrInvalid,
			"the rotated assignment's certificate does not authenticate under the genesis configuration pin")
	})
}

func TestPDRBundleIsolatedRefusals(t *testing.T) {
	t.Run("altered configuration PDR bytes", func(t *testing.T) {
		v := newV2Fixture(t, nil, 1)
		bad := v.bundle
		bad.ConfigPDR = append(bytes.Clone(bad.ConfigPDR), 0)
		raw, err := bad.MarshalCBOR()
		require.NoError(t, err)
		err = Verify(raw, v.trust, v.claim, DefaultLimits())
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "configuration PDR")
	})
	t.Run("a PDR that is not the certificate's configuration", func(t *testing.T) {
		v := newV2Fixture(t, nil, 1)
		bad := v.bundle
		raw, err := types.Cbor.Marshal(v.f.chain.Full)
		require.NoError(t, err)
		bad.ConfigPDR = raw
		out, err := bad.MarshalCBOR()
		require.NoError(t, err)
		err = Verify(out, v.trust, v.claim, DefaultLimits())
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "does not hash to the certificate's configuration")
	})
	t.Run("a non-membership setting changed", func(t *testing.T) {
		v := newV2Fixture(t, func(p *types.PartitionDescriptionRecord) { p.PartitionParams["chain_id"] = "999" }, 1)
		err := Verify(v.raw, v.trust, v.claim, DefaultLimits())
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "non-membership setting")
	})
	t.Run("the genesis commitment of G changed", func(t *testing.T) {
		v := newV2Fixture(t, func(p *types.PartitionDescriptionRecord) { p.PartitionParams["seal_registry_genesis"] = "00" }, 1)
		err := Verify(v.raw, v.trust, v.claim, DefaultLimits())
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "non-membership setting")
	})
	t.Run("the validator set is malformed", func(t *testing.T) {
		v := newV2Fixture(t, func(p *types.PartitionDescriptionRecord) {
			p.Validators[1].SigKey = bytes.Clone(p.Validators[0].SigKey)
		}, 1)
		err := Verify(v.raw, v.trust, v.claim, DefaultLimits())
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "validators")
	})
	t.Run("the certified shard epoch is another assignment's", func(t *testing.T) {
		v := newV2Fixture(t, nil, 2) // IR epoch 2 over a PDR of epoch 1
		err := Verify(v.raw, v.trust, v.claim, DefaultLimits())
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "certified shard epoch 2, configuration PDR epoch 1")
	})
	t.Run("another deployment's genesis pin", func(t *testing.T) {
		v := newV2Fixture(t, nil, 1)
		other := *v.f.chain.Full
		other.PartitionID++
		claim := v.claim
		claim.Pin = GenesisPin{Genesis: &other}
		err := Verify(v.raw, v.trust, claim, DefaultLimits())
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "not of the pinned deployment")
	})
}

func TestPDRBundleCodec(t *testing.T) {
	v := newV2Fixture(t, nil, 1)
	got, err := DecodeBundleV2(v.raw, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, v.bundle.ConfigPDR, got.ConfigPDR)
	for name, raw := range map[string][]byte{
		"trailing byte": append(bytes.Clone(v.raw), 0),
		"truncated":     v.raw[:len(v.raw)-1],
	} {
		_, err := DecodeBundleV2(raw, DefaultLimits())
		require.Error(t, err, name)
	}
	_, err = DecodeBundle(v.raw, DefaultLimits())
	require.ErrorIs(t, err, ErrInvalid, "the version 1 decoder never accepts a version 2 bundle")
	oversized := v.bundle
	oversized.ConfigPDR = make([]byte, MaxConfigPDRBytes+1)
	_, err = oversized.MarshalCBOR()
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorIs(t, Verify([]byte{0x80}, v.trust, v.claim, DefaultLimits()), ErrInvalid)
}

func TestExtractV2RefusesAPDRThatIsNotTheRecordsConfiguration(t *testing.T) {
	v := newV2Fixture(t, nil, 1)
	_, err := ExtractV2(v.f.store, ExtractRequest{Archive: v.f.request.Archive, ConfigPDR: v.f.chain.Full})
	require.ErrorIs(t, err, ErrInvalid)
	_, err = ExtractV2(v.f.store, ExtractRequest{Archive: v.f.request.Archive})
	require.ErrorIs(t, err, ErrUnavailable)
}
