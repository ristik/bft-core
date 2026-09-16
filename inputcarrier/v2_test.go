package inputcarrier

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

type mutatingV2Trust struct {
	tb     *types.RootTrustBaseV1
	mutate func()
}

func (m mutatingV2Trust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	m.mutate()
	return m.tb, nil
}

func bootstrapV2(t *testing.T) (rootinput.ObservationContextV2, rootinput.ContextV2, Envelope, Header) {
	c := certifiedchain.New(t, 3, 0)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(c.Genesis.GenesisJSON(), &doc))
	var alloc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc["alloc"], &alloc))
	for k := range alloc {
		if strings.EqualFold(strings.TrimPrefix(k, "0x"), strings.TrimPrefix(registryproof.RegistryAddress.Hex(), "0x")) {
			delete(alloc, k)
		}
	}
	doc["alloc"], _ = json.Marshal(alloc)
	source, _ := json.Marshal(doc)
	art, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)
	p, err := registrygenesis.PrepareGenesisJSON(certifiedchain.Config(3), c.Pins, art, source, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	o := p.Origin()
	snap, err := registryproof.Verify(o.ProofContext(), o.BlockHash(), o.Evidence())
	require.NoError(t, err)
	tr := certifiedchain.Technical(0)
	tr.Round = 1
	uc := c.Certify(c.Signer, &types.InputRecord{Version: 1}, tr, 4)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Signatures = nil
	v, _ := c.Signer.Verifier()
	pk, _ := v.MarshalPublicKey()
	id, _ := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), c.Signer))
	require.NoError(t, uc.Verify(c.TrustBase, crypto.SHA256, 8, types.ShardID{}, o.FullShardConfHash().Bytes()))
	ucb, err := types.Cbor.Marshal(uc)
	require.NoError(t, err)
	trb, err := types.Cbor.Marshal(tr)
	require.NoError(t, err)
	oc := rootinput.ObservationContextV2{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, ShardConfHash: o.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: mutatingV2Trust{tb: c.TrustBase, mutate: func() {}}}
	dc := rootinput.ContextV2{Genesis: o, Parent: snap, Round: 1, ParentHash: o.BlockHash().Bytes()}
	obs, err := rootinput.AuthenticateObservationV2(context.Background(), oc, uc, tr)
	require.NoError(t, err)
	derived, err := rootinput.DeriveV2(dc, obs)
	require.NoError(t, err)
	block := bytes.Repeat([]byte{0x44}, 32)
	env := Envelope{Version: VersionV2, ShardRound: 1, BlockHash: block, Certificate: ucb, TechnicalRecord: trb}
	h := Header{Hash: block, ParentHash: o.BlockHash().Bytes(), ExtraData: derived.Commitment[:]}
	return oc, dc, env, h
}

func TestV2EnvelopeVersionIsolationAndOwnership(t *testing.T) {
	oc, dc, env, h := bootstrapV2(t)
	enc, err := EncodeV2(env, DefaultLimits)
	require.NoError(t, err)
	decoded, err := DecodeV2(enc, DefaultLimits)
	require.NoError(t, err)
	require.Equal(t, env, decoded)
	_, err = Encode(env, DefaultLimits)
	require.ErrorIs(t, err, ErrMalformedEnvelope)
	_, err = Decode(enc, DefaultLimits)
	require.ErrorIs(t, err, ErrMalformedEnvelope)
	callerParent := dc.ParentHash
	oc.TrustBases = mutatingV2Trust{tb: oc.TrustBases.(mutatingV2Trust).tb, mutate: func() {
		for i := range callerParent {
			callerParent[i] ^= 0xff
		}
	}}
	res, err := VerifyV2(context.Background(), oc, dc, env, h)
	require.NoError(t, err)
	require.Equal(t, h.ParentHash, res.Input.ParentHash, "the context was copied before the trust callback")
	res.Input.ParentHash[0] ^= 1
	res.Encoded[0] ^= 1
	require.NotEqual(t, res.Input.ParentHash, dc.ParentHash)
}
