package configuredprogress

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

type testTrust struct{ tb *types.RootTrustBaseV1 }

func (t testTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return t.tb, nil
}

type fixture struct {
	t      *testing.T
	c      *certifiedchain.Chain
	origin registrygenesis.GenesisOrigin
	ctx    Context
}

func newFixture(t *testing.T, blocks int) *fixture {
	t.Helper()
	c := certifiedchain.New(t, 3, blocks)
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
	require.Equal(t, c.Blocks[0].Hash, o.BlockHash())
	require.Equal(t, c.Blocks[0].StateRoot, o.StateRoot())
	trust := testTrust{c.TrustBase}
	oc := rootinput.ObservationContextV2{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, ShardConfHash: o.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: trust}
	rc := certifiedstore.Context{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, FullShardConfHash: o.FullShardConfHash().Bytes(), Registry: o.ProofContext(), TrustBases: trust}
	return &fixture{t: t, c: c, origin: o, ctx: Context{Origin: o, Observation: oc, Record: rc}}
}

func (f *fixture) sign(ir *types.InputRecord, assigned, rootRound uint64) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	f.t.Helper()
	tr := certifiedchain.Technical(assigned - 1)
	tr.Round = assigned
	uc := f.c.Certify(f.c.Signer, ir, tr, rootRound)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Signatures = nil
	v, err := f.c.Signer.Verifier()
	require.NoError(f.t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(f.t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(f.t, err)
	require.NoError(f.t, uc.UnicitySeal.Sign(id.String(), f.c.Signer))
	return uc, tr
}
func (f *fixture) observation(ir *types.InputRecord, assigned, root uint64) rootinput.VerifiedObservationV2 {
	u, tr := f.sign(ir, assigned, root)
	o, err := rootinput.AuthenticateObservationV2(context.Background(), f.ctx.Observation, u, tr)
	require.NoError(f.t, err)
	return o
}
func (f *fixture) bootstrap(assigned, root uint64) rootinput.VerifiedObservationV2 {
	return f.observation(&types.InputRecord{Version: 1}, assigned, root)
}
func (f *fixture) first(i int, assigned, root uint64) rootinput.VerifiedObservationV2 {
	b := f.c.Blocks[i]
	return f.observation(&types.InputRecord{Version: 1, RoundNumber: b.Round, Hash: b.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000 + b.Round, BlockHash: b.Hash.Bytes()}, assigned, root)
}
func (f *fixture) ordinary(i int, assigned, root uint64) rootinput.VerifiedObservationV2 {
	return f.observation(f.c.InputRecord(i), assigned, root)
}
func (f *fixture) record(i int, obs rootinput.VerifiedObservationV2) certifiedstore.Record {
	b := f.c.Blocks[i]
	return certifiedstore.Record{BlockHash: b.Hash, BlockNumber: b.Number, StateRoot: b.StateRoot, PartitionRound: b.Round, Certificate: obs.Certificate(), Technical: obs.TechnicalRecord(), Witness: b.Evidence}
}
func (f *fixture) open(retain int) (*Store, string) {
	f.t.Helper()
	path := f.t.TempDir() + "/progress.db"
	s, err := OpenConfiguredV2(path, Settings{Retain: retain})
	require.NoError(f.t, err)
	return s, path
}
