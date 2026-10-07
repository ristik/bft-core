// Package b1fixture supplies real signatures and independently authenticated
// genesis trie proofs to inactive paired-admission tests.
package b1fixture

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1paired"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

type Fixture struct {
	Pair        *b1paired.Config
	Genesis     *registrygenesis.Genesis
	Origin      registrygenesis.GenesisOrigin
	Parent      registryproof.Snapshot
	Observation rootinput.VerifiedObservationV2
	UC          *types.UnicityCertificate
	TR          *certification.TechnicalRecord
	Chain       *certifiedchain.Chain
	History     *q3format.History
}

func New(t *testing.T, w uint64) *Fixture { return NewWithReservation(t, w, 65536) }
func NewWithReservation(t *testing.T, w, other uint64) *Fixture {
	return newFixture(t, w, other, 0)
}
func NewWithRootStart(t *testing.T, w, start uint64) *Fixture {
	return newFixture(t, w, 65536, start)
}
func newFixture(t *testing.T, w, other, start uint64) *Fixture {
	t.Helper()
	c := certifiedchain.New(t, 5, 0)
	c.TrustBase.EpochStart = start
	clear(c.TrustBase.Signatures)
	require.NoError(t, c.TrustBase.Sign(c.TrustBase.RootNodes[0].NodeID, c.Signer))
	h, err := q3format.NewHistory(c.TrustBase)
	require.NoError(t, err)
	p := b1state.Profile{Network: 5, RootGenesisID: h.Genesis(), ExecutionChainID: 1337, RuntimeHash: [32]byte(common.HexToHash(b1registry.CodeHashHex)), CompilerHash: b1registry.CompilerHash(), WCert: w, DeltaEV: w + 1, DeltaHold: w + 2, RestGas: 1096500 + 1141500*(w+1), CompanionBytes: 1 << 20, OtherCompanionBytes: other, OrdinaryCapacity: 7000000}
	p.SystemGas, err = p.RequiredSystemGas()
	require.NoError(t, err)
	p.MaxGas = p.SystemGas + p.OrdinaryCapacity
	g, err := registrygenesis.GenerateB1(certifiedchain.Config(5), p, h, registrygenesis.EVMParams{GasLimit: p.MaxGas, BaseFee: registrygenesis.DefaultEVMParams.BaseFee})
	require.NoError(t, err)
	full, err := g.FullConfig()
	require.NoError(t, err)
	origin, err := registrygenesis.B1Origin(full, p, h, g.GenesisJSON(), nil, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	parent, err := registryproof.Verify(g.ProofContext(), g.EVMGenesisHash(), g.Evidence())
	require.NoError(t, err)
	rt, err := q3active.New(q3active.Config{DB: memorydb.New(), Genesis: c.TrustBase})
	require.NoError(t, err)
	pair := &b1paired.Config{Profile: p, Runtime: rt, Proofs: func(_ context.Context, s registryproof.Snapshot, keys []common.Hash) ([][][]byte, error) {
		return g.B1Proofs(keys), nil
	}}
	tr := certifiedchain.Technical(0)
	tr.Round = 1
	uc := c.CertifyFor(full, c.Signer, &types.InputRecord{Version: 1}, tr, 5)
	uc.UnicitySeal.NetworkID = 5
	uc.UnicitySeal.Signatures = nil
	verifier, err := c.Signer.Verifier()
	require.NoError(t, err)
	key, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(key)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), c.Signer))
	observation, err := rootinput.AuthenticateObservationV2(context.Background(), rootinput.ObservationContextV2{NetworkID: 5, PartitionID: 8, ShardID: types.ShardID{}, ShardConfHash: g.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: rt.Trust(nil)}, uc, tr)
	require.NoError(t, err)
	return &Fixture{pair, g, origin, parent, observation, uc, tr, c, h}
}
