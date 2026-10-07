package b1paired_test

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/b1paired"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestAuthenticatedSupersessionProjectsOnlySurvivingEpochs(t *testing.T) {
	first := q3fixture.New(t, q3fixture.Options{})
	second := q3fixture.New(t, q3fixture.Options{After: first})
	process := q3process.New(t, first)
	rt := process.Start()
	ctx := context.Background()
	require.NoError(t, rt.Activate(ctx, process.Bundle()))
	require.NoError(t, rt.Activate(ctx, q3active.Bundle{Envelope: second.EnvelopeBytes, Snapshot: second.Snapshot}))
	c := certifiedchain.New(t, 5, 0)
	for _, w := range []uint64{0, 15} {
		t.Run(string(rune('A'+w)), func(t *testing.T) {
			p := b1state.Profile{Network: 5, RootGenesisID: first.Genesis, ExecutionChainID: 1337, RuntimeHash: [32]byte(common.HexToHash(b1registry.CodeHashHex)), CompilerHash: b1registry.CompilerHash(), WCert: w, DeltaEV: w + 1, DeltaHold: w + 2, RestGas: 1096500 + 1141500*(w+1), CompanionBytes: 1 << 20, OtherCompanionBytes: 65536, OrdinaryCapacity: 7000000}
			p.SystemGas, _ = p.RequiredSystemGas()
			p.MaxGas = p.SystemGas + p.OrdinaryCapacity
			g, err := registrygenesis.GenerateB1(certifiedchain.Config(5), p, rt.History(), registrygenesis.EVMParams{GasLimit: p.MaxGas})
			require.NoError(t, err)
			full, err := g.FullConfig()
			require.NoError(t, err)
			parent, err := registryproof.Verify(g.ProofContext(), g.EVMGenesisHash(), g.Evidence())
			require.NoError(t, err)
			pair := &b1paired.Config{Profile: p, Runtime: rt, Proofs: func(_ context.Context, _ registryproof.Snapshot, keys []common.Hash) ([][][]byte, error) {
				return g.B1Proofs(keys), nil
			}}
			signed := func(epoch, round uint64) rootinput.VerifiedObservationV2 {
				tr := certifiedchain.Technical(0)
				uc := c.CertifyFor(full, second.NewNodes[0].Signer, &types.InputRecord{Version: 1}, tr, round)
				uc.UnicitySeal.NetworkID = 5
				uc.UnicitySeal.Epoch = epoch
				uc.UnicitySeal.Signatures = nil
				nodes := second.NewNodes
				if epoch == 1 {
					nodes = first.OldNodes
				}
				count := 2
				if epoch == 1 {
					count = 3
				}
				for _, node := range nodes[:count] {
					require.NoError(t, uc.UnicitySeal.Sign(node.PeerConf.ID.String(), node.Signer))
				}
				o, err := rootinput.AuthenticateHistoricalObservationV2(ctx, rootinput.ObservationContextV2{NetworkID: 5, PartitionID: 8, ShardConfHash: g.FullShardConfHash().Bytes(), RootEpoch: 3, EpochAuthority: installedEpoch(3), TrustBases: rt.Trust(nil)}, uc, tr)
				require.NoError(t, err)
				return o
			}
			result, err := pair.Derive(ctx, parent, signed(3, 15))
			require.NoError(t, err)
			update, _, err := b1state.Admit(result.Update, p, p.SystemGas)
			require.NoError(t, err)
			require.NotNil(t, update.OldTipEnd)
			require.EqualValues(t, 7, *update.OldTipEnd)
			if w == 0 {
				require.Len(t, update.NewEntries, 1)
				require.EqualValues(t, 3, update.NewEntries[0].Epoch)
			} else {
				require.Len(t, update.NewEntries, 2)
				require.EqualValues(t, 2, update.NewEntries[0].Epoch)
				require.EqualValues(t, 15, *update.NewEntries[0].End)
			}
			require.Equal(t, second.Body.Identity(), update.NewEntries[len(update.NewEntries)-1].BodyID)
			_, err = pair.Derive(ctx, parent, signed(1, 8))
			require.ErrorIs(t, err, q3format.ErrOutsideInterval, "authenticated old suffix is not ordinary admission")
		})
	}
}

type installedEpoch uint64

func (e installedEpoch) CurrentRootEpoch() (uint64, bool) { return uint64(e), true }
