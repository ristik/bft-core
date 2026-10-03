package consensus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/frontiertransport"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/internal/frontiercodec"
	rctest "github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestFrontierHandlersRequireTheSigningSampler(t *testing.T) {
	_, shardInfos := rctest.CreateTestNodes(t, 1)
	plain, _ := createConsensusManagersWithOptions(t, 1, shardInfos, nil, nil)
	_, err := plain[0].FrontierHandlers()
	require.ErrorIs(t, err, ErrFrontierSigningDisabled)
	_, err = (*ConsensusManager)(nil).FrontierHandlers()
	require.ErrorIs(t, err, ErrFrontierSigningDisabled)

	sampling, _ := createConsensusManagersWithOptions(t, 1, shardInfos, func(tb *types.RootTrustBaseV1) []Option {
		return []Option{WithFrontierSampler(DefaultFrontierSamplerConfig(tb))}
	}, nil)
	_, err = sampling[0].FrontierHandlers()
	require.ErrorIs(t, err, ErrFrontierSigningDisabled, "an unsigned sampler serves nothing")

	signing, _ := createConsensusManagersWithOptions(t, 1, shardInfos, func(tb *types.RootTrustBaseV1) []Option {
		return []Option{WithFrontierSampler(DefaultFrontierSamplerConfig(tb)), WithFrontierSigning()}
	}, nil)
	handlers, err := signing[0].FrontierHandlers()
	require.NoError(t, err)
	require.NotNil(t, handlers.Frontier)
	require.NotNil(t, handlers.Cut)
}

// A root serves only the one root epoch and network it was pinned to; other contexts are refused before any
// storage read.
func TestFrontierCutServiceRefusesAnotherRootEpochOrNetwork(t *testing.T) {
	_, shardInfos := rctest.CreateTestNodes(t, 1)
	cms, _ := createConsensusManagersWithOptions(t, 1, shardInfos, func(tb *types.RootTrustBaseV1) []Option {
		return []Option{WithFrontierSampler(DefaultFrontierSamplerConfig(tb)), WithFrontierSigning()}
	}, nil)
	cm := cms[0]
	good := frontiercodec.Context{NetworkID: cm.frontier.trust.NetworkID, PartitionID: partitionID, CanonicalShardBytes: shardID.Bytes(), RootEpoch: cm.frontier.trust.Epoch}
	for name, mutate := range map[string]func(*frontiercodec.Context){
		"root epoch": func(c *frontiercodec.Context) { c.RootEpoch++ },
		"network":    func(c *frontiercodec.Context) { c.NetworkID++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := good
			mutate(&bad)
			_, err := cm.serveCut(context.Background(), frontiertransport.CutRequest{Context: bad})
			require.ErrorIs(t, err, ErrFrontierUnavailable)
		})
	}
}

func TestValidateFrontierProfileEnforcesTheFixedProfile(t *testing.T) {
	_, shardInfos := rctest.CreateTestNodes(t, 1)
	cms, _ := createConsensusManagersWithOptions(t, 4, shardInfos, func(tb *types.RootTrustBaseV1) []Option {
		return []Option{WithFrontierSampler(DefaultFrontierSamplerConfig(tb))}
	}, nil)
	good := cms[0].frontier.trust
	require.NoError(t, ValidateFrontierProfile(good))
	require.ErrorIs(t, ValidateFrontierProfile(nil), ErrFrontierProfile)

	weighted := *good
	weighted.RootNodes = append([]*types.NodeInfo(nil), good.RootNodes...)
	first := weighted.RootNodes[0]
	weighted.RootNodes[0] = &types.NodeInfo{NodeID: first.NodeID, SigKey: first.SigKey, Stake: 2}
	require.ErrorIs(t, ValidateFrontierProfile(&weighted), ErrFrontierProfile, "weighted roots are outside the profile")

	lowQuorum := *good
	lowQuorum.QuorumThreshold = uint64(len(good.RootNodes)) * 2 / 3
	require.ErrorIs(t, ValidateFrontierProfile(&lowQuorum), ErrFrontierProfile, "q must exceed 2N/3")
}

// A root that joined after the pinned trust base was cut (a successor member of the handoff profile) is not
// enrolled in it. It must be able to find that out before building its consensus manager, which refuses it.
func TestValidateFrontierSignerRequiresEnrollmentUnderThePinnedTrustBase(t *testing.T) {
	nodes, infos := rctest.CreateTestNodes(t, 3)
	trust, err := types.NewTrustBase(5, infos[:2])
	require.NoError(t, err)
	id := func(i int) string { return nodes[i].PeerConf.ID.String() }

	require.NoError(t, ValidateFrontierSigner(trust, id(0), nodes[0].Signer))
	require.ErrorIs(t, ValidateFrontierSigner(trust, id(2), nodes[2].Signer), ErrFrontierSigner, "a later member is not in the pinned trust base")
	require.ErrorIs(t, ValidateFrontierSigner(trust, id(0), nodes[1].Signer), ErrFrontierSigner, "the enrolled identity with another key")
	require.ErrorIs(t, ValidateFrontierSigner(trust, "", nodes[0].Signer), ErrFrontierSigner)
	require.ErrorIs(t, ValidateFrontierSigner(trust, id(0), nil), ErrFrontierSigner)
	require.ErrorIs(t, ValidateFrontierSigner(nil, id(0), nodes[0].Signer), ErrFrontierProfile)

	// The same check is what refuses the manager: the validation and the constructor cannot disagree.
	_, shardInfos := rctest.CreateTestNodes(t, 1)
	cms, _ := createConsensusManagersWithOptions(t, 1, shardInfos, func(tb *types.RootTrustBaseV1) []Option {
		return []Option{WithFrontierSampler(DefaultFrontierSamplerConfig(tb)), WithFrontierSigning()}
	}, nil)
	require.NotNil(t, cms[0].frontier)
	require.True(t, cms[0].frontier.signing)
}
