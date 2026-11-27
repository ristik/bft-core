package posclosure

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// On a VR chain the mandatory closure is a UNICITY_VR_CONTROL op 1 whose exposure digest is formed in the VR domain (VR's address in the
// deployment's place, design section 5.6); everything else in it is the P85 closure's.
func TestAVRClosureIsAVRControlInTheVRDomain(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	raw, err := handoffdelivery.EncodeWitnessV3(handoffdelivery.WitnessV3{Proof: f.Proof, Body: f.Body.Encode(), Snapshot: f.Snapshot, Candidate: f.Candidate})
	require.NoError(t, err)
	first := f.Snapshot.ShardInfo[0]
	conf, err := f.ShardConf.Hash(crypto.SHA256)
	require.NoError(t, err)
	hist := fixedHistory{old: f.Old, hash: conf, ids: []evmassign.Identity{testIdentity(1, 6), testIdentity(2, 1)}}
	auth := Authority{Verifier: handoffdelivery.ClosureVerifier{Partition: first.Partition, Shard: first.Shard, History: hist}}
	dep := storage.PosDeployment{RootNetwork: 5, Deployment: evmassign.Deployment{NetworkWord: [32]byte{1}, ChainID: [32]byte{31: 9}, Custody: [20]byte{19: 5}}}
	closed := f.Proof.Record.Epoch

	c, _, err := Proposer{Source: witnessSource{raw}, Authority: auth, Deployment: dep}.Closure(closed, closed+1, 9)
	require.NoError(t, err)
	require.False(t, c.Registry)
	vrDep := dep
	vrDep.Custody = [20]byte{0xff, 19: 1}
	vc, _, err := Proposer{Source: witnessSource{raw}, Authority: auth, Deployment: vrDep, Registry: true}.Closure(closed, closed+1, 9)
	require.NoError(t, err)
	require.True(t, vc.Registry)
	require.Equal(t, vrDep.Custody, vc.Custody)
	require.Equal(t, c.Data[:128], vc.Data[:128], "the same assignment, H and terminal root")
	require.NotEqual(t, c.Data[128:160], vc.Data[128:160], "the exposure digest of the VR domain")
	require.Equal(t, c.Data[160:], vc.Data[160:], "the same key history")
	require.NoError(t, vc.Validate())
}
