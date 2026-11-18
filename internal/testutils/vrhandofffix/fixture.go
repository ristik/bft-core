// Package vrhandofffix is the VR handoff protocol fixture shared by the vrhandoff and vrschedule tests: K = identities 1..4 acknowledged on
// the EVM shard, VR's published output R electing J = 1, 2, 3, 5 with one CommitteeLimits change, real secp256k1 keys.
package vrhandofffix

import (
	"bytes"
	"crypto/sha256"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/continuity"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The protocol fixture: K = identities 1..4 is the acknowledged committee installed on the EVM shard (partition 8, epoch 3); VR's
// published output R elects J = 1, 2, 3, 5 with one CommitteeLimits change bound. Every key is a real secp256k1 key.

const (
	Network = 5
	EVMPart = 8
)

type Key struct {
	Signer abcrypto.Signer
	Pub    []byte
}

func MkKey(t testing.TB, seed byte) Key {
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{seed}, 32))
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return Key{Signer: s, Pub: pub}
}

type Member struct {
	Root, EVM string
	RK, EK    Key
}

type Fixture struct {
	T       *testing.T
	Dep     vradmit.Deployment
	Members map[uint64]Member
	K, J    []evmassign.Identity
	RC      vrhandoff.RootContext
	Out     vrhandoff.Output
	Src     vrhandoff.Source
	BC      vrhandoff.BodyContext
	R       vrschema.Word
}

func StakingID(id uint64) []byte { w := vrschema.U64(id); return w[:] }

func (f *Fixture) Identity(id uint64) evmassign.Identity {
	m := f.Members[id]
	var payee [20]byte
	payee[0], payee[19] = 0x9a, byte(id)
	exp := vrschema.PoaExposureDigest(f.Dep.NetworkWord, f.Dep.ChainID, f.Dep.Registry, f.R, id)
	return evmassign.Identity{StakingID: StakingID(id), Generation: 1, RootNodeID: m.Root, RootKey: m.RK.Pub, EVMNodeID: m.EVM, EVMKey: m.EK.Pub,
		Weight: 1, RawWeight: 1, OperatorPayee: payee[:], ExposureDigest: exp[:]}
}

func New(t *testing.T) *Fixture {
	f := &Fixture{T: t, Members: map[uint64]Member{}, R: vrschema.Keccak([]byte("result R"))}
	f.Dep = vradmit.Deployment{RootNetwork: Network, NetworkWord: vrschema.Keccak([]byte("net")), ChainID: vrschema.U64(3), Registry: vrschema.ValidatorRegistry,
		RegistryCode: vrschema.Keccak([]byte("vr code"))}
	for i := uint64(1); i <= 5; i++ {
		f.Members[i] = Member{Root: "root-" + string(rune('0'+i)), EVM: "evm-" + string(rune('0'+i)), RK: MkKey(t, byte(i)), EK: MkKey(t, byte(20+i))}
	}
	var infos []*types.NodeInfo
	for i := uint64(1); i <= 4; i++ {
		f.K = append(f.K, f.Identity(i))
		infos = append(infos, &types.NodeInfo{NodeID: f.Members[i].EVM, SigKey: f.Members[i].EK.Pub, Stake: 1})
	}
	for _, i := range []uint64{1, 2, 3, 5} {
		f.J = append(f.J, f.Identity(i))
	}
	installed := &types.PartitionDescriptionRecord{Version: 1, NetworkID: Network, PartitionID: EVMPart, PartitionTypeID: evmassign.EVMPartitionTypeID,
		TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 5 * time.Second, Epoch: 3, EpochStart: 11,
		PartitionParams: map[string]string{"chain": "1", "continuity_max_distance": "1/2"}, Validators: infos}
	kd, err := evmassign.IdentitiesDigest(f.K)
	require.NoError(t, err)
	base, err := evmassign.AssignmentHash(installed, kd)
	require.NoError(t, err)
	shard := types.PartitionShardID{PartitionID: EVMPart, ShardID: types.ShardID{}.Key()}
	f.RC = vrhandoff.RootContext{Deployment: f.Dep, Genesis: [32]byte{0x6e}, RootEpoch: 1, Predecessor: [32]byte{1}, Attempt: 0, AttemptOpenRound: 4390,
		Installed: installed, Lifecycle: evmassign.LifecycleContext{Incumbent: f.K, IncumbentAssignment: base, Policy: continuity.Policy{MaxM: 4, MaxDistNum: 1, MaxDistDen: 2}},
		Fold: vradmit.FoldContext{Network: Network, SuccessorRootEpoch: 2, Installed: map[types.PartitionShardID]*types.PartitionDescriptionRecord{shard: installed},
			EVMPartition: EVMPart, ControlPartition: evmroot.D4ControlPartition}.Input()}
	limits, err := vrschema.EncodeChange(vrschema.KindCommitteeLimits, uint64(3), uint64(4), uint64(7))
	require.NoError(t, err)
	changes := []vrschema.RegistryChange{{ID: 4, Kind: uint64(vrschema.KindCommitteeLimits), Payload: limits}}
	f.Out = f.Output(f.J, changes)
	f.Src = vrhandoff.Source{ResultID: f.R[:], EVMBlockHash: bytes.Repeat([]byte{0xe7}, 32), EVMBlockNumber: 77, CertRootRound: 4400,
		OutputCommit: bytes.Clone(f.Out.State.Output.OutputCommit[:])}
	f.BC = vrhandoff.BodyContext{PredecessorLink: bytes.Repeat([]byte{0x11}, 32), Config: q3format.Q3Config(Network, f.RC.Genesis)}
	return f
}

// output is VR's published output of members and changes, with every digest VR computes.
func (f *Fixture) Output(members []evmassign.Identity, changes []vrschema.RegistryChange) vrhandoff.Output {
	t := f.T
	snap, pol := vrschema.Keccak([]byte("snapshot")), vrschema.Keccak([]byte("policy"))
	s := vradmit.OutputState{ResultID: f.R, Network: f.Dep.NetworkWord, OpenOutput: f.R, LastAcked: vrschema.GenesisResult,
		Limits: vrschema.CommitteeLimits{NMin: 4, NTarget: 4, NMax: 7}, Status: vrschema.Status{KnownRootEpoch: 1},
		Output: vrschema.OutputRecord{State: vrschema.OutPublished, Attempt: 7, ReservedProgress: 100, ExpiresAtProgress: 100 + vrschema.Lifetime,
			Predecessor: vrschema.GenesisResult, SourceModule: [20]byte{0xa0, 19: 1}, ModuleTag: vrschema.PoaModuleTag, SnapshotDigest: snap, PolicyDigest: pol}}
	o := &s.Output
	var err error
	o.MembersDigest, err = vradmit.MembersDigestOf(members)
	require.NoError(t, err)
	o.KDigest, err = vradmit.MembersDigestOf(f.K)
	require.NoError(t, err)
	o.ChangesDigest, err = vrschema.ChangesDigestOf(changes)
	require.NoError(t, err)
	o.OutputCommit = vrschema.OutputCommit(vrschema.OutputCommitInput{Network: s.Network, ChainID: f.Dep.ChainID, Registry: f.Dep.Registry, ResultID: f.R,
		Predecessor: o.Predecessor, Attempt: o.Attempt, ModuleTag: o.ModuleTag, Native: o.Native, SnapshotDigest: o.SnapshotDigest, PolicyDigest: o.PolicyDigest,
		MembersDigest: o.MembersDigest, KDigest: o.KDigest, ChangesDigest: o.ChangesDigest})
	return vrhandoff.Output{State: s, Members: append([]evmassign.Identity(nil), members...), Changes: append([]vrschema.RegistryChange(nil), changes...)}
}

func (f *Fixture) ByStaking(id []byte) Member {
	for i, m := range f.Members {
		if bytes.Equal(StakingID(i), id) {
			return m
		}
	}
	f.T.Fatalf("no member %x", id)
	return Member{}
}

func (f *Fixture) Intent() (vrhandoff.Intent, [32]byte) {
	in, d, err := vrhandoff.NewIntent(f.RC, f.Src, f.Out)
	require.NoError(f.T, err)
	return in, d
}

func (f *Fixture) PoPs(in vrhandoff.Intent) []vrhandoff.PoPOffer {
	var out []vrhandoff.PoPOffer
	for _, m := range f.J {
		p, err := vrhandoff.SignPoP(in, m, f.ByStaking(m.StakingID).EK.Signer)
		require.NoError(f.T, err)
		out = append(out, p)
	}
	return out
}

func (f *Fixture) Incumbents() (map[string][]byte, []string) {
	keys := map[string][]byte{}
	var ids []string
	for _, i := range f.K {
		keys[i.RootNodeID] = i.RootKey
		ids = append(ids, i.RootNodeID)
	}
	sort.Strings(ids)
	return keys, ids
}

// assembly assembles and signs view slot's assembly as that view's assembler.
func (f *Fixture) Assembly(in vrhandoff.Intent, d [32]byte, slot uint64, pops []vrhandoff.PoPOffer) vrhandoff.Assembly {
	_, raw, _, err := vrhandoff.Assemble(in, pops)
	require.NoError(f.T, err)
	_, ids := f.Incumbents()
	who := vrhandoff.Assembler(d, ids, slot)
	for _, i := range f.K {
		if i.RootNodeID == who {
			a, err := vrhandoff.SignAssembly(in, slot, raw, f.ByStaking(i.StakingID).RK.Signer)
			require.NoError(f.T, err)
			return a
		}
	}
	f.T.Fatal("no assembler")
	return vrhandoff.Assembly{}
}

// certificate is the complete certificate of an assembly: every successor's readiness over the derived body and trust base.
func (f *Fixture) Certificate(in vrhandoff.Intent, a vrhandoff.Assembly) (vrhandoff.ViewCertificate, q3format.BodyV3, []byte) {
	t := f.T
	body, err := vrhandoff.DeriveBody(in, f.RC.RootEpoch, sha256.Sum256(a.Candidate), f.BC)
	require.NoError(t, err)
	_, tb, err := vrhandoff.TrustBase(in, f.RC.RootEpoch)
	require.NoError(t, err)
	rs := map[string]vrhandoff.Readiness{}
	for _, m := range f.J {
		r, err := vrhandoff.SignReadiness(in, a, body, m.RootNodeID, tb, nil, f.ByStaking(m.StakingID).RK.Signer)
		require.NoError(t, err)
		rs[m.RootNodeID] = r
	}
	c, err := vrhandoff.Certificate(a, f.J, rs, body.Identity())
	require.NoError(t, err)
	return c, body, tb
}
