package vrhandoff_test

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
	network = 5
	evmPart = 8
)

type key struct {
	signer abcrypto.Signer
	pub    []byte
}

func mkKey(t testing.TB, seed byte) key {
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{seed}, 32))
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return key{signer: s, pub: pub}
}

type member struct {
	root, evm string
	rk, ek    key
}

type fixture struct {
	t       *testing.T
	dep     vradmit.Deployment
	members map[uint64]member
	k, j    []evmassign.Identity
	rc      vrhandoff.RootContext
	out     vrhandoff.Output
	src     vrhandoff.Source
	bc      vrhandoff.BodyContext
	r       vrschema.Word
}

func stakingID(id uint64) []byte { w := vrschema.U64(id); return w[:] }

func (f *fixture) identity(id uint64) evmassign.Identity {
	m := f.members[id]
	var payee [20]byte
	payee[0], payee[19] = 0x9a, byte(id)
	exp := vrschema.PoaExposureDigest(f.dep.NetworkWord, f.dep.ChainID, f.dep.Registry, f.r, id)
	return evmassign.Identity{StakingID: stakingID(id), Generation: 1, RootNodeID: m.root, RootKey: m.rk.pub, EVMNodeID: m.evm, EVMKey: m.ek.pub,
		Weight: 1, RawWeight: 1, OperatorPayee: payee[:], ExposureDigest: exp[:]}
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, members: map[uint64]member{}, r: vrschema.Keccak([]byte("result R"))}
	f.dep = vradmit.Deployment{RootNetwork: network, NetworkWord: vrschema.Keccak([]byte("net")), ChainID: vrschema.U64(3), Registry: vrschema.ValidatorRegistry,
		RegistryCode: vrschema.Keccak([]byte("vr code"))}
	for i := uint64(1); i <= 5; i++ {
		f.members[i] = member{root: "root-" + string(rune('0'+i)), evm: "evm-" + string(rune('0'+i)), rk: mkKey(t, byte(i)), ek: mkKey(t, byte(20+i))}
	}
	var infos []*types.NodeInfo
	for i := uint64(1); i <= 4; i++ {
		f.k = append(f.k, f.identity(i))
		infos = append(infos, &types.NodeInfo{NodeID: f.members[i].evm, SigKey: f.members[i].ek.pub, Stake: 1})
	}
	for _, i := range []uint64{1, 2, 3, 5} {
		f.j = append(f.j, f.identity(i))
	}
	installed := &types.PartitionDescriptionRecord{Version: 1, NetworkID: network, PartitionID: evmPart, PartitionTypeID: evmassign.EVMPartitionTypeID,
		TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 5 * time.Second, Epoch: 3, EpochStart: 11,
		PartitionParams: map[string]string{"chain": "1", "continuity_max_distance": "1/2"}, Validators: infos}
	kd, err := evmassign.IdentitiesDigest(f.k)
	require.NoError(t, err)
	base, err := evmassign.AssignmentHash(installed, kd)
	require.NoError(t, err)
	shard := types.PartitionShardID{PartitionID: evmPart, ShardID: types.ShardID{}.Key()}
	f.rc = vrhandoff.RootContext{Deployment: f.dep, Genesis: [32]byte{0x6e}, RootEpoch: 1, Predecessor: [32]byte{1}, Attempt: 0, AttemptOpenRound: 4390,
		Installed: installed, Lifecycle: evmassign.LifecycleContext{Incumbent: f.k, IncumbentAssignment: base, Policy: continuity.Policy{MaxM: 4, MaxDistNum: 1, MaxDistDen: 2}},
		Fold: vradmit.FoldContext{Network: network, SuccessorRootEpoch: 2, Installed: map[types.PartitionShardID]*types.PartitionDescriptionRecord{shard: installed},
			EVMPartition: evmPart, ControlPartition: evmroot.D4ControlPartition}.Input()}
	limits, err := vrschema.EncodeChange(vrschema.KindCommitteeLimits, uint64(3), uint64(4), uint64(7))
	require.NoError(t, err)
	changes := []vrschema.RegistryChange{{ID: 4, Kind: uint64(vrschema.KindCommitteeLimits), Payload: limits}}
	f.out = f.output(f.j, changes)
	f.src = vrhandoff.Source{ResultID: f.r[:], EVMBlockHash: bytes.Repeat([]byte{0xe7}, 32), EVMBlockNumber: 77, CertRootRound: 4400,
		OutputCommit: bytes.Clone(f.out.State.Output.OutputCommit[:])}
	f.bc = vrhandoff.BodyContext{PredecessorLink: bytes.Repeat([]byte{0x11}, 32), Config: q3format.Q3Config(network, f.rc.Genesis)}
	return f
}

// output is VR's published output of members and changes, with every digest VR computes.
func (f *fixture) output(members []evmassign.Identity, changes []vrschema.RegistryChange) vrhandoff.Output {
	t := f.t
	snap, pol := vrschema.Keccak([]byte("snapshot")), vrschema.Keccak([]byte("policy"))
	s := vradmit.OutputState{ResultID: f.r, Network: f.dep.NetworkWord, OpenOutput: f.r, LastAcked: vrschema.GenesisResult,
		Limits: vrschema.CommitteeLimits{NMin: 4, NTarget: 4, NMax: 7}, Status: vrschema.Status{KnownRootEpoch: 1},
		Output: vrschema.OutputRecord{State: vrschema.OutPublished, Attempt: 7, ReservedProgress: 100, ExpiresAtProgress: 100 + vrschema.Lifetime,
			Predecessor: vrschema.GenesisResult, SourceModule: [20]byte{0xa0, 19: 1}, ModuleTag: vrschema.PoaModuleTag, SnapshotDigest: snap, PolicyDigest: pol}}
	o := &s.Output
	var err error
	o.MembersDigest, err = vradmit.MembersDigestOf(members)
	require.NoError(t, err)
	o.KDigest, err = vradmit.MembersDigestOf(f.k)
	require.NoError(t, err)
	o.ChangesDigest, err = vrschema.ChangesDigestOf(changes)
	require.NoError(t, err)
	o.OutputCommit = vrschema.OutputCommit(vrschema.OutputCommitInput{Network: s.Network, ChainID: f.dep.ChainID, Registry: f.dep.Registry, ResultID: f.r,
		Predecessor: o.Predecessor, Attempt: o.Attempt, ModuleTag: o.ModuleTag, Native: o.Native, SnapshotDigest: o.SnapshotDigest, PolicyDigest: o.PolicyDigest,
		MembersDigest: o.MembersDigest, KDigest: o.KDigest, ChangesDigest: o.ChangesDigest})
	return vrhandoff.Output{State: s, Members: append([]evmassign.Identity(nil), members...), Changes: append([]vrschema.RegistryChange(nil), changes...)}
}

func (f *fixture) byStaking(id []byte) member {
	for i, m := range f.members {
		if bytes.Equal(stakingID(i), id) {
			return m
		}
	}
	f.t.Fatalf("no member %x", id)
	return member{}
}

func (f *fixture) intent() (vrhandoff.Intent, [32]byte) {
	in, d, err := vrhandoff.NewIntent(f.rc, f.src, f.out)
	require.NoError(f.t, err)
	return in, d
}

func (f *fixture) pops(in vrhandoff.Intent) []vrhandoff.PoPOffer {
	var out []vrhandoff.PoPOffer
	for _, m := range f.j {
		p, err := vrhandoff.SignPoP(in, m, f.byStaking(m.StakingID).ek.signer)
		require.NoError(f.t, err)
		out = append(out, p)
	}
	return out
}

func (f *fixture) incumbents() (map[string][]byte, []string) {
	keys := map[string][]byte{}
	var ids []string
	for _, i := range f.k {
		keys[i.RootNodeID] = i.RootKey
		ids = append(ids, i.RootNodeID)
	}
	sort.Strings(ids)
	return keys, ids
}

// assembly assembles and signs view slot's assembly as that view's assembler.
func (f *fixture) assembly(in vrhandoff.Intent, d [32]byte, slot uint64, pops []vrhandoff.PoPOffer) vrhandoff.Assembly {
	_, raw, _, err := vrhandoff.Assemble(in, pops)
	require.NoError(f.t, err)
	_, ids := f.incumbents()
	who := vrhandoff.Assembler(d, ids, slot)
	for _, i := range f.k {
		if i.RootNodeID == who {
			a, err := vrhandoff.SignAssembly(in, slot, raw, f.byStaking(i.StakingID).rk.signer)
			require.NoError(f.t, err)
			return a
		}
	}
	f.t.Fatal("no assembler")
	return vrhandoff.Assembly{}
}

// certificate is the complete certificate of an assembly: every successor's readiness over the derived body and trust base.
func (f *fixture) certificate(in vrhandoff.Intent, a vrhandoff.Assembly) (vrhandoff.ViewCertificate, q3format.BodyV3, []byte) {
	t := f.t
	body, err := vrhandoff.DeriveBody(in, f.rc.RootEpoch, sha256.Sum256(a.Candidate), f.bc)
	require.NoError(t, err)
	_, tb, err := vrhandoff.TrustBase(in, f.rc.RootEpoch)
	require.NoError(t, err)
	rs := map[string]vrhandoff.Readiness{}
	for _, m := range f.j {
		r, err := vrhandoff.SignReadiness(in, a, body, m.RootNodeID, tb, nil, f.byStaking(m.StakingID).rk.signer)
		require.NoError(t, err)
		rs[m.RootNodeID] = r
	}
	c, err := vrhandoff.Certificate(a, f.j, rs, body.Identity())
	require.NoError(t, err)
	return c, body, tb
}
