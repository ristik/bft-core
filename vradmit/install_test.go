package vradmit

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Install paths of the live partition changes (VT-06d AddPartition, VT-06e UpdatePartition): the committed changes of a candidate v6, and
// what they install at the activation round against the installed configurations.

const ixNetwork = 5

func ixKey(t *testing.T, seed byte) (abcrypto.Signer, []byte) {
	t.Helper()
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{seed}, 32))
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return s, pub
}

func ixPDR(t *testing.T, partition types.PartitionID, typeID types.PartitionTypeID, epoch uint64, seeds ...byte) *types.PartitionDescriptionRecord {
	t.Helper()
	p := &types.PartitionDescriptionRecord{Version: 1, NetworkID: ixNetwork, PartitionID: partition, PartitionTypeID: typeID, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Epoch: epoch, PartitionParams: map[string]string{"proof_type": "aggregator_rsmt_v1"}}
	for _, s := range seeds {
		_, pub := ixKey(t, s)
		p.Validators = append(p.Validators, &types.NodeInfo{NodeID: "n" + hex.EncodeToString([]byte{s}), SigKey: pub, Stake: 1})
	}
	return p
}

func ixRaw(t *testing.T, p *types.PartitionDescriptionRecord) []byte {
	t.Helper()
	b, err := types.Cbor.Marshal(p)
	require.NoError(t, err)
	return b
}

// ixAdd is an AddPartition payload with VR-context PoPs for change id.
func ixAdd(t *testing.T, id uint64, p *types.PartitionDescriptionRecord, seeds ...byte) []byte {
	t.Helper()
	raw := ixRaw(t, p)
	var pops []evmassign.PoP
	for i, v := range p.Validators {
		s, _ := ixKey(t, seeds[i])
		msg, err := vrschema.ChangePoPMessage(ixNetwork, vrschema.ValidatorRegistry, id, uint32(p.PartitionID), p.ShardID.Bytes(), raw, v.NodeID)
		require.NoError(t, err)
		sig, err := s.SignBytes(msg)
		require.NoError(t, err)
		pops = append(pops, evmassign.PoP{NodeID: v.NodeID, Key: v.SigKey, Signature: sig})
	}
	pb, err := types.Cbor.Marshal(pops)
	require.NoError(t, err)
	b, err := vrschema.EncodeChange(vrschema.KindAddPartition, raw, pb)
	require.NoError(t, err)
	return b
}

func ixUpdate(t *testing.T, cur, succ *types.PartitionDescriptionRecord) []byte {
	t.Helper()
	h, err := evmassign.PDRHash(cur)
	require.NoError(t, err)
	b, err := vrschema.EncodeChange(vrschema.KindUpdatePartition, uint64(cur.PartitionID), cur.ShardID.Bytes(), h, ixRaw(t, succ))
	require.NoError(t, err)
	return b
}

func ixInstalled(ps ...*types.PartitionDescriptionRecord) map[types.PartitionShardID]*types.PartitionDescriptionRecord {
	out := map[types.PartitionShardID]*types.PartitionDescriptionRecord{}
	for _, p := range ps {
		out[types.PartitionShardID{PartitionID: p.PartitionID, ShardID: p.ShardID.Key()}] = p
	}
	return out
}

func ixFold(installed map[types.PartitionShardID]*types.PartitionDescriptionRecord) vrschema.FoldInput {
	return FoldContext{Network: ixNetwork, SuccessorRootEpoch: 2, Installed: installed, EVMPartition: 8, ControlPartition: 0xFFFFFFFF}.Input()
}

func allSupported(string) bool { return true }

var ixReserved = []types.PartitionID{0xFFFFFFFF, 0xFFFFFFFE, 8}

// The committed changes of a candidate v6 are its Accepted kind 6, 7 and 8 entries, with the candidate change kind each derives (2 for an
// AddPartition, 3 for an UpdatePartition), the target shard and the expected hash; they install at the activation round.
func TestCommittedPartitionChangesInstallAtTheActivationRound(t *testing.T) {
	agg := ixPDR(t, 9, 9, 0, 1)
	succ := ixPDR(t, 9, 9, 1, 1)
	succ.T2Timeout = 4 * time.Second
	succ.PartitionParams["note"] = "v2"
	added := ixPDR(t, 10, 10, 0, 2, 3)
	limits, err := vrschema.EncodeChange(vrschema.KindCommitteeLimits, uint64(1), uint64(4), uint64(7))
	require.NoError(t, err)
	rc := []vrschema.RegistryChange{{ID: 3, Kind: uint64(vrschema.KindCommitteeLimits), Payload: limits}, {ID: 4, Kind: uint64(vrschema.KindAddPartition), Payload: ixAdd(t, 4, added, 2, 3)},
		{ID: 6, Kind: uint64(vrschema.KindUpdatePartition), Payload: ixUpdate(t, agg, succ)}}
	installed := ixInstalled(agg, ixPDR(t, 8, evmassign.EVMPartitionTypeID, 3, 7))
	verdicts, err := vrschema.FoldVerdicts(ixFold(installed), rc)
	require.NoError(t, err)
	require.Equal(t, []uint8{0, 0, 0}, verdicts)
	for i := range rc {
		rc[i].Verdict = uint64(verdicts[i])
	}
	changes, err := CommittedChanges(vrschema.CandidateV6{RegistryChanges: rc})
	require.NoError(t, err)
	require.Len(t, changes, 2)
	require.Equal(t, uint64(evmassign.ChangeAddPartition), changes[0].Derived)
	require.Equal(t, uint64(evmassign.ChangeUpdatePartition), changes[1].Derived)
	h, err := evmassign.PDRHash(agg)
	require.NoError(t, err)
	require.Equal(t, h, changes[1].Expected)

	confs, err := Install(changes, installed, ixReserved, 200, allSupported)
	require.NoError(t, err)
	require.Len(t, confs, 2)
	require.EqualValues(t, 10, confs[0].PartitionID)
	require.EqualValues(t, 0, confs[0].Epoch)
	require.EqualValues(t, 200, confs[0].EpochStart, "the addition starts at the committed activation round")
	require.EqualValues(t, 9, confs[1].PartitionID)
	require.EqualValues(t, 1, confs[1].Epoch)
	require.EqualValues(t, 200, confs[1].EpochStart)
	require.Equal(t, 4*time.Second, confs[1].T2Timeout, "the changed parameters are what the successor installs")
	require.Equal(t, "v2", confs[1].PartitionParams["note"])
	require.Zero(t, changes[0].Successor.EpochStart, "the committed configuration itself is never mutated")

	// a rejected change installs nothing
	rc[2].Verdict = uint64(vrschema.VerdictConflict)
	changes, err = CommittedChanges(vrschema.CandidateV6{RegistryChanges: rc})
	require.NoError(t, err)
	require.Len(t, changes, 1)
	require.Equal(t, vrschema.KindAddPartition, changes[0].Kind)
}

// The install is checked against the installed configurations; a committed change that does not fit them is corrupt history and refused.
func TestInstallRefusals(t *testing.T) {
	agg := ixPDR(t, 9, 9, 0, 1)
	succ := ixPDR(t, 9, 9, 1, 1)
	succ.T2Timeout = 4 * time.Second
	h, err := evmassign.PDRHash(agg)
	require.NoError(t, err)
	update := Change{ID: 6, Kind: vrschema.KindUpdatePartition, Expected: h, Successor: succ, Shard: vrschema.ShardKey{Partition: 9, Shard: string(agg.ShardID.Bytes())}}
	add := func(p *types.PartitionDescriptionRecord) Change {
		return Change{ID: 4, Kind: vrschema.KindAddPartition, Successor: p, Shard: vrschema.ShardKey{Partition: uint32(p.PartitionID), Shard: string(p.ShardID.Bytes())}}
	}
	installed := ixInstalled(agg)
	cases := []struct {
		name    string
		changes []Change
		inst    map[types.PartitionShardID]*types.PartitionDescriptionRecord
		want    error
	}{
		{"an old-hash mismatch", []Change{func() Change { c := update; c.Expected = vrschema.Word{1}; return c }()}, installed, ErrInstall},
		{"an update of a shard that is not installed", []Change{update}, ixInstalled(), ErrInstall},
		{"an update that skips an epoch", []Change{func() Change {
			c := update
			c.Successor = ixPDR(t, 9, 9, 2, 1)
			return c
		}()}, installed, ErrInstall},
		{"an update of the EVM partition", []Change{func() Change {
			evm := ixPDR(t, 9, evmassign.EVMPartitionTypeID, 0, 1)
			eh, _ := evmassign.PDRHash(evm)
			c := update
			c.Expected = eh
			return c
		}()}, ixInstalled(ixPDR(t, 9, evmassign.EVMPartitionTypeID, 0, 1)), ErrInstall},
		{"an addition of an installed partition", []Change{add(ixPDR(t, 9, 9, 0, 2))}, installed, ErrInstall},
		{"an addition of a reserved partition", []Change{add(ixPDR(t, 0xFFFFFFFE, 9, 0, 2))}, installed, ErrInstall},
		{"an addition of the EVM partition id", []Change{add(ixPDR(t, 8, 9, 0, 2))}, installed, ErrInstall},
		{"an EVM-typed addition", []Change{add(ixPDR(t, 11, evmassign.EVMPartitionTypeID, 0, 2))}, installed, ErrInstall},
		{"an addition past epoch 0", []Change{add(ixPDR(t, 11, 9, 1, 2))}, installed, ErrInstall},
		{"a configuration that already has an activation round", []Change{func() Change {
			c := add(ixPDR(t, 11, 9, 0, 2))
			c.Successor.EpochStart = 7
			return c
		}()}, installed, ErrInstall},
		{"a proof type the build cannot verify", []Change{func() Change {
			p := ixPDR(t, 11, 9, 0, 2)
			p.PartitionParams = map[string]string{"proof_type": "sp1", "vkey_path": "/k", "chain_id": "1"}
			return add(p)
		}()}, installed, ErrProofSupportMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Install(tc.changes, tc.inst, ixReserved, 200, func(pt string) bool { return pt != "sp1" })
			require.ErrorIs(t, err, tc.want)
		})
	}
	_, err = Install([]Change{update}, installed, ixReserved, 0, allSupported)
	require.ErrorIs(t, err, ErrInstall, "no activation round")
	confs, err := Install(nil, installed, ixReserved, 200, allSupported)
	require.NoError(t, err)
	require.Empty(t, confs)
}

// A change of a partition added earlier in the same list is judged by the fold against the tentative addition and composes onto it at
// install: the partition starts with the final configuration (one configuration per shard per handoff).
func TestAnUpdateOfAPartitionAddedInTheSameListComposes(t *testing.T) {
	added := ixPDR(t, 10, 10, 0, 2)
	succ := ixPDR(t, 10, 10, 1, 2)
	succ.T2Timeout = 9 * time.Second
	rc := []vrschema.RegistryChange{{ID: 4, Kind: uint64(vrschema.KindAddPartition), Payload: ixAdd(t, 4, added, 2)},
		{ID: 5, Kind: uint64(vrschema.KindUpdatePartition), Payload: ixUpdate(t, added, succ)}}
	installed := ixInstalled(ixPDR(t, 8, evmassign.EVMPartitionTypeID, 3, 7))
	verdicts, err := vrschema.FoldVerdicts(ixFold(installed), rc)
	require.NoError(t, err)
	require.Equal(t, []uint8{0, 0}, verdicts, "the fold accepts the update against the tentative addition")
	changes, err := AcceptedChanges(rc, verdicts)
	require.NoError(t, err)
	confs, err := Install(changes, installed, ixReserved, 200, allSupported)
	require.NoError(t, err)
	require.Len(t, confs, 1)
	require.EqualValues(t, 1, confs[0].Epoch)
	require.Equal(t, 9*time.Second, confs[0].T2Timeout)

	_, err = AcceptedChanges(rc, verdicts[:1])
	require.ErrorIs(t, err, ErrInstall, "one verdict per change")
}

// Vector conformance of the install path: for every frozen fold.verdicts vector that carries a kind 6, 7 or 8 change, the reference fold
// reproduces the vector's verdicts over its FoldInput, and every Accepted root-side change installs over the vector's installed
// configurations: what every root accepts, every root can install.
func TestFoldVectorsAcceptedPartitionChangesInstall(t *testing.T) {
	type change struct {
		ID      uint64 `json:"id"`
		Kind    uint64 `json:"kind"`
		Payload string `json:"payload"`
	}
	type input struct {
		Network            uint64   `json:"network"`
		SuccessorRootEpoch uint64   `json:"successorRootEpoch"`
		Reserved           []uint32 `json:"reserved"`
		Ceiling            uint32   `json:"ceiling"`
		Installed          []struct {
			PDR string `json:"pdr"`
		} `json:"installed"`
		Schedule []struct {
			RuleID          string `json:"ruleId"`
			RootEpoch       uint64 `json:"rootEpoch"`
			NotBeforeUcTime uint64 `json:"notBeforeUcTime"`
			State           uint8  `json:"state"`
		} `json:"schedule"`
		Changes []change `json:"changes"`
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		require.NoError(t, err)
		return b
	}
	ran, installedAny := 0, 0
	for _, v := range vectors(t, "statemachine.json", "fold.verdicts") {
		var in input
		require.NoError(t, json.Unmarshal(v.Input, &in))
		partition := false
		for _, c := range in.Changes {
			k := uint8(c.Kind)
			partition = partition || k == vrschema.KindReplaceAggregator || k == vrschema.KindAddPartition || k == vrschema.KindUpdatePartition
		}
		if !partition {
			continue
		}
		var ex struct {
			Verdicts []uint8 `json:"verdicts"`
		}
		require.NoError(t, json.Unmarshal(v.Expect, &ex), v.Name)
		fi := vrschema.FoldInput{Network: in.Network, SuccessorRootEpoch: in.SuccessorRootEpoch, Installed: map[vrschema.ShardKey]*types.PartitionDescriptionRecord{},
			ReservedPartitions: in.Reserved, PartitionCeiling: in.Ceiling}
		installed := map[types.PartitionShardID]*types.PartitionDescriptionRecord{}
		var reserved []types.PartitionID
		for _, r := range in.Reserved {
			reserved = append(reserved, types.PartitionID(r))
		}
		for _, i := range in.Installed {
			var p types.PartitionDescriptionRecord
			require.NoError(t, types.Cbor.Unmarshal(unhex(i.PDR), &p), v.Name)
			fi.Installed[vrschema.ShardKey{Partition: uint32(p.PartitionID), Shard: string(p.ShardID.Bytes())}] = &p
			installed[types.PartitionShardID{PartitionID: p.PartitionID, ShardID: p.ShardID.Key()}] = &p
		}
		for _, s := range in.Schedule {
			fi.Schedule = append(fi.Schedule, vrschema.Activation{RuleID: vrschema.Word(unhex(s.RuleID)), RootEpoch: s.RootEpoch, NotBeforeUcTime: s.NotBeforeUcTime, State: s.State})
		}
		var rc []vrschema.RegistryChange
		for _, c := range in.Changes {
			rc = append(rc, vrschema.RegistryChange{ID: c.ID, Kind: c.Kind, Payload: unhex(c.Payload)})
		}
		got, err := vrschema.FoldVerdicts(fi, rc)
		require.NoError(t, err, v.Name)
		require.Equal(t, ex.Verdicts, got, v.Name)
		changes, err := AcceptedChanges(rc, got)
		require.NoError(t, err, v.Name)
		confs, err := Install(changes, installed, reserved, 1_000, allSupported)
		require.NoError(t, err, v.Name)
		for _, c := range confs {
			require.EqualValues(t, 1_000, c.EpochStart, v.Name)
		}
		ran++
		if len(confs) > 0 {
			installedAny++
		}
	}
	t.Logf("%d fold vectors with partition changes conform; %d install at least one configuration", ran, installedAny)
	require.Positive(t, installedAny)
}
