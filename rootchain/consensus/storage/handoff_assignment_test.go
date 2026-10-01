package storage

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type evmKey struct {
	id     string
	signer abcrypto.Signer
	info   *types.NodeInfo
}

func newEVMKey(t *testing.T, id string) evmKey {
	t.Helper()
	s, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return evmKey{id: id, signer: s, info: &types.NodeInfo{NodeID: id, SigKey: pub, Stake: 1}}
}

// assignmentFixture is a four-root-node network whose single EVM shard has a
// valid installed PDR, ready for an EVM-only assignment handoff.
type assignmentFixture struct {
	store       *BlockStore
	signers     map[string]abcrypto.Signer
	tb          *types.RootTrustBaseV1
	predecessor []byte
	parent      []byte
	current     *types.PartitionDescriptionRecord
	shard       types.PartitionShardID
	oldKeys     []evmKey
	nextKeys    []evmKey
	succ        *types.PartitionDescriptionRecord
	pop         evmassign.PoPContext
	orch        *partitions.Orchestration
	base        uint64 // ordered round of the prepare record; zero means 2
}

func newAssignmentFixture(t *testing.T) *assignmentFixture {
	t.Helper()
	s := profileStore(t)
	f := &assignmentFixture{store: s, parent: bytes.Repeat([]byte{5}, 32), signers: map[string]abcrypto.Signer{}}
	for _, id := range []string{"old-a", "old-b", "old-c", "old-d"} {
		signer, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		f.signers[id] = signer
	}
	f.tb = testtrustbase.NewTrustBaseFromSigners(t, f.signers).(*types.RootTrustBaseV1)
	require.NoError(t, s.ConfigureHandoffAuthority(f.tb))
	var err error
	f.predecessor, err = f.tb.Hash(crypto.SHA256)
	require.NoError(t, err)

	f.oldKeys = []evmKey{newEVMKey(t, "ev-a"), newEVMKey(t, "ev-b"), newEVMKey(t, "ev-c"), newEVMKey(t, "ev-d")}
	infos := make([]*types.NodeInfo, 0, 4)
	for _, k := range f.oldKeys {
		infos = append(infos, k.info)
	}
	f.current = &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8,
		TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 5 * time.Second, Epoch: 0, EpochStart: 1,
		PartitionParams: map[string]string{"seal_registry_genesis": "g"}, Validators: infos}
	f.installShard(t, f.current, func(si *ShardInfo) { si.IR.BlockHash = bytes.Clone(f.parent) })

	// Keep one old key and add three new ones: retained keys prove possession too.
	f.nextKeys = []evmKey{f.oldKeys[0], newEVMKey(t, "ev-e"), newEVMKey(t, "ev-f"), newEVMKey(t, "ev-g")}
	next := make([]*types.NodeInfo, 0, 4)
	for _, k := range f.nextKeys {
		next = append(next, k.info)
	}
	f.succ, err = evmassign.NewSuccessor(f.current, next)
	require.NoError(t, err)
	f.pop = evmassign.PoPContext{Network: 5, Attempt: 0}
	copy(f.pop.Predecessor[:], f.predecessor)
	copy(f.pop.Parent[:], f.parent)
	return f
}

func (f *assignmentFixture) installShard(t *testing.T, conf *types.PartitionDescriptionRecord, tweak func(*ShardInfo)) {
	t.Helper()
	si, err := NewShardInfo(conf, crypto.SHA256)
	require.NoError(t, err)
	tweak(si)
	f.shard = types.PartitionShardID{PartitionID: conf.PartitionID, ShardID: conf.ShardID.Key()}
	if f.orch == nil {
		f.store.orchestration = mockOrchestration{shardConfigs: func(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
			return map[types.PartitionShardID]*types.PartitionDescriptionRecord{f.shard: conf}, nil
		}}
	}
	root := f.store.blockTree.Root()
	root.ShardState.States[f.shard] = si
	tree, _, err := root.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	root.RootHash = tree.RootHash()
	if root.CommitQc != nil && root.CommitQc.LedgerCommitInfo != nil {
		root.CommitQc.LedgerCommitInfo.Hash = root.RootHash
	}
	require.NoError(t, f.store.storage.WriteBlock(root, true))
}

func (f *assignmentFixture) rootMembers() []evmassign.RootMember {
	out := make([]evmassign.RootMember, 0, len(f.tb.RootNodes))
	for _, n := range f.tb.RootNodes {
		out = append(out, evmassign.RootMember{NodeID: n.NodeID, Key: n.SigKey, Weight: n.Stake})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

func (f *assignmentFixture) pops(t *testing.T, ctx evmassign.PoPContext, succ *types.PartitionDescriptionRecord) []evmassign.PoP {
	t.Helper()
	var out []evmassign.PoP
	for _, v := range succ.Validators {
		for _, k := range append(append([]evmKey(nil), f.oldKeys...), f.nextKeys...) {
			if k.id == v.NodeID {
				p, err := evmassign.SignPoP(k.signer, ctx, succ, k.id)
				require.NoError(t, err)
				out = append(out, p)
				break
			}
		}
	}
	require.Len(t, out, len(succ.Validators))
	return out
}

func (f *assignmentFixture) candidate(t *testing.T) evmassign.Candidate {
	t.Helper()
	raw, err := types.Cbor.Marshal(f.succ)
	require.NoError(t, err)
	old, err := evmassign.PDRHash(f.current)
	require.NoError(t, err)
	return evmassign.Candidate{Version: evmassign.CandidateVersion, Network: 5, Predecessor: bytes.Clone(f.predecessor),
		Attempt: f.pop.Attempt, Parent: bytes.Clone(f.parent), RootMembers: f.rootMembers(), OldShardEpoch: f.current.Epoch,
		OldActiveHash: old[:], Assignment: raw, PoPs: f.pops(t, f.pop, f.succ)}
}

type builtFreeze struct {
	body      evmroot.TrustBaseBodyV2
	prepare   evmroot.OrderedHandoffRecord
	freeze    evmroot.OrderedHandoffRecord
	companion []byte
	preimage  []byte
}

// build links a candidate into the D3 body, FrozenID, record and companion,
// so a mutation of the candidate is caught only by the check that owns it.
func (f *assignmentFixture) build(t *testing.T, c evmassign.Candidate, mutate ...func(*FreezeAssignmentAuthorization, *evmroot.TrustBaseBodyV2)) builtFreeze {
	t.Helper()
	raw, err := c.Encode()
	require.NoError(t, err)
	digest := sha256.Sum256(raw)
	link, err := evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1, NetworkID: 5, Epoch: 1, HashIncludingSigs: f.predecessor})
	require.NoError(t, err)
	members := make(evmroot.WeightSet, 0, len(f.tb.RootNodes))
	for _, n := range f.tb.RootNodes {
		members = append(members, evmroot.Member{StakingID: n.NodeID, NodeID: n.NodeID, ConsensusKey: n.SigKey, Weight: 1})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].NodeID < members[j].NodeID })
	body := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: 5, Epoch: 2, EarliestActivation: 7, Members: members,
		RootThreshold:    evmroot.RootQuorumThreshold(uint64(len(members))),
		StateSummary:     bytes.Repeat([]byte{3}, 32),
		ChangeRecordHash: evmroot.D4CandidateContextHash(5, f.predecessor, f.pop.Attempt, digest[:], 7), PredecessorHash: link}
	auth := FreezeAssignmentAuthorization{Version: 2, Parent: bytes.Clone(f.parent), Candidate: digest[:], Preimage: raw}
	for _, m := range mutate {
		m(&auth, &body)
	}
	require.NoError(t, body.Validate())
	auth.Body = body.Encode()
	id := body.Identity()
	frozen := evmroot.D4FrozenID(id[:], body.StateSummary, f.parent, auth.Candidate, f.pop.Attempt, f.predecessor)
	base := f.base
	if base == 0 {
		base = 2
	}
	freeze := evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, Attempt: f.pop.Attempt, OrderedRound: base + 1, ActivationRound: 7 + base - 2,
		PredecessorBodyID: f.predecessor, NextBodyID: id[:], FrozenID: frozen, SuccessorTRHash: make([]byte, 32), Kind: "freeze"}
	prepare := freeze
	prepare.Kind, prepare.OrderedRound, prepare.FrozenID = "prepare", base, make([]byte, 32)
	message, err := EndorsementBytes(freeze)
	require.NoError(t, err)
	auth.Signatures = map[string]hex.Bytes{}
	for _, name := range []string{"old-a", "old-b", "old-c"} {
		sig, err := f.signers[name].SignBytes(message)
		require.NoError(t, err)
		auth.Signatures[name] = sig
	}
	companion, err := auth.Bytes()
	require.NoError(t, err)
	return builtFreeze{body: body, prepare: prepare, freeze: freeze, companion: companion, preimage: raw}
}

func (f *assignmentFixture) admit(t *testing.T, b builtFreeze) error {
	t.Helper()
	addProfileBlock(t, f.store, 2, [][]byte{b.prepare.Bytes()})
	parent, err := f.store.Block(2)
	require.NoError(t, err)
	_, err = f.store.Add(&rctypes.BlockData{Version: 2, Round: 3, Epoch: 1,
		Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{b.freeze.Bytes(), b.companion}},
		Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: parent.RootHash}}}, nil)
	return err
}

func TestFreezeAdmitsAssignmentCandidateAndRetainsPreimage(t *testing.T) {
	f := newAssignmentFixture(t)
	b := f.build(t, f.candidate(t))
	require.NoError(t, f.admit(t, b))
	got, err := f.store.HandoffCandidate(b.freeze.NextBodyID)
	require.NoError(t, err)
	require.Equal(t, b.preimage, got)
	body, err := f.store.HandoffBody(b.freeze.NextBodyID)
	require.NoError(t, err)
	require.Equal(t, b.body.Encode(), body)
	none, err := f.store.HandoffCandidate(bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	require.Empty(t, none)
}

func TestFreezeAssignmentBindingIsolatedMutations(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate, extra *[]func(*FreezeAssignmentAuthorization, *evmroot.TrustBaseBodyV2))
		want   error
		reason string
	}{
		{"missing PoP for one successor key", func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate, _ *[]func(*FreezeAssignmentAuthorization, *evmroot.TrustBaseBodyV2)) {
			c.PoPs = c.PoPs[:len(c.PoPs)-1]
		}, evmassign.ErrPoP, "proofs"},
		{"PoP replayed from another attempt", func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate, _ *[]func(*FreezeAssignmentAuthorization, *evmroot.TrustBaseBodyV2)) {
			ctx := f.pop
			ctx.Attempt = 9
			c.PoPs = f.pops(t, ctx, f.succ)
		}, evmassign.ErrPoP, "verification failed"},
		{"candidate names another parent", func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate, _ *[]func(*FreezeAssignmentAuthorization, *evmroot.TrustBaseBodyV2)) {
			c.Parent = bytes.Repeat([]byte{6}, 32)
		}, evmassign.ErrContext, "parent"},
		{"candidate names another attempt", func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate, _ *[]func(*FreezeAssignmentAuthorization, *evmroot.TrustBaseBodyV2)) {
			c.Attempt = 1
		}, evmassign.ErrContext, "attempt"},
		{"candidate names another predecessor", func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate, _ *[]func(*FreezeAssignmentAuthorization, *evmroot.TrustBaseBodyV2)) {
			c.Predecessor = bytes.Repeat([]byte{6}, 32)
		}, evmassign.ErrContext, "predecessor"},
		{"candidate names another network", func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate, _ *[]func(*FreezeAssignmentAuthorization, *evmroot.TrustBaseBodyV2)) {
			c.Network = 6
		}, evmassign.ErrContext, "network"},
		{"candidate root members differ from the body", func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate, _ *[]func(*FreezeAssignmentAuthorization, *evmroot.TrustBaseBodyV2)) {
			c.RootMembers = c.RootMembers[:3]
		}, evmassign.ErrContext, "successor root members"},
		{"combined root and EVM change", func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate, extra *[]func(*FreezeAssignmentAuthorization, *evmroot.TrustBaseBodyV2)) {
			grown := append(append([]evmassign.RootMember(nil), c.RootMembers...), evmassign.RootMember{NodeID: "zz-new", Key: f.nextKeys[1].info.SigKey, Weight: 1})
			c.RootMembers = grown
			*extra = append(*extra, func(_ *FreezeAssignmentAuthorization, body *evmroot.TrustBaseBodyV2) {
				body.Members = append(append(evmroot.WeightSet(nil), body.Members...), evmroot.Member{StakingID: "zz-new", NodeID: "zz-new",
					ConsensusKey: f.nextKeys[1].info.SigKey, Weight: 1})
				body.RootThreshold = evmroot.RootQuorumThreshold(uint64(len(body.Members)))
			})
		}, evmassign.ErrCombined, ""},
		{"candidate digest differs from the companion", nil, evmassign.ErrContext, "candidate digest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAssignmentFixture(t)
			c := f.candidate(t)
			var extra []func(*FreezeAssignmentAuthorization, *evmroot.TrustBaseBodyV2)
			if tc.mutate != nil {
				tc.mutate(t, f, &c, &extra)
			} else {
				extra = append(extra, func(a *FreezeAssignmentAuthorization, body *evmroot.TrustBaseBodyV2) {
					a.Candidate = bytes.Repeat([]byte{8}, 32)
					body.ChangeRecordHash = evmroot.D4CandidateContextHash(5, f.predecessor, 0, a.Candidate, 7)
				})
			}
			err := f.admit(t, f.build(t, c, extra...))
			require.ErrorIs(t, err, ErrHandoffRecord)
			require.ErrorIs(t, err, tc.want)
			if tc.reason != "" {
				require.ErrorContains(t, err, tc.reason)
			}
			stored, rerr := f.store.HandoffCandidate(f.build(t, f.candidate(t)).freeze.NextBodyID)
			require.NoError(t, rerr)
			require.Empty(t, stored, "a refused candidate is never retained")
		})
	}
}

func TestFreezeAssignmentInstalledStateIsolatedMutations(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate)
		want   error
		reason string
	}{
		{"stale installed epoch", func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate) { c.OldShardEpoch = 9 }, evmassign.ErrContext, "installed assignment epoch"},
		{"stale installed configuration hash", func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate) {
			c.OldActiveHash = bytes.Repeat([]byte{1}, 32)
		}, evmassign.ErrContext, "installed assignment hash"},
		{"fee or execution setting changed", func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate) {
			p := *f.succ
			p.PartitionParams = map[string]string{"seal_registry_genesis": "other"}
			raw, err := types.Cbor.Marshal(&p)
			require.NoError(t, err)
			c.Assignment = raw
			c.PoPs = f.pops(t, f.pop, &p)
		}, evmassign.ErrConfig, ""},
		{"epoch skipped", func(t *testing.T, f *assignmentFixture, c *evmassign.Candidate) {
			p := *f.succ
			p.Epoch = f.current.Epoch + 2
			raw, err := types.Cbor.Marshal(&p)
			require.NoError(t, err)
			c.Assignment = raw
			c.PoPs = f.pops(t, f.pop, &p)
		}, evmassign.ErrEpoch, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAssignmentFixture(t)
			c := f.candidate(t)
			tc.mutate(t, f, &c)
			err := f.admit(t, f.build(t, c))
			require.ErrorIs(t, err, ErrHandoffRecord)
			require.ErrorIs(t, err, tc.want)
			if tc.reason != "" {
				require.ErrorContains(t, err, tc.reason)
			}
		})
	}
}

func TestPendingAssignmentAckRefusesEveryOtherHandoff(t *testing.T) {
	pending := func(si *ShardInfo) { si.TR.Epoch = si.IR.Epoch + 1 }
	t.Run("assignment without supersession", func(t *testing.T) {
		f := newAssignmentFixture(t)
		f.installShard(t, f.current, func(si *ShardInfo) { si.IR.BlockHash = bytes.Clone(f.parent); pending(si) })
		require.ErrorIs(t, f.admit(t, f.build(t, f.candidate(t))), ErrAssignmentAckPending)
	})
	t.Run("root only", func(t *testing.T) {
		f := newAssignmentFixture(t)
		f.installShard(t, f.current, func(si *ShardInfo) { si.IR.BlockHash = bytes.Clone(f.parent); pending(si) })
		legacy := f.build(t, f.candidate(t))
		auth := FreezeAuthorization{Version: 1, Body: legacy.body.Encode(), Parent: bytes.Clone(f.parent),
			Candidate: bytes.Repeat([]byte{4}, 32)}
		body := legacy.body
		body.ChangeRecordHash = evmroot.D4CandidateContextHash(5, f.predecessor, 0, auth.Candidate, 7)
		auth.Body = body.Encode()
		id := body.Identity()
		freeze := legacy.freeze
		freeze.NextBodyID = id[:]
		freeze.FrozenID = evmroot.D4FrozenID(id[:], body.StateSummary, f.parent, auth.Candidate, 0, f.predecessor)
		prepare := freeze
		prepare.Kind, prepare.OrderedRound, prepare.FrozenID = "prepare", 2, make([]byte, 32)
		message, err := EndorsementBytes(freeze)
		require.NoError(t, err)
		auth.Signatures = map[string]hex.Bytes{}
		for _, name := range []string{"old-a", "old-b", "old-c"} {
			sig, err := f.signers[name].SignBytes(message)
			require.NoError(t, err)
			auth.Signatures[name] = sig
		}
		companion, err := auth.Bytes()
		require.NoError(t, err)
		err = f.admit(t, builtFreeze{body: body, prepare: prepare, freeze: freeze, companion: companion})
		require.ErrorIs(t, err, ErrAssignmentAckPending)
	})
	t.Run("acknowledged assignment admits a fresh handoff", func(t *testing.T) {
		f := newAssignmentFixture(t)
		require.NoError(t, f.admit(t, f.build(t, f.candidate(t))))
	})
}

func TestFreezeCompanionCodecRefusesNonCanonicalAndWrongShape(t *testing.T) {
	f := newAssignmentFixture(t)
	b := f.build(t, f.candidate(t))
	got, err := ParseFreezeCompanion(b.companion)
	require.NoError(t, err)
	require.EqualValues(t, 2, got.Version)
	require.Equal(t, b.preimage, got.Preimage)
	for name, raw := range map[string][]byte{
		"trailing byte": append(bytes.Clone(b.companion), 0),
		"truncated":     b.companion[:len(b.companion)-1],
		"empty":         nil,
	} {
		_, err := ParseFreezeCompanion(raw)
		require.ErrorIs(t, err, ErrHandoffRecord, name)
	}
	empty, err := (FreezeAssignmentAuthorization{Version: 2, Body: []byte{1}, Parent: b.freeze.NextBodyID, Candidate: b.freeze.NextBodyID,
		Signatures: map[string]hex.Bytes{"a": {1}}}).Bytes()
	require.NoError(t, err)
	_, err = ParseFreezeCompanion(empty)
	require.ErrorIs(t, err, ErrHandoffRecord, "a version-2 companion must carry its preimage")
	wrong, err := (FreezeAssignmentAuthorization{Version: 3, Body: []byte{1}, Parent: b.freeze.NextBodyID, Candidate: b.freeze.NextBodyID,
		Preimage: []byte{1}, Signatures: map[string]hex.Bytes{"a": {1}}}).Bytes()
	require.NoError(t, err)
	_, err = ParseFreezeCompanion(wrong)
	require.ErrorIs(t, err, ErrHandoffRecord)
}
