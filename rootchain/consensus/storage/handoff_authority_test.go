package storage

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type authorizedFixture struct {
	store       *BlockStore
	signers     map[string]abcrypto.Signer
	body        evmroot.TrustBaseBodyV2
	predecessor []byte
	frozen      []byte
}

func newAuthorizedFixture(t *testing.T) authorizedFixture {
	t.Helper()
	s := profileStore(t)
	signers := make(map[string]abcrypto.Signer)
	for _, id := range []string{"old-a", "old-b", "old-c", "old-d"} {
		signer, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		signers[id] = signer
	}
	tb := testtrustbase.NewTrustBaseFromSigners(t, signers).(*types.RootTrustBaseV1)
	require.NoError(t, s.ConfigureHandoffAuthority(tb))
	predecessor, err := tb.Hash(crypto.SHA256)
	require.NoError(t, err)
	link, err := evmroot.FirstV2PredecessorHash(evmroot.V1Anchor{Version: 1, NetworkID: 5, Epoch: 1, HashIncludingSigs: predecessor})
	require.NoError(t, err)
	body := evmroot.TrustBaseBodyV2{Version: 2, NetworkID: 5, Epoch: 2, EarliestActivation: 7,
		Members: evmroot.WeightSet{{StakingID: "next-stake", NodeID: tb.RootNodes[0].NodeID,
			ConsensusKey: tb.RootNodes[0].SigKey, Weight: 1}}, RootThreshold: 1,
		StateSummary: bytes.Repeat([]byte{3}, 32), ChangeRecordHash: bytes.Repeat([]byte{4}, 32), PredecessorHash: link}
	require.NoError(t, body.Validate())
	return authorizedFixture{store: s, signers: signers, body: body, predecessor: predecessor, frozen: bytes.Repeat([]byte{2}, 32)}
}

func (f authorizedFixture) record(kind string, round, attempt uint64) evmroot.OrderedHandoffRecord {
	id := f.body.Identity()
	tr := make([]byte, 32)
	if kind == "commit" {
		tr = bytes.Repeat([]byte{9}, 32)
	}
	frozen := make([]byte, 32)
	if kind == "freeze" || kind == "commit" {
		frozen = f.frozen
	}
	return evmroot.OrderedHandoffRecord{Network: 5, Epoch: 1, Attempt: attempt, OrderedRound: round,
		ActivationRound: 7, PredecessorBodyID: f.predecessor, NextBodyID: id[:], FrozenID: frozen,
		SuccessorTRHash: tr, Kind: kind}
}

func (f authorizedFixture) companion(t *testing.T, r evmroot.OrderedHandoffRecord, names ...string) []byte {
	t.Helper()
	message, err := EndorsementBytes(r)
	require.NoError(t, err)
	sigs := make(map[string]hex.Bytes)
	for _, name := range names {
		sig, err := f.signers[name].SignBytes(message)
		require.NoError(t, err)
		sigs[name] = sig
	}
	encoded, err := (FreezeAuthorization{Version: 1, Body: f.body.Encode(), Signatures: sigs}).Bytes()
	require.NoError(t, err)
	return encoded
}

func (f authorizedFixture) abortCompanion(t *testing.T, r evmroot.OrderedHandoffRecord, names ...string) []byte {
	t.Helper()
	message, err := AbortEndorsementBytes(r)
	require.NoError(t, err)
	sigs := make(map[string]hex.Bytes)
	for _, name := range names {
		sig, err := f.signers[name].SignBytes(message)
		require.NoError(t, err)
		sigs[name] = sig
	}
	encoded, err := (AbortAuthorization{Version: 1, Signatures: sigs}).Bytes()
	require.NoError(t, err)
	return encoded
}

func TestAuthorizedFirstV2HandoffDerivesEpochGenesis(t *testing.T) {
	f := newAuthorizedFixture(t)
	addProfileBlock(t, f.store, 2, [][]byte{f.record("prepare", 2, 0).Bytes()})
	freeze := f.record("freeze", 3, 0)
	addProfileBlock(t, f.store, 3, [][]byte{freeze.Bytes(), f.companion(t, freeze, "old-a", "old-b", "old-c")})
	commit := f.record("commit", 4, 0)
	h := addProfileBlock(t, f.store, 4, [][]byte{commit.Bytes()})
	v := evmroot.VerifiedHandoff{RecordID: commit.ID(), Record: commit, Root: h.RootHash,
		ControlDigest: h.ShardState.Control.Digest(), Epoch: 1, OrderRound: 4, CommitSealRound: 4}
	g, err := evmroot.DeriveEpochGenesis(v, f.body)
	require.NoError(t, err)
	require.EqualValues(t, 7, g.Start)
	require.EqualValues(t, 2, g.Epoch)
	bad := f.body
	bad.PredecessorHash = bytes.Clone(f.predecessor)
	badV := v
	badID := bad.Identity()
	badV.Record.NextBodyID = badID[:]
	_, err = evmroot.DeriveEpochGenesis(badV, bad)
	require.ErrorIs(t, err, evmroot.ErrD4Anchor)
}
}

func TestConfigureHandoffAuthorityRequiresAuthenticCurrentBase(t *testing.T) {
	f := newAuthorizedFixture(t)
	tb := *f.store.handoffAuth.(*v1HandoffAuthority).trust
	tb.Epoch = 2
	require.ErrorIs(t, f.store.ConfigureHandoffAuthority(&tb), ErrHandoffRecord)
	tb.Epoch = 1
	tb.Signatures = nil
	require.ErrorIs(t, f.store.ConfigureHandoffAuthority(&tb), ErrHandoffRecord)
}

func TestHandoffAuthorizationRejectsUnauthorizedCommit(t *testing.T) {
	t.Run("valid old quorum permits freeze and commit", func(t *testing.T) {
		f := newAuthorizedFixture(t)
		addProfileBlock(t, f.store, 2, [][]byte{f.record("prepare", 2, 0).Bytes()})
		freeze := f.record("freeze", 3, 0)
		addProfileBlock(t, f.store, 3, [][]byte{freeze.Bytes(), f.companion(t, freeze, "old-a", "old-b", "old-c")})
		h := addProfileBlock(t, f.store, 4, [][]byte{f.record("commit", 4, 0).Bytes()})
		require.Equal(t, "committed", h.ShardState.Control.Phase)
	})
	t.Run("no quorum", func(t *testing.T) {
		f := newAuthorizedFixture(t)
		addProfileBlock(t, f.store, 2, [][]byte{f.record("prepare", 2, 0).Bytes()})
		freeze := f.record("freeze", 3, 0)
		parent, err := f.store.Block(2)
		require.NoError(t, err)
		block := &rctypes.BlockData{Version: 2, Round: 3, Epoch: 1, Payload: &rctypes.Payload{Version: 2,
			HandoffRecords: [][]byte{freeze.Bytes(), f.companion(t, freeze, "old-a")}},
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: parent.RootHash}}}
		_, err = f.store.Add(block, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("bad next body", func(t *testing.T) {
		f := newAuthorizedFixture(t)
		f.body.PredecessorHash[0] ^= 1
		addProfileBlock(t, f.store, 2, [][]byte{f.record("prepare", 2, 0).Bytes()})
		freeze := f.record("freeze", 3, 0)
		parent, err := f.store.Block(2)
		require.NoError(t, err)
		block := &rctypes.BlockData{Version: 2, Round: 3, Epoch: 1, Payload: &rctypes.Payload{Version: 2,
			HandoffRecords: [][]byte{freeze.Bytes(), f.companion(t, freeze, "old-a", "old-b", "old-c")}},
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: parent.RootHash}}}
		_, err = f.store.Add(block, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("nonunit next body weight", func(t *testing.T) {
		f := newAuthorizedFixture(t)
		f.body.Members[0].Weight = 2
		f.body.RootThreshold = evmroot.RootQuorumThreshold(2)
		addProfileBlock(t, f.store, 2, [][]byte{f.record("prepare", 2, 0).Bytes()})
		freeze := f.record("freeze", 3, 0)
		parent, err := f.store.Block(2)
		require.NoError(t, err)
		block := &rctypes.BlockData{Version: 2, Round: 3, Epoch: 1, Payload: &rctypes.Payload{Version: 2,
			HandoffRecords: [][]byte{freeze.Bytes(), f.companion(t, freeze, "old-a", "old-b", "old-c")}},
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: parent.RootHash}}}
		_, err = f.store.Add(block, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("malformed D3 body", func(t *testing.T) {
		f := newAuthorizedFixture(t)
		f.body.RootThreshold++
		addProfileBlock(t, f.store, 2, [][]byte{f.record("prepare", 2, 0).Bytes()})
		freeze := f.record("freeze", 3, 0)
		parent, err := f.store.Block(2)
		require.NoError(t, err)
		block := &rctypes.BlockData{Version: 2, Round: 3, Epoch: 1, Payload: &rctypes.Payload{Version: 2,
			HandoffRecords: [][]byte{freeze.Bytes(), f.companion(t, freeze, "old-a", "old-b", "old-c")}},
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: parent.RootHash}}}
		_, err = f.store.Add(block, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("forged endorsement signature", func(t *testing.T) {
		f := newAuthorizedFixture(t)
		addProfileBlock(t, f.store, 2, [][]byte{f.record("prepare", 2, 0).Bytes()})
		freeze := f.record("freeze", 3, 0)
		var companion FreezeAuthorization
		require.NoError(t, types.Cbor.Unmarshal(f.companion(t, freeze, "old-a", "old-b", "old-c", "old-d"), &companion))
		companion.Signatures["old-a"][0] ^= 1
		bad, err := companion.Bytes()
		require.NoError(t, err)
		parent, err := f.store.Block(2)
		require.NoError(t, err)
		block := &rctypes.BlockData{Version: 2, Round: 3, Epoch: 1, Payload: &rctypes.Payload{Version: 2,
			HandoffRecords: [][]byte{freeze.Bytes(), bad}},
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: parent.RootHash}}}
		_, err = f.store.Add(block, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	for _, tc := range []struct {
		name   string
		change func(*authorizedFixture)
	}{
		{"wrong body identity", nil},
		{"body activation after record", func(f *authorizedFixture) { f.body.EarliestActivation = 8 }},
		{"wrong body epoch", func(f *authorizedFixture) { f.body.Epoch = 3 }},
		{"wrong body network", func(f *authorizedFixture) { f.body.NetworkID = 6 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthorizedFixture(t)
			if tc.change != nil {
				tc.change(&f)
			}
			prepare, freeze := f.record("prepare", 2, 0), f.record("freeze", 3, 0)
			if tc.name == "wrong body identity" {
				prepare.NextBodyID[0] ^= 1
				freeze.NextBodyID[0] ^= 1
			}
			addProfileBlock(t, f.store, 2, [][]byte{prepare.Bytes()})
			parent, err := f.store.Block(2)
			require.NoError(t, err)
			block := &rctypes.BlockData{Version: 2, Round: 3, Epoch: 1, Payload: &rctypes.Payload{Version: 2,
				HandoffRecords: [][]byte{freeze.Bytes(), f.companion(t, freeze, "old-a", "old-b", "old-c")}},
				Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: parent.RootHash}}}
			_, err = f.store.Add(block, nil)
			require.ErrorIs(t, err, ErrHandoffRecord)
		})
	}
	t.Run("wrong predecessor", func(t *testing.T) {
		f := newAuthorizedFixture(t)
		prepare := f.record("prepare", 2, 0)
		prepare.PredecessorBodyID[0] ^= 1
		parent, err := f.store.Block(1)
		require.NoError(t, err)
		block := &rctypes.BlockData{Version: 2, Round: 2, Epoch: 1, Payload: &rctypes.Payload{Version: 2,
			HandoffRecords: [][]byte{prepare.Bytes()}},
			Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 1, Epoch: 1, CurrentRootHash: parent.RootHash}}}
		_, err = f.store.Add(block, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("commit requires endorsed phase", func(t *testing.T) {
		f := newAuthorizedFixture(t)
		freeze := f.record("freeze", 3, 0)
		control := &evmroot.ControlState{Network: 5, Epoch: 1, Attempt: 0,
			PredecessorBodyID: f.predecessor, Phase: "frozen", OrderedRound: 3,
			RecordBytes: freeze.Bytes(), PreviousDigest: bytes.Repeat([]byte{1}, 32)}
		_, err := applyHandoffRecord(control, f.record("commit", 4, 0).Bytes(), 5, 1, 4, f.store.handoffAuth, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("abort permits next attempt", func(t *testing.T) {
		f := newAuthorizedFixture(t)
		addProfileBlock(t, f.store, 2, [][]byte{f.record("prepare", 2, 0).Bytes()})
		beforeAbort, err := f.store.Block(2)
		require.NoError(t, err)
		wrongAbort := f.record("abort", 3, 0)
		wrongAbort.NextBodyID[0] ^= 1
		invalidAbort := &rctypes.BlockData{Version: 2, Round: 3, Epoch: 1,
			Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{wrongAbort.Bytes()}},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: beforeAbort.RootHash}}}
		_, err = f.store.Add(invalidAbort, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
		abort := f.record("abort", 3, 0)
		addProfileBlock(t, f.store, 3, [][]byte{abort.Bytes(), f.abortCompanion(t, abort, "old-a", "old-b", "old-c")})
		parent, err := f.store.Block(3)
		require.NoError(t, err)
		skipped := &rctypes.BlockData{Version: 2, Round: 4, Epoch: 1,
			Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{f.record("prepare", 4, 2).Bytes()}},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 3, Epoch: 1, CurrentRootHash: parent.RootHash}}}
		_, err = f.store.Add(skipped, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
		prepared := addProfileBlock(t, f.store, 4, [][]byte{f.record("prepare", 4, 1).Bytes()})
		require.Equal(t, "prepared", prepared.ShardState.Control.Phase)
		require.Equal(t, uint64(1), prepared.ShardState.Control.Attempt)
	})
	t.Run("abort proof requires quorum", func(t *testing.T) {
		f := newAuthorizedFixture(t)
		addProfileBlock(t, f.store, 2, [][]byte{f.record("prepare", 2, 0).Bytes()})
		abort := f.record("abort", 3, 0)
		parent, err := f.store.Block(2)
		require.NoError(t, err)
		block := &rctypes.BlockData{Version: 2, Round: 3, Epoch: 1,
			Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{abort.Bytes(), f.abortCompanion(t, abort, "old-a")}},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: parent.RootHash}}}
		_, err = f.store.Add(block, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("abort signature binds attempt", func(t *testing.T) {
		f := newAuthorizedFixture(t)
		addProfileBlock(t, f.store, 2, [][]byte{f.record("prepare", 2, 0).Bytes()})
		abort := f.record("abort", 3, 0)
		wrongAttempt := abort
		wrongAttempt.Attempt++
		parent, err := f.store.Block(2)
		require.NoError(t, err)
		block := &rctypes.BlockData{Version: 2, Round: 3, Epoch: 1,
			Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{abort.Bytes(), f.abortCompanion(t, wrongAttempt, "old-a", "old-b", "old-c")}},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: parent.RootHash}}}
		_, err = f.store.Add(block, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
	t.Run("abort signature binds predecessor", func(t *testing.T) {
		f := newAuthorizedFixture(t)
		addProfileBlock(t, f.store, 2, [][]byte{f.record("prepare", 2, 0).Bytes()})
		abort := f.record("abort", 3, 0)
		wrongPredecessor := abort
		wrongPredecessor.PredecessorBodyID = bytes.Clone(abort.PredecessorBodyID)
		wrongPredecessor.PredecessorBodyID[0] ^= 1
		parent, err := f.store.Block(2)
		require.NoError(t, err)
		block := &rctypes.BlockData{Version: 2, Round: 3, Epoch: 1,
			Payload: &rctypes.Payload{Version: 2, HandoffRecords: [][]byte{abort.Bytes(), f.abortCompanion(t, wrongPredecessor, "old-a", "old-b", "old-c")}},
			Qc:      &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 2, Epoch: 1, CurrentRootHash: parent.RootHash}}}
		_, err = f.store.Add(block, nil)
		require.ErrorIs(t, err, ErrHandoffRecord)
	})
}
