package abdrc

import (
	"bytes"
	gocrypto "crypto"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// dbFixture is a root committee of four fixed keys with trust bases for epochs 1, 2 and 3, all signing with the legacy
// scheme until an epoch is activated. Epoch 2 is the first domain-bound epoch in the tests that activate it.
type dbFixture struct {
	store   *trustbase.TrustBaseStore
	signers map[string]abcrypto.Signer
	ids     []string
	cfg     votesig.Config
}

func fixedSigner(t *testing.T, name string) abcrypto.Signer {
	t.Helper()
	k := sha256.Sum256([]byte("domain-bound-test-key/" + name))
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(k[:])
	require.NoError(t, err)
	return s
}

func genesisIdentity() [32]byte { return sha256.Sum256([]byte("domain-bound-test-root-genesis")) }

func newDBFixture(t *testing.T) *dbFixture {
	t.Helper()
	f := &dbFixture{signers: map[string]abcrypto.Signer{}, cfg: votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: genesisIdentity()}}
	var nodes []*types.NodeInfo
	for _, id := range []string{"1", "2", "3", "4"} {
		s := fixedSigner(t, id)
		v, err := s.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		f.signers[id] = s
		f.ids = append(f.ids, id)
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: key, Stake: 1})
	}
	store, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	var prev *types.RootTrustBaseV1
	for epoch, start := uint64(1), uint64(1); epoch <= 3; epoch, start = epoch+1, start+9 {
		opts := []types.Option{types.WithEpoch(epoch), types.WithEpochStart(start)}
		if prev != nil {
			h, err := prev.Hash(gocrypto.SHA256)
			require.NoError(t, err)
			opts = append(opts, types.WithPreviousTrustBaseHash(h))
		}
		tb, err := types.NewTrustBase(5, cloneNodes(nodes), opts...)
		require.NoError(t, err)
		for _, id := range f.ids {
			require.NoError(t, tb.Sign(id, f.signers[id]))
		}
		require.NoError(t, store.Store(tb))
		prev = tb
	}
	f.store = store
	return f
}

func cloneNodes(in []*types.NodeInfo) []*types.NodeInfo {
	out := make([]*types.NodeInfo, len(in))
	for i, n := range in {
		out[i] = &types.NodeInfo{NodeID: n.NodeID, SigKey: bytes.Clone(n.SigKey), Stake: n.Stake}
	}
	return out
}

func (f *dbFixture) activate(t *testing.T, epoch uint64) {
	t.Helper()
	require.NoError(t, f.store.ActivateSigning(epoch, f.cfg))
}

// legacyQC is a legacy-form QC signed by every member for the given epoch and round.
func (f *dbFixture) legacyQC(t *testing.T, epoch, round uint64) *drctypes.QuorumCert {
	t.Helper()
	vi := &drctypes.RoundInfo{Version: 1, RoundNumber: round, Epoch: epoch, Timestamp: 1000 + round, ParentRoundNumber: round - 1, CurrentRootHash: bytes.Repeat([]byte{byte(round)}, 32)}
	h, err := vi.Hash(gocrypto.SHA256)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, PreviousHash: h}
	bs, err := seal.SigBytes()
	require.NoError(t, err)
	qc := &drctypes.QuorumCert{VoteInfo: vi, LedgerCommitInfo: seal, Signatures: map[string]hex.Bytes{}}
	for _, id := range f.ids {
		sig, err := f.signers[id].SignBytes(bs)
		require.NoError(t, err)
		qc.Signatures[id] = sig
	}
	return qc
}

// voteV2 is a scheme 2 vote of the author for the given epoch and round (parent round-1) that carries high.
func (f *dbFixture) voteV2(t *testing.T, author string, epoch, round uint64, committing bool, high *drctypes.QuorumCert) *VoteMsg {
	t.Helper()
	exec := bytes.Repeat([]byte{0x5e}, 32)
	vi := votesig.VoteInfo{Epoch: epoch, Round: round, Parent: round - 1}
	copy(vi.Exec[:], exec)
	vh, err := f.cfg.VoteInfoHash(vi)
	require.NoError(t, err)
	seal := &types.UnicitySeal{Version: 1, PreviousHash: vh[:]}
	if committing {
		seal = &types.UnicitySeal{Version: 1, NetworkID: types.NetworkID(f.cfg.Network), PreviousHash: vh[:], RootChainRoundNumber: round - 1,
			Epoch: epoch, Timestamp: 4242, Hash: bytes.Repeat([]byte{0xc0}, 32)}
	}
	v := &VoteMsg{VoteInfo: &drctypes.RoundInfo{Version: 1, RoundNumber: round, Epoch: epoch, ParentRoundNumber: round - 1, CurrentRootHash: exec},
		LedgerCommitInfo: seal, HighQc: high, Author: author}
	require.NoError(t, v.SignDomainBound(f.signers[author], f.cfg))
	return v
}

func TestDomainBoundVoteVerifiesOnlyInADomainBoundEpoch(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)
	high := f.legacyQC(t, 1, 11) // a legacy QC of the previous epoch, verified by that epoch's own rule

	for _, committing := range []bool{true, false} {
		t.Run(fmt.Sprintf("committing=%v", committing), func(t *testing.T) {
			v := f.voteV2(t, "1", 2, 12, committing, high)
			require.NoError(t, v.Verify(f.store))
			require.Equal(t, committing, len(v.SealSignature) != 0)

			// the wire round-trips as the scheme 2 form
			raw, err := types.Cbor.Marshal(v)
			require.NoError(t, err)
			require.Equal(t, []byte{0x82, 0x02}, raw[:2])
			var back VoteMsg
			require.NoError(t, types.Cbor.Unmarshal(raw, &back))
			require.EqualValues(t, votesig.SchemeDomainBound, back.Scheme)
			require.NoError(t, back.Verify(f.store))
		})
	}

	t.Run("the legacy form is refused in a domain-bound epoch and the new form before it", func(t *testing.T) {
		legacy := f.voteV2(t, "1", 2, 12, true, high)
		legacy.Scheme, legacy.SealSignature = 0, nil
		require.ErrorIs(t, legacy.Verify(f.store), votesig.ErrScheme)

		early := f.voteV2(t, "1", 3, 22, true, high)
		g := newDBFixture(t) // epoch 2 and 3 not activated here
		require.ErrorIs(t, early.Verify(g.store), votesig.ErrScheme)
	})

	t.Run("an embedded legacy-form high QC of the activated epoch is the wrong scheme", func(t *testing.T) {
		v := f.voteV2(t, "1", 2, 12, true, f.legacyQC(t, 2, 11))
		err := v.Verify(f.store)
		require.ErrorIs(t, err, votesig.ErrScheme)
	})
}

func TestDomainBoundVoteNegatives(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)
	high := f.legacyQC(t, 1, 11)
	mutate := func(committing bool, fn func(v *VoteMsg)) error {
		v := f.voteV2(t, "1", 2, 12, committing, high)
		fn(v)
		return v.Verify(f.store)
	}
	// the signed fields: each single change either breaks the vote info hash binding or the signature
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.VoteInfo.RoundNumber++ }), votesig.ErrStatement)
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.VoteInfo.Epoch = 3 }), votesig.ErrStatement, "the epoch is bound through the vote info hash")
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.VoteInfo.ParentRoundNumber-- }), votesig.ErrStatement)
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.VoteInfo.CurrentRootHash = bytes.Repeat([]byte{1}, 32) }), votesig.ErrStatement)
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.VoteInfo.CurrentRootHash = []byte{1} }), votesig.ErrStatement)
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.LedgerCommitInfo.PreviousHash = bytes.Repeat([]byte{1}, 32) }), votesig.ErrStatement)
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.LedgerCommitInfo.Hash = bytes.Repeat([]byte{0xc1}, 32) }), votesig.ErrBadSignature)
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.LedgerCommitInfo.RootChainRoundNumber = 3 }), votesig.ErrBadSignature)
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.LedgerCommitInfo.RootChainRoundNumber = 12 }), votesig.ErrStatement, "commit round must be below the voting round")
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.LedgerCommitInfo.Hash = nil }), votesig.ErrStatement, "half-empty commit pair")
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.LedgerCommitInfo.NetworkID = 6 }), votesig.ErrStatement)
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.LedgerCommitInfo.Timestamp++ }), votesig.ErrBadSignature, "the native seal timestamp is bound by the seal signature")
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.LedgerCommitInfo.Version = 2 }), votesig.ErrBadSignature)
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.Author = "2" }), votesig.ErrBadSignature)
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.Author = "stranger" }), votesig.ErrBadSignature)

	// the two named signatures are not interchangeable and a committing vote needs both
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.Signature, v.SealSignature = v.SealSignature, v.Signature }), votesig.ErrBadSignature)
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.SealSignature = nil }), votesig.ErrSignatureShape)
	require.ErrorIs(t, mutate(false, func(v *VoteMsg) { v.SealSignature = v.Signature }), votesig.ErrStatement, "no seal signature on a non-committing vote")
	require.ErrorIs(t, mutate(false, func(v *VoteMsg) { v.LedgerCommitInfo.Epoch = 2 }), votesig.ErrStatement)

	// the executed state hash is exactly 32 bytes: a short one would alias its zero-padded twin, so it cannot even be signed
	short := f.voteV2(t, "1", 2, 12, true, high)
	short.VoteInfo.CurrentRootHash = []byte{1}
	padded := votesig.VoteInfo{Epoch: 2, Round: 12, Parent: 11, Exec: [32]byte{1}} // the statement its zero-padded twin would sign
	paddedHash, err := f.cfg.VoteInfoHash(padded)
	require.NoError(t, err)
	short.LedgerCommitInfo.PreviousHash = paddedHash[:]
	require.ErrorIs(t, short.SignDomainBound(f.signers["1"], f.cfg), votesig.ErrStatement)

	// signature shape
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.Signature = v.Signature[:63] }), votesig.ErrSignatureShape, "truncated")
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.Signature = append(bytes.Clone(v.Signature[:64]), 2) }), votesig.ErrSignatureShape, "forbidden recovery byte")
	require.NoError(t, mutate(true, func(v *VoteMsg) { v.Signature = bytes.Clone(v.Signature[:64]) }), "64 bytes without the recovery byte is accepted")
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) { v.Signature = highS(t, v.Signature) }), votesig.ErrBadSignature, "high-s")

	// old bytes under the new version: the legacy signature of the same vote over the native seal bytes
	require.ErrorIs(t, mutate(true, func(v *VoteMsg) {
		bs, err := v.LedgerCommitInfo.SigBytes()
		require.NoError(t, err)
		v.Signature, err = f.signers["1"].SignBytes(bs)
		require.NoError(t, err)
	}), votesig.ErrBadSignature)

	// wrong network and wrong domain: a vote signed under another configuration does not verify under this one
	for name, other := range map[string]votesig.Config{
		"network": {Scheme: 2, Network: 6, Genesis: f.cfg.Genesis},
		"domain":  {Scheme: 2, Network: 5, Genesis: sha256.Sum256([]byte("another root chain"))},
	} {
		v := f.voteV2(t, "1", 2, 12, true, high)
		if name == "network" {
			v.LedgerCommitInfo.NetworkID = 6
		}
		vh, err := other.VoteInfoHash(votesig.VoteInfo{Epoch: 2, Round: 12, Parent: 11, Exec: [32]byte(v.VoteInfo.CurrentRootHash)})
		require.NoError(t, err)
		v.LedgerCommitInfo.PreviousHash = vh[:]
		require.NoError(t, v.SignDomainBound(f.signers["1"], other))
		// the vote info hash and the commit network are statements of the other configuration, not of this epoch's
		require.ErrorIs(t, v.Verify(f.store), votesig.ErrStatement, name)
	}
}

// highS flips a low-s signature into its high-s twin (s -> n - s), keeping it a well-shaped but malleable signature.
func highS(t *testing.T, sig []byte) []byte {
	t.Helper()
	n, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	s := new(big.Int).SetBytes(sig[32:64])
	s.Sub(n, s)
	out := bytes.Clone(sig)
	copy(out[32:64], make([]byte, 32))
	sb := s.Bytes()
	copy(out[64-len(sb):64], sb)
	return out
}

// timeoutV2 is a scheme 2 timeout of the author for the epoch and round that carries high as its high QC.
func (f *dbFixture) timeoutV2(t *testing.T, author string, epoch, round uint64, high *drctypes.QuorumCert) *TimeoutMsg {
	t.Helper()
	m := NewTimeoutMsg(drctypes.NewTimeout(round, epoch, high), author, nil)
	require.NoError(t, m.SignDomainBound(f.signers[author], f.cfg))
	return m
}

func TestDomainBoundTimeoutDispatchAndNegatives(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)
	high := f.legacyQC(t, 1, 11)
	m := f.timeoutV2(t, "2", 2, 12, high)
	require.NoError(t, m.Verify(f.store))

	raw, err := types.Cbor.Marshal(m)
	require.NoError(t, err)
	require.Equal(t, []byte{0x82, 0x02}, raw[:2])
	var back TimeoutMsg
	require.NoError(t, types.Cbor.Unmarshal(raw, &back))
	require.NoError(t, back.Verify(f.store))

	// new bytes under the old version and old bytes under the new version, both directions at the epoch boundary
	legacySigned := NewTimeoutMsg(drctypes.NewTimeout(12, 2, high), "2", nil)
	require.NoError(t, legacySigned.Sign(f.signers["2"]))
	require.ErrorIs(t, legacySigned.Verify(f.store), votesig.ErrScheme, "legacy form in the domain-bound epoch")
	relabelled := *legacySigned
	relabelled.Scheme = votesig.SchemeDomainBound
	require.ErrorIs(t, relabelled.Verify(f.store), votesig.ErrBadSignature, "old signature bytes under the new version")

	g := newDBFixture(t) // nothing activated: epoch 2 is legacy
	asNew := *m
	require.ErrorIs(t, asNew.Verify(g.store), votesig.ErrScheme, "new form in a legacy epoch")
	asOld := *m
	asOld.Scheme = 0
	require.ErrorIs(t, asOld.Verify(g.store), votesig.ErrBadSignature, "new signature bytes under the old version")

	single := func(fn func(m *TimeoutMsg)) error {
		c := f.timeoutV2(t, "2", 2, 12, high)
		fn(c)
		return c.Verify(f.store)
	}
	require.ErrorIs(t, single(func(c *TimeoutMsg) { c.Timeout.Round = 13; c.Timeout.HighQc = f.legacyQC(t, 1, 12) }), votesig.ErrBadSignature)
	require.ErrorIs(t, single(func(c *TimeoutMsg) { c.Author = "3" }), votesig.ErrBadSignature)
	require.ErrorIs(t, single(func(c *TimeoutMsg) { c.Signature = c.Signature[:63] }), votesig.ErrSignatureShape)
	require.ErrorIs(t, single(func(c *TimeoutMsg) { c.Signature = highS(t, c.Signature) }), votesig.ErrBadSignature)
	require.ErrorIs(t, single(func(c *TimeoutMsg) { c.Timeout.HighQc = f.legacyQC(t, 1, 10); c.Timeout.Round = 11 }), votesig.ErrBadSignature, "the round and the high QC round are signed")
	require.ErrorIs(t, single(func(c *TimeoutMsg) { c.Timeout.HighQc = f.legacyQC(t, 2, 11) }), votesig.ErrScheme, "a legacy-form QC of the activated epoch is the wrong scheme")

	// other network or root: the same timeout statement under another configuration does not verify
	for name, other := range map[string]votesig.Config{
		"network": {Scheme: 2, Network: 6, Genesis: f.cfg.Genesis},
		"domain":  {Scheme: 2, Network: 5, Genesis: sha256.Sum256([]byte("another root chain"))},
	} {
		c := NewTimeoutMsg(drctypes.NewTimeout(12, 2, high), "2", nil)
		require.NoError(t, c.SignDomainBound(f.signers["2"], other))
		require.ErrorIs(t, c.Verify(f.store), votesig.ErrBadSignature, name)
	}

	// an anchor timeout: the anchor and its slot are signed
	anchor := &drctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{7}, 32), Epoch: 2, Slot: 9, StateRoot: bytes.Repeat([]byte{8}, 32)}
	am := NewTimeoutMsg(drctypes.NewAnchorTimeout(10, anchor), "2", nil)
	require.NoError(t, am.SignDomainBound(f.signers["2"], f.cfg))
	require.NoError(t, am.Verify(f.store))
	am.Timeout.Anchor = &drctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{6}, 32), Epoch: 2, Slot: 9, StateRoot: anchor.StateRoot}
	require.ErrorIs(t, am.Verify(f.store), votesig.ErrBadSignature)
}

func TestUnknownWireVersionIsRefusedBeforeAnyVerification(t *testing.T) {
	for name, target := range map[string]any{"vote": new(VoteMsg), "timeout": new(TimeoutMsg), "timeout certificate": new(drctypes.TimeoutCert)} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, types.Cbor.Unmarshal([]byte{0x82, 0x03, 0xf6}, target), votesig.ErrScheme, "version 3")
			require.ErrorIs(t, types.Cbor.Unmarshal([]byte{0x82, 0x01, 0xf6}, target), votesig.ErrScheme, "version 1 is the legacy form, never a wrapper")
			require.ErrorIs(t, types.Cbor.Unmarshal([]byte{0x82, 0x18, 0x02, 0xf6}, target), votesig.ErrNotCanonical, "version 2 in a non-shortest integer")
			require.ErrorIs(t, types.Cbor.Unmarshal([]byte{0x82, 0x00, 0xf6}, target), votesig.ErrScheme, "version 0")
		})
	}
}

// The legacy wire forms are exactly what they were: an independent copy of the array shapes, written here, encodes the same
// bytes as the types do, so adding the scheme field changed nothing for a legacy message.
func TestLegacyWireFormsAreUnchanged(t *testing.T) {
	f := newDBFixture(t)
	high := f.legacyQC(t, 1, 11)

	tm := NewTimeoutMsg(drctypes.NewTimeout(12, 1, high), "2", nil)
	require.NoError(t, tm.Sign(f.signers["2"]))
	type legacyTimeoutMsg struct {
		_         struct{} `cbor:",toarray"`
		Timeout   *drctypes.Timeout
		Author    string
		Signature hex.Bytes
		LastTC    *drctypes.TimeoutCert
	}
	want, err := types.Cbor.Marshal(legacyTimeoutMsg{Timeout: tm.Timeout, Author: tm.Author, Signature: tm.Signature})
	require.NoError(t, err)
	got, err := types.Cbor.Marshal(tm)
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.NotEqual(t, byte(0x02), got[1], "never a wrapper")

	tc := &drctypes.TimeoutCert{Timeout: tm.Timeout, Signatures: map[string]*drctypes.TimeoutVote{"2": {HqcRound: 11, Signature: tm.Signature}}}
	type legacyTC struct {
		_          struct{} `cbor:",toarray"`
		Timeout    *drctypes.Timeout
		Signatures map[string]*drctypes.TimeoutVote
	}
	want, err = types.Cbor.Marshal(legacyTC{Timeout: tc.Timeout, Signatures: tc.Signatures})
	require.NoError(t, err)
	got, err = types.Cbor.Marshal(tc)
	require.NoError(t, err)
	require.Equal(t, want, got)

	// and a legacy message decodes as scheme 1 and round-trips
	var back TimeoutMsg
	raw, err := types.Cbor.Marshal(tm)
	require.NoError(t, err)
	require.NoError(t, types.Cbor.Unmarshal(raw, &back))
	require.Zero(t, back.Scheme)
	require.NoError(t, back.Verify(f.store))
}

// A timeout certificate verifies every entry from that entry's own high QC round and anchor, never from the maximum; under
// scheme 2 an entry signed over the legacy bytes refuses the whole certificate.
func TestDomainBoundTimeoutCertificate(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)
	high := f.legacyQC(t, 1, 11)

	round, epoch := uint64(13), uint64(2)
	build := func(rounds map[string]uint64) *drctypes.TimeoutCert {
		maxHigh := uint64(0)
		for _, r := range rounds {
			maxHigh = max(maxHigh, r)
		}
		tc := &drctypes.TimeoutCert{Timeout: drctypes.NewTimeout(round, epoch, f.legacyQC(t, 1, maxHigh)), Signatures: map[string]*drctypes.TimeoutVote{}, Scheme: votesig.SchemeDomainBound}
		for id, r := range rounds {
			pt, err := tc.TimeoutPreimage(f.cfg, id, &drctypes.TimeoutVote{HqcRound: r})
			require.NoError(t, err)
			sig, err := f.signers[id].SignBytes(pt)
			require.NoError(t, err)
			tc.Signatures[id] = &drctypes.TimeoutVote{HqcRound: r, Signature: sig}
		}
		return tc
	}
	_ = high
	tc := build(map[string]uint64{"1": 11, "2": 10, "3": 11, "4": 9}) // different signer high QC rounds
	require.NoError(t, tc.Verify(f.store))

	raw, err := types.Cbor.Marshal(tc)
	require.NoError(t, err)
	require.Equal(t, []byte{0x82, 0x02}, raw[:2])
	var back drctypes.TimeoutCert
	require.NoError(t, types.Cbor.Unmarshal(raw, &back))
	require.EqualValues(t, votesig.SchemeDomainBound, back.Scheme)
	require.NoError(t, back.Verify(f.store))

	// the maximum high QC round must not stand in for an entry's own
	bad := build(map[string]uint64{"1": 11, "2": 10, "3": 11, "4": 9})
	bad.Signatures["2"].HqcRound = 11
	require.ErrorIs(t, bad.Verify(f.store), votesig.ErrBadSignature)

	// a mixed certificate: one entry signed over the legacy bytes
	mixed := build(map[string]uint64{"1": 11, "2": 10, "3": 11, "4": 9})
	mixed.Signatures["4"].Signature, err = f.signers["4"].SignBytes(drctypes.BytesFromTimeoutVote(mixed.Timeout, "4", mixed.Signatures["4"]))
	require.NoError(t, err)
	require.ErrorIs(t, mixed.Verify(f.store), votesig.ErrBadSignature)

	// scheme mismatch in both directions
	legacyForm := build(map[string]uint64{"1": 11, "2": 10, "3": 11, "4": 9})
	legacyForm.Scheme = 0
	require.ErrorIs(t, legacyForm.Verify(f.store), votesig.ErrScheme)
	g := newDBFixture(t)
	require.ErrorIs(t, tc.Verify(g.store), votesig.ErrScheme)

	// a signature of a key that is not a member, in the right shape
	stranger := build(map[string]uint64{"1": 11, "2": 10, "3": 11, "4": 9})
	stranger.Signatures["x"] = stranger.Signatures["4"]
	require.ErrorIs(t, stranger.Verify(f.store), votesig.ErrBadSignature)

	// the signers are a set: sorted ids make the order of entries irrelevant to the result
	ids := make([]string, 0, len(tc.Signatures))
	for id := range tc.Signatures {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	require.Equal(t, []string{"1", "2", "3", "4"}, ids)

	// an entry's signature has the scheme 2 shape
	short := build(map[string]uint64{"1": 11, "2": 10, "3": 11, "4": 9})
	short.Signatures["4"].Signature = short.Signatures["4"].Signature[:63]
	require.ErrorIs(t, short.Verify(f.store), votesig.ErrSignatureShape)

	// the high QC round is bound too: an entry whose HqcRound differs from what it signed
	tamper := build(map[string]uint64{"1": 11, "2": 10, "3": 11, "4": 9})
	tamper.Signatures["4"].HqcRound = 8
	require.ErrorIs(t, tamper.Verify(f.store), votesig.ErrBadSignature)
}

// A proposal's block carries a QC; in a domain-bound epoch that QC has no legacy form, and the proposal is refused with the
// typed error before its QC is looked at.
func TestProposalInADomainBoundEpochIsRefusedWithTheTypedError(t *testing.T) {
	f := newDBFixture(t)
	block := &drctypes.BlockData{Author: "1", Round: 12, Epoch: 2, Timestamp: 1000, Payload: &drctypes.Payload{}, Qc: f.legacyQC(t, 2, 11)}
	p := &ProposalMsg{Block: block, Signature: []byte{1}}
	require.NoError(t, p.IsValid())
	require.NotErrorIs(t, p.Verify(f.store), votesig.ErrScheme, "while epoch 2 signs with scheme 1 the QC is the right form")
	f.activate(t, 2)
	require.ErrorIs(t, p.Verify(f.store), votesig.ErrScheme)
}

// Isolated single-field mutations of a signed scheme 2 timeout: each leaves the message structurally valid (a stub last TC supplies
// the structure a changed round or high QC round needs) so that the signature is the only thing that can refuse it.
func TestDomainBoundTimeoutIsolatedFieldMutations(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)
	high := f.legacyQC(t, 1, 11)
	stubTC := func(round uint64) *drctypes.TimeoutCert {
		return &drctypes.TimeoutCert{Timeout: drctypes.NewTimeout(round, 2, high)}
	}
	signed := f.timeoutV2(t, "2", 2, 12, high)
	require.NoError(t, signed.Verify(f.store))

	epochOnly := f.timeoutV2(t, "2", 2, 12, high)
	epochOnly.Timeout.Epoch = 3
	require.ErrorIs(t, epochOnly.Verify(f.store), votesig.ErrBadSignature, "the epoch alone")

	roundOnly := f.timeoutV2(t, "2", 2, 12, high)
	roundOnly.Timeout.Round, roundOnly.LastTC = 13, stubTC(12)
	require.NoError(t, roundOnly.IsValid(), "premise: structurally valid")
	require.ErrorIs(t, roundOnly.Verify(f.store), votesig.ErrBadSignature, "the round alone")

	hqcOnly := f.timeoutV2(t, "2", 2, 12, high)
	hqcOnly.Timeout.HighQc, hqcOnly.LastTC = f.legacyQC(t, 1, 10), stubTC(11)
	require.NoError(t, hqcOnly.IsValid(), "premise: structurally valid")
	require.ErrorIs(t, hqcOnly.Verify(f.store), votesig.ErrBadSignature, "the high QC round alone")
}

// A key that the successor committee dropped signs nothing for the successor epoch, while its messages of its own epoch still verify.
func TestDomainBoundRetiredKeyFailsForTheCurrentEpochOnly(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)
	// epoch 4: the committee of 1, 2, 3 and a new key; "4" is retired
	var nodes []*types.NodeInfo
	for _, id := range []string{"1", "2", "3", "5"} {
		s := fixedSigner(t, id)
		v, err := s.Verifier()
		require.NoError(t, err)
		key, err := v.MarshalPublicKey()
		require.NoError(t, err)
		f.signers[id] = s
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: key, Stake: 1})
	}
	prev, err := f.store.GetByEpoch(3)
	require.NoError(t, err)
	h, err := prev.Hash(gocrypto.SHA256)
	require.NoError(t, err)
	tb, err := types.NewTrustBase(5, nodes, types.WithEpoch(4), types.WithEpochStart(30), types.WithPreviousTrustBaseHash(h))
	require.NoError(t, err)
	for _, id := range []string{"1", "2", "3", "4"} { // signed by the previous committee
		require.NoError(t, tb.Sign(id, f.signers[id]))
	}
	require.NoError(t, f.store.Store(tb))

	high := f.legacyQC(t, 1, 11)
	ownEpoch := f.timeoutV2(t, "4", 2, 12, high)
	require.NoError(t, ownEpoch.Verify(f.store), "the retired key still verifies its own epoch's message")
	current := f.timeoutV2(t, "4", 4, 12, high)
	require.ErrorIs(t, current.Verify(f.store), votesig.ErrBadSignature, "and nothing of the epoch that dropped it")
	require.NoError(t, f.timeoutV2(t, "5", 4, 12, high).Verify(f.store), "the key that replaced it does")
}

// A scheme 2 timeout may carry the last TC of an earlier, legacy epoch: that certificate is verified by its own epoch's rule, and
// relabelling only it as scheme 2 is refused.
func TestDomainBoundTimeoutWithAnOldSchemeLastTC(t *testing.T) {
	f := newDBFixture(t)
	f.activate(t, 2)
	oldTC := &drctypes.TimeoutCert{Timeout: drctypes.NewTimeout(11, 1, f.legacyQC(t, 1, 10)), Signatures: map[string]*drctypes.TimeoutVote{}}
	for _, id := range f.ids {
		vote := &drctypes.TimeoutVote{HqcRound: 10}
		sig, err := f.signers[id].SignBytes(drctypes.BytesFromTimeoutVote(oldTC.Timeout, id, vote))
		require.NoError(t, err)
		vote.Signature = sig
		oldTC.Signatures[id] = vote
	}
	m := NewTimeoutMsg(drctypes.NewTimeout(12, 2, f.legacyQC(t, 1, 10)), "2", oldTC)
	require.NoError(t, m.SignDomainBound(f.signers["2"], f.cfg))
	require.NoError(t, m.Verify(f.store), "the old legacy last TC keeps its own epoch's rule")

	relabelled := *m
	tc := *oldTC
	tc.Scheme = votesig.SchemeDomainBound
	relabelled.LastTC = &tc
	require.ErrorIs(t, relabelled.Verify(f.store), votesig.ErrScheme, "only the last TC relabelled")
}
