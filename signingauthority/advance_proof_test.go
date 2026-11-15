package signingauthority

import (
	"bytes"
	"context"
	gocrypto "crypto"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
)

// The proof-verified advance (#1085): the authority verifies every activation from its own pin, and nothing else changes its scope.

func bundleOf(t *testing.T, f *q3fixture.Fixture) []byte {
	t.Helper()
	raw, err := q3active.EncodeBundle(q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot, Candidate: f.Candidate})
	require.NoError(t, err)
	return raw
}

func bundleWith(t *testing.T, f *q3fixture.Fixture, snapshot *abdrc.CommittedBlock, candidate []byte) []byte {
	t.Helper()
	raw, err := q3active.EncodeBundle(q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: snapshot, Candidate: candidate})
	require.NoError(t, err)
	return raw
}

// proofAuthority is an authority of validator index v of the fixture's genesis EVM configuration, enrolled at root epoch 1 against the
// fixture's genesis trust and configuration, with its lineage pinned to that genesis. The test gives it the validator's key (the only
// way to have a configuration that names it: in production the authority's own key is what the configuration is generated from).
func proofAuthority(t *testing.T, f *q3fixture.Fixture, v int, opts ...Option) *Authority {
	t.Helper()
	conf := f.ShardConf
	enroll := Enrollment{AuthorityID: "a", NodeID: conf.Validators[v].NodeID, NetworkID: conf.NetworkID, PartitionID: conf.PartitionID, ShardID: conf.ShardID,
		ShardEpoch: conf.Epoch, RootEpoch: PinRootEpoch(1), Profile: ProfileLegacyBCRv1}
	a, err := New(enroll, currentTrust{base: f.Old}, append([]Option{WithLineage(f.Old, f.UTB)}, opts...)...)
	require.NoError(t, err)
	giveKey(t, a, f.GenesisEVM[v].Signer)
	require.NoError(t, a.CompleteEnrollment(conf))
	_, err = a.ReplaceSession()
	require.NoError(t, err)
	return a
}

func giveKey(t *testing.T, a *Authority, signer abcrypto.Signer) {
	t.Helper()
	pub, err := publicKeyOf(signer)
	require.NoError(t, err)
	fp := sha256.Sum256(pub)
	a.mu.Lock()
	a.signer, a.enroll.SigningKeyFingerprint = signer, fp[:]
	a.mu.Unlock()
}

func TestARootOnlyActivationAdvancesTheScopeAndAReplayIsANoOp(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	a := proofAuthority(t, f, 0)
	before := a.Status()
	confHash := a.Enrollment().ShardConfHash
	a.mu.Lock()
	a.irAckSeen = true // the authority operated at its shard epoch
	a.mu.Unlock()

	res, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f))
	require.NoError(t, err)
	require.Equal(t, AdvanceResult{Epoch: 2, Advanced: true, RootEpoch: 2, ShardEpoch: before.ShardEpoch, LineageEpoch: 2, Generation: before.Generation + 1}, res,
		"the generation every session up to which the advance fenced")
	after := a.Status()
	require.True(t, after.LineagePinned)
	require.Equal(t, uint64(2), after.RootEpoch)
	require.Equal(t, before.Generation+1, after.Generation, "the client is fenced")
	require.False(t, after.SessionIssued, "the next session is the operator's")
	require.Equal(t, confHash, a.Enrollment().ShardConfHash, "a root-only change keeps the configuration")
	a.mu.Lock()
	require.True(t, a.irAckSeen, "the same shard epoch: the acknowledgement is not reset")
	tb, err := a.trust.GetByEpoch(context.Background(), 2)
	a.mu.Unlock()
	require.NoError(t, err)
	want := f.History.Tip().Projection()
	require.Equal(t, want.RootNodes, tb.RootNodes, "the successor trust is the lineage's own projection, not anything supplied")
	require.Equal(t, want.QuorumThreshold, tb.QuorumThreshold)

	again, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f))
	require.NoError(t, err, "an exact duplicate is a no-op")
	require.True(t, again.Replay)
	require.False(t, again.Advanced)
	require.Equal(t, after.Generation, a.Status().Generation, "and fences nothing")
}

func coupledFixture(t *testing.T) *q3fixture.Fixture {
	return q3fixture.New(t, q3fixture.Options{Assignment: true})
}

// keptIndex is a genesis EVM validator the coupled successor keeps with its key, and droppedIndex one it does not name.
func keptAndDropped(t *testing.T, f *q3fixture.Fixture) (kept, dropped int) {
	t.Helper()
	kept, dropped = -1, -1
	for i, v := range f.ShardConf.Validators {
		named := false
		for _, s := range f.Successor.Validators {
			if s.NodeID == v.NodeID && bytes.Equal(s.SigKey, v.SigKey) {
				named = true
			}
		}
		if named && kept < 0 {
			kept = i
		}
		if !named && dropped < 0 {
			dropped = i
		}
	}
	require.GreaterOrEqual(t, kept, 0)
	require.GreaterOrEqual(t, dropped, 0)
	return kept, dropped
}

func TestACoupledActivationDerivesTheConfigurationItselfAndKeepsTheAcknowledgementRule(t *testing.T) {
	f := coupledFixture(t)
	kept, _ := keptAndDropped(t, f)
	a := proofAuthority(t, f, kept)
	old := a.Enrollment()
	a.mu.Lock()
	a.irAckSeen = true
	a.rec = record{scopeVersion: a.scopeVersion, reserved: 41, unsigned: []byte{1}, digest: sha256.Sum256([]byte{1}), authorizationID: []byte{2}}
	a.mu.Unlock()

	res, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f))
	require.NoError(t, err)
	require.True(t, res.Advanced)
	enrolled := a.Enrollment()
	require.Greater(t, enrolled.ShardEpoch, old.ShardEpoch, "the activated assignment's shard epoch")
	_, activated, err := activatedOf(f)
	require.NoError(t, err)
	hash, err := activated.Hash(gocrypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, hash, enrolled.ShardConfHash, "derived from the committed candidate, never supplied")
	a.mu.Lock()
	defer a.mu.Unlock()
	require.Equal(t, uint64(41), a.rec.reserved, "the high-water record is kept")
	require.True(t, a.irBaseKnown)
	require.Equal(t, old.ShardEpoch, a.irBase, "the epoch it acknowledged is the input-record epoch to expect")
	require.False(t, a.irAckSeen)
}

func TestAnActivationThatDropsTheValidatorRetiresTheAuthority(t *testing.T) {
	f := coupledFixture(t)
	_, dropped := keptAndDropped(t, f)
	a := proofAuthority(t, f, dropped)
	before := a.Enrollment()
	res, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f))
	require.NoError(t, err)
	require.True(t, res.Retired)
	require.False(t, res.Advanced)
	st := a.Status()
	require.True(t, st.Retired)
	require.Equal(t, uint64(2), st.LineageEpoch, "the history is installed")
	require.Equal(t, before.ShardConfHash, a.Enrollment().ShardConfHash, "no scope is taken from an activation that does not name it")
	_, err = a.ReplaceSession()
	require.ErrorIs(t, err, ErrRetired, "no session is issued again")
	require.ErrorIs(t, a.Sign(Session{authority: a.instance, generation: a.generation}), ErrRetired)
	again, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f))
	require.NoError(t, err)
	require.True(t, again.Retired && again.Replay)
}

func TestANodeNamedWithAnotherKeyIsRetired(t *testing.T) {
	f := coupledFixture(t)
	kept, dropped := keptAndDropped(t, f)
	a := proofAuthority(t, f, kept)
	giveKey(t, a, f.GenesisEVM[dropped].Signer) // this authority's key is not the one the successor names for the node
	res, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f))
	require.NoError(t, err)
	require.True(t, res.Retired)
}

func TestCorruptedProofsAreRefusedAndChangeNothing(t *testing.T) {
	f := coupledFixture(t)
	kept, _ := keptAndDropped(t, f)
	good := bundleOf(t, f)
	tamperedSnapshot := *f.Snapshot
	tamperedSnapshot.ShardInfo = append([]abdrc.ShardInfo(nil), f.Snapshot.ShardInfo...)
	tamperedSnapshot.ShardInfo[0].IRTR.Round++
	stranger := q3fixture.New(t, q3fixture.Options{Assignment: true}) // another chain: another genesis, old committee and network history
	forged := q3fixture.New(t, q3fixture.Options{Chain: f, SignedBy: 1})
	cases := map[string][]byte{
		"truncated bytes":             good[:len(good)-7],
		"a flipped byte":              flip(good, len(good)/2),
		"a snapshot not committed":    bundleWith(t, f, &tamperedSnapshot, f.Candidate),
		"no candidate":                bundleWith(t, f, f.Snapshot, nil),
		"another handoff's candidate": bundleWith(t, f, f.Snapshot, stranger.Candidate),
		"another chain":               bundleOf(t, stranger),
		"a commit below the quorum":   bundleOf(t, forged),
		"empty":                       nil,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			a := proofAuthority(t, f, kept)
			before, enrolled := a.Status(), a.Enrollment()
			_, err := a.AdvanceWithProof(context.Background(), raw)
			require.ErrorIs(t, err, ErrLineageUnverified)
			require.Equal(t, before, a.Status())
			require.Equal(t, enrolled, a.Enrollment())
		})
	}
	t.Run("a configuration hash the checkpoint does not certify", func(t *testing.T) {
		a := proofAuthority(t, f, kept)
		a.mu.Lock()
		a.enroll.ShardConfHash = bytes.Repeat([]byte{9}, 32)
		a.mu.Unlock()
		_, err := a.AdvanceWithProof(context.Background(), good)
		require.ErrorIs(t, err, ErrLineageUnverified)
		require.Equal(t, uint64(1), a.Status().RootEpoch)
	})
	t.Run("a provisioned root trust that is not the lineage's", func(t *testing.T) {
		a := proofAuthority(t, f, kept)
		a.mu.Lock()
		a.trust = currentTrust{base: stranger.Old}
		a.mu.Unlock()
		_, err := a.AdvanceWithProof(context.Background(), good)
		require.ErrorIs(t, err, ErrContextMismatch)
		require.Equal(t, uint64(1), a.Status().RootEpoch)
	})
	t.Run("a pin of another network", func(t *testing.T) {
		other := *f.Old
		other.NetworkID++
		conf := f.ShardConf
		_, err := New(Enrollment{AuthorityID: "a", NodeID: conf.Validators[0].NodeID, NetworkID: conf.NetworkID, PartitionID: conf.PartitionID,
			RootEpoch: PinRootEpoch(1), Profile: ProfileLegacyBCRv1}, currentTrust{base: f.Old}, WithLineage(&other, false))
		require.Error(t, err)
	})
}

func flip(raw []byte, i int) []byte {
	out := bytes.Clone(raw)
	out[i] ^= 0x01
	return out
}

func TestSkippedAndConflictingEpochs(t *testing.T) {
	f1 := q3fixture.New(t, q3fixture.Options{})
	f2 := q3fixture.New(t, q3fixture.Options{After: f1})
	a := proofAuthority(t, f1, 0)
	_, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f2))
	require.ErrorIs(t, err, ErrLineageUnverified, "epoch 3 before epoch 2: send them in order")
	require.Equal(t, uint64(1), a.Status().LineageEpoch)

	res, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f1))
	require.NoError(t, err)
	require.True(t, res.Advanced)
	res, err = a.AdvanceWithProof(context.Background(), bundleOf(t, f2))
	require.NoError(t, err)
	require.True(t, res.Advanced)
	require.Equal(t, uint64(3), a.Status().RootEpoch)

	conflict := q3fixture.New(t, q3fixture.Options{Chain: f1, Weights: []uint64{5, 2, 1, 1}}) // another epoch 2 of the same chain
	_, err = a.AdvanceWithProof(context.Background(), bundleOf(t, conflict))
	require.ErrorIs(t, err, ErrLineageUnverified)
	require.Equal(t, uint64(3), a.Status().RootEpoch)
}

// An authority whose lineage is behind its scope (it was provisioned at a later epoch) catches up first, and the bundle of its own epoch
// authenticates the trust it was provisioned with; only then does it advance.
func TestALaggingLineageCatchesUpAndAuthenticatesTheProvisionedTip(t *testing.T) {
	f1 := q3fixture.New(t, q3fixture.Options{})
	f2 := q3fixture.New(t, q3fixture.Options{After: f1})
	a := proofAuthority(t, f1, 0)
	a.mu.Lock()
	a.enroll.RootEpoch = PinRootEpoch(2)
	a.trust = currentTrust{base: f1.History.Tip().Projection()}
	a.mu.Unlock()

	_, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f2))
	require.ErrorIs(t, err, ErrLineageUnverified, "its own epoch is not in the lineage yet")
	res, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f1))
	require.NoError(t, err)
	require.False(t, res.Advanced, "catch-up of the lineage only")
	require.Equal(t, uint64(2), res.LineageEpoch)
	res, err = a.AdvanceWithProof(context.Background(), bundleOf(t, f2))
	require.NoError(t, err)
	require.True(t, res.Advanced)
	require.Equal(t, uint64(3), res.RootEpoch)

	b := proofAuthority(t, f1, 0)
	b.mu.Lock()
	b.enroll.RootEpoch = PinRootEpoch(2)
	other := q3fixture.New(t, q3fixture.Options{Chain: f1, Weights: []uint64{5, 2, 1, 1}})
	b.trust = currentTrust{base: other.History.Tip().Projection()} // provisioned with an epoch-2 trust that is not the lineage's
	b.mu.Unlock()
	_, err = b.AdvanceWithProof(context.Background(), bundleOf(t, f1))
	require.ErrorIs(t, err, ErrContextMismatch)
}

// bft-core#1114: a member that joins at root epoch 3 has its authority provisioned with the epoch-3 trust before that epoch activates
// (it attests possession for the handoff), so the trust's boundary is a guess: in a UTB chain the activation round is fixed only by the
// old committee's commit. Its lineage, pinned at the genesis, catches up through epoch 2, authenticates the provisioned epoch-3
// committee and from then on holds the lineage's epoch-3 trust, and the next handoff advances it to epoch 4. A provisioned trust of
// the same epoch whose committee is not the lineage's is still refused.
func TestAJoinedMemberAuthenticatesItsProvisionedCommitteeAndAdvances(t *testing.T) {
	f1 := q3fixture.New(t, q3fixture.Options{UTB: true})
	f2 := q3fixture.New(t, q3fixture.Options{UTB: true, After: f1})
	f3 := q3fixture.New(t, q3fixture.Options{UTB: true, After: f2})
	lineage3 := f2.History.Tip().Projection()
	require.EqualValues(t, 3, lineage3.Epoch)
	prepared := func(edit func(tb *types.RootTrustBaseV1)) *types.RootTrustBaseV1 {
		tb := f2.History.Tip().Projection()
		tb.EpochStart = 400000 // the drive's prepare-time boundary (handoff_drive.epoch_start), not the committed activation round
		require.NotEqual(t, lineage3.EpochStart, tb.EpochStart)
		if edit != nil {
			edit(tb)
		}
		return tb
	}
	joiner := func(t *testing.T, provisioned *types.RootTrustBaseV1) *Authority {
		a := proofAuthority(t, f1, 0)
		a.mu.Lock()
		a.enroll.RootEpoch = PinRootEpoch(3)
		a.trust = currentTrust{base: provisioned}
		a.mu.Unlock()
		res, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f1))
		require.NoError(t, err, "the earlier proof extends the lineage")
		require.False(t, res.Advanced)
		require.EqualValues(t, 2, res.LineageEpoch)
		return a
	}

	t.Run("the next handoff", func(t *testing.T) {
		a := joiner(t, prepared(nil))
		gen := a.Status().Generation
		res, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f2))
		require.NoError(t, err, "the provisioned committee is the lineage's")
		require.False(t, res.Advanced)
		require.False(t, res.Replay)
		require.EqualValues(t, 3, res.RootEpoch)
		require.EqualValues(t, 3, res.LineageEpoch)
		require.Equal(t, gen, res.Generation, "the scope is unchanged: no fence")
		require.True(t, a.Status().SessionIssued)
		held, err := a.trust.GetByEpoch(context.Background(), 3)
		require.NoError(t, err)
		require.Equal(t, lineage3.EpochStart, held.EpochStart, "the authority holds the lineage's boundary from now on")

		res, err = a.AdvanceWithProof(context.Background(), bundleOf(t, f3))
		require.NoError(t, err)
		require.True(t, res.Advanced)
		require.EqualValues(t, 4, res.RootEpoch)
		require.EqualValues(t, 4, res.LineageEpoch)
		// the drive's resume sends the target's bundle again: a replay
		res, err = a.AdvanceWithProof(context.Background(), bundleOf(t, f3))
		require.NoError(t, err)
		require.True(t, res.Replay)
	})

	t.Run("a held trust whose boundary is not the lineage's is refused at the advance from it", func(t *testing.T) {
		a := joiner(t, prepared(nil))
		_, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f2))
		require.NoError(t, err)
		a.mu.Lock()
		a.trust = currentTrust{base: prepared(nil)}
		a.mu.Unlock()
		_, err = a.AdvanceWithProof(context.Background(), bundleOf(t, f3))
		require.ErrorIs(t, err, ErrContextMismatch)
		require.EqualValues(t, 3, a.Status().RootEpoch)
	})

	other := q3fixture.New(t, q3fixture.Options{UTB: true, After: f1, Weights: []uint64{5, 2, 1, 1}}).History.Tip().Projection()
	require.EqualValues(t, 3, other.Epoch)
	different := map[string]*types.RootTrustBaseV1{
		"another epoch-3 committee": other,
		"a member's key": prepared(func(tb *types.RootTrustBaseV1) {
			tb.RootNodes[0].SigKey = bytes.Clone(tb.RootNodes[1].SigKey)
		}),
		"a member's weight": prepared(func(tb *types.RootTrustBaseV1) { tb.RootNodes[0].Stake++ }),
		"the threshold":     prepared(func(tb *types.RootTrustBaseV1) { tb.QuorumThreshold++ }),
		"the network":       prepared(func(tb *types.RootTrustBaseV1) { tb.NetworkID++ }),
		"a member listed twice for one left out": prepared(func(tb *types.RootTrustBaseV1) {
			n := tb.RootNodes[0]
			tb.RootNodes[1] = &types.NodeInfo{NodeID: n.NodeID, SigKey: bytes.Clone(n.SigKey), Stake: n.Stake}
		}),
		"a member fewer": prepared(func(tb *types.RootTrustBaseV1) { tb.RootNodes = tb.RootNodes[1:] }),
	}
	for name, provisioned := range different {
		t.Run(name, func(t *testing.T) {
			a := joiner(t, provisioned)
			before := a.Status()
			_, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f2))
			require.ErrorIs(t, err, ErrContextMismatch)
			require.Equal(t, before, a.Status(), "nothing changes: the lineage stays at 2")
			held, err := a.trust.GetByEpoch(context.Background(), 3)
			require.NoError(t, err)
			require.Same(t, provisioned, held)
			_, err = a.AdvanceWithProof(context.Background(), bundleOf(t, f3))
			require.ErrorIs(t, err, ErrLineageUnverified, "and the next epoch does not follow the lineage's tip")
		})
	}
}

func TestTheUncheckedAdvanceIsRecoveryOnly(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	next := f.History.Tip().Projection()
	a := proofAuthority(t, f, 0)
	require.ErrorIs(t, a.AdvanceEpoch(context.Background(), f.ShardConf, next), ErrRecoveryOnly)
	require.Equal(t, uint64(1), a.Status().RootEpoch)

	recovery := proofAuthority(t, f, 0, WithUncheckedAdvance())
	require.NoError(t, recovery.AdvanceEpoch(context.Background(), f.ShardConf, next), "the explicit recovery policy")
	require.Equal(t, uint64(2), recovery.Status().RootEpoch)
	require.False(t, recovery.Status().SessionIssued)
}

func TestAClosedAuthorityAdvancesNothing(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	a := proofAuthority(t, f, 0)
	a.Close()
	_, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f))
	require.ErrorIs(t, err, ErrKeyLost)
}

func TestAnAuthorityWithoutAPinRefusesProofs(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	conf := f.ShardConf
	a, err := New(Enrollment{AuthorityID: "a", NodeID: conf.Validators[0].NodeID, NetworkID: conf.NetworkID, PartitionID: conf.PartitionID,
		ShardEpoch: conf.Epoch, RootEpoch: PinRootEpoch(1), Profile: ProfileLegacyBCRv1}, currentTrust{base: f.Old})
	require.NoError(t, err)
	_, err = a.AdvanceWithProof(context.Background(), bundleOf(t, f))
	require.ErrorIs(t, err, ErrLineageUnverified)
	require.False(t, a.Status().LineagePinned)
}

// Proof advances race every signing operation and session replacement; the advance is serialised with them and a second advance at
// the same time is refused, not interleaved. Run under -race.
func TestAProofAdvanceRacesSigningAndSessions(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	a := proofAuthority(t, f, 0)
	raw := bundleOf(t, f)
	ctx := context.Background()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				a.mu.Lock()
				s := Session{authority: a.instance, generation: a.generation}
				a.mu.Unlock()
				_ = a.Sign(s)
				_ = a.RetainResponse(s)
				_, _ = a.Release(s, 1, [32]byte{})
				_, _ = a.Reserve(ctx, s, Request{})
				_ = a.Status()
				_, _ = a.ReplaceSession()
			}
		}()
	}
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := a.AdvanceWithProof(ctx, raw)
			results <- err
		}()
	}
	for range 8 {
		err := <-results
		if err != nil {
			require.True(t, errorsIsAny(err, ErrAdvanceBusy, ErrConflict), "%v", err)
		}
	}
	close(stop)
	wg.Wait()
	st := a.Status()
	require.Equal(t, uint64(2), st.RootEpoch, "advanced exactly once, whatever the interleaving")
	require.False(t, st.Faulted)
	res, err := a.AdvanceWithProof(ctx, raw)
	require.NoError(t, err)
	require.True(t, res.Replay)
}

func errorsIsAny(err error, targets ...error) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}

func activatedOf(f *q3fixture.Fixture) (evmassign.Candidate, *types.PartitionDescriptionRecord, error) {
	return evmassign.ActivatedFromPreimage(f.Candidate, f.Proof.Record.ActivationRound)
}

// A retired authority signs nothing of any kind (astra on #1087): the handoff possession proof and the EVM election and delegation
// possessions are refused as well as certification, after a real proof-driven retirement, and also when the retirement races them.
func TestARetiredAuthorityAttestsNoPossession(t *testing.T) {
	f := coupledFixture(t)
	kept, dropped := keptAndDropped(t, f)
	ctx := context.Background()
	requests := func(a *Authority) (HandoffPoPRequest, ElectionPoPRequest, DelegationPossessionRequest) {
		pub, err := a.SigningPublicKey()
		require.NoError(t, err)
		e := a.Enrollment()
		succ := f.ShardConf
		handoff := HandoffPoPRequest{Domain: evmassign.PoPDomain, NodeID: e.NodeID, Successor: succ,
			Context: evmassign.PoPContext{Network: uint64(e.NetworkID), Attempt: 2, Predecessor: [32]byte{1}}}
		election := ElectionPoPRequest{Attempt: 3}
		delegation := DelegationPossessionRequest{Network: [32]byte{7}, Request: evmassign.DelegationRequest{Id: 5, Generation: 1, Expiry: 1_000_000_000,
			Binding: evmassign.DelegationBinding{EvmKey: pub}}}
		return handoff, election, delegation
	}
	signAll := func(a *Authority) []error {
		h, e, d := requests(a)
		_, errH := a.SignHandoffPoP(h)
		_, errE := a.SignElectionPoP(e)
		_, errD := a.SignDelegationPossession(d)
		return []error{errH, errE, errD}
	}

	control := proofAuthority(t, f, kept)
	for i, err := range signAll(control) {
		require.NotErrorIs(t, err, ErrRetired, "operation %d of an active authority", i)
	}
	retired := proofAuthority(t, f, dropped)
	res, err := retired.AdvanceWithProof(ctx, bundleOf(t, f))
	require.NoError(t, err)
	require.True(t, res.Retired)
	for i, err := range signAll(retired) {
		require.ErrorIs(t, err, ErrRetired, "operation %d after the retirement", i)
	}

	racing := proofAuthority(t, f, dropped)
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					signAll(racing)
				}
			}
		}()
	}
	res, err = racing.AdvanceWithProof(ctx, bundleOf(t, f))
	require.NoError(t, err)
	require.True(t, res.Retired)
	for i, err := range signAll(racing) {
		require.ErrorIs(t, err, ErrRetired, "operation %d once the retirement is published", i)
	}
	close(done)
	wg.Wait()
}

// bft-core#1091: on a UTB chain the authority advances when its lineage is pinned as a UTB genesis, and refuses the activation (changing
// nothing) when it is not.
func TestAUTBChainAdvancesOnlyAUTBPinnedAuthority(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{UTB: true})
	require.True(t, f.UTB)
	a := proofAuthority(t, f, 0) // pinned WithLineage(f.Old, f.UTB)
	res, err := a.AdvanceWithProof(context.Background(), bundleOf(t, f))
	require.NoError(t, err)
	require.True(t, res.Advanced)

	conf := f.ShardConf
	b, err := New(Enrollment{AuthorityID: "b", NodeID: conf.Validators[0].NodeID, NetworkID: conf.NetworkID, PartitionID: conf.PartitionID, ShardID: conf.ShardID,
		ShardEpoch: conf.Epoch, RootEpoch: PinRootEpoch(1), Profile: ProfileLegacyBCRv1}, currentTrust{base: f.Old}, WithLineage(f.Old, false))
	require.NoError(t, err)
	giveKey(t, b, f.GenesisEVM[0].Signer)
	require.NoError(t, b.CompleteEnrollment(conf))
	_, err = b.AdvanceWithProof(context.Background(), bundleOf(t, f))
	require.ErrorIs(t, err, ErrLineageUnverified)
	require.ErrorContains(t, err, "UTB envelope")
	require.EqualValues(t, 1, b.Status().RootEpoch)
}
