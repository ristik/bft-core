package consensus

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

type fakeWitness struct {
	mu           sync.Mutex
	err          error
	factsErr     error
	facts        evmassign.PrimaryFacts
	parent       []byte
	builds       int
	factsCalls   int
	release      chan struct{} // when set, a build waits for it
	factsRelease chan struct{} // when set, a facts read waits for it
}

func (f *fakeWitness) PrimaryWitness(_ context.Context, parent []byte, _ [32]byte) ([]byte, error) {
	f.mu.Lock()
	f.builds++
	f.parent = parent
	rel, err := f.release, f.err
	f.mu.Unlock()
	if rel != nil {
		<-rel
	}
	return []byte("witness"), err
}

func (f *fakeWitness) PrimaryFacts(_ context.Context, _ [32]byte) (evmassign.PrimaryFacts, error) {
	f.mu.Lock()
	f.factsCalls++
	rel, facts, err := f.factsRelease, f.facts, f.factsErr
	f.mu.Unlock()
	if rel != nil {
		<-rel
	}
	return facts, err
}

func (f *fakeWitness) factsCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.factsCalls }

func (f *fakeWitness) buildCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.builds }

type fakeAuthority struct{}

func (fakeAuthority) VerifyPrimary([]byte, [32]byte, [32]byte) (evmassign.PrimaryFacts, error) {
	return evmassign.PrimaryFacts{}, nil
}

func managerFor(judged bool) *ConsensusManager {
	bs := &storage.BlockStore{}
	svc := &storage.PosServices{}
	if judged {
		svc.Primary = fakeAuthority{}
		svc.Deployment.Election = [20]byte{19: 3}
		svc.Deployment.NetworkWord = [32]byte{1}
		svc.Deployment.Custody = [20]byte{19: 5}
		svc.Deployment.ChainID = [32]byte{31: 1}
	}
	bs.SetPosServices(svc)
	return &ConsensusManager{blockStore: bs, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

type memberFx struct {
	c    evmassign.Candidate
	keys []*ecdsa.PrivateKey
}

func newMemberFx(t *testing.T, n int) memberFx {
	f := memberFx{c: evmassign.Candidate{Kind: evmassign.KindPrimary, Authorization: &evmassign.Authorization{
		ResultID: bytes.Repeat([]byte{4}, 32), SnapshotDigest: bytes.Repeat([]byte{5}, 32)}}}
	for i := 0; i < n; i++ {
		k, err := ethcrypto.GenerateKey()
		require.NoError(t, err)
		f.keys = append(f.keys, k)
		sid := make([]byte, evmassign.StakingIDLen)
		sid[evmassign.StakingIDLen-1] = byte(i + 1)
		f.c.Identities = append(f.c.Identities, evmassign.Identity{StakingID: sid, Generation: 1, EVMKey: ethcrypto.CompressPubkey(&k.PublicKey)})
	}
	return f
}

func (f memberFx) dep(x *ConsensusManager) evmassign.ElectionDeployment {
	svc := x.blockStore.PosServices()
	return evmassign.ElectionDeployment{Deployment: svc.Deployment.Deployment, Election: svc.Deployment.Election}
}

func (f memberFx) pops(t *testing.T, x *ConsensusManager, attempt uint64, keys []*ecdsa.PrivateKey) []evmassign.EVMPoP {
	var out []evmassign.EVMPoP
	for _, k := range keys {
		p, err := evmassign.SignEVMPoP(k, f.c, f.dep(x), attempt)
		require.NoError(t, err)
		out = append(out, p)
	}
	return out
}

func encoded(t *testing.T, p []evmassign.EVMPoP) []byte {
	raw, err := evmassign.EncodePoPs(p)
	require.NoError(t, err)
	return raw
}

// The proofs are judged in full when a plan arrives: well-formed but wrong proofs never occupy the plan's slot, because they never get in.
func TestCheckPrimaryPoPsJudgesTheProofsOnArrival(t *testing.T) {
	x := managerFor(true)
	f := newMemberFx(t, 3)
	honest := f.pops(t, x, 7, f.keys)
	_, set, err := evmassign.AssemblePoPs(f.c, f.dep(x), 7, honest)
	require.NoError(t, err)
	src := &fakeWitness{facts: evmassign.PrimaryFacts{Published: true, Attempt: 7, PopSetDigest: set}}
	x.SetPrimaryWitnessSource(src)
	msg := func(p []evmassign.EVMPoP) *abdrc.HandoffApprovalMsg {
		return &abdrc.HandoffApprovalMsg{CandidatePreimage: []byte{1}, PrimaryPoPs: encoded(t, p)}
	}

	require.NoError(t, x.checkPrimaryPoPs(msg(honest), f.c))
	require.Equal(t, 1, src.factsCalls)
	require.NoError(t, x.checkPrimaryPoPs(msg(honest), f.c))
	require.Equal(t, 1, src.factsCalls, "a published result's facts are cached")

	stranger := make([]evmassign.EVMPoP, 3)
	copy(stranger, honest)
	stranger[1].Signature = bytes.Clone(honest[0].Signature) // well-formed, wrong
	for name, bad := range map[string][]evmassign.EVMPoP{
		"another member's signature": stranger,
		"a proof of another attempt": f.pops(t, x, 8, f.keys),
		"a member missing":           honest[:2],
		"proofs of non-members":      append(append([]evmassign.EVMPoP{}, honest[:2]...), evmassign.EVMPoP{ID: 99, EVMKey: honest[0].EVMKey, Signature: honest[0].Signature}),
	} {
		err := x.checkPrimaryPoPs(msg(bad), f.c)
		require.ErrorIs(t, err, storage.ErrPrimaryProofRefused, name)
		require.ErrorIs(t, err, ErrHandoffApproval, name)
	}

	// valid signatures that are not the set the election stored (the stored digest is what fixes the set)
	src.mu.Lock()
	src.facts.PopSetDigest[0] ^= 1
	src.mu.Unlock()
	x.primaryCache.mu.Lock()
	x.primaryCache.facts = nil
	x.primaryCache.mu.Unlock()
	require.ErrorIs(t, x.checkPrimaryPoPs(msg(honest), f.c), storage.ErrPrimaryProofRefused, "valid proofs, not the stored set")
}

func TestCheckPrimaryPoPsNeedsTheExecutionClientAndAPublishedResult(t *testing.T) {
	x := managerFor(true)
	f := newMemberFx(t, 3)
	honest := f.pops(t, x, 7, f.keys)
	msg := &abdrc.HandoffApprovalMsg{CandidatePreimage: []byte{1}, PrimaryPoPs: encoded(t, honest)}

	require.ErrorIs(t, x.checkPrimaryPoPs(msg, f.c), storage.ErrWitnessUnavailable, "no client configured: refused for now")
	src := &fakeWitness{factsErr: errors.New("node down")}
	x.SetPrimaryWitnessSource(src)
	require.ErrorIs(t, x.checkPrimaryPoPs(msg, f.c), storage.ErrWitnessUnavailable)
	src.factsErr, src.facts = nil, evmassign.PrimaryFacts{Published: false}
	require.ErrorIs(t, x.checkPrimaryPoPs(msg, f.c), evmassign.ErrNotPublished)
	require.Empty(t, x.primaryCache.facts, "an unpublished result is not cached")
}

func TestCheckPrimaryPoPsRequiresThemExactlyWhereTheChainJudges(t *testing.T) {
	primary, recovery := evmassign.Candidate{Kind: evmassign.KindPrimary}, evmassign.Candidate{Kind: evmassign.KindRecovery}
	somePoPs := encoded(t, []evmassign.EVMPoP{{ID: 1, EVMKey: bytes.Repeat([]byte{2}, 33), Signature: bytes.Repeat([]byte{3}, 65)}})
	withPoPs := &abdrc.HandoffApprovalMsg{CandidatePreimage: []byte{1}, PrimaryPoPs: somePoPs}
	without := &abdrc.HandoffApprovalMsg{CandidatePreimage: []byte{1}}
	junk := &abdrc.HandoffApprovalMsg{CandidatePreimage: []byte{1}, PrimaryPoPs: []byte{0xf6}}

	judged, plain := managerFor(true), managerFor(false)
	require.ErrorIs(t, judged.checkPrimaryPoPs(without, primary), storage.ErrPrimaryProofMissing)
	require.ErrorIs(t, judged.checkPrimaryPoPs(junk, primary), storage.ErrPrimaryProofMissing)
	require.ErrorIs(t, judged.checkPrimaryPoPs(withPoPs, recovery), storage.ErrPrimaryProofUnexpected, "a recovery proves nothing")
	require.NoError(t, judged.checkPrimaryPoPs(without, recovery))
	require.ErrorIs(t, plain.checkPrimaryPoPs(withPoPs, primary), storage.ErrPrimaryProofUnexpected, "an unjudged chain takes none")
	require.NoError(t, plain.checkPrimaryPoPs(without, primary))
	require.ErrorIs(t, judged.checkPrimaryPoPs(&abdrc.HandoffApprovalMsg{PrimaryPoPs: somePoPs}, primary), storage.ErrPrimaryProofUnexpected, "a root-only plan carries none")
}

// The proposal path only reads the cache; the build runs in the background and is rebuilt only for a new (frozen parent, result).
func TestPrimaryFreezeProofNeverBlocksTheRoundAndIsBuiltOncePerOrigin(t *testing.T) {
	parent := bytes.Repeat([]byte{9}, 32)
	primary, recovery := evmassign.Candidate{Kind: evmassign.KindPrimary, Authorization: &evmassign.Authorization{ResultID: bytes.Repeat([]byte{4}, 32)}}, evmassign.Candidate{Kind: evmassign.KindRecovery}
	pops := encoded(t, []evmassign.EVMPoP{{ID: 1, EVMKey: bytes.Repeat([]byte{2}, 33), Signature: bytes.Repeat([]byte{3}, 65)}})
	x := managerFor(true)

	release := make(chan struct{})
	w := &fakeWitness{release: release}
	x.SetPrimaryWitnessSource(w)

	start := time.Now()
	_, err := x.primaryProofFor(primary, pops, parent)
	require.ErrorIs(t, err, storage.ErrWitnessUnavailable, "a miss is a cache miss")
	_, err = x.primaryProofFor(primary, pops, parent)
	require.ErrorIs(t, err, storage.ErrWitnessUnavailable)
	require.Less(t, time.Since(start), time.Second, "the round never waits for the execution client")
	require.Eventually(t, func() bool { return w.buildCount() == 1 }, 2*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, w.buildCount(), "one build in flight however many rounds ask")

	close(release)
	var raw []byte
	require.Eventually(t, func() bool {
		raw, err = x.primaryProofFor(primary, pops, parent)
		return err == nil
	}, 2*time.Second, 5*time.Millisecond)
	proof, err := evmassign.DecodePrimaryProof(raw)
	require.NoError(t, err)
	require.Equal(t, []byte("witness"), proof.Witness)
	require.Equal(t, parent, w.parent, "built at the parent the root bound")
	_, err = x.primaryProofFor(primary, pops, parent)
	require.NoError(t, err)
	require.Equal(t, 1, w.buildCount(), "the same origin is not rebuilt")

	// a new frozen parent is a new origin
	other := bytes.Repeat([]byte{8}, 32)
	_, err = x.primaryProofFor(primary, pops, other)
	require.ErrorIs(t, err, storage.ErrWitnessUnavailable)
	require.Eventually(t, func() bool { return w.buildCount() == 2 }, 2*time.Second, 5*time.Millisecond)

	none, err := x.primaryProofFor(recovery, nil, parent)
	require.NoError(t, err)
	require.Nil(t, none, "a recovery carries no proof")
	none, err = managerFor(false).primaryProofFor(primary, nil, parent)
	require.NoError(t, err)
	require.Nil(t, none, "an unjudged chain builds none")
	_, err = x.primaryProofFor(primary, nil, parent)
	require.ErrorIs(t, err, storage.ErrPrimaryProofMissing)
}

func TestAFailedWitnessBuildIsRetriedAfterTheBackoffNotEveryRound(t *testing.T) {
	parent := bytes.Repeat([]byte{9}, 32)
	primary := evmassign.Candidate{Kind: evmassign.KindPrimary, Authorization: &evmassign.Authorization{ResultID: bytes.Repeat([]byte{4}, 32)}}
	pops := encoded(t, []evmassign.EVMPoP{{ID: 1, EVMKey: bytes.Repeat([]byte{2}, 33), Signature: bytes.Repeat([]byte{3}, 65)}})
	x := managerFor(true)
	w := &fakeWitness{err: errors.New("node down")}
	x.SetPrimaryWitnessSource(w)

	_, err := x.primaryProofFor(primary, pops, parent)
	require.ErrorIs(t, err, storage.ErrWitnessUnavailable)
	require.Eventually(t, func() bool { return w.buildCount() == 1 }, 2*time.Second, 5*time.Millisecond)
	for i := 0; i < 20; i++ {
		_, _ = x.primaryProofFor(primary, pops, parent)
	}
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, w.buildCount(), "rounds inside the backoff do not hammer the client")
	x.primaryCache.mu.Lock()
	x.primaryCache.failedAt = time.Now().Add(-2 * primaryWitnessRetry)
	x.primaryCache.mu.Unlock()
	w.mu.Lock()
	w.err = nil
	w.mu.Unlock()
	_, _ = x.primaryProofFor(primary, pops, parent)
	require.Eventually(t, func() bool { _, err := x.primaryProofFor(primary, pops, parent); return err == nil }, 2*time.Second, 5*time.Millisecond)
}

// The consensus loop never waits for the execution client: a facts miss returns at once with the approval parked and a background fetch
// started, however long the client takes; when the facts land the parked approval is judged and delivered.
func TestIntakeNeverCallsTheExecutionClientSynchronously(t *testing.T) {
	x := managerFor(true)
	f := newMemberFx(t, 3)
	honest := f.pops(t, x, 7, f.keys)
	_, set, err := evmassign.AssemblePoPs(f.c, f.dep(x), 7, honest)
	require.NoError(t, err)
	release := make(chan struct{})
	src := &fakeWitness{facts: evmassign.PrimaryFacts{Published: true, Attempt: 7, PopSetDigest: set}, factsRelease: release}
	x.SetPrimaryWitnessSource(src)
	delivered := make(chan string, 4)
	x.approvalSink = func(m *abdrc.HandoffApprovalMsg) error {
		// what the loop would do with it: judge it against the (now cached) facts
		if err := x.judgePoPs(m, f.c, mustFacts(t, x, f.c.ResultID())); err != nil {
			return err
		}
		delivered <- m.Signer
		return nil
	}

	result := f.c.ResultID()
	msg := func(signer string) *abdrc.HandoffApprovalMsg {
		return &abdrc.HandoffApprovalMsg{Signer: signer, PrimaryPoPs: encoded(t, honest)}
	}
	start := time.Now()
	for _, who := range []string{"a", "b"} {
		_, ok := x.cachedPrimaryFacts(result)
		require.False(t, ok)
		x.parkApproval(msg(who), result)
		x.kickPrimaryFacts(result)
	}
	require.Less(t, time.Since(start), 500*time.Millisecond, "a blocked execution client does not hold the caller")
	require.Eventually(t, func() bool { return src.factsCount() == 1 }, 2*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, src.factsCount(), "one fetch in flight however many approvals arrive")

	close(release)
	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case s := <-delivered:
			got[s] = true
		case <-time.After(2 * time.Second):
			t.Fatal("a parked approval was lost")
		}
	}
	require.Equal(t, map[string]bool{"a": true, "b": true}, got, "both honest approvals are judged when the facts land")
	_, ok := x.cachedPrimaryFacts(result)
	require.True(t, ok)
	x.primaryCache.mu.Lock()
	require.Empty(t, x.primaryCache.parked)
	x.primaryCache.mu.Unlock()
}

func mustFacts(t *testing.T, x *ConsensusManager, result [32]byte) evmassign.PrimaryFacts {
	f, ok := x.cachedPrimaryFacts(result)
	require.True(t, ok)
	return f
}

func TestParkedApprovalsAreBoundedOnePerSignerAndExpire(t *testing.T) {
	x := managerFor(true)
	result := [32]byte{1}
	for i := 0; i < maxParkedApprovals*2; i++ {
		x.parkApproval(&abdrc.HandoffApprovalMsg{Signer: string(rune('A'+i%64)) + string(rune('a'+i/64))}, result)
	}
	x.primaryCache.mu.Lock()
	require.LessOrEqual(t, len(x.primaryCache.parked), maxParkedApprovals, "a flood cannot grow the set")
	x.primaryCache.mu.Unlock()

	x2 := managerFor(true)
	x2.parkApproval(&abdrc.HandoffApprovalMsg{Signer: "s", PrimaryPoPs: []byte{1}}, result)
	x2.parkApproval(&abdrc.HandoffApprovalMsg{Signer: "s", PrimaryPoPs: []byte{2}}, result)
	x2.primaryCache.mu.Lock()
	require.Len(t, x2.primaryCache.parked, 1, "one per signer: the newest replaces")
	require.Equal(t, []byte{2}, x2.primaryCache.parked["s"].msg.PrimaryPoPs)
	p := x2.primaryCache.parked["s"]
	p.at = time.Now().Add(-2 * parkedApprovalTTL)
	x2.primaryCache.parked["s"] = p
	x2.primaryCache.mu.Unlock()
	x2.parkApproval(&abdrc.HandoffApprovalMsg{Signer: "t"}, result)
	x2.primaryCache.mu.Lock()
	require.NotContains(t, x2.primaryCache.parked, "s", "an expired approval is dropped")
	x2.primaryCache.mu.Unlock()
}

func TestAFailedFactsFetchBacksOffAndParksStay(t *testing.T) {
	x := managerFor(true)
	src := &fakeWitness{factsErr: errors.New("node down")}
	x.SetPrimaryWitnessSource(src)
	result := [32]byte{2}
	x.parkApproval(&abdrc.HandoffApprovalMsg{Signer: "a"}, result)
	x.kickPrimaryFacts(result)
	require.Eventually(t, func() bool { return src.factsCount() == 1 }, 2*time.Second, 5*time.Millisecond)
	for i := 0; i < 20; i++ {
		x.kickPrimaryFacts(result)
	}
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, src.factsCount(), "rounds inside the backoff do not hammer the client")
	x.primaryCache.mu.Lock()
	require.Len(t, x.primaryCache.parked, 1, "the approval waits for the next try")
	x.primaryCache.mu.Unlock()
}

// The real intake path with a validly signed approval of a real primary plan: the facts are not cached and the execution client blocks.
// Intake returns at once with errPrimaryFactsPending, the approval is parked and takes no slot in the plan, exactly one background fetch is
// started however many approvals arrive, and when the client answers each parked approval is judged through the same intake
// (releaseParkedApprovals -> onHandoffApprovalMsg -> judgeApprovalPoPs). Making intake fetch the facts itself (primaryFactsSync in
// judgeApprovalPoPs) blocks this test's first call and fails it.
func TestRealIntakeParksAnApprovalUntilItsFactsLandAndThenJudgesIt(t *testing.T) {
	ctx := context.Background()
	f := newOperatorAssignmentFixture(t)
	svc := &storage.PosServices{Primary: fakeAuthority{}}
	svc.Deployment.Election = [20]byte{19: 3}
	f.cm.blockStore.SetPosServices(svc)

	plan, err := f.cm.buildHandoffPlanFromState(f.next, f.state, f.proposal(t))
	require.NoError(t, err)
	require.NotEmpty(t, plan.CandidatePreimage)
	plan.PrimaryPoPs = encoded(t, []evmassign.EVMPoP{{ID: 1, EVMKey: bytes.Repeat([]byte{2}, 33), Signature: bytes.Repeat([]byte{3}, 65)}})

	// this validator endorses first (its own request may wait for the client; the proofs are not what is under test here)
	facts := evmassign.PrimaryFacts{Published: true, Attempt: 7}
	f.cm.SetPrimaryWitnessSource(&fakeWitness{facts: facts})
	f.cm.judgeHook = func(*abdrc.HandoffApprovalMsg) error { return nil }
	require.NoError(t, f.cm.endorseHandoffAtState(ctx, plan, f.preparedState(t, plan)))
	f.cm.judgeHook = nil
	require.Len(t, f.cm.handoffPlans, 1)
	var stored *pendingHandoff
	for _, p := range f.cm.handoffPlans {
		stored = p
	}
	domain, err := storage.EndorsementBytes(stored.record)
	require.NoError(t, err)
	abortDomain, err := storage.AbortEndorsementBytes(stored.record)
	require.NoError(t, err)
	peer := func(n *testutils.TestNode) *abdrc.HandoffApprovalMsg {
		m := stored.plan
		m.Signer = n.PeerConf.ID.String()
		var err error
		m.Signature, err = n.Signer.SignBytes(domain)
		require.NoError(t, err)
		m.AbortSignature, err = n.Signer.SignBytes(abortDomain)
		require.NoError(t, err)
		return &m
	}

	// the facts are no longer cached, and the execution client blocks
	f.cm.primaryCache.mu.Lock()
	f.cm.primaryCache.facts = nil
	f.cm.primaryCache.mu.Unlock()
	release := make(chan struct{})
	src := &fakeWitness{facts: facts, factsRelease: release}
	f.cm.SetPrimaryWitnessSource(src)
	judged := make(chan error, 4)
	f.cm.approvalSink = func(m *abdrc.HandoffApprovalMsg) error {
		err := f.cm.onHandoffApprovalMsg(ctx, m)
		judged <- err
		return err
	}

	first, second := peer(f.others[0]), peer(f.others[1])
	for i, m := range []*abdrc.HandoffApprovalMsg{first, second} {
		done := make(chan error, 1)
		start := time.Now()
		go func() { done <- f.cm.onHandoffApprovalMsg(ctx, m) }()
		select {
		case err := <-done:
			require.Less(t, time.Since(start), time.Second, "approval %d: a blocked execution client does not hold the intake", i)
			require.ErrorIs(t, err, errPrimaryFactsPending, "approval %d", i)
			require.ErrorIs(t, err, ErrHandoffApproval)
		case <-time.After(2 * time.Second):
			t.Fatalf("approval %d: intake is blocked on the execution client", i)
		}
	}
	f.cm.primaryCache.mu.Lock()
	require.Len(t, f.cm.primaryCache.parked, 2, "both approvals are held, one per signer")
	f.cm.primaryCache.mu.Unlock()
	f.cm.handoffMu.Lock()
	for _, p := range f.cm.handoffPlans {
		require.NotContains(t, p.signatures, first.Signer, "a parked approval takes no slot in the plan")
		require.NotContains(t, p.signatures, second.Signer)
	}
	f.cm.handoffMu.Unlock()
	require.Eventually(t, func() bool { return src.factsCount() == 1 }, 2*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, src.factsCount(), "exactly one fetch for both approvals")

	close(release)
	for i := 0; i < 2; i++ {
		select {
		case err := <-judged:
			// judged through the real intake against the landed facts: this plan's proofs are not the stored set, so each is refused for that
			require.ErrorIs(t, err, storage.ErrPrimaryProofRefused, "a parked approval is judged, not dropped")
		case <-time.After(2 * time.Second):
			t.Fatal("a parked approval was never judged")
		}
	}
	f.cm.primaryCache.mu.Lock()
	require.Empty(t, f.cm.primaryCache.parked)
	f.cm.primaryCache.mu.Unlock()
	_, cached := f.cm.cachedPrimaryFacts(plan0Result(t, plan))
	require.True(t, cached, "and the facts are cached for the approvals that follow")
}

func plan0Result(t *testing.T, plan abdrc.HandoffApprovalMsg) [32]byte {
	c, err := evmassign.DecodeCandidate(plan.CandidatePreimage)
	require.NoError(t, err)
	return c.ResultID()
}

func TestFailedFactFetchesAreForgottenAfterTheBackoff(t *testing.T) {
	x := managerFor(true)
	src := &fakeWitness{factsErr: errors.New("down")}
	x.SetPrimaryWitnessSource(src)
	old := [32]byte{0xaa}
	x.primaryCache.mu.Lock()
	x.primaryCache.factsFailed = map[[32]byte]time.Time{old: time.Now().Add(-time.Hour)}
	x.primaryCache.mu.Unlock()
	x.kickPrimaryFacts([32]byte{0xbb})
	require.Eventually(t, func() bool { return src.factsCount() == 1 }, 2*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool {
		x.primaryCache.mu.Lock()
		defer x.primaryCache.mu.Unlock()
		_, kept := x.primaryCache.factsFailed[old]
		_, fresh := x.primaryCache.factsFailed[[32]byte{0xbb}]
		return !kept && fresh
	}, 2*time.Second, 5*time.Millisecond, "a stale failure is pruned, the new one is remembered for the backoff")
}
