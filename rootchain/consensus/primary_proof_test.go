package consensus

import (
	"bytes"
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
)

type fakeWitness struct {
	mu         sync.Mutex
	err        error
	factsErr   error
	facts      evmassign.PrimaryFacts
	parent     []byte
	builds     int
	factsCalls int
	release    chan struct{} // when set, a build waits for it
}

func (f *fakeWitness) PrimaryWitness(parent []byte, _ [32]byte) ([]byte, error) {
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

func (f *fakeWitness) PrimaryFacts([32]byte) (evmassign.PrimaryFacts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.factsCalls++
	return f.facts, f.factsErr
}

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
