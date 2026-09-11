// Package f6csigning is an executable design, not a production signer or storage implementation.
// The authority's atomic durable store and authenticated enrollment are premises, not verified here.
package f6csigning

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	errContext   = errors.New("signing-context-mismatch")
	errFenced    = errors.New("signing-session-fenced")
	errStale     = errors.New("signing-stale")
	errConflict  = errors.New("signing-conflict")
	errUntrusted = errors.New("signing-state-untrusted")
	errLost      = errors.New("signing-key-lost")
	errStage     = errors.New("response-not-durable")
)

// Policy fields are immutable enrollment, not caller-selected conflict namespaces.
type policy struct {
	network, config, domain string
	epoch, rootEpoch        uint64
}

var enrolled = policy{"private-network-A", "config-A", "legacy-bcr-v1", 1, 7}

type record struct {
	round                             uint64
	unsigned, signed, durableResponse []byte
}

type authority struct {
	mu         sync.Mutex
	policy     policy
	signer     abcrypto.Signer
	generation uint64
	healthy    bool
	record     record
}

func newAuthority(t *testing.T) *authority {
	t.Helper()
	s, err := abcrypto.NewInMemorySecp256K1Signer()
	if err != nil {
		t.Fatal(err)
	}
	return &authority{policy: enrolled, signer: s, healthy: true}
}

// Only the operator control plane may invoke fence in the proposed protocol.
func (a *authority) fence() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.generation == ^uint64(0) {
		a.healthy = false
		return 0
	}
	a.generation++
	return a.generation
}

func (a *authority) guard(session uint64, p policy) error {
	if a.signer == nil {
		return errLost
	}
	if !a.healthy {
		return errUntrusted
	}
	if p != a.policy {
		return errContext
	}
	if session == 0 || session != a.generation {
		return errFenced
	}
	return nil
}

// reserve models a successful ATOMIC DURABLE compare-and-reserve. The real implementation must
// authenticate UC/TR before calling it. No client-supplied authenticated boolean exists here.
func (a *authority) reserve(session uint64, p policy, req *certification.BlockCertificationRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.guard(session, p); err != nil {
		return err
	}
	if req == nil || req.InputRecord == nil || req.PartitionID != 8 ||
		req.NodeID != "validator-A" || !req.ShardID.Equal(types.ShardID{}) || req.InputRecord.Epoch != p.epoch {
		return errContext
	}
	if err := req.InputRecord.IsValid(); err != nil {
		return err
	}
	b, err := req.Bytes()
	if err != nil {
		return err
	}
	if len(b) > 1<<20 {
		return errors.New("request-too-large")
	}
	r := req.InputRecord.RoundNumber // Never trust a separately supplied journal round.
	if r < a.record.round {
		return errStale
	}
	if r == a.record.round {
		if !bytes.Equal(b, a.record.unsigned) {
			return errConflict
		}
		return nil
	}
	a.record = record{round: r, unsigned: bytes.Clone(b)}
	return nil
}

func (a *authority) sign(session uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.guard(session, a.policy); err != nil {
		return err
	}
	if len(a.record.unsigned) == 0 {
		return errStage
	}
	if len(a.record.durableResponse) != 0 {
		return nil
	}
	var req certification.BlockCertificationRequest
	if err := types.Cbor.Unmarshal(a.record.unsigned, &req); err != nil {
		return err
	}
	if err := req.Sign(a.signer); err != nil {
		return err
	}
	b, err := types.Cbor.Marshal(req)
	if err != nil {
		return err
	}
	a.record.signed = b // private work; no response can escape yet
	return nil
}

func (a *authority) persistResponse(session uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.guard(session, a.policy); err != nil {
		return err
	}
	if len(a.record.signed) == 0 {
		return errStage
	}
	a.record.durableResponse = bytes.Clone(a.record.signed)
	return nil
}

func (a *authority) release(session uint64, round uint64) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.guard(session, a.policy); err != nil {
		return nil, err
	}
	if round != a.record.round {
		return nil, errStale
	}
	if len(a.record.durableResponse) == 0 {
		return nil, errStage
	}
	return bytes.Clone(a.record.durableResponse), nil
}

func (a *authority) loseAuthority() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signer = nil // journal survives, but this profile has no way to import/recover the old key
}

func proposal(round uint64, size uint64) *certification.BlockCertificationRequest {
	state := bytes.Repeat([]byte{0x12}, 32)
	return &certification.BlockCertificationRequest{
		PartitionID: 8, NodeID: "validator-A", BlockSize: size, StateSize: 42,
		InputRecord: &types.InputRecord{Version: 1, RoundNumber: round, Epoch: 1,
			PreviousHash: bytes.Clone(state), Hash: state, SummaryValue: []byte{}, Timestamp: 100},
	}
}

func complete(t *testing.T, a *authority, session uint64, req *certification.BlockCertificationRequest) []byte {
	t.Helper()
	for _, step := range []func() error{func() error { return a.reserve(session, enrolled, req) }, func() error { return a.sign(session) }, func() error { return a.persistResponse(session) }} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	b, err := a.release(session, req.IRRound())
	if err != nil {
		t.Fatal(err)
	}
	var signed certification.BlockCertificationRequest
	if err := types.Cbor.Unmarshal(b, &signed); err != nil {
		t.Fatal(err)
	}
	v, err := a.signer.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.IsValid(v); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCrashBoundariesKeepOnePreimage(t *testing.T) {
	// Cuts: before reserve, after durable reserve, after private signing, after durable response,
	// after release. The shard is discarded; only the independent authority survives each cut.
	for cut := 0; cut <= 4; cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			a := newAuthority(t)
			old := a.fence()
			req := proposal(12, 1)
			if cut >= 1 {
				if err := a.reserve(old, enrolled, req); err != nil {
					t.Fatal(err)
				}
			}
			if cut >= 2 {
				if err := a.sign(old); err != nil {
					t.Fatal(err)
				}
			}
			if cut >= 3 {
				if err := a.persistResponse(old); err != nil {
					t.Fatal(err)
				}
			}
			var before []byte
			if cut >= 4 {
				before, _ = a.release(old, 12)
			}
			if cut < 3 {
				if _, err := a.release(old, 12); !errors.Is(err, errStage) && !errors.Is(err, errStale) {
					t.Fatal("released before durable response", err)
				}
			}
			fresh := a.fence()
			if _, err := a.release(old, 12); !errors.Is(err, errFenced) {
				t.Fatal("old client survived fence", err)
			}
			if cut >= 1 {
				if err := a.reserve(fresh, enrolled, proposal(12, 2)); !errors.Is(err, errConflict) {
					t.Fatal("changed content reopened round", err)
				}
			}
			after := complete(t, a, fresh, req)
			if before != nil && !bytes.Equal(before, after) {
				t.Fatal("released retry changed wire bytes")
			}
		})
	}
}

func TestFullRequestAndCanonicalBytesAreTheLock(t *testing.T) {
	mutations := map[string]func(*certification.BlockCertificationRequest){
		"block-size":      func(r *certification.BlockCertificationRequest) { r.BlockSize++ },
		"state-size":      func(r *certification.BlockCertificationRequest) { r.StateSize++ },
		"proof-nil-empty": func(r *certification.BlockCertificationRequest) { r.ZkProof = []byte{} },
		"timestamp":       func(r *certification.BlockCertificationRequest) { r.InputRecord.Timestamp++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			a := newAuthority(t)
			s := a.fence()
			complete(t, a, s, proposal(12, 1))
			r := proposal(12, 1)
			mutate(r)
			if err := a.reserve(s, enrolled, r); !errors.Is(err, errConflict) {
				t.Fatal("unsigned field not bound", err)
			}
		})
	}
}

func TestHistoricalCheckpointQuietHeadAndRepeatCannotResetSigning(t *testing.T) {
	a := newAuthority(t)
	s := a.fence()
	complete(t, a, s, proposal(12, 1))
	fresh := a.fence() // restoring any old node checkpoint produces no authority write
	if err := a.reserve(fresh, enrolled, proposal(8, 1)); !errors.Is(err, errStale) {
		t.Fatal(err)
	}
	if err := a.reserve(fresh, enrolled, proposal(12, 2)); !errors.Is(err, errConflict) {
		t.Fatal(err)
	}
	// A later authentic TR can assign a non-consecutive round. Identical quiet executor state
	// is deliberately used in every proposal, and cannot be the signing watermark.
	complete(t, a, fresh, proposal(16, 2))
	if err := a.reserve(fresh, enrolled, proposal(12, 1)); !errors.Is(err, errStale) {
		t.Fatal(err)
	}
}

func TestScopeIsEnrollmentNotAResetNamespace(t *testing.T) {
	for _, p := range []policy{{"other", "config-A", "legacy-bcr-v1", 1, 7}, {"private-network-A", "other", "legacy-bcr-v1", 1, 7}, {"private-network-A", "config-A", "other", 1, 7}, {"private-network-A", "config-A", "legacy-bcr-v1", 2, 7}, {"private-network-A", "config-A", "legacy-bcr-v1", 1, 8}} {
		a := newAuthority(t)
		s := a.fence()
		complete(t, a, s, proposal(12, 1))
		if err := a.reserve(s, p, proposal(12, 2)); !errors.Is(err, errContext) {
			t.Fatal(err)
		}
	}
}

func TestAuthorityLossAndUncertainStorageNeverBootstrap(t *testing.T) {
	for _, lose := range []bool{false, true} {
		a := newAuthority(t)
		s := a.fence()
		complete(t, a, s, proposal(12, 1))
		want := errUntrusted
		if lose {
			a.loseAuthority()
			want = errLost
		} else {
			a.healthy = false
		}
		fresh := a.fence()
		if err := a.reserve(fresh, enrolled, proposal(16, 1)); !errors.Is(err, want) {
			t.Fatal(err)
		}
		if _, err := a.release(fresh, 12); !errors.Is(err, want) {
			t.Fatal(err)
		}
		// A perfectly decoded historical journal cannot resurrect a key or clear uncertainty.
		a.record = record{round: 8, unsigned: mustBytes(t, proposal(8, 1))}
		if err := a.reserve(fresh, enrolled, proposal(12, 2)); !errors.Is(err, want) {
			t.Fatal(err)
		}
	}
}

func mustBytes(t *testing.T, r *certification.BlockCertificationRequest) []byte {
	t.Helper()
	b, err := r.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestConcurrentCandidatesAndFencedRelease(t *testing.T) {
	a := newAuthority(t)
	s := a.fence()
	results := make(chan error, 2)
	for _, size := range []uint64{1, 2} {
		go func(n uint64) { results <- a.reserve(s, enrolled, proposal(12, n)) }(size)
	}
	wins, conflicts := 0, 0
	for i := 0; i < 2; i++ {
		err := <-results
		if err == nil {
			wins++
		} else if errors.Is(err, errConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal(wins, conflicts)
	}
	if err := a.sign(s); err != nil {
		t.Fatal(err)
	}
	if err := a.persistResponse(s); err != nil {
		t.Fatal(err)
	}
	fresh := a.fence()
	if _, err := a.release(s, 12); !errors.Is(err, errFenced) {
		t.Fatal(err)
	}
	b, err := a.release(fresh, 12)
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xff
	again, err := a.release(fresh, 12)
	if err != nil || bytes.Equal(b, again) {
		t.Fatal("response aliases authority state", err)
	}
}

func TestAdversarialOrdersNeverReleaseTwoStatements(t *testing.T) {
	// Exhaust all 4^4 request sequences: lower/equal conflicting/higher round, fencing each time.
	choices := []*certification.BlockCertificationRequest{proposal(8, 1), proposal(12, 1), proposal(12, 2), proposal(16, 1)}
	for schedule := 0; schedule < 256; schedule++ {
		a := newAuthority(t)
		emitted := map[uint64][]byte{}
		n := schedule
		for step := 0; step < 4; step++ {
			r := choices[n%4]
			n /= 4
			s := a.fence()
			if err := a.reserve(s, enrolled, r); err != nil {
				if !errors.Is(err, errStale) && !errors.Is(err, errConflict) {
					t.Fatal(err)
				}
				continue
			}
			complete(t, a, s, r)
			b := mustBytes(t, r)
			if prior, ok := emitted[r.IRRound()]; ok && !bytes.Equal(prior, b) {
				t.Fatalf("schedule %d equivocated", schedule)
			}
			emitted[r.IRRound()] = b
		}
	}
}

func TestReplayableLocalJournalIsNotFreshness(t *testing.T) {
	// Negative control: give a key-holding signer an older journal. BOTH conflicting signatures
	// verify. This is why arbitrary authority rollback is excluded rather than 'detected by fsync'.
	a := newAuthority(t)
	s := a.fence()
	complete(t, a, s, proposal(12, 1))
	a.record = record{} // deliberately break the independent-authority assumption
	complete(t, a, s, proposal(12, 2))
}

func TestLaterReservationCannotAnswerAnEarlierCall(t *testing.T) {
	a := newAuthority(t)
	s := a.fence()
	complete(t, a, s, proposal(12, 1))
	complete(t, a, s, proposal(16, 1))
	if _, err := a.release(s, 12); !errors.Is(err, errStale) {
		t.Fatal("a delayed round-12 caller received round-16's response", err)
	}
}

func TestLostAuthorityCannotRecreateEnrolledKey(t *testing.T) {
	old := newAuthority(t)
	v, err := old.signer.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := v.MarshalPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	old.loseAuthority()
	replacement := newAuthority(t)
	v, err = replacement.signer.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := v.MarshalPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldKey, newKey) {
		t.Fatal("new authority recreated the enrolled identity")
	}
}

func TestGenerationCannotWrapIntoAnOldSession(t *testing.T) {
	a := newAuthority(t)
	a.generation = ^uint64(0)
	if a.fence() != 0 {
		t.Fatal("exhausted generation was issued")
	}
	if err := a.reserve(1, enrolled, proposal(12, 1)); !errors.Is(err, errUntrusted) {
		t.Fatal(err)
	}
}
