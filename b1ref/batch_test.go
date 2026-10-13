package b1ref_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
)

// The any-age acceptance relation and the verification-local reuse of briefs/b1-any-age-by-signatures.md sections 3 and 5, on the
// multi-epoch b1gen.History scenario. Encoding-independent: claims use the v1 claim encoding and reach the batch through the test-only
// b1ref.EvalClaims, until the batch ABI (briefs/b1-any-age-contract.md) is frozen.

const historySeed = "b1-any-age-v1"

func seal(epoch, round uint64, variant string) b1gen.Seal {
	return b1gen.Seal{Epoch: epoch, Round: round, Variant: variant, Signers: b1gen.DefaultSigners(epoch)}
}

func evalClaims(t *testing.T, pre *b1gen.PreState, claims ...[]byte) error {
	t.Helper()
	err := b1ref.EvalClaims(claims, registry(t, pre))
	if err != nil && !errors.Is(err, b1ref.ErrInvalid) {
		t.Fatalf("expected a verdict, got a call failure: %v", err)
	}
	return err
}

func clonePre(p b1gen.PreState) b1gen.PreState {
	p.Epochs = append([]b1gen.EpochWords{}, p.Epochs...)
	return p
}

func TestAnyAgeAcceptance(t *testing.T) {
	h := b1gen.NewHistory(historySeed)
	const O = b1gen.HistoryClock
	// preloaded: the origin epoch 8 is closed at a round beyond O by a stored successor 9 that is not usable yet
	preloaded := func(p *b1gen.PreState) {
		p.Epochs[8].End = O + 500
		p.Epochs = append(p.Epochs, b1gen.EpochWords{Epoch: 9, Members: p.Epochs[8].Members, BodyID: p.Epochs[8].BodyID, Start: O + 500})
	}
	for _, tc := range []struct {
		name string
		seal b1gen.Seal
		pre  func(*b1gen.PreState)
		want error
	}{
		{"genesis epoch, ~10^6 rounds old", seal(0, 500, "a"), nil, nil},
		{"closed epoch at its start", seal(1, 1000, "a"), nil, nil},
		{"closed epoch at its end-1", seal(1, 1999, "a"), nil, nil},
		{"round inside the predecessor's interval", seal(2, 1999, "a"), nil, b1ref.ErrBeforeStart},
		{"round at the closed epoch's end", seal(2, 3000, "a"), nil, b1ref.ErrAfterEnd},
		{"same members as the predecessor, round in the predecessor's interval", seal(5, 4500, "a"), nil, b1ref.ErrBeforeStart},
		{"origin epoch at O", seal(8, O, "a"), nil, nil},
		{"origin epoch at O+1", seal(8, O+1, "a"), nil, b1ref.ErrFuture},
		{"preloaded epoch above the origin", seal(9, O+600, "a"), preloaded, b1ref.ErrSealEpoch},
		{"origin epoch closed by a preloaded successor, r = O", seal(8, O, "a"), preloaded, nil},
		{"origin epoch closed by a preloaded successor, O < r < end", seal(8, O+100, "a"), preloaded, b1ref.ErrFuture},
		{"no entry for an epoch below the origin", seal(3, 3500, "a"), func(p *b1gen.PreState) { p.Epochs = append(p.Epochs[:3], p.Epochs[4:]...) }, b1ref.ErrUnknownEpoch},
		{"open entry below the origin", seal(5, 5500, "a"), func(p *b1gen.PreState) { p.Epochs[5].End = 0 }, b1ref.ErrOpenInterval},
		{"signed by the next epoch's set", b1gen.Seal{Epoch: 3, Round: 3500, Variant: "a", Signers: []int{1, 2, 4}}, nil, b1ref.ErrUnknownSigner},
		{"one signer short of quorum", b1gen.Seal{Epoch: 6, Round: 6500, Variant: "a", Signers: []int{1, 2}}, nil, b1ref.ErrQuorum},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pre := clonePre(h.Pre)
			if tc.pre != nil {
				tc.pre(&pre)
			}
			err := evalClaims(t, &pre, h.Claim(tc.seal, 1, ""))
			if tc.want == nil && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// TestReuseCounts: one entry read per distinct epoch, one key parse per member of an epoch whose seals reach their signatures, one
// signature loop per distinct complete seal and one fold per distinct claim.
func TestReuseCounts(t *testing.T) {
	h := b1gen.NewHistory(historySeed)
	a := seal(8, 9000, "a")
	for _, tc := range []struct {
		name   string
		claims [][]byte
		want   map[string]int
	}{
		{"three claims under one seal", [][]byte{h.Claim(a, 1, ""), h.Claim(a, 2, "0"), h.Claim(a, 2, "1")},
			map[string]int{"epoch-load": 1, "point": 4, "quorum": 1, "signature": 3, "fold": 3}},
		{"two seals of one epoch", [][]byte{h.Claim(a, 1, ""), h.Claim(seal(8, 9100, "b"), 1, "")},
			map[string]int{"epoch-load": 1, "point": 4, "quorum": 2, "signature": 6, "fold": 2}},
		{"seals of three epochs", [][]byte{h.Claim(seal(1, 1500, "a"), 1, ""), h.Claim(seal(4, 4500, "a"), 1, ""), h.Claim(a, 1, "")},
			map[string]int{"epoch-load": 3, "point": 12, "quorum": 3, "signature": 9, "fold": 3}},
		{"an identical claim twice", [][]byte{h.Claim(a, 1, ""), h.Claim(a, 1, "")},
			map[string]int{"epoch-load": 1, "point": 4, "quorum": 1, "signature": 3, "fold": 1}},
		{"one shard under two seals", [][]byte{h.Claim(a, 3, ""), h.Claim(seal(8, 9200, "a"), 3, "")},
			map[string]int{"epoch-load": 1, "point": 4, "quorum": 2, "signature": 6, "fold": 2}},
		{"one shard under seals of two epochs", [][]byte{h.Claim(seal(2, 2500, "a"), 3, ""), h.Claim(a, 3, "")},
			map[string]int{"epoch-load": 2, "point": 8, "quorum": 2, "signature": 6, "fold": 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counts := countWork(t)
			if err := evalClaims(t, &h.Pre, tc.claims...); err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			for kind, n := range tc.want {
				if counts[kind] != n {
					t.Errorf("%s: %d, want %d (all: %v)", kind, counts[kind], n, counts)
				}
			}
		})
	}
}

// TestReuseIsPerCall: a second call repeats every read and check; nothing is remembered across calls.
func TestReuseIsPerCall(t *testing.T) {
	h := b1gen.NewHistory(historySeed)
	c := h.Claim(seal(8, 9000, "a"), 1, "")
	counts := countWork(t)
	for i := 0; i < 2; i++ {
		if err := evalClaims(t, &h.Pre, c); err != nil {
			t.Fatal(err)
		}
	}
	if counts["epoch-load"] != 2 || counts["quorum"] != 2 || counts["fold"] != 2 {
		t.Fatalf("second call reused work: %v", counts)
	}
}

// TestAlteredSignatureWitness: a seal whose unsigned bytes equal a verified seal's but whose signatures differ is a different seal.
// A bad signature in it fails the batch whichever comes first; an extra valid signature makes a second, valid seal.
func TestAlteredSignatureWitness(t *testing.T) {
	h := b1gen.NewHistory(historySeed)
	x := seal(8, 9000, "a")
	bad := x
	bad.BadLast = true
	extra := x
	extra.Signers = []int{1, 2, 3, 4}
	good, altered := h.Claim(x, 1, ""), h.Claim(bad, 3, "")
	for name, order := range map[string][][]byte{"verified first": {good, altered}, "altered first": {altered, good}} {
		if err := evalClaims(t, &h.Pre, order...); !errors.Is(err, b1ref.ErrSigInvalid) {
			t.Fatalf("%s: expected ErrSigInvalid, got %v", name, err)
		}
	}
	counts := countWork(t)
	if err := evalClaims(t, &h.Pre, good, h.Claim(extra, 3, "")); err != nil {
		t.Fatalf("extra valid signature: %v", err)
	}
	if counts["quorum"] != 2 {
		t.Fatalf("seals differing only in their signatures shared one check: %v", counts)
	}
}

// claimField returns a copy of a v1 claim with one byte of the claimed shard configuration hash (0), state root (1) or input record
// digest (2) flipped.
func claimField(c []byte, field int) []byte {
	out := append([]byte{}, c...)
	off := 6 + int(binary.BigEndian.Uint16(c[4:6])) + 32*field
	out[off] ^= 1
	return out
}

// TestSealHitDoesNotSkipClaimChecks: a claim whose seal already verified in the call still has its own bindings checked, and the same
// certificate cannot authorize a different claimed tuple.
func TestSealHitDoesNotSkipClaimChecks(t *testing.T) {
	h := b1gen.NewHistory(historySeed)
	good := h.Claim(seal(8, 9000, "a"), 1, "")
	for field, want := range []error{b1ref.ErrShardConf, b1ref.ErrStateRoot, b1ref.ErrIRHash} {
		wrong := claimField(good, field)
		for name, order := range map[string][][]byte{"seal verified first": {good, wrong}, "wrong claim first": {wrong, good}} {
			if err := evalClaims(t, &h.Pre, order...); !errors.Is(err, want) {
				t.Fatalf("%s, field %d: expected %v, got %v", name, field, want, err)
			}
		}
	}
}
