package tokenvec_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
	"github.com/unicitynetwork/bft-core/b1ref/tokenvec"
)

// TestDirectProjection: the reference projection passes every scenario.
func TestDirectProjection(t *testing.T) {
	for _, s := range tokenvec.Scenarios {
		r, err := tokenvec.Check(s, tokenvec.Direct{})
		if err != nil {
			t.Fatal(err)
		}
		roots, _ := tokenvec.Direct{}.Roots(s)
		for i, a := range r.Anchors {
			at := 6 + int(binary.BigEndian.Uint16(a.Claim[4:6])) + 32
			if !bytes.Equal(a.Claim[at:at+32], roots[i][:]) {
				t.Fatalf("%s: anchor %d does not certify the projection's state root", s.ID, i)
			}
		}
		t.Logf("%s: C=%d E=%d S=%d Q=%d A=%d P=%d G_batch=%d", s.ID, r.Grouping.C, r.Grouping.E, r.Grouping.S, r.Grouping.Q, r.Grouping.A, r.Grouping.P, r.Grouping.Gas)
	}
}

// broken wraps Direct with one fault.
type broken struct {
	tokenvec.Direct
	request func([]b1gen.Anchor) []byte
}

func (b broken) Request(_ tokenvec.Scenario, a []b1gen.Anchor) ([]byte, error) {
	return b.request(a), nil
}

func batch(claims ...[]byte) []byte {
	out := []byte{2, 0, 0, byte(len(claims))}
	for _, c := range claims {
		out = append(out, c...)
	}
	return out
}

// TestHarnessRefuses: a projection that drops, duplicates or alters an anchor, or reorders the batch, is caught by the check that
// applies (reordering is allowed: order is the projection's).
func TestHarnessRefuses(t *testing.T) {
	s := tokenvec.Scenarios[0]
	for name, tc := range map[string]struct {
		request func([]b1gen.Anchor) []byte
		want    error
	}{
		"drops an anchor":   {func(a []b1gen.Anchor) []byte { return batch(a[0].Claim, a[1].Claim) }, tokenvec.ErrCoverage},
		"repeats an anchor": {func(a []b1gen.Anchor) []byte { return batch(a[0].Claim, a[1].Claim, a[1].Claim) }, tokenvec.ErrCoverage},
		"alters a state root": {func(a []b1gen.Anchor) []byte {
			c := append([]byte{}, a[2].Claim...)
			c[6+1+32] ^= 1
			return batch(a[0].Claim, a[1].Claim, c)
		}, tokenvec.ErrCoverage},
	} {
		_, err := tokenvec.Check(s, broken{request: tc.request})
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	reordered := broken{request: func(a []b1gen.Anchor) []byte { return batch(a[2].Claim, a[0].Claim, a[1].Claim) }}
	if _, err := tokenvec.Check(s, reordered); err != nil {
		t.Fatalf("reordered: %v", err)
	}
	wrong := s
	wrong.Want.E = 2
	if _, err := tokenvec.Check(wrong, tokenvec.Direct{}); !errors.Is(err, tokenvec.ErrGrouping) {
		t.Fatalf("grouping: %v", err)
	}
}
