package s1ref_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/unicitynetwork/bft-core/s1ref"
	"github.com/unicitynetwork/bft-core/s1ref/s1gen"
)

// contexts returns the distinct injected contexts of the golden manifest and,
// per vector, the index of its own.
func contexts(t testing.TB) (ctxs []*s1ref.Context, own map[string]int, m *s1gen.Manifest) {
	m, _ = loadGolden(t)
	own = map[string]int{}
	index := map[string]int{}
	for _, v := range m.Vectors {
		key := ""
		if v.Context != nil {
			key = contextKey(v.Context)
		}
		i, ok := index[key]
		if !ok {
			i = len(ctxs)
			index[key] = i
			ctxs = append(ctxs, contextOf(t, v.Context))
		}
		own[v.ID] = i
	}
	return ctxs, own, m
}

func contextKey(c *s1gen.ContextJSON) string {
	b := []byte{byte(c.Network >> 8), byte(c.Network), byte(c.OpenEpoch)}
	for _, e := range c.Epochs {
		b = append(b, e.ViewHash...)
		b = append(b, e.Genesis...)
		b = append(b, byte(e.Scheme), byte(e.Epoch), byte(e.Start), byte(e.End), byte(e.SourceKind))
	}
	return string(b)
}

// checkInvariants asserts, for any input, the malformed-versus-false split,
// the bounds, the agreement of Run with Verify and the order invariance of a
// true pair.
func checkInvariants(t testing.TB, in []byte, ctx *s1ref.Context) {
	t.Helper()
	v, err := s1ref.Verify(in, ctx)
	const big = 1 << 30
	out, used, rerr := s1ref.Run(in, ctx, big)
	if len(in) > s1ref.MaxInputBytes {
		if !errors.Is(err, s1ref.ErrInputTooLarge) || !errors.Is(rerr, s1ref.ErrInputTooLarge) {
			t.Fatalf("%d bytes admitted: %v %v", len(in), err, rerr)
		}
		return
	}
	if err != nil {
		if !errors.Is(err, s1ref.ErrMalformed) || errors.Is(err, s1ref.ErrInvalid) || v.Valid || v.Offence != nil {
			t.Fatalf("error outside the malformed family: %v (%+v)", err, v)
		}
		if rerr == nil || out != nil || used != big || !errors.Is(rerr, s1ref.ErrMalformed) {
			t.Fatalf("Run disagrees with Verify on a malformed input: %v %x %d", rerr, out, used)
		}
		return
	}
	if v.Valid != (v.Why == nil) || v.Valid != (v.Offence != nil) || (!v.Valid && !errors.Is(v.Why, s1ref.ErrInvalid)) || errors.Is(v.Why, s1ref.ErrMalformed) {
		t.Fatalf("inconsistent verdict %+v", v)
	}
	if v.Gas == 0 || v.Gas > s1ref.MaxGas {
		t.Fatalf("charge %d outside (0, %d]", v.Gas, s1ref.MaxGas)
	}
	want := s1ref.Output(v)
	if (v.Valid && len(want) != 384) || (!v.Valid && len(want) != 64) {
		t.Fatalf("output length %d for valid=%v", len(want), v.Valid)
	}
	if rerr != nil || !bytes.Equal(out, want) || used != v.Gas {
		t.Fatalf("Run disagrees with Verify: %v used=%d gas=%d", rerr, used, v.Gas)
	}
	if _, _, err := s1ref.Run(in, ctx, v.Gas-1); !errors.Is(err, s1ref.ErrOutOfGas) {
		t.Fatalf("one gas short: %v", err)
	}
	if v.Valid {
		if o := v.Offence; o.Kind != 1 || (o.Scheme != 1 && o.Scheme != 2) || (o.Scheme == 1 && (o.DomainHash != [32]byte{} || o.ConflictID != [32]byte{})) {
			t.Fatalf("offence %+v", o)
		}
		if in[3] == 2 {
			hdr, view, evs := frames(t, in)
			sw, err := s1ref.Verify(reframe(hdr, view, [][]byte{evs[1], evs[0]}), ctx)
			if err != nil || !sw.Valid || !bytes.Equal(s1ref.Output(sw), want) {
				t.Fatalf("pair order changes the result: %+v %v", sw, err)
			}
		}
	}
}

func FuzzVerify(f *testing.F) {
	ctxs, own, m := contexts(f)
	for _, v := range m.Vectors {
		if len(v.Request) < 40000 {
			f.Add(requestOf(f, v), uint8(own[v.ID]))
		}
	}
	f.Fuzz(func(t *testing.T, in []byte, which uint8) {
		checkInvariants(t, in, ctxs[int(which)%len(ctxs)])
	})
}

// TestMutationSweep applies every single-byte flip, every truncation and a
// few splices to each committed request and checks the invariants, so the
// whole decoder is exercised around real structure rather than only random
// bytes.
func TestMutationSweep(t *testing.T) {
	ctxs, own, m := contexts(t)
	n := 0
	for _, v := range m.Vectors {
		req := requestOf(t, v)
		ctx := ctxs[own[v.ID]]
		if len(req) > 3000 {
			continue
		}
		for i := range req {
			mut := append([]byte{}, req...)
			mut[i] ^= 0xff
			checkInvariants(t, mut, ctx)
			mut[i] = req[i] ^ 0x01
			checkInvariants(t, mut, ctx)
			n += 2
		}
		for l := 0; l < len(req); l++ {
			checkInvariants(t, req[:l], ctx)
			n++
		}
		if len(req) >= 4 {
			checkInvariants(t, append(append([]byte{}, req...), req[4:]...), ctx)
		}
		if len(req) > 8 {
			checkInvariants(t, append(append([]byte{}, req[:4]...), req[8:]...), ctx)
		}
	}
	if n < 100000 {
		t.Fatalf("only %d mutations", n)
	}
}

// TestNoPanicOnGarbage feeds structured near-misses of the framing.
func TestNoPanicOnGarbage(t *testing.T) {
	ctxs, _, _ := contexts(t)
	for _, in := range [][]byte{
		nil, {1}, {1, 0}, {1, 0, 0, 1}, {1, 0, 0, 1, 0, 0, 0, 0}, {1, 0, 0, 2, 0xff, 0xff, 0xff, 0xff},
		bytes.Repeat([]byte{0xff}, 5000), bytes.Repeat([]byte{0x86}, 4000), bytes.Repeat([]byte{0x00}, s1ref.MaxInputBytes),
		bytes.Repeat([]byte{0x00}, s1ref.MaxInputBytes+1),
	} {
		for _, c := range ctxs[:3] {
			checkInvariants(t, in, c)
		}
	}
}
