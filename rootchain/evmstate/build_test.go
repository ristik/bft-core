package evmstate

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// worldSource serves proofs from the in-memory test world, counting calls and optionally corrupting what it returns.
type worldSource struct {
	t       testing.TB
	w       *world
	calls   int
	failOn  [20]byte
	lieSlot bool
}

func (s *worldSource) Proof(_ context.Context, addr [20]byte, slots [][32]byte) ([][]byte, []SlotProof, error) {
	s.calls++
	if addr == s.failOn {
		return nil, nil, errors.New("node unavailable")
	}
	out := make([]SlotProof, len(slots))
	for i, sl := range slots {
		v := s.w.contents[addr][sl]
		if s.lieSlot {
			v[31] ^= 1
		}
		out[i] = SlotProof{Value: v, Proofs: s.w.slotProof(s.t, addr, sl)}
	}
	return s.w.accountProof(s.t, addr), out, nil
}

func TestBuiltPrimaryWitnessEqualsTheReadersAndVerifies(t *testing.T) {
	p := newPrimaryWorld(t, "published")
	resultID := hexWord(t, p.fx.ResultID)
	want, root := p.witness(t, resultID)
	w := buildWorld(t,
		contract{addr: p.pins.Election, codeHash: p.pins.ElectionCode, storage: p.election},
		contract{addr: p.pins.Custody, codeHash: p.pins.CustodyCode, storage: p.custody})

	got, err := BuildPrimaryWitness(context.Background(), &worldSource{t: t, w: w}, p.pins, resultID)
	require.NoError(t, err)
	require.Equal(t, want, got, "exactly the slots the verifier reads, in the canonical order")
	f, err := Authority{Pins: p.pins}.VerifyPrimary(got, w.root, resultID)
	require.NoError(t, err)
	require.True(t, f.Published)
	require.Equal(t, root, w.root)
}

func TestBuildPrimaryWitnessFailuresAreNotWitnesses(t *testing.T) {
	p := newPrimaryWorld(t, "published")
	resultID := hexWord(t, p.fx.ResultID)
	w := buildWorld(t,
		contract{addr: p.pins.Election, codeHash: p.pins.ElectionCode, storage: p.election},
		contract{addr: p.pins.Custody, codeHash: p.pins.CustodyCode, storage: p.custody})

	_, err := BuildPrimaryWitness(context.Background(), &worldSource{t: t, w: w, failOn: p.pins.Custody}, p.pins, resultID)
	require.ErrorIs(t, err, ErrBuild, "an unavailable account is unavailable, not an empty witness")

	// A source that lies about a value yields a witness the verifier refuses: nothing the source says is trusted.
	got, err := BuildPrimaryWitness(context.Background(), &worldSource{t: t, w: w, lieSlot: true}, p.pins, resultID)
	if err == nil {
		_, err = Authority{Pins: p.pins}.VerifyPrimary(got, w.root, resultID)
	}
	require.Error(t, err)
}
