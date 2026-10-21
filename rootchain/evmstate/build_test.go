package evmstate

import (
	"bytes"
	"context"
	"encoding/json"
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

func retirableScenario(t *testing.T) (scenario, setup, *world) {
	fx := loadFixture(t, "state-slots.json")
	for _, sc := range fx.Scenarios {
		if sc.Kind == "retirement" && sc.Name == "retirable" {
			var f retirementFx
			require.NoError(t, json.Unmarshal(sc.Facts, &f))
			s, _ := retirementSetup(t, sc, f.RecordCursor, f.RecordCursor, 0)
			return sc, s, s.world(t)
		}
	}
	t.Fatal("no retirable scenario")
	return scenario{}, setup{}, nil
}

// The built witness is the readers' witness and verifies against the certified root: the facts it proves are the ones the builder reports.
func TestBuiltRetirementWitnessEqualsTheReadersAndVerifies(t *testing.T) {
	sc, s, w := retirableScenario(t)
	_, want, _, wantFacts := retirementWitness(t, s, sc)

	src := &worldSource{t: t, w: w}
	got, facts, err := BuildRetirementWitness(context.Background(), src, s.pins, sc.ID, sc.Generation)
	require.NoError(t, err)
	require.Equal(t, want, got, "exactly the slots the verifier reads, in the canonical order")
	require.Equal(t, wantFacts, facts)
	proven, err := Authority{Pins: s.pins}.VerifyRetirement(got, w.root, sc.ID, sc.Generation)
	require.NoError(t, err)
	require.Equal(t, facts, proven)
	require.True(t, proven.Requested && proven.NotImported && proven.NoLiveExposures && proven.NoLotReferences && proven.RecordsCaughtUp)
	// the fixed slots are fetched in one call per account, the lots one by one: far fewer calls than slots
	require.LessOrEqual(t, src.calls, 2+int(maxLots), "batched")
	require.Less(t, src.calls, 8)
}

// A built witness is judged against the state it was built from only.
func TestBuiltRetirementWitnessIsRefusedAgainstAnythingElse(t *testing.T) {
	sc, s, w := retirableScenario(t)
	raw, _, err := BuildRetirementWitness(context.Background(), &worldSource{t: t, w: w}, s.pins, sc.ID, sc.Generation)
	require.NoError(t, err)
	a := Authority{Pins: s.pins}

	other := w.root
	other[0] ^= 1
	_, err = a.VerifyRetirement(raw, other, sc.ID, sc.Generation)
	require.ErrorIs(t, err, ErrProof, "another state root")

	_, err = a.VerifyRetirement(raw, w.root, sc.ID, sc.Generation+1)
	require.Error(t, err, "another generation reads other slots: the witness lacks them")
	_, err = a.VerifyRetirement(raw, w.root, sc.ID+1, sc.Generation)
	require.Error(t, err, "another identity")

	for name, pins := range map[string]Pins{
		"custody code":  func() Pins { p := s.pins; p.CustodyCode[0] ^= 1; return p }(),
		"registry code": func() Pins { p := s.pins; p.RegistryCode[0] ^= 1; return p }(),
		"network word":  func() Pins { p := s.pins; p.NetworkWord[0] ^= 1; return p }(),
		"custody addr":  func() Pins { p := s.pins; p.Custody[0] ^= 1; return p }(),
	} {
		_, err = Authority{Pins: pins}.VerifyRetirement(raw, w.root, sc.ID, sc.Generation)
		require.Error(t, err, name)
	}

	// a missing slot, an extra slot
	decoded, err := decodeWitness(raw)
	require.NoError(t, err)
	missing, extra := decoded, decoded
	missing.Accounts = cloneAccounts(decoded.Accounts)
	extra.Accounts = cloneAccounts(decoded.Accounts)
	missing.Accounts[0].Slots = missing.Accounts[0].Slots[1:]
	_, err = a.VerifyRetirement(encode(t, missing.Accounts), w.root, sc.ID, sc.Generation)
	require.Error(t, err, "a missing slot")
	extra.Accounts[0].Slots = append(extra.Accounts[0].Slots, slotProof{Slot: bytes.Repeat([]byte{0xee}, 32), Value: make([]byte, 32)})
	_, err = a.VerifyRetirement(encode(t, extra.Accounts), w.root, sc.ID, sc.Generation)
	require.Error(t, err, "an extra slot")
}

func cloneAccounts(in []accountProof) []accountProof {
	out := make([]accountProof, len(in))
	for i, a := range in {
		out[i] = a
		out[i].Slots = append([]slotProof(nil), a.Slots...)
	}
	return out
}

// An absent or lying source is not a witness, and a lot list beyond custody's bound is refused while building.
func TestBuildRetirementWitnessFailuresAreNotWitnesses(t *testing.T) {
	sc, s, w := retirableScenario(t)
	_, _, err := BuildRetirementWitness(context.Background(), &worldSource{t: t, w: w, failOn: s.pins.Custody}, s.pins, sc.ID, sc.Generation)
	require.ErrorIs(t, err, ErrBuild)
	_, _, err = BuildRetirementWitness(context.Background(), &worldSource{t: t, w: w, failOn: s.pins.Registry}, s.pins, sc.ID, sc.Generation)
	require.ErrorIs(t, err, ErrBuild)

	// a lying source builds bytes, but they do not verify against the certified root
	raw, _, err := BuildRetirementWitness(context.Background(), &worldSource{t: t, w: w, lieSlot: true}, s.pins, sc.ID, sc.Generation)
	if err == nil {
		_, err = Authority{Pins: s.pins}.VerifyRetirement(raw, w.root, sc.ID, sc.Generation)
	}
	require.Error(t, err)

	// lot bounds
	lots := nested(custodyGenerationLots, sc.ID, sc.Generation)
	huge := custodyOf(t, sc)
	huge[lots] = bigWord(maxLots + 1)
	hs := setup{pins: s.pins, custody: huge, registry: s.registry}
	_, _, err = BuildRetirementWitness(context.Background(), &worldSource{t: t, w: hs.world(t)}, s.pins, sc.ID, sc.Generation)
	require.ErrorIs(t, err, ErrWitness)
}
