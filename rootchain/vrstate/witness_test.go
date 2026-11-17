package vrstate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
)

var (
	vrCode   = vrschema.Keccak([]byte("vr code"))
	sealCode = vrschema.Keccak([]byte("seal code"))
	holderAt = [20]byte{0xb0, 19: 0x02}
)

func testPins() Pins {
	return Pins{Registry: vrschema.ValidatorRegistry, RegistryCode: vrCode, NetworkWord: vrschema.Keccak([]byte("net")), SealRegistry: vrschema.SealRegistry,
		SealRegistryCode: sealCode}
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T { t.Helper(); require.NoError(t, err); return v }
}

// TestRetirementVectorsThroughTheWitness runs every retirement.verify vector end to end: the vector's facts are written into a real EVM
// state (VR's status, holder entry and retired bit; the SealRegistry's counts and v2 dedup key; the holder's cursor and facts at the
// frozen liability layout), the three-account witness is built and verified against the state root, and the verdict is the vector's.
func TestRetirementVectorsThroughTheWitness(t *testing.T) {
	f := loadVectors(t, "statemachine.json")
	n := 0
	for _, v := range f.Vectors {
		if v.Op != "retirement.verify" {
			continue
		}
		var in struct {
			BlockProgress      uint64 `json:"blockProgress"`
			Data               string `json:"data"`
			DedupPresent       bool   `json:"dedupPresent"`
			HandoffInFlight    bool   `json:"handoffInFlight"`
			HolderCodeHash     string `json:"holderCodeHash"`
			HolderCursor       uint64 `json:"holderCursor"`
			HolderKnown        bool   `json:"holderKnown"`
			LiveExposures      uint32 `json:"liveExposures"`
			LotReferences      uint32 `json:"lotReferences"`
			MaxLiabilityAnchor uint64 `json:"maxLiabilityAnchor"`
			PinnedCodeHash     string `json:"pinnedCodeHash"`
			RecordCount        uint64 `json:"recordCount"`
			RefDigest          string `json:"refDigest"`
			Requested          bool   `json:"requested"`
			Retired            bool   `json:"retired"`
			TargetCount        uint64 `json:"targetCount"`
		}
		var ex struct {
			Error string `json:"error"`
			OK    bool   `json:"ok"`
		}
		require.NoError(t, json.Unmarshal(v.Input, &in))
		require.NoError(t, json.Unmarshal(v.Expect, &ex))
		data, err := hex.DecodeString(strings.TrimPrefix(in.Data, "0x"))
		require.NoError(t, err)
		h, err := vrschema.DecodeHolderRetirement(data)
		require.NoError(t, err, v.Name)

		pins := testPins()
		vr := map[[32]byte][32]byte{vrschema.VRSlot(vrschema.SlotNetwork): pins.NetworkWord}
		count := uint8(0)
		if in.HolderKnown {
			count = h.Holder + 1
			hw := must[[3]vrschema.Word](t)(vrschema.Holder{Holder: holderAt, CodeHash: word(t, in.PinnedCodeHash), Module: [20]byte{0xa0, 19: 1}, RegisteredEpoch: 1}.Words())
			for j := range hw {
				vr[vrschema.HolderSlot(h.Holder, uint64(j))] = hw[j]
			}
		}
		vr[vrschema.VRSlot(vrschema.SlotStatus)] = must[vrschema.Word](t)(vrschema.Status{HolderCount: count}.Word())
		vr[vrschema.RetiredSlot(h.Holder, h.ID, h.Generation)] = vrschema.BoolWord(in.Retired)
		seal := map[[32]byte][32]byte{SealRecordCount: vrschema.U64(in.RecordCount), SealTargetCount: vrschema.U64(in.TargetCount)}
		if in.DedupPresent {
			seal[vrschema.RetirementV2Key(h.Holder, h.ID, h.Generation)] = vrschema.U64(1)
		}
		facts := must[[2]vrschema.Word](t)(vrschema.LiabilityFacts{Requested: in.Requested, LiveExposures: in.LiveExposures, LotReferences: in.LotReferences,
			MaxLiabilityAnchor: in.MaxLiabilityAnchor, RefDigest: word(t, in.RefDigest)}.Words())
		holder := map[[32]byte][32]byte{vrschema.LiabilityCursorSlot(): vrschema.U64(in.HolderCursor),
			vrschema.LiabilityFactsSlot(h.ID, h.Generation, 0): facts[0], vrschema.LiabilityFactsSlot(h.ID, h.Generation, 1): facts[1]}
		world := evmstatetest.NewWorld(t,
			evmstatetest.Contract{Addr: pins.Registry, CodeHash: vrCode, Storage: vr},
			evmstatetest.Contract{Addr: pins.SealRegistry, CodeHash: sealCode, Storage: seal},
			evmstatetest.Contract{Addr: holderAt, CodeHash: word(t, in.HolderCodeHash), Storage: holder})

		raw, _, err := BuildRetirementWitness(context.Background(), world, pins, h)
		require.NoError(t, err, v.Name)
		w, err := VerifyRetirement(raw, world.Root(), pins, h, in.BlockProgress, in.HandoffInFlight)
		require.NoError(t, err, v.Name)
		err = vradmit.VerifyRetirement(w, h)
		if ex.OK {
			require.NoError(t, err, v.Name)
		} else {
			require.EqualError(t, err, ex.Error, v.Name)
		}
		n++
	}
	require.Equal(t, 13, n)
}

// fixture state for the output and reject witnesses
func outputWorld(t *testing.T) (*evmstatetest.World, vrschema.Word) {
	pins := testPins()
	r := vrschema.Keccak([]byte("R"))
	o := vrschema.OutputRecord{State: vrschema.OutPublished, Attempt: 1, ReservedProgress: 10, ExpiresAtProgress: 10 + vrschema.Lifetime,
		Predecessor: vrschema.GenesisResult, ModuleTag: vrschema.PoaModuleTag, OutputCommit: vrschema.Keccak([]byte("c"))}
	vr := map[[32]byte][32]byte{vrschema.VRSlot(vrschema.SlotNetwork): pins.NetworkWord, vrschema.VRSlot(vrschema.SlotOpenOutput): r,
		vrschema.VRSlot(vrschema.SlotLastAcked):       vrschema.GenesisResult,
		vrschema.VRSlot(vrschema.SlotCommitteeLimits): must[vrschema.Word](t)(vrschema.CommitteeLimits{NMin: 4, NTarget: 4, NMax: 7}.Word()),
		vrschema.VRSlot(vrschema.SlotStatus):          must[vrschema.Word](t)(vrschema.Status{KnownRootEpoch: 1}.Word())}
	ow := must[[vrschema.OutputWords]vrschema.Word](t)(o.Words())
	for j, x := range ow {
		vr[vrschema.OutputSlot(r, uint64(j))] = x
	}
	return evmstatetest.NewWorld(t, evmstatetest.Contract{Addr: pins.Registry, CodeHash: vrCode, Storage: vr},
		evmstatetest.Contract{Addr: pins.SealRegistry, CodeHash: sealCode, Storage: map[[32]byte][32]byte{SealProgress: vrschema.U64(20000)}}), r
}

func TestOutputWitness(t *testing.T) {
	w, r := outputWorld(t)
	pins := testPins()
	raw, built, err := BuildOutputWitness(context.Background(), w, pins, r)
	require.NoError(t, err)
	s, err := VerifyOutput(raw, w.Root(), pins, r)
	require.NoError(t, err)
	require.Equal(t, built, s)
	require.Equal(t, vrschema.OutPublished, s.Output.State)
	require.Equal(t, r, s.OpenOutput)

	_, err = VerifyOutput(raw, vrschema.Keccak([]byte("another root")), pins, r)
	require.ErrorIs(t, err, evmstate.ErrProof, "another state root")
	bad := pins
	bad.RegistryCode = vrschema.Keccak([]byte("other code"))
	_, err = VerifyOutput(raw, w.Root(), bad, r)
	require.ErrorIs(t, err, ErrState, "VR is pinned by code hash")
	_, err = VerifyOutput(raw, w.Root(), pins, vrschema.Keccak([]byte("other")))
	require.ErrorIs(t, err, evmstate.ErrWitness, "a witness proves exactly the slots its reader reads")
	two, _, err := BuildRejectWitness(context.Background(), w, pins, r)
	require.NoError(t, err)
	_, err = VerifyOutput(two, w.Root(), pins, r)
	require.ErrorIs(t, err, evmstate.ErrWitness, "the Freeze witness covers exactly one account")
}

func TestRejectWitnessAndDueTable(t *testing.T) {
	w, r := outputWorld(t)
	pins := testPins()
	raw, _, err := BuildRejectWitness(context.Background(), w, pins, r)
	require.NoError(t, err)
	s, err := VerifyReject(raw, w.Root(), pins, r)
	require.NoError(t, err)
	require.Equal(t, uint64(20000), s.Progress)
	dep := vradmit.Deployment{RootNetwork: 3, NetworkWord: pins.NetworkWord, Registry: pins.Registry, RegistryCode: pins.RegistryCode}
	k := vrschema.Word{}
	require.NoError(t, vradmit.VerifyReject(s, vrschema.OutputRejected{ResultID: r, Reason: vrschema.RejExpired}, dep, vrschema.GenesisResult, k),
		"progress 20000 >= expiry 16394")
	s.Progress = 10 + vrschema.Lifetime - 1
	require.ErrorIs(t, vradmit.VerifyReject(s, vrschema.OutputRejected{ResultID: r, Reason: vrschema.RejExpired}, dep, vrschema.GenesisResult, k), vradmit.ErrReject)
}
