package vrstate

import (
	"context"
	"errors"
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// SealRegistry slots the VR controls read: fixed slots named keccak256("unicity.seal-registry/" + name), as the P85 controls read them.
var (
	SealRecordCount  = sealKey("records.count")
	SealTargetCount  = sealKey("records.targetCount")
	SealProgress     = sealKey("records.progress")
	errHolderAccount = errors.New("the holder account is not the one VR registers")
)

func sealKey(name string) vrschema.Word {
	return vrschema.Word(ethcrypto.Keccak256Hash([]byte("unicity.seal-registry/" + name)))
}

func checkCode(a evmstate.ProvenAccount, want [32]byte, name string) error {
	if want == ([32]byte{}) || a.CodeHash() != want {
		return fmt.Errorf("%w: %s code hash %x is not the pinned one", ErrState, name, a.CodeHash())
	}
	return nil
}

// checkNetwork requires V+0 to be the deployment's network word (admission item 1): read first by every VR reader.
func checkNetwork(r Reader, pins Pins) error {
	nw, err := r.Scalar(vrschema.SlotNetwork)
	if err != nil {
		return err
	}
	if nw != pins.NetworkWord {
		return fmt.Errorf("%w: VR network word %x is not the deployment's", ErrState, nw)
	}
	return nil
}

func uintWord(w vrschema.Word, name string) (uint64, error) {
	v, err := vrschema.WordU64(w)
	if err != nil {
		return 0, fmt.Errorf("%w: %s %x is not a uint64", ErrState, name, w)
	}
	return v, nil
}

// VerifyOutput is the Freeze v5 witness (design section 5.1): exactly one account, VR at the pinned address and code hash, proving the
// output state of R at the frozen parent. It returns what ReadOutputState read; vradmit judges it.
func VerifyOutput(raw []byte, stateRoot [32]byte, pins Pins, resultID vrschema.Word) (vradmit.OutputState, error) {
	accs, err := evmstate.VerifyAccounts(raw, stateRoot, pins.Registry)
	if err != nil {
		return vradmit.OutputState{}, err
	}
	if err := checkCode(accs[0], pins.RegistryCode, "VR"); err != nil {
		return vradmit.OutputState{}, err
	}
	s, err := ReadOutputState(Reader{accs[0]}, resultID)
	if err != nil {
		return s, err
	}
	return s, accs[0].Unused()
}

// BuildOutputWitness builds VerifyOutput's witness at the source's block.
func BuildOutputWitness(ctx context.Context, src evmstate.ProofSource, pins Pins, resultID vrschema.Word) ([]byte, vradmit.OutputState, error) {
	var s vradmit.OutputState
	raw, err := evmstate.BuildAccounts(ctx, src, [][20]byte{pins.Registry}, func(a []evmstate.SlotReader) error {
		var err error
		s, err = ReadOutputState(Reader{a[0]}, resultID)
		return err
	})
	return raw, s, err
}

// readReject is the RejectResult v2 read: R's output state from VR, and the SealRegistry's canonical progress, the clock
// expiresAtProgress counts in (VR stamps reservedProgress from SealRegistry progress()).
func readReject(vr, seal evmstate.SlotReader, resultID vrschema.Word) (vradmit.RejectState, error) {
	var s vradmit.RejectState
	var err error
	if s.Output, err = ReadOutputState(Reader{vr}, resultID); err != nil {
		return s, err
	}
	w, err := seal.Word(SealProgress)
	if err != nil {
		return s, err
	}
	s.Progress, err = uintWord(w, "SealRegistry records.progress")
	return s, err
}

// VerifyReject is the RejectResult v2 witness at the rejection parent: exactly VR and the SealRegistry, both pinned by address and
// code hash.
func VerifyReject(raw []byte, stateRoot [32]byte, pins Pins, resultID vrschema.Word) (vradmit.RejectState, error) {
	accs, err := evmstate.VerifyAccounts(raw, stateRoot, pins.Registry, pins.SealRegistry)
	if err != nil {
		return vradmit.RejectState{}, err
	}
	if err := errors.Join(checkCode(accs[0], pins.RegistryCode, "VR"), checkCode(accs[1], pins.SealRegistryCode, "SealRegistry")); err != nil {
		return vradmit.RejectState{}, err
	}
	s, err := readReject(accs[0], accs[1], resultID)
	if err != nil {
		return s, err
	}
	return s, errors.Join(accs[0].Unused(), accs[1].Unused())
}

// BuildRejectWitness builds VerifyReject's witness at the source's block.
func BuildRejectWitness(ctx context.Context, src evmstate.ProofSource, pins Pins, resultID vrschema.Word) ([]byte, vradmit.RejectState, error) {
	var s vradmit.RejectState
	raw, err := evmstate.BuildAccounts(ctx, src, [][20]byte{pins.Registry, pins.SealRegistry}, func(a []evmstate.SlotReader) error {
		var err error
		s, err = readReject(a[0], a[1], resultID)
		return err
	})
	return raw, s, err
}

// HolderEntry is VR's holder entry, read for discovery (which account the three-account witness must carry). nil when holder is not a
// registered index.
func HolderEntry(vr evmstate.SlotReader, holder uint8) (*vrschema.Holder, error) {
	r := Reader{vr}
	st, err := r.Status()
	if err != nil {
		return nil, err
	}
	if holder >= st.HolderCount {
		return nil, nil
	}
	h, err := r.Holder(holder)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// readRetirement reads the three accounts in the frozen check order (schema section 13). holderAcc is nil for an unregistered holder
// index: the witness then proves only that.
func readRetirement(vr, seal, holderAcc evmstate.SlotReader, holderCode [32]byte, h vrschema.HolderRetirement) (vrschema.RetirementWitness, error) {
	var w vrschema.RetirementWitness
	r := Reader{vr}
	entry, err := HolderEntry(vr, h.Holder)
	if err != nil || entry == nil {
		return w, err
	}
	w.HolderKnown, w.VRHolder, w.HolderCodeHash = true, *entry, holderCode
	if holderAcc == nil {
		return w, fmt.Errorf("%w: the witness carries no holder account", ErrState)
	}
	if w.Retired, err = r.Retired(h.Holder, h.ID, h.Generation); err != nil {
		return w, err
	}
	for _, x := range []struct {
		slot vrschema.Word
		into *uint64
		name string
	}{{SealRecordCount, &w.RecordCount, "records.count"}, {SealTargetCount, &w.TargetCount, "records.targetCount"}} {
		v, err := seal.Word(x.slot)
		if err != nil {
			return w, err
		}
		if *x.into, err = uintWord(v, x.name); err != nil {
			return w, err
		}
	}
	dedup, err := seal.Word(vrschema.RetirementV2Key(h.Holder, h.ID, h.Generation))
	if err != nil {
		return w, err
	}
	w.DedupPresent = dedup != (vrschema.Word{})
	cw, err := holderAcc.Word(vrschema.LiabilityCursorSlot())
	if err != nil {
		return w, err
	}
	if w.HolderCursor, err = vrschema.DecodeLiabilityCursor(cw); err != nil {
		return w, wrap(err)
	}
	var fw [2]vrschema.Word
	for j := range fw {
		if fw[j], err = holderAcc.Word(vrschema.LiabilityFactsSlot(h.ID, h.Generation, uint64(j))); err != nil {
			return w, err
		}
	}
	if w.Facts, err = vrschema.DecodeLiabilityFacts(fw); err != nil {
		return w, wrap(err)
	}
	return w, nil
}

// VerifyRetirement is the generic three-account Retirement witness of control op 2 v2 (design section 3.9.3): VR (holders[holder] and
// retired[holder][id][generation]), the SealRegistry (counts and the v2 dedup key) and the holder account VR registers, whose proven code
// hash is compared with VR's pin by the verdict. The VR and SealRegistry accounts are pinned by address and code hash. blockProgress
// and inFlight are the carrying block's root facts. It returns the decoded witness; vrschema.VerifyHolderRetirement is the verdict.
func VerifyRetirement(raw []byte, stateRoot [32]byte, pins Pins, h vrschema.HolderRetirement, blockProgress uint64, inFlight bool) (vrschema.RetirementWitness, error) {
	accs, err := evmstate.VerifyWitness(raw, stateRoot)
	if err != nil {
		return vrschema.RetirementWitness{}, err
	}
	var vr, seal, holder *evmstate.ProvenAccount
	for i := range accs {
		switch accs[i].Address {
		case pins.Registry:
			vr = &accs[i]
		case pins.SealRegistry:
			seal = &accs[i]
		default:
			if holder != nil {
				return vrschema.RetirementWitness{}, fmt.Errorf("%w: more than one account besides VR and the SealRegistry", ErrState)
			}
			holder = &accs[i]
		}
	}
	if vr == nil || seal == nil {
		return vrschema.RetirementWitness{}, fmt.Errorf("%w: the witness lacks VR or the SealRegistry", ErrState)
	}
	if err := errors.Join(checkCode(*vr, pins.RegistryCode, "VR"), checkCode(*seal, pins.SealRegistryCode, "SealRegistry")); err != nil {
		return vrschema.RetirementWitness{}, err
	}
	var holderReader evmstate.SlotReader
	var holderCode [32]byte
	if holder != nil {
		holderReader, holderCode = *holder, holder.CodeHash()
	}
	w, err := readRetirement(*vr, *seal, holderReader, holderCode, h)
	if err != nil {
		return w, err
	}
	if w.HolderKnown && holder.Address != w.VRHolder.Holder {
		return w, fmt.Errorf("%w: %w", ErrState, errHolderAccount)
	}
	if !w.HolderKnown && holder != nil {
		return w, fmt.Errorf("%w: a holder account for an unregistered index", ErrState)
	}
	unused := []error{vr.Unused(), seal.Unused()}
	if holder != nil {
		unused = append(unused, holder.Unused())
	}
	if err := errors.Join(unused...); err != nil {
		return w, err
	}
	w.BlockProgress, w.HandoffInFlight = blockProgress, inFlight
	return w, nil
}

// BuildRetirementWitness builds VerifyRetirement's witness at the source's block: it discovers VR's holder entry first, so the witness
// names the holder account VR registers (none for an unregistered index, whose witness then proves exactly that).
func BuildRetirementWitness(ctx context.Context, src evmstate.ProofSource, pins Pins, h vrschema.HolderRetirement) ([]byte, vrschema.RetirementWitness, error) {
	var entry *vrschema.Holder
	if _, err := evmstate.BuildAccounts(ctx, src, [][20]byte{pins.Registry}, func(a []evmstate.SlotReader) error {
		var err error
		entry, err = HolderEntry(a[0], h.Holder)
		return err
	}); err != nil {
		return nil, vrschema.RetirementWitness{}, err
	}
	addrs := [][20]byte{pins.Registry, pins.SealRegistry}
	if entry != nil {
		addrs = append(addrs, entry.Holder)
	}
	var w vrschema.RetirementWitness
	raw, err := evmstate.BuildAccounts(ctx, src, addrs, func(a []evmstate.SlotReader) error {
		var holder evmstate.SlotReader
		var code [32]byte
		if len(a) == 3 {
			holder, code = a[2], entry.CodeHash // the proven code hash is the verifier's; the builder only lists slots
		}
		var err error
		w, err = readRetirement(a[0], a[1], holder, code, h)
		return err
	})
	return raw, w, err
}
