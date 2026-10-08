package evmstate

import (
	"errors"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// Pins identify the deployed contracts a witness may speak about: the addresses, the code hashes of the deployed code and the custody
// network word (custody.network, as its manifest exports it). Everything else a witness says is proven against the certified root.
type Pins struct {
	Custody, Registry         [20]byte
	CustodyCode, RegistryCode [32]byte
	NetworkWord               [32]byte
}

// Authority is the storage.EVMStateAuthority over Ethereum state proofs.
type Authority struct{ Pins Pins }

var _ storage.EVMStateAuthority = Authority{}

// reader is the proven storage of one account.
type reader interface {
	word(slot [32]byte) ([32]byte, error)
}

// maxLots is the most generation lots a witness may list when custody's own bound is larger.
const maxLots = 1024

func (a Authority) accounts(raw []byte, stateRoot [32]byte, wantRegistry bool) (custody, registry *proven, err error) {
	w, err := decodeWitness(raw)
	if err != nil {
		return nil, nil, err
	}
	want := 1
	if wantRegistry {
		want = 2
	}
	if len(w.Accounts) != want {
		return nil, nil, fmt.Errorf("%w: %d accounts, want %d", ErrWitness, len(w.Accounts), want)
	}
	all, err := w.verify(stateRoot)
	if err != nil {
		return nil, nil, err
	}
	custody = all[ethcommon.Address(a.Pins.Custody)]
	if custody == nil {
		return nil, nil, fmt.Errorf("%w: no custody account", ErrWitness)
	}
	if custody.codeHash != a.Pins.CustodyCode {
		return nil, nil, fmt.Errorf("%w: custody code hash %x is not the pinned one", ErrProof, custody.codeHash)
	}
	if nw, err := custody.word(baseSlot(custodyNetwork)); err != nil || nw != a.Pins.NetworkWord {
		return nil, nil, errors.Join(fmt.Errorf("%w: custody.network is not the deployment's", ErrProof), err)
	}
	if wantRegistry {
		registry = all[ethcommon.Address(a.Pins.Registry)]
		if registry == nil {
			return nil, nil, fmt.Errorf("%w: no registry account", ErrWitness)
		}
		if registry.codeHash != a.Pins.RegistryCode {
			return nil, nil, fmt.Errorf("%w: registry code hash %x is not the pinned one", ErrProof, registry.codeHash)
		}
		roots, err := custody.word(baseSlot(custodyRoots))
		if err != nil || ethcommon.BytesToAddress(roots[:]) != ethcommon.Address(a.Pins.Registry) {
			return nil, nil, errors.Join(fmt.Errorf("%w: custody.roots is not the pinned registry", ErrProof), err)
		}
	}
	return custody, registry, nil
}

// VerifyRetirement proves from one state root the facts custody and the registry hold about (id, generation) (spec section 3).
func (a Authority) VerifyRetirement(raw []byte, stateRoot [32]byte, id, generation uint64) (storage.RetirementFacts, error) {
	var f storage.RetirementFacts
	custody, registry, err := a.accounts(raw, stateRoot, true)
	if err != nil {
		return f, err
	}
	if err := readRetirement(custody, registry, id, generation, &f); err != nil {
		return f, err
	}
	if err := errors.Join(custody.unused(), registry.unused()); err != nil {
		return f, err
	}
	return f, nil
}

func readRetirement(custody, registry reader, id, generation uint64, out *storage.RetirementFacts) error {
	f := out
	f.ID, f.Generation = id, generation

	pos, err := custody.word(slotWord(mapUint(baseSlot(custodyPositions), id), positionsGenerationSlot))
	if err != nil {
		return err
	}
	current := fieldUint(pos, positionGenerationOffset, 8)
	f.Requested = pos[32-positionRequestedOffset-1] == 1 && current == generation

	retired, err := custody.word(nested(custodyRetirements, id, generation))
	if err != nil {
		return err
	}
	reg, err := registry.word(registryRetirementKey(id, generation))
	if err != nil {
		return err
	}
	f.NotImported = retired[32-retirementImportedOffset-1] == 0 && reg == [32]byte{}

	live, err := custody.word(nested(custodyLiveExposures, id, generation))
	if err != nil {
		return err
	}
	f.NoLiveExposures = fieldUint(live, 0, 4) == 0
	if f.RefDigest, err = custody.word(nested(custodyExposureChain, id, generation)); err != nil {
		return err
	}
	anchor, err := custody.word(nested(custodyMaxLiabilityAnchor, id, generation))
	if err != nil {
		return err
	}
	f.MaxLiabilityAnchor = fieldUint(anchor, 0, 8)

	limits, err := custody.word(baseSlot(custodyLimits))
	if err != nil {
		return err
	}
	bound := min(fieldUint(limits, limitsLMaxOffset, limitsLMaxSize), maxLots)
	lotsSlot := nested(custodyGenerationLots, id, generation)
	n, err := custody.word(lotsSlot)
	if err != nil {
		return err
	}
	count := fieldUint(n, 0, 32)
	if wordIsBig(n) || count > bound {
		return fmt.Errorf("%w: %x lots exceed the bound %d", ErrWitness, n, bound)
	}
	f.NoLotReferences = true
	for i := uint64(0); i < count; i++ {
		lot, err := custody.word(arrayElement(lotsSlot, i))
		if err != nil {
			return err
		}
		if wordIsBig(lot) {
			return fmt.Errorf("%w: lot id %x is not a uint64", ErrWitness, lot)
		}
		refs, err := custody.word(slotWord(mapUint(baseSlot(custodyLots), fieldUint(lot, 0, 8)), lotRefCountSlot))
		if err != nil {
			return err
		}
		if fieldUint(refs, lotRefCountOffset, lotRefCountSz) != 0 {
			f.NoLotReferences = false
		}
	}

	cursorW, err := custody.word(baseSlot(custodyRecordCursor))
	if err != nil {
		return err
	}
	countW, err := registry.word(registryKey("records.count"))
	if err != nil {
		return err
	}
	targetW, err := registry.word(registryKey("records.targetCount"))
	if err != nil {
		return err
	}
	f.RecordsCaughtUp = cursorW == countW && countW == targetW
	return nil
}

// VerifyReject proves the custody session of an Election result (spec section 4).
func (a Authority) VerifyReject(raw []byte, stateRoot [32]byte, resultID [32]byte, _ uint64) (storage.RejectFacts, error) {
	var f storage.RejectFacts
	custody, _, err := a.accounts(raw, stateRoot, false)
	if err != nil {
		return f, err
	}
	if err := readReject(custody, resultID, &f); err != nil {
		return f, err
	}
	return f, custody.unused()
}

func readReject(custody reader, resultID [32]byte, f *storage.RejectFacts) error {
	f.ResultID = resultID
	session := mapSlot(baseSlot(custodySessions), resultID[:])
	state, err := custody.word(slotWord(session, sessionStateSlot))
	if err != nil {
		return err
	}
	assignmentID, err := custody.word(slotWord(session, sessionAssignmentSlot))
	if err != nil {
		return err
	}
	attemptW, err := custody.word(slotWord(session, sessionAttemptSlot))
	if err != nil {
		return err
	}
	incumbent, err := custody.word(slotWord(session, sessionIncumbentSlot))
	if err != nil {
		return err
	}
	asg, err := custody.word(slotWord(mapSlot(baseSlot(custodyAssignments), assignmentID[:]), assignmentStateSlot))
	if err != nil {
		return err
	}
	acked, err := custody.word(baseSlot(custodyLastAckedAssignment))
	if err != nil {
		return err
	}
	f.Attempt = fieldUint(attemptW, 0, 8)
	f.Unresolved = fieldUint(state, 0, 1) == sessionOpen && fieldUint(asg, 0, 1) == assignmentReserved
	f.NoInstalledSession = incumbent == acked
	return nil
}

func wordIsBig(w [32]byte) bool {
	for _, b := range w[:24] {
		if b != 0 {
			return true
		}
	}
	return false
}
