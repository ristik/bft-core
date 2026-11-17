package vrschema

import "errors"

// RetirementWitness is what the three-account Retirement witness proves at P (design section 3.9.3), decoded from storage words:
// VR's holder entry and retired bit, the SealRegistry's counts and dedup key, and the holder account's code hash, cursor and facts.
type RetirementWitness struct {
	VRHolder        Holder // holders[holder] at P
	HolderKnown     bool   // holder < holderCount at P
	Retired         bool   // retired[holder][id][generation]
	RecordCount     uint64 // SealRegistry records.count
	TargetCount     uint64 // SealRegistry records.targetCount
	DedupPresent    bool   // the (RECORDS_RETIREMENT_V2, holder, id, generation) key is present
	HolderCodeHash  Word   // the holder account's code hash
	HolderCursor    uint64 // B + 0
	Facts           LiabilityFacts
	BlockProgress   uint64 // the carrying block's progress
	HandoffInFlight bool
}

// Retirement verdicts.
var (
	ErrRetInFlight = errors.New("HandoffInFlight")
	ErrRetHolder   = errors.New("UnknownHolder")
	ErrRetCode     = errors.New("HolderCodeMismatch")
	ErrRetDone     = errors.New("AlreadyRetired")
	ErrRetBehind   = errors.New("RegistryBehind")
	ErrRetDedup    = errors.New("RetirementLogged")
	ErrRetCursor   = errors.New("HolderCursorStale")
	ErrRetNotReq   = errors.New("NotRequested")
	ErrRetLive     = errors.New("LiveExposures")
	ErrRetLots     = errors.New("LotReferences")
	ErrRetRef      = errors.New("RefDigestMismatch")
	ErrRetAnchor   = errors.New("LiabilityAnchorAhead")
)

// VerifyHolderRetirement is the HolderRetirement (control op 2 v2) admission over the decoded witness, in the frozen check order.
func VerifyHolderRetirement(w RetirementWitness, h HolderRetirement) error {
	switch {
	case w.HandoffInFlight:
		return ErrRetInFlight
	case !w.HolderKnown:
		return ErrRetHolder
	case w.HolderCodeHash != w.VRHolder.CodeHash:
		return ErrRetCode
	case w.Retired:
		return ErrRetDone
	case w.RecordCount != w.TargetCount:
		return ErrRetBehind
	case w.DedupPresent:
		return ErrRetDedup
	case w.HolderCursor != w.RecordCount:
		return ErrRetCursor
	case !w.Facts.Requested:
		return ErrRetNotReq
	case w.Facts.LiveExposures != 0:
		return ErrRetLive
	case w.Facts.LotReferences != 0:
		return ErrRetLots
	case w.Facts.RefDigest != h.RefDigest:
		return ErrRetRef
	case w.Facts.MaxLiabilityAnchor > w.BlockProgress:
		return ErrRetAnchor
	}
	return nil
}
