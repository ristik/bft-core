package vrschema

import (
	"encoding/json"
	"fmt"
)

// VR storage lives under the ERC-7201 namespace V = Erc7201("unicity.vr.registry.v1"). Offsets 0..15 are scalar words, 32..37 are
// mapping bases; 16..31 and 38..63 are reserved for VR-internal state that no root, node or ureth reads (VT-02 lays it out and may
// not move anything frozen here). Packed words hold their fields from the low-order byte (Solidity struct packing); every other byte is
// reserved and zero, and readers refuse nonzero reserved bytes.
const (
	SlotNetwork          = 0
	SlotOpenOutput       = 1
	SlotLastAcked        = 2
	SlotPendingPair      = 3
	SlotCommitteeLimits  = 4
	SlotHookLimits       = 5
	SlotStatus           = 6
	SlotActiveModule     = 7
	SlotActiveModuleHash = 8
	SlotGovernor         = 9
	SlotCounters         = 10
	SlotFeesPrevious     = 11
	SlotFeesPrevCollect  = 12
	SlotFeesCurrent      = 13
	SlotFeesCurCollect   = 14
	SlotFeesEffective    = 15
	MapOutputs           = 32
	MapChanges           = 33
	MapChangePayload     = 34
	MapActivations       = 35
	MapHolders           = 36
	MapRetired           = 37

	OutputWords     = 11
	ChangeWords     = 4
	ActivationWords = 3
	HolderWords     = 3

	LiabilityCursor    = 0
	LiabilityFactsBase = 1
)

// Packed word layouts.
var (
	CommitteeLimitsWord = PackedWord{{"nMin", 0, 4, "uint"}, {"nTarget", 4, 4, "uint"}, {"nMax", 8, 4, "uint"}}
	HookLimitsWord      = PackedWord{{"vMax", 0, 4, "uint"}, {"lMax", 4, 4, "uint"}, {"rMax", 8, 4, "uint"}, {"maxBatch", 12, 4, "uint"}}
	StatusWord          = PackedWord{{"health", 0, 1, "uint"}, {"knownRootEpoch", 1, 8, "uint"}, {"recordCursor", 9, 8, "uint"},
		{"activationCount", 17, 4, "uint"}, {"holderCount", 21, 1, "uint"}}
	AddressWord   = PackedWord{{"address", 0, 20, "address"}}
	CountersWord  = PackedWord{{"nextChangeId", 0, 8, "uint"}, {"identityCount", 8, 8, "uint"}, {"nativeAttempt", 16, 8, "uint"}}
	FeesWord      = PackedWord{{"baseFeeFloor", 0, 8, "uint"}, {"changeDenominator", 8, 8, "uint"}}
	EffectiveWord = PackedWord{{"effectiveBlock", 0, 8, "uint"}}

	OutputWord0  = PackedWord{{"state", 0, 1, "uint"}, {"attempt", 1, 8, "uint"}, {"reservedProgress", 9, 8, "uint"}, {"expiresAtProgress", 17, 8, "uint"}}
	OutputWord2  = PackedWord{{"sourceModule", 0, 20, "address"}, {"native", 20, 1, "bool"}}
	OutputWord10 = PackedWord{{"invalidReason", 0, 1, "uint"}, {"invalidAtProgress", 1, 8, "uint"}}

	ChangeWord0 = PackedWord{{"kind", 0, 1, "uint"}, {"state", 1, 1, "uint"}, {"rejectReason", 2, 1, "uint"}, {"notBeforeProgress", 3, 8, "uint"},
		{"notBeforeTime", 11, 8, "uint"}, {"activeRootEpoch", 19, 8, "uint"}}
	ChangeWord3 = PackedWord{{"scheduledAt", 0, 8, "uint"}, {"payloadLength", 8, 4, "uint"}}

	ActivationWord2 = PackedWord{{"rootEpoch", 0, 8, "uint"}, {"notBeforeUcTime", 8, 8, "uint"}, {"state", 16, 1, "uint"}, {"changeId", 17, 8, "uint"}}
	HolderWord0     = PackedWord{{"holder", 0, 20, "address"}, {"registeredEpoch", 20, 8, "uint"}}

	LiabilityCursorWord = PackedWord{{"cursor", 0, 8, "uint"}}
	LiabilityWord0      = PackedWord{{"requested", 0, 1, "bool"}, {"liveExposures", 1, 4, "uint"}, {"lotReferences", 5, 4, "uint"}, {"maxLiabilityAnchor", 9, 8, "uint"}}
)

// VRSlot is V + k.
func VRSlot(k uint64) Word { return SlotAdd(VRNamespace, k) }

// OutputSlot is word j of outputs[resultID].
func OutputSlot(resultID Word, j uint64) Word {
	return SlotAdd(MapSlot(resultID, VRSlot(MapOutputs)), j)
}

// ChangeSlot is word j of changes[id].
func ChangeSlot(id uint64, j uint64) Word { return SlotAdd(MapSlot(U64(id), VRSlot(MapChanges)), j) }

// ChangePayloadSlot is the Solidity bytes slot of changePayload[id].
func ChangePayloadSlot(id uint64) Word { return MapSlot(U64(id), VRSlot(MapChangePayload)) }

// ActivationSlot is word j of activations[i].
func ActivationSlot(i uint32, j uint64) Word {
	return SlotAdd(MapSlot(U64(uint64(i)), VRSlot(MapActivations)), j)
}

// HolderSlot is word j of holders[h].
func HolderSlot(h uint8, j uint64) Word {
	return SlotAdd(MapSlot(U64(uint64(h)), VRSlot(MapHolders)), j)
}

// RetiredSlot is retired[holder][id][generation].
func RetiredSlot(h uint8, id, generation uint64) Word {
	return MapSlot(U64(generation), MapSlot(U64(id), MapSlot(U64(uint64(h)), VRSlot(MapRetired))))
}

// LiabilityCursorSlot is B + 0.
func LiabilityCursorSlot() Word { return SlotAdd(LiabilityNS, LiabilityCursor) }

// LiabilityFactsSlot is word j (0 or 1) of the facts of (id, generation): q = keccak(id, B+1), s = keccak(generation, q).
func LiabilityFactsSlot(id, generation uint64, j uint64) Word {
	q := MapSlot(U64(id), SlotAdd(LiabilityNS, LiabilityFactsBase))
	return SlotAdd(MapSlot(U64(generation), q), j)
}

// ---- decoded records ----

// OutputRecord is outputs[R] decoded.
type OutputRecord struct {
	State             uint8    `json:"state"`
	Attempt           uint64   `json:"attempt"`
	ReservedProgress  uint64   `json:"reservedProgress"`
	ExpiresAtProgress uint64   `json:"expiresAtProgress"`
	Predecessor       Word     `json:"-"`
	SourceModule      [20]byte `json:"-"`
	Native            bool     `json:"native"`
	ModuleTag         Word     `json:"-"`
	MembersDigest     Word     `json:"-"`
	KDigest           Word     `json:"-"`
	ChangesDigest     Word     `json:"-"`
	SnapshotDigest    Word     `json:"-"`
	PolicyDigest      Word     `json:"-"`
	OutputCommit      Word     `json:"-"`
	InvalidReason     uint8    `json:"invalidReason"`
	InvalidAtProgress uint64   `json:"invalidAtProgress"`
}

// Words encodes the record into its 11 storage words.
func (o OutputRecord) Words() ([OutputWords]Word, error) {
	var w [OutputWords]Word
	var err error
	if w[0], err = OutputWord0.Pack(map[string]any{"state": uint64(o.State), "attempt": o.Attempt, "reservedProgress": o.ReservedProgress,
		"expiresAtProgress": o.ExpiresAtProgress}); err != nil {
		return w, err
	}
	w[1] = o.Predecessor
	if w[2], err = OutputWord2.Pack(map[string]any{"sourceModule": o.SourceModule, "native": o.Native}); err != nil {
		return w, err
	}
	w[3], w[4], w[5], w[6], w[7], w[8], w[9] = o.ModuleTag, o.MembersDigest, o.KDigest, o.ChangesDigest, o.SnapshotDigest, o.PolicyDigest, o.OutputCommit
	w[10], err = OutputWord10.Pack(map[string]any{"invalidReason": uint64(o.InvalidReason), "invalidAtProgress": o.InvalidAtProgress})
	return w, err
}

// DecodeOutput reads outputs[R] from its 11 words. An all-zero record is the unknown id (state None). The state must be a defined
// state, the expiry must be reservation + LIFETIME for a known id, and the invalidation fields are set exactly when an invalidation was
// recorded.
func DecodeOutput(w [OutputWords]Word) (OutputRecord, error) {
	var o OutputRecord
	f0, err := OutputWord0.Unpack(w[0])
	if err != nil {
		return o, err
	}
	f2, err := OutputWord2.Unpack(w[2])
	if err != nil {
		return o, err
	}
	f10, err := OutputWord10.Unpack(w[10])
	if err != nil {
		return o, err
	}
	o.State = uint8(f0["state"].(uint64))
	o.Attempt, o.ReservedProgress, o.ExpiresAtProgress = f0["attempt"].(uint64), f0["reservedProgress"].(uint64), f0["expiresAtProgress"].(uint64)
	o.Predecessor = w[1]
	o.SourceModule, o.Native = f2["sourceModule"].([20]byte), f2["native"].(uint64) == 1
	o.ModuleTag, o.MembersDigest, o.KDigest, o.ChangesDigest, o.SnapshotDigest, o.PolicyDigest, o.OutputCommit = w[3], w[4], w[5], w[6], w[7], w[8], w[9]
	o.InvalidReason, o.InvalidAtProgress = uint8(f10["invalidReason"].(uint64)), f10["invalidAtProgress"].(uint64)
	if o.State > OutClosed {
		return o, fmt.Errorf("%w: output state %d", ErrRange, o.State)
	}
	if o.State == OutNone {
		for _, x := range w {
			if x != (Word{}) {
				return o, fmt.Errorf("%w: an unknown output has nonzero words", ErrReserved)
			}
		}
		return o, nil
	}
	if o.ReservedProgress > ^uint64(0)-Lifetime || o.ExpiresAtProgress != o.ReservedProgress+Lifetime {
		return o, fmt.Errorf("%w: expiry is not reservation + LIFETIME", ErrRange)
	}
	if o.InvalidReason == 0 && o.InvalidAtProgress != 0 {
		return o, fmt.Errorf("%w: invalidation progress without a reason", ErrReserved)
	}
	if o.Native != (o.ModuleTag == RegistryNative) {
		return o, fmt.Errorf("%w: native flag and REGISTRY_NATIVE tag disagree", ErrRange)
	}
	return o, nil
}

// ChangeRecord is changes[id] decoded.
type ChangeRecord struct {
	Kind              uint8  `json:"kind"`
	State             uint8  `json:"state"`
	RejectReason      uint8  `json:"rejectReason"`
	NotBeforeProgress uint64 `json:"notBeforeProgress"`
	NotBeforeTime     uint64 `json:"notBeforeTime"`
	ActiveRootEpoch   uint64 `json:"activeRootEpoch"`
	PayloadHash       Word   `json:"-"`
	BoundTo           Word   `json:"-"`
	ScheduledAt       uint64 `json:"scheduledAt"`
	PayloadLength     uint32 `json:"payloadLength"`
}

// Words encodes changes[id].
func (c ChangeRecord) Words() ([ChangeWords]Word, error) {
	var w [ChangeWords]Word
	var err error
	if w[0], err = ChangeWord0.Pack(map[string]any{"kind": uint64(c.Kind), "state": uint64(c.State), "rejectReason": uint64(c.RejectReason),
		"notBeforeProgress": c.NotBeforeProgress, "notBeforeTime": c.NotBeforeTime, "activeRootEpoch": c.ActiveRootEpoch}); err != nil {
		return w, err
	}
	w[1], w[2] = c.PayloadHash, c.BoundTo
	w[3], err = ChangeWord3.Pack(map[string]any{"scheduledAt": c.ScheduledAt, "payloadLength": uint64(c.PayloadLength)})
	return w, err
}

// DecodeChange reads changes[id]. boundTo is nonzero exactly in state Bound and in the terminal states reached from Bound (Active,
// and Rejected by a boundary verdict or an activation-time rejection); a Rejected ModuleAction carries no binding.
func DecodeChange(w [ChangeWords]Word) (ChangeRecord, error) {
	var c ChangeRecord
	f0, err := ChangeWord0.Unpack(w[0])
	if err != nil {
		return c, err
	}
	f3, err := ChangeWord3.Unpack(w[3])
	if err != nil {
		return c, err
	}
	c.Kind, c.State, c.RejectReason = uint8(f0["kind"].(uint64)), uint8(f0["state"].(uint64)), uint8(f0["rejectReason"].(uint64))
	c.NotBeforeProgress, c.NotBeforeTime, c.ActiveRootEpoch = f0["notBeforeProgress"].(uint64), f0["notBeforeTime"].(uint64), f0["activeRootEpoch"].(uint64)
	c.PayloadHash, c.BoundTo = w[1], w[2]
	c.ScheduledAt, c.PayloadLength = f3["scheduledAt"].(uint64), uint32(f3["payloadLength"].(uint64))
	if c.State == ChNone {
		for _, x := range w {
			if x != (Word{}) {
				return c, fmt.Errorf("%w: an unknown change has nonzero words", ErrReserved)
			}
		}
		return c, nil
	}
	if c.Kind < KindSetModule || c.Kind > KindForceRemove || c.State > ChCancelled {
		return c, fmt.Errorf("%w: kind %d state %d", ErrRange, c.Kind, c.State)
	}
	if (c.RejectReason != 0) != (c.State == ChRejected) {
		return c, fmt.Errorf("%w: reject reason %d in state %d", ErrRange, c.RejectReason, c.State)
	}
	if c.PayloadLength > MaxChangePayload {
		return c, ErrOversize
	}
	return c, nil
}

// Activation is activations[i] decoded.
type Activation struct {
	RuleID          Word   `json:"ruleId"`
	ReleaseDigest   Word   `json:"releaseDigest"`
	RootEpoch       uint64 `json:"rootEpoch"`
	NotBeforeUcTime uint64 `json:"notBeforeUcTime"`
	State           uint8  `json:"state"`
	ChangeID        uint64 `json:"changeId"`
}

// Words encodes activations[i].
func (a Activation) Words() ([ActivationWords]Word, error) {
	w2, err := ActivationWord2.Pack(map[string]any{"rootEpoch": a.RootEpoch, "notBeforeUcTime": a.NotBeforeUcTime, "state": uint64(a.State), "changeId": a.ChangeID})
	return [ActivationWords]Word{a.RuleID, a.ReleaseDigest, w2}, err
}

// DecodeActivation reads activations[i] for i < activationCount.
func DecodeActivation(w [ActivationWords]Word) (Activation, error) {
	f, err := ActivationWord2.Unpack(w[2])
	if err != nil {
		return Activation{}, err
	}
	a := Activation{RuleID: w[0], ReleaseDigest: w[1], RootEpoch: f["rootEpoch"].(uint64), NotBeforeUcTime: f["notBeforeUcTime"].(uint64),
		State: uint8(f["state"].(uint64)), ChangeID: f["changeId"].(uint64)}
	if a.State < ActActive || a.State > ActLatched || a.RuleID == (Word{}) || a.ChangeID == 0 {
		return a, fmt.Errorf("%w: activation entry", ErrRange)
	}
	return a, nil
}

// Holder is holders[h] decoded.
type Holder struct {
	Holder          [20]byte `json:"holder"`
	CodeHash        Word     `json:"codeHash"`
	Module          [20]byte `json:"module"`
	RegisteredEpoch uint64   `json:"registeredEpoch"`
}

// Words encodes holders[h].
func (h Holder) Words() ([HolderWords]Word, error) {
	w0, err := HolderWord0.Pack(map[string]any{"holder": h.Holder, "registeredEpoch": h.RegisteredEpoch})
	return [HolderWords]Word{w0, h.CodeHash, AddrWord(h.Module)}, err
}

// DecodeHolder reads holders[h] for h < holderCount: the holder address and code hash are nonzero.
func DecodeHolder(w [HolderWords]Word) (Holder, error) {
	f, err := HolderWord0.Unpack(w[0])
	if err != nil {
		return Holder{}, err
	}
	m, err := WordAddr(w[2])
	if err != nil {
		return Holder{}, err
	}
	h := Holder{Holder: f["holder"].([20]byte), RegisteredEpoch: f["registeredEpoch"].(uint64), CodeHash: w[1], Module: m}
	if h.Holder == ([20]byte{}) || h.CodeHash == (Word{}) {
		return h, fmt.Errorf("%w: empty holder entry", ErrRange)
	}
	return h, nil
}

// Status is the status scalar decoded.
type Status struct {
	Health          uint8  `json:"health"`
	KnownRootEpoch  uint64 `json:"knownRootEpoch"`
	RecordCursor    uint64 `json:"recordCursor"`
	ActivationCount uint32 `json:"activationCount"`
	HolderCount     uint8  `json:"holderCount"`
}

// Word encodes the status scalar.
func (s Status) Word() (Word, error) {
	return StatusWord.Pack(map[string]any{"health": uint64(s.Health), "knownRootEpoch": s.KnownRootEpoch, "recordCursor": s.RecordCursor,
		"activationCount": uint64(s.ActivationCount), "holderCount": uint64(s.HolderCount)})
}

// DecodeStatus reads the status scalar.
func DecodeStatus(w Word) (Status, error) {
	f, err := StatusWord.Unpack(w)
	if err != nil {
		return Status{}, err
	}
	s := Status{Health: uint8(f["health"].(uint64)), KnownRootEpoch: f["knownRootEpoch"].(uint64), RecordCursor: f["recordCursor"].(uint64),
		ActivationCount: uint32(f["activationCount"].(uint64)), HolderCount: uint8(f["holderCount"].(uint64))}
	if s.Health > HealthInconsistent || s.ActivationCount > MaxActivations || s.HolderCount > MaxHolders {
		return s, fmt.Errorf("%w: status", ErrRange)
	}
	return s, nil
}

// CommitteeLimits are nMin, nTarget and nMax.
type CommitteeLimits struct {
	NMin    uint32 `json:"nMin"`
	NTarget uint32 `json:"nTarget"`
	NMax    uint32 `json:"nMax"`
}

// Valid is 1 <= nMin <= nTarget <= nMax <= 16.
func (l CommitteeLimits) Valid() bool {
	return 1 <= l.NMin && l.NMin <= l.NTarget && l.NTarget <= l.NMax && l.NMax <= MaxCommittee
}

// Word encodes the committee-limits scalar.
func (l CommitteeLimits) Word() (Word, error) {
	return CommitteeLimitsWord.Pack(map[string]any{"nMin": uint64(l.NMin), "nTarget": uint64(l.NTarget), "nMax": uint64(l.NMax)})
}

// DecodeCommitteeLimits reads the committee-limits scalar and requires valid limits.
func DecodeCommitteeLimits(w Word) (CommitteeLimits, error) {
	f, err := CommitteeLimitsWord.Unpack(w)
	if err != nil {
		return CommitteeLimits{}, err
	}
	l := CommitteeLimits{uint32(f["nMin"].(uint64)), uint32(f["nTarget"].(uint64)), uint32(f["nMax"].(uint64))}
	if !l.Valid() {
		return l, fmt.Errorf("%w: committee limits", ErrRange)
	}
	return l, nil
}

// LiabilityFacts is the holder-owned facts of one (id, generation).
type LiabilityFacts struct {
	Requested          bool   `json:"requested"`
	LiveExposures      uint32 `json:"liveExposures"`
	LotReferences      uint32 `json:"lotReferences"`
	MaxLiabilityAnchor uint64 `json:"maxLiabilityAnchor"`
	RefDigest          Word   `json:"-"`
}

// Words encodes the two fact words.
func (f LiabilityFacts) Words() ([2]Word, error) {
	w0, err := LiabilityWord0.Pack(map[string]any{"requested": f.Requested, "liveExposures": uint64(f.LiveExposures),
		"lotReferences": uint64(f.LotReferences), "maxLiabilityAnchor": f.MaxLiabilityAnchor})
	return [2]Word{w0, f.RefDigest}, err
}

// DecodeLiabilityFacts reads the two fact words; a non-canonical bool or a nonzero reserved byte is refused. All zero is the absent
// entry: not requested.
func DecodeLiabilityFacts(w [2]Word) (LiabilityFacts, error) {
	f, err := LiabilityWord0.Unpack(w[0])
	if err != nil {
		return LiabilityFacts{}, err
	}
	return LiabilityFacts{Requested: f["requested"].(uint64) == 1, LiveExposures: uint32(f["liveExposures"].(uint64)),
		LotReferences: uint32(f["lotReferences"].(uint64)), MaxLiabilityAnchor: f["maxLiabilityAnchor"].(uint64), RefDigest: w[1]}, nil
}

// DecodeLiabilityCursor reads B + 0.
func DecodeLiabilityCursor(w Word) (uint64, error) {
	f, err := LiabilityCursorWord.Unpack(w)
	if err != nil {
		return 0, err
	}
	return f["cursor"].(uint64), nil
}

// FeeParams is one fee profile set.
type FeeParams struct {
	BaseFeeFloor      uint64   `json:"baseFeeFloor"`
	ChangeDenominator uint64   `json:"changeDenominator"`
	FeeCollector      [20]byte `json:"-"`
}

// Fees is the VR fee state: previous, current and the first block current applies to.
type Fees struct {
	Previous       FeeParams
	Current        FeeParams
	EffectiveBlock uint64
}

// Words encodes the five fee words V+11..V+15.
func (f Fees) Words() ([5]Word, error) {
	p, err := FeesWord.Pack(map[string]any{"baseFeeFloor": f.Previous.BaseFeeFloor, "changeDenominator": f.Previous.ChangeDenominator})
	if err != nil {
		return [5]Word{}, err
	}
	c, err := FeesWord.Pack(map[string]any{"baseFeeFloor": f.Current.BaseFeeFloor, "changeDenominator": f.Current.ChangeDenominator})
	if err != nil {
		return [5]Word{}, err
	}
	return [5]Word{p, AddrWord(f.Previous.FeeCollector), c, AddrWord(f.Current.FeeCollector), U64(f.EffectiveBlock)}, nil
}

// DecodeFees reads V+11..V+15; both parameter sets must be valid fee parameters.
func DecodeFees(w [5]Word) (Fees, error) {
	var out Fees
	for i, set := range []*FeeParams{&out.Previous, &out.Current} {
		f, err := FeesWord.Unpack(w[2*i])
		if err != nil {
			return out, err
		}
		col, err := WordAddr(w[2*i+1])
		if err != nil {
			return out, err
		}
		*set = FeeParams{BaseFeeFloor: f["baseFeeFloor"].(uint64), ChangeDenominator: f["changeDenominator"].(uint64), FeeCollector: col}
		if err := set.ValidateChange(); err != nil {
			return out, err
		}
	}
	e, err := WordU64(w[4])
	out.EffectiveBlock = e
	return out, err
}

// LayoutEntry is one row of vr-layout.json.
type LayoutEntry struct {
	Name    string     `json:"name"`
	Slot    string     `json:"slot"` // formula
	Value   string     `json:"value,omitempty"`
	Words   int        `json:"words,omitempty"`
	Packed  PackedWord `json:"packed,omitempty"`
	Comment string     `json:"comment,omitempty"`
}

// Layout is the frozen storage layout (vr-layout.json).
type Layout struct {
	Schema      string            `json:"schema"`
	Address     string            `json:"address"`
	Namespace   string            `json:"namespace"`
	NamespaceID string            `json:"namespaceId"`
	Derivation  string            `json:"derivation"`
	VR          []LayoutEntry     `json:"vr"`
	Liability   []LayoutEntry     `json:"liability"`
	LiabilityNS string            `json:"liabilityNamespace"`
	LiabilityID string            `json:"liabilityNamespaceId"`
	Reserved    string            `json:"reserved"`
	PackingRule string            `json:"packingRule"`
	OutputWords []string          `json:"outputWords"`
	ChangeWords []string          `json:"changeWords"`
	Domains     map[string]string `json:"domains"`
}

// VRLayout builds vr-layout.json.
func VRLayout() Layout {
	v := func(k uint64) string { return hx(VRSlot(k)) }
	return Layout{
		Schema: SchemaID, Address: fmt.Sprintf("0x%x", ValidatorRegistry[:]), Namespace: hx(VRNamespace), NamespaceID: VRNamespaceID,
		Derivation:  "keccak256(abi.encode(uint256(keccak256(id)) - 1)) & ~bytes32(uint256(0xff))",
		PackingRule: "packed fields are placed from the low-order byte (Solidity struct packing); offset is bytes from the low end; every other byte is reserved and zero",
		Reserved:    "V+16..V+31 and V+38..V+63 are VR-internal (VT-02); nothing outside VR reads them",
		VR: []LayoutEntry{
			{Name: "network", Slot: "V+0", Value: v(0), Comment: "bytes32 deployment network word"},
			{Name: "openOutput", Slot: "V+1", Value: v(1), Comment: "bytes32 result id, zero when none"},
			{Name: "lastAcked", Slot: "V+2", Value: v(2), Comment: "bytes32, GENESIS_RESULT before the first acknowledgement"},
			{Name: "pendingPair", Slot: "V+3", Value: v(3), Comment: "bytes32, zero when none"},
			{Name: "committeeLimits", Slot: "V+4", Value: v(4), Packed: CommitteeLimitsWord},
			{Name: "hookLimits", Slot: "V+5", Value: v(5), Packed: HookLimitsWord},
			{Name: "status", Slot: "V+6", Value: v(6), Packed: StatusWord},
			{Name: "activeModule", Slot: "V+7", Value: v(7), Packed: AddressWord},
			{Name: "activeModuleCodeHash", Slot: "V+8", Value: v(8)},
			{Name: "governor", Slot: "V+9", Value: v(9), Packed: AddressWord},
			{Name: "counters", Slot: "V+10", Value: v(10), Packed: CountersWord},
			{Name: "fees.previous", Slot: "V+11", Value: v(11), Packed: FeesWord},
			{Name: "fees.previous.feeCollector", Slot: "V+12", Value: v(12), Packed: AddressWord},
			{Name: "fees.current", Slot: "V+13", Value: v(13), Packed: FeesWord},
			{Name: "fees.current.feeCollector", Slot: "V+14", Value: v(14), Packed: AddressWord},
			{Name: "fees.effectiveBlock", Slot: "V+15", Value: v(15), Packed: EffectiveWord},
			{Name: "outputs[resultId]", Slot: "keccak256(abi.encode(resultId, V+32)) + j", Value: v(32), Words: OutputWords},
			{Name: "changes[id]", Slot: "keccak256(abi.encode(uint256(id), V+33)) + j", Value: v(33), Words: ChangeWords},
			{Name: "changePayload[id]", Slot: "keccak256(abi.encode(uint256(id), V+34)) (Solidity bytes)", Value: v(34)},
			{Name: "activations[i]", Slot: "keccak256(abi.encode(uint256(i), V+35)) + j", Value: v(35), Words: ActivationWords},
			{Name: "activations[i].word2", Slot: "+2", Packed: ActivationWord2},
			{Name: "holders[h]", Slot: "keccak256(abi.encode(uint256(h), V+36)) + j", Value: v(36), Words: HolderWords},
			{Name: "holders[h].word0", Slot: "+0", Packed: HolderWord0, Comment: "word1 holderCodeHash, word2 module address"},
			{Name: "retired[h][id][gen]", Slot: "keccak256(abi.encode(uint256(gen), keccak256(abi.encode(uint256(id), keccak256(abi.encode(uint256(h), V+37))))))", Value: v(37), Comment: "canonical bool"},
			{Name: "outputs[R].word0", Slot: "+0", Packed: OutputWord0},
			{Name: "outputs[R].word2", Slot: "+2", Packed: OutputWord2},
			{Name: "outputs[R].word10", Slot: "+10", Packed: OutputWord10},
			{Name: "changes[id].word0", Slot: "+0", Packed: ChangeWord0},
			{Name: "changes[id].word3", Slot: "+3", Packed: ChangeWord3},
		},
		OutputWords: []string{"word0 state|attempt|reservedProgress|expiresAtProgress", "word1 predecessor", "word2 sourceModule|native",
			"word3 moduleTag", "word4 membersDigest", "word5 kDigest", "word6 changesDigest", "word7 snapshotDigest", "word8 policyDigest",
			"word9 outputCommit", "word10 invalidReason|invalidAtProgress"},
		ChangeWords: []string{"word0 kind|state|rejectReason|notBeforeProgress|notBeforeTime|activeRootEpoch", "word1 payloadHash",
			"word2 boundTo", "word3 scheduledAt|payloadLength"},
		LiabilityNS: hx(LiabilityNS), LiabilityID: LiabilityNamespaceID,
		Liability: []LayoutEntry{
			{Name: "cursor", Slot: "B+0", Value: hx(LiabilityCursorSlot()), Packed: LiabilityCursorWord},
			{Name: "facts[id][generation]", Slot: "s = keccak256(abi.encode(uint256(gen), keccak256(abi.encode(uint256(id), B+1)))); words s, s+1",
				Value: hx(SlotAdd(LiabilityNS, LiabilityFactsBase)), Words: 2},
			{Name: "facts.word0", Slot: "s+0", Packed: LiabilityWord0},
			{Name: "facts.word1", Slot: "s+1", Comment: "refDigest"},
		},
		Domains: domainTable(),
	}
}

func domainTable() map[string]string {
	return map[string]string{
		GenesisResultText: hx(GenesisResult), RegistryNativeText: hx(RegistryNative), MembersDomainText: hx(MembersDomain),
		ChangesDomainText: hx(ChangesDomain), OutputDomainText: hx(OutputDomain), NativeResultText: hx(NativeResult),
		RegisterDomainText: hx(RegisterDomain), BindingDomainText: hx(BindingDomain), P85ExposureText: hx(P85ExposureDomain),
		PoaModuleTagText: hx(PoaModuleTag), RetirementV2Text: hx(RetirementV2), RetirementEventText: hx(RetirementTopic),
	}
}

// MarshalJSON renders an entry with hex words.
func (a Activation) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"ruleId": hx(a.RuleID), "releaseDigest": hx(a.ReleaseDigest), "rootEpoch": a.RootEpoch,
		"notBeforeUcTime": a.NotBeforeUcTime, "state": a.State, "changeId": a.ChangeID})
}
