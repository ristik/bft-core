package vrschema

import "fmt"

// SchemaVersion is the version of this schema. Every vector file and the constants table carry it; any change to a frozen encoding or
// constant is a new version.
const SchemaVersion = 1

// SchemaID names the schema in vector files.
const SchemaID = "unicity.vr.schema/v1"

// Addresses (genesis alloc).
var (
	SystemCaller      = addr(0x01)
	SealRegistry      = addr(0x02)
	ValidatorRegistry = addr(0x03)
)

func addr(last byte) (a [20]byte) {
	a[0], a[1], a[19] = 0xff, 0x00, last
	return a
}

// Namespaces (ERC-7201 ids).
const (
	VRNamespaceID        = "unicity.vr.registry.v1"
	LiabilityNamespaceID = "unicity.vr.liability.v1"
)

// EVM-side domain texts; the domain word is keccak256(text).
const (
	GenesisResultText   = "unicity.vr.genesis-result.v1"
	RegistryNativeText  = "unicity.vr.registry-native.v1"
	MembersDomainText   = "unicity.vr.members.v1"
	ChangesDomainText   = "unicity.vr.changes.v1"
	OutputDomainText    = "unicity.vr.output.v1"
	NativeResultText    = "unicity.vr.native-result.v1"
	RegisterDomainText  = "unicity.vr.register"
	BindingDomainText   = "unicity.vr.binding"
	P85ExposureText     = "unicity.p85.exposure"
	PoaModuleTagText    = "unicity.vr.poa.v1"
	RulePrefix          = "unicity.rule/"
	RetirementV2Text    = "unicity.seal-registry/records.retirement.v2"
	RetirementEventText = "RetirementRequested(uint64,uint64)"
)

// Root-side (CBOR, SHA-256) domain texts.
const (
	ChangePoPDomain      = "UNICITY_VR_CHANGE_POP"
	IntentDomain         = "UNICITY_VR_HANDOFF_INTENT"
	AssemblyDomain       = "UNICITY_VR_HANDOFF_ASSEMBLY"
	ReadinessDomain      = "UNICITY_VR_READINESS"
	RuleSupportDomain    = "UNICITY_VR_RULE_SUPPORT"
	RuleSupportSetDomain = "UNICITY_VR_RULE_SUPPORT_SET"
	CertificateDomain    = "UNICITY_VR_VIEW_CERTIFICATE"
	FreezeDomain         = "UNICITY_VR_FREEZE"
	VRControlTag         = "UNICITY_VR_CONTROL"
	BackoffDomain        = "UNICITY_VR_HANDOFF_BACKOFF"
)

// Derived constant words.
var (
	GenesisResult     = DomainWord(GenesisResultText)
	RegistryNative    = DomainWord(RegistryNativeText)
	MembersDomain     = DomainWord(MembersDomainText)
	ChangesDomain     = DomainWord(ChangesDomainText)
	OutputDomain      = DomainWord(OutputDomainText)
	NativeResult      = DomainWord(NativeResultText)
	RegisterDomain    = DomainWord(RegisterDomainText)
	BindingDomain     = DomainWord(BindingDomainText)
	P85ExposureDomain = DomainWord(P85ExposureText)
	PoaModuleTag      = DomainWord(PoaModuleTagText)
	RetirementV2      = DomainWord(RetirementV2Text)
	RetirementTopic   = DomainWord(RetirementEventText)
	VRNamespace       = Erc7201(VRNamespaceID)
	LiabilityNS       = Erc7201(LiabilityNamespaceID)
)

// Rule and premise constants (design section 10).
const (
	Lifetime            = 16_384 // ResultReservationLifetimeProgress; provisional (design section 13)
	DelayRounds         = 2_000
	DelaySeconds        = 3_600
	MaxPendingChanges   = 32
	MaxBoundRootSide    = 8
	MaxBoundTotal       = 16
	MaxBoundPayload     = 64 * 1024
	MaxChangePayload    = 16 * 1024
	MaxPendingForce     = 4
	MaxCommittee        = 16
	MinEpochGap         = 100
	ComposerPool        = 6
	ComposerTrials      = 64
	MaxHolders          = 8
	MaxActivations      = 64
	SupportMembers      = 16
	SupportRules        = 64
	RecordsPerRootBlock = 32
	MetadataStaticGas   = 50_000
	GasMarginNum        = 5
	GasMarginDen        = 4
	T0Seconds           = 10
	LMax                = 9
	SatExponent         = 37
	SatSeconds          = uint64(1) << 40
	EarliestOffset      = 16
	PrepareLapse        = 24
	PrepareCooldown     = 48
	ActivationFloor     = 24 + 8
	RetainedViews       = 4
	BufferedAhead       = 2
	MaxIntents          = 2
	PeerMessageBytes    = 256 * 1024
	PeerQueue           = 64
	ReplacementsPerView = 1
	RecoveryRun         = 4
	RecoverySpacing     = 256
	MaxBaseFee          = uint64(1) << 62
	MaxCandidateBytes   = 256 * 1024 // evmassign.MaxCandidateBytes; separate from the 256 KiB peer-message limit
	TimerChunkSeconds   = 3_600      // local timers sleep in chunks of at most this and re-check; no time.Duration in consensus code
	CustodyHolderIndex  = 0          // P85 custody is holder 0 on the PoS-prototype generation
	PartitionCeiling    = 64
	TargetIntervalMS    = 450
	TargetIntervalMinMS = 100
	MaxClockSkewSeconds = 30
	LocalTimeoutSeconds = 10
	// Premises: assumptions liveness claims depend on, never validity rules.
	PremiseRhoNum   = 1
	PremiseRhoDen   = 10_000
	PremiseGf       = 8
	PremiseTauTgtMS = 450
	PremiseCFz      = 32
)

// Record widths (bytes) of root-record kinds 1 to 8.
var RecordWidths = [10]int{0, 32, 128, 288, 192, 96, 224, 128, 128, 96}

// MaxRet are the VR immutable return caps, ABI envelope included.
const (
	MaxRetElect    = 160
	MaxRetReady    = 5408
	MaxRetPending  = 96
	MaxRetAdoption = 96
	MaxRetVoid     = 0
)

// LeaderLag is 4n + 4 rounds.
func LeaderLag(n uint64) uint64 { return 4*n + 4 }

// RecoveryAllowance F_r = (b+1)*256 + 4 rounds.
func RecoveryAllowance(b uint64) uint64 { return (b+1)*RecoverySpacing + RecoveryRun }

// ForceDeadline and the stall deadline are maxElectionInterval + 2*LIFETIME; PARK_PERIOD is 2*LIFETIME.
func ForceDeadline(maxElectionInterval uint64) uint64 { return maxElectionInterval + 2*Lifetime }

// ParkPeriod is 2*LIFETIME.
const ParkPeriod = 2 * Lifetime

// PoPWindow is the handoff-PoP response window (#1319): a PoPRequest committed at root progress p has its cutoff at p + PoPWindow, and its
// certified misses count only when that cutoff is at or before the result's expiresAtProgress, so the whole window lies within the
// result's lifetime.
const PoPWindow = Lifetime / 4

// Constant is one row of the canonical constants table.
type Constant struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Kind  string `json:"kind"` // genesis, schema, rule, existing, local, premise, measured
	Owner string `json:"owner"`
}

func hx(w Word) string { return fmt.Sprintf("0x%x", w[:]) }

// ConstantsTable is the one canonical constants table of schema v1, in the order of the specification.
func ConstantsTable() []Constant {
	a := func(x [20]byte) string { return fmt.Sprintf("0x%x", x[:]) }
	d := func(n uint64) string { return fmt.Sprintf("%d", n) }
	return []Constant{
		{"schemaVersion", d(SchemaVersion), "schema", "all"},
		{"SYSTEM_CALLER", a(SystemCaller), "existing", "ureth"},
		{"SEAL_REGISTRY", a(SealRegistry), "existing", "ureth"},
		{"VALIDATOR_REGISTRY", a(ValidatorRegistry), "genesis", "VR"},
		{"VR_NAMESPACE", hx(VRNamespace), "schema", "VR"},
		{"LIABILITY_NAMESPACE", hx(LiabilityNS), "schema", "holders"},
		{"GENESIS_RESULT", hx(GenesisResult), "schema", "VR, roots"},
		{"REGISTRY_NATIVE", hx(RegistryNative), "schema", "VR, roots"},
		{"MEMBERS_DOMAIN", hx(MembersDomain), "schema", "VR, roots"},
		{"CHANGES_DOMAIN", hx(ChangesDomain), "schema", "VR, roots"},
		{"OUTPUT_DOMAIN", hx(OutputDomain), "schema", "VR, roots"},
		{"VR_RESULT_DOMAIN", hx(NativeResult), "schema", "VR"},
		{"REGISTER_DOMAIN", hx(RegisterDomain), "schema", "VR, CLI"},
		{"BINDING_DOMAIN", hx(BindingDomain), "schema", "VR, CLI"},
		{"EXPOSURE_DOMAIN (custody, reused by PoA)", hx(P85ExposureDomain), "existing", "PoA, custody, roots"},
		{"POA_MODULE_TAG", hx(PoaModuleTag), "schema", "PoA"},
		{"RECORDS_RETIREMENT_V2", hx(RetirementV2), "schema", "SealRegistry, roots"},
		{"RetirementRequested topic", hx(RetirementTopic), "schema", "holders, roots"},
		{"LIFETIME", d(Lifetime), "rule (provisional)", "roots, VR"},
		{"DELAY_ROUNDS", d(DelayRounds), "rule", "VR"},
		{"DELAY_SECONDS", d(DelaySeconds), "rule", "VR"},
		{"MAX_PENDING_CHANGES", d(MaxPendingChanges), "rule", "VR"},
		{"MAX_BOUND_ROOT_SIDE", d(MaxBoundRootSide), "rule", "VR, roots"},
		{"MAX_BOUND_TOTAL", d(MaxBoundTotal), "rule", "VR, roots"},
		{"MAX_BOUND_PAYLOAD", d(MaxBoundPayload), "rule", "VR, roots"},
		{"MAX_CHANGE_PAYLOAD", d(MaxChangePayload), "rule", "VR"},
		{"MAX_PENDING_FORCE_REMOVE", d(MaxPendingForce), "rule", "VR"},
		{"MAX_COMMITTEE", d(MaxCommittee), "rule", "roots, VR"},
		{"MIN_EPOCH_GAP", d(MinEpochGap), "rule", "VR, modules"},
		{"FORCE_DEADLINE", "maxElectionInterval + 2*LIFETIME", "rule", "VR"},
		{"STALL_DEADLINE", "maxElectionInterval + 2*LIFETIME", "rule", "VR"},
		{"PARK_PERIOD", d(ParkPeriod), "rule", "PoA"},
		{"POP_WINDOW", d(PoPWindow), "rule", "roots"},
		{"COMPOSER_POOL", d(ComposerPool), "rule", "PoA"},
		{"COMPOSER_TRIALS", d(ComposerTrials), "rule", "PoA"},
		{"MAX_HOLDERS", d(MaxHolders), "rule", "VR"},
		{"MAX_ACTIVATIONS", d(MaxActivations), "rule", "VR"},
		{"SUPPORT_TABLE", "16 x 64", "rule", "roots"},
		{"RECORD_WIDTHS", "32/128/288/192/96/224/128/128/96", "schema", "all"},
		{"RECORDS_PER_ROOT_BLOCK", d(RecordsPerRootBlock), "existing", "roots"},
		{"MAX_RET", "elect 160, ready 5408, pending/notMine 96, adoption 96, void 0", "rule", "VR"},
		{"METADATA_STATICCALL_GAS", d(MetadataStaticGas), "rule", "VR"},
		{"MAX_RET_METADATA", "256 (32 x 8), exact per getter: moduleTag 32, capabilities 32, gasBounds 256, maxElectionInterval 32, liabilityHolder 64", "rule", "VR"},
		{"MAX_CANDIDATE_BYTES", d(MaxCandidateBytes), "existing", "roots"},
		{"TIMER_CHUNK", d(TimerChunkSeconds) + " s", "rule (local)", "roots, nodes"},
		{"CUSTODY_HOLDER_INDEX", "0", "rule", "VR, PoS prototype"},
		{"pi_max", "enforced per-message verification budget (value fixed by VT-05b)", "rule", "roots"},
		{"GAS_MARGIN", "measured compound worst case * 5/4", "rule", "profile"},
		{"T0", d(T0Seconds) + " s", "rule", "roots"},
		{"LMAX", d(LMax), "rule", "roots"},
		{"TIMEOUT_SATURATION", "exponent >= 37 or T > 2^40 s: never", "rule", "roots"},
		{"EARLIEST_ACTIVATION_OFFSET", d(EarliestOffset), "rule", "roots"},
		{"PREPARE_LAPSE", d(PrepareLapse), "existing", "roots"},
		{"PREPARE_COOLDOWN", "dead after > 48", "existing", "roots"},
		{"ACTIVATION_FLOOR", "24 + 8", "existing", "roots"},
		{"RETAINED_VIEWS / BUFFERED_AHEAD / INTENTS", "4 / 2 / 2", "rule", "nodes, roots"},
		{"PEER_MESSAGE / PEER_QUEUE", "262144 / 64", "rule", "nodes, roots"},
		{"VERIFICATION_QUEUE", "(1 + n_s) * 4 * 2", "rule", "roots"},
		{"REPLACEMENTS_PER_SENDER_VIEW", d(ReplacementsPerView), "rule", "roots"},
		{"RECOVERY_RUN / SPACING / LEADER_LAG", "4 / 256 / 4n + 4", "existing", "roots"},
		{"F_r", "(b+1)*256 + 4 rounds", "derived accounting bound (not an abort, replay or validity rule)", "-"},
		{"live-vote residence wait", "T(L,v)*(1+rho) on the local monotonic clock since first learning the opening commit", "rule (local voting policy)", "roots"},
		{"MAX_BASE_FEE", d(MaxBaseFee), "existing", "ureth"},
		{"PARTITION_CEILING", d(PartitionCeiling), "rule", "roots"},
		{"--target-block-interval", "default 450 ms, >= 100 ms, < LocalTimeout/2", "local, non-consensus", "roots"},
		{"MaxClockSkew / LocalTimeout", "30 s / 10 s", "existing", "roots"},
		{"rho", "1/10000", "premise", "-"},
		{"G_f", d(PremiseGf) + " (provisional)", "premise", "-"},
		{"tau_tgt", "450 ms", "premise", "-"},
		{"C_Fz", d(PremiseCFz), "premise", "-"},
		{"Q_max, O_max, Lambda, Lambda_r, delta, D, T_req", "measured", "premise", "-"},
	}
}
