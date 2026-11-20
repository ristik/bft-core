package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// validatorStatusReport is `validator status`, as text or --json.
type validatorStatusReport struct {
	RPC      string `json:"rpc"`
	ChainID  string `json:"chainId"`
	Block    uint64 `json:"block"`
	Registry string `json:"registry"`

	// Identity is "found", "none" (the lookup succeeded and found nothing) or "unknown" (it failed; see Unknown).
	Identity   string `json:"identity"`
	ID         uint64 `json:"id,omitempty"`
	Owner      string `json:"owner,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
	RootNodeID string `json:"rootNodeId,omitempty"`
	EVMNodeID  string `json:"evmNodeId,omitempty"`
	Payee      string `json:"payee,omitempty"`
	Staged     *struct {
		RootNodeID string `json:"rootNodeId"`
		EVMNodeID  string `json:"evmNodeId"`
		Payee      string `json:"payee"`
	} `json:"staged,omitempty"`
	LocalKeys string `json:"localKeys,omitempty"` // "current", "staged", "other" or empty when the keys are not readable

	PoaState     string   `json:"poaState,omitempty"`
	PoaSince     uint64   `json:"poaSinceProgress,omitempty"`
	Member       bool     `json:"member"`
	Pending      []string `json:"pendingGovernance,omitempty"`
	Module       string   `json:"module"`
	ModuleTag    string   `json:"moduleTag"`
	Health       string   `json:"health"`
	Epoch        uint64   `json:"rootEpoch"`
	EpochStart   uint64   `json:"epochStartProgress"`
	Committee    []uint64 `json:"committee"`
	Limits       string   `json:"limits"`
	Progress     uint64   `json:"progress"`
	UcTime       uint64   `json:"ucTime"`
	RecordCursor uint64   `json:"recordCursor"`
	RecordCount  uint64   `json:"recordCount"`
	NextBoundary string   `json:"nextBoundary"`
	Activations  []string `json:"activations,omitempty"`
	PublicHead   *uint64  `json:"publicHead"` // null when the public head could not be read, never 0
	// PublicHeadUnknown: the public head could not be read, so PublicHead is not a measurement (see Unknown).
	PublicHeadUnknown bool    `json:"publicHeadUnknown,omitempty"`
	PublicHeadAge     string  `json:"publicHeadAge"`
	PublicSyncing     *bool   `json:"publicSyncing"` // null: eth_syncing failed (see Unknown)
	LocalRPC          string  `json:"localRpc,omitempty"`
	LocalHead         *uint64 `json:"localHead,omitempty"`
	LocalSync         string  `json:"localSync,omitempty"` // "in sync", "syncing …", "behind by …", "unreachable: …" or "unknown: …"
	PublicHeadTime    uint64  `json:"publicHeadTime"`
	// Sync is the catch-up view (VT-11): height, rate, time to the head, and where the node's data came from.
	Sync *syncView `json:"sync,omitempty"`
	// The numeric form of what the text fields say, for scripts and the VR exporter (VT-12). Codes are the contract's enums
	// (vrclient.Poa*, OutputState, Health); they are stable.
	HealthCode      uint8         `json:"healthCode"`
	PoaStateCode    *uint8        `json:"poaStateCode,omitempty"`
	OpenOutput      *statusOutput `json:"openOutput,omitempty"`
	PendingBoundary bool          `json:"pendingBoundary"`
	// EarliestBoundaryProgress is the progress at which the next election may be reserved (the epoch's start plus the epoch gap).
	EarliestBoundaryProgress uint64 `json:"earliestBoundaryProgress"`
	// CustodyCursor is custody's recordCursor (--custody; a PoS generation), RecordRootTarget the records the root has projected
	// (--root-metrics: the root's unicity_root_records_projected); both nil when not asked for. The four counters of the catch-up
	// runbook (root target, imported count = RecordCount, VR cursor = RecordCursor, custody cursor) are read at the same pinned block.
	CustodyCursor    *uint64 `json:"custodyCursor,omitempty"`
	RecordRootTarget *uint64 `json:"recordRootTarget,omitempty"`
	// RecordRootTargetAt is the unix time the root target was sampled: a separate observation of the root, not at the pinned EVM block.
	RecordRootTargetAt int64 `json:"recordRootTargetAt,omitempty"`

	// Verdict is the status as a script reads it: "ok", "warning", "critical" or "unknown" (some read failed), with the findings behind it.
	// `status --exit-code` exits 0, 1, 2 or 3 accordingly.
	Verdict  string    `json:"verdict"`
	Findings []Finding `json:"findings,omitempty"`

	// UpgradeRequired lists the schedule entries (Active or Latched) whose (rule, release) this binary does not implement; ScheduleKnown is false when the
	// schedule could not be read (then nothing is said about upgrades either way). The exporter reconciles unicity_upgrade_* from them at every poll.
	ScheduleKnown   bool            `json:"scheduleKnown"`
	UpgradeRequired []statusUpgrade `json:"upgradeRequired,omitempty"`
	// Unknown lists every read that failed; status then exits with an error after printing what it could read.
	Unknown []string `json:"unknown,omitempty"`
}

// statusUpgrade is a schedule entry this binary cannot support.
type statusUpgrade struct {
	Rule      string `json:"rule"`
	Release   string `json:"release"`
	RootEpoch uint64 `json:"rootEpoch"`
	State     string `json:"state"`
}

// statusOutput is VR's open output in numbers.
type statusOutput struct {
	ID                string `json:"id"`
	State             string `json:"state"`
	StateCode         uint8  `json:"stateCode"`
	Members           int    `json:"members"`
	Attempt           uint64 `json:"attempt"`
	ReservedProgress  uint64 `json:"reservedProgress"`
	ExpiresAtProgress uint64 `json:"expiresAtProgress"`
	ProgressLeft      int64  `json:"progressLeft"`
}

type validatorStatusFlags struct {
	validatorFlags
	JSON     bool
	Sample   time.Duration
	ExitCode bool
	// NoKeys never reads the operator's or the node's key files (the exporter's mode: it needs the identity id, and compares nothing with local keys)
	NoKeys bool
	// Custody is the PoS custody contract (holder 0) whose recordCursor joins the record counters; RootMetrics the root's metrics URL its
	// projected-record count is read from. Both optional.
	Custody     string
	RootMetrics string
	Thresholds  statusThresholds
}

func validatorStatusCmd(base *baseFlags) *cobra.Command {
	f := &validatorStatusFlags{validatorFlags: validatorFlags{baseFlags: base}}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the validator's VR record, PoA state, the committee, epoch, next boundary and sync state (public RPC)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := validatorStatus(cmd.Context(), f)
			if r == nil {
				if f.ExitCode && err != nil {
					return &ExitCodeError{Code: ExitUnknown, Err: err}
				}
				return err
			}
			if f.JSON {
				b, merr := json.MarshalIndent(r, "", "  ")
				if merr != nil {
					return merr
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
			} else {
				r.text(cmd.OutOrStdout())
			}
			if f.ExitCode {
				return exitForVerdict(r, err)
			}
			return err
		},
	}
	f.validatorFlags.add(cmd)
	cmd.Flags().DurationVar(&f.Sample, "sample", 3*time.Second, "how long to sample the local and public heads for the catch-up rate (0: no rate)")
	cmd.Flags().BoolVar(&f.JSON, "json", false, "print the status as JSON (it carries the numeric fields, the verdict and its findings)")
	cmd.Flags().BoolVar(&f.ExitCode, "exit-code", false, "exit with the verdict: 0 ok, 1 warning, 2 critical, 3 unknown (a read failed); for scripts and alerting. Without it status exits 0 unless a read failed")
	cmd.Flags().StringVar(&f.Custody, "custody", "", "PoS generation: the custody contract (holder 0) whose recordCursor is read with the other record counters")
	cmd.Flags().StringVar(&f.RootMetrics, "root-metrics", "", "the root's metrics URL (http://host:port/api/v1/metrics): its projected-record count joins the record counters")
	f.Thresholds.add(cmd)
	return cmd
}

func blockInfo(ctx context.Context, c *rpc.Client, tag string) (number, ts uint64, err error) {
	var h *struct {
		Number    *hexutil.Uint64 `json:"number"`
		Timestamp *hexutil.Uint64 `json:"timestamp"`
	}
	if err := c.CallContext(ctx, &h, "eth_getBlockByNumber", tag, false); err != nil {
		return 0, 0, err
	}
	// a null answer or a block without a number is an unavailable head, never block 0 (a genuine genesis block carries "0x0")
	if h == nil || h.Number == nil || h.Timestamp == nil {
		return 0, 0, fmt.Errorf("eth_getBlockByNumber %s returned no block", tag)
	}
	return uint64(*h.Number), uint64(*h.Timestamp), nil
}

// syncing is eth_syncing: false, or a progress object (true). Any other answer is an error.
func syncing(ctx context.Context, c *rpc.Client) (bool, error) {
	var raw json.RawMessage
	if err := c.CallContext(ctx, &raw, "eth_syncing"); err != nil {
		return false, err
	}
	switch t := strings.TrimSpace(string(raw)); {
	case t == "false":
		return false, nil
	case strings.HasPrefix(t, "{"):
		return true, nil
	default:
		return false, fmt.Errorf("eth_syncing answered %q", t)
	}
}

func validatorStatus(ctx context.Context, f *validatorStatusFlags) (*validatorStatusReport, error) {
	v, err := f.load()
	if err != nil {
		return nil, err
	}
	ch, err := v.dialWith(ctx, true, true) // one pinned block for everything below, VR's configuration and module included
	if err != nil {
		return nil, err
	}
	defer ch.close()
	vr, head := ch.vr, ch.head
	r := &validatorStatusReport{RPC: v.cfg.RPC, ChainID: ch.chainID.String(), Block: head, Registry: vr.Registry.Hex(),
		Module: ch.module.Module.Hex(), ModuleTag: fmt.Sprintf("%x", ch.module.Meta.ModuleTag), Health: vrclient.Health(ch.module.Health),
		Epoch: ch.cfg.KnownRootEpoch, EpochStart: ch.cfg.EpochStartProgress,
		Limits: fmt.Sprintf("nMin %d, nTarget %d, nMax %d", ch.cfg.NMin, ch.cfg.NTarget, ch.cfg.NMax)}

	// the identity: --id or the config's, else the operator account's from VR's logs. Only a lookup that succeeded says "none".
	var keys *validatorKeys
	kerr := errors.New("key files are not read in this mode")
	if !f.NoKeys {
		keys, kerr = v.keys()
	}
	id := v.cfg.ID
	switch {
	case id != 0:
		r.Identity = "found"
	case f.NoKeys:
		r.Identity = "unknown"
		r.Unknown = append(r.Unknown, "identity: no id is configured (set \"id\" in the config or pass --id)")
	case kerr != nil:
		r.Identity = "unknown"
		r.Unknown = append(r.Unknown, fmt.Sprintf("identity: the operator key is not readable, so its identity was not looked up (pass --id): %v", kerr))
	default:
		got, ok, err := findID(ctx, v, ch, operatorAddress(keys))
		switch {
		case err != nil:
			r.Identity = "unknown"
			r.Unknown = append(r.Unknown, "identity: "+err.Error())
		case ok:
			id, r.Identity = got, "found"
		default:
			r.Identity = "none"
		}
	}
	committee, err := vr.Committee(ctx)
	if err != nil {
		return nil, err
	}
	for _, m := range committee {
		r.Committee = append(r.Committee, m.Id)
		if id != 0 && m.Id == id {
			r.Member = true
		}
	}
	if id != 0 {
		idn, err := vr.Identity(ctx, id)
		if err != nil {
			return nil, err
		}
		if !idn.Known() {
			return nil, fmt.Errorf("%w: VR has no identity %d", ErrValidator, id)
		}
		r.ID, r.Owner, r.Generation = id, idn.Owner.Hex(), idn.Generation
		r.RootNodeID, r.EVMNodeID, r.Payee = idn.Current.RootNodeID, idn.Current.EvmNodeID, idn.Current.Payee.Hex()
		if idn.StagedRef != ([32]byte{}) {
			r.Staged = &struct {
				RootNodeID string `json:"rootNodeId"`
				EVMNodeID  string `json:"evmNodeId"`
				Payee      string `json:"payee"`
			}{idn.Staged.RootNodeID, idn.Staged.EvmNodeID, idn.Staged.Payee.Hex()}
		}
		if kerr == nil {
			if reg, _, _, err := registration(v, keys, 0); err == nil {
				switch {
				case vrclient.BindingMatches(idn.Current, reg):
					r.LocalKeys = "current"
				case idn.StagedRef != ([32]byte{}) && vrclient.BindingMatches(idn.Staged, reg):
					r.LocalKeys = "staged"
				default:
					r.LocalKeys = "other"
				}
			}
		}
		if ch.module.Meta.ModuleTag == vrclient.ModuleTagPoA {
			s, since, err := vr.PoaStatus(ctx, ch.module.Module, id)
			if err != nil {
				return nil, err
			}
			r.PoaState, r.PoaSince = vrclient.PoaState(s), since
			code := uint8(s)
			r.PoaStateCode = &code
		}
	}
	clock, err := vr.Clock(ctx)
	if err != nil {
		return nil, err
	}
	r.Progress, r.UcTime, r.RecordCursor, r.RecordCount = clock.Progress, clock.UcTime, clock.RecordCursor, clock.RecordCount
	r.HealthCode, r.EarliestBoundaryProgress = ch.module.Health, ch.cfg.EpochStartProgress+vrclient.MinEpochGap
	r.readCounters(ctx, f, vr)

	// governance in flight that names this identity
	pending, err := vr.PendingChanges(ctx)
	if err != nil {
		return nil, err
	}
	for _, cid := range pending {
		c, err := vr.Change(ctx, cid)
		if err != nil {
			return nil, err
		}
		target := uint64(0)
		what := vrclient.ChangeKind(c.Kind)
		switch c.Kind {
		case vrclient.KindModuleAction:
			if a, ok := vrclient.DecodeModuleAction(c.Payload); ok {
				target, what = a.ID, "ModuleAction "+vrclient.ActionName(a.Action)
			}
		case 10: // ForceRemove(uint64 id)
			if vals, err := decodeU64(c.Payload); err == nil {
				target = vals
			}
		}
		if id == 0 || target != id {
			continue
		}
		line := fmt.Sprintf("change %d %s: %s", cid, what, vrclient.ChangeState(c.State))
		if c.State == 1 { // Queued
			line += fmt.Sprintf(", executable at progress %d and UC time %d (now %d, %d)", c.NotBeforeProgress, c.NotBeforeTime, clock.Progress, clock.UcTime)
		}
		r.Pending = append(r.Pending, line)
	}

	// the next boundary
	open, err := vr.OpenOutput(ctx)
	if err != nil {
		return nil, err
	}
	pair, err := vr.PendingPair(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	case pair != ([32]byte{}):
		r.PendingBoundary = true
		r.NextBoundary = fmt.Sprintf("output %x is acknowledged; its Boundary record is awaited (the committee changes when it is applied)", pair)
	case open != ([32]byte{}):
		o, err := vr.Output(ctx, open)
		if err != nil {
			return nil, err
		}
		in := ""
		for _, m := range o.Members {
			if id != 0 && m.Id == id {
				in = "; this validator is in its committee"
			}
		}
		left := int64(o.ExpiresAtProgress) - int64(clock.Progress)
		r.OpenOutput = &statusOutput{ID: fmt.Sprintf("%x", open), State: vrclient.OutputState(o.State), StateCode: o.State, Members: len(o.Members), Attempt: o.Attempt,
			ReservedProgress: o.ReservedProgress, ExpiresAtProgress: o.ExpiresAtProgress, ProgressLeft: left}
		r.NextBoundary = fmt.Sprintf("output %x is %s (%d members, attempt %d), reserved at progress %d, expires at %d (%d to go)%s; its boundary comes when the roots commit its handoff",
			open, vrclient.OutputState(o.State), len(o.Members), o.Attempt, o.ReservedProgress, o.ExpiresAtProgress, left, in)
	default:
		earliest := ch.cfg.EpochStartProgress + vrclient.MinEpochGap
		s := "no output is open; the module elects when it has work (an admitted joiner, a leaver, a staged binding, a removal)"
		if clock.Progress < earliest {
			s += fmt.Sprintf(" and progress reaches %d (now %d)", earliest, clock.Progress)
		} else {
			s += fmt.Sprintf(" (progress %d is past the epoch gap)", clock.Progress)
		}
		if clock.RecordCursor < clock.RecordCount {
			s += fmt.Sprintf("; VR is still importing root records (%d of %d)", clock.RecordCursor, clock.RecordCount)
		}
		r.NextBoundary = s
	}

	r.readActivations(ctx, vr)

	// sync: the public endpoint's head, and this validator's own ureth against it
	n, ts, err := blockInfo(ctx, ch.rpc, hexutil.EncodeUint64(head)) // the pinned block, so the public head and VR's state are one point
	if err != nil {
		// an unavailable public head (null, an error) leaves the head and everything derived from it unknown; the rest of the report stands
		r.PublicHeadUnknown = true
		r.Unknown = append(r.Unknown, "public head: "+err.Error())
	} else {
		if ts == 0 && n > 0 {
			r.PublicHeadUnknown = true
			r.Unknown = append(r.Unknown, fmt.Sprintf("public head: block %d carries no timestamp", n))
		} else {
			r.PublicHead = &n
			r.PublicHeadTime = ts
		}
		r.PublicHeadAge = time.Since(time.Unix(int64(ts), 0)).Round(time.Second).String()
	}
	if busy, err := syncing(ctx, ch.rpc); err != nil {
		r.Unknown = append(r.Unknown, "public sync: eth_syncing: "+err.Error())
	} else {
		r.PublicSyncing = &busy
	}
	if v.cfg.LocalRPC != "" {
		r.LocalRPC = v.cfg.LocalRPC
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if r.PublicHeadUnknown {
			r.LocalSync = "unknown: the public head is unavailable"
			if h, err := headOf(lctx, v.cfg.LocalRPC); err == nil {
				r.LocalHead = &h
			}
		} else {
			r.LocalSync = localSync(lctx, v.cfg.LocalRPC, n, &r.LocalHead)
		}
		if strings.HasPrefix(r.LocalSync, "unknown:") {
			r.Unknown = append(r.Unknown, "local sync: "+strings.TrimPrefix(r.LocalSync, "unknown: "))
		}
	}
	r.Sync = buildSyncView(ctx, v, r, f.Sample)
	r.judge(f.Thresholds)
	if len(r.Unknown) > 0 {
		return r, fmt.Errorf("%w: status is incomplete: %s", ErrValidator, strings.Join(r.Unknown, "; "))
	}
	return r, nil
}

func (r *validatorStatusReport) readActivations(ctx context.Context, vr *vrclient.Client) {
	acts, err := vr.Activations(ctx)
	if err != nil {
		r.Unknown = append(r.Unknown, "activation schedule: "+err.Error())
		return
	}
	r.ScheduleKnown = true
	for _, a := range acts {
		if (a.State == 1 || a.State == 3) && !vrschedule.ImplementedRules[[2]vrschema.Word{a.RuleId, a.ReleaseDigest}] { // Active or Latched
			r.UpgradeRequired = append(r.UpgradeRequired, statusUpgrade{Rule: fmt.Sprintf("%x", a.RuleId[:8]), Release: fmt.Sprintf("%x", a.ReleaseDigest[:8]),
				RootEpoch: a.RootEpoch, State: vrclient.ActivationState(a.State)})
		}
		r.Activations = append(r.Activations, fmt.Sprintf("rule %x release %x at root epoch %d, not before UC time %d: %s",
			a.RuleId, a.ReleaseDigest, a.RootEpoch, a.NotBeforeUcTime, vrclient.ActivationState(a.State)))
	}
}

func localSync(ctx context.Context, url string, publicHead uint64, head **uint64) string {
	c, err := dialBounded(ctx, url)
	if err != nil {
		return "unreachable: " + err.Error()
	}
	defer c.Close()
	n, _, err := blockInfo(ctx, c, "latest")
	if err != nil {
		return "unreachable: " + err.Error()
	}
	*head = &n
	busy, err := syncing(ctx, c)
	switch {
	case err != nil:
		return fmt.Sprintf("unknown: head %d, eth_syncing failed: %v", n, err)
	case busy:
		return fmt.Sprintf("syncing (block %d of %d)", n, publicHead)
	case n+2 < publicHead:
		return fmt.Sprintf("behind by %d blocks", publicHead-n)
	}
	return "in sync"
}

func decodeU64(payload []byte) (uint64, error) {
	if len(payload) != 32 {
		return 0, fmt.Errorf("%w: not one word", ErrValidator)
	}
	for _, b := range payload[:24] {
		if b != 0 {
			return 0, fmt.Errorf("%w: wide value", ErrValidator)
		}
	}
	return common.BytesToHash(payload).Big().Uint64(), nil
}

func (r *validatorStatusReport) text(w io.Writer) {
	fmt.Fprintf(w, "chain %s via %s, block %d; ValidatorRegistry %s\n", r.ChainID, r.RPC, r.Block, r.Registry)
	switch r.Identity {
	case "none":
		fmt.Fprintln(w, "validator: no VR identity for this operator (run `ubft validator apply`)")
	case "unknown":
		fmt.Fprintln(w, "validator: UNKNOWN (the identity lookup failed; see below)")
	default:
		fmt.Fprintf(w, "validator %d (owner %s, binding generation %d)\n", r.ID, r.Owner, r.Generation)
		fmt.Fprintf(w, "  root node   %s\n  EVM node    %s\n  payee       %s\n", r.RootNodeID, r.EVMNodeID, r.Payee)
		if r.Staged != nil {
			fmt.Fprintf(w, "  staged      root %s, EVM %s, payee %s (installed at the next boundary that captures it)\n", r.Staged.RootNodeID, r.Staged.EVMNodeID, r.Staged.Payee)
		}
		switch r.LocalKeys {
		case "current":
			fmt.Fprintln(w, "  local keys  match the current binding")
		case "staged":
			fmt.Fprintln(w, "  local keys  match the STAGED binding: they sign only once it is installed")
		case "other":
			fmt.Fprintln(w, "  local keys  DO NOT match the binding in VR")
		}
		if r.PoaState != "" {
			fmt.Fprintf(w, "  PoA state   %s (since progress %d)\n", r.PoaState, r.PoaSince)
		}
		fmt.Fprintf(w, "  member      %v\n", r.Member)
		for _, p := range r.Pending {
			fmt.Fprintf(w, "  governance  %s\n", p)
		}
	}
	fmt.Fprintf(w, "committee: root epoch %d, %d members %v (%s)\n", r.Epoch, len(r.Committee), r.Committee, r.Limits)
	fmt.Fprintf(w, "module: %s (tag %s), health %s\n", r.Module, r.ModuleTag, r.Health)
	fmt.Fprintf(w, "clock: progress %d, UC time %d, epoch started at progress %d; root records %d of %d imported\n", r.Progress, r.UcTime, r.EpochStart,
		r.RecordCursor, r.RecordCount)
	fmt.Fprintf(w, "next boundary: %s\n", r.NextBoundary)
	if !r.ScheduleKnown {
		fmt.Fprintln(w, "activation schedule: unknown")
	} else if len(r.Activations) == 0 {
		fmt.Fprintln(w, "activation schedule: empty")
	}
	for _, a := range r.Activations {
		fmt.Fprintf(w, "activation: %s\n", a)
	}
	pub := "syncing UNKNOWN"
	if r.PublicSyncing != nil {
		pub = fmt.Sprintf("syncing %v", *r.PublicSyncing)
	}
	if r.PublicHeadUnknown || r.PublicHead == nil {
		fmt.Fprintf(w, "sync: public head UNKNOWN (%s)", pub)
	} else {
		fmt.Fprintf(w, "sync: public head %d (%s old, %s)", *r.PublicHead, r.PublicHeadAge, pub)
	}
	if r.LocalRPC != "" {
		fmt.Fprintf(w, "; local ureth %s: %s", r.LocalRPC, r.LocalSync)
	}
	fmt.Fprintln(w)
	r.Sync.text(w)
	for _, u := range r.Unknown {
		fmt.Fprintf(w, "UNKNOWN: %s\n", u)
	}
	fmt.Fprintf(w, "verdict: %s\n", r.Verdict)
	for _, f := range r.Findings {
		fmt.Fprintf(w, "  %s %s: %s\n", strings.ToUpper(f.Severity), f.Code, f.Message)
	}
}
