package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-core/vrclient"
)

// validatorStatusReport is `validator status`, as text or --json.
type validatorStatusReport struct {
	RPC      string `json:"rpc"`
	ChainID  string `json:"chainId"`
	Block    uint64 `json:"block"`
	Registry string `json:"registry"`

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

	PoaState      string   `json:"poaState,omitempty"`
	PoaSince      uint64   `json:"poaSinceProgress,omitempty"`
	Member        bool     `json:"member"`
	Pending       []string `json:"pendingGovernance,omitempty"`
	Module        string   `json:"module"`
	ModuleTag     string   `json:"moduleTag"`
	Health        string   `json:"health"`
	Epoch         uint64   `json:"rootEpoch"`
	EpochStart    uint64   `json:"epochStartProgress"`
	Committee     []uint64 `json:"committee"`
	Limits        string   `json:"limits"`
	Progress      uint64   `json:"progress"`
	UcTime        uint64   `json:"ucTime"`
	RecordCursor  uint64   `json:"recordCursor"`
	RecordCount   uint64   `json:"recordCount"`
	NextBoundary  string   `json:"nextBoundary"`
	Activations   []string `json:"activations,omitempty"`
	PublicHead    uint64   `json:"publicHead"`
	PublicHeadAge string   `json:"publicHeadAge"`
	PublicSyncing bool     `json:"publicSyncing"`
	LocalRPC      string   `json:"localRpc,omitempty"`
	LocalHead     *uint64  `json:"localHead,omitempty"`
	LocalSync     string   `json:"localSync,omitempty"`
}

type validatorStatusFlags struct {
	validatorFlags
	JSON bool
}

func validatorStatusCmd(base *baseFlags) *cobra.Command {
	f := &validatorStatusFlags{validatorFlags: validatorFlags{baseFlags: base}}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the validator's VR record, PoA state, the committee, epoch, next boundary and sync state (public RPC)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := validatorStatus(cmd.Context(), f)
			if err != nil {
				return err
			}
			if f.JSON {
				b, err := json.MarshalIndent(r, "", "  ")
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			r.text(cmd.OutOrStdout())
			return nil
		},
	}
	f.validatorFlags.add(cmd)
	cmd.Flags().BoolVar(&f.JSON, "json", false, "print the status as JSON")
	return cmd
}

func blockInfo(ctx context.Context, c *rpc.Client, tag string) (number, ts uint64, err error) {
	var h struct {
		Number    hexutil.Uint64 `json:"number"`
		Timestamp hexutil.Uint64 `json:"timestamp"`
	}
	if err := c.CallContext(ctx, &h, "eth_getBlockByNumber", tag, false); err != nil {
		return 0, 0, err
	}
	return uint64(h.Number), uint64(h.Timestamp), nil
}

func syncing(ctx context.Context, c *rpc.Client) (bool, error) {
	var raw json.RawMessage
	if err := c.CallContext(ctx, &raw, "eth_syncing"); err != nil {
		return false, err
	}
	return strings.TrimSpace(string(raw)) != "false", nil
}

func validatorStatus(ctx context.Context, f *validatorStatusFlags) (*validatorStatusReport, error) {
	v, err := f.load()
	if err != nil {
		return nil, err
	}
	ch, err := v.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer ch.close()
	vr, head, err := ch.vr.Pin(ctx)
	if err != nil {
		return nil, err
	}
	r := &validatorStatusReport{RPC: v.cfg.RPC, ChainID: ch.chainID.String(), Block: head, Registry: vr.Registry.Hex(),
		Module: ch.module.Module.Hex(), ModuleTag: fmt.Sprintf("%x", ch.module.Meta.ModuleTag), Health: vrclient.Health(ch.module.Health),
		Epoch: ch.cfg.KnownRootEpoch, EpochStart: ch.cfg.EpochStartProgress,
		Limits: fmt.Sprintf("nMin %d, nTarget %d, nMax %d", ch.cfg.NMin, ch.cfg.NTarget, ch.cfg.NMax)}

	// the identity: --id or the config's, else the operator account's from VR's logs
	keys, kerr := v.keys()
	id := v.cfg.ID
	if id == 0 && kerr == nil {
		if got, ok, err := findID(ctx, v, ch, operatorAddress(keys)); err == nil && ok {
			id = got
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
		}
	}
	clock, err := vr.Clock(ctx)
	if err != nil {
		return nil, err
	}
	r.Progress, r.UcTime, r.RecordCursor, r.RecordCount = clock.Progress, clock.UcTime, clock.RecordCursor, clock.RecordCount

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

	acts, err := vr.Activations(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range acts {
		r.Activations = append(r.Activations, fmt.Sprintf("rule %x release %x at root epoch %d, not before UC time %d: %s",
			a.RuleId, a.ReleaseDigest, a.RootEpoch, a.NotBeforeUcTime, vrclient.ActivationState(a.State)))
	}

	// sync: the public endpoint's head, and this validator's own ureth against it
	n, ts, err := blockInfo(ctx, ch.rpc, "latest")
	if err != nil {
		return nil, err
	}
	r.PublicHead = n
	r.PublicHeadAge = time.Since(time.Unix(int64(ts), 0)).Round(time.Second).String()
	r.PublicSyncing, _ = syncing(ctx, ch.rpc)
	if v.cfg.LocalRPC != "" {
		r.LocalRPC = v.cfg.LocalRPC
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		r.LocalSync = localSync(lctx, v.cfg.LocalRPC, n, &r.LocalHead)
	}
	return r, nil
}

func localSync(ctx context.Context, url string, publicHead uint64, head **uint64) string {
	c, err := rpc.DialContext(ctx, url)
	if err != nil {
		return "unreachable: " + err.Error()
	}
	defer c.Close()
	n, _, err := blockInfo(ctx, c, "latest")
	if err != nil {
		return "unreachable: " + err.Error()
	}
	*head = &n
	busy, _ := syncing(ctx, c)
	switch {
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
	if r.ID == 0 {
		fmt.Fprintln(w, "validator: no VR identity for this operator (run `ubft validator apply`)")
	} else {
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
	if len(r.Activations) == 0 {
		fmt.Fprintln(w, "activation schedule: empty")
	}
	for _, a := range r.Activations {
		fmt.Fprintf(w, "activation: %s\n", a)
	}
	fmt.Fprintf(w, "sync: public head %d (%s old, syncing %v)", r.PublicHead, r.PublicHeadAge, r.PublicSyncing)
	if r.LocalRPC != "" {
		fmt.Fprintf(w, "; local ureth %s: %s", r.LocalRPC, r.LocalSync)
	}
	fmt.Fprintln(w)
}
