package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrrules"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// `ubft validator upgrade` (VT-07, design section 7.4): the activation schedule as the registry holds it, queued and scheduled changes
// included (the warning starts at the Queued event), against the rules this binary supports. Rule support decides; the release digest is
// advisory: it names the release to install.

// ErrUpgradeRequired is the exit of `validator upgrade --exit-code` when a scheduled rule is unsupported by this binary.
var ErrUpgradeRequired = errors.New("upgrade required: the schedule holds a rule this binary does not support")

type upgradeEntry struct {
	Rule            string `json:"rule"`
	RuleID          string `json:"ruleId"`
	ReleaseDigest   string `json:"releaseDigest"`
	RootEpoch       uint64 `json:"rootEpoch"`
	NotBeforeUcTime uint64 `json:"notBeforeUcTime"`
	// State is the registry's entry state (Active, Latched), or the pending change's (Queued, Scheduled, Bound).
	State           string `json:"state"`
	ChangeID        uint64 `json:"changeId"`
	Label           string `json:"label,omitempty"`
	Supported       bool   `json:"supported"`
	EpochsRemaining int64  `json:"epochsRemaining"` // E minus the known root epoch; <= 0: in force now
}

type upgradeReport struct {
	KnownRootEpoch uint64         `json:"knownRootEpoch"`
	UcTime         uint64         `json:"ucTime"`
	Supported      []string       `json:"supportedRules"`
	Schedule       []upgradeEntry `json:"schedule"`
	// UpgradeRequired is true when an effective or pending entry names a rule this binary lacks.
	UpgradeRequired bool `json:"upgradeRequired"`
}

func validatorUpgradeCmd(_ *baseFlags) *cobra.Command {
	var gf govFlags
	var asJSON, exitCode bool
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Show the activation schedule: what activates at which root epoch, the release it needs, and whether this binary supports it",
		Long: `Reads the registry's activation schedule (the entries VR holds, and the ScheduleActivation changes still Queued, Scheduled or Bound), and
compares each rule with the rules this binary supports. A node refuses to run an epoch at or past an activation whose rule it lacks, so
install the named release before that epoch. --exit-code exits non-zero when an unsupported rule is scheduled.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gc, err := gf.dial(cmd.Context())
			if err != nil {
				return err
			}
			defer gc.close()
			r, err := buildUpgradeReport(cmd, gc)
			if err != nil {
				return err
			}
			if asJSON {
				b, _ := json.MarshalIndent(r, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
			} else {
				r.text(cmd.OutOrStdout())
			}
			if exitCode && r.UpgradeRequired {
				return ErrUpgradeRequired
			}
			return nil
		}}
	gf.add(cmd)
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the schedule as JSON")
	cmd.Flags().BoolVar(&exitCode, "exit-code", false, "exit non-zero when the schedule holds a rule this binary does not support")
	return cmd
}

func buildUpgradeReport(cmd *cobra.Command, gc *govChain) (*upgradeReport, error) {
	ctx := cmd.Context()
	clk, err := gc.vr.Clock(ctx)
	if err != nil {
		return nil, err
	}
	acts, err := gc.vr.Activations(ctx)
	if err != nil {
		return nil, err
	}
	known := vrrules.Known()
	r := &upgradeReport{KnownRootEpoch: gc.cfg.KnownRootEpoch, UcTime: clk.UcTime, Schedule: []upgradeEntry{}, Supported: []string{}}
	for _, n := range known {
		r.Supported = append(r.Supported, n)
	}
	name := func(id [32]byte) string {
		if n, ok := known[vrschema.Word(id)]; ok {
			return n
		}
		return "unknown rule " + hexutil.Encode(id[:])[:14] + "…"
	}
	add := func(e upgradeEntry, id [32]byte) {
		e.Rule, e.RuleID = name(id), hexutil.Encode(id[:])
		e.Supported = known.Has(vrschema.Word(id))
		e.EpochsRemaining = int64(e.RootEpoch) - int64(gc.cfg.KnownRootEpoch)
		if !e.Supported {
			r.UpgradeRequired = true
		}
		r.Schedule = append(r.Schedule, e)
	}
	for _, a := range acts {
		if a.State == 2 { // Superseded
			continue
		}
		add(upgradeEntry{ReleaseDigest: hexutil.Encode(a.ReleaseDigest[:]), RootEpoch: a.RootEpoch, NotBeforeUcTime: a.NotBeforeUcTime,
			State: vrclient.ActivationState(a.State), ChangeID: a.ChangeId}, a.RuleId)
	}
	pending, err := gc.vr.PendingChanges(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range pending {
		ch, err := gc.vr.Change(ctx, id)
		if err != nil {
			return nil, err
		}
		if ch.Kind != vrclient.KindScheduleActivation {
			continue
		}
		s, err := vrschema.DecodeSchedule(ch.Payload)
		if err != nil {
			return nil, err
		}
		add(upgradeEntry{ReleaseDigest: hexutil.Encode(s.ReleaseDigest[:]), RootEpoch: s.RootEpoch, NotBeforeUcTime: s.NotBeforeUcTime,
			State: vrclient.ChangeState(ch.State), ChangeID: id, Label: s.Label}, s.RuleID)
	}
	return r, nil
}

func (r *upgradeReport) text(w io.Writer) {
	fmt.Fprintf(w, "known root epoch %d, UC time %d\nthis binary supports: %v\n", r.KnownRootEpoch, r.UcTime, r.Supported)
	if len(r.Schedule) == 0 {
		fmt.Fprintln(w, "no activation is scheduled")
		return
	}
	for _, e := range r.Schedule {
		when := fmt.Sprintf("in %d epochs", e.EpochsRemaining)
		if e.EpochsRemaining <= 0 {
			when = "in force"
		}
		fmt.Fprintf(w, "- %s: %s, from root epoch %d (%s), not before UC time %d, change %d\n    release digest %s\n", e.Rule, e.State, e.RootEpoch, when,
			e.NotBeforeUcTime, e.ChangeID, e.ReleaseDigest)
		if e.Supported {
			fmt.Fprintln(w, "    this binary supports it")
		} else {
			fmt.Fprintf(w, "    UPGRADE REQUIRED: this binary does not support it; a node without it refuses to run epoch %d and later\n", e.RootEpoch)
		}
		if e.Label != "" {
			fmt.Fprintf(w, "    label: %s\n", e.Label)
		}
	}
}
