package cmd

// `ubft governance`: the Foundation's side of the validator registry (VT-10b, bft-core#1190; design briefs/validator-registry-design-final.md
// sections 3.5 and 3.5.6). The FoundationMultisig (3-of-5, VR's governor) approves one call, VR.queue(kind, payload) or VR.cancel(id), under
// an EIP-712 digest; the Foundation's tooling is a pipeline of files, so that every signer works offline on his own key:
//
//	signer init      create or locate a signer's key (exclusive create, never replaced)
//	propose <kind>   build the change payload, pre-judge it, show it decoded, simulate VR.queue as the governor; write a proposal file
//	sign             one signer: re-derive and show what the proposal does, sign its digest offline; write an approval file
//	aggregate        collect three or more approvals into a bundle, ordered as the multisig requires
//	execute          anyone: --bundle sends multisig.execute (the change is queued); --change N sends VR.execute(N) once both delays passed
//	list             the multisig, the clock and the pending changes with their delays, state and expiry
//
// The kinds: the PoA ModuleActions (admit, confirm-exit, remove), force-remove, the live configuration (committee-limits, fee-params),
// cancel, and raw (any kind from a payload built elsewhere: `ubft vr-change` for the partition kinds, SetModule, SetGovernor,
// ReplaceAggregatorValidators and ScheduleActivation). Every command that sends shows a decoded, simulated preview and takes --dry-run;
// reads and transactions use a public JSON-RPC endpoint only.

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-core/vrclient"
)

// ErrGovernance is returned for a refusal of a `ubft governance` command.
var ErrGovernance = errors.New("governance")

const (
	proposalFormat = "unicity.governance.proposal.v1"
	approvalFormat = "unicity.governance.approval.v1"
	bundleFormat   = "unicity.governance.bundle.v1"
)

// govProposal is one call the multisig is asked to approve. The digest is derived, never trusted: every reader recomputes it from the other
// fields, and a signer reads what the call does from Data, not from Description.
type govProposal struct {
	Format      string `json:"format"`
	ChainID     uint64 `json:"chainId"`
	Multisig    string `json:"multisig"`
	Target      string `json:"target"`
	Data        string `json:"data"`
	Nonce       uint64 `json:"nonce"`
	Digest      string `json:"digest"`
	Description string `json:"description,omitempty"`
	// PredictedChangeID is the id VR would assign at queue, as simulated when proposing (advisory).
	PredictedChangeID uint64 `json:"predictedChangeId,omitempty"`
}

type govApproval struct {
	Format    string `json:"format,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

type govBundle struct {
	Format    string        `json:"format"`
	Proposal  govProposal   `json:"proposal"`
	Approvals []govApproval `json:"approvals"`
}

// checked is a proposal with its fields parsed and its digest verified.
type checkedProposal struct {
	p        govProposal
	multisig common.Address
	target   common.Address
	data     []byte
	digest   [32]byte
}

func (p govProposal) check() (*checkedProposal, error) {
	if p.Format != proposalFormat {
		return nil, fmt.Errorf("%w: proposal format %q, want %q", ErrGovernance, p.Format, proposalFormat)
	}
	if !common.IsHexAddress(p.Multisig) || !common.IsHexAddress(p.Target) {
		return nil, fmt.Errorf("%w: the proposal's multisig or target is not an address", ErrGovernance)
	}
	data, err := hexutil.Decode(p.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: proposal data: %v", ErrGovernance, err)
	}
	c := &checkedProposal{p: p, multisig: common.HexToAddress(p.Multisig), target: common.HexToAddress(p.Target), data: data}
	c.digest, err = vrclient.CallDigest(new(big.Int).SetUint64(p.ChainID), c.multisig, c.target, data, p.Nonce)
	if err != nil {
		return nil, err
	}
	if want := hexutil.Encode(c.digest[:]); !strings.EqualFold(p.Digest, want) {
		return nil, fmt.Errorf("%w: the proposal's digest %s is not the digest of its fields (%s): the file was altered or is not for this multisig",
			ErrGovernance, p.Digest, want)
	}
	return c, nil
}

// what reads the call a proposal makes. Only VR.queue and VR.cancel are the Foundation's proposals; any other call is refused.
func (c *checkedProposal) what() (string, error) {
	call, err := vrclient.DecodeCall(c.data)
	if err != nil || call.Contract != "ValidatorRegistry" {
		return "", fmt.Errorf("%w: the proposal's call is not a ValidatorRegistry call this tool signs (queue or cancel)", ErrGovernance)
	}
	switch call.Method {
	case "queue":
		return "VR.queue: " + vrclient.DescribeChange(call.Args[0].Value.(uint8), call.Args[1].Value.([]byte)), nil
	case "cancel":
		return fmt.Sprintf("VR.cancel: change %d", call.Args[0].Value.(uint64)), nil
	}
	return "", fmt.Errorf("%w: VR.%s is not a proposal this tool signs (queue or cancel)", ErrGovernance, call.Method)
}

func (c *checkedProposal) preview(w io.Writer) error {
	what, err := c.what()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "proposal: chain %d, multisig %s, nonce %d\n  target: %s\n  call:   %s\n  digest: %s\n", c.p.ChainID, c.multisig.Hex(), c.p.Nonce,
		c.target.Hex(), what, hexutil.Encode(c.digest[:]))
	if c.p.Description != "" {
		fmt.Fprintf(w, "  note:   %s (the proposer's words; the call above is what is signed)\n", c.p.Description)
	}
	return nil
}

// ---- files and keys ------------------------------------------------------------------------------------------------------------------

func sameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if canonicalPath(a) == canonicalPath(b) {
		return true
	}
	sa, errA := os.Stat(a)
	sb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(sa, sb)
}

// writeOut writes data to out (standard output when empty): a new file, 0600, never over an existing file and never over a key.
func writeOut(cmd *cobra.Command, out string, data []byte, keys ...string) error {
	data = append(data, '\n')
	if out == "" {
		_, err := cmd.OutOrStdout().Write(data)
		return err
	}
	for _, k := range keys {
		if sameFile(out, k) {
			return fmt.Errorf("%w: the output %s is the key file %s", ErrGovernance, out, k)
		}
	}
	created, err := createExclusive(out, data)
	if err != nil {
		return err
	}
	if !created {
		return fmt.Errorf("%w: %s exists (it is never overwritten; remove it or choose another path)", ErrGovernance, out)
	}
	return nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrGovernance, path, err)
	}
	return nil
}

// readSignerKey reads a signer or sender key (0x-hex) and refuses one that other users can read.
func readSignerKey(path string) (*ecdsa.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: the key file %s is readable by other users (mode %o): chmod 600 it", ErrGovernance, path, st.Mode().Perm())
	}
	return readOperatorKey(path)
}

// ---- chain ---------------------------------------------------------------------------------------------------------------------------

type govFlags struct {
	RPC      string
	Registry string
}

func (f *govFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.RPC, "rpc", "", "public JSON-RPC endpoint")
	cmd.Flags().StringVar(&f.Registry, "registry", "", "ValidatorRegistry address (default 0xff..03)")
}

type govChain struct {
	rpc     *rpc.Client
	vr      *vrclient.Client
	chainID *big.Int
	cfg     vrclient.ConfigView
	module  vrclient.ModuleView
}

func (f *govFlags) dial(ctx context.Context) (*govChain, error) {
	if f.RPC == "" {
		return nil, fmt.Errorf("%w: --rpc (the public JSON-RPC endpoint) is required", ErrGovernance)
	}
	reg := vrclient.DefaultRegistry
	if f.Registry != "" {
		if !common.IsHexAddress(f.Registry) {
			return nil, fmt.Errorf("%w: registry %q is not an address", ErrGovernance, f.Registry)
		}
		reg = common.HexToAddress(f.Registry)
	}
	c, err := rpc.DialContext(ctx, f.RPC)
	if err != nil {
		return nil, fmt.Errorf("%w: dialing %s: %w", ErrGovernance, f.RPC, err)
	}
	gc := &govChain{rpc: c}
	fail := func(err error) (*govChain, error) { c.Close(); return nil, fmt.Errorf("%w: %w", ErrGovernance, err) }
	var id hexutil.Big
	if err := c.CallContext(ctx, &id, "eth_chainId"); err != nil {
		return fail(fmt.Errorf("eth_chainId at %s: %w", f.RPC, err))
	}
	gc.chainID = id.ToInt()
	// one head for every read of the command
	pinned, _, err := vrclient.New(c, reg).Pin(ctx)
	if err != nil {
		return fail(err)
	}
	gc.vr = pinned
	if gc.cfg, err = gc.vr.Config(ctx); err != nil {
		return fail(fmt.Errorf("reading VR at %s: %w", reg.Hex(), err))
	}
	if gc.cfg.Governor == (common.Address{}) {
		return fail(fmt.Errorf("VR at %s has no governor", reg.Hex()))
	}
	if gc.module, err = gc.vr.ActiveModule(ctx); err != nil {
		return fail(fmt.Errorf("reading VR's active module: %w", err))
	}
	return gc, nil
}

func (gc *govChain) close() { gc.rpc.Close() }

// poa is the active module when it is PoaElection v1 (the lifecycle actions are PoA's).
func (gc *govChain) poa() (common.Address, error) {
	if gc.module.Meta.ModuleTag != vrclient.ModuleTagPoA {
		return common.Address{}, fmt.Errorf("%w: VR's active module %s is not PoaElection v1 (tag %x); its ModuleActions are not PoA's", ErrGovernance,
			gc.module.Module.Hex(), gc.module.Meta.ModuleTag)
	}
	return gc.module.Module, nil
}

// ---- signer init ---------------------------------------------------------------------------------------------------------------------

func govSignerInitCmd() *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "init-signer",
		Short: "Create or locate a multisig signer's key (a new 0600 file, never replaced)",
		Long: `Creates the signer's key as 0x-hex in a 0600 file in a 0700 directory, exclusively: of concurrent creators exactly one installs
its key, and an existing file is kept and read back, never replaced. Prints the signer's address, which the multisig's signer set must
contain for the approvals to count.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if keyPath == "" {
				return fmt.Errorf("%w: --key is required", ErrGovernance)
			}
			removeStaleTemps([]string{keyPath}, time.Now())
			created, err := ensureSecretHex(keyPath, "0x")
			if err != nil {
				return fmt.Errorf("%w: %w", ErrGovernance, err)
			}
			k, err := readSignerKey(keyPath)
			if err != nil {
				return err
			}
			verb := "found  "
			if created {
				verb = "created"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s signer key %s\nsigner address %s\n", verb, keyPath, ethcrypto.PubkeyToAddress(k.PublicKey).Hex())
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "the signer key file")
	return cmd
}

// ---- propose -------------------------------------------------------------------------------------------------------------------------

type proposeFlags struct {
	govFlags
	Out          string
	Description  string
	DryRun       bool
	NoStateCheck bool
}

func (f *proposeFlags) add(cmd *cobra.Command) {
	f.govFlags.add(cmd)
	cmd.Flags().StringVar(&f.Out, "out", "", "proposal file to create (default: standard output; never overwritten)")
	cmd.Flags().StringVar(&f.Description, "note", "", "a note for the signers (shown with the decoded call; not signed)")
	cmd.Flags().BoolVar(&f.DryRun, "dry-run", false, "decode and simulate, write nothing")
}

// propose is the common tail of every proposal: the multisig's nonce, the digest (checked against the multisig's own), the queue
// simulated as the governor, the preview, the file.
func propose(cmd *cobra.Command, f *proposeFlags, gc *govChain, target common.Address, data []byte) error {
	ctx := cmd.Context()
	w := cmd.ErrOrStderr() // with no --out the proposal is the standard output, so the preview goes to the error stream
	if f.Out != "" {
		w = cmd.OutOrStdout()
	}
	gov := gc.cfg.Governor
	nonce, err := gc.vr.MultisigNonce(ctx, gov)
	if err != nil {
		return fmt.Errorf("%w: reading the governor %s (is it the FoundationMultisig?): %w", ErrGovernance, gov.Hex(), err)
	}
	digest, err := vrclient.CallDigest(gc.chainID, gov, target, data, nonce)
	if err != nil {
		return err
	}
	if onchain, err := gc.vr.MultisigCallDigest(ctx, gov, target, data, nonce); err != nil {
		return fmt.Errorf("%w: the multisig's own digest: %w", ErrGovernance, err)
	} else if onchain != digest {
		return fmt.Errorf("%w: the multisig computes digest %x, this tool %x (a different multisig version or chain)", ErrGovernance, onchain, digest)
	}
	p := govProposal{Format: proposalFormat, ChainID: gc.chainID.Uint64(), Multisig: gov.Hex(), Target: target.Hex(), Data: hexutil.Encode(data),
		Nonce: nonce, Digest: hexutil.Encode(digest[:]), Description: f.Description}
	cp, err := p.check()
	if err != nil {
		return err
	}
	// the call, simulated as the governor: VR's refusal is decoded here; inside the multisig it would be a bare CallFailed
	ret, err := gc.vr.CallRawFrom(ctx, gov, vrclient.Tx{To: target, Data: data})
	if err != nil {
		return fmt.Errorf("%w: VR would refuse the call: %w", ErrGovernance, err)
	}
	if call, derr := vrclient.DecodeCall(data); derr == nil && call.Method == "queue" {
		if vals, err := vrclient.VRABI.Methods["queue"].Outputs.Unpack(ret); err == nil && len(vals) == 1 {
			p.PredictedChangeID, _ = vals[0].(uint64)
		}
	}
	if err := cp.preview(w); err != nil {
		return err
	}
	fmt.Fprintf(w, "  simulation: VR accepts the call as the governor")
	if p.PredictedChangeID != 0 {
		fmt.Fprintf(w, " (it would be change %d)", p.PredictedChangeID)
	}
	fmt.Fprintln(w, "\n  approvals: 3 of the 5 signers, each with `ubft governance sign`; the nonce is consumed by the first execution, so proposals at one nonce are alternatives")
	if f.DryRun {
		fmt.Fprintln(w, "dry run: nothing written")
		return nil
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeOut(cmd, f.Out, b)
}

func newGovProposeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "propose",
		Short: "Build a proposal: a ModuleAction, force-remove, committee limits, fee parameters, cancel, or any payload",
		Long: `Builds the call VR.queue(kind, payload) (or VR.cancel), reads the multisig's nonce, computes the EIP-712 digest the signers sign,
pre-judges the payload with the frozen schema checks, simulates the call as the governor against the chain (a VR refusal is decoded) and
writes the proposal file. The preview shows the decoded call; signers sign what it does, not the note.`,
	}
	cmd.AddCommand(govModuleActionCmd("admit", "Admit an applied validator (PoA ModuleAction Admit)", vrclient.ActionAdmit),
		govModuleActionCmd("confirm-exit", "Confirm a validator's requested exit (PoA ModuleAction ConfirmExit)", vrclient.ActionConfirmExit),
		govModuleActionCmd("remove", "Remove a validator in any state but None and Exited (PoA ModuleAction Remove)", vrclient.ActionRemove),
		govForceRemoveCmd(), govCommitteeLimitsCmd(), govFeeParamsCmd(), govCancelCmd(), govRawCmd())
	return cmd
}

func govModuleActionCmd(use, short string, action uint64) *cobra.Command {
	f := &proposeFlags{}
	var id uint64
	cmd := &cobra.Command{Use: use, Short: short,
		Long: short + `. PoaElection takes an action its guard refuses without reverting (VR then shows the change Active): this command
checks the identity's PoA state first and refuses a proposal the module would refuse.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id == 0 {
				return fmt.Errorf("%w: --id is required", ErrGovernance)
			}
			gc, err := f.dial(cmd.Context())
			if err != nil {
				return err
			}
			defer gc.close()
			module, err := gc.poa()
			if err != nil {
				return err
			}
			state, since, err := gc.vr.PoaStatus(cmd.Context(), module, id)
			if err != nil {
				return err
			}
			if !f.NoStateCheck {
				if err := checkActionState(action, id, state); err != nil {
					return err
				}
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "identity %d is %s (since progress %d)\n", id, vrclient.PoaState(state), since)
			payload, err := vrclient.EncodeModuleAction(module, action, id)
			if err != nil {
				return err
			}
			data, err := vrclient.QueueCalldata(vrclient.KindModuleAction, payload)
			if err != nil {
				return err
			}
			return propose(cmd, f, gc, gc.vr.Registry, data)
		}}
	f.add(cmd)
	cmd.Flags().Uint64Var(&id, "id", 0, "the VR identity")
	cmd.Flags().BoolVar(&f.NoStateCheck, "no-state-check", false, "propose even if the module would refuse the action in the identity's current state")
	return cmd
}

// checkActionState is PoaElection's guard for an action (design 3.7.1).
func checkActionState(action, id uint64, state uint8) error {
	ok := false
	switch action {
	case vrclient.ActionAdmit:
		ok = state == vrclient.PoaApplied
	case vrclient.ActionConfirmExit:
		ok = state == vrclient.PoaExitRequested
	case vrclient.ActionRemove:
		ok = state != vrclient.PoaNone && state != vrclient.PoaExited
	}
	if !ok {
		return fmt.Errorf("%w: identity %d is %s: PoaElection would refuse %s without effect (--no-state-check overrides)", ErrGovernance, id,
			vrclient.PoaState(state), vrclient.ActionName(action))
	}
	return nil
}

func govForceRemoveCmd() *cobra.Command {
	f := &proposeFlags{}
	var id uint64
	cmd := &cobra.Command{Use: "force-remove", Short: "Remove a committee member by the roots (change kind ForceRemove), for an unavailable validator",
		Long: `ForceRemove is a root-side change (it needs no module cooperation): VR binds it into a boundary and the roots remove the member
at their next election. The id must be in the committee in force and fewer than four ForceRemoves may be pending.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id == 0 {
				return fmt.Errorf("%w: --id is required", ErrGovernance)
			}
			gc, err := f.dial(cmd.Context())
			if err != nil {
				return err
			}
			defer gc.close()
			payload, err := vrclient.ForceRemovePayload(id)
			if err != nil {
				return err
			}
			data, err := vrclient.QueueCalldata(vrclient.KindForceRemove, payload)
			if err != nil {
				return err
			}
			return propose(cmd, f, gc, gc.vr.Registry, data)
		}}
	f.add(cmd)
	cmd.Flags().Uint64Var(&id, "id", 0, "the committee member's VR identity")
	return cmd
}

func govCommitteeLimitsCmd() *cobra.Command {
	f := &proposeFlags{}
	var nMin, nTarget, nMax uint32
	cmd := &cobra.Command{Use: "committee-limits", Short: "Change the committee size limits (nMin <= nTarget <= nMax)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			gc, err := f.dial(cmd.Context())
			if err != nil {
				return err
			}
			defer gc.close()
			fmt.Fprintf(cmd.ErrOrStderr(), "current limits: nMin %d, nTarget %d, nMax %d\n", gc.cfg.NMin, gc.cfg.NTarget, gc.cfg.NMax)
			payload, err := vrclient.CommitteeLimitsPayload(nMin, nTarget, nMax)
			if err != nil {
				return err
			}
			data, err := vrclient.QueueCalldata(vrclient.KindCommitteeLimits, payload)
			if err != nil {
				return err
			}
			return propose(cmd, f, gc, gc.vr.Registry, data)
		}}
	f.add(cmd)
	cmd.Flags().Uint32Var(&nMin, "n-min", 0, "minimum committee size")
	cmd.Flags().Uint32Var(&nTarget, "n-target", 0, "target committee size")
	cmd.Flags().Uint32Var(&nMax, "n-max", 0, "maximum committee size")
	_ = cmd.MarkFlagRequired("n-min")
	_ = cmd.MarkFlagRequired("n-target")
	_ = cmd.MarkFlagRequired("n-max")
	return cmd
}

func govFeeParamsCmd() *cobra.Command {
	f := &proposeFlags{}
	var floor, denom uint64
	var collector string
	cmd := &cobra.Command{Use: "fee-params", Short: "Change the base fee floor, the change denominator and the fee collector",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !common.IsHexAddress(collector) {
				return fmt.Errorf("%w: --fee-collector %q is not an address", ErrGovernance, collector)
			}
			gc, err := f.dial(cmd.Context())
			if err != nil {
				return err
			}
			defer gc.close()
			cur := gc.cfg.FeesCurrent
			fmt.Fprintf(cmd.ErrOrStderr(), "current fees: base fee floor %d, change denominator %d, collector %s\n", cur.BaseFeeFloor, cur.ChangeDenominator, cur.FeeCollector.Hex())
			payload, err := vrclient.FeeParamsPayload(floor, denom, common.HexToAddress(collector))
			if err != nil {
				return err
			}
			data, err := vrclient.QueueCalldata(vrclient.KindFeeParams, payload)
			if err != nil {
				return err
			}
			return propose(cmd, f, gc, gc.vr.Registry, data)
		}}
	f.add(cmd)
	cmd.Flags().Uint64Var(&floor, "base-fee-floor", 0, "base fee floor (wei)")
	cmd.Flags().Uint64Var(&denom, "change-denominator", 0, "base fee change denominator")
	cmd.Flags().StringVar(&collector, "fee-collector", "", "fee collector address")
	_ = cmd.MarkFlagRequired("base-fee-floor")
	_ = cmd.MarkFlagRequired("change-denominator")
	_ = cmd.MarkFlagRequired("fee-collector")
	return cmd
}

func govCancelCmd() *cobra.Command {
	f := &proposeFlags{}
	var id uint64
	cmd := &cobra.Command{Use: "cancel", Short: "Cancel a Queued or Scheduled change (never once Bound)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if id == 0 {
				return fmt.Errorf("%w: --change is required", ErrGovernance)
			}
			gc, err := f.dial(cmd.Context())
			if err != nil {
				return err
			}
			defer gc.close()
			ch, err := gc.vr.Change(cmd.Context(), id)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "change %d is %s: %s\n", id, vrclient.ChangeState(ch.State), vrclient.DescribeChange(ch.Kind, ch.Payload))
			data, err := vrclient.CancelCalldata(id)
			if err != nil {
				return err
			}
			return propose(cmd, f, gc, gc.vr.Registry, data)
		}}
	f.add(cmd)
	cmd.Flags().Uint64Var(&id, "change", 0, "the change id")
	return cmd
}

func govRawCmd() *cobra.Command {
	f := &proposeFlags{}
	var kind uint8
	var payloadHex string
	cmd := &cobra.Command{Use: "raw", Short: "Queue any change kind from an abi.encode payload built elsewhere",
		Long: `For the kinds whose payloads are built by their own tools: AddPartition (7) and UpdatePartition (8) from
` + "`ubft vr-change add-partition` and `update-partition`" + `, and SetModule (1), SetGovernor (3), ReplaceAggregatorValidators (6) and
ScheduleActivation (9). The payload is pre-judged with the frozen queue check before anything is simulated.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			payload, err := hexutil.Decode(strings.TrimSpace(payloadHex))
			if err != nil {
				return fmt.Errorf("%w: --payload: %v", ErrGovernance, err)
			}
			gc, err := f.dial(cmd.Context())
			if err != nil {
				return err
			}
			defer gc.close()
			data, err := vrclient.QueueCalldata(kind, payload)
			if err != nil {
				return err
			}
			return propose(cmd, f, gc, gc.vr.Registry, data)
		}}
	f.add(cmd)
	cmd.Flags().Uint8Var(&kind, "kind", 0, "the change kind (1 SetModule, 3 SetGovernor, 6 ReplaceAggregatorValidators, 7 AddPartition, 8 UpdatePartition, 9 ScheduleActivation)")
	cmd.Flags().StringVar(&payloadHex, "payload", "", "the payload, 0x-hex (or @file to read it from a file)")
	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("payload")
	cmd.PreRunE = func(_ *cobra.Command, _ []string) error {
		if strings.HasPrefix(payloadHex, "@") {
			b, err := os.ReadFile(strings.TrimPrefix(payloadHex, "@")) // #nosec G304 -- operator supplied local file
			if err != nil {
				return err
			}
			payloadHex = string(b)
		}
		return nil
	}
	return cmd
}

// ---- sign ----------------------------------------------------------------------------------------------------------------------------

func govSignCmd() *cobra.Command {
	var proposalFile, keyFile, out string
	var f govFlags
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "One signer: show what a proposal does and sign its digest offline",
		Long: `Works offline from the proposal file and the signer's key file: it recomputes the digest from the proposal's fields, decodes the call and
shows it, and signs the digest. With --rpc it also checks that the key is one of the multisig's signers and that the nonce is still
current. The signature is an approval file for ` + "`ubft governance aggregate`" + `.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var p govProposal
			if err := readJSON(proposalFile, &p); err != nil {
				return err
			}
			cp, err := p.check()
			if err != nil {
				return err
			}
			if err := cp.preview(cmd.ErrOrStderr()); err != nil {
				return err
			}
			key, err := readSignerKey(keyFile)
			if err != nil {
				return err
			}
			signer := ethcrypto.PubkeyToAddress(key.PublicKey)
			fmt.Fprintf(cmd.ErrOrStderr(), "signing as %s\n", signer.Hex())
			if f.RPC != "" {
				if err := checkSignerOnline(cmd.Context(), &f, cp, signer); err != nil {
					return err
				}
			}
			sig, err := vrclient.SignCall(key, cp.digest)
			if err != nil {
				return err
			}
			b, err := json.MarshalIndent(govApproval{Format: approvalFormat, Digest: hexutil.Encode(cp.digest[:]), Signer: signer.Hex(),
				Signature: hexutil.Encode(sig)}, "", "  ")
			if err != nil {
				return err
			}
			return writeOut(cmd, out, b, keyFile, proposalFile)
		}}
	f.add(cmd)
	cmd.Flags().StringVar(&proposalFile, "proposal", "", "the proposal file")
	cmd.Flags().StringVar(&keyFile, "signer-key", "", "the signer's key file")
	cmd.Flags().StringVar(&out, "out", "", "approval file to create (default: standard output; never overwritten)")
	_ = cmd.MarkFlagRequired("proposal")
	_ = cmd.MarkFlagRequired("signer-key")
	return cmd
}

func checkSignerOnline(ctx context.Context, f *govFlags, cp *checkedProposal, signer common.Address) error {
	gc, err := f.dial(ctx)
	if err != nil {
		return err
	}
	defer gc.close()
	if err := gc.checkProposalCurrent(ctx, cp); err != nil {
		return err
	}
	set, err := gc.vr.MultisigSigners(ctx, cp.multisig)
	if err != nil {
		return err
	}
	for _, s := range set {
		if s == signer {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not one of the multisig's signers %v", ErrGovernance, signer.Hex(), set)
}

// checkProposalCurrent refuses a proposal that is not for this chain and governor, or whose nonce the multisig has passed.
func (gc *govChain) checkProposalCurrent(ctx context.Context, cp *checkedProposal) error {
	if cp.p.ChainID != gc.chainID.Uint64() {
		return fmt.Errorf("%w: the proposal is for chain %d, the endpoint serves chain %s", ErrGovernance, cp.p.ChainID, gc.chainID)
	}
	if cp.multisig != gc.cfg.Governor {
		return fmt.Errorf("%w: the proposal is for multisig %s, VR's governor is %s", ErrGovernance, cp.multisig.Hex(), gc.cfg.Governor.Hex())
	}
	if cp.target != gc.vr.Registry {
		return fmt.Errorf("%w: the proposal's target %s is not the registry %s", ErrGovernance, cp.target.Hex(), gc.vr.Registry.Hex())
	}
	nonce, err := gc.vr.MultisigNonce(ctx, cp.multisig)
	if err != nil {
		return err
	}
	if nonce != cp.p.Nonce {
		return fmt.Errorf("%w: the proposal is at nonce %d, the multisig is at nonce %d: propose again", ErrGovernance, cp.p.Nonce, nonce)
	}
	return nil
}

// ---- aggregate -----------------------------------------------------------------------------------------------------------------------

func govAggregateCmd() *cobra.Command {
	var proposalFile, out string
	var approvalFiles []string
	var f govFlags
	cmd := &cobra.Command{
		Use:   "aggregate",
		Short: "Collect three or more approvals into a bundle, ordered as the multisig requires",
		Long: `Checks every approval against the proposal's digest (each signature must recover to the signer it names), refuses a signer twice or fewer
than three, and orders them by ascending signer address. With --rpc it also refuses an approval of an address that is not one of
the multisig's five signers, and a proposal whose nonce has passed.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var p govProposal
			if err := readJSON(proposalFile, &p); err != nil {
				return err
			}
			cp, err := p.check()
			if err != nil {
				return err
			}
			if _, err := cp.what(); err != nil {
				return err
			}
			var as []vrclient.Approval
			for _, af := range approvalFiles {
				var a govApproval
				if err := readJSON(af, &a); err != nil {
					return err
				}
				if a.Digest != "" && !strings.EqualFold(a.Digest, hexutil.Encode(cp.digest[:])) {
					return fmt.Errorf("%w: %s approves digest %s, not this proposal's %x", ErrGovernance, af, a.Digest, cp.digest)
				}
				sig, err := hexutil.Decode(a.Signature)
				if err != nil || !common.IsHexAddress(a.Signer) {
					return fmt.Errorf("%w: %s: malformed approval", ErrGovernance, af)
				}
				as = append(as, vrclient.Approval{Signer: common.HexToAddress(a.Signer), Signature: sig})
			}
			ordered, err := vrclient.OrderApprovals(cp.digest, as)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrGovernance, err)
			}
			if len(ordered) < vrclient.MultisigThreshold {
				return fmt.Errorf("%w: %d approvals, the multisig needs %d distinct signers", ErrGovernance, len(ordered), vrclient.MultisigThreshold)
			}
			if f.RPC != "" {
				gc, err := f.dial(cmd.Context())
				if err != nil {
					return err
				}
				defer gc.close()
				if err := gc.checkProposalCurrent(cmd.Context(), cp); err != nil {
					return err
				}
				if err := gc.checkSigners(cmd.Context(), cp.multisig, ordered); err != nil {
					return err
				}
			}
			b := govBundle{Format: bundleFormat, Proposal: p}
			for _, a := range ordered {
				b.Approvals = append(b.Approvals, govApproval{Signer: a.Signer.Hex(), Signature: hexutil.Encode(a.Signature)})
				fmt.Fprintf(cmd.ErrOrStderr(), "approval by %s\n", a.Signer.Hex())
			}
			raw, err := json.MarshalIndent(b, "", "  ")
			if err != nil {
				return err
			}
			return writeOut(cmd, out, raw, proposalFile)
		}}
	f.add(cmd)
	cmd.Flags().StringVar(&proposalFile, "proposal", "", "the proposal file")
	cmd.Flags().StringSliceVar(&approvalFiles, "approval", nil, "an approval file (repeat, any order)")
	cmd.Flags().StringVar(&out, "out", "", "bundle file to create (default: standard output; never overwritten)")
	_ = cmd.MarkFlagRequired("proposal")
	_ = cmd.MarkFlagRequired("approval")
	return cmd
}

func (gc *govChain) checkSigners(ctx context.Context, gov common.Address, as []vrclient.Approval) error {
	set, err := gc.vr.MultisigSigners(ctx, gov)
	if err != nil {
		return err
	}
	in := map[common.Address]bool{}
	for _, s := range set {
		in[s] = true
	}
	for _, a := range as {
		if !in[a.Signer] {
			return fmt.Errorf("%w: %s is not one of the multisig's signers %v", ErrGovernance, a.Signer.Hex(), set)
		}
	}
	return nil
}

// ---- execute -------------------------------------------------------------------------------------------------------------------------

type executeFlags struct {
	govFlags
	Bundle    string
	Change    uint64
	SenderKey string
	DryRun    bool
	Wait      time.Duration
}

func govExecuteCmd() *cobra.Command {
	f := &executeFlags{}
	cmd := &cobra.Command{
		Use:   "execute",
		Short: "Send an approved bundle to the multisig (--bundle), or execute a queued change after its delays (--change)",
		Long: `Two sends, both open to anyone with an account that pays the gas (--sender-key; it needs no authority):
  --bundle FILE   FoundationMultisig.execute(VR, VR.queue(...), signatures): the change is queued, with its two governance delays
  --change N      VR.execute(N): after both delays a ModuleAction executes into the PoA module, any other kind becomes Scheduled
                  for the next election's boundary
The preview decodes the call, checks the approvals against the multisig's signers and nonce, simulates the call as the governor (so a
VR refusal is named) and the transaction itself. After a ModuleAction executes, the PoA module may still have refused it by its guard
(VR then shows the change Active): the receipt is read for ActionRefused and the command fails if it finds one.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if (f.Bundle == "") == (f.Change == 0) {
				return fmt.Errorf("%w: pass exactly one of --bundle and --change", ErrGovernance)
			}
			if f.SenderKey == "" {
				return fmt.Errorf("%w: --sender-key (the account that pays for the transaction) is required", ErrGovernance)
			}
			key, err := readSignerKey(f.SenderKey)
			if err != nil {
				return err
			}
			gc, err := f.dial(cmd.Context())
			if err != nil {
				return err
			}
			defer gc.close()
			s := vrclient.Sender{RPC: gc.rpc, Key: key, ChainID: gc.chainID, Wait: f.Wait}
			if f.Bundle != "" {
				return executeBundle(cmd, f, gc, s)
			}
			return executeChange(cmd, f, gc, s)
		}}
	f.govFlags.add(cmd)
	cmd.Flags().StringVar(&f.Bundle, "bundle", "", "the aggregated bundle (`ubft governance aggregate`)")
	cmd.Flags().Uint64Var(&f.Change, "change", 0, "the queued change to execute")
	cmd.Flags().StringVar(&f.SenderKey, "sender-key", "", "key file of the account that sends and pays (0x-hex)")
	cmd.Flags().BoolVar(&f.DryRun, "dry-run", false, "build, decode and simulate the transaction, send nothing")
	cmd.Flags().DurationVar(&f.Wait, "wait", 2*time.Minute, "how long to wait for the receipt")
	return cmd
}

func executeBundle(cmd *cobra.Command, f *executeFlags, gc *govChain, s vrclient.Sender) error {
	ctx := cmd.Context()
	w := cmd.OutOrStdout()
	var b govBundle
	if err := readJSON(f.Bundle, &b); err != nil {
		return err
	}
	if b.Format != bundleFormat {
		return fmt.Errorf("%w: bundle format %q, want %q", ErrGovernance, b.Format, bundleFormat)
	}
	cp, err := b.Proposal.check()
	if err != nil {
		return err
	}
	if err := cp.preview(w); err != nil {
		return err
	}
	if err := gc.checkProposalCurrent(ctx, cp); err != nil {
		return err
	}
	var as []vrclient.Approval
	for _, a := range b.Approvals {
		sig, err := hexutil.Decode(a.Signature)
		if err != nil || !common.IsHexAddress(a.Signer) {
			return fmt.Errorf("%w: a malformed approval in the bundle", ErrGovernance)
		}
		as = append(as, vrclient.Approval{Signer: common.HexToAddress(a.Signer), Signature: sig})
	}
	ordered, err := vrclient.OrderApprovals(cp.digest, as)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrGovernance, err)
	}
	if len(ordered) < vrclient.MultisigThreshold {
		return fmt.Errorf("%w: %d approvals, the multisig needs %d", ErrGovernance, len(ordered), vrclient.MultisigThreshold)
	}
	if err := gc.checkSigners(ctx, cp.multisig, ordered); err != nil {
		return err
	}
	fmt.Fprintf(w, "approvals: %d, all by the multisig's signers, in ascending order\n", len(ordered))
	// the inner call as the governor: VR's own refusal, decoded (the multisig reports only CallFailed)
	if _, err := gc.vr.CallRawFrom(ctx, cp.multisig, vrclient.Tx{To: cp.target, Data: cp.data}); err != nil {
		return fmt.Errorf("%w: VR would refuse the approved call: %w", ErrGovernance, err)
	}
	data, err := vrclient.ExecuteCalldata(cp.target, cp.data, ordered)
	if err != nil {
		return err
	}
	after := func(_ int, r *vrclient.Receipt) ([]step, error) {
		if id, kind, ok := vrclient.ChangeQueuedID(r, gc.vr.Registry); ok {
			ch, err := gc.vr.Change(ctx, id)
			if err == nil {
				// the head moved after the pin: read the change at the new head
				fresh := *gc.vr
				fresh.Block = ""
				if ch, err = fresh.Change(ctx, id); err == nil {
					fmt.Fprintf(w, "  queued: change %d (%s), executable after progress %d and UC time %d; then `ubft governance execute --change %d`\n", id,
						vrclient.ChangeKind(kind), ch.NotBeforeProgress, ch.NotBeforeTime, id)
				}
			}
		} else {
			fmt.Fprintln(w, "  executed: the call took effect (a cancel emits no ChangeQueued)")
		}
		return nil, nil
	}
	return runStepsAs(ctx, ErrGovernance, w, s, f.DryRun, []step{{what: "execute the approved call through the Foundation multisig",
		tx: vrclient.Tx{To: cp.multisig, Data: data}}}, after)
}

func executeChange(cmd *cobra.Command, f *executeFlags, gc *govChain, s vrclient.Sender) error {
	ctx := cmd.Context()
	w := cmd.OutOrStdout()
	id := f.Change
	ch, err := gc.vr.Change(ctx, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "change %d is %s: %s\n", id, vrclient.ChangeState(ch.State), vrclient.DescribeChange(ch.Kind, ch.Payload))
	if ch.State != vrclient.ChangeQueued {
		return fmt.Errorf("%w: change %d is %s; only a Queued change is executed", ErrGovernance, id, vrclient.ChangeState(ch.State))
	}
	clk, err := gc.vr.Clock(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "delays: %s\n", delayText(ch, clk))
	data, err := vrclient.ExecuteChangeCalldata(id)
	if err != nil {
		return err
	}
	module := gc.module.Module
	after := func(_ int, r *vrclient.Receipt) ([]step, error) {
		fresh := *gc.vr
		fresh.Block = ""
		now, err := fresh.Change(ctx, id)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(w, "  change %d is now %s\n", id, vrclient.ChangeState(now.State))
		if refused := vrclient.ActionRefusals(r, module); len(refused) > 0 {
			for _, a := range refused {
				fmt.Fprintf(w, "  %s\n", a)
			}
			return nil, fmt.Errorf("%w: VR executed change %d, but the module refused the action: it had no effect", ErrGovernance, id)
		}
		return nil, nil
	}
	return runStepsAs(ctx, ErrGovernance, w, s, f.DryRun, []step{{what: fmt.Sprintf("execute change %d", id),
		tx: vrclient.Tx{To: gc.vr.Registry, Data: data}}}, after)
}

// ---- list ----------------------------------------------------------------------------------------------------------------------------

func govListCmd() *cobra.Command {
	var f govFlags
	var only uint64
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show the multisig, the clock and the queued changes with their delays, state and expiry",
		Long: `Reads one head. Pending changes are those VR still holds: Queued (waiting for both governance delays), Scheduled (executed, waiting for a
boundary) and Bound (in an output; it takes effect when the roots acknowledge it, or the output expires). A change that is Active,
Rejected or Cancelled is no longer listed; --change N shows any change by its id.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gc, err := f.dial(cmd.Context())
			if err != nil {
				return err
			}
			defer gc.close()
			return listChanges(cmd, gc, only)
		}}
	f.add(cmd)
	cmd.Flags().Uint64Var(&only, "change", 0, "show this change only (in any state)")
	return cmd
}

func listChanges(cmd *cobra.Command, gc *govChain, only uint64) error {
	ctx := cmd.Context()
	w := cmd.OutOrStdout()
	gov := gc.cfg.Governor
	clk, err := gc.vr.Clock(ctx)
	if err != nil {
		return err
	}
	set, err := gc.vr.MultisigSigners(ctx, gov)
	if err != nil {
		return fmt.Errorf("%w: reading the governor %s (is it the FoundationMultisig?): %w", ErrGovernance, gov.Hex(), err)
	}
	nonce, err := gc.vr.MultisigNonce(ctx, gov)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "governor: FoundationMultisig %s (%d of %d), nonce %d\n  signers: %v\n", gov.Hex(), vrclient.MultisigThreshold, len(set), nonce, set)
	if pend, np, nt, err := gc.vr.MultisigPendingSigners(ctx, gov); err == nil && pend {
		fmt.Fprintf(w, "  signer change staged: applicable after progress %d and UC time %d\n", np, nt)
	}
	fmt.Fprintf(w, "clock: progress %d, UC time %d; active module %s\n", clk.Progress, clk.UcTime, gc.module.Module.Hex())
	ids := []uint64{only}
	if only == 0 {
		if ids, err = gc.vr.PendingChanges(ctx); err != nil {
			return err
		}
		fmt.Fprintf(w, "pending changes: %d\n", len(ids))
	}
	for _, id := range ids {
		ch, err := gc.vr.Change(ctx, id)
		if err != nil {
			return err
		}
		if ch.State == 0 {
			return fmt.Errorf("%w: there is no change %d", ErrGovernance, id)
		}
		fmt.Fprintf(w, "  #%d %s\n", id, vrclient.DescribeChange(ch.Kind, ch.Payload))
		fmt.Fprintf(w, "      state %s%s\n", vrclient.ChangeState(ch.State), rejectText(ch))
		switch ch.State {
		case vrclient.ChangeQueued:
			fmt.Fprintf(w, "      delays: %s\n", delayText(ch, clk))
			fmt.Fprintf(w, "      expiry: none while Queued; after `execute --change %d` it is Scheduled", id)
			if ch.Kind == vrclient.KindModuleAction {
				fmt.Fprintf(w, " (a ModuleAction runs in the module at once and is then Active)")
			}
			fmt.Fprintln(w)
		case vrclient.ChangeScheduled:
			fmt.Fprintf(w, "      scheduled at progress %d; it is bound into the next election's output\n      expiry: none while Scheduled\n", ch.ScheduledAt)
		case vrclient.ChangeBound:
			fmt.Fprintf(w, "      bound to output %x\n", ch.BoundTo)
			if out, err := gc.vr.Output(ctx, ch.BoundTo); err == nil {
				fmt.Fprintf(w, "      expiry: the output expires at progress %d (%s); if it expires the change returns to Scheduled\n", out.ExpiresAtProgress,
					remaining(out.ExpiresAtProgress, clk.Progress, "progress units"))
			}
		case vrclient.ChangeActive:
			fmt.Fprintf(w, "      in force since root epoch %d\n", ch.ActiveRootEpoch)
		}
	}
	return nil
}

func rejectText(ch vrclient.ChangeView) string {
	if ch.State != vrclient.ChangeRejected {
		return ""
	}
	switch ch.RejectReason {
	case 19:
		return " (the module's action failed: the module is Faulted)"
	case 20:
		return " (the target was not the active module)"
	}
	return fmt.Sprintf(" (reason %d)", ch.RejectReason)
}

func remaining(deadline, now uint64, unit string) string {
	if now >= deadline {
		return "passed"
	}
	return fmt.Sprintf("in %d %s", deadline-now, unit)
}

// delayText states both governance delays of a change against the clock: a change executes only when both have passed.
func delayText(ch vrclient.ChangeView, clk vrclient.Clock) string {
	if clk.Progress >= ch.NotBeforeProgress && clk.UcTime >= ch.NotBeforeTime {
		return fmt.Sprintf("both passed (progress %d, UC time %d): executable now", ch.NotBeforeProgress, ch.NotBeforeTime)
	}
	var parts []string
	if clk.Progress < ch.NotBeforeProgress {
		parts = append(parts, fmt.Sprintf("progress %d (in %d units)", ch.NotBeforeProgress, ch.NotBeforeProgress-clk.Progress))
	}
	if clk.UcTime < ch.NotBeforeTime {
		parts = append(parts, fmt.Sprintf("UC time %d (in %s)", ch.NotBeforeTime, (time.Duration(ch.NotBeforeTime-clk.UcTime)*time.Second).String()))
	}
	return "waiting for " + strings.Join(parts, " and ")
}

// ---- group ---------------------------------------------------------------------------------------------------------------------------

func newGovernanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "governance",
		Short: "The Foundation multisig's side of the validator registry: propose, sign, aggregate, execute, list",
		Long: `The Foundation's governance of the validator registry under proof of authority: a 3-of-5 multisig approves each change, offline, one
signer at a time, and anyone submits it. The pipeline is a set of files:
  propose <kind> --out p.json     the call to approve, decoded and simulated      (admit, confirm-exit, remove, force-remove,
                                                                                   committee-limits, fee-params, cancel, raw)
  sign --proposal p.json --signer-key k --out a1.json         each of three signers, offline
  aggregate --proposal p.json --approval a1.json ... --out b.json
  execute --bundle b.json --sender-key k                      the change is queued, with its two delays
  execute --change N --sender-key k                           after the delays: the change executes
  list                                                        what is queued, its delays, state and expiry
Signer keys stay in local files: init-signer creates one exclusively and never replaces it. Reads and transactions use a public
JSON-RPC endpoint only; every sending command previews decoded and simulated and takes --dry-run.`,
	}
	cmd.AddCommand(govSignerInitCmd(), newGovProposeCmd(), govSignCmd(), govAggregateCmd(), govExecuteCmd(), govListCmd())
	return cmd
}
