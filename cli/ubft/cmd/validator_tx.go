package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-core/vrclient"
)

// validatorChain is an open connection to the public RPC with VR's domain read from it.
type validatorChain struct {
	rpc     *rpc.Client
	vr      *vrclient.Client
	chainID *big.Int
	cfg     vrclient.ConfigView
	module  vrclient.ModuleView
}

func (v *loadedValidator) dial(ctx context.Context) (*validatorChain, error) {
	if v.cfg.RPC == "" {
		return nil, fmt.Errorf("%w: no RPC endpoint (validator.json \"rpc\" or --rpc)", ErrValidator)
	}
	c, err := rpc.DialContext(ctx, v.cfg.RPC)
	if err != nil {
		return nil, fmt.Errorf("%w: dialing %s: %w", ErrValidator, v.cfg.RPC, err)
	}
	reg, err := v.registry()
	if err != nil {
		c.Close()
		return nil, err
	}
	ch := &validatorChain{rpc: c, vr: vrclient.New(c, reg)}
	var id hexutil.Big
	if err := c.CallContext(ctx, &id, "eth_chainId"); err != nil {
		c.Close()
		return nil, fmt.Errorf("%w: eth_chainId at %s: %w", ErrValidator, v.cfg.RPC, err)
	}
	ch.chainID = id.ToInt()
	if v.cfg.ChainID != 0 && ch.chainID.Cmp(new(big.Int).SetUint64(v.cfg.ChainID)) != 0 {
		c.Close()
		return nil, fmt.Errorf("%w: the RPC serves chain %s, the config expects %d", ErrValidator, ch.chainID, v.cfg.ChainID)
	}
	if ch.cfg, err = ch.vr.Config(ctx); err != nil {
		c.Close()
		return nil, fmt.Errorf("%w: reading VR at %s: %w", ErrValidator, reg.Hex(), err)
	}
	if ch.module, err = ch.vr.ActiveModule(ctx); err != nil {
		c.Close()
		return nil, fmt.Errorf("%w: reading VR's active module: %w", ErrValidator, err)
	}
	return ch, nil
}

func (ch *validatorChain) close() { ch.rpc.Close() }

// poa refuses a module that is not PoaElection: the lifecycle commands are PoA's (design 3.7.1).
func (ch *validatorChain) poa() (common.Address, error) {
	if ch.module.Meta.ModuleTag != vrclient.ModuleTagPoA {
		return common.Address{}, fmt.Errorf("%w: VR's active module %s is not PoaElection v1 (tag %x); this CLI drives the PoA lifecycle only",
			ErrValidator, ch.module.Module.Hex(), ch.module.Meta.ModuleTag)
	}
	return ch.module.Module, nil
}

func (ch *validatorChain) domain() vrclient.Domain {
	return vrclient.Domain{Network: ch.cfg.Network, ChainID: ch.chainID, Registry: ch.vr.Registry}
}

// txFlags are the state-changing commands' flags.
type txFlags struct {
	validatorFlags
	DryRun bool
	Wait   time.Duration
}

func (f *txFlags) add(cmd *cobra.Command) {
	f.validatorFlags.add(cmd)
	cmd.Flags().BoolVar(&f.DryRun, "dry-run", false, "build, decode and simulate the transactions, send nothing")
	cmd.Flags().DurationVar(&f.Wait, "wait", 2*time.Minute, "how long to wait for each receipt")
}

// step is one transaction of a command, with its plan built lazily (the second transaction of apply depends on the first's id).
type step struct {
	what string
	tx   vrclient.Tx
	// note explains a step that cannot be simulated yet (it depends on an earlier step).
	note string
}

// runSteps previews each step and, unless dry, sends it. after is called with each receipt (apply reads the new id from it) and may
// return the next steps.
func runSteps(ctx context.Context, w io.Writer, s vrclient.Sender, dry bool, steps []step, after func(i int, r *vrclient.Receipt) ([]step, error)) error {
	return runStepsAs(ctx, ErrValidator, w, s, dry, steps, after)
}

// runStepsAs is runSteps with the command group's own error (`ubft governance` has its own).
func runStepsAs(ctx context.Context, base error, w io.Writer, s vrclient.Sender, dry bool, steps []step, after func(i int, r *vrclient.Receipt) ([]step, error)) error {
	for i := 0; i < len(steps); i++ {
		st := steps[i]
		fmt.Fprintf(w, "[%d] %s\n", i+1, st.what)
		if st.note != "" {
			call, err := vrclient.DecodeCall(st.tx.Data)
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "  from: %s\n  to:   %s\n  call: %s\n  simulation: not run: %s\n", s.From().Hex(), st.tx.To.Hex(),
				strings.ReplaceAll(call.String(), "\n", "\n  "), st.note)
			continue
		}
		p, err := s.Plan(ctx, st.tx)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", base, st.what, err)
		}
		fmt.Fprint(w, p.String())
		if p.SimErr != nil {
			return fmt.Errorf("%w: %s would be refused: %w", base, st.what, p.SimErr)
		}
		if dry {
			continue
		}
		h, r, err := s.Send(ctx, p)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", base, st.what, err)
		}
		fmt.Fprintf(w, "  sent: %s, included in block %d (gas used %d)\n", h.Hex(), r.BlockNumber, r.GasUsed)
		if after != nil {
			more, err := after(i, r)
			if err != nil {
				return err
			}
			steps = append(steps[:i+1], more...)
		}
	}
	if dry {
		fmt.Fprintln(w, "dry run: nothing sent")
	}
	return nil
}

// openTx loads the config, the keys and the chain for a state-changing command.
func openTx(cmd *cobra.Command, f *txFlags) (*loadedValidator, *validatorKeys, *validatorChain, vrclient.Sender, error) {
	v, err := f.load()
	if err != nil {
		return nil, nil, nil, vrclient.Sender{}, err
	}
	// before any transaction: apply records the id in the config, which must not share a file with a key
	if err := v.checkPaths(); err != nil {
		return nil, nil, nil, vrclient.Sender{}, err
	}
	keys, err := v.keys()
	if err != nil {
		return nil, nil, nil, vrclient.Sender{}, err
	}
	ch, err := v.dial(cmd.Context())
	if err != nil {
		return nil, nil, nil, vrclient.Sender{}, err
	}
	s := vrclient.Sender{RPC: ch.rpc, Key: keys.Operator, ChainID: ch.chainID, Wait: f.Wait}
	return v, keys, ch, s, nil
}

// findID returns the identity this operator owns: the configured id (checked to be the operator's), else the operator's only
// registered identity found in VR's logs. ok is false when the operator has none.
func findID(ctx context.Context, v *loadedValidator, ch *validatorChain, owner common.Address) (uint64, bool, error) {
	if v.cfg.ID != 0 {
		o, err := ch.vr.OwnerOf(ctx, v.cfg.ID)
		if err != nil {
			return 0, false, err
		}
		if o != owner {
			return 0, false, fmt.Errorf("%w: identity %d is owned by %s, not by the operator account %s", ErrValidator, v.cfg.ID, o.Hex(), owner.Hex())
		}
		return v.cfg.ID, true, nil
	}
	ids, err := ch.vr.IdentitiesOf(ctx, owner)
	if err != nil {
		return 0, false, fmt.Errorf("%w: looking up the operator's identities in VR's logs (pass --id if the endpoint refuses log queries): %w", ErrValidator, err)
	}
	// the logs name candidates; VR's ownerOf decides (an identity's owner never changes in VR v1, but the answer is the endpoint's)
	var owned []uint64
	for _, id := range ids {
		o, err := ch.vr.OwnerOf(ctx, id)
		if err != nil {
			return 0, false, fmt.Errorf("%w: checking the owner of identity %d (pass --id to skip the log lookup): %w", ErrValidator, id, err)
		}
		if o != owner {
			return 0, false, fmt.Errorf("%w: VR's logs name identity %d for %s, but VR says its owner is %s", ErrValidator, id, owner.Hex(), o.Hex())
		}
		owned = append(owned, id)
	}
	switch len(owned) {
	case 0:
		return 0, false, nil
	case 1:
		return owned[0], true, nil
	}
	return 0, false, fmt.Errorf("%w: the operator account owns identities %v; pass --id", ErrValidator, owned)
}

// registration is this validator's registration from its keys and payee.
func registration(v *loadedValidator, keys *validatorKeys, nonce uint64) (vrclient.Registration, vrclient.NodeKeys, vrclient.Prover, error) {
	root, err1 := nodeKeys(keys.Root)
	var evm vrclient.Prover
	var err2 error
	if keys.EVMAuth != nil {
		evm = keys.EVMAuth
	} else {
		var nk vrclient.NodeKeys
		nk, err2 = nodeKeys(keys.EVM)
		evm = nk
	}
	payee, err3 := v.payee()
	if err := errors.Join(err1, err2, err3); err != nil {
		return vrclient.Registration{}, root, evm, err
	}
	r, err := vrclient.NewRegistration(root, evm, payee, nonce)
	return r, root, evm, err
}

// ---- apply ---------------------------------------------------------------------------------------------------------------------------

func validatorApplyCmd(base *baseFlags) *cobra.Command {
	f := &txFlags{validatorFlags: validatorFlags{baseFlags: base}}
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Register the validator in VR and apply to the PoA committee (VR.register + PoaElection.submitApplication)",
		Long: `The deposit step: VR.register binds the root node and the EVM shard node keys (each signs a proof of possession) and the payee
to a new identity owned by the operator account; PoaElection.submitApplication(id) applies it to the committee. An identity this
operator already registered with exactly these keys is reused, so a second apply only applies. After applying, the Foundation
multisig admits the validator (ModuleAction Admit), and it joins at a later boundary.`,
		RunE: func(cmd *cobra.Command, _ []string) error { return validatorApply(cmd, f) },
	}
	f.add(cmd)
	return cmd
}

func validatorApply(cmd *cobra.Command, f *txFlags) error {
	ctx := cmd.Context()
	w := cmd.OutOrStdout()
	v, keys, ch, s, err := openTx(cmd, f)
	if err != nil {
		return err
	}
	defer ch.close()
	module, err := ch.poa()
	if err != nil {
		return err
	}
	owner := s.From()
	id, have, err := findID(ctx, v, ch, owner)
	if err != nil {
		return err
	}
	var steps []step
	if have {
		idn, err := ch.vr.Identity(ctx, id)
		if err != nil {
			return err
		}
		r, _, _, err := registration(v, keys, 0)
		if err != nil {
			return err
		}
		if !vrclient.BindingMatches(idn.Current, r) && !(idn.StagedRef != [32]byte{} && vrclient.BindingMatches(idn.Staged, r)) {
			return fmt.Errorf("%w: identity %d is registered with other keys or another payee; use `ubft validator rotate` to change them", ErrValidator, id)
		}
		state, _, err := ch.vr.PoaStatus(ctx, module, id)
		if err != nil {
			return err
		}
		if state != vrclient.PoaNone && state != vrclient.PoaExited {
			return fmt.Errorf("%w: identity %d is %s; apply needs None or Exited", ErrValidator, id, vrclient.PoaState(state))
		}
		fmt.Fprintf(w, "identity %d is already registered with these keys: applying only\n", id)
		data, err := vrclient.PoaCalldata(vrclient.MethodSubmitApplication, id)
		if err != nil {
			return err
		}
		steps = append(steps, step{what: fmt.Sprintf("apply identity %d to the PoA committee", id), tx: vrclient.Tx{To: module, Data: data}})
	} else {
		nonce, err := ch.vr.RegistrationNonce(ctx, owner)
		if err != nil {
			return err
		}
		r, root, evm, err := registration(v, keys, nonce)
		if err != nil {
			return err
		}
		signed, err := vrclient.SignWith(ctx, ch.domain(), owner, false, 0, r, root, evm)
		if err != nil {
			return err
		}
		data, err := vrclient.RegisterCalldata(signed)
		if err != nil {
			return err
		}
		regTx := vrclient.Tx{To: ch.vr.Registry, Data: data}
		// the id register would return, simulated at the head
		predicted := uint64(0)
		if ret, err := ch.vr.CallRawFrom(ctx, owner, regTx); err == nil {
			if vals, err := vrclient.VRABI.Methods["register"].Outputs.Unpack(ret); err == nil && len(vals) == 1 {
				predicted, _ = vals[0].(uint64)
			}
		}
		apply, err := vrclient.PoaCalldata(vrclient.MethodSubmitApplication, predicted)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "registration digest %x, signed by the root node key and the EVM shard node key%s\n", signed.Digest, viaAuthority(keys))
		steps = append(steps,
			step{what: "register the validator's keys and payee in VR", tx: regTx},
			step{what: fmt.Sprintf("apply identity %d (predicted) to the PoA committee", predicted), tx: vrclient.Tx{To: module, Data: apply},
				note: "it applies the identity the registration creates"})
	}
	after := func(i int, r *vrclient.Receipt) ([]step, error) {
		if have || i != 0 {
			return nil, nil
		}
		newID, ok := vrclient.RegisteredID(r, ch.vr.Registry)
		if !ok {
			return nil, fmt.Errorf("%w: the register receipt has no Registered log", ErrValidator)
		}
		id = newID
		v.cfg.ID = id
		if err := v.save(); err != nil {
			return nil, err
		}
		fmt.Fprintf(w, "  registered identity %d (saved to %s)\n", id, v.path)
		data, err := vrclient.PoaCalldata(vrclient.MethodSubmitApplication, id)
		if err != nil {
			return nil, err
		}
		return []step{{what: fmt.Sprintf("apply identity %d to the PoA committee", id), tx: vrclient.Tx{To: module, Data: data}}}, nil
	}
	if err := runSteps(ctx, w, s, f.DryRun, steps, after); err != nil {
		return err
	}
	if !f.DryRun {
		if have && v.cfg.ID != id {
			v.cfg.ID = id
			if err := v.save(); err != nil {
				return err
			}
		}
		fmt.Fprintf(w, "applied: identity %d is Applied; the Foundation multisig admits it (ModuleAction Admit), and it joins at a later boundary.\n"+
			"Follow it with `ubft validator status`.\n", id)
	}
	return nil
}

// ---- exit, rejoin --------------------------------------------------------------------------------------------------------------------

// ownerAction is exit or rejoin: one PoA owner transaction chosen from the identity's state.
func ownerAction(cmd *cobra.Command, f *txFlags, choose func(id uint64, state uint8) (method, what string, err error)) error {
	ctx := cmd.Context()
	w := cmd.OutOrStdout()
	v, _, ch, s, err := openTx(cmd, f)
	if err != nil {
		return err
	}
	defer ch.close()
	module, err := ch.poa()
	if err != nil {
		return err
	}
	id, have, err := findID(ctx, v, ch, s.From())
	if err != nil {
		return err
	}
	if !have {
		return fmt.Errorf("%w: the operator account %s owns no VR identity (run `ubft validator apply`)", ErrValidator, s.From().Hex())
	}
	state, since, err := ch.vr.PoaStatus(ctx, module, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "identity %d is %s (since progress %d)\n", id, vrclient.PoaState(state), since)
	method, what, err := choose(id, state)
	if err != nil {
		return err
	}
	data, err := vrclient.PoaCalldata(method, id)
	if err != nil {
		return err
	}
	return runSteps(ctx, w, s, f.DryRun, []step{{what: what, tx: vrclient.Tx{To: module, Data: data}}}, nil)
}

func validatorExitCmd(base *baseFlags) *cobra.Command {
	f := &txFlags{validatorFlags: validatorFlags{baseFlags: base}}
	cmd := &cobra.Command{
		Use:   "exit",
		Short: "Leave the committee (PoaElection.requestExit), or withdraw an application not yet admitted (withdrawApplication)",
		Long: `The voluntary exit: an Active validator requests its exit; the Foundation multisig confirms it (ModuleAction ConfirmExit), and the
validator leaves at a later boundary. Keep the nodes running until status shows Exited. An application that is not admitted yet is
withdrawn instead. Other states cannot be left by the owner: an Admitted, Joining or Parked validator leaves through the Foundation
(ModuleAction Remove).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return ownerAction(cmd, f, func(id uint64, state uint8) (string, string, error) {
				switch state {
				case vrclient.PoaActive:
					return vrclient.MethodRequestExit, fmt.Sprintf("request the exit of identity %d", id), nil
				case vrclient.PoaApplied:
					return vrclient.MethodWithdrawApplication, fmt.Sprintf("withdraw the application of identity %d", id), nil
				case vrclient.PoaExitRequested:
					return "", "", fmt.Errorf("%w: the exit is already requested; the Foundation confirms it (ModuleAction ConfirmExit)", ErrValidator)
				case vrclient.PoaRemoving, vrclient.PoaLeaving:
					return "", "", fmt.Errorf("%w: identity %d is already leaving (%s): it leaves at a boundary; keep the nodes running until it is Exited",
						ErrValidator, id, vrclient.PoaState(state))
				case vrclient.PoaNone, vrclient.PoaExited:
					return "", "", fmt.Errorf("%w: identity %d is %s: nothing to leave", ErrValidator, id, vrclient.PoaState(state))
				}
				return "", "", fmt.Errorf("%w: identity %d is %s: the owner cannot leave from this state; ask the Foundation for ModuleAction Remove",
					ErrValidator, id, vrclient.PoaState(state))
			})
		},
	}
	f.add(cmd)
	return cmd
}

func validatorRejoinCmd(base *baseFlags) *cobra.Command {
	f := &txFlags{validatorFlags: validatorFlags{baseFlags: base}}
	cmd := &cobra.Command{
		Use:   "rejoin",
		Short: "Return a parked joiner to Admitted now (PoaElection.rejoin)",
		Long: `A joiner that was not ready when its output expired is Parked (design 3.7.4): a retry, not a penalty. It returns to Admitted by
itself after PARK_PERIOD; rejoin returns it at once, for the next election. Make sure both nodes are synced first.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return ownerAction(cmd, f, func(id uint64, state uint8) (string, string, error) {
				if state != vrclient.PoaParked {
					return "", "", fmt.Errorf("%w: identity %d is %s; rejoin needs Parked", ErrValidator, id, vrclient.PoaState(state))
				}
				return vrclient.MethodRejoin, fmt.Sprintf("rejoin identity %d", id), nil
			})
		},
	}
	f.add(cmd)
	return cmd
}

// ---- rotate --------------------------------------------------------------------------------------------------------------------------

type rotateFlags struct {
	txFlags
	RootKeys string
	EVMKeys  string
	Payee    string
	// the new EVM key held by a signing authority (instead of --new-evm-keys)
	EVMAuthoritySocket, EVMAuthorityCredential, EVMNodeInfo string
}

// viaAuthority notes that the EVM proof came from a signing authority.
func viaAuthority(k *validatorKeys) string {
	if k.EVMAuth != nil {
		return " (held by the signing authority)"
	}
	return ""
}

func validatorRotateCmd(base *baseFlags) *cobra.Command {
	f := &rotateFlags{txFlags: txFlags{validatorFlags: validatorFlags{baseFlags: base}}}
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Stage new node keys or a new payee for the identity (VR.proposeBinding), effective at the next boundary",
		Long: `Owner key rotation without multisig approval (design 3.1, 14): VR stages the new binding, and the next output that captures it
installs it at its boundary. Each new key signs a proof of possession. A new proposal replaces a staged one. Keys are tombstoned for
good: a key another identity or role ever used is refused. Pass the new key files (made with root-node init / shard-node init in a
new directory) and/or a new payee; what is not passed stays. Run the nodes with the new keys once status shows the binding installed.`,
		RunE: func(cmd *cobra.Command, _ []string) error { return validatorRotate(cmd, f) },
	}
	f.txFlags.add(cmd)
	cmd.Flags().StringVar(&f.RootKeys, "new-root-keys", "", "the root node's new key file")
	cmd.Flags().StringVar(&f.EVMKeys, "new-evm-keys", "", "the EVM shard node's new key file")
	cmd.Flags().StringVar(&f.EVMAuthoritySocket, "new-evm-authority-socket", "", "the new EVM key is held by a signing authority: its operator socket, relative to the validator home (instead of --new-evm-keys; needs --new-evm-authority-credential and --new-evm-node-info)")
	cmd.Flags().StringVar(&f.EVMAuthorityCredential, "new-evm-authority-credential", "", "the operator credential of the new EVM key's authority")
	cmd.Flags().StringVar(&f.EVMNodeInfo, "new-evm-node-info", "", "the node info of the new EVM key's authority (`signing-authority node-info`)")
	cmd.Flags().StringVar(&f.Payee, "new-payee", "", "the new payee address")
	return cmd
}

func validatorRotate(cmd *cobra.Command, f *rotateFlags) error {
	newAuth := f.EVMAuthoritySocket != "" || f.EVMAuthorityCredential != "" || f.EVMNodeInfo != ""
	if f.RootKeys == "" && f.EVMKeys == "" && f.Payee == "" && !newAuth {
		return fmt.Errorf("%w: pass --new-root-keys, --new-evm-keys (or --new-evm-authority-*) and/or --new-payee", ErrValidator)
	}
	if newAuth && f.EVMKeys != "" {
		return fmt.Errorf("%w: --new-evm-keys and --new-evm-authority-* are two holders of the new EVM key: give one", ErrValidator)
	}
	ctx := cmd.Context()
	w := cmd.OutOrStdout()
	v, keys, ch, s, err := openTx(cmd, &f.txFlags)
	if err != nil {
		return err
	}
	defer ch.close()
	id, have, err := findID(ctx, v, ch, s.From())
	if err != nil {
		return err
	}
	if !have {
		return fmt.Errorf("%w: the operator account owns no VR identity (run `ubft validator apply`)", ErrValidator)
	}
	idn, err := ch.vr.Identity(ctx, id)
	if err != nil {
		return err
	}
	next := *keys
	if f.RootKeys != "" {
		if next.Root, err = readKeyConf(f.RootKeys); err != nil {
			return fmt.Errorf("%w: new root keys: %w", ErrValidator, err)
		}
	}
	if f.EVMKeys != "" {
		if next.EVM, err = readKeyConf(f.EVMKeys); err != nil {
			return fmt.Errorf("%w: new EVM keys: %w", ErrValidator, err)
		}
		next.EVMAuth = nil
	}
	if newAuth {
		if next.EVMAuth, err = loadEVMAuthority(evmAuthorityConfig{Socket: v.abs(f.EVMAuthoritySocket), Credential: v.abs(f.EVMAuthorityCredential), NodeInfo: v.abs(f.EVMNodeInfo)}); err != nil {
			return err
		}
		next.EVM = nil
	}
	if err := next.distinct(); err != nil {
		return err
	}
	nv := *v
	if f.Payee != "" {
		nv.cfg.Payee = f.Payee
	}
	r, root, evm, err := registration(&nv, &next, idn.BindingNonce)
	if err != nil {
		return err
	}
	if vrclient.BindingMatches(idn.Current, r) {
		return fmt.Errorf("%w: the proposed binding is identity %d's current one", ErrValidator, id)
	}
	signed, err := vrclient.SignWith(ctx, ch.domain(), s.From(), true, id, r, root, evm)
	if err != nil {
		return err
	}
	data, err := vrclient.ProposeBindingCalldata(id, signed)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "identity %d, generation %d; binding nonce %d; digest %x\n", id, idn.Generation, idn.BindingNonce, signed.Digest)
	if idn.StagedRef != ([32]byte{}) {
		fmt.Fprintf(w, "note: a staged binding %x is replaced\n", idn.StagedRef)
	}
	if err := runSteps(ctx, w, s, f.DryRun, []step{{what: fmt.Sprintf("stage a new binding for identity %d", id),
		tx: vrclient.Tx{To: ch.vr.Registry, Data: data}}}, nil); err != nil {
		return err
	}
	if !f.DryRun {
		fmt.Fprintln(w, "staged: it is installed at the boundary of the next output that captures it (status shows the staged binding until then);"+
			" then switch the nodes to the new keys and update validator.json")
	}
	return nil
}

// operatorAddress is the operator account's address.
func operatorAddress(k *validatorKeys) common.Address {
	return ethcrypto.PubkeyToAddress(k.Operator.PublicKey)
}
