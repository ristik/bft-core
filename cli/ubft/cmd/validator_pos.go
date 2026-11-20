package cmd

// The PoS prototype's validator lifecycle (VT-04, design 3.5.6): `validator apply` dispatches on VR's active module. On the PoS
// adapter it is the deposit: VR.register, custody.register, custody.bond and ElectionPolicy.admitDelegation (the Ethereum-familiar
// "deposit" then "activation" at the election and the boundary). `exit` is custody.requestRetirement, and `claim` matures the retired
// generation's lots and pulls the credit. The generation's custody is the active module's liability holder.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-core/vrclient"
)

func (ch *validatorChain) isPoS() bool { return ch.module.Meta.ModuleTag == vrclient.ModuleTagPoS }

// posAddrs are the generation's custody and election.
func (ch *validatorChain) posAddrs(ctx context.Context) (custody, election common.Address, err error) {
	if !ch.isPoS() {
		return custody, election, fmt.Errorf("%w: VR's active module %s is not the PoS adapter", ErrValidator, ch.module.Module.Hex())
	}
	return ch.vr.PosContracts(ctx, ch.module)
}

// posFlags are the PoS-only flags of apply.
type posFlags struct {
	Bond       string
	Withdrawal string
}

func (p *posFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&p.Bond, "bond", "", "PoS: the stake to bond in base units (decimal; default: one bond unit of the generation)")
	cmd.Flags().StringVar(&p.Withdrawal, "withdrawal", "", "PoS: the address that receives the matured principal (default: the operator account)")
}

func validatorApplyPoS(cmd *cobra.Command, f *txFlags, pf *posFlags) error {
	ctx := cmd.Context()
	w := cmd.OutOrStdout()
	v, keys, ch, s, err := openTx(cmd, f)
	if err != nil {
		return err
	}
	defer ch.close()
	custody, election, err := ch.posAddrs(ctx)
	if err != nil {
		return err
	}
	if keys.EVMAuth != nil {
		return fmt.Errorf("%w: the P85 possession proof of admitDelegation is signed by the EVM key, which a signing authority holds: authority signing of P85 possession proofs is not available yet (use SIGNING=local)", ErrValidator)
	}
	owner := s.From()
	withdrawal := owner
	if pf.Withdrawal != "" {
		if !common.IsHexAddress(pf.Withdrawal) {
			return fmt.Errorf("%w: --withdrawal is not an address", ErrValidator)
		}
		withdrawal = common.HexToAddress(pf.Withdrawal)
	}
	var unit *big.Int
	if err := ch.vr.CallPos(ctx, custody, vrclient.CustodyABI, "bondUnit", &unit); err != nil {
		return err
	}
	bond := new(big.Int).Set(unit)
	if pf.Bond != "" {
		var ok bool
		if bond, ok = new(big.Int).SetString(pf.Bond, 10); !ok || bond.Sign() <= 0 {
			return fmt.Errorf("%w: --bond must be a positive decimal", ErrValidator)
		}
	}
	root, evm, payee, err := posKeys(v, keys)
	if err != nil {
		return err
	}
	id, have, err := findID(ctx, v, ch, owner)
	if err != nil {
		return err
	}
	var network [32]byte
	if err := ch.vr.CallPos(ctx, custody, vrclient.CustodyABI, "network", &network); err != nil {
		return err
	}
	chainID := ch.chainID
	registerVR := func() ([]step, error) {
		nonce, err := ch.vr.RegistrationNonce(ctx, owner)
		if err != nil {
			return nil, err
		}
		r, rootN, evmN, err := registration(v, keys, nonce)
		if err != nil {
			return nil, err
		}
		signed, err := vrclient.SignWith(ctx, ch.domain(), owner, false, 0, r, rootN, evmN)
		if err != nil {
			return nil, err
		}
		data, err := vrclient.RegisterCalldata(signed)
		if err != nil {
			return nil, err
		}
		return []step{{what: "register the validator's keys and payee in VR", tx: vrclient.Tx{To: ch.vr.Registry, Data: data}}}, nil
	}
	custodyRegister := func() ([]step, error) {
		var nonce uint64
		if err := ch.vr.CallPos(ctx, custody, vrclient.CustodyABI, "registerNonce", &nonce, owner); err != nil {
			return nil, err
		}
		d, err := vrclient.CustodyRegisterDigest(network, chainID, custody, owner, withdrawal, root.Public(), nonce)
		if err != nil {
			return nil, err
		}
		pop, err := vrclient.SignDigest(root.Key, d)
		if err != nil {
			return nil, err
		}
		data, err := vrclient.PosCalldata(vrclient.CustodyABI, "register", root.Public(), pop, withdrawal)
		if err != nil {
			return nil, err
		}
		return []step{{what: "register the root key in custody (VR id = custody StakingID)", tx: vrclient.Tx{To: custody, Data: data}}}, nil
	}
	bondStep := func(id uint64) ([]step, error) {
		data, err := vrclient.PosCalldata(vrclient.CustodyABI, "bond", id)
		if err != nil {
			return nil, err
		}
		return []step{{what: fmt.Sprintf("bond %s base units for identity %d", bond, id), tx: vrclient.Tx{To: custody, Data: data, Value: bond}}}, nil
	}
	admitStep := func(id uint64) ([]step, error) {
		var pos struct {
			Owner               common.Address
			Withdrawal          common.Address
			RootKeyHash         [32]byte
			StagedRootKeyHash   [32]byte
			Generation          uint64
			RoleNonce           uint64
			OpenLots            uint32
			LotCount            uint32
			RetirementRequested bool
		}
		if err := ch.vr.CallPos(ctx, custody, vrclient.CustodyABI, "positions", &pos, id); err != nil {
			return nil, err
		}
		var d struct {
			Binding     vrclient.Delegation
			BindingHash [32]byte
			NextNonce   uint64
		}
		if err := ch.vr.CallPos(ctx, election, vrclient.PosElectionABI, "delegation", &d, id, pos.Generation); err != nil {
			return nil, err
		}
		req := vrclient.DelegationRequest{Id: id, Generation: pos.Generation, RoleNonce: pos.RoleNonce, DelegationNonce: d.NextNonce, Expiry: math.MaxUint64,
			Binding: vrclient.Delegation{RootNodeID: vrclient.NodeIDWord(root.NodeID), RootKey: root.Public(), EvmNodeID: vrclient.NodeIDWord(evm.NodeID),
				EvmKey: evm.Public(), OperatorPayee: payee}}
		var digest [32]byte
		if err := ch.vr.CallPos(ctx, election, vrclient.PosElectionABI, "delegationDigest", &digest, req); err != nil {
			return nil, err
		}
		ownerSig, err1 := vrclient.SignDigest(keys.Operator, digest)
		evmSig, err2 := vrclient.SignDigest(evm.Key, digest)
		if err := errors.Join(err1, err2); err != nil {
			return nil, err
		}
		data, err := vrclient.PosCalldata(vrclient.PosElectionABI, "admitDelegation", req, ownerSig, evmSig)
		if err != nil {
			return nil, err
		}
		return []step{{what: fmt.Sprintf("admit identity %d's delegation (the node words, keys and payee the election elects)", id), tx: vrclient.Tx{To: election, Data: data}}}, nil
	}

	var steps []step
	switch {
	case have:
		// already registered in VR: continue from custody (the id must be free there, or already ours)
		var pos struct {
			Owner               common.Address
			Withdrawal          common.Address
			RootKeyHash         [32]byte
			StagedRootKeyHash   [32]byte
			Generation          uint64
			RoleNonce           uint64
			OpenLots            uint32
			LotCount            uint32
			RetirementRequested bool
		}
		if err := ch.vr.CallPos(ctx, custody, vrclient.CustodyABI, "positions", &pos, id); err != nil {
			return err
		}
		fmt.Fprintf(w, "identity %d is registered in VR\n", id)
		switch {
		case pos.Owner == (common.Address{}):
			if steps, err = custodyRegister(); err != nil {
				return err
			}
		case pos.Owner == owner && pos.OpenLots == 0:
			if steps, err = bondStep(id); err != nil {
				return err
			}
		case pos.Owner == owner:
			if steps, err = admitStep(id); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: custody's identity %d is owned by %s, not the operator", ErrValidator, id, pos.Owner.Hex())
		}
	default:
		if steps, err = registerVR(); err != nil {
			return err
		}
	}
	// the chain of steps: each receipt names the next (VR register -> custody register -> bond -> admit); stage is the step just done
	stage := 0
	if have {
		first := steps[0]
		switch {
		case strings.Contains(first.what, "register the root key"):
			stage = 1
		case strings.Contains(first.what, "bond"):
			stage = 2
		default:
			stage = 3
		}
	}
	after := func(i int, r *vrclient.Receipt) ([]step, error) {
		switch {
		case stage == 0: // VR.register done
			stage = 1
			newID, ok := vrclient.RegisteredID(r, ch.vr.Registry)
			if !ok {
				return nil, fmt.Errorf("%w: the register receipt has no Registered log", ErrValidator)
			}
			id = newID
			v.cfg.ID = id
			if err := v.save(); err != nil {
				return nil, err
			}
			fmt.Fprintf(w, "  registered identity %d in VR (saved to %s)\n", id, v.path)
			return custodyRegister()
		case stage == 1: // custody.register done
			stage = 2
			cid, ok := vrclient.CustodyRegisteredID(r, custody)
			if !ok || cid != id {
				return nil, fmt.Errorf("%w: custody registered identity %d, VR's is %d: the two registries' ids are out of step (another account registered in between); stop and ask the Foundation", ErrValidator, cid, id)
			}
			return bondStep(id)
		case stage == 2:
			stage = 3
			return admitStep(id)
		}
		return nil, nil
	}
	if err := runSteps(ctx, w, s, f.DryRun, steps, after); err != nil {
		return err
	}
	if !f.DryRun {
		fmt.Fprintf(w, "applied: identity %d is registered, bonded and its delegation admitted; it is elected at the next election and joins at the boundary.\n"+
			"Follow it with `ubft validator status`.\n", id)
	}
	return nil
}

// posKeys are the operator's node keys and payee.
func posKeys(v *loadedValidator, keys *validatorKeys) (root, evm vrclient.NodeKeys, payee common.Address, err error) {
	var e1, e2, e3 error
	root, e1 = nodeKeys(keys.Root)
	evm, e2 = nodeKeys(keys.EVM)
	payee, e3 = v.payee()
	return root, evm, payee, errors.Join(e1, e2, e3)
}

// validatorExitPoS is the PoS voluntary exit: custody.requestRetirement(id). The identity is excluded at the next election, the
// HolderRetirement follows its closure, then `validator claim`.
func validatorExitPoS(cmd *cobra.Command, f *txFlags) error {
	ctx := cmd.Context()
	w := cmd.OutOrStdout()
	v, _, ch, s, err := openTx(cmd, f)
	if err != nil {
		return err
	}
	defer ch.close()
	custody, _, err := ch.posAddrs(ctx)
	if err != nil {
		return err
	}
	id, have, err := findID(ctx, v, ch, s.From())
	if err != nil {
		return err
	}
	if !have {
		return fmt.Errorf("%w: the operator account %s owns no VR identity", ErrValidator, s.From().Hex())
	}
	data, err := vrclient.PosCalldata(vrclient.CustodyABI, "requestRetirement", id)
	if err != nil {
		return err
	}
	if err := runSteps(ctx, w, s, f.DryRun, []step{{what: fmt.Sprintf("request the retirement of identity %d (it is excluded at the next election)", id),
		tx: vrclient.Tx{To: custody, Data: data}}}, nil); err != nil {
		return err
	}
	if !f.DryRun {
		fmt.Fprintf(w, "retirement requested: keep the nodes running until the closure; then `ubft validator claim`.\n")
	}
	return nil
}

func validatorClaimCmd(base *baseFlags) *cobra.Command {
	f := &txFlags{validatorFlags: validatorFlags{baseFlags: base}}
	cmd := &cobra.Command{
		Use:   "claim",
		Short: "PoS: mature the retired generation's lots and withdraw the credit (custody.mature, custody.claim)",
		Long: `After the identity's retirement was requested, excluded by an election, closed and authorized by a HolderRetirement record,
custody releases the principal in two steps: mature the lots (the protection gates must have passed), then claim the credit. The credit
goes to the address that received it (the withdrawal address); this command claims it for the operator account.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			w := cmd.OutOrStdout()
			v, _, ch, s, err := openTx(cmd, f)
			if err != nil {
				return err
			}
			defer ch.close()
			custody, _, err := ch.posAddrs(ctx)
			if err != nil {
				return err
			}
			id, have, err := findID(ctx, v, ch, s.From())
			if err != nil {
				return err
			}
			if !have {
				return fmt.Errorf("%w: the operator account owns no VR identity", ErrValidator)
			}
			var generation struct {
				Owner               common.Address
				Withdrawal          common.Address
				RootKeyHash         [32]byte
				StagedRootKeyHash   [32]byte
				Generation          uint64
				RoleNonce           uint64
				OpenLots            uint32
				LotCount            uint32
				RetirementRequested bool
			}
			if err := ch.vr.CallPos(ctx, custody, vrclient.CustodyABI, "positions", &generation, id); err != nil {
				return err
			}
			var lots []*big.Int
			if err := ch.vr.CallPos(ctx, custody, vrclient.CustodyABI, "generationLots", &lots, id, generation.Generation); err != nil {
				return err
			}
			var steps []step
			if generation.OpenLots != 0 && len(lots) > 0 {
				data, err := vrclient.PosCalldata(vrclient.CustodyABI, "mature", lots)
				if err != nil {
					return err
				}
				steps = append(steps, step{what: fmt.Sprintf("mature identity %d's %d lot(s)", id, len(lots)), tx: vrclient.Tx{To: custody, Data: data}})
			}
			after := func(i int, r *vrclient.Receipt) ([]step, error) { return claimStep(ctx, ch, custody, s) }
			if len(steps) == 0 {
				cs, err := claimStep(ctx, ch, custody, s)
				if err != nil {
					return err
				}
				steps, after = cs, nil
			}
			return runSteps(ctx, w, s, f.DryRun, steps, after)
		},
	}
	f.add(cmd)
	return cmd
}

func claimStep(ctx context.Context, ch *validatorChain, custody common.Address, s vrclient.Sender) ([]step, error) {
	var credit *big.Int
	if err := ch.vr.CallPos(ctx, custody, vrclient.CustodyABI, "credit", &credit, s.From()); err != nil {
		return nil, err
	}
	if credit.Sign() == 0 {
		return nil, fmt.Errorf("%w: the operator account has no credit to claim", ErrValidator)
	}
	data, err := vrclient.PosCalldata(vrclient.CustodyABI, "claim", credit, s.From())
	if err != nil {
		return nil, err
	}
	return []step{{what: fmt.Sprintf("claim %s base units to %s", credit, s.From().Hex()), tx: vrclient.Tx{To: custody, Data: data}}}, nil
}

var _ = ethcrypto.Keccak256
