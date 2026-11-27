package cmd

// The PoS prototype's validator lifecycle (VT-04, design 3.5.6): `validator apply` dispatches on VR's active module. On the PoS
// adapter it is the deposit: VR.register, custody.register, custody.bond and ElectionPolicy.admitDelegation (the Ethereum-familiar
// "deposit" then "activation" at the election and the boundary). `exit` is custody.requestRetirement, and `claim` matures the retired
// generation's lots and pulls the credit. The generation's custody is the active module's liability holder.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/signingauthority"
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
	evmNode, evmPub := keys.evmNodeAndKey(evm)
	id, have, err := findID(ctx, v, ch, owner)
	if err != nil {
		return err
	}
	if have && !f.DryRun {
		// a resumed apply (the VR registration committed in an earlier run) saves the verified id too, so a caller can always read it back
		if err := v.rememberID(id); err != nil {
			return err
		}
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
		if err := ch.vr.CallPosMulti(ctx, custody, vrclient.CustodyABI, "positions", &pos, id); err != nil {
			return nil, err
		}
		var d struct {
			Binding     vrclient.Delegation
			BindingHash [32]byte
			NextNonce   uint64
		}
		if err := ch.vr.CallPosMulti(ctx, election, vrclient.PosElectionABI, "delegation", &d, id, pos.Generation); err != nil {
			return nil, err
		}
		// #1286: on a bonded identity the delegation must be VR's current or staged binding; other words are rotate's or recover's
		if pos.OpenLots != 0 {
			idn, err := ch.vr.Identity(ctx, id)
			if err != nil {
				return nil, err
			}
			want := vrclient.Registration{RootNodeID: root.NodeID, RootKey: root.Public(), EvmNodeID: evmNode, EvmKey: evmPub, Payee: payee}
			if err := refuseBondedMismatch(idn, id, want); err != nil {
				return nil, err
			}
		}
		req := vrclient.DelegationRequest{Id: id, Generation: pos.Generation, RoleNonce: pos.RoleNonce, DelegationNonce: d.NextNonce, Expiry: math.MaxUint64,
			Binding: vrclient.Delegation{RootNodeID: vrclient.NodeIDWord(root.NodeID), RootKey: root.Public(), EvmNodeID: vrclient.NodeIDWord(evmNode),
				EvmKey: evmPub, OperatorPayee: payee}}
		if sameDelegation(d.Binding, req.Binding) {
			// a retry after the final receipt was lost: the election already stages this binding; another admission would only burn a nonce
			fmt.Fprintf(w, "identity %d's delegation is already staged as configured\n", id)
			return nil, nil
		}
		var digest [32]byte
		if err := ch.vr.CallPos(ctx, election, vrclient.PosElectionABI, "delegationDigest", &digest, req); err != nil {
			return nil, err
		}
		ownerSig, err := vrclient.SignDigest(keys.Operator, digest)
		if err != nil {
			return nil, err
		}
		var evmSig []byte
		if keys.EVMAuth != nil {
			// the EVM key is the signing authority's: it recomputes the digest from the typed payload and its own pin; the digest the
			// election returned must be the one it signs, or the authority and the contracts disagree about the domain
			var chainWord [32]byte
			chainID.FillBytes(chainWord[:])
			dreq := delegationRequestOf(req)
			if want := evmassign.DelegationDigest(network, chainWord, election, dreq); want != digest {
				return nil, fmt.Errorf("%w: the election's delegation digest %x is not the one the authority signs (%x): the deployment's network word or chain differs from custody's", ErrValidator, digest, want)
			}
			evmSig, err = keys.EVMAuth.DelegationPossession(ctx, signingauthority.DelegationPossessionRequest{Network: network, Chain: chainWord, Election: election, Request: dreq})
		} else {
			evmSig, err = vrclient.SignDigest(evm.Key, digest)
		}
		if err != nil {
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
		if err := ch.vr.CallPosMulti(ctx, custody, vrclient.CustodyABI, "positions", &pos, id); err != nil {
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
	if len(steps) == 0 {
		fmt.Fprintf(w, "identity %d is already registered, bonded and its delegation staged: nothing to do\n", id)
		return nil
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
	if keys.EVMAuth == nil { // a signing authority holds the EVM key: there is no key file to load
		evm, e2 = nodeKeys(keys.EVM)
	}
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
			if err := ch.vr.CallPosMulti(ctx, custody, vrclient.CustodyABI, "positions", &generation, id); err != nil {
				return err
			}
			var lots []*big.Int
			if err := ch.vr.CallPos(ctx, custody, vrclient.CustodyABI, "generationLots", &lots, id, generation.Generation); err != nil {
				return err
			}
			var steps []step
			maturing := generation.OpenLots != 0 && len(lots) > 0
			anchoredInDryRun := false
			if maturing {
				// #1297/#1298: custody refuses mature while a closed term of the lots has no report anchors (TermAnchorPending). anchorTerm
				// is permissionless (no keeper or relay): the exit sends it first for each closed term its own lots back, with the words of the
				// term's Closure record. Each is previewed: one that is not anchorable yet (its successor epoch is not installed) or that
				// another party anchors meanwhile is skipped, not an error.
				if anchoredInDryRun, err = anchorTerms(ctx, w, ch, s, custody, lots, f.DryRun); err != nil {
					return err
				}
				data, err := vrclient.PosCalldata(vrclient.CustodyABI, "mature", lots)
				if err != nil {
					return err
				}
				ms := step{what: fmt.Sprintf("mature identity %d's %d lot(s)", id, len(lots)), tx: vrclient.Tx{To: custody, Data: data}}
				if anchoredInDryRun {
					ms.note = "it can be simulated once the term anchors are included"
				}
				steps = append(steps, ms)
			}
			if !maturing {
				steps, err = claimStep(ctx, ch, custody, s)
				if err != nil {
					return err
				}
			}
			after := func(i int, r *vrclient.Receipt) ([]step, error) {
				if maturing && i == 0 {
					return claimStep(ctx, ch, custody, s)
				}
				amount, ok := vrclient.CustodyClaimedAmount(r, custody, s.From(), s.From())
				if !ok {
					return nil, fmt.Errorf("%w: claim transaction confirmed, but its receipt has no unique valid CreditClaimed event", ErrValidator)
				}
				fmt.Fprintf(w, "claimed %s base units to %s\n", amount, s.From().Hex())
				return nil, nil
			}
			return runSteps(ctx, w, s, f.DryRun, steps, after)
		},
	}
	f.add(cmd)
	return cmd
}

// anchorTerms previews and (unless dry) sends a permissionless anchorTerm for every closed, unanchored term the lots back. A term whose preview
// reverts (not anchorable yet, or anchored meanwhile) is reported and skipped; a send that fails is accepted when the term turns out anchored
// (a concurrent anchor). planned reports, for a dry run, whether any anchor was planned (mature cannot be simulated before it lands).
func anchorTerms(ctx context.Context, w io.Writer, ch *validatorChain, s vrclient.Sender, custody common.Address, lots []*big.Int, dry bool) (planned bool, err error) {
	terms, _, err := ch.vr.PendingTerms(ctx, custody, lots)
	if err != nil {
		return false, err
	}
	for _, t := range terms {
		data, err := vrclient.PosCalldata(vrclient.CustodyTermsABI, "anchorTerm", t.AssignmentID, t.HRecordID, t.TerminalRoot)
		if err != nil {
			return false, err
		}
		what := fmt.Sprintf("anchor closed term %s (permissionless; the words of its Closure record)", hexutil.Encode(t.AssignmentID[:]))
		p, err := s.Plan(ctx, vrclient.Tx{To: custody, Data: data})
		if err != nil {
			return false, fmt.Errorf("%w: %s: %w", ErrValidator, what, err)
		}
		if p.SimErr != nil {
			fmt.Fprintf(w, "skip: %s: not anchorable now (%v); it may be anchored already, or its successor epoch is not installed yet: claim again later\n", what, p.SimErr)
			continue
		}
		fmt.Fprintf(w, "[anchor] %s\n", what)
		fmt.Fprint(w, p.String())
		if dry {
			planned = true
			continue
		}
		h, r, err := s.Send(ctx, p)
		if err != nil {
			if done, cerr := ch.vr.TermAnchored(ctx, custody, t.AssignmentID); cerr == nil && done {
				fmt.Fprintf(w, "  anchored meanwhile by another party\n")
				continue
			}
			return false, fmt.Errorf("%w: %s: %w", ErrValidator, what, err)
		}
		fmt.Fprintf(w, "  sent: %s, included in block %d (gas used %d)\n", h.Hex(), r.BlockNumber, r.GasUsed)
	}
	return planned, nil
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

// validatorPosPublishCmd is the development relayer of the PoS lane: the result a hook reserved becomes Ready once every frozen member's
// possession proof is in and `finalizeCandidate` has published it; then anyone publishes it in VR. Proofs are permissionless to relay, so a
// lane that holds every member's EVM key (SIGNING=local) submits them all here. Production members submit their own.
func validatorPosPublishCmd(base *baseFlags) *cobra.Command {
	f := &txFlags{validatorFlags: validatorFlags{baseFlags: base}}
	var keyArgs, authArgs []string
	var ownProof, participate bool
	var expectedResult string
	var memberID uint64
	cmd := &cobra.Command{
		Use:   "pos-publish",
		Short: "Submit P85 possession proofs or finalize and publish an election result",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			w := cmd.OutOrStdout()
			v, keys, ch, s, err := openTx(cmd, f)
			if err != nil {
				return err
			}
			defer ch.close()
			_, election, err := ch.posAddrs(ctx)
			if err != nil {
				return err
			}
			rid, err := ch.vr.OpenResult(ctx, election)
			if err != nil {
				return err
			}
			if rid == ([32]byte{}) {
				return fmt.Errorf("%w: the election has no open result (no election has been reserved)", ErrValidator)
			}
			if participate && expectedResult == "" {
				return fmt.Errorf("%w: --participate requires a certified --result", ErrValidator)
			}
			if expectedResult != "" && !strings.EqualFold(common.Hash(rid).Hex(), expectedResult) {
				return fmt.Errorf("%w: the open result differs from expected %s", ErrValidator, expectedResult)
			}
			members, err := ch.vr.FrozenMembers(ctx, election, rid)
			if err != nil {
				return err
			}
			if ownProof {
				return publishOwnPosProof(ctx, w, v, keys, ch, s, election, rid, members, f.DryRun)
			}
			if participate {
				if memberID == 0 {
					memberID, _, err = findID(ctx, v, ch, s.From())
					if err != nil {
						return err
					}
				}
				gate, err := readPosParticipation(ctx, ch, memberID)
				if err != nil {
					return err
				}
				if gate.Reason != "" {
					fmt.Fprintf(w, "no election transactions: %s\n", gate.Reason)
					return nil
				}
				for _, member := range members {
					if member.Id == memberID {
						if err := submitMemberProof(ctx, w, keys, ch, s, election, rid, member, f.DryRun); err != nil {
							return err
						}
						break
					}
				}
				return publishReadyResult(ctx, w, posPublishRun{Election: election, Registry: ch.vr.Registry,
					Rid: rid, Members: members, Chain: posPublishReader{ch, election}, Sender: s, DryRun: f.DryRun})
			}
			return runPosPublish(ctx, w, posPublishRun{Election: election, Registry: ch.vr.Registry, Rid: rid, Members: members, Chain: posPublishReader{ch, election},
				Sender: s, DryRun: f.DryRun, Pops: func(ctx context.Context) ([]vrclient.PoPInput, error) {
					keys := map[uint64]*KeyConf{}
					for _, a := range keyArgs {
						var id uint64
						var path string
						if i := strings.Index(a, "="); i > 0 {
							if _, err := fmt.Sscanf(a[:i], "%d", &id); err != nil {
								return nil, fmt.Errorf("%w: --evm-keys %q is not id=path", ErrValidator, a)
							}
							path = a[i+1:]
						}
						kc, err := readKeyConf(path)
						if err != nil {
							return nil, err
						}
						keys[id] = kc
					}
					auths := map[uint64]*evmAuthority{}
					for _, a := range authArgs {
						id, ea, err := parseEVMAuthorityArg(a)
						if err != nil {
							return nil, err
						}
						auths[id] = ea
					}
					var rec vrclient.ResultRecord
					if len(auths) > 0 {
						var err error
						if rec, err = ch.vr.Result(ctx, election, rid); err != nil {
							return nil, err
						}
					}
					var pops []vrclient.PoPInput
					for _, m := range members {
						if ea := auths[m.Id]; ea != nil {
							if keys[m.Id] != nil {
								return nil, fmt.Errorf("%w: member %d has both --evm-keys and --evm-authority", ErrValidator, m.Id)
							}
							proof, err := authorityPosProof(ctx, ch, election, rid, rec, m, ea)
							if err != nil {
								return nil, err
							}
							pops = append(pops, proof)
							continue
						}
						kc := keys[m.Id]
						if kc == nil {
							return nil, fmt.Errorf("%w: no EVM key file for member %d (--evm-keys %d=path or --evm-authority %d=socket,credential,nodeInfo)", ErrValidator, m.Id, m.Id, m.Id)
						}
						nk, err := nodeKeys(kc)
						if err != nil {
							return nil, err
						}
						pub := nk.Public()
						d, err := ch.vr.PopDigest(ctx, election, rid, m.Id, [32]byte(ethcrypto.Keccak256(pub)))
						if err != nil {
							return nil, err
						}
						sig, err := vrclient.SignDigest(nk.Key, d)
						if err != nil {
							return nil, err
						}
						pops = append(pops, vrclient.PoPInput{Id: m.Id, EvmKey: pub, Signature: sig})
					}
					return pops, nil
				}})
		},
	}
	f.add(cmd)
	cmd.Flags().BoolVar(&ownProof, "own-proof", false, "submit only the configured validator's authority-held proof; leave finalization to a relayer")
	cmd.Flags().BoolVar(&participate, "participate", false, "submit only this node's own proof and permissionlessly publish when every proof is recorded")
	cmd.Flags().Uint64Var(&memberID, "proof-member", 0, "the local authority's member ID for --participate, when the gas payer is separate")
	cmd.Flags().StringVar(&expectedResult, "result", "", "restrict this call to the exact open result id")
	cmd.Flags().StringArrayVar(&authArgs, "evm-authority", nil, "id=socket,credential,nodeInfo of the signing authority that holds a member's EVM key (repeat per member; instead of --evm-keys)")
	cmd.Flags().StringArrayVar(&keyArgs, "evm-keys", nil, "id=path of a member's EVM shard node key file (repeat per member)")
	cmd.MarkFlagsMutuallyExclusive("own-proof", "evm-authority")
	cmd.MarkFlagsMutuallyExclusive("own-proof", "evm-keys")
	cmd.MarkFlagsMutuallyExclusive("participate", "own-proof")
	cmd.MarkFlagsMutuallyExclusive("participate", "evm-authority")
	cmd.MarkFlagsMutuallyExclusive("participate", "evm-keys")
	return cmd
}

// posParticipationState is what the election-participation gate decides from, read at the certified block: custody's position of the
// identity and whether evidence excluded it.
type posParticipationState struct {
	ID       uint64
	Position custodyPosition
	Excluded bool
}

// posParticipation is the gate of `pos-publish --participate` (#1316): Reason is empty when the identity still takes part in the
// elections (its own possession proof when it is a frozen member of the open result, and the permissionless finalization and VR
// publication of a result whose proofs are all in), and names why it sends nothing otherwise.
type posParticipation struct {
	Reason string
}

// planPosParticipation applies the P85 rules to an identity's state:
//   - an identity that requested retirement is excluded at the next election, and a result that froze it cannot be finalized
//     (finalizeCandidate requires every member covered, and custody's coverage refuses a retiring member): its proof is useless and its
//     finalization can only revert; the other members relay every result it is not part of;
//   - an identity excluded by evidence is not covered either;
//   - an identity custody does not know, or with no open lots (never bonded, or matured), is no member of any result.
//
// What a leaving identity keeps is outside the election: its custody steps (`validator claim`: the permissionless anchorTerm, then
// mature and claim), which this gate does not touch.
func planPosParticipation(st posParticipationState) posParticipation {
	switch {
	case st.Position.Owner == (common.Address{}):
		return posParticipation{Reason: fmt.Sprintf("custody knows no identity %d", st.ID)}
	case st.Position.RetirementRequested:
		return posParticipation{Reason: fmt.Sprintf("identity %d requested retirement: it leaves at the next election, and the remaining members publish the results", st.ID)}
	case st.Excluded:
		return posParticipation{Reason: fmt.Sprintf("identity %d is excluded by evidence", st.ID)}
	case st.Position.OpenLots == 0:
		return posParticipation{Reason: fmt.Sprintf("identity %d has no open lots (not bonded, or its bond matured)", st.ID)}
	}
	return posParticipation{}
}

// readPosParticipation reads the gate's state at the RPC's certified (finalized) block and applies it.
func readPosParticipation(ctx context.Context, ch *validatorChain, id uint64) (posParticipation, error) {
	if id == 0 {
		return posParticipation{Reason: "the operator account owns no identity"}, nil
	}
	custody, _, err := ch.posAddrs(ctx)
	if err != nil {
		return posParticipation{}, err
	}
	c, _, err := ch.certifiedClient(ctx)
	if err != nil {
		return posParticipation{}, err
	}
	st := posParticipationState{ID: id}
	if err := c.CallPosMulti(ctx, custody, vrclient.CustodyABI, "positions", &st.Position, id); err != nil {
		return posParticipation{}, err
	}
	var evidence common.Address
	if err := c.CallPos(ctx, custody, vrclient.CustodyABI, "evidence", &evidence); err != nil {
		return posParticipation{}, err
	}
	if evidence == (common.Address{}) {
		return posParticipation{}, fmt.Errorf("%w: custody %s names no evidence contract", ErrValidator, custody.Hex())
	}
	if err := c.CallPos(ctx, evidence, vrclient.EvidenceABI, "excluded", &st.Excluded, id); err != nil {
		return posParticipation{}, err
	}
	return planPosParticipation(st), nil
}

func publishOwnPosProof(ctx context.Context, w io.Writer, v *loadedValidator, keys *validatorKeys, ch *validatorChain, sender vrclient.Sender,
	election common.Address, result [32]byte, members []vrclient.FrozenMember, dryRun bool) error {
	id, found, err := findID(ctx, v, ch, sender.From())
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: apply before submitting an assignment proof", ErrValidator)
	}
	for _, member := range members {
		if member.Id != id {
			continue
		}
		return submitMemberProof(ctx, w, keys, ch, sender, election, result, member, dryRun)
	}
	return fmt.Errorf("%w: identity %d is not a frozen member of result %x", ErrValidator, id, result)
}

func submitMemberProof(ctx context.Context, w io.Writer, keys *validatorKeys, ch *validatorChain, sender vrclient.Sender,
	election common.Address, result [32]byte, member vrclient.FrozenMember, dryRun bool) error {
	recorded := func() (bool, error) {
		var accepted [32]byte
		err := ch.vr.CallPos(ctx, election, vrclient.PosPublishABI, "popHash", &accepted, result, member.Id)
		return accepted != ([32]byte{}), err
	}
	if hasProof, err := recorded(); err != nil || hasProof {
		return err
	}
	if keys.EVMAuth == nil {
		return fmt.Errorf("%w: publishing a member proof requires its configured signing authority", ErrValidator)
	}
	record, err := ch.vr.Result(ctx, election, result)
	if err != nil {
		return err
	}
	proof, err := authorityPosProof(ctx, ch, election, result, record, member, keys.EVMAuth)
	if err != nil {
		return err
	}
	data, err := vrclient.PosCalldata(vrclient.PosPublishABI, "submitAssignmentPoPs", result, []vrclient.PoPInput{proof})
	if err != nil {
		return err
	}
	err = runSteps(ctx, w, sender, dryRun, []step{{what: fmt.Sprintf("submit identity %d's possession proof for result %x", member.Id, result),
		tx: vrclient.Tx{To: election, Data: data}}}, nil)
	if err != nil {
		if accepted, checkErr := recorded(); checkErr == nil && accepted {
			return nil
		}
	}
	return err
}

func authorityPosProof(ctx context.Context, ch *validatorChain, election common.Address, result [32]byte,
	record vrclient.ResultRecord, member vrclient.FrozenMember, authority *evmAuthority) (vrclient.PoPInput, error) {
	proof, err := authority.PosPoP(ctx, signingauthority.PosPoPRequest{ResultID: result, AssignmentID: record.AssignmentID, Snapshot: record.SnapshotDigest,
		Attempt: record.Attempt, ID: member.Id, Generation: member.Generation})
	if err != nil {
		return vrclient.PoPInput{}, err
	}
	digest, err := ch.vr.PopDigest(ctx, election, result, member.Id, [32]byte(ethcrypto.Keccak256(proof.EVMKey)))
	if err != nil {
		return vrclient.PoPInput{}, err
	}
	if err := checkRecovers(digest, proof.Signature, proof.EVMKey); err != nil {
		return vrclient.PoPInput{}, fmt.Errorf("%w: member %d: the authority's proof does not verify against the election's popDigest: %w", ErrValidator, member.Id, err)
	}
	return vrclient.PoPInput{Id: member.Id, EvmKey: proof.EVMKey, Signature: proof.Signature}, nil
}

// planPosPublish says which of the relayer's three steps (submit the possession proofs, finalize the candidate, publish in VR) are still to do,
// from what the election and VR already hold, so an interrupted run resumes at the first unfinished step. The election refuses proofs once the
// candidate is published, and VR refuses a second publication, so the finished steps must not be sent again. A VR output past Reserved
// (state 2, or Acknowledged, Recovered, Closed) means the result is published; Invalidated and Rejected are refusals, never success.
func planPosPublish(members int, popCount uint32, candidatePublished bool, out vrclient.OutputView) ([3]bool, error) {
	switch out.State {
	case 0, 1: // None, Reserved: not published in VR yet
		finalize := !candidatePublished
		return [3]bool{finalize && int(popCount) < members, finalize, true}, nil
	case 2: // Published
		return [3]bool{}, nil
	case 5, 6, 7: // Acknowledged, Recovered, Closed: published before, but only if VR holds the publication commitment (a reservation that expired
		// before publication also ends Closed)
		if out.OutputCommit != ([32]byte{}) {
			return [3]bool{}, nil
		}
	}
	// Invalidated (3, a member lost its coverage), Rejected (4), or a closure that never held a publication: VR will not publish this result
	return [3]bool{}, fmt.Errorf("%w: VR's output of this result is %s%s: it cannot be published; wait for the next election", ErrValidator, vrOutputState(out.State), noCommitNote(out))
}

// noCommitNote says why a Closed, Acknowledged or Recovered output is not a publication.
func noCommitNote(out vrclient.OutputView) string {
	if out.State >= 5 && out.OutputCommit == ([32]byte{}) {
		return " without a publication commitment (it was never published)"
	}
	return ""
}

func vrOutputState(s uint8) string {
	names := []string{"None", "Reserved", "Published", "Invalidated", "Rejected", "Acknowledged", "Recovered", "Closed"}
	if int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("state %d", s)
}

// sameDelegation reports whether two delegation bindings are the same node words, keys and payee.
func sameDelegation(a, b vrclient.Delegation) bool {
	return a.RootNodeID == b.RootNodeID && a.EvmNodeID == b.EvmNodeID && a.OperatorPayee == b.OperatorPayee &&
		bytes.Equal(a.RootKey, b.RootKey) && bytes.Equal(a.EvmKey, b.EvmKey)
}

// verifyPosPublishEffect re-reads the election and VR after one of pos-publish's transactions (kind 0 submit proofs, 1 finalize, 2 VR publish) and
// requires its intended effect, naming the state found otherwise.
func verifyPosPublishEffect(ctx context.Context, chain posPublishChain, rid [32]byte, kind, members int) error {
	switch kind {
	case 0:
		p, err := chain.Publication(ctx, rid)
		if err != nil {
			return err
		}
		if int(p.PopCount) != members {
			return fmt.Errorf("%w: after submitting the possession proofs the election stores %d of %d", ErrValidator, p.PopCount, members)
		}
	case 1:
		p, err := chain.Publication(ctx, rid)
		if err != nil {
			return err
		}
		if !p.Published {
			return fmt.Errorf("%w: after finalizeCandidate the candidate is not published in the election (lost coverage: %t)", ErrValidator, p.Lost)
		}
	case 2:
		out, err := chain.Output(ctx, rid)
		if err != nil {
			return err
		}
		if err := requireVRPublished(out); err != nil {
			return err
		}
	}
	return nil
}

// requireVRPublished accepts only a VR output that is Published (or past it); every other state is named in the refusal.
func requireVRPublished(out vrclient.OutputView) error {
	switch out.State {
	case 2:
		return nil
	case 5, 6, 7: // beyond Published only counts when VR holds the publication commitment
		if out.OutputCommit != ([32]byte{}) {
			return nil
		}
	}
	return fmt.Errorf("%w: after VR.publish the result's output is %s%s, not Published (VR.publish returns a status without reverting when it cannot publish)", ErrValidator, vrOutputState(out.State), noCommitNote(out))
}

// posPublishChain is what the relayer reads from the election and VR.
type posPublishChain interface {
	Publication(ctx context.Context, rid [32]byte) (vrclient.PublicationRecord, error)
	Output(ctx context.Context, rid [32]byte) (vrclient.OutputView, error)
}

type posPublishReader struct {
	ch       *validatorChain
	election common.Address
}

func (r posPublishReader) Publication(ctx context.Context, rid [32]byte) (vrclient.PublicationRecord, error) {
	return r.ch.vr.Publication(ctx, r.election, rid)
}

func (r posPublishReader) Output(ctx context.Context, rid [32]byte) (vrclient.OutputView, error) {
	return r.ch.vr.Output(ctx, rid)
}

// posPublishRun is one relayer run: the open result and its frozen members, how to read the chain, the sender, and Pops, which collects the
// members' possession proofs and is called only when they must still be submitted.
type posPublishRun struct {
	Election, Registry common.Address
	Rid                [32]byte
	Members            []vrclient.FrozenMember
	Chain              posPublishChain
	Pops               func(ctx context.Context) ([]vrclient.PoPInput, error)
	Sender             vrclient.Sender
	DryRun             bool
}

func publishReadyResult(ctx context.Context, w io.Writer, r posPublishRun) error {
	view, err := r.Chain.Publication(ctx, r.Rid)
	if err != nil {
		return err
	}
	if len(r.Members) == 0 || int(view.PopCount) != len(r.Members) || view.Lost {
		return nil
	}
	// No peer credentials are accepted. Publication is safe to repeat or race.
	r.Pops = func(context.Context) ([]vrclient.PoPInput, error) {
		return nil, fmt.Errorf("%w: the result no longer has all its frozen proofs", ErrValidator)
	}
	err = runPosPublish(ctx, w, r)
	if err != nil {
		if out, readErr := r.Chain.Output(ctx, r.Rid); readErr == nil && requireVRPublished(out) == nil {
			return nil
		}
	}
	return err
}

// runPosPublish plans from the chain's state, sends the unfinished steps and, after each mined transaction, reads the state again and requires
// its intended effect: a successful receipt is not enough (VR.publish returns a status without reverting when the result was invalidated).
func runPosPublish(ctx context.Context, w io.Writer, r posPublishRun) error {
	pubRec, err := r.Chain.Publication(ctx, r.Rid)
	if err != nil {
		return err
	}
	out, err := r.Chain.Output(ctx, r.Rid)
	if err != nil {
		return err
	}
	plan, err := planPosPublish(len(r.Members), pubRec.PopCount, pubRec.Published, out)
	if err != nil {
		return err
	}
	var pops []vrclient.PoPInput
	if plan[0] { // holders are read only when proofs must still be submitted: a resumed run needs no key file
		if pops, err = r.Pops(ctx); err != nil {
			return err
		}
	}
	sub, err := vrclient.PosCalldata(vrclient.PosPublishABI, "submitAssignmentPoPs", r.Rid, pops)
	if err != nil {
		return err
	}
	fin, err := vrclient.PosCalldata(vrclient.PosPublishABI, "finalizeCandidate", r.Rid)
	if err != nil {
		return err
	}
	pub, err := vrclient.PosCalldata(vrclient.PosPublishABI, "publish", r.Rid)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "result %x with %d members\n", r.Rid, len(r.Members))
	all := []step{
		{what: "submit every frozen member's possession proof", tx: vrclient.Tx{To: r.Election, Data: sub}},
		{what: "finalize the candidate (publish it in P85)", tx: vrclient.Tx{To: r.Election, Data: fin}},
		{what: "publish the result in VR", tx: vrclient.Tx{To: r.Registry, Data: pub}},
	}
	var steps []step
	var kinds []int
	for i, st := range all {
		if plan[i] {
			steps = append(steps, st)
			kinds = append(kinds, i)
		} else {
			fmt.Fprintf(w, "already done: %s\n", st.what)
		}
	}
	if len(steps) == 0 {
		fmt.Fprintln(w, "nothing to do: the result is published in VR")
		return nil
	}
	// runSteps replaces the steps after i with the callback's result: the effect check hands the remaining steps back unchanged
	verify := func(i int, _ *vrclient.Receipt) ([]step, error) {
		if err := verifyPosPublishEffect(ctx, r.Chain, r.Rid, kinds[i], len(r.Members)); err != nil {
			return nil, err
		}
		return append([]step(nil), steps[i+1:]...), nil
	}
	return runSteps(ctx, w, r.Sender, r.DryRun, steps, verify)
}

// evmNodeAndKey is the EVM node id and 33-byte public key: the authority's enrolled identity, or the loaded key file's.
func (k *validatorKeys) evmNodeAndKey(file vrclient.NodeKeys) (string, []byte) {
	if k.EVMAuth != nil {
		return k.EVMAuth.Node(), k.EVMAuth.Public()
	}
	return file.NodeID, file.Public()
}

// delegationRequestOf is the admitDelegation payload in the form the authority and evmassign take.
func delegationRequestOf(r vrclient.DelegationRequest) evmassign.DelegationRequest {
	return evmassign.DelegationRequest{Id: r.Id, Generation: r.Generation, RoleNonce: r.RoleNonce, DelegationNonce: r.DelegationNonce, Expiry: r.Expiry,
		Binding: evmassign.DelegationBinding{RootNodeID: r.Binding.RootNodeID, RootKey: r.Binding.RootKey, EvmNodeID: r.Binding.EvmNodeID,
			EvmKey: r.Binding.EvmKey, OperatorPayee: r.Binding.OperatorPayee}}
}

// parseEVMAuthorityArg reads one --evm-authority value: id=socket,credential,nodeInfo.
func parseEVMAuthorityArg(a string) (uint64, *evmAuthority, error) {
	i := strings.Index(a, "=")
	if i <= 0 {
		return 0, nil, fmt.Errorf("%w: --evm-authority %q is not id=socket,credential,nodeInfo", ErrValidator, a)
	}
	id, perr := strconv.ParseUint(a[:i], 10, 64)
	if perr != nil || id == 0 {
		return 0, nil, fmt.Errorf("%w: --evm-authority %q: the identity is a positive number", ErrValidator, a)
	}
	parts := strings.Split(a[i+1:], ",")
	if len(parts) != 3 {
		return 0, nil, fmt.Errorf("%w: --evm-authority %q is not id=socket,credential,nodeInfo", ErrValidator, a)
	}
	ea, err := loadEVMAuthority(evmAuthorityConfig{Socket: parts[0], Credential: parts[1], NodeInfo: parts[2]})
	return id, ea, err
}

// checkRecovers verifies a contracts-form signature (v 27/28) over digest against the compressed key.
func checkRecovers(digest [32]byte, sig, pub []byte) error {
	if len(sig) != 65 {
		return fmt.Errorf("a %d-byte signature", len(sig))
	}
	rec := bytes.Clone(sig)
	rec[64] -= 27
	got, err := ethcrypto.SigToPub(digest[:], rec)
	if err != nil {
		return err
	}
	if !bytes.Equal(ethcrypto.CompressPubkey(got), pub) {
		return errors.New("the signature recovers to another key")
	}
	return nil
}

// rememberID saves the identity id findID verified (the owner's registered one) into the validator configuration when it is not there yet.
func (v *loadedValidator) rememberID(id uint64) error {
	if v.cfg.ID == id {
		return nil
	}
	v.cfg.ID = id
	return v.save()
}
