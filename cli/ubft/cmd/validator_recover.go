package cmd

// #1286: an in-place EVM-key change of a bonded PoS identity (`validator recover` after an authority loss, and `validator rotate` on the PoS
// adapter). In PoS the generation is custody's frozen bond cycle and the binding words are VR's exact current binding or its nonzero staged
// one (astra's ruling). The change is two transactions, delegation first:
//
//  1. ElectionPolicy.admitDelegation of the new words at custody's current generation, confirmed. It fences the old key: the old delegation
//     no longer equals a VR binding, so no later snapshot selects the identity with the old key (an incumbent keeps its binding until the
//     boundary, and an already-frozen result keeps the binding it captured).
//  2. VR.proposeBinding of the identical words. The next snapshot freezes the new key, its authority proves possession, and the
//     acknowledgement installs the binding at the unchanged custody generation; the bond stays in its lots.
//
// Each step is skipped when its words are already in place (a resumed run compares the exact words after every confirmed transaction). A
// staged binding that an open result froze is never replaced. The root key never changes here: root-key loss takes the exit path.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// authorityLifetimeMarker is the fail-stop marker the validator container writes into an authority volume before the authority process
// first starts (deploy/testnet/validator-container/validator.py): a volume carrying it never runs an authority again.
const authorityLifetimeMarker = "lifetime"

// custodyPosition is StakeCustody.positions(id).
type custodyPosition struct {
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

// posBindingState is what a PoS key change decides from: custody's position and exclusion, the election's delegation at custody's
// generation and its open result, and VR's identity (current and staged bindings).
type posBindingState struct {
	ID              uint64
	Position        custodyPosition
	Excluded        bool
	Delegation      vrclient.Delegation
	DelegationNonce uint64
	Identity        vrclient.IdentityView
	OpenResult      [32]byte
	Frozen          []vrclient.FrozenMember
}

// posKeyChange is the plan: which of the two transactions are still to send.
type posKeyChange struct {
	Admit bool // admitDelegation of the new words at custody's generation
	Stage bool // VR.proposeBinding of the same words
}

// delegationOf is a registration's words as the election's delegation binding.
func delegationOf(r vrclient.Registration) vrclient.Delegation {
	return vrclient.Delegation{RootNodeID: vrclient.NodeIDWord(r.RootNodeID), RootKey: bytes.Clone(r.RootKey), EvmNodeID: vrclient.NodeIDWord(r.EvmNodeID),
		EvmKey: bytes.Clone(r.EvmKey), OperatorPayee: r.Payee}
}

// delegationOfBinding is a stored VR binding's words as a delegation binding.
func delegationOfBinding(b vrclient.Binding) vrclient.Delegation {
	return vrclient.Delegation{RootNodeID: b.RootNodeWord, RootKey: bytes.Clone(b.RootKey), EvmNodeID: b.EvmNodeWord, EvmKey: bytes.Clone(b.EvmKey),
		OperatorPayee: b.Payee}
}

// delegationBindingHash is ElectionPolicy's binding hash of (id, generation, binding): the hash a frozen member records.
func delegationBindingHash(id, generation uint64, d vrclient.Delegation) [32]byte {
	wid, wgen := vrschema.U64(id), vrschema.U64(generation)
	return [32]byte(ethcrypto.Keccak256(vrElectionBindingDomain[:], wid[:], wgen[:], d.RootNodeID[:], ethcrypto.Keccak256(d.RootKey),
		d.EvmNodeID[:], ethcrypto.Keccak256(d.EvmKey), common.LeftPadBytes(d.OperatorPayee[:], 32)))
}

// planPosKeyChange checks a PoS key change of identity st.ID by operator to the words want and returns the transactions still to send.
// evmOnly (recover) also refuses a payee change. Nothing to send is an empty plan, not an error.
func planPosKeyChange(st posBindingState, operator common.Address, want vrclient.Registration, evmOnly bool) (posKeyChange, error) {
	var p posKeyChange
	pos, idn := st.Position, st.Identity
	switch {
	case pos.Owner != operator:
		return p, fmt.Errorf("%w: custody's identity %d is owned by %s, not the operator %s", ErrValidator, st.ID, pos.Owner.Hex(), operator.Hex())
	case !idn.Known():
		return p, fmt.Errorf("%w: VR knows no identity %d", ErrValidator, st.ID)
	case pos.OpenLots == 0:
		return p, fmt.Errorf("%w: identity %d has no open lots (not bonded): there is no seat to recover; `ubft validator apply` bonds and delegates the configured keys", ErrValidator, st.ID)
	case pos.RetirementRequested:
		return p, fmt.Errorf("%w: identity %d requested retirement: finish the exit (`validator claim`), then re-bond and `apply` at the next generation", ErrValidator, st.ID)
	case st.Excluded:
		return p, fmt.Errorf("%w: identity %d is excluded by evidence: it takes the exit path, not a key change", ErrValidator, st.ID)
	}
	// the root key is never changed here (root-key loss takes the exit path): the configured root key is custody's and VR's current one
	if [32]byte(ethcrypto.Keccak256(want.RootKey)) != pos.RootKeyHash || !bytes.Equal(want.RootKey, idn.Current.RootKey) || want.RootNodeID != idn.Current.RootNodeID {
		return p, fmt.Errorf("%w: the configured root key or root node is not identity %d's current one: a root-key change is refused (root-key loss takes the exit path: `validator exit`, claim, then a fresh identity)", ErrValidator, st.ID)
	}
	if evmOnly && want.Payee != idn.Current.Payee {
		return p, fmt.Errorf("%w: recover changes the EVM key only; the configured payee %s is not identity %d's %s (use `validator rotate --new-payee` once recovered)",
			ErrValidator, want.Payee.Hex(), st.ID, idn.Current.Payee.Hex())
	}
	installed := vrclient.BindingMatches(idn.Current, want)
	if evmOnly && installed && sameDelegation(st.Delegation, delegationOf(want)) {
		return p, nil // done: VR's current binding and the delegation are the new words
	}
	if evmOnly && bytes.Equal(want.EvmKey, idn.Current.EvmKey) && !installed {
		return p, fmt.Errorf("%w: the new EVM key is identity %d's current one with other words: pass a fresh authority's key", ErrValidator, st.ID)
	}
	staged := idn.StagedRef != ([32]byte{})
	p.Admit = !sameDelegation(st.Delegation, delegationOf(want))
	p.Stage = !installed && !(staged && vrclient.BindingMatches(idn.Staged, want))
	if p.Stage && staged {
		// replacing a staged binding a live frozen result captured would leave that member unservable (the adapter serves the frozen hash)
		if st.OpenResult != ([32]byte{}) {
			sh := delegationBindingHash(st.ID, pos.Generation, delegationOfBinding(idn.Staged))
			for _, f := range st.Frozen {
				if f.Id == st.ID && f.BindingHash == sh {
					return posKeyChange{}, fmt.Errorf("%w: the open result %x froze identity %d's staged binding %x: replacing it would make that member unservable; wait until the result is published and acknowledged, rejected or recovered",
						ErrValidator, st.OpenResult, st.ID, idn.StagedRef)
				}
			}
		}
	}
	return p, nil
}

// certifiedClient reads at the RPC's finalized block (the certified state), pinned by hash.
func (ch *validatorChain) certifiedClient(ctx context.Context) (*vrclient.Client, uint64, error) {
	var b struct {
		Hash   common.Hash    `json:"hash"`
		Number hexutil.Uint64 `json:"number"`
	}
	if err := ch.rpc.CallContext(ctx, &b, "eth_getBlockByNumber", "finalized", false); err != nil {
		return nil, 0, fmt.Errorf("%w: reading the finalized (certified) block: %w", ErrValidator, err)
	}
	if b.Hash == (common.Hash{}) {
		return nil, 0, fmt.Errorf("%w: the RPC serves no finalized (certified) block", ErrValidator)
	}
	c := *ch.vr
	c.Block, c.BlockHash = "", b.Hash.Hex()
	return &c, uint64(b.Number), nil
}

// readPosBindingState reads the state a key change decides from, through c (certified, or latest after a confirmed transaction).
func readPosBindingState(ctx context.Context, c *vrclient.Client, custody, election common.Address, id uint64) (posBindingState, error) {
	st := posBindingState{ID: id}
	if err := c.CallPosMulti(ctx, custody, vrclient.CustodyABI, "positions", &st.Position, id); err != nil {
		return st, err
	}
	var evidence common.Address
	if err := c.CallPos(ctx, custody, vrclient.CustodyABI, "evidence", &evidence); err != nil {
		return st, err
	}
	if evidence == (common.Address{}) {
		return st, fmt.Errorf("%w: custody %s names no evidence contract", ErrValidator, custody.Hex())
	}
	if err := c.CallPos(ctx, evidence, vrclient.EvidenceABI, "excluded", &st.Excluded, id); err != nil {
		return st, err
	}
	var d struct {
		Binding     vrclient.Delegation
		BindingHash [32]byte
		NextNonce   uint64
	}
	if err := c.CallPosMulti(ctx, election, vrclient.PosElectionABI, "delegation", &d, id, st.Position.Generation); err != nil {
		return st, err
	}
	st.Delegation, st.DelegationNonce = d.Binding, d.NextNonce
	var err error
	if st.Identity, err = c.Identity(ctx, id); err != nil {
		return st, err
	}
	if st.OpenResult, err = c.OpenResult(ctx, election); err != nil {
		return st, err
	}
	if st.OpenResult != ([32]byte{}) {
		if st.Frozen, err = c.FrozenMembers(ctx, election, st.OpenResult); err != nil {
			return st, err
		}
	}
	return st, nil
}

// posKeyChangeRun is one PoS key change: the chain, the operator, the new keys (EVM key holder: next.EVMAuth or next.EVM) and the words.
type posKeyChangeRun struct {
	ch                *validatorChain
	v                 *loadedValidator
	next              *validatorKeys
	sender            vrclient.Sender
	custody, election common.Address
	id                uint64
	want              vrclient.Registration
	evmOnly           bool
	dry               bool
}

// run plans from the certified state, then sends the delegation (confirmed and re-read) before the binding (confirmed and re-read).
func (r *posKeyChangeRun) run(ctx context.Context, w io.Writer) error {
	cert, height, err := r.ch.certifiedClient(ctx)
	if err != nil {
		return err
	}
	st, err := readPosBindingState(ctx, cert, r.custody, r.election, r.id)
	if err != nil {
		return err
	}
	operator := r.sender.From()
	plan, err := planPosKeyChange(st, operator, r.want, r.evmOnly)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "identity %d: custody generation %d, %d open lot(s), certified at block %d; new EVM node %s\n", r.id, st.Position.Generation,
		st.Position.OpenLots, height, r.want.EvmNodeID)
	// the latest state decides each transaction's nonces; it must agree with the certified plan (a step done since is skipped)
	latest, err := readPosBindingState(ctx, r.ch.vr, r.custody, r.election, r.id)
	if err != nil {
		return err
	}
	if lp, err := planPosKeyChange(latest, operator, r.want, r.evmOnly); err != nil {
		return err
	} else {
		plan.Admit, plan.Stage = plan.Admit && lp.Admit, plan.Stage && lp.Stage
	}
	if !plan.Admit {
		fmt.Fprintf(w, "already done: identity %d's delegation at generation %d is the new words\n", r.id, latest.Position.Generation)
	}
	if !plan.Stage {
		fmt.Fprintf(w, "already done: VR's binding of identity %d is the new words\n", r.id)
	}
	if !plan.Admit && !plan.Stage {
		fmt.Fprintln(w, "nothing to do: the delegation and VR's binding are the new words")
		return nil
	}
	var steps []step
	if plan.Admit {
		s, err := r.admitStep(ctx, latest)
		if err != nil {
			return err
		}
		steps = append(steps, s)
	}
	stageStep := func() ([]step, error) {
		s, err := r.stageStep(ctx)
		if err != nil {
			return nil, err
		}
		return []step{s}, nil
	}
	if plan.Stage {
		if plan.Admit && r.dry {
			s, err := r.stageStep(ctx)
			if err != nil {
				return err
			}
			s.note = "it is sent after the delegation confirms"
			steps = append(steps, s)
		} else if !plan.Admit {
			more, err := stageStep()
			if err != nil {
				return err
			}
			steps = append(steps, more...)
		}
	}
	// the receipts arrive in order: the delegation's (when planned) first, then the binding's
	admitPending := plan.Admit
	after := func(_ int, _ *vrclient.Receipt) ([]step, error) {
		now, err := readPosBindingState(ctx, r.ch.vr, r.custody, r.election, r.id)
		if err != nil {
			return nil, err
		}
		want := delegationOf(r.want)
		if admitPending {
			admitPending = false
			if !sameDelegation(now.Delegation, want) {
				return nil, fmt.Errorf("%w: after the confirmed delegation the election stages other words for identity %d: stop and re-run", ErrValidator, r.id)
			}
			fmt.Fprintf(w, "  confirmed: identity %d's delegation at generation %d is the new words (the old key is fenced from later snapshots)\n", r.id, now.Position.Generation)
			if !plan.Stage {
				return nil, nil
			}
			// re-plan from the confirmed state: the staged-binding guard is checked again before replacing anything
			p, err := planPosKeyChange(now, operator, r.want, r.evmOnly)
			if err != nil {
				return nil, err
			}
			if !p.Stage {
				return nil, nil
			}
			return stageStep()
		}
		if !(vrclient.BindingMatches(now.Identity.Current, r.want) || (now.Identity.StagedRef != ([32]byte{}) && vrclient.BindingMatches(now.Identity.Staged, r.want))) {
			return nil, fmt.Errorf("%w: after the confirmed proposeBinding VR's bindings of identity %d are not the new words", ErrValidator, r.id)
		}
		if !sameDelegation(now.Delegation, want) {
			return nil, fmt.Errorf("%w: VR stages the new words but the delegation is not them: re-run to admit it", ErrValidator)
		}
		fmt.Fprintf(w, "  confirmed: VR stages identity %d's new binding, the delegation equals it\n", r.id)
		return nil, nil
	}
	if r.dry {
		after = nil
	}
	return runSteps(ctx, w, r.sender, r.dry, steps, after)
}

// admitStep is ElectionPolicy.admitDelegation of the new words at custody's generation, signed by the operator and the new EVM key.
func (r *posKeyChangeRun) admitStep(ctx context.Context, st posBindingState) (step, error) {
	var network [32]byte
	if err := r.ch.vr.CallPos(ctx, r.custody, vrclient.CustodyABI, "network", &network); err != nil {
		return step{}, err
	}
	req := vrclient.DelegationRequest{Id: r.id, Generation: st.Position.Generation, RoleNonce: st.Position.RoleNonce, DelegationNonce: st.DelegationNonce,
		Expiry: math.MaxUint64, Binding: delegationOf(r.want)}
	var digest [32]byte
	if err := r.ch.vr.CallPos(ctx, r.election, vrclient.PosElectionABI, "delegationDigest", &digest, req); err != nil {
		return step{}, err
	}
	ownerSig, evmSig, err := signDelegation(ctx, r.ch, r.election, network, r.next, req, digest)
	if err != nil {
		return step{}, err
	}
	data, err := vrclient.PosCalldata(vrclient.PosElectionABI, "admitDelegation", req, ownerSig, evmSig)
	if err != nil {
		return step{}, err
	}
	return step{what: fmt.Sprintf("admit identity %d's delegation to the new EVM key at custody generation %d (first: it fences the old key)", r.id, req.Generation),
		tx: vrclient.Tx{To: r.election, Data: data}}, nil
}

// signDelegation signs an admitDelegation request: the operator key, and the EVM key (the authority recomputes the digest and must agree).
func signDelegation(ctx context.Context, ch *validatorChain, election common.Address, network [32]byte, keys *validatorKeys, req vrclient.DelegationRequest,
	digest [32]byte) (ownerSig, evmSig []byte, err error) {
	if ownerSig, err = vrclient.SignDigest(keys.Operator, digest); err != nil {
		return nil, nil, err
	}
	if keys.EVMAuth != nil {
		var chainWord [32]byte
		ch.chainID.FillBytes(chainWord[:])
		dreq := delegationRequestOf(req)
		if want := evmassign.DelegationDigest(network, chainWord, election, dreq); want != digest {
			return nil, nil, fmt.Errorf("%w: the election's delegation digest %x is not the one the authority signs (%x): the deployment's network word or chain differs from custody's", ErrValidator, digest, want)
		}
		evmSig, err = keys.EVMAuth.DelegationPossession(ctx, signingauthority.DelegationPossessionRequest{Network: network, Chain: chainWord, Election: election, Request: dreq})
		return ownerSig, evmSig, err
	}
	evm, err := nodeKeys(keys.EVM)
	if err != nil {
		return nil, nil, err
	}
	evmSig, err = vrclient.SignDigest(evm.Key, digest)
	return ownerSig, evmSig, err
}

// stageStep is VR.proposeBinding of the same words at VR's current binding nonce (read when the step is built: after the delegation).
func (r *posKeyChangeRun) stageStep(ctx context.Context) (step, error) {
	idn, err := r.ch.vr.Identity(ctx, r.id)
	if err != nil {
		return step{}, err
	}
	reg, root, evm, err := registration(r.v, r.next, idn.BindingNonce)
	if err != nil {
		return step{}, err
	}
	reg.Payee = r.want.Payee
	if !vrclient.BindingMatches(vrclient.Binding{RootNodeID: reg.RootNodeID, RootKey: reg.RootKey, EvmNodeID: reg.EvmNodeID, EvmKey: reg.EvmKey, Payee: reg.Payee}, r.want) {
		return step{}, fmt.Errorf("%w: the binding to stage is not the delegated words", ErrValidator)
	}
	signed, err := vrclient.SignWith(ctx, r.ch.domain(), r.sender.From(), true, r.id, reg, root, evm)
	if err != nil {
		return step{}, err
	}
	data, err := vrclient.ProposeBindingCalldata(r.id, signed)
	if err != nil {
		return step{}, err
	}
	return step{what: fmt.Sprintf("stage the identical binding for identity %d in VR (binding nonce %d)", r.id, idn.BindingNonce),
		tx: vrclient.Tx{To: r.ch.vr.Registry, Data: data}}, nil
}

// ---- recover -----------------------------------------------------------------------------------------------------------------------------

type recoverFlags struct {
	txFlags
	EVMKeys                string
	EVMAuthoritySocket     string
	EVMAuthorityCredential string
	EVMNodeInfo            string
	OldAuthorityHome       string
}

func validatorRecoverCmd(base *baseFlags) *cobra.Command {
	f := &recoverFlags{txFlags: txFlags{validatorFlags: validatorFlags{baseFlags: base}, enrollsRootKey: true}}
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "PoS: move a bonded identity whose EVM signing authority is lost to a fresh EVM key (delegation first, then VR)",
		Long: `For a bonded PoS identity whose EVM key is gone with its signing authority (#1286). The root key, root node and payee stay; only
the EVM node and key change, at custody's current generation, so the bond stays in its lots. Preflight from the certified (finalized)
state: the custody owner is the operator, the identity has open lots, no retirement request and no exclusion. The old authority's
fail-stop marker must be present in its preserved volume (--old-authority-home): an unreachable authority alone is not evidence of loss.
Then ElectionPolicy.admitDelegation of the new EVM key, confirmed, fences the old key from later snapshots, and VR.proposeBinding stages
the identical words for the next election. A re-run skips what is done. A staged binding that an open result froze is not replaced.
Root-key loss is refused: take the exit path. Start the node on the new authority, then follow the election and the boundary.`,
		RunE: func(cmd *cobra.Command, _ []string) error { return validatorRecover(cmd, f) },
	}
	f.txFlags.add(cmd)
	cmd.Flags().StringVar(&f.EVMKeys, "new-evm-keys", "", "the EVM shard node's new key file (instead of --new-evm-authority-*)")
	cmd.Flags().StringVar(&f.EVMAuthoritySocket, "new-evm-authority-socket", "", "the fresh signing authority holding the new EVM key: its operator socket, relative to the validator home (needs --new-evm-authority-credential and --new-evm-node-info)")
	cmd.Flags().StringVar(&f.EVMAuthorityCredential, "new-evm-authority-credential", "", "the operator credential of the fresh authority")
	cmd.Flags().StringVar(&f.EVMNodeInfo, "new-evm-node-info", "", "the node info of the fresh authority (`signing-authority node-info`)")
	cmd.Flags().StringVar(&f.OldAuthorityHome, "old-authority-home", "", "the preserved volume of the lost authority, holding its fail-stop marker (required; relative to the validator home)")
	return cmd
}

// checkFailStop requires the lost authority's fail-stop marker in its preserved volume, and refuses a new authority inside that volume.
func checkFailStop(oldHome, newSocket string) error {
	if oldHome == "" {
		return fmt.Errorf("%w: --old-authority-home is required: the lost authority's volume with its fail-stop marker (an unreachable authority alone is not evidence of key loss)", ErrValidator)
	}
	raw, err := os.ReadFile(filepath.Join(oldHome, authorityLifetimeMarker)) // #nosec G304 -- operator supplied local directory
	if err != nil || !strings.HasPrefix(string(raw), "fail-stop") {
		return fmt.Errorf("%w: no fail-stop marker in %s (%s): recover needs the old authority's preserved volume and marker", ErrValidator, oldHome, authorityLifetimeMarker)
	}
	if newSocket != "" {
		oh, err1 := filepath.Abs(oldHome)
		ns, err2 := filepath.Abs(newSocket)
		if err := errors.Join(err1, err2); err != nil {
			return err
		}
		if rel, err := filepath.Rel(oh, ns); err == nil && !strings.HasPrefix(rel, "..") {
			return fmt.Errorf("%w: the new authority's socket %s is in the marked volume %s: use a fresh authority volume", ErrValidator, newSocket, oldHome)
		}
	}
	return nil
}

// checkOldAuthorityGone refuses when the configured (old) authority still answers and holds its key: that is a live authority, use rotate.
func checkOldAuthorityGone(ctx context.Context, old *evmAuthority) error {
	if old == nil {
		return nil
	}
	op, err := openOperator(old.cfg.Socket, old.cfg.Credential)
	if err != nil {
		return nil // unreachable: the marker decides
	}
	defer func() { _ = op.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := op.Status(ctx)
	if err != nil || st.KeyLost || st.Faulted {
		return nil
	}
	return fmt.Errorf("%w: the configured authority at %s still answers and holds its key: this is not an authority loss (use `validator rotate`)", ErrValidator, old.cfg.Socket)
}

func validatorRecover(cmd *cobra.Command, f *recoverFlags) error {
	ctx := cmd.Context()
	w := cmd.OutOrStdout()
	newAuth := f.EVMAuthoritySocket != "" || f.EVMAuthorityCredential != "" || f.EVMNodeInfo != ""
	if newAuth == (f.EVMKeys != "") {
		return fmt.Errorf("%w: pass the new EVM key: --new-evm-keys or --new-evm-authority-* (one of them)", ErrValidator)
	}
	v, keys, ch, s, err := openTx(cmd, &f.txFlags)
	if err != nil {
		return err
	}
	defer ch.close()
	if !ch.isPoS() {
		return fmt.Errorf("%w: recover is the PoS adapter's: VR's active module %s is not it", ErrValidator, ch.module.Module.Hex())
	}
	socket := ""
	if newAuth {
		socket = v.abs(f.EVMAuthoritySocket)
	}
	if err := checkFailStop(v.abs(f.OldAuthorityHome), socket); err != nil {
		return err
	}
	if err := checkOldAuthorityGone(ctx, keys.EVMAuth); err != nil {
		return err
	}
	next := *keys
	if f.EVMKeys != "" {
		if next.EVM, err = readKeyConf(f.EVMKeys); err != nil {
			return fmt.Errorf("%w: new EVM keys: %w", ErrValidator, err)
		}
		next.EVMAuth = nil
	} else {
		if next.EVMAuth, err = loadEVMAuthority(evmAuthorityConfig{Socket: socket, Credential: v.abs(f.EVMAuthorityCredential), NodeInfo: v.abs(f.EVMNodeInfo)}); err != nil {
			return err
		}
		next.EVM = nil
	}
	if err := next.distinct(); err != nil {
		return err
	}
	return runPosKeyChange(ctx, w, v, &next, ch, s, f.DryRun, true)
}

// runPosKeyChange finds the operator's identity and runs the two-transaction key change to the words of next.
func runPosKeyChange(ctx context.Context, w io.Writer, v *loadedValidator, next *validatorKeys, ch *validatorChain, s vrclient.Sender, dry, evmOnly bool) error {
	custody, election, err := ch.posAddrs(ctx)
	if err != nil {
		return err
	}
	id, have, err := findID(ctx, v, ch, s.From())
	if err != nil {
		return err
	}
	if !have {
		return fmt.Errorf("%w: the operator account owns no VR identity (run `ubft validator apply`)", ErrValidator)
	}
	want, _, _, err := registration(v, next, 0)
	if err != nil {
		return err
	}
	r := &posKeyChangeRun{ch: ch, v: v, next: next, sender: s, custody: custody, election: election, id: id, want: want, evmOnly: evmOnly, dry: dry}
	if err := r.run(ctx, w); err != nil {
		return err
	}
	if !dry {
		fmt.Fprintln(w, "the delegation and VR's staged binding are the new words: run the nodes on the new EVM key (validator init --force with the new key or authority);"+
			" the next election selects it and the boundary installs it (`validator status`)")
	}
	return nil
}

// refuseBondedMismatch is apply's guard on a bonded PoS identity (#1286): the delegation it would admit must be VR's current or staged binding;
// other words are a key change, which is `rotate` or `recover` (delegation and VR binding together).
func refuseBondedMismatch(idn vrclient.IdentityView, id uint64, want vrclient.Registration) error {
	if vrclient.BindingMatches(idn.Current, want) || (idn.StagedRef != ([32]byte{}) && vrclient.BindingMatches(idn.Staged, want)) {
		return nil
	}
	return fmt.Errorf("%w: identity %d is bonded and the configured keys or payee are not its VR binding: changing them is `ubft validator rotate` (or `validator recover` after an authority loss), which moves the delegation and VR's binding together", ErrValidator, id)
}
