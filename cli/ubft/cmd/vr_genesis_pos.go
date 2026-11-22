package cmd

// The PoS-prototype generation's share of `vr-genesis verify` (VT-04, design 3.8): the module is the PosElectionAdapter at 0xff..07 (no
// storage, no composer), custody is liability holder 0 of the generation, and the P85 stack the contracts genesis allocates is bound to
// the plan: its accounts, code hashes, balances, and the custody slots that tie it to VR and to the roots' genesis identities.

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The PosElectionAdapter's cached metadata (src/vr/pos/PosElectionAdapter.sol): the tag, LIABILITY_HOLDER, and the gas bounds it
// declares: the PoS-capable VR build's caps (5.0 / 1.5 / 2.5 M; VT-04b, astra's caps ruling), which VR takes as min(its ceiling, these).
var (
	vrPosTag       = vrschema.Keccak([]byte("unicity.vr.pos-p85.v1"))
	vrPosGasBounds = [8]uint64{5_000_000, 1_500_000, 2_500_000, 10_000, 10_000, 10_000, 10_000, 10_000}
)

// Measured PoS deployment limits for one lifetime lot per identity generation.
const (
	vrPosMaxCommittee = 16
	vrPosMaxPool      = 20
	vrPosLegacyPool   = 8
)

// This runtime contains the immutable address and code hash of the live custody writer.
var vrPosCustodyWriterPinned = common.HexToHash("0x7ef8f1ca7090f9d51c58e956b424e331456ffeab1786eb64a5e03d199c2db255")

// custody storage appended by VT-04 (docs/p85/custody-storage-layout.txt): deploymentDomain and exposureMemberDigest.
const (
	vrCustodyDomainSlot       = 39
	vrCustodyMemberDigestSlot = 40
)

func vrModuleTag(in vrGenesisInput) vrschema.Word {
	if in.Pos != nil {
		return vrPosTag
	}
	return vrPoaTag
}

// vrPosAccounts are the accounts of the P85 stack the PoS deployment report names.
func vrPosAccounts(in vrGenesisInput, d vrDeploymentFile) (map[common.Address]string, error) {
	out := map[common.Address]string{}
	if in.Pos == nil {
		if d.Pos {
			return nil, fmt.Errorf("%w: the deployment report is a PoS deployment but the input has no pos object", ErrVRGenesis)
		}
		return out, nil
	}
	if !d.Pos || d.PosAssignmentID == "" {
		return nil, fmt.Errorf("%w: the input is a PoS plan but the deployment report is not a PoS deployment", ErrVRGenesis)
	}
	roles := map[string]string{"factory": d.Factory, "custody": d.Custody, "genesisImpl": d.GenesisImpl, "election": d.Election,
		"evidence": d.Evidence, "selection": d.Selection, "reader": d.Reader, "policy": d.Policy, "rewardPool": d.RewardPool}
	if d.ElectionPublication != "" || in.Limits.VMax > vrPosLegacyPool {
		roles["electionPublication"] = d.ElectionPublication
	}
	for role, s := range roles {
		a, err := vrAddress("PoS "+role, s)
		if err != nil {
			return nil, err
		}
		if a == (common.Address{}) {
			return nil, fmt.Errorf("%w: the PoS %s is the zero address", ErrVRGenesis, role)
		}
		if prior, dup := out[a]; dup {
			return nil, fmt.Errorf("%w: the PoS %s and %s are one account", ErrVRGenesis, role, prior)
		}
		if vrGenesisRole(a) != "" {
			return nil, fmt.Errorf("%w: the PoS %s collides with a VR genesis account", ErrVRGenesis, role)
		}
		out[a] = role
	}
	return out, nil
}

// vrPosExpectedState rewrites VR's expected genesis storage for the PoS module: its cached metadata (V+16..V+21), holder 0
// (V+36, V+49, the holder count in V+6). The module account itself holds no storage.
func vrPosExpectedState(in vrGenesisInput, d vrDeploymentFile, identities []evmassign.Identity, vr vrStorage, moduleCode [32]byte) error {
	V := vrschema.VRSlot
	custody, err := vrAddress("PoS custody", d.Custody)
	if err != nil {
		return err
	}
	custodyHash, err := vrHex("PoS custody code hash", d.CustodyCodeHash, 32)
	if err != nil {
		return err
	}
	set := func(slot, w vrschema.Word) {
		if w == (vrschema.Word{}) {
			delete(vr, slot)
			return
		}
		vr[slot] = w
	}
	set(V(16), vrPosTag)
	set(V(17), packed([3]uint64{0, 4, 1}, [3]uint64{4, 8, in.Pos.CadenceRounds}))
	gasBounds := vrPosGasBounds
	if d.ElectionPublication != "" {
		gasBounds[0] = 7_000_000
	}
	for half := 0; half < 2; half++ {
		set(V(18+uint64(half)), packed([3]uint64{0, 8, gasBounds[4*half]}, [3]uint64{8, 8, gasBounds[4*half+1]},
			[3]uint64{16, 8, gasBounds[4*half+2]}, [3]uint64{24, 8, gasBounds[4*half+3]}))
	}
	cw := vrschema.AddrWord(custody)
	set(V(20), cw)
	set(V(21), vrschema.Word(custodyHash))
	set(V(vrschema.SlotStatus), packed([3]uint64{1, 8, in.KnownRootEpoch}, [3]uint64{21, 1, 1}))
	// holders[0] = {custody, registeredEpoch, custody code hash, module}: V+36 (a uint8 key), V+49 holderIndexPlusOne[custody] = 1
	h := vrschema.MapSlot(vrschema.U64(0), V(36))
	w := packed([3]uint64{20, 8, in.KnownRootEpoch})
	addrAt(&w, 0, custody)
	set(h, w)
	set(vrschema.SlotAdd(h, 1), vrschema.Word(custodyHash))
	mw := vrschema.AddrWord(vrGenesisAddress(7))
	set(vrschema.SlotAdd(h, 2), mw)
	set(vrschema.MapSlot(cw, V(49)), vrschema.U64(1))
	_ = moduleCode
	_ = identities
	return nil
}

// vrCheckPosStack binds the P85 stack to the plan: every account allocated with the code hash the report names, custody holding exactly the
// bonds and the reward pool exactly its funding, custody's deployment domain VR, and each genesis identity's member digest in custody the
// one the roots' genesis identity carries (so a closure of the genesis assignment derives the digest custody stored).
func vrCheckPosStack(in vrGenesisInput, d vrDeploymentFile, identities []evmassign.Identity, alloc map[common.Address]vrAllocAccount, posAccts map[common.Address]string) error {
	fail := func(f string, a ...any) error { return fmt.Errorf("%w: "+f, append([]any{ErrVRGenesis}, a...)...) }
	hashes := map[string]string{"custody": d.CustodyCodeHash, "election": d.ElectionCodeHash, "policy": d.PolicyCodeHash, "rewardPool": d.RewardPoolCodeHash}
	if d.ElectionPublication != "" {
		hashes["electionPublication"] = d.ElectionPublicationCodeHash
		election := common.HexToAddress(d.Election)
		impl := vrschema.AddrWord(common.HexToAddress(d.ElectionPublication))
		hash, err := vrHex("publication implementation code hash", d.ElectionPublicationCodeHash, 32)
		if err != nil {
			return err
		}
		code := common.FromHex(alloc[election].Code)
		if !bytes.Contains(code, impl[:]) || !bytes.Contains(code, hash) {
			return fail("the PoS election does not pin its publication implementation and code")
		}
	}
	if strings.EqualFold(d.RegistryCodeHash, lowerHex(b1state.VRBuildPos16.RegistryCodeHash[:])) ||
		d.ElectionPublication != "" || in.Limits.VMax > vrPosLegacyPool || d.GenesisImplCodeHash != "" {
		if ethcrypto.Keccak256Hash(common.FromHex(alloc[common.HexToAddress(d.Custody)].Code)) != vrPosCustodyWriterPinned {
			return fail("the PoS custody runtime is not the reviewed build with an authenticated writer")
		}
		if err := vrCheckPosCustodyImplementation(d, alloc); err != nil {
			return err
		}
	}
	var custody common.Address
	for a, role := range posAccts {
		acct, ok := alloc[a]
		if !ok {
			return fail("the PoS %s %s is not allocated", role, a)
		}
		code := strings.TrimPrefix(acct.Code, "0x")
		if code == "" {
			return fail("the PoS %s has no code", role)
		}
		raw, err := vrHex("code", "0x"+code, len(code)/2)
		if err != nil {
			return err
		}
		if want, named := hashes[role]; named {
			if got := ethcrypto.Keccak256Hash(raw); !strings.EqualFold(lowerHex(got[:]), want) {
				return fail("the PoS %s code hashes to %x, the report names %s", role, got, want)
			}
		}
		if role == "custody" {
			custody = a
		}
	}
	bondUnit, _ := new(big.Int).SetString(in.Pos.BondUnit, 10)
	total := new(big.Int)
	for _, p := range in.Identities {
		total.Add(total, new(big.Int).Mul(new(big.Int).SetUint64(p.RawWeight), bondUnit))
	}
	balance := func(a common.Address) *big.Int {
		w, _ := bigWord(cmpOr(alloc[a].Balance, "0x0"))
		return new(big.Int).SetBytes(w[:])
	}
	if got := balance(custody); got.Cmp(total) != 0 {
		return fail("custody holds %s, the genesis bonds are %s", got, total)
	}
	pool, _ := vrAddress("PoS reward pool", d.RewardPool)
	funding, _ := new(big.Int).SetString(in.Pos.RewardFunding, 10)
	if got := balance(pool); got.Cmp(funding) != 0 {
		return fail("the reward pool holds %s, the plan funds %s", got, funding)
	}
	slots, err := storageOf(alloc[custody])
	if err != nil {
		return err
	}
	if got := slots[vrschema.U64(vrCustodyDomainSlot)]; got != vrschema.AddrWord(common.Address(vrschema.ValidatorRegistry)) {
		return fail("custody's exposure-digest domain is %x, not VR", got)
	}
	network, err := vrHex("network", in.Network, 32)
	if err != nil {
		return err
	}
	assignment, err := vrHex("assignment", in.Pos.AssignmentID, 32)
	if err != nil {
		return err
	}
	if err := vrCheckPosElection(in, d, network, alloc); err != nil {
		return err
	}
	if err := vrCheckPosCustody(in, d, network, alloc); err != nil {
		return err
	}
	chainWord := vrschema.U64(in.ChainID)
	for i, id := range identities {
		sid := uint64(i + 1)
		eid := vrschema.PoaExposureDigest(vrschema.Word(network), chainWord, vrschema.ValidatorRegistry, vrschema.Word(assignment), sid)
		got := slots[vrschema.MapSlot(eid, vrschema.U64(vrCustodyMemberDigestSlot))]
		if in.Limits.VMax > vrPosLegacyPool {
			// vrCheckPosCustody authenticated the ordered row and its binding. The compact getter derives the genesis digest.
			got = vrschema.PoaExposureDigest(vrschema.Word(network), chainWord, vrschema.ValidatorRegistry, vrschema.GenesisResult, sid)
		}
		if !strings.EqualFold(lowerHex(got[:]), lowerHex(id.ExposureDigest)) {
			return fail("custody's member digest of genesis identity %d is %x, the roots' genesis identity carries %x", sid, got, id.ExposureDigest)
		}
	}
	return nil
}

// The custody runtime checks this immutable address and code hash before delegating.
func vrCheckPosCustodyImplementation(d vrDeploymentFile, alloc map[common.Address]vrAllocAccount) error {
	impl, err := vrAddress("PoS custody implementation", d.GenesisImpl)
	if err != nil {
		return err
	}
	want, err := vrHex("PoS custody implementation code hash", d.GenesisImplCodeHash, 32)
	if err != nil {
		return err
	}
	runtime := common.FromHex(alloc[impl].Code)
	got := ethcrypto.Keccak256Hash(runtime)
	if len(runtime) == 0 || !bytes.Equal(got[:], want) {
		return fmt.Errorf("%w: allocated PoS custody implementation does not match its runtime hash", ErrVRGenesis)
	}
	code := common.FromHex(alloc[common.HexToAddress(d.Custody)].Code)
	addressWord := vrschema.AddrWord(impl)
	if !bytes.Contains(code, addressWord[:]) || !bytes.Contains(code, want) {
		return fmt.Errorf("%w: PoS custody does not pin its implementation address and runtime hash", ErrVRGenesis)
	}
	return nil
}

// ElectionPolicy storage (the compiled layout the genesis script initializes through the factory; unicity-pos-contracts src/p85/ElectionPolicy.sol).
const (
	vrElectionInitializedSlot = 0
	vrElectionNetworkSlot     = 2
	vrElectionCustodySlot     = 3
	vrElectionRootsSlot       = 4
	vrElectionEvidenceSlot    = 5
	vrElectionSelectionSlot   = 6
	vrElectionParamsSlot      = 8  // nMin, nTarget, nMax as three 4-byte fields
	vrElectionCadenceSlot     = 9  // cadenceRounds, then cadenceSeconds, above the low 8 bytes
	vrElectionStagedSlot      = 18 // mapping(id => mapping(generation => Staged))
	vrElectionIndexLenSlot    = 19 // the live index: the length here, the entries (uint64, four to a word) from keccak(19)
	vrElectionPositionSlot    = 20 // mapping(id => 1-based position in the index)
	vrElectionMaxBatchSlot    = 15
	vrElectionReaderSlot      = 21
	vrElectionHookCallerSlot  = 23
	vrElectionRegistrySlot    = 24
)

// vrPosElectionExpected is the election's ENTIRE planned genesis storage, derived from the plan alone: every slot ElectionPolicy.initialize
// writes (links, limits, parameters and cadence, the live index with its reverse positions, and each genesis identity's staged binding at
// generation 1 with its key bytes and hashes). Nothing else is written at genesis, so the allocated storage must equal it slot for slot: an extra slot,
// a missing one or an altered one is refused. The manifest hash is the factory's hash of the whole manifest and is not derivable from the plan; it
// must be present and is the one word taken from the alloc.
func vrPosElectionExpected(in vrGenesisInput, d vrDeploymentFile, network []byte, manifestHash vrschema.Word) (vrStorage, error) {
	e := vrStorage{}
	addr := func(name, s string) (common.Address, error) { return vrAddress("PoS "+name, s) }
	custody, err1 := addr("custody", d.Custody)
	evidence, err2 := addr("evidence", d.Evidence)
	selection, err3 := addr("selection", d.Selection)
	reader, err4 := addr("reader", d.Reader)
	policy, err5 := addr("policy", d.Policy)
	if err := errors.Join(err1, err2, err3, err4, err5); err != nil {
		return nil, err
	}
	e.set(vrschema.U64(vrElectionInitializedSlot), vrschema.U64(1))
	e.set(vrschema.U64(1), manifestHash)
	e.set(vrschema.U64(vrElectionNetworkSlot), vrschema.Word(network))
	e.set(vrschema.U64(vrElectionCustodySlot), vrschema.AddrWord(custody))
	e.set(vrschema.U64(vrElectionRootsSlot), vrschema.AddrWord(common.Address(vrschema.SealRegistry)))
	e.set(vrschema.U64(vrElectionEvidenceSlot), vrschema.AddrWord(evidence))
	e.set(vrschema.U64(vrElectionSelectionSlot), vrschema.AddrWord(selection))
	// policySource (20 bytes) and vMax (uint32) share a word
	w := packed([3]uint64{20, 4, uint64(in.Limits.VMax)})
	addrAt(&w, 0, policy)
	e.set(vrschema.U64(7), w)
	// ElectionParams: nMin, nTarget, nMax (uint32), maxM, distNum (uint64) in the first word; distDen, cadenceRounds, cadenceSeconds in the next
	e.set(vrschema.U64(vrElectionParamsSlot), packed([3]uint64{0, 4, uint64(in.Limits.NMin)}, [3]uint64{4, 4, uint64(in.Limits.NTarget)}, [3]uint64{8, 4, uint64(in.Limits.NMax)},
		[3]uint64{12, 8, in.Continuity.MaxM}, [3]uint64{20, 8, in.Continuity.DistNum}))
	e.set(vrschema.U64(vrElectionCadenceSlot), packed([3]uint64{0, 8, in.Continuity.DistDen}, [3]uint64{8, 8, in.Pos.CadenceRounds}, [3]uint64{16, 8, in.Pos.CadenceSeconds}))
	e.set(vrschema.U64(vrElectionMaxBatchSlot), vrschema.U64(uint64(in.Limits.MaxBatch)))
	e.set(vrschema.U64(vrElectionReaderSlot), vrschema.AddrWord(reader))
	e.set(vrschema.U64(vrElectionHookCallerSlot), vrschema.AddrWord(vrGenesisAddress(7)))
	e.set(vrschema.U64(vrElectionRegistrySlot), vrschema.AddrWord(common.Address(vrschema.ValidatorRegistry)))
	e.set(vrschema.U64(vrElectionIndexLenSlot), vrschema.U64(uint64(len(in.Identities))))
	for i, id := range in.Identities {
		sid := uint64(i + 1)
		rootKey, err1 := vrHex("rootKey", id.RootKey, 33)
		evmKey, err2 := vrHex("evmKey", id.EVMKey, 33)
		payee, err3 := vrAddress("payee", id.Payee)
		if err := errors.Join(err1, err2, err3); err != nil {
			return nil, err
		}
		base := vrschema.MapSlot(vrschema.U64(1), vrschema.MapSlot(vrschema.U64(sid), vrschema.U64(vrElectionStagedSlot)))
		rootNode, evmNode := vrschema.Keccak([]byte(id.RootNodeID)), vrschema.Keccak([]byte(id.EVMNodeID))
		e.set(base, rootNode)
		e.bytesAt(vrschema.SlotAdd(base, 1), rootKey)
		e.set(vrschema.SlotAdd(base, 2), evmNode)
		e.bytesAt(vrschema.SlotAdd(base, 3), evmKey)
		e.set(vrschema.SlotAdd(base, 4), vrschema.AddrWord(payee))
		e.set(vrschema.SlotAdd(base, 5), vrschema.Keccak(wb(vrElectionBindingDomain), wb(vrschema.U64(sid)), wb(vrschema.U64(1)), wb(rootNode),
			wb(vrschema.Keccak(rootKey)), wb(evmNode), wb(vrschema.Keccak(evmKey)), wb(vrschema.AddrWord(payee))))
		e.set(vrschema.SlotAdd(base, 7), vrschema.Keccak(rootKey))
		e.set(vrschema.SlotAdd(base, 8), vrschema.Keccak(evmKey))
		// the live index: entry i is identity i+1 (four uint64 to a word), and the reverse position is 1-based
		entry := vrschema.SlotAdd(vrschema.Keccak(wb(vrschema.U64(vrElectionIndexLenSlot))), uint64(i)/4)
		cur := e[entry]
		cur = orWord(cur, packed([3]uint64{(uint64(i) % 4) * 8, 8, sid}))
		e.set(entry, cur)
		e.set(vrschema.MapSlot(vrschema.U64(sid), vrschema.U64(vrElectionPositionSlot)), vrschema.U64(sid))
	}
	return e, nil
}

func orWord(a, b vrschema.Word) vrschema.Word {
	for i := range a {
		a[i] |= b[i]
	}
	return a
}

// vrCheckPosElection compares the election's whole allocated storage with the one the plan derives (vrPosElectionExpected): a missing link (the
// eligibility reader included), index entry or key byte, and any extra slot, is refused.
func vrCheckPosElection(in vrGenesisInput, d vrDeploymentFile, network []byte, alloc map[common.Address]vrAllocAccount) error {
	election, err := vrAddress("PoS election", d.Election)
	if err != nil {
		return err
	}
	got, err := storageOf(alloc[election])
	if err != nil {
		return err
	}
	want, err := vrPosElectionExpected(in, d, network, got[vrschema.U64(1)])
	if err != nil {
		return err
	}
	if got[vrschema.U64(1)] == (vrschema.Word{}) {
		return fmt.Errorf("%w: the election has no manifest hash: it is not initialized", ErrVRGenesis)
	}
	if diffs := diffStorage("the PoS election", want, got); len(diffs) > 0 {
		return fmt.Errorf("%w: the election's storage is not the plan's: %s", ErrVRGenesis, strings.Join(diffs, "; "))
	}
	return nil
}

// vrElectionBindingDomain is ElectionPolicy.BINDING_DOMAIN.
var vrElectionBindingDomain = vrschema.Keccak([]byte("unicity.p85.delegation-binding"))

// wb is a word as a byte slice.
func wb(w vrschema.Word) []byte { return w[:] }

// ---- custody's entire planned genesis storage ----------------------------------------------------------------------------------------------

// Fixed by the PoS genesis script (VRPosGenesis.s.sol: the policy) and by the contracts (the genesis assignment's lineage and epochs); not choices of the plan.
const (
	vrCustodyLifetimeCapBps   = 500
	vrCustodyHoldRetirement   = 2_000
	vrCustodyTimeFloor        = 3_600
	vrCustodyPolicyID         = 1
	vrCustodyCatEncumbered    = 2
	vrCustodyStatusNotEntered = 1 // the reentrancy guard's rest value
)

var (
	vrGenesisLineage       = vrschema.Keccak([]byte("p85/lane/lineage"))
	vrCustodyChainDomain   = vrschema.Keccak([]byte("unicity.p85.exposure-chain"))
	vrCustodyExpoDigestDom = vrschema.Keccak([]byte("unicity.p85.exposure-digest"))
	vrCustodyKeyDigestDom  = vrschema.Keccak([]byte("unicity.p85.key-history-digest"))
)

// vrPosCustodyExpected derives custody's whole genesis storage from the plan, replaying CustodyGenesis.initialize, one seedGenesis per identity
// and sealGenesis: the wiring, the positions, the root and EVM key claims, one lot per identity (encumbered by its genesis exposure), the
// genesis assignment and its exposures with the VR member digests, the exposure digest and key digest, and the holder facts at the liability
// namespace. Nothing else is stored at genesis, so the allocated storage must equal it slot for slot. The manifest hash is the factory's hash of the
// whole manifest and is taken from the alloc (it must be present).
func vrPosCustodyExpected(in vrGenesisInput, d vrDeploymentFile, network []byte, manifestHash vrschema.Word) (vrStorage, error) {
	e := vrStorage{}
	addr := func(name, s string) (common.Address, error) { return vrAddress("PoS "+name, s) }
	election, err1 := addr("election", d.Election)
	evidence, err2 := addr("evidence", d.Evidence)
	policy, err3 := addr("policy", d.Policy)
	treasury, err4 := vrAddress("PoS treasury", in.Pos.Treasury)
	assignment, err5 := vrHex("assignment", in.Pos.AssignmentID, 32)
	bondUnit, ok := new(big.Int).SetString(in.Pos.BondUnit, 10)
	if err := errors.Join(err1, err2, err3, err4, err5); err != nil {
		return nil, err
	}
	if !ok || bondUnit.Sign() <= 0 {
		return nil, fmt.Errorf("%w: the plan's bond unit is not a positive decimal", ErrVRGenesis)
	}
	vr := common.Address(vrschema.ValidatorRegistry)
	chain := vrschema.U64(in.ChainID)
	net := vrschema.Word(network)
	asg := vrschema.Word(assignment)
	U := vrschema.U64
	A := vrschema.AddrWord
	e.set(U(0), U(vrCustodyStatusNotEntered))
	e.set(U(1), packed([3]uint64{0, 1, 1}, [3]uint64{1, 1, 1})) // genesisStarted, initialized
	e.set(U(2), asg)
	e.set(U(3), manifestHash)
	e.set(U(4), net)
	e.set(U(5), A(election))
	e.set(U(6), A(evidence))
	e.set(U(7), A(policy))
	e.set(U(8), A(common.Address(vrschema.SealRegistry)))
	e.set(U(9), A(treasury))
	// bondUnit and minBond (both the plan's unit) share a word: bondUnit low, minBond high
	var bw vrschema.Word
	put128(&bw, 0, bondUnit)
	put128(&bw, 16, bondUnit)
	e.set(U(10), bw)
	e.set(U(11), packed([3]uint64{0, 4, uint64(in.Limits.VMax)}, [3]uint64{4, 4, uint64(in.Limits.LMax)}, [3]uint64{8, 4, uint64(in.Limits.RMax)}, [3]uint64{12, 4, uint64(in.Limits.MaxBatch)}))
	n := uint64(len(in.Identities))
	e.set(U(12), U(n))
	e.set(U(13), U(n))
	e.set(U(14), asg)
	total := new(big.Int)
	compact := in.Limits.VMax > vrPosLegacyPool
	if compact {
		e.set(U(41), U(n))                        // _nextBinding
		e.set(vrschema.MapSlot(asg, U(44)), U(n)) // _seats[genesis]
	}
	// positions, keys, lots, exposures
	expoIDs := make([]vrschema.Word, 0, n)
	expoDigest, keyDigest := vrCustodyExpoDigestDom, vrCustodyKeyDigestDom
	nsB := vrschema.LiabilityNS
	for i, id := range in.Identities {
		sid := uint64(i + 1)
		owner, err1 := vrAddress("owner", id.Owner)
		payee, err2 := vrAddress("payee", id.Payee)
		rootKey, err3 := vrHex("rootKey", id.RootKey, 33)
		evmKey, err4 := vrHex("evmKey", id.EVMKey, 33)
		if err := errors.Join(err1, err2, err3, err4); err != nil {
			return nil, err
		}
		rootHash, evmHash := vrschema.Keccak(rootKey), vrschema.Keccak(evmKey)
		bond := new(big.Int).Mul(new(big.Int).SetUint64(id.RawWeight), bondUnit)
		if bond.BitLen() > 128 {
			return nil, fmt.Errorf("%w: identity %d's genesis bond %s does not fit a custody lot (uint128): bond unit %s x raw weight %d", ErrVRGenesis, sid, bond, bondUnit, id.RawWeight)
		}
		total.Add(total, bond)
		// positions[id]: owner, withdrawal (= owner), root key hash, staged (zero), then generation 1 / roleNonce 0 / openLots 1 / lotCount 1 / no retirement
		pos := vrschema.MapSlot(U(sid), U(22))
		e.set(pos, A(owner))
		e.set(vrschema.SlotAdd(pos, 1), A(owner))
		e.set(vrschema.SlotAdd(pos, 2), rootHash)
		e.set(vrschema.SlotAdd(pos, 4), packed([3]uint64{0, 8, 1}, [3]uint64{16, 4, 1}, [3]uint64{20, 4, 1}))
		// _keys[hash] = {id, role}
		e.set(vrschema.MapSlot(rootHash, U(25)), packed([3]uint64{0, 8, sid}, [3]uint64{8, 1, 1}))
		e.set(vrschema.MapSlot(evmHash, U(25)), packed([3]uint64{0, 8, sid}, [3]uint64{8, 1, 2}))
		// the lot (id = sid): moved to Encumbered by its genesis exposure
		lot := vrschema.MapSlot(U(sid), U(27))
		w0 := packed([3]uint64{0, 8, sid}, [3]uint64{8, 8, 1}) // id, generation 1; initial (uint128) above them
		put128(&w0, 16, bond)
		var w1 vrschema.Word // remaining (uint128) in the low half, penalized zero
		put128(&w1, 0, bond)
		e.set(lot, w0)
		e.set(vrschema.SlotAdd(lot, 1), w1)
		e.set(vrschema.SlotAdd(lot, 2), packed([3]uint64{0, 1, vrCustodyCatEncumbered}, [3]uint64{1, 2, vrCustodyLifetimeCapBps}, [3]uint64{3, 4, 1},
			[3]uint64{7, 8, vrCustodyHoldRetirement}, [3]uint64{15, 8, vrCustodyTimeFloor}))
		// _generationLots[id][1] = [lot]
		gl := vrschema.MapSlot(U(1), vrschema.MapSlot(U(sid), U(26)))
		e.set(gl, U(1))
		e.set(vrschema.BytesDataSlot(gl), U(sid))
		// the exposure at the genesis assignment, in the VR domain
		eid := vrschema.PoaExposureDigest(net, chain, vr, asg, sid)
		expoIDs = append(expoIDs, eid)
		if compact {
			binding := vrschema.MapSlot(U(sid), U(42))
			e.set(binding, packed([3]uint64{0, 8, sid}, [3]uint64{8, 8, 1}))
			e.set(vrschema.SlotAdd(binding, 1), vrschema.Keccak([]byte(id.RootNodeID)))
			e.set(vrschema.SlotAdd(binding, 2), rootHash)
			e.set(vrschema.SlotAdd(binding, 3), vrschema.Keccak([]byte(id.EVMNodeID)))
			e.set(vrschema.SlotAdd(binding, 4), evmHash)
			e.set(vrschema.SlotAdd(binding, 5), A(payee))
			e.set(vrschema.MapSlot(U(1), vrschema.MapSlot(U(sid), U(43))), U(sid))
			row := vrschema.SlotAdd(vrschema.BytesDataSlot(vrschema.MapSlot(asg, U(44))), uint64(i))
			e.set(row, packed([3]uint64{0, 8, sid}, [3]uint64{8, 8, sid}, [3]uint64{16, 8, id.RawWeight}, [3]uint64{24, 8, id.RawWeight}))
		} else {
			ex := vrschema.MapSlot(eid, U(33))
			e.set(ex, asg)
			e.set(vrschema.SlotAdd(ex, 1), packed([3]uint64{0, 8, sid}, [3]uint64{8, 8, 1}, [3]uint64{16, 8, id.RawWeight}, [3]uint64{24, 8, id.RawWeight}))
			e.set(vrschema.SlotAdd(ex, 2), rootHash)
			e.set(vrschema.SlotAdd(ex, 3), evmHash)
			w4 := vrschema.Word{}
			addrAt(&w4, 0, payee)
			e.set(vrschema.SlotAdd(ex, 4), w4)
			e.set(vrschema.SlotAdd(ex, 5), U(1))
			e.set(vrschema.BytesDataSlot(vrschema.SlotAdd(ex, 5)), U(sid))
			e.set(vrschema.MapSlot(U(sid), vrschema.MapSlot(eid, U(34))), U(1)) // _exposureHasLot[eid][lot]
		}
		// the exposure chain of (id, 1) and the holder facts
		chainWord := vrschema.Keccak(wb(vrCustodyChainDomain), zeroWordBytes(), wb(eid))
		if !compact {
			e.set(vrschema.MapSlot(U(1), vrschema.MapSlot(U(sid), U(29))), chainWord)
			e.set(vrschema.MapSlot(U(1), vrschema.MapSlot(U(sid), U(31))), U(1))
		}
		f := vrschema.MapSlot(U(1), vrschema.MapSlot(U(sid), vrschema.SlotAdd(nsB, 1)))
		e.set(f, packed([3]uint64{1, 4, 1}, [3]uint64{5, 4, 1}))
		e.set(vrschema.SlotAdd(f, 1), chainWord)
		// the member digest of the VR domain: VR's seat digest over GENESIS_RESULT
		member := vrschema.PoaExposureDigest(net, chain, vr, vrschema.GenesisResult, sid)
		if !compact {
			e.set(vrschema.MapSlot(eid, U(40)), member)
		}
		expoDigest = vrschema.Keccak(wb(expoDigest), wb(eid), wb(U(sid)), wb(U(id.RawWeight)), wb(U(id.RawWeight)), wb(A(payee)), wb(member))
		keyDigest = vrschema.Keccak(wb(keyDigest), wb(U(sid)), wb(rootHash), wb(evmHash))
		_ = owner
	}
	e.set(U(18), wordOfBig(total)) // totalEncumbered: every genesis lot is encumbered
	e.set(U(39), A(vr))
	// the genesis assignment
	a := vrschema.MapSlot(asg, U(32))
	e.set(a, U(2)) // Active
	e.set(vrschema.SlotAdd(a, 1), vrGenesisLineage)
	e.set(vrschema.SlotAdd(a, 2), packed([3]uint64{0, 8, 1}, [3]uint64{8, 8, 1}, [3]uint64{24, 8, 1})) // rootEpoch 1, evmEpoch 1, firstRound 1 (offset 0)
	e.set(vrschema.SlotAdd(a, 3), packed([3]uint64{0, 1, 1}))                                          // offsetSet
	e.set(vrschema.SlotAdd(a, 5), expoDigest)
	e.set(vrschema.SlotAdd(a, 6), keyDigest)
	e.set(vrschema.SlotAdd(a, 7), U(vrCustodyPolicyID))
	if !compact {
		e.set(vrschema.SlotAdd(a, 8), U(uint64(len(expoIDs))))
		for i, eid := range expoIDs {
			e.set(vrschema.SlotAdd(vrschema.BytesDataSlot(vrschema.SlotAdd(a, 8)), uint64(i)), eid)
		}
	}
	return e, nil
}

func zeroWordBytes() []byte { return make([]byte, 32) }

// put128 writes a uint128 at the byte offset off of a packed word.
func put128(w *vrschema.Word, off int, b *big.Int) {
	b.FillBytes(w[32-off-16 : 32-off])
}

func wordOfBig(b *big.Int) vrschema.Word {
	var w vrschema.Word
	b.FillBytes(w[:])
	return w
}

// vrCheckPosCustody compares custody's whole allocated storage with the one the plan derives (vrPosCustodyExpected): a cleared `initialized`, a
// member digest, a lot, the record cursor or any other slot that differs, and any extra slot, is refused.
func vrCheckPosCustody(in vrGenesisInput, d vrDeploymentFile, network []byte, alloc map[common.Address]vrAllocAccount) error {
	custody, err := vrAddress("PoS custody", d.Custody)
	if err != nil {
		return err
	}
	got, err := storageOf(alloc[custody])
	if err != nil {
		return err
	}
	if got[vrschema.U64(3)] == (vrschema.Word{}) {
		return fmt.Errorf("%w: custody has no manifest hash: it is not initialized", ErrVRGenesis)
	}
	want, err := vrPosCustodyExpected(in, d, network, got[vrschema.U64(3)])
	if err != nil {
		return err
	}
	if diffs := diffStorage("custody", want, got); len(diffs) > 0 {
		return fmt.Errorf("%w: custody's storage is not the plan's: %s", ErrVRGenesis, strings.Join(diffs, "; "))
	}
	return nil
}
