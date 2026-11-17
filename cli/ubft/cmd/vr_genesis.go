package cmd

// The genesis plan of a validator-registry (VR) generation (VT-14, ristik/bft-core#1158; design section 2.1 "Genesis consistency"). One
// plan produces every artifact of the generation, and `verify` refuses any mismatch between them:
//
//   - the VR alloc (unicity-pos-contracts script/vr-genesis.sh over the input `plan` writes): identities 1..n, the committee in force,
//     governor = FoundationMultisig 3-of-5, the PoA module, limits and fees, the three facet accounts, PoaElection and its composer;
//   - the roots' --genesis-identities, StakingID = the VR id as a 32-byte big-endian word (so evmassign.CustodyID holds);
//   - the EVM PDR pins (validator_registry, validator_registry_code_hash), which the roots also read to start in VR mode;
//   - the B1 profile with both hooks on VR (engine-api b1-profile --vr-hook-measurement), and the ureth flags it prints;
//   - the roots' --vr-deployment, written by `verify` once everything agrees.
//
// The order is fixed by what each step needs: the measurement (ureth tests/vr_hook.rs, at the genesis addresses) gives the VR and module
// code hashes the PDR pins before anything is deployed; the profile gives the generation's MaxGas and SystemGas, which VR's fee
// configuration repeats; the plan gives the contracts input and the root identities; the contracts give the alloc; `engine-api genesis`
// folds it into the EVM genesis; `verify` checks the finished set.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/weightcap"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/posclosure"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrVRGenesis reports a genesis artifact that disagrees with the plan or with another artifact.
var ErrVRGenesis = errors.New("VR genesis plan")

const (
	vrInputFormat      = "unicity.vr.genesis-input.v1"
	vrDeploymentFormat = "unicity.vr.deployment.v1"
	vrRootDeployFormat = "unicity.vr.root-deployment.v1"
)

// The genesis accounts of a VR generation (owner-questions "VT-02 ureth hook test" default; the multisig at 0xff..09 is the VT-14
// default). VR's runtime carries the facets' addresses and code hashes, the facets their own address and PoaElection VR's and the
// composer's: the code hashes are defined only for these addresses.
var vrGenesisAccounts = []struct {
	role string
	low  byte
}{{"registry", 3}, {"governanceFacet", 4}, {"repairFacet", 5}, {"recordsFacet", 6}, {"module", 7}, {"composer", 8}, {"governor", 9}}

func vrGenesisAddress(low byte) common.Address {
	var a common.Address
	a[0], a[19] = 0xff, low
	return a
}

type vrInputLimits struct {
	NMin     uint32 `json:"nMin"`
	NTarget  uint32 `json:"nTarget"`
	NMax     uint32 `json:"nMax"`
	VMax     uint32 `json:"vMax"`
	LMax     uint32 `json:"lMax"`
	RMax     uint32 `json:"rMax"`
	MaxBatch uint32 `json:"maxBatch"`
}

type vrInputFees struct {
	BaseFeeFloor      uint64 `json:"baseFeeFloor"`
	ChangeDenominator uint64 `json:"changeDenominator"`
	FeeCollector      string `json:"feeCollector"`
}

type vrInputContinuity struct {
	MaxM    uint64 `json:"maxM"`
	DistNum uint64 `json:"distNum"`
	DistDen uint64 `json:"distDen"`
}

type vrInputIdentity struct {
	ID         uint64 `json:"id"`
	Owner      string `json:"owner"`
	RootNodeID string `json:"rootNodeID"`
	RootKey    string `json:"rootKey"`
	EVMNodeID  string `json:"evmNodeID"`
	EVMKey     string `json:"evmKey"`
	Payee      string `json:"payee"`
	RawWeight  uint64 `json:"rawWeight"`
}

// vrGenesisInput is the contracts genesis input (script/VRGenesis.s.sol reads exactly these fields).
type vrGenesisInput struct {
	Format             string            `json:"format"`
	ChainID            uint64            `json:"chainId"`
	Network            string            `json:"network"`
	GovernorSigners    []string          `json:"governorSigners"`
	Limits             vrInputLimits     `json:"limits"`
	KnownRootEpoch     uint64            `json:"knownRootEpoch"`
	EpochStartProgress uint64            `json:"epochStartProgress"`
	Fees               vrInputFees       `json:"fees"`
	MaxGas             uint64            `json:"maxGas"`
	SystemGas          uint64            `json:"systemGas"`
	Continuity         vrInputContinuity `json:"continuity"`
	IdentityCount      int               `json:"identityCount"`
	Identities         []vrInputIdentity `json:"identities"`
}

// vrOwner is one identity's owner and payee (the --owners file, in id order).
type vrOwner struct {
	Owner string `json:"owner"`
	Payee string `json:"payee"`
}

// vrRootDeployment is the roots' --vr-deployment: the generation's vradmit.Deployment and the SealRegistry pins of its witnesses.
type vrRootDeployment struct {
	Format           string `json:"format"`
	RootNetwork      uint64 `json:"rootNetwork"`
	NetworkWord      string `json:"networkWord"`
	ChainID          uint64 `json:"chainId"`
	Registry         string `json:"registry"`
	RegistryCodeHash string `json:"registryCodeHash"`
	SealRegistry     string `json:"sealRegistry"`
	SealRegistryCode string `json:"sealRegistryCodeHash"`
}

func vrStrictJSON(path string, v any) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: decoding %q: %v", ErrVRGenesis, path, err)
	}
	return nil
}

func vrHex(name, s string, n int) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") || len(s) != 2+2*n {
		return nil, fmt.Errorf("%w: %s %q is not 0x-prefixed hex of %d bytes", ErrVRGenesis, name, s, n)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrVRGenesis, name, err)
	}
	return b, nil
}

func vrAddress(name, s string) (common.Address, error) {
	if !common.IsHexAddress(s) || !strings.HasPrefix(s, "0x") {
		return common.Address{}, fmt.Errorf("%w: %s %q is not an address", ErrVRGenesis, name, s)
	}
	return common.HexToAddress(s), nil
}

func lowerHex(b []byte) string { return "0x" + hex.EncodeToString(b) }

// devAddress is a DEV owner or payee nobody holds a key for, derived from the root node id (as the P85 lane derives its owners).
func devAddress(domain, nodeID string) string {
	h := ethcrypto.Keccak256([]byte(domain), []byte(nodeID))
	return strings.ToLower(common.BytesToAddress(h[12:]).Hex())
}

// vrPlanInput is everything `plan` derives from: the root trust base, the coupled base EVM shard configuration, the root-to-EVM bindings,
// the profile and the governance and fee choices.
type vrPlanInput struct {
	tb              *types.RootTrustBaseV1
	conf            *types.PartitionDescriptionRecord
	bindings        []evmassign.Binding
	owners          []vrOwner
	profile         b1state.Profile
	network         [32]byte
	governorSigners []string
	limits          vrInputLimits
	fees            vrInputFees
}

// vrPlan builds the contracts input and the roots' genesis identity records. Ids are assigned 1..n in ascending root node id (the order
// the bindings are read in); every genesis identity is a member with its trust-base stake as raw weight.
func vrPlan(in vrPlanInput) (vrGenesisInput, []evmassign.Identity, error) {
	var out vrGenesisInput
	if v, set := in.conf.PartitionParams[evmassign.CouplingParam]; set && v != "true" {
		return out, nil, fmt.Errorf("%w: the EVM shard configuration refuses coupled changes (%s=%s)", ErrVRGenesis, evmassign.CouplingParam, v)
	}
	if _, _, ok, err := vrstate.PinsFromPDR(in.conf); err != nil || !ok {
		return out, nil, fmt.Errorf("%w: the EVM shard configuration does not pin VR (validator_registry, validator_registry_code_hash): %v", ErrVRGenesis, err)
	}
	chainID, ok := zkverifier.ParseChainIDFromParams(in.conf.PartitionParams)
	if !ok || chainID != in.profile.ExecutionChainID {
		return out, nil, fmt.Errorf("%w: the shard configuration's chain id is not the profile's %d", ErrVRGenesis, in.profile.ExecutionChainID)
	}
	if !in.profile.HookEnabled() || in.profile.RecordsCustody != vrschema.ValidatorRegistry || in.profile.ElectionContract != vrschema.ValidatorRegistry {
		return out, nil, fmt.Errorf("%w: the profile's hooks are not both on VR (engine-api b1-profile --vr-hook-measurement)", ErrVRGenesis)
	}
	if len(in.governorSigners) != 5 {
		return out, nil, fmt.Errorf("%w: the FoundationMultisig takes exactly 5 signers, got %d", ErrVRGenesis, len(in.governorSigners))
	}
	seen := map[common.Address]bool{}
	for i, s := range in.governorSigners {
		a, err := vrAddress(fmt.Sprintf("governor signer %d", i+1), s)
		if err != nil {
			return out, nil, err
		}
		if a == (common.Address{}) || seen[a] {
			return out, nil, fmt.Errorf("%w: governor signers must be distinct nonzero addresses", ErrVRGenesis)
		}
		seen[a] = true
		in.governorSigners[i] = strings.ToLower(a.Hex())
	}
	// FoundationMultisig takes its signers strictly ascending (a set): the plan orders them
	sort.Strings(in.governorSigners)
	l := in.limits
	if l.NMin < 1 || l.NMin > l.NTarget || l.NTarget > l.NMax || l.NMax > vrschema.MaxCommittee || l.MaxBatch < in.profile.HRecords || l.MaxBatch > b1state.HookMaxRecords {
		return out, nil, fmt.Errorf("%w: limits need 1 <= nMin <= nTarget <= nMax <= 16 and H <= maxBatch <= 32", ErrVRGenesis)
	}
	collector, err := vrAddress("fee collector", in.fees.FeeCollector)
	if err != nil {
		return out, nil, err
	}
	in.fees.FeeCollector = strings.ToLower(collector.Hex())
	policy, err := storage.ContinuityPolicy(in.conf)
	if err != nil {
		return out, nil, errors.Join(ErrVRGenesis, err)
	}
	roots := map[string]evmassign.RootMember{}
	for _, m := range genesisCommittee(in.tb) {
		roots[m.NodeID] = m
	}
	evms := map[string]*types.NodeInfo{}
	for _, v := range in.conf.Validators {
		evms[v.NodeID] = v
	}
	bindings := append([]evmassign.Binding(nil), in.bindings...)
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].RootNodeID < bindings[j].RootNodeID })
	if in.owners != nil && len(in.owners) != len(bindings) {
		return out, nil, fmt.Errorf("%w: %d owners for %d identities", ErrVRGenesis, len(in.owners), len(bindings))
	}
	raw := make([]uint64, len(bindings))
	for i, b := range bindings {
		r, okR := roots[b.RootNodeID]
		if !okR {
			return out, nil, fmt.Errorf("%w: binding %q names no genesis root", ErrVRGenesis, b.RootNodeID)
		}
		raw[i] = r.Weight
	}
	q, _, err := evmassign.Quantize(raw, weightcap.B)
	if err != nil {
		return out, nil, errors.Join(ErrVRGenesis, err)
	}
	network := vrschema.Word(in.network)
	chainWord := vrschema.U64(chainID)
	ids := make([]evmassign.Identity, 0, len(bindings))
	out = vrGenesisInput{Format: vrInputFormat, ChainID: chainID, Network: lowerHex(in.network[:]), GovernorSigners: in.governorSigners, Limits: l,
		KnownRootEpoch: in.tb.Epoch, Fees: in.fees, MaxGas: in.profile.MaxGas, SystemGas: in.profile.SystemGas,
		Continuity: vrInputContinuity{MaxM: policy.MaxM, DistNum: policy.MaxDistNum, DistDen: policy.MaxDistDen}, IdentityCount: len(bindings)}
	for i, b := range bindings {
		r := roots[b.RootNodeID]
		v, okE := evms[b.EVMNodeID]
		if !okE {
			return out, nil, fmt.Errorf("%w: binding %q -> %q names no genesis EVM validator", ErrVRGenesis, b.RootNodeID, b.EVMNodeID)
		}
		if q[i] != r.Weight {
			return out, nil, fmt.Errorf("%w: root %q weighs %d in the trust base but quantizes to %d in VR", ErrVRGenesis, b.RootNodeID, r.Weight, q[i])
		}
		id := uint64(i + 1)
		owner, payee := devAddress("unicity.vr.dev-owner/", b.RootNodeID), devAddress("unicity.vr.dev-payee/", b.RootNodeID)
		if in.owners != nil {
			o, errO := vrAddress("owner", in.owners[i].Owner)
			p, errP := vrAddress("payee", in.owners[i].Payee)
			if err := errors.Join(errO, errP); err != nil {
				return out, nil, err
			}
			owner, payee = strings.ToLower(o.Hex()), strings.ToLower(p.Hex())
		}
		out.Identities = append(out.Identities, vrInputIdentity{ID: id, Owner: owner, RootNodeID: r.NodeID, RootKey: lowerHex(r.Key),
			EVMNodeID: v.NodeID, EVMKey: lowerHex(v.SigKey), Payee: payee, RawWeight: raw[i]})
		exposure := vrschema.PoaExposureDigest(network, chainWord, vrschema.ValidatorRegistry, vrschema.GenesisResult, id)
		staking := vrschema.U64(id)
		ids = append(ids, evmassign.Identity{StakingID: staking[:], Generation: 1, RootNodeID: r.NodeID, RootKey: bytes.Clone(r.Key),
			EVMNodeID: v.NodeID, EVMKey: bytes.Clone(v.SigKey), Weight: q[i], RawWeight: raw[i], OperatorPayee: common.HexToAddress(payee).Bytes(),
			ExposureDigest: exposure[:]})
	}
	if err := checkGenesisIdentities(ids, in.tb, in.conf); err != nil {
		return out, nil, errors.Join(ErrVRGenesis, err)
	}
	return out, ids, nil
}

// vrDeploymentFile is what script/vr-genesis.sh writes next to the alloc.
type vrDeploymentFile struct {
	Format                  string `json:"format"`
	ChainID                 uint64 `json:"chainId"`
	NetworkWord             string `json:"networkWord"`
	Registry                string `json:"registry"`
	RegistryCodeHash        string `json:"registryCodeHash"`
	GovernanceFacet         string `json:"governanceFacet"`
	GovernanceFacetCodeHash string `json:"governanceFacetCodeHash"`
	RepairFacet             string `json:"repairFacet"`
	RepairFacetCodeHash     string `json:"repairFacetCodeHash"`
	RecordsFacet            string `json:"recordsFacet"`
	RecordsFacetCodeHash    string `json:"recordsFacetCodeHash"`
	Module                  string `json:"module"`
	ModuleCodeHash          string `json:"moduleCodeHash"`
	ModuleTag               string `json:"moduleTag"`
	Composer                string `json:"composer"`
	ComposerCodeHash        string `json:"composerCodeHash"`
	Governor                string `json:"governor"`
	GovernorCodeHash        string `json:"governorCodeHash"`
	CommitteeDigest         string `json:"committeeDigest"`
	LastAcked               string `json:"lastAcked"`
	IdentityCount           uint64 `json:"identityCount"`
	Members                 uint64 `json:"members"`
}

func (d vrDeploymentFile) accounts() map[string][2]string {
	return map[string][2]string{"registry": {d.Registry, d.RegistryCodeHash}, "governanceFacet": {d.GovernanceFacet, d.GovernanceFacetCodeHash},
		"repairFacet": {d.RepairFacet, d.RepairFacetCodeHash}, "recordsFacet": {d.RecordsFacet, d.RecordsFacetCodeHash},
		"module": {d.Module, d.ModuleCodeHash}, "composer": {d.Composer, d.ComposerCodeHash}, "governor": {d.Governor, d.GovernorCodeHash}}
}

type vrAllocAccount struct {
	Code    string            `json:"code"`
	Storage map[string]string `json:"storage"`
	Balance string            `json:"balance"`
	Nonce   string            `json:"nonce"`
}

// vrAllocSlots is the storage of one alloc account as an evmstate slot reader (absent slots are zero).
type vrAllocSlots map[vrschema.Word]vrschema.Word

func (s vrAllocSlots) Word(slot vrschema.Word) (vrschema.Word, error) { return s[slot], nil }

func vrAllocAccounts(genesisPath string) (map[common.Address]vrAllocAccount, error) {
	raw, err := os.ReadFile(genesisPath) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, err
	}
	var g struct {
		Alloc map[string]vrAllocAccount `json:"alloc"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, fmt.Errorf("%w: decoding the EVM genesis %q: %v", ErrVRGenesis, genesisPath, err)
	}
	out := map[common.Address]vrAllocAccount{}
	for k, v := range g.Alloc {
		if !common.IsHexAddress(k) {
			return nil, fmt.Errorf("%w: alloc key %q", ErrVRGenesis, k)
		}
		out[common.HexToAddress(k)] = v
	}
	return out, nil
}

func vrSlots(a vrAllocAccount) (vrAllocSlots, error) {
	out := vrAllocSlots{}
	for k, v := range a.Storage {
		kb, ok1 := new(big.Int).SetString(strings.TrimPrefix(k, "0x"), 16)
		vb, ok2 := new(big.Int).SetString(strings.TrimPrefix(v, "0x"), 16)
		if !ok1 || !ok2 || kb.BitLen() > 256 || vb.BitLen() > 256 {
			return nil, fmt.Errorf("%w: storage entry %q: %q", ErrVRGenesis, k, v)
		}
		var kw, vw vrschema.Word
		kb.FillBytes(kw[:])
		vb.FillBytes(vw[:])
		out[kw] = vw
	}
	return out, nil
}

// inertCode reports whether code has no opcode that calls, creates, delegates, self-destructs or writes storage (PUSH data skipped): the
// composer engine is a stateless pure contract, and PoaElection's code hash commits to its address only (owner-questions "Two contracts").
func inertCode(code []byte) bool {
	for i := 0; i < len(code); i++ {
		op := code[i]
		if op >= 0x60 && op <= 0x7f {
			i += int(op - 0x5f)
			continue
		}
		switch op {
		case 0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xff, 0x55:
			return false
		}
	}
	return true
}

// vrVerifyInput is the finished set `verify` checks.
type vrVerifyInput struct {
	input        vrGenesisInput
	deployment   vrDeploymentFile
	alloc        map[common.Address]vrAllocAccount
	full         *types.PartitionDescriptionRecord
	tb           *types.RootTrustBaseV1
	profile      b1state.Profile
	profileFile  b1ProfileFile
	identities   []evmassign.Identity
	fresh        b1state.VRHookMeasurement
	urethFlags   string // optional: the ureth command line to check
	feeCollector string // optional: the shard nodes' --engine-fee-collector
}

// vrVerify cross-checks every artifact of the generation and returns the roots' deployment file.
func vrVerify(v vrVerifyInput) (vrRootDeployment, error) {
	var out vrRootDeployment
	fail := func(format string, a ...any) (vrRootDeployment, error) {
		return out, fmt.Errorf("%w: "+format, append([]any{ErrVRGenesis}, a...)...)
	}
	in, d := v.input, v.deployment
	if in.Format != vrInputFormat || d.Format != vrDeploymentFormat {
		return fail("unknown input or deployment format")
	}

	// 1. the alloc holds exactly the deployment's seven accounts at their genesis addresses, with the recorded code
	accounts := d.accounts()
	hashes := map[string][32]byte{}
	for _, a := range vrGenesisAccounts {
		rec := accounts[a.role]
		addr, err := vrAddress(a.role, rec[0])
		if err != nil {
			return out, err
		}
		if addr != vrGenesisAddress(a.low) {
			return fail("%s is at %s, not its genesis address %s", a.role, addr, vrGenesisAddress(a.low))
		}
		acct, ok := v.alloc[addr]
		if !ok {
			return fail("the EVM genesis has no %s account at %s", a.role, addr)
		}
		code, err := hex.DecodeString(strings.TrimPrefix(acct.Code, "0x"))
		if err != nil || len(code) == 0 {
			return fail("%s has no code in the EVM genesis", a.role)
		}
		want, err := vrHex(a.role+" code hash", strings.ToLower(rec[1]), 32)
		if err != nil {
			return out, err
		}
		if got := ethcrypto.Keccak256(code); !bytes.Equal(got, want) {
			return fail("%s code in the EVM genesis hashes to %x, the deployment records %x", a.role, got, want)
		}
		hashes[a.role] = [32]byte(want)
		if a.role == "composer" {
			slots, err := vrSlots(acct)
			if err != nil {
				return out, err
			}
			for _, w := range slots {
				if w != (vrschema.Word{}) {
					return fail("the composer engine has storage: it is not the stateless engine")
				}
			}
			if !inertCode(code) {
				return fail("the composer engine can call, create, delegate, self-destruct or write storage: it may be a proxy")
			}
		}
	}

	// 2. the measurement the profile was pinned from, and a fresh one, are of exactly this code, and still cover the pins
	if v.profileFile.VRHookMeasurement == nil {
		return fail("the B1 profile carries no VR hook measurement")
	}
	if err := b1state.CheckVRHookGasFresh(v.profile, hashes["registry"], hashes["module"], *v.profileFile.VRHookMeasurement, v.fresh); err != nil {
		return out, errors.Join(ErrVRGenesis, err)
	}

	// 3. the EVM PDR pins VR, and the roots derive VR mode with the genesis committee from it
	registry, code, ok, err := vrstate.PinsFromPDR(v.full)
	if err != nil || !ok {
		return fail("the EVM shard configuration does not pin VR: %v", err)
	}
	if code != hashes["registry"] || registry != vrschema.ValidatorRegistry {
		return fail("the EVM PDR pins VR code %x, the alloc carries %x", code, hashes["registry"])
	}
	if !evmassign.CouplingRequired(v.full) || len(v.full.Validators) != in.IdentityCount {
		return fail("the coupled EVM shard has %d validators for %d genesis identities", len(v.full.Validators), in.IdentityCount)
	}

	// 4. the profile and the input agree on the chain, the gas envelope and the hooks
	chainID, ok := zkverifier.ParseChainIDFromParams(v.full.PartitionParams)
	if !ok || chainID != in.ChainID || in.ChainID != d.ChainID || v.profile.ExecutionChainID != in.ChainID {
		return fail("the chain id differs between the shard configuration, the input, the deployment and the profile")
	}
	if v.profile.MaxGas != in.MaxGas || v.profile.SystemGas != in.SystemGas {
		return fail("VR's fee configuration (maxGas %d, systemGas %d) is not the profile's (%d, %d)", in.MaxGas, in.SystemGas, v.profile.MaxGas, v.profile.SystemGas)
	}
	if in.Limits.MaxBatch < v.profile.HRecords {
		return fail("VR's maxBatch %d is below the profile's H %d", in.Limits.MaxBatch, v.profile.HRecords)
	}
	if v.profile.Network != uint16(v.tb.NetworkID) || uint64(v.full.NetworkID) != uint64(v.tb.NetworkID) {
		return fail("the profile, the shard configuration and the trust base name different networks")
	}

	// 5. VR's storage is the plan's: network word, limits, status, module, governor, counters, fees
	vrAcct := v.alloc[common.Address(vrschema.ValidatorRegistry)]
	slots, err := vrSlots(vrAcct)
	if err != nil {
		return out, err
	}
	r := vrstate.Reader{W: slots}
	network, err := vrHex("network", in.Network, 32)
	if err != nil {
		return out, err
	}
	if w, _ := r.Scalar(vrschema.SlotNetwork); !bytes.Equal(w[:], network) || !strings.EqualFold(d.NetworkWord, in.Network) {
		return fail("VR's network word is not the plan's")
	}
	if w, _ := r.Scalar(vrschema.SlotLastAcked); w != vrschema.GenesisResult {
		return fail("VR's lastAcked is not GENESIS_RESULT")
	}
	for _, k := range []uint64{vrschema.SlotOpenOutput, vrschema.SlotPendingPair} {
		if w, _ := r.Scalar(k); w != (vrschema.Word{}) {
			return fail("VR starts with an open output or a pending pair")
		}
	}
	limits, err := r.CommitteeLimits()
	if err != nil || limits.NMin != in.Limits.NMin || limits.NTarget != in.Limits.NTarget || limits.NMax != in.Limits.NMax {
		return fail("VR's committee limits are not the plan's")
	}
	status, err := r.Status()
	if err != nil || status.Health != 0 || status.KnownRootEpoch != in.KnownRootEpoch || status.RecordCursor != 0 || in.KnownRootEpoch != v.tb.Epoch {
		return fail("VR's status (health, knownRootEpoch, cursor) is not the genesis one")
	}
	word := func(k uint64) vrschema.Word { w, _ := r.Scalar(k); return w }
	if a := word(vrschema.SlotActiveModule); !bytes.Equal(a[12:], vrGenesisAddress(7).Bytes()) || word(vrschema.SlotActiveModuleHash) != hashes["module"] {
		return fail("VR's active module is not the PoA module with its recorded code hash")
	}
	if a := word(vrschema.SlotGovernor); !bytes.Equal(a[12:], vrGenesisAddress(9).Bytes()) {
		return fail("VR's governor is not the FoundationMultisig")
	}
	if c := word(vrschema.SlotCounters); c == (vrschema.Word{}) || d.IdentityCount != uint64(in.IdentityCount) || d.Members != uint64(len(v.identities)) {
		return fail("VR's identity count is not the plan's")
	}
	collector, err := vrAddress("fee collector", in.Fees.FeeCollector)
	if err != nil {
		return out, err
	}
	for _, k := range []uint64{vrschema.SlotFeesPrevCollect, vrschema.SlotFeesCurCollect} {
		if a := word(k); !bytes.Equal(a[12:], collector.Bytes()) {
			return fail("VR's fee collector is not the plan's")
		}
	}
	if v.feeCollector != "" {
		if c, err := vrAddress("--fee-collector", v.feeCollector); err != nil || c != collector {
			return fail("the shard nodes' fee collector %s is not VR's %s", v.feeCollector, collector)
		}
	}

	// 6. the roots' genesis identities are VR's genesis committee, StakingID = the VR id word, and the coupled genesis
	if len(v.identities) != in.IdentityCount {
		return fail("%d root genesis identities for %d VR identities", len(v.identities), in.IdentityCount)
	}
	for i, id := range v.identities {
		want := vrschema.U64(uint64(i + 1))
		if !bytes.Equal(id.StakingID, want[:]) || id.Generation != 1 {
			return fail("genesis identity %d is not VR id %d at generation 1 as a 32-byte big-endian StakingID", i, i+1)
		}
		p := in.Identities[i]
		if p.ID != uint64(i+1) || p.RootNodeID != id.RootNodeID || p.EVMNodeID != id.EVMNodeID || !strings.EqualFold(p.RootKey, lowerHex(id.RootKey)) ||
			!strings.EqualFold(p.EVMKey, lowerHex(id.EVMKey)) || !strings.EqualFold(p.Payee, lowerHex(id.OperatorPayee)) || p.RawWeight != id.RawWeight {
			return fail("genesis identity %d differs from VR identity %d", i, i+1)
		}
	}
	digest, err := vradmit.MembersDigestOf(v.identities)
	if err != nil {
		return out, errors.Join(ErrVRGenesis, err)
	}
	committee, err := vrHex("committeeDigest", strings.ToLower(d.CommitteeDigest), 32)
	if err != nil {
		return out, err
	}
	if !bytes.Equal(digest[:], committee) {
		return fail("the roots' genesis identities are not VR's genesis committee (membersDigest %x, VR %x)", digest, committee)
	}
	if err := checkGenesisIdentities(v.identities, v.tb, v.full); err != nil {
		return out, errors.Join(ErrVRGenesis, err)
	}

	// 7. the ureth command line pins the paired client to this profile
	if v.urethFlags != "" {
		hash, err := v.profile.Hash()
		if err != nil {
			return out, errors.Join(ErrVRGenesis, err)
		}
		for _, f := range strings.Fields(urethFlags(v.profile, hash)) {
			if !containsField(v.urethFlags, f) {
				return fail("the ureth flags lack %s", f)
			}
		}
		for flag, want := range map[string]uint64{"--unicity.base-fee-floor": in.Fees.BaseFeeFloor, "--unicity.base-fee-change-denominator": in.Fees.ChangeDenominator} {
			got := urethDefault(v.urethFlags, flag)
			if got != want {
				return fail("ureth's %s is %d, VR's genesis fee is %d", flag, got, want)
			}
		}
	}

	sealCode, err := vrHex("SealRegistry code hash", b1registry.CodeHashHex, 32)
	if err != nil {
		return out, err
	}
	if !bytes.Equal(v.profile.RuntimeHash[:], sealCode) {
		return fail("the profile pins another SealRegistry runtime")
	}
	vrCode := hashes["registry"]
	return vrRootDeployment{Format: vrRootDeployFormat, RootNetwork: uint64(v.tb.NetworkID), NetworkWord: strings.ToLower(in.Network), ChainID: in.ChainID,
		Registry: lowerHex(vrschema.ValidatorRegistry[:]), RegistryCodeHash: lowerHex(vrCode[:]), SealRegistry: lowerHex(vrschema.SealRegistry[:]),
		SealRegistryCode: lowerHex(sealCode)}, nil
}

func containsField(line, field string) bool {
	for _, f := range strings.Fields(line) {
		if f == field {
			return true
		}
	}
	return false
}

// urethDefault is the value of a --flag=N in the ureth command line, or ureth's default (block.rs PROFILE: floor 1,000,000, denominator 8).
func urethDefault(line, flag string) uint64 {
	defaults := map[string]uint64{"--unicity.base-fee-floor": 1_000_000, "--unicity.base-fee-change-denominator": 8}
	for _, f := range strings.Fields(line) {
		if v, ok := strings.CutPrefix(f, flag+"="); ok {
			n, ok := new(big.Int).SetString(v, 10)
			if !ok || !n.IsUint64() {
				return 0
			}
			return n.Uint64()
		}
	}
	return defaults[flag]
}

// loadVRRootDeployment reads the roots' --vr-deployment and binds it to the genesis EVM PDR the root runs with.
func loadVRRootDeployment(path string, rootNetwork uint64, shardConfs []*types.PartitionDescriptionRecord) (vradmit.Deployment, vrstate.Pins, error) {
	var dep vradmit.Deployment
	var pins vrstate.Pins
	var f vrRootDeployment
	if err := vrStrictJSON(path, &f); err != nil {
		return dep, pins, err
	}
	if f.Format != vrRootDeployFormat || f.RootNetwork != rootNetwork || f.ChainID == 0 {
		return dep, pins, fmt.Errorf("%w: %q is not a VR root deployment of root network %d", ErrVRGenesis, path, rootNetwork)
	}
	word, err1 := vrHex("networkWord", f.NetworkWord, 32)
	reg, err2 := vrHex("registry", f.Registry, 20)
	code, err3 := vrHex("registryCodeHash", f.RegistryCodeHash, 32)
	seal, err4 := vrHex("sealRegistry", f.SealRegistry, 20)
	sealCode, err5 := vrHex("sealRegistryCodeHash", f.SealRegistryCode, 32)
	if err := errors.Join(err1, err2, err3, err4, err5); err != nil {
		return dep, pins, err
	}
	conf, err := coupledGenesisShard(shardConfs)
	if err != nil {
		return dep, pins, errors.Join(ErrVRGenesis, err)
	}
	pr, pc, ok, err := vrstate.PinsFromPDR(conf)
	if err != nil || !ok || !bytes.Equal(pr[:], reg) || !bytes.Equal(pc[:], code) {
		return dep, pins, fmt.Errorf("%w: the VR deployment is not the one the genesis EVM PDR pins", ErrVRGenesis)
	}
	if chainID, ok := zkverifier.ParseChainIDFromParams(conf.PartitionParams); !ok || chainID != f.ChainID {
		return dep, pins, fmt.Errorf("%w: the VR deployment's chain id is not the EVM shard's", ErrVRGenesis)
	}
	if [20]byte(seal) != vrschema.SealRegistry {
		return dep, pins, fmt.Errorf("%w: the SealRegistry is at %x", ErrVRGenesis, seal)
	}
	dep = vradmit.Deployment{RootNetwork: rootNetwork, NetworkWord: vrschema.Word(word), ChainID: vrschema.U64(f.ChainID), Registry: [20]byte(reg),
		RegistryCode: [32]byte(code)}
	pins = vrstate.Pins{Registry: [20]byte(reg), RegistryCode: [32]byte(code), NetworkWord: vrschema.Word(word), SealRegistry: [20]byte(seal),
		SealRegistryCode: [32]byte(sealCode)}
	return dep, pins, nil
}

// newVRGenesisCmd is `ubft vr-genesis`.
func newVRGenesisCmd() *cobra.Command {
	root := &cobra.Command{Use: "vr-genesis", Short: "The genesis plan of a validator-registry generation (VT-14)"}
	root.AddCommand(newVRGenesisPlanCmd(), newVRGenesisVerifyCmd())
	return root
}

func newVRGenesisPlanCmd() *cobra.Command {
	var trustBaseFile, shardConfFile, bindingsFile, ownersFile, profileFile, networkWord, governors, limits, feeCollector, outInput, outIDs string
	var baseFeeFloor, changeDenominator uint64
	cmd := &cobra.Command{Use: "plan", Short: "Write the contracts genesis input and the roots' genesis identities of a VR generation",
		Long: "Identities 1..n are the coupled genesis entities in ascending root node id; each is a member of the genesis committee with its\n" +
			"trust-base stake as raw weight. StakingID is the VR id as a 32-byte big-endian word. MaxGas and SystemGas come from the B1 profile,\n" +
			"which must already pin both hooks on VR (engine-api b1-profile --vr-hook-measurement). The input goes to unicity-pos-contracts\n" +
			"script/vr-genesis.sh; the identities are the roots' --genesis-identities.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tb, err := readTrustBase(trustBaseFile)
			if err != nil {
				return err
			}
			conf, err := readShardConf(shardConfFile)
			if err != nil {
				return err
			}
			bindings, err := readBindings(bindingsFile)
			if err != nil {
				return err
			}
			p, err := readB1Profile(profileFile)
			if err != nil {
				return err
			}
			word, err := vrHex("--network-word", networkWord, 32)
			if err != nil {
				return err
			}
			var owners []vrOwner
			if ownersFile != "" {
				if err := vrStrictJSON(ownersFile, &owners); err != nil {
					return err
				}
			}
			var l vrInputLimits
			if _, err := fmt.Sscanf(limits, "%d,%d,%d", &l.NMin, &l.NTarget, &l.NMax); err != nil {
				return fmt.Errorf("%w: --limits must be nMin,nTarget,nMax", ErrVRGenesis)
			}
			// vMax, lMax and rMax are the P85-compatible limits() view only (VR v1 reads maxBatch alone)
			l.VMax, l.LMax, l.RMax, l.MaxBatch = vrschema.MaxCommittee, 1, 4, b1state.HookMaxRecords
			input, ids, err := vrPlan(vrPlanInput{tb: tb, conf: conf, bindings: bindings, owners: owners, profile: p, network: [32]byte(word),
				governorSigners: strings.Split(governors, ","), limits: l,
				fees: vrInputFees{BaseFeeFloor: baseFeeFloor, ChangeDenominator: changeDenominator, FeeCollector: feeCollector}})
			if err != nil {
				return err
			}
			if err := writeJSONFile(outInput, input); err != nil {
				return err
			}
			if err := writeJSONFile(outIDs, ids); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%d identities, chain %d) and %s\n", outInput, len(ids), input.ChainID, outIDs)
			return nil
		}}
	f := cmd.Flags()
	f.StringVar(&trustBaseFile, "trust-base", "", "the genesis root trust base")
	f.StringVar(&shardConfFile, "shard-conf", "", "the coupled EVM shard's genesis shard configuration (it pins VR)")
	f.StringVar(&bindingsFile, "bindings", "", "JSON array of {rootNodeId, evmNodeId}: one per entity")
	f.StringVar(&ownersFile, "owners", "", "optional JSON array of {owner, payee} in id order (default: DEV addresses derived from the root node id, keyless)")
	f.StringVar(&profileFile, "b1-profile", "", "the B1 profile (both hooks on VR)")
	f.StringVar(&networkWord, "network-word", "", "VR's deployment network word (0x + 64 hex)")
	f.StringVar(&governors, "governor-signers", "", "the FoundationMultisig's five signer addresses, comma-separated")
	f.StringVar(&limits, "limits", "4,4,16", "the genesis CommitteeLimits nMin,nTarget,nMax")
	f.StringVar(&feeCollector, "fee-collector", "", "the fee collector (the shard nodes' --engine-fee-collector)")
	f.Uint64Var(&baseFeeFloor, "base-fee-floor", 1_000_000, "the base-fee floor (ureth --unicity.base-fee-floor)")
	f.Uint64Var(&changeDenominator, "change-denominator", 8, "the base-fee change denominator (ureth --unicity.base-fee-change-denominator)")
	f.StringVar(&outInput, "out-input", "", "the contracts genesis input to write")
	f.StringVar(&outIDs, "out-identities", "", "the roots' genesis identities to write")
	for _, n := range []string{"trust-base", "shard-conf", "bindings", "b1-profile", "network-word", "governor-signers", "fee-collector", "out-input", "out-identities"} {
		_ = cmd.MarkFlagRequired(n)
	}
	return cmd
}

func newVRGenesisVerifyCmd() *cobra.Command {
	var inputFile, deploymentFile, genesisFile, shardConfFile, trustBaseFile, profileFile, idsFile, freshFile, urethLine, feeCollector, out string
	cmd := &cobra.Command{Use: "verify", Short: "Refuse any mismatch between the artifacts of a VR generation, and write the roots' --vr-deployment",
		Long: "Checks the finished generation: the EVM genesis carries exactly the seven VR accounts at their genesis addresses with the recorded\n" +
			"code (the composer engine stateless and no proxy); the profile's measurement and a fresh one are of that code and cover the pins;\n" +
			"the EVM PDR pins VR's address and code hash; VR's storage is the plan's (network word, limits, status, module, governor, fees);\n" +
			"the roots' genesis identities are VR's genesis committee (membersDigest) and the coupled genesis; the ureth flags pin the profile.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var v vrVerifyInput
			var err error
			if err = vrStrictJSON(inputFile, &v.input); err != nil {
				return err
			}
			if err = vrStrictJSON(deploymentFile, &v.deployment); err != nil {
				return err
			}
			if v.alloc, err = vrAllocAccounts(genesisFile); err != nil {
				return err
			}
			if v.full, err = readShardConf(shardConfFile); err != nil {
				return err
			}
			if v.tb, err = readTrustBase(trustBaseFile); err != nil {
				return err
			}
			if v.profile, v.profileFile, err = readB1ProfileFile(profileFile); err != nil {
				return err
			}
			if v.identities, _, err = readIdentities(idsFile); err != nil {
				return err
			}
			if v.fresh, err = readVRHookMeasurement(freshFile); err != nil {
				return err
			}
			v.urethFlags, v.feeCollector = urethLine, feeCollector
			dep, err := vrVerify(v)
			if err != nil {
				return err
			}
			if out != "" {
				if err := writeJSONFile(out, dep); err != nil {
					return err
				}
			}
			mh, _ := v.fresh.BatchRequirement()
			fmt.Fprintf(cmd.OutOrStdout(), "VR generation consistent: VR %s code %s, module %s, %d identities, H=%d HookRecordGas=%d ElectGas=%d (fresh M_H %d, E %d)\n",
				dep.Registry, dep.RegistryCodeHash, v.deployment.ModuleCodeHash, len(v.identities), v.profile.HRecords, v.profile.HookRecordGas, v.profile.ElectGas, mh, v.fresh.Elect)
			return nil
		}}
	f := cmd.Flags()
	f.StringVar(&inputFile, "input", "", "the contracts genesis input `plan` wrote")
	f.StringVar(&deploymentFile, "deployment", "", "the deployment.json script/vr-genesis.sh wrote")
	f.StringVar(&genesisFile, "genesis", "", "the finalized EVM genesis (engine-api genesis --out)")
	f.StringVar(&shardConfFile, "shard-conf", "", "the full EVM shard configuration (engine-api genesis --full-shard-conf)")
	f.StringVar(&trustBaseFile, "trust-base", "", "the genesis root trust base")
	f.StringVar(&profileFile, "b1-profile", "", "the B1 profile")
	f.StringVar(&idsFile, "genesis-identities", "", "the roots' genesis identities `plan` wrote")
	f.StringVar(&freshFile, "vr-hook-measurement", "", "a fresh complete-path VR hook measurement (ureth tests/vr_hook.rs vr_hook_measurement)")
	f.StringVar(&urethLine, "ureth-flags", "", "optional: the paired ureth's --unicity.* command line to check against the profile and VR's fees")
	f.StringVar(&feeCollector, "fee-collector", "", "optional: the shard nodes' --engine-fee-collector, checked against VR's")
	f.StringVar(&out, "out-root-deployment", "", "write the roots' --vr-deployment here once everything agrees")
	for _, n := range []string{"input", "deployment", "genesis", "shard-conf", "trust-base", "b1-profile", "genesis-identities", "vr-hook-measurement"} {
		_ = cmd.MarkFlagRequired(n)
	}
	return cmd
}

// enableVRServices installs the VR-mode collaborators of the control executor (design sections 5.2 and 5.6): the generation's deployment,
// the witness verifier over the pinned VR and SealRegistry, and the closure duty in the VR domain. The intent derivation (VT-05b) and the
// committed schedule (VT-07a) are not wired yet: without them the executor refuses every HandoffView and Freeze v5 and every RuleSupport
// (fail closed), so such a root follows a VR chain but cannot itself admit a primary handoff.
func enableVRServices(cm *consensus.ConsensusManager, orchestration *partitions.Orchestration, trustBases posclosure.TrustBases, tb *types.RootTrustBaseV1,
	shardConfs []*types.PartitionDescriptionRecord, path string) error {
	dep, pins, err := loadVRRootDeployment(path, uint64(tb.NetworkID), shardConfs)
	if err != nil {
		return err
	}
	conf, err := coupledGenesisShard(shardConfs)
	if err != nil {
		return errors.Join(ErrVRGenesis, err)
	}
	authority := posclosure.New(posclosure.History{Partition: conf.PartitionID, Shard: conf.ShardID, TrustBases: trustBases, Orchestration: orchestration})
	domain := storage.PosDeployment{RootNetwork: dep.RootNetwork,
		Deployment: evmassign.Deployment{NetworkWord: dep.NetworkWord, ChainID: dep.ChainID, Custody: dep.Registry}}
	cm.SetPosServices(&storage.PosServices{
		Deployment: domain,
		Authority:  authority,
		Witnesses:  cm,
		Proposer:   posclosure.Proposer{Source: cm, Authority: authority, Deployment: domain, Registry: true},
		Registry:   &storage.VRServices{Deployment: dep, State: vrstate.Authority{Pins: pins}},
	})
	return nil
}
