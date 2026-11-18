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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"reflect"
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

// ErrVRGenesisPartial is the outcome of a --partial check whose files agree: the generation is not certified.
var ErrVRGenesisPartial = errors.New("VR genesis plan: PARTIAL check (the ureth arguments and the fee collector were not checked): the generation is not certified")

// vrMaxBaseFee is ureth's MAX_BASE_FEE (1 << 62), the design's FeeParams bound.
const vrMaxBaseFee = uint64(1) << 62

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

// vrStrictJSON decodes a plan file exactly: no unknown, duplicate or case-variant key (Go's decoder takes the last of duplicates and
// matches case-insensitively; forge reads keys exactly), no trailing data, and every key spelled as the type names it.
func vrStrictJSON(path string, v any) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return err
	}
	bad := func(e error) error { return fmt.Errorf("%w: decoding %q: %v", ErrVRGenesis, path, e) }
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return bad(err)
	}
	if dec.More() {
		return bad(errors.New("trailing data"))
	}
	got, err := vrGenericJSON(raw)
	if err != nil {
		return bad(err)
	}
	again, err := json.Marshal(v)
	if err != nil {
		return bad(err)
	}
	want, err := vrGenericJSON(again)
	if err != nil {
		return bad(err)
	}
	if !reflect.DeepEqual(got, want) {
		return bad(errors.New("a key is not spelled as the format names it, or a value is not in its canonical form"))
	}
	return nil
}

// vrGenericJSON decodes JSON into maps, slices and json.Numbers, refusing a key that occurs twice in one object.
func vrGenericJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var walk func() (any, error)
	walk = func() (any, error) {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				m := map[string]any{}
				for dec.More() {
					k, err := dec.Token()
					if err != nil {
						return nil, err
					}
					key := k.(string)
					if _, dup := m[key]; dup {
						return nil, fmt.Errorf("key %q occurs twice", key)
					}
					if m[key], err = walk(); err != nil {
						return nil, err
					}
				}
				_, err := dec.Token()
				return m, err
			case '[':
				var a []any
				for dec.More() {
					e, err := walk()
					if err != nil {
						return nil, err
					}
					a = append(a, e)
				}
				_, err := dec.Token()
				return a, err
			}
		}
		return tok, nil
	}
	return walk()
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
	if in.network == ([32]byte{}) {
		return out, nil, fmt.Errorf("%w: a zero network word (ValidatorRegistry's constructor refuses it: BadGenesis(1))", ErrVRGenesis)
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
	// vMax, lMax and rMax are the P85-compatible limits() view only (VR v1 reads maxBatch alone); the plan fixes them
	l := vrInputLimits{NMin: in.limits.NMin, NTarget: in.limits.NTarget, NMax: in.limits.NMax, VMax: vrschema.MaxCommittee, LMax: 1, RMax: 4,
		MaxBatch: b1state.HookMaxRecords}
	if in.fees.BaseFeeFloor == 0 || in.fees.BaseFeeFloor > vrMaxBaseFee || in.fees.ChangeDenominator == 0 {
		return out, nil, fmt.Errorf("%w: the base-fee floor must be in 1..2^62 and the change denominator positive", ErrVRGenesis)
	}
	if l.NMin < 1 || l.NMin > l.NTarget || l.NTarget > l.NMax || l.NMax > vrschema.MaxCommittee || l.MaxBatch < in.profile.HRecords || l.MaxBatch > b1state.HookMaxRecords {
		return out, nil, fmt.Errorf("%w: limits need 1 <= nMin <= nTarget <= nMax <= 16 and H <= maxBatch <= 32", ErrVRGenesis)
	}
	collector, err := vrAddress("fee collector", in.fees.FeeCollector)
	if err != nil {
		return out, nil, err
	}
	if collector == (common.Address{}) {
		return out, nil, fmt.Errorf("%w: a zero fee collector burns the fees", ErrVRGenesis)
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
			if o == (common.Address{}) || p == (common.Address{}) {
				return out, nil, fmt.Errorf("%w: identity %d has a zero owner or payee", ErrVRGenesis, i+1)
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
		if _, dup := out[kw]; dup {
			return nil, fmt.Errorf("%w: storage slot %x is given twice", ErrVRGenesis, kw)
		}
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
	input       vrGenesisInput
	deployment  vrDeploymentFile
	genesis     []byte // the finalized EVM genesis JSON, exactly as the nodes load it
	full        *types.PartitionDescriptionRecord
	tb          *types.RootTrustBaseV1
	profile     b1state.Profile
	profileFile b1ProfileFile
	identities  []evmassign.Identity
	fresh       b1state.VRHookMeasurement
	// urethFlags is the paired ureth's argument vector and feeCollector the shard nodes' --engine-fee-collector. Both are required for a
	// complete check; partial skips them and never certifies the generation (no root deployment is returned).
	urethFlags   string
	feeCollector string
	partial      bool
	// funded are the balance-only accounts the plan funds (no code, storage or nonce), with their exact balances: the only accounts the
	// genesis may hold besides the SealRegistry and the seven VR accounts.
	funded map[common.Address]vrschema.Word
	// devGeneration names a development generation (its network word is vrDevNetworkWord(devGeneration)); funded accounts are accepted
	// only for one, and then every owner and governor signer the plan generated keys for must be among them.
	devGeneration string
}

// vrDevNetworkWord is the network word of a development generation: sha256("unicity.dev.vr." + name). A generation with any other word
// takes no dev funding.
func vrDevNetworkWord(name string) string {
	h := sha256.Sum256([]byte("unicity.dev.vr." + name))
	return lowerHex(h[:])
}

// vrCheckDevFunding is the premine rule (VT-14 follow-up): balance-only accounts are an expected premine of a development generation,
// never a hole. They are refused unless the generation is a dev one; each listed account must be allocated (the exact balance, no code,
// storage or nonce, checked with the alloc); and every identity owner and governor signer must be funded, so the keys the plan generated
// can send the transactions an election needs (proposeBinding, a multisig execute).
func vrCheckDevFunding(v vrVerifyInput, alloc map[common.Address]vrAllocAccount) error {
	if v.devGeneration != "" && !strings.EqualFold(v.input.Network, vrDevNetworkWord(v.devGeneration)) {
		return fmt.Errorf("%w: %q is not the network word of development generation %q", ErrVRGenesis, v.input.Network, v.devGeneration)
	}
	if len(v.funded) == 0 {
		if v.devGeneration != "" {
			return fmt.Errorf("%w: --dev-generation names a development generation's premine, and none is listed (--funded-accounts)", ErrVRGenesis)
		}
		return nil
	}
	if v.devGeneration == "" {
		return fmt.Errorf("%w: funded accounts are a development generation's premine only (--dev-generation)", ErrVRGenesis)
	}
	for a := range v.funded {
		if _, ok := alloc[a]; !ok {
			return fmt.Errorf("%w: the planned premine of %s is not allocated", ErrVRGenesis, a)
		}
	}
	var need []string
	for _, p := range v.input.Identities {
		need = append(need, p.Owner)
	}
	need = append(need, v.input.GovernorSigners...)
	for _, s := range need {
		a, err := vrAddress("funded owner or signer", s)
		if err != nil {
			return err
		}
		if _, ok := v.funded[a]; !ok {
			return fmt.Errorf("%w: dev funding does not fund %s, an owner or governor signer of the plan", ErrVRGenesis, a)
		}
	}
	return nil
}

func vrGenesisRole(a common.Address) string {
	for _, r := range vrGenesisAccounts {
		if vrGenesisAddress(r.low) == a {
			return r.role
		}
	}
	return ""
}

// vrReplan re-derives the plan from the generation's own files and requires it to be exactly input.json and the roots' identities.
func vrReplan(v vrVerifyInput) error {
	var bindings []evmassign.Binding
	for _, i := range v.identities {
		bindings = append(bindings, evmassign.Binding{RootNodeID: i.RootNodeID, EVMNodeID: i.EVMNodeID})
	}
	owners := make([]vrOwner, len(v.input.Identities))
	for i, p := range v.input.Identities {
		owners[i] = vrOwner{Owner: p.Owner, Payee: p.Payee}
	}
	word, err := vrHex("network", v.input.Network, 32)
	if err != nil {
		return err
	}
	in, ids, err := vrPlan(vrPlanInput{tb: v.tb, conf: v.full, bindings: bindings, owners: owners, profile: v.profile, network: [32]byte(word),
		governorSigners: append([]string(nil), v.input.GovernorSigners...), limits: v.input.Limits, fees: v.input.Fees})
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(in, v.input) {
		return fmt.Errorf("%w: input.json is not the plan the generation's files re-derive", ErrVRGenesis)
	}
	if !reflect.DeepEqual(ids, v.identities) {
		return fmt.Errorf("%w: the roots' genesis identities are not the plan's", ErrVRGenesis)
	}
	return nil
}

// vrGenesisFile is the finalized EVM genesis: its chain configuration, header fields and allocation.
type vrGenesisFile struct {
	Config struct {
		ChainID      uint64  `json:"chainId"`
		ShanghaiTime *uint64 `json:"shanghaiTime"`
		CancunTime   *uint64 `json:"cancunTime"`
	} `json:"config"`
	GasLimit      string                    `json:"gasLimit"`
	BaseFeePerGas string                    `json:"baseFeePerGas"`
	Timestamp     string                    `json:"timestamp"`
	Coinbase      string                    `json:"coinbase"`
	Nonce         string                    `json:"nonce"`
	MixHash       string                    `json:"mixHash"`
	Difficulty    string                    `json:"difficulty"`
	Number        string                    `json:"number"`
	ParentHash    string                    `json:"parentHash"`
	GasUsed       string                    `json:"gasUsed"`
	Alloc         map[string]vrAllocAccount `json:"alloc"`
}

// vrGenesisBaseFee is the genesis base fee the plan writes (1 gwei; deploy/testnet funded_base_genesis). extraData is the one free
// header field: per-generation entropy by design.
const vrGenesisBaseFee = 1_000_000_000

func vrParseGenesis(raw []byte) (vrGenesisFile, map[common.Address]vrAllocAccount, error) {
	var g vrGenesisFile
	if err := json.Unmarshal(raw, &g); err != nil {
		return g, nil, fmt.Errorf("%w: decoding the EVM genesis: %v", ErrVRGenesis, err)
	}
	out := map[common.Address]vrAllocAccount{}
	for k, v := range g.Alloc {
		if !common.IsHexAddress(k) {
			return g, nil, fmt.Errorf("%w: alloc key %q", ErrVRGenesis, k)
		}
		a := common.HexToAddress(k)
		if _, dup := out[a]; dup {
			return g, nil, fmt.Errorf("%w: alloc names %s twice", ErrVRGenesis, a)
		}
		out[a] = v
	}
	return g, out, nil
}

// vrGenesisCommitmentSlot is the SealRegistry's genesisCommitment word (the paired client's --unicity.genesis-commitment).
var vrGenesisCommitmentSlot = vrschema.Keccak([]byte("unicity.seal-registry/genesisCommitment"))

// urethArgs is a ureth argument vector parsed as the client's parser takes it: `--flag=value` and `--flag value` alike, a bare flag
// with no value, and every flag at most once (the client refuses repeated --unicity options; a repeat here is a conflict, never a choice).
type urethArgs map[string]string

// urethUnicityFlags are the flags of the vector verify certifies: ureth's --unicity.* options (bin/unicity-reth/src/main.rs UnicityArgs)
// and the two pool bounds the profile sets. true marks a value-less switch. Any other argument is not part of the certified vector.
var urethUnicityFlags = map[string]bool{
	"--unicity.fee-collector": false, "--unicity.network-id": false, "--unicity.root-genesis-id": false, "--unicity.chain-id": false,
	"--unicity.profile-hash": false, "--unicity.genesis-commitment": false, "--unicity.max-epochs-per-update": false,
	"--unicity.records-custody": false, "--unicity.h-records": false, "--unicity.hook-record-gas": false, "--unicity.election": false,
	"--unicity.elect-gas": false, "--unicity.max-gas": false, "--unicity.system-gas": false, "--unicity.base-fee-floor": false,
	"--unicity.elasticity": false, "--unicity.base-fee-change-denominator": false, "--unicity.companion-retention-depth": false,
	"--unicity.no-proof-source": true, "--unicity.accounting-repair-limit": false, "--txpool.max-tx-gas": false, "--txpool.max-tx-input-bytes": false,
}

func parseUrethArgs(line string) (urethArgs, error) {
	out := urethArgs{}
	f := strings.Fields(line)
	for i := 0; i < len(f); i++ {
		tok := f[i]
		name, value, hasValue := strings.Cut(tok, "=")
		isSwitch, known := urethUnicityFlags[name]
		if !known {
			return nil, fmt.Errorf("%w: ureth argument %q is not a flag of the certified vector", ErrVRGenesis, tok)
		}
		switch {
		case isSwitch && hasValue:
			return nil, fmt.Errorf("%w: ureth switch %s takes no value", ErrVRGenesis, name)
		case isSwitch:
		case !hasValue:
			if i+1 >= len(f) || strings.HasPrefix(f[i+1], "--") {
				return nil, fmt.Errorf("%w: ureth %s has no value", ErrVRGenesis, name)
			}
			value, i = f[i+1], i+1
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%w: ureth argument %s is given more than once", ErrVRGenesis, name)
		}
		out[name] = value
	}
	return out, nil
}

// urethAccountingWindow is ureth's recovery ACCOUNTING_WINDOW (crates/unicity/payload/src/recovery.rs), and urethRepairLimit the default of
// --unicity.accounting-repair-limit: a companion retention depth below their sum is refused at start-up (UnicityArgs::validate_retention).
const (
	urethAccountingWindow uint64 = 16
	urethRepairLimit      uint64 = 64
)

// typed holds every argument to the client's own parsing: addresses and 32-byte hashes as such, every other value as a Rust u64
// (decimal digits with an optional leading +), and the retention relation the client checks before it starts.
func (a urethArgs) typed() error {
	for flag, value := range a {
		switch flag {
		case "--unicity.no-proof-source":
		case "--unicity.fee-collector", "--unicity.records-custody", "--unicity.election":
			if !common.IsHexAddress(value) {
				return fmt.Errorf("%w: ureth %s=%q is not an address", ErrVRGenesis, flag, value)
			}
		case "--unicity.root-genesis-id", "--unicity.profile-hash", "--unicity.genesis-commitment":
			if _, err := hex.DecodeString(strings.TrimPrefix(value, "0x")); err != nil || len(strings.TrimPrefix(value, "0x")) != 64 {
				return fmt.Errorf("%w: ureth %s=%q is not a 32-byte hash", ErrVRGenesis, flag, value)
			}
		default:
			if _, err := a.uint(flag, 0); err != nil {
				return err
			}
		}
	}
	depth, hasDepth := a["--unicity.companion-retention-depth"]
	if !hasDepth {
		return nil
	}
	d, _ := a.uint("--unicity.companion-retention-depth", 0)
	repair, _ := a.uint("--unicity.accounting-repair-limit", urethRepairLimit)
	if repair > math.MaxUint64-urethAccountingWindow {
		return fmt.Errorf("%w: ureth's accounting repair limit %d overflows the companion retention rule", ErrVRGenesis, repair)
	}
	if d < urethAccountingWindow+repair {
		return fmt.Errorf("%w: ureth's companion retention depth %s is below the accounting window + repair limit (%d)", ErrVRGenesis, depth, urethAccountingWindow+repair)
	}
	return nil
}

// uint is the effective numeric value of a flag: its value, or the client's default when absent.
func (a urethArgs) uint(flag string, def uint64) (uint64, error) {
	v, ok := a[flag]
	if !ok {
		return def, nil
	}
	digits := strings.TrimPrefix(v, "+")
	n, okN := new(big.Int).SetString(digits, 10)
	if digits == "" || strings.ContainsAny(digits, "+-_") || !okN || !n.IsUint64() {
		return 0, fmt.Errorf("%w: ureth %s=%q is not a number", ErrVRGenesis, flag, v)
	}
	return n.Uint64(), nil
}

// vrVerify cross-checks every artifact of the generation against the plan and the finalized genesis, and returns the roots' deployment
// file. Nothing a report says about the allocation is trusted: the allocated code and storage are compared with what the plan and the
// reviewed code determine.
func vrVerify(v vrVerifyInput) (vrRootDeployment, error) {
	var out vrRootDeployment
	fail := func(format string, a ...any) (vrRootDeployment, error) {
		return out, fmt.Errorf("%w: "+format, append([]any{ErrVRGenesis}, a...)...)
	}
	in, d := v.input, v.deployment
	if in.Format != vrInputFormat || d.Format != vrDeploymentFormat {
		return fail("unknown input or deployment format")
	}
	if !v.partial && (v.urethFlags == "" || v.feeCollector == "") {
		return fail("a complete check needs the ureth arguments and the shard nodes' fee collector")
	}
	if v.partial && (v.urethFlags != "" || v.feeCollector != "") {
		return fail("a partial check does not check the ureth arguments or the fee collector: do not pass them")
	}

	// 0. the plan itself: re-derived from the trust base, the PDR, the identities' bindings, the profile and the plan's own choices, it
	// must be exactly input.json and the roots' identities (the plan's policy is re-applied, never assumed)
	if err := vrReplan(v); err != nil {
		return out, err
	}

	// 1. the finalized EVM genesis: the B1 rules (SealRegistry predeploy code and state, chain id, the full PDR's seal_registry_genesis
	// and the execution identity), then the header and chain configuration against the profile and the plan
	h, err := bindB1Profile(v.profile, v.tb, v.full)
	if err != nil {
		return out, errors.Join(ErrVRGenesis, err)
	}
	if err := checkB1FinalizedGenesis(v.full, v.profile, h, v.genesis); err != nil {
		return fail("the finalized EVM genesis is not the generation's: %v", err)
	}
	g, alloc, err := vrParseGenesis(v.genesis)
	if err != nil {
		return out, err
	}
	gasLimit, ok1 := bigWord(g.GasLimit)
	if !ok1 || vrschema.U64(v.profile.MaxGas) != gasLimit {
		return fail("the genesis gasLimit %s is not the profile's MaxGas %d", g.GasLimit, v.profile.MaxGas)
	}
	baseFee, okB := bigWord(g.BaseFeePerGas)
	if !okB || baseFee != vrschema.U64(vrGenesisBaseFee) || in.Fees.BaseFeeFloor > vrGenesisBaseFee {
		return fail("the genesis baseFeePerGas %s is not the plan's %d (at or above VR's floor %d)", g.BaseFeePerGas, vrGenesisBaseFee, in.Fees.BaseFeeFloor)
	}
	for name, field := range map[string]string{"timestamp": g.Timestamp, "coinbase": g.Coinbase, "nonce": g.Nonce, "mixHash": g.MixHash,
		"difficulty": g.Difficulty, "number": g.Number, "parentHash": g.ParentHash, "gasUsed": g.GasUsed} {
		if w, ok := bigWord(cmpOr(field, "0x0")); !ok || w != (vrschema.Word{}) {
			return fail("the genesis %s is %q, not zero", name, field)
		}
	}
	// exactly the generation's accounts: the SealRegistry, the seven VR accounts, and the balance-only accounts the plan funds
	for a, acct := range alloc {
		if a == common.Address(vrschema.SealRegistry) || vrGenesisRole(a) != "" {
			continue
		}
		want, funded := v.funded[a]
		bal, okBal := bigWord(cmpOr(acct.Balance, "0x0"))
		nonce, okN := bigWord(cmpOr(acct.Nonce, "0x0"))
		if !funded || !okBal || !okN || bal != want || nonce != (vrschema.Word{}) || strings.TrimPrefix(cmpOr(acct.Code, "0x"), "0x") != "" || len(acct.Storage) != 0 {
			return fail("the genesis allocates %s, which the plan does not (only the SealRegistry, the seven VR accounts and listed balance-only accounts)", a)
		}
	}
	for a := range v.funded {
		if a == common.Address(vrschema.SealRegistry) || a == vrGenesisAddress(1) || vrGenesisRole(a) != "" || a == (common.Address{}) {
			return fail("the funded account %s collides with a reserved genesis account", a)
		}
		if _, ok := alloc[a]; !ok {
			return fail("the planned funded account %s is not allocated", a)
		}
	}
	if err := vrCheckDevFunding(v, alloc); err != nil {
		return out, err
	}
	if g.Config.ChainID != in.ChainID || g.Config.ShanghaiTime == nil || *g.Config.ShanghaiTime != 0 || g.Config.CancunTime == nil || *g.Config.CancunTime != 0 {
		return fail("the genesis chain configuration (chain %d, Shanghai and Cancun at 0) is not the plan's chain %d", g.Config.ChainID, in.ChainID)
	}
	sealAcct, ok := alloc[common.Address(vrschema.SealRegistry)]
	if !ok {
		return fail("the genesis has no SealRegistry")
	}
	sealStorage, err := storageOf(sealAcct)
	if err != nil {
		return out, err
	}
	commitment := sealStorage[vrGenesisCommitmentSlot]
	if commitment == (vrschema.Word{}) {
		return fail("the SealRegistry's genesisCommitment is not set")
	}

	// 2. code: the core and the module are the measured code (and the core the PDR's); the facets are the ones the pinned core embeds;
	// the composer and the multisig are the reviewed runtimes
	if v.profileFile.VRHookMeasurement == nil {
		return fail("the B1 profile carries no VR hook measurement")
	}
	codes, hashes := map[string][]byte{}, map[string][32]byte{}
	accounts := d.accounts()
	for _, a := range vrGenesisAccounts {
		acct, ok := alloc[vrGenesisAddress(a.low)]
		if !ok {
			return fail("the EVM genesis has no %s account at %s", a.role, vrGenesisAddress(a.low))
		}
		code, err := hex.DecodeString(strings.TrimPrefix(acct.Code, "0x"))
		if err != nil || len(code) == 0 {
			return fail("%s has no code in the EVM genesis", a.role)
		}
		if b, ok := bigWord(cmpOr(acct.Balance, "0x0")); !ok || b != (vrschema.Word{}) {
			return fail("%s holds a balance", a.role)
		}
		if n, ok := bigWord(cmpOr(acct.Nonce, "0x0")); !ok || n != (vrschema.Word{}) {
			return fail("%s has nonce %s, not the genesis construction's 0", a.role, acct.Nonce)
		}
		codes[a.role], hashes[a.role] = code, [32]byte(ethcrypto.Keccak256(code))
		rec := accounts[a.role]
		addr, err := vrAddress(a.role, rec[0])
		if err != nil {
			return out, err
		}
		hh := hashes[a.role]
		if addr != vrGenesisAddress(a.low) || !strings.EqualFold(rec[1], lowerHex(hh[:])) {
			return fail("the deployment report's %s is not the allocated account", a.role)
		}
	}
	if err := b1state.CheckVRHookGasFresh(v.profile, hashes["registry"], hashes["module"], *v.profileFile.VRHookMeasurement, v.fresh); err != nil {
		return fail("the recorded or the fresh measurement does not cover the pins for this code: %v", err)
	}
	// each facet at its own role: the pinned core embeds its hash, the facet's runtime carries its own address (its SELF immutable), and
	// the three are distinct (a swapped or duplicated facet reverts every delegated call: ValidatorRegistry._delegate checks each role)
	for _, a := range vrGenesisAccounts[1:4] {
		self := vrschema.AddrWord(vrGenesisAddress(a.low))
		if !embeds(codes["registry"], hashes[a.role]) || !embeds(codes[a.role], self) {
			return fail("the allocated %s (%x) is not the facet the pinned VR core delegates to at %s", a.role, hashes[a.role], vrGenesisAddress(a.low))
		}
	}
	if hashes["governanceFacet"] == hashes["repairFacet"] || hashes["repairFacet"] == hashes["recordsFacet"] || hashes["governanceFacet"] == hashes["recordsFacet"] {
		return fail("two facet roles carry the same code")
	}
	composerHash, governorHash := hashes["composer"], hashes["governor"]
	if lowerHex(composerHash[:]) != vrReviewedComposerCodeHash || !inertCode(codes["composer"]) {
		return fail("the composer engine is not the reviewed PoaComposerEngine runtime %s", vrReviewedComposerCodeHash)
	}
	if lowerHex(governorHash[:]) != vrReviewedGovernorCodeHash {
		return fail("the governor is not the reviewed FoundationMultisig runtime %s", vrReviewedGovernorCodeHash)
	}

	// 3. the EVM PDR pins VR, and the roots derive VR mode with the genesis committee from it
	registry, code, ok, err := vrstate.PinsFromPDR(v.full)
	if err != nil || !ok {
		return fail("the EVM shard configuration does not pin VR: %v", err)
	}
	if code != hashes["registry"] || registry != vrschema.ValidatorRegistry {
		return fail("the EVM PDR pins VR code %x, the alloc carries %x", code, hashes["registry"])
	}
	if !evmassign.CouplingRequired(v.full) || len(v.full.Validators) != in.IdentityCount || len(in.Identities) != in.IdentityCount {
		return fail("the coupled EVM shard has %d validators for %d genesis identities", len(v.full.Validators), in.IdentityCount)
	}

	// 4. the profile and the plan agree on the chain, the gas envelope and the hooks
	chainID, ok := zkverifier.ParseChainIDFromParams(v.full.PartitionParams)
	if !ok || chainID != in.ChainID || in.ChainID != d.ChainID || v.profile.ExecutionChainID != in.ChainID {
		return fail("the chain id differs between the shard configuration, the input, the deployment and the profile")
	}
	if v.profile.MaxGas != in.MaxGas || v.profile.SystemGas != in.SystemGas {
		return fail("VR's fee configuration (maxGas %d, systemGas %d) is not the profile's (%d, %d)", in.MaxGas, in.SystemGas, v.profile.MaxGas, v.profile.SystemGas)
	}
	if in.Limits.MaxBatch < v.profile.HRecords || in.Limits.MaxBatch > b1state.HookMaxRecords {
		return fail("VR's maxBatch %d does not admit the profile's H %d", in.Limits.MaxBatch, v.profile.HRecords)
	}
	if in.KnownRootEpoch != v.tb.Epoch || v.profile.Network != uint16(v.tb.NetworkID) || uint64(v.full.NetworkID) != uint64(v.tb.NetworkID) {
		return fail("the root epoch or network differs between the plan, the trust base, the profile and the shard configuration")
	}
	policy, err := storage.ContinuityPolicy(v.full)
	if err != nil || policy.MaxM != in.Continuity.MaxM || policy.MaxDistNum != in.Continuity.DistNum || policy.MaxDistDen != in.Continuity.DistDen {
		return fail("VR's continuity budget is not the EVM PDR's")
	}

	// 5. the roots' genesis identities are the plan's identities, StakingID = the VR id word, and the coupled genesis
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
			!strings.EqualFold(p.EVMKey, lowerHex(id.EVMKey)) || !strings.EqualFold(p.Payee, lowerHex(id.OperatorPayee)) || p.RawWeight != id.RawWeight ||
			p.RawWeight == 0 {
			return fail("genesis identity %d differs from VR identity %d", i, i+1)
		}
	}
	if err := checkGenesisIdentities(v.identities, v.tb, v.full); err != nil {
		return out, errors.Join(ErrVRGenesis, err)
	}

	// 6. the allocated storage is exactly the plan's: VR, the module, the multisig; the facets and the composer hold none
	wantVR, wantPoA, wantMultisig, committee, err := vrExpectedState(in, v.identities, hashes["module"])
	if err != nil {
		return out, err
	}
	if !strings.EqualFold(d.CommitteeDigest, lowerHex(committee[:])) || d.Members != uint64(len(v.identities)) || d.IdentityCount != uint64(in.IdentityCount) ||
		!strings.EqualFold(d.NetworkWord, in.Network) || !strings.EqualFold(d.ModuleTag, lowerHex(vrPoaTag[:])) ||
		!strings.EqualFold(d.LastAcked, lowerHex(vrschema.GenesisResult[:])) {
		return fail("the deployment report's committee, counts or network word are not the plan's")
	}
	want := map[string]vrStorage{"registry": wantVR, "module": wantPoA, "governor": wantMultisig}
	var diffs []string
	for _, a := range vrGenesisAccounts {
		got, err := storageOf(alloc[vrGenesisAddress(a.low)])
		if err != nil {
			return out, err
		}
		exp := want[a.role]
		if exp == nil {
			exp = vrStorage{}
		}
		diffs = append(diffs, diffStorage(a.role, exp, got)...)
	}
	if len(diffs) != 0 {
		if len(diffs) > 8 {
			diffs = append(diffs[:8], fmt.Sprintf("... %d more", len(diffs)-8))
		}
		return fail("the allocated storage is not the plan's:\n  %s", strings.Join(diffs, "\n  "))
	}

	sealCode, err := vrHex("SealRegistry code hash", b1registry.CodeHashHex, 32)
	if err != nil {
		return out, err
	}
	if v.partial {
		return out, ErrVRGenesisPartial
	}

	// 7. the runtime inputs: the shard nodes' fee collector is VR's, and the ureth argument vector pins the profile, the genesis
	// commitment and VR's fees
	if c, err := vrAddress("--fee-collector", v.feeCollector); err != nil || !strings.EqualFold(lowerHex(c[:]), in.Fees.FeeCollector) {
		return fail("the shard nodes' fee collector %s is not VR's %s", v.feeCollector, in.Fees.FeeCollector)
	}
	args, err := parseUrethArgs(v.urethFlags)
	if err != nil {
		return out, err
	}
	hash, err := v.profile.Hash()
	if err != nil {
		return out, errors.Join(ErrVRGenesis, err)
	}
	pinned, err := parseUrethArgs(urethFlags(v.profile, hash) + " --unicity.genesis-commitment=" + lowerHex(commitment[:]) +
		" --unicity.fee-collector=" + in.Fees.FeeCollector)
	if err != nil {
		return out, err
	}
	for flag, value := range pinned {
		if got, ok := args[flag]; !ok || !strings.EqualFold(got, value) {
			return fail("ureth %s is %q, the generation pins %q", flag, got, value)
		}
	}
	if err := args.typed(); err != nil {
		return out, err
	}
	for flag, want := range map[string]uint64{"--unicity.base-fee-floor": in.Fees.BaseFeeFloor, "--unicity.base-fee-change-denominator": in.Fees.ChangeDenominator,
		"--unicity.elasticity": 2} {
		def := map[string]uint64{"--unicity.base-fee-floor": 1_000_000, "--unicity.base-fee-change-denominator": 8, "--unicity.elasticity": 2}[flag]
		got, err := args.uint(flag, def)
		if err != nil {
			return out, err
		}
		if got != want {
			return fail("ureth's effective %s is %d, VR's genesis has %d", flag, got, want)
		}
	}

	vrCode := hashes["registry"]
	return vrRootDeployment{Format: vrRootDeployFormat, RootNetwork: uint64(v.tb.NetworkID), NetworkWord: strings.ToLower(in.Network), ChainID: in.ChainID,
		Registry: lowerHex(vrschema.ValidatorRegistry[:]), RegistryCodeHash: lowerHex(vrCode[:]), SealRegistry: lowerHex(vrschema.SealRegistry[:]),
		SealRegistryCode: lowerHex(sealCode)}, nil
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
	var partial bool
	var fundedFile, devGeneration string
	cmd := &cobra.Command{Use: "verify", Short: "Refuse any mismatch between the artifacts of a VR generation, and write the roots' --vr-deployment",
		Long: "Checks the finished generation against the plan, never a report's description of it:\n" +
			"  - the finalized EVM genesis by the B1 rules (SealRegistry code and state, chain id, seal_registry_genesis), its gasLimit = MaxGas\n" +
			"    and its chain configuration;\n" +
			"  - the code: VR and the module are the measured code (VR the PDR's), the facets the ones VR embeds, the composer and the multisig\n" +
			"    the reviewed runtimes; the profile's measurement and the fresh one cover the pins;\n" +
			"  - the storage of VR, the module and the multisig, slot for slot against the state the plan determines;\n" +
			"  - the roots' genesis identities, the coupled genesis, the PDR pins;\n" +
			"  - the ureth argument vector (both flag forms, no repeats) against the profile, the genesis commitment and VR's fees, and the\n" +
			"    shard nodes' fee collector against VR's.\n" +
			"--partial skips the two runtime inputs; it certifies nothing and writes no root deployment.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var v vrVerifyInput
			var err error
			if err = vrStrictJSON(inputFile, &v.input); err != nil {
				return err
			}
			if err = vrStrictJSON(deploymentFile, &v.deployment); err != nil {
				return err
			}
			if v.genesis, err = os.ReadFile(genesisFile); err != nil { // #nosec G304 -- operator supplied local file
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
			v.urethFlags, v.feeCollector, v.partial = urethLine, feeCollector, partial
			if partial && out != "" {
				return fmt.Errorf("%w: a partial check certifies nothing: no --out-root-deployment", ErrVRGenesis)
			}
			if fundedFile != "" {
				var funded map[string]string
				if err := vrStrictJSON(fundedFile, &funded); err != nil {
					return err
				}
				v.funded = map[common.Address]vrschema.Word{}
				for k, bal := range funded {
					a, err := vrAddress("funded account", k)
					if err != nil {
						return err
					}
					w, ok := bigWord(bal)
					if !ok || w == (vrschema.Word{}) {
						return fmt.Errorf("%w: funded account %s balance %q", ErrVRGenesis, k, bal)
					}
					v.funded[a] = w
				}
			}
			v.devGeneration = devGeneration
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
	f.StringVar(&inputFile, "input", "", "the contracts genesis input vr-genesis plan wrote")
	f.StringVar(&deploymentFile, "deployment", "", "the deployment.json script/vr-genesis.sh wrote")
	f.StringVar(&genesisFile, "genesis", "", "the finalized EVM genesis (engine-api genesis --out)")
	f.StringVar(&shardConfFile, "shard-conf", "", "the full EVM shard configuration (engine-api genesis --full-shard-conf)")
	f.StringVar(&trustBaseFile, "trust-base", "", "the genesis root trust base")
	f.StringVar(&profileFile, "b1-profile", "", "the B1 profile")
	f.StringVar(&idsFile, "genesis-identities", "", "the roots' genesis identities vr-genesis plan wrote")
	f.StringVar(&freshFile, "vr-hook-measurement", "", "a fresh complete-path VR hook measurement (ureth tests/vr_hook.rs vr_hook_measurement)")
	f.StringVar(&urethLine, "ureth-flags", "", "the paired ureth's argument vector (its --unicity.* and --txpool.* flags), checked against the profile, the genesis commitment and VR's fees")
	f.StringVar(&feeCollector, "fee-collector", "", "the shard nodes' --engine-fee-collector, checked against VR's")
	f.StringVar(&fundedFile, "funded-accounts", "", "a development generation's premine: JSON {address: balance hex} of the balance-only accounts it funds, every owner and governor signer among them; the genesis may allocate nothing else besides the SealRegistry and the seven VR accounts (needs --dev-generation)")
	f.StringVar(&devGeneration, "dev-generation", "", "the development generation's name: its network word must be sha256(\"unicity.dev.vr.\" + name); dev funding is refused for any other generation")
	f.BoolVar(&partial, "partial", false, "check the files only, without --ureth-flags and --fee-collector (refused with them): exits non-zero with PARTIAL even when the files agree, certifies nothing, writes no root deployment")
	f.StringVar(&out, "out-root-deployment", "", "write the roots' --vr-deployment here once everything agrees")
	for _, n := range []string{"input", "deployment", "genesis", "shard-conf", "trust-base", "b1-profile", "genesis-identities", "vr-hook-measurement"} {
		_ = cmd.MarkFlagRequired(n)
	}
	return cmd
}

// enableVRServices installs the VR-mode collaborators of the control executor (design sections 5.2 and 5.6): the generation's deployment,
// the witness verifier over the pinned VR and SealRegistry, and the closure duty in the VR domain. The intent derivation and the handoff
// protocol (VT-05b) are wired after it by enableVRHandoffInVRMode, which needs --pos-evm-rpc. The committed schedule (VT-07a) is not wired
// yet: without it the executor refuses every RuleSupport (fail closed).
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
