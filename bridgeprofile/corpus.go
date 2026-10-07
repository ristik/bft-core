package bridgeprofile

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/unicitynetwork/bft-go-base/types"
)

// This file defines the candidate vector corpus format and its executable
// replay. The corpus is the machine-readable form of the oracle's behaviour:
// every case is a self-contained input (bytes as lower-case hex), an operation
// and the outcome every implementation must reproduce. Replay uses only the
// case and the fixture set, never builder state, so a consumer in another
// language can follow the same procedure.

// CorpusFormat identifies the case layout.
const CorpusFormat = "native-bridge-vectors/2"

// Expect is the outcome every implementation must reproduce.
type Expect struct {
	Status string            `json:"status"`           // "ok" or "error"
	Family string            `json:"family,omitempty"` // malformed | invalid | budget
	Reason string            `json:"reason,omitempty"` // sentinel name
	Result *RJSON            `json:"result,omitempty"` // relation result
	Output string            `json:"output,omitempty"` // canonical kernel output, hex
	Values map[string]string `json:"values,omitempty"` // op-specific derived values
}

// LeafJSON is a leaf (sid, txHash, t, v).
type LeafJSON struct {
	SID           string `json:"sid"`
	TxHash        string `json:"txHash"`
	ReferenceTime string `json:"referenceTime"` // decimal u64
	LeafValue     string `json:"leafValue"`
}

// RJSON is a Result rendered for the corpus.
type RJSON struct {
	Cfg                string     `json:"cfg"`
	Nonce              string     `json:"nonce"` // decimal u64
	Amount             string     `json:"amount"`
	TokenID            string     `json:"tokenId"`
	Salt               string     `json:"salt"`
	FirstPredicateHash string     `json:"firstPredicateHash"`
	LockDigest         string     `json:"lockDigest"`
	ReleaseTo          string     `json:"releaseTo"`
	Nullifier          string     `json:"nullifier"`
	Leaves             []LeafJSON `json:"leaves"`
}

// Case is one input with its expected outcome.
type Case struct {
	ID          string            `json:"id"`
	Family      string            `json:"family"`
	Op          string            `json:"op"`
	Description string            `json:"description"`
	Cfg         string            `json:"cfg,omitempty"` // fixture name
	Input       string            `json:"input"`
	Aux         map[string]string `json:"aux,omitempty"`
	Expected    Expect            `json:"expected"`
}

// CaseFile is one family file.
type CaseFile struct {
	Format  string `json:"format"`
	Proto   int    `json:"nativeBridgeProtoVersion"`
	Family  string `json:"family"`
	Fixture string `json:"fixtureDigest"`
	Cases   []Case `json:"cases"`
}

// FixtureJSON publishes one instantiated deployment fixture.
type FixtureJSON struct {
	Name                string `json:"name"`
	ChainID             string `json:"chainId"`
	AggregatorPartition uint32 `json:"aggregatorPartition"`
	AggregatorShardConf string `json:"aggregatorShardConfHash"`
	EVMPartition        uint32 `json:"evmPartition"`
	EVMShard            string `json:"evmShard"`
	Cfg                 string `json:"cfg"`
	CfgHash             string `json:"cfgHash"`
	PolicyBody          string `json:"policyBody"`
	PolicyHash          string `json:"policyHash"`
	Vault               string `json:"vault"`
	Ty                  string `json:"ty"`
	Aid                 string `json:"aid"`
}

// PinJSON is a deployment pin.
type PinJSON struct {
	GenesisPDR    string `json:"genesisPDR"` // canonical PartitionDescriptionRecord, hex
	VaultCodeHash string `json:"vaultCodeHash"`
}

// FixtureSet is everything cases refer to by name.
type FixtureSet struct {
	Format     string                 `json:"format"`
	Proto      int                    `json:"nativeBridgeProtoVersion"`
	Notes      []string               `json:"notes"`
	Cfgs       map[string]FixtureJSON `json:"fixtures"`
	TrustBases map[string]string      `json:"trustBases"` // name -> canonical root trust base CBOR, hex
	Pins       map[string]PinJSON     `json:"pins"`
	Aggregat   map[string]string      `json:"aggregatorAuthorities"` // name -> canonical root trust base hex
}

func fixtureJSON(name string, f *Fixture) FixtureJSON {
	c := f.Cfg
	return FixtureJSON{Name: name, ChainID: strconv.FormatUint(c.ChainID, 10), AggregatorPartition: f.Policy.Partition,
		AggregatorShardConf: h32(f.Policy.ShardConf), EVMPartition: c.EVMPartition, EVMShard: hx(c.EVMShard),
		Cfg: hx(c.Bytes()), CfgHash: h32(c.Hash()), PolicyBody: hx(f.Policy.Bytes()), PolicyHash: h32(f.Policy.Hash()),
		Vault: hx(c.Vault[:]), Ty: h32(c.Ty), Aid: h32(c.Aid)}
}

// reasons lists every leaf sentinel by name. Children precede their parents so
// the first match is the most specific reason.
var reasons = []struct {
	name string
	err  error
}{
	{"ErrTruncated", ErrTruncated}, {"ErrTrailing", ErrTrailing}, {"ErrNonCanonical", ErrNonCanonical},
	{"ErrForbiddenCBOR", ErrForbiddenCBOR}, {"ErrShape", ErrShape}, {"ErrTag", ErrTag}, {"ErrVersion", ErrVersion},
	{"ErrLength", ErrLength}, {"ErrIntRange", ErrIntRange}, {"ErrABIFraming", ErrABIFraming}, {"ErrBadOperation", ErrBadOperation},
	{"ErrDeadline", ErrDeadline}, {"ErrRLP", ErrRLP}, {"ErrResultFrame", ErrResultFrame},
	{"ErrInputTooLarge", ErrInputTooLarge}, {"ErrTooManyTx", ErrTooManyTx}, {"ErrTooManyItems", ErrTooManyItems},
	{"ErrTooDeep", ErrTooDeep}, {"ErrTooManyPaths", ErrTooManyPaths},
	{"ErrJustificationTooLarge", ErrJustificationTooLarge}, {"ErrLockProofTooLarge", ErrLockProofTooLarge},
	{"ErrCfgMismatch", ErrCfgMismatch}, {"ErrPolicyHash", ErrPolicyHash}, {"ErrPolicyTuple", ErrPolicyTuple},
	{"ErrPolicyAnchors", ErrPolicyAnchors}, {"ErrPolicyLeafIndex", ErrPolicyLeafIndex},
	{"ErrPolicyLeafCount", ErrPolicyLeafCount}, {"ErrPolicyPartition", ErrPolicyPartition},
	{"ErrPredicate", ErrPredicate}, {"ErrMintShape", ErrMintShape},
	{"ErrLockProofShape", ErrLockProofShape}, {"ErrLockProofCfg", ErrLockProofCfg}, {"ErrMintJustif", ErrMintJustif},
	{"ErrMintSalt", ErrMintSalt}, {"ErrMintType", ErrMintType}, {"ErrMintData", ErrMintData},
	{"ErrTransferData", ErrTransferData}, {"ErrCDMismatch", ErrCDMismatch}, {"ErrUnlock", ErrUnlock},
	{"ErrUnlockLength", ErrUnlockLength}, {"ErrUnlockScalars", ErrUnlockScalars}, {"ErrUnlockRecovery", ErrUnlockRecovery},
	{"ErrUnlockKey", ErrUnlockKey}, {"ErrMinterKey", ErrMinterKey}, {"ErrRepeatedSID", ErrRepeatedSID},
	{"ErrNoTransfers", ErrNoTransfers}, {"ErrHasTransfers", ErrHasTransfers}, {"ErrBurnNotFinal", ErrBurnNotFinal},
	{"ErrNotBurn", ErrNotBurn}, {"ErrBurnReason", ErrBurnReason}, {"ErrReturnData", ErrReturnData},
	{"ErrReturnAmount", ErrReturnAmount}, {"ErrReturnRecip", ErrReturnRecip}, {"ErrLockInput", ErrLockInput},
	{"ErrZeroDigest", ErrZeroDigest}, {"ErrDeadlineMismatch", ErrDeadlineMismatch}, {"ErrDeadlineExpired", ErrDeadlineExpired},
	{"ErrIROpening", ErrIROpening}, {"ErrIRShape", ErrIRShape}, {"ErrIRState", ErrIRState}, {"ErrIRTime", ErrIRTime},
	{"ErrAnchorAuth", ErrAnchorAuth}, {"ErrLeafProof", ErrLeafProof},
	{"ErrTrustBaseDigest", ErrTrustBaseDigest}, {"ErrEpochMismatch", ErrEpochMismatch}, {"ErrTrustConfig", ErrTrustConfig}, {"ErrLockUC", ErrLockUC},
	{"ErrLockPDR", ErrLockPDR}, {"ErrLockHeader", ErrLockHeader}, {"ErrLockAccount", ErrLockAccount},
	{"ErrLockCodeHash", ErrLockCodeHash}, {"ErrLockStorage", ErrLockStorage}, {"ErrLockDigest", ErrLockDigest},
	{"ErrMPTNode", ErrMPTNode}, {"ErrMPTPath", ErrMPTPath}, {"ErrMPTAbsent", ErrMPTAbsent}, {"ErrMPTExtraneous", ErrMPTExtraneous},
}

// Reason names the leaf sentinel err wraps and its family.
func Reason(err error) (name, family string) {
	for _, r := range reasons {
		if errors.Is(err, r.err) {
			name = r.name
			break
		}
	}
	switch {
	case errors.Is(err, ErrMalformed):
		family = "malformed"
	case errors.Is(err, ErrBudget):
		family = "budget"
	case errors.Is(err, ErrInvalid):
		family = "invalid"
	}
	return
}

func errExpect(err error) Expect {
	name, fam := Reason(err)
	return Expect{Status: "error", Family: fam, Reason: name}
}

func okValues(kv ...string) Expect {
	v := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		v[kv[i]] = kv[i+1]
	}
	return Expect{Status: "ok", Values: v}
}

func renderResult(r *Result) *RJSON {
	out := &RJSON{Cfg: h32(r.Cfg), Nonce: strconv.FormatUint(r.Nonce, 10), Amount: hx(AmountBytes(r.Amount)), TokenID: h32(r.TokenID),
		Salt: h32(r.Salt), FirstPredicateHash: h32(r.FirstPredicateHash), LockDigest: h32(r.LockDigest),
		ReleaseTo: hx(r.ReleaseTo[:]), Nullifier: h32(r.Nullifier), Leaves: []LeafJSON{}}
	for _, l := range r.Leaves {
		out.Leaves = append(out.Leaves, LeafJSON{SID: h32(l.SID), TxHash: h32(l.TxHash),
			ReferenceTime: strconv.FormatUint(l.ReferenceTime, 10), LeafValue: h32(l.Value)})
	}
	return out
}

func resultExpect(res *Result, err error) Expect {
	if err != nil {
		return errExpect(err)
	}
	out, _ := EncodeResult(true, res)
	return Expect{Status: "ok", Result: renderResult(res), Output: hx(out)}
}

// ClaimsB1 is the corpus's B1: anchor authentication is membership of the
// (expectedStateRoot, expectedIRHash) pair in an admitted claim set, and leaf
// membership is the real RSMT_MEMBER_V1. It states B1's contract, not its
// implementation; the UC machinery behind 0x0100 is B1's own conformance.
type ClaimsB1 struct{ Claims map[[64]byte]bool }

func claimKey(root, ir [32]byte) (k [64]byte) { copy(k[:32], root[:]); copy(k[32:], ir[:]); return }

// AuthenticateAnchor admits an anchor whose claim pair is in the set.
func (c ClaimsB1) AuthenticateAnchor(a *Anchor) error {
	if !c.Claims[claimKey(a.ExpectedStateRoot, a.ExpectedIRHash)] {
		return ErrAnchorAuth
	}
	return nil
}

// VerifyMember is the shared RSMT membership.
func (ClaimsB1) VerifyMember(root, key, value [32]byte, p LeafProof) error {
	return RefB1{}.VerifyMember(root, key, value, p)
}

func parseClaims(s string) (ClaimsB1, error) {
	c := ClaimsB1{Claims: map[[64]byte]bool{}}
	for _, p := range strings.Split(s, ";") {
		if p == "" {
			continue
		}
		parts := strings.Split(p, ":")
		if len(parts) != 2 {
			return c, fmt.Errorf("claim %q", p)
		}
		var r, i [32]byte
		a, err1 := hex.DecodeString(parts[0])
		b, err2 := hex.DecodeString(parts[1])
		if err1 != nil || err2 != nil || len(a) != 32 || len(b) != 32 {
			return c, fmt.Errorf("claim %q", p)
		}
		copy(r[:], a)
		copy(i[:], b)
		c.Claims[claimKey(r, i)] = true
	}
	return c, nil
}

func (fs *FixtureSet) cfg(name string) (*Cfg, error) {
	f, ok := fs.Cfgs[name]
	if !ok {
		return nil, fmt.Errorf("fixture %q", name)
	}
	b, err := hex.DecodeString(f.Cfg)
	if err != nil {
		return nil, err
	}
	return DecodeCfg(b)
}

func (fs *FixtureSet) policyBody(name string) []byte {
	b, _ := hex.DecodeString(fs.Cfgs[name].PolicyBody)
	return b
}

func (fs *FixtureSet) trustInput(name string) (*TrustInput, error) {
	raw, err := hex.DecodeString(fs.TrustBases[name])
	if err != nil || len(raw) == 0 {
		return nil, ErrTrustBaseDigest
	}
	return LoadTrustInput(raw)
}

func (fs *FixtureSet) pin(name string) (*DeploymentPin, error) {
	p, ok := fs.Pins[name]
	if !ok {
		return nil, nil
	}
	raw, err := hex.DecodeString(p.GenesisPDR)
	if err != nil {
		return nil, err
	}
	var pdr types.PartitionDescriptionRecord
	if err := types.Cbor.Unmarshal(raw, &pdr); err != nil {
		return nil, err
	}
	var ch [32]byte
	b, _ := hex.DecodeString(p.VaultCodeHash)
	copy(ch[:], b)
	return &DeploymentPin{Genesis: &pdr, VaultCodeHash: ch}, nil
}

// Replay executes a case against the oracle and returns the outcome. It is the
// definition of each op.
func Replay(fs *FixtureSet, c Case) Expect {
	var in []byte
	switch c.Op {
	case "identifiers", "value-data", "derive", "mpt": // textual inputs
	default:
		var err error
		if in, err = hex.DecodeString(c.Input); err != nil {
			return Expect{Status: "error", Reason: "bad-hex"}
		}
	}
	cfgOf := func() (*Cfg, error) { return fs.cfg(c.Cfg) }
	switch c.Op {
	case "identifiers":
		p := strings.Split(c.Input, ":") // network:rootGenesis:executionGenesis:chainId
		nw, _ := strconv.ParseUint(p[0], 10, 16)
		var r, x [32]byte
		a, _ := hex.DecodeString(p[1])
		b, _ := hex.DecodeString(p[2])
		copy(r[:], a)
		copy(x[:], b)
		ch, _ := strconv.ParseUint(p[3], 10, 64)
		return okValues("D", identityD(uint16(nw), r, x, ch), "ty", h32(DeriveType(uint16(nw), r, x, ch)), "aid", h32(DeriveAsset(uint16(nw), r, x, ch)))
	case "value-data":
		p := strings.Split(c.Input, ":") // aidHex:amountDecimal
		var aid [32]byte
		a, _ := hex.DecodeString(p[0])
		copy(aid[:], a)
		amt, _ := new(big.Int).SetString(p[1], 10)
		return okValues("data", hx(ValueData(aid, amt)))
	case "cfg-decode":
		cfg, err := DecodeCfg(in)
		if err != nil {
			return errExpect(err)
		}
		if !bytes.Equal(cfg.Bytes(), in) {
			return errExpect(ErrNonCanonical)
		}
		valid := "true"
		if cfg.Validate() != nil {
			valid = "false"
		}
		return okValues("cfgHash", h32(cfg.Hash()), "ty", h32(cfg.Ty), "aid", h32(cfg.Aid), "identitiesDerived", valid)
	case "derive":
		cfg, err := cfgOf()
		if err != nil {
			return errExpect(err)
		}
		n, _ := strconv.ParseUint(c.Input, 10, 64)
		amt, _ := new(big.Int).SetString(c.Aux["amount"], 10)
		rc, _ := hex.DecodeString(c.Aux["firstPredicateHash"])
		var rcp [32]byte
		copy(rcp[:], rc)
		ch := cfg.Hash()
		salt := DeriveSalt(ch, n)
		id := DeriveTokenID(salt, cfg.Network)
		k := LockRecord(cfg.ZeroAddress, cfg.Ty, cfg.Aid, amt, id, rcp)
		d := LockDigest(ch, n, k)
		slot, spent := LockDigestSlot(n), SpentSlot(n)
		return okValues("cfg", h32(ch), "salt", h32(salt), "tokenId", h32(id), "mintSourceHash", h32(MintSourceHash(id)),
			"lockRecord", hx(k), "lockDigest", h32(d), "lockSlot", h32(slot), "lockTrieKey", h32(StorageTrieKey(slot)),
			"spentSlot", h32(spent), "spentTrieKey", h32(StorageTrieKey(spent)), "storageValueRLP", hx(StorageValueRLP(d)))
	case "unlock":
		var sh, th [32]byte
		if len(in) < 64 {
			return errExpect(ErrUnlockLength)
		}
		copy(sh[:], in[:32])
		copy(th[:], in[32:64])
		kb, _ := hex.DecodeString(c.Aux["key"])
		pk, perr := ParseKey(kb)
		if perr != nil {
			return errExpect(perr)
		}
		if err := VerifyUnlock(pk, sh, th, in[64:]); err != nil {
			return errExpect(err)
		}
		return Expect{Status: "ok"}
	case "policy-decode":
		if _, err := DecodePolicy(in); err != nil {
			return errExpect(err)
		}
		return Expect{Status: "ok"}
	case "envelope-policy":
		cfg, err := cfgOf()
		if err != nil {
			return errExpect(err)
		}
		leaves, _ := strconv.Atoi(c.Aux["leaves"])
		env, err := DecodeEnvelope(in)
		if err == nil {
			_, err = CheckPolicy(cfg, env, leaves)
		}
		if err != nil {
			return errExpect(err)
		}
		return Expect{Status: "ok"}
	case "prepareLock":
		cfg, err := cfgOf()
		if err != nil {
			return errExpect(err)
		}
		n, _ := strconv.ParseUint(c.Aux["n"], 10, 64)
		amt, _ := new(big.Int).SetString(c.Aux["amount"], 10)
		res, err := PrepareLock(cfg, n, amt, in)
		return resultExpect(res, err)
	case "mint", "return":
		cfg, err := cfgOf()
		if err != nil {
			return errExpect(err)
		}
		var res *Result
		if c.Op == "mint" {
			res, err = VerifyMint(cfg, in)
		} else {
			res, err = VerifyReturn(cfg, in)
		}
		return resultExpect(res, err)
	case "token-project":
		p, err := ProjectToken(in)
		if err != nil {
			return errExpect(err)
		}
		return okValues("projection", hx(p))
	case "kernel":
		out, err := Kernel(in)
		if err != nil {
			return errExpect(err)
		}
		return Expect{Status: "ok", Output: hx(out)}
	case "justification":
		cfg, err := cfgOf()
		if err != nil {
			return errExpect(err)
		}
		n, lp, err := ParseJustification(cfg, in)
		if err != nil {
			return errExpect(err)
		}
		return okValues("nonce", strconv.FormatUint(n, 10), "proofCfg", h32(lp.Cfg), "trustBaseId", h32(lp.TrustBaseID))
	case "lock-backing":
		cfg, err := cfgOf()
		if err != nil {
			return errExpect(err)
		}
		h, err := DecodeHistory(in)
		if err != nil {
			return errExpect(err)
		}
		tb, err := fs.trustInput(c.Aux["trustBase"])
		if err != nil {
			return errExpect(err)
		}
		pin, err := fs.pin(c.Aux["pin"])
		if err != nil {
			return errExpect(err)
		}
		if err := VerifyMintBacking(cfg, h, tb, pin); err != nil {
			return errExpect(err)
		}
		return Expect{Status: "ok"}
	case "mpt":
		var root, key [32]byte
		r, _ := hex.DecodeString(c.Aux["root"])
		k, _ := hex.DecodeString(c.Aux["key"])
		copy(root[:], r)
		copy(key[:], k)
		var nodes [][]byte
		for _, n := range strings.Split(c.Aux["nodes"], ",") {
			if n != "" {
				b, _ := hex.DecodeString(n)
				nodes = append(nodes, b)
			}
		}
		v, err := mptVerify(root, key, nodes)
		if err != nil {
			return errExpect(err)
		}
		return okValues("value", hx(v))
	case "compose":
		cfg, err := cfgOf()
		if err != nil {
			return errExpect(err)
		}
		b1, err := parseClaims(c.Aux["claims"])
		if err != nil {
			return errExpect(err)
		}
		op := uint8(OpReturn)
		if c.Aux["operation"] == "mint" {
			op = OpMint
		}
		res, err := Compose(cfg, op, in, b1)
		return resultExpect(res, err)
	}
	return Expect{Status: "error", Reason: "unknown-op"}
}

// ExpectJSON renders an Expect for comparison.
func ExpectJSON(e Expect) string { b, _ := json.Marshal(e); return string(b) }
