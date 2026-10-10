package bridgeprofile

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// The builders below construct valid histories for the vectors, tests and
// benchmarks. They are the oracle's own construction; J and R construct tokens
// independently in their repositories.

// Fixture is a deterministic deployment fixture: an instantiated Cfg, its
// policy and the underlying literal inputs.
type Fixture struct {
	Cfg    *Cfg
	Policy Policy
}

// NewFixture builds the DEV fixture Cfg from literal inputs. The aggregator
// partition differs from the EVM partition.
func NewFixture(chainID uint64, aggPartition uint32, aggConfs ...[32]byte) *Fixture {
	var c Cfg
	c.Network = 3
	c.RootGenesis = H([]byte("fixture-root-genesis"))
	c.ChainID = chainID
	c.ExecutionGenesis = H([]byte("fixture-execution-genesis"))
	c.EVMPartition = 7
	c.EVMShard = EmptyPrefixShard
	vh := H([]byte("fixture-vault"))
	copy(c.Vault[:], vh[:20])
	th := H([]byte("fixture-verifier"))
	copy(c.TokenVerifierAddress[:], th[:20])
	c.TokenVerifierCodeHash = H([]byte("fixture-verifier-code"))
	c.SemanticProfileHash = H([]byte("fixture-semantic-profile"))
	c.B1ProfileHash = H([]byte("fixture-b1-profile"))
	c.Ty = DeriveType(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
	c.Aid = DeriveAsset(c.Network, c.RootGenesis, c.ExecutionGenesis, c.ChainID)
	pol := NewPolicy(aggPartition, aggConfs...)
	c.AggregatorPolicyHash = pol.Hash()
	return &Fixture{Cfg: &c, Policy: pol}
}

// KeyFromSeed derives a deterministic signing key.
func KeyFromSeed(seed string) *secp256k1.PrivateKey {
	for i := 0; ; i++ {
		k := H(append([]byte(seed), byte(i)))
		var sc secp256k1.ModNScalar
		if !sc.SetByteSlice(k[:]) && !sc.IsZero() {
			return secp256k1.PrivKeyFromBytes(k[:])
		}
	}
}

func sigPred(k *secp256k1.PrivateKey) Predicate {
	return SignaturePredicate(k.PubKey().SerializeCompressed())
}

// BaseTime is the reference time of a fixture history's mint; transfer i is
// certified at BaseTime+10*i seconds. Fixture times are small and fixed so a
// vector never depends on a clock.
const BaseTime uint64 = 1_700_000_000

// StructuralProof is a deterministic placeholder LockProof bound to the
// fixture's cfg. It satisfies the kernel's structural scan and cfg binding and
// authenticates nothing; real evidence is built by LockFixture.
func (f *Fixture) StructuralProof(n uint64) *LockProof {
	d := func(label string) []byte { h := H(append([]byte(label), CUint(n)...)); return h[:] }
	return &LockProof{Cfg: f.Cfg.Hash(), TrustBaseID: H([]byte("fixture-trust-base-id")),
		PDR: d("pdr"), UC: d("uc"), Header: d("header"),
		AccountNodes: [][]byte{d("account-node")}, StorageNodes: [][]byte{d("storage-node")}}
}

// BuildOpts selects the optional parts of a built history; the zero value is
// the null-deadline default with a structural proof.
type BuildOpts struct {
	Proof        *LockProof
	MintDeadline Deadline
}

// BuildToken builds a lock-backed token for nonce n and amount whose first
// owner is keys[0], transferred through keys[1:], with no burn.
func (f *Fixture) BuildToken(n uint64, amount *big.Int, keys []*secp256k1.PrivateKey) (*History, error) {
	return f.BuildTokenWith(n, amount, keys, BuildOpts{})
}

// BuildTokenWith is BuildToken with explicit options.
func (f *Fixture) BuildTokenWith(n uint64, amount *big.Int, keys []*secp256k1.PrivateKey, o BuildOpts) (*History, error) {
	cfg := f.Cfg
	ch := cfg.Hash()
	salt := DeriveSalt(ch, n)
	id := DeriveTokenID(salt, cfg.Network)
	if o.Proof == nil {
		o.Proof = f.StructuralProof(n)
	}
	m := MintTx{Network: cfg.Network, Recipient: sigPred(keys[0]), Salt: salt, Type: cfg.Ty,
		Justification: MintJustification(cfg.ChainID, cfg.Vault, cfg.ZeroAddress, n, o.Proof), Data: ValueData(cfg.Aid, amount),
		Deadline: o.MintDeadline}
	mk, err := MinterKey(id)
	if err != nil {
		return nil, err
	}
	h0 := MintSourceHash(id)
	raw := m.Bytes()
	cd := Certification{Source: sigPred(mk), SourceHash: h0, TxHash: H(raw), Deadline: m.Deadline}
	cd.Unlock = SignUnlock(mk, cd.SourceHash, cd.TxHash)
	h := &History{Mint: m, MintCD: cd, MintTime: BaseTime, mintRaw: raw}
	state := ResultState(h0, id[:])
	owner := keys[0]
	for i := 1; i < len(keys); i++ {
		if err := h.appendTransfer(&state, owner, sigPred(keys[i]), nil, uint64(i)); err != nil {
			return nil, err
		}
		owner = keys[i]
	}
	return h, nil
}

// AppendBurn adds the terminal return transfer to the current owner.
func (f *Fixture) AppendBurn(h *History, owner *secp256k1.PrivateKey, recipient [20]byte, amount *big.Int) {
	cfg := f.Cfg
	r := ReturnReason(cfg.ChainID, cfg.Vault, cfg.ZeroAddress, cfg.Ty, cfg.Aid, recipient, amount)
	state := h.finalState(cfg)
	_ = h.appendTransfer(&state, owner, BurnPredicate(H(r)), r, 1000)
}

func (h *History) finalState(cfg *Cfg) [32]byte {
	id := DeriveTokenID(h.Mint.Salt, cfg.Network)
	st := ResultState(MintSourceHash(id), id[:])
	for i := range h.Transfers {
		st = ResultState(st, h.Transfers[i].Mask[:])
	}
	return st
}

func (h *History) appendTransfer(state *[32]byte, owner *secp256k1.PrivateKey, next Predicate, data []byte, i uint64) error {
	mask := H(append(append([]byte("mask"), h.Mint.Salt[:]...), CUint(i)...))
	t := TransferTx{Recipient: next, Mask: mask, Data: data}
	raw := t.Bytes()
	cd := Certification{Source: sigPred(owner), SourceHash: *state, TxHash: H(raw), Deadline: t.Deadline}
	cd.Unlock = SignUnlock(owner, cd.SourceHash, cd.TxHash)
	h.Transfers = append(h.Transfers, t)
	h.CDs = append(h.CDs, cd)
	h.Times = append(h.Times, BaseTime+10*uint64(len(h.Transfers)))
	h.transfersRaw = append(h.transfersRaw, raw)
	*state = ResultState(*state, mask[:])
	return nil
}

// Refresh re-derives the cached raw encodings after a field mutation, so a
// mutated history can be re-encoded and decoded from bytes.
func (h *History) Refresh() {
	h.mintRaw = h.Mint.Bytes()
	h.transfersRaw = h.transfersRaw[:0]
	for i := range h.Transfers {
		h.transfersRaw = append(h.transfersRaw, h.Transfers[i].Bytes())
	}
}

// Resign recomputes every certification data item of h from its current
// transactions, so a test can mutate exactly one property and keep the rest of
// the history self-consistent. owners[i] signs transfer i; the minter key is
// derived from the mint's salt and network.
func (h *History) Resign(owners []*secp256k1.PrivateKey) error {
	h.Refresh()
	id := DeriveTokenID(h.Mint.Salt, h.Mint.Network)
	mk, err := MinterKey(id)
	if err != nil {
		return err
	}
	h0 := MintSourceHash(id)
	h.MintCD = Certification{Source: sigPred(mk), SourceHash: h0, TxHash: H(h.mintRaw), Deadline: h.Mint.Deadline}
	h.MintCD.Unlock = SignUnlock(mk, h.MintCD.SourceHash, h.MintCD.TxHash)
	state := ResultState(h0, id[:])
	h.CDs = h.CDs[:0]
	for i := range h.Transfers {
		cd := Certification{Source: sigPred(owners[i]), SourceHash: state, TxHash: H(h.transfersRaw[i]), Deadline: h.Transfers[i].Deadline}
		cd.Unlock = SignUnlock(owners[i], cd.SourceHash, cd.TxHash)
		h.CDs = append(h.CDs, cd)
		state = ResultState(state, h.Transfers[i].Mask[:])
	}
	return nil
}

// HighRecoveryUnlock constructs a signature whose recovery ID is 2 or 3: the
// signing point R has x = r+n. A real signer meets this with probability about
// 2^-128, so the vector fixes r small and chooses R first; the matching public
// key Q = r^-1 (s*R - z*G) then has no known private key but verifies (r,s)
// over digest z and is recovered by the supplied ID. It returns the compressed
// key, the 65-byte unlock and the ID.
func HighRecoveryUnlock(sourceHash, txHash [32]byte) (key []byte, unlock []byte) {
	digest := UnlockMessage(sourceHash, txHash)
	var z, s, r, rinv, negz secp256k1.ModNScalar
	z.SetByteSlice(digest[:])
	sh0 := H([]byte("high-recovery-s"))
	s.SetByteSlice(sh0[:])
	if s.IsOverHalfOrder() {
		s.Negate()
	}
	for rv := uint16(1); ; rv++ {
		r.SetInt(uint32(rv))
		var x, y secp256k1.FieldVal
		// x = n + r as a field element (n + r < p for small r).
		nb := secpN.FillBytes(make([]byte, 32))
		x.SetByteSlice(nb)
		var rf secp256k1.FieldVal
		rf.SetInt(rv)
		x.Add(&rf)
		x.Normalize()
		var yOdd bool
		if !secp256k1.DecompressY(&x, false, &y) {
			continue
		}
		y.Normalize()
		yOdd = y.IsOdd()
		var R, sR, zG, sum, Q secp256k1.JacobianPoint
		R.X, R.Y = x, y
		R.Z.SetInt(1)
		secp256k1.ScalarMultNonConst(&s, &R, &sR)
		negz.Set(&z)
		negz.Negate()
		secp256k1.ScalarBaseMultNonConst(&negz, &zG)
		secp256k1.AddNonConst(&sR, &zG, &sum)
		rinv.Set(&r)
		rinv.InverseNonConst()
		secp256k1.ScalarMultNonConst(&rinv, &sum, &Q)
		Q.ToAffine()
		pub := secp256k1.NewPublicKey(&Q.X, &Q.Y)
		unlock = make([]byte, 65)
		rb, sb := r.Bytes(), s.Bytes()
		copy(unlock[:32], rb[:])
		copy(unlock[32:64], sb[:])
		unlock[64] = 2
		if yOdd {
			unlock[64] = 3
		}
		return pub.SerializeCompressed(), unlock
	}
}
