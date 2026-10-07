package bridgeprofile

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"net"
	"net/http"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

var errNetwork = errors.New("network is disabled in this test")

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, errNetwork }

func oneKey() []*secp256k1.PrivateKey { return []*secp256k1.PrivateKey{KeyFromSeed("lock-a")} }

func TestLockProofPositive(t *testing.T) {
	e := newEnv(t)
	h, _ := e.backedToken(t, 5, amt, oneKey())
	_, err := VerifyMint(e.F.Cfg, h.Bytes())
	require.NoError(t, err)
	require.NoError(t, VerifyMintBacking(e.F.Cfg, h, e.Trust, e.Pin))
}

// Receipt verification reads only the token and the pinned bundle: with every
// network path failing it still succeeds.
func TestLockProofVerifiesWithTheNetworkDisabled(t *testing.T) {
	e := newEnv(t)
	h, _ := e.backedToken(t, 5, amt, oneKey())
	oldT, oldD := http.DefaultTransport, net.DefaultResolver.Dial
	http.DefaultTransport = failTransport{}
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(context_ context.Context, n, a string) (net.Conn, error) { return nil, errNetwork }
	defer func() { http.DefaultTransport, net.DefaultResolver.Dial = oldT, oldD }()
	require.NoError(t, VerifyMintBacking(e.F.Cfg, h, e.Trust, e.Pin))
}

// remint rebuilds the history around a mutated proof (CDs re-signed): the
// isolated failing relation is the proof, not the certification.
func (e *env) remint(t testing.TB, lp *LockProof, mut func(lp *LockProof)) *History {
	t.Helper()
	c := *lp
	mut(&c)
	h, err := e.F.BuildTokenWith(5, amt, oneKey(), BuildOpts{Proof: &c})
	require.NoError(t, err)
	return h
}

func TestLockProofMutations(t *testing.T) {
	e := newEnv(t)
	_, lp := e.backedToken(t, 5, amt, oneKey())
	verify := func(h *History) error { return VerifyMintBacking(e.F.Cfg, h, e.Trust, e.Pin) }
	flip := func(b []byte, i int) []byte { c := bytes.Clone(b); c[i] ^= 1; return c }
	reUC := func(f func(uc *types.UnicityCertificate)) func(lp *LockProof) {
		return func(lp *LockProof) {
			var uc types.UnicityCertificate
			require.NoError(t, types.Cbor.Unmarshal(lp.UC, &uc))
			f(&uc)
			b, err := types.Cbor.Marshal(&uc)
			require.NoError(t, err)
			lp.UC = b
		}
	}
	cases := []struct {
		name string
		mut  func(lp *LockProof)
		want error
	}{
		{"unknown trust epoch", func(lp *LockProof) { lp.TrustBaseID[0] ^= 1 }, ErrTrustBaseDigest},
		{"cfg of another deployment", func(lp *LockProof) { lp.Cfg[0] ^= 1 }, ErrLockProofCfg},
		{"uc seal signature", reUC(func(uc *types.UnicityCertificate) {
			for k, v := range uc.UnicitySeal.Signatures {
				c := bytes.Clone(v)
				c[3] ^= 1
				uc.UnicitySeal.Signatures[k] = c
			}
		}), ErrLockUC},
		{"uc input record hash", reUC(func(uc *types.UnicityCertificate) { uc.InputRecord.Hash[0] ^= 1 }), ErrLockUC},
		{"uc seal network", reUC(func(uc *types.UnicityCertificate) { uc.UnicitySeal.NetworkID++ }), ErrEpochMismatch},
		{"uc noncanonical", func(lp *LockProof) { lp.UC = append(bytes.Clone(lp.UC), 0) }, ErrLockUC},
		{"uc undecodable", func(lp *LockProof) { lp.UC = []byte{1, 2, 3} }, ErrLockUC},
		{"pdr noncanonical", func(lp *LockProof) { lp.PDR = append(bytes.Clone(lp.PDR), 0) }, ErrLockPDR},
		{"pdr bytes flipped", func(lp *LockProof) { lp.PDR = flip(lp.PDR, len(lp.PDR)-2) }, ErrLockPDR},
		{"header bytes flipped", func(lp *LockProof) { lp.Header = flip(lp.Header, 40) }, ErrLockHeader},
		{"header undecodable", func(lp *LockProof) { lp.Header = []byte{1} }, ErrLockHeader},
		{"account node flipped", func(lp *LockProof) { lp.AccountNodes = cloneNodes(lp.AccountNodes); lp.AccountNodes[0][5] ^= 1 }, ErrLockAccount},
		{"account extraneous node", func(lp *LockProof) { lp.AccountNodes = append(cloneNodes(lp.AccountNodes), lp.AccountNodes[0]) }, ErrMPTExtraneous},
		{"account node dropped", func(lp *LockProof) { lp.AccountNodes = lp.AccountNodes[:len(lp.AccountNodes)-1] }, ErrLockAccount},
		{"storage node flipped", func(lp *LockProof) { lp.StorageNodes = cloneNodes(lp.StorageNodes); lp.StorageNodes[0][3] ^= 1 }, ErrLockStorage},
		{"storage extraneous node", func(lp *LockProof) { lp.StorageNodes = append(cloneNodes(lp.StorageNodes), lp.StorageNodes[0]) }, ErrMPTExtraneous},
		{"storage proof of the account trie", func(lp *LockProof) { lp.StorageNodes = lp.AccountNodes }, ErrLockStorage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := verify(e.remint(t, lp, c.mut))
			require.ErrorIs(t, err, c.want)
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
	t.Run("header not bound to the certified input record", func(t *testing.T) {
		// A certificate over an unrelated state root, with a header that does not match it.
		w := &LockWorld{Vault: e.World.Vault, VaultCodeHash: e.World.VaultCodeHash, Locks: map[uint64][32]byte{5: e.World.Locks[5]}, Filler: 2}
		other, err := w.Certified(e.F, e.Auth, e.EVMPDR, e.Trust, testRound, 5, 9)
		require.NoError(t, err)
		mixed := *lp
		mixed.UC = other.UC // signed over another state root and header hash
		require.ErrorIs(t, verify(e.remint(t, &mixed, func(*LockProof) {})), ErrLockHeader)
	})
	certifiedWith := func(mut func(ir *types.InputRecord)) *History {
		p, err := e.World.CertifiedWith(e.F, e.Auth, e.EVMPDR, e.Trust, testRound, 5, 9, mut)
		require.NoError(t, err)
		return e.remint(t, p, func(*LockProof) {})
	}
	t.Run("input record state hash is not the header state root", func(t *testing.T) {
		h := certifiedWith(func(ir *types.InputRecord) { ir.Hash = sl(H([]byte("unrelated-state-root"))) })
		require.ErrorIs(t, verify(h), ErrLockHeader)
	})
	t.Run("input record block hash is not the header hash", func(t *testing.T) {
		h := certifiedWith(func(ir *types.InputRecord) { ir.BlockHash = sl(H([]byte("unrelated-block"))) })
		require.ErrorIs(t, verify(h), ErrLockHeader)
	})
	t.Run("certified shard epoch differs from the carried configuration's", func(t *testing.T) {
		h := certifiedWith(func(ir *types.InputRecord) { ir.Epoch = 5 })
		require.ErrorIs(t, verify(h), ErrLockPDR)
	})
	t.Run("certificate of another network under a base of that network", func(t *testing.T) {
		auth := e.Auth
		tb4, err := auth.TrustBase(4, 1)
		require.NoError(t, err)
		b, _ := RenderTrustBaseJSON(tb4)
		t4, err := LoadTrustInput(b)
		require.NoError(t, err)
		p, err := e.World.Certified(e.F, auth, e.EVMPDR, t4, testRound, 5, 9)
		require.NoError(t, err)
		require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, e.remint(t, p, func(*LockProof) {}), t4, e.Pin), ErrEpochMismatch)
	})
	t.Run("VerifyLockProof binds the cfg itself", func(t *testing.T) {
		c := *lp
		c.Cfg[0] ^= 1
		require.ErrorIs(t, VerifyLockProof(&c, e.F.Cfg, 5, e.World.Locks[5], e.Trust, e.Pin), ErrLockProofCfg)
	})
	t.Run("vault runtime pin", func(t *testing.T) {
		pin := *e.Pin
		pin.VaultCodeHash[0] ^= 1
		h := e.remint(t, lp, func(*LockProof) {})
		require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, h, e.Trust, &pin), ErrLockCodeHash)
	})
	t.Run("deployment pin: another genesis configuration", func(t *testing.T) {
		pin := *e.Pin
		g := *e.EVMPDR
		g.T2Timeout++
		pin.Genesis = &g
		h := e.remint(t, lp, func(*LockProof) {})
		require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, h, e.Trust, &pin), ErrLockPDR)
	})
	t.Run("deployment pin missing", func(t *testing.T) {
		h := e.remint(t, lp, func(*LockProof) {})
		require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, h, e.Trust, nil), ErrLockPDR)
	})
}

// Every field of the mint is bound to the stored lock word.
func TestLockProofBindsTheMint(t *testing.T) {
	e := newEnv(t)
	keys := oneKey()
	_, lp := e.backedToken(t, 5, amt, keys)
	build := func(n uint64, a *big.Int, k *secp256k1.PrivateKey) *History {
		h, err := e.F.BuildTokenWith(n, a, []*secp256k1.PrivateKey{k}, BuildOpts{Proof: lpFor(lp, e.F, n)})
		require.NoError(t, err)
		return h
	}
	require.NoError(t, VerifyMintBacking(e.F.Cfg, build(5, amt, keys[0]), e.Trust, e.Pin))
	require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, build(5, new(big.Int).Add(amt, big.NewInt(1)), keys[0]), e.Trust, e.Pin), ErrLockDigest, "amount")
	require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, build(5, amt, KeyFromSeed("thief")), e.Trust, e.Pin), ErrLockDigest, "recipient")
	// Another nonce: the storage key differs and the supplied nodes prove another word.
	err := VerifyMintBacking(e.F.Cfg, build(6, amt, keys[0]), e.Trust, e.Pin)
	require.ErrorIs(t, err, ErrLockStorage)
	// A zero (absent or unset) word is never a lock.
	e.World.Locks[7] = [32]byte{}
	zp, err := e.World.Certified(e.F, e.Auth, e.EVMPDR, e.Trust, testRound, 7, 10)
	require.NoError(t, err)
	h, err := e.F.BuildTokenWith(7, amt, keys, BuildOpts{Proof: zp})
	require.NoError(t, err)
	require.Error(t, VerifyMintBacking(e.F.Cfg, h, e.Trust, e.Pin))
}

func lpFor(lp *LockProof, f *Fixture, n uint64) *LockProof { c := *lp; c.Cfg = f.Cfg.Hash(); return &c }

// J is committed by the mint transaction hash: changing it after certification
// breaks the certification, never silently re-proves.
func TestLockProofMutationAfterCertification(t *testing.T) {
	e := newEnv(t)
	h, _ := e.backedToken(t, 5, amt, oneKey())
	h.Mint.Justification = bytes.Clone(h.Mint.Justification)
	h.Mint.Justification[len(h.Mint.Justification)-3] ^= 1
	h.Refresh()
	_, err := VerifyMint(e.F.Cfg, roundTrip(t, h))
	require.ErrorIs(t, err, ErrCDMismatch)
}

// One pinned SDK trust-base document. Trust-base evolution (epochs, appended
// records, newer bases, weights) is common SDK work for later: the scenarios
// below are rejections, never support.
func TestLockProofFixedProfile(t *testing.T) {
	e := newEnv(t)
	h, lp := e.backedToken(t, 5, amt, oneKey())
	require.NoError(t, VerifyMintBacking(e.F.Cfg, h, e.Trust, e.Pin))
	inst := func(tb *types.RootTrustBaseV1) *TrustInput {
		b, err := RenderTrustBaseJSON(tb)
		require.NoError(t, err)
		ti, err := LoadTrustInput(b)
		require.NoError(t, err)
		return ti
	}
	// Digest: a different document (another epoch, same keys) is another id.
	next, err := e.Auth.TrustBase(3, 2)
	require.NoError(t, err)
	require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, h, inst(next), e.Pin), ErrTrustBaseDigest)
	require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, h, nil, e.Pin), ErrTrustBaseDigest)
	rogue, _ := NewAuthority("rogue")
	rtb, err := rogue.TrustBase(3, 1)
	require.NoError(t, err)
	require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, h, inst(rtb), e.Pin), ErrTrustBaseDigest)
	// The digest is of the installed bytes: a semantically equal re-serialisation is another id.
	re := bytes.Replace(e.Trust.JSON, []byte(`"epoch":"1"`), []byte(`"epoch": "1"`), 1)
	require.NotEqual(t, e.Trust.JSON, re)
	rti, err := LoadTrustInput(re)
	require.NoError(t, err)
	require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, h, rti, e.Pin), ErrTrustBaseDigest)
	// Epoch scope guards, with the proof naming the installed document.
	named := func(ti *TrustInput) *History {
		c := *lp
		c.TrustBaseID = ti.ID()
		hh, err := e.F.BuildTokenWith(5, amt, oneKey(), BuildOpts{Proof: &c})
		require.NoError(t, err)
		return hh
	}
	ti2 := inst(next)
	require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, named(ti2), ti2, e.Pin), ErrEpochMismatch, "seal epoch 1, base epoch 2")
	late, err := e.Auth.TrustBaseWith(3, 1, testRound+1)
	require.NoError(t, err)
	tl := inst(late)
	require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, named(tl), tl, e.Pin), ErrEpochMismatch, "root round before epochStartRound")
	early, err := e.Auth.TrustBaseWith(3, 1, testRound)
	require.NoError(t, err)
	te := inst(early)
	require.NoError(t, VerifyMintBacking(e.F.Cfg, named(te), te, e.Pin), "root round equal to epochStartRound")
	net, err := e.Auth.TrustBase(4, 1)
	require.NoError(t, err)
	tn := inst(net)
	require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, named(tn), tn, e.Pin), ErrEpochMismatch, "another network")
}

func TestTrustInputRejectsUnsupportedConfiguration(t *testing.T) {
	e := newEnv(t)
	render := func(mut func(tb *types.RootTrustBaseV1)) []byte {
		tb := *e.TB
		mut(&tb)
		b, err := RenderTrustBaseJSON(&tb)
		require.NoError(t, err)
		return b
	}
	for name, mut := range map[string]func(tb *types.RootTrustBaseV1){
		"weight 2": func(tb *types.RootTrustBaseV1) {
			tb.RootNodes = []*types.NodeInfo{{NodeID: "a", SigKey: tb.RootNodes[0].SigKey, Stake: 2}}
		},
		"weight 0": func(tb *types.RootTrustBaseV1) {
			tb.RootNodes = []*types.NodeInfo{{NodeID: "a", SigKey: tb.RootNodes[0].SigKey, Stake: 0}}
		},
		"threshold 2 of 1": func(tb *types.RootTrustBaseV1) { tb.QuorumThreshold = 2 },
		"threshold 0":      func(tb *types.RootTrustBaseV1) { tb.QuorumThreshold = 0 },
		"no nodes":         func(tb *types.RootTrustBaseV1) { tb.RootNodes = nil },
		"epoch 0":          func(tb *types.RootTrustBaseV1) { tb.Epoch = 0 },
		"version 2":        func(tb *types.RootTrustBaseV1) { tb.Version = 2 },
		"duplicate node id": func(tb *types.RootTrustBaseV1) {
			a := tb.RootNodes[0]
			tb.RootNodes = []*types.NodeInfo{a, a}
			tb.QuorumThreshold = 2
		},
	} {
		_, err := LoadTrustInput(render(mut))
		require.ErrorIs(t, err, ErrTrustConfig, name)
	}
	_, err := LoadTrustInput([]byte("not json"))
	require.ErrorIs(t, err, ErrTrustConfig)
	// N=4 requires 3, N=7 requires 5, N=3 requires 3 (N-(N-1)/3).
	for _, c := range []struct{ n, q uint64 }{{1, 1}, {3, 3}, {4, 3}, {7, 5}, {10, 7}} {
		tb := *e.TB
		tb.RootNodes = nil
		for i := uint64(0); i < c.n; i++ {
			tb.RootNodes = append(tb.RootNodes, &types.NodeInfo{NodeID: string(rune('a' + i)), SigKey: e.TB.RootNodes[0].SigKey, Stake: 1})
		}
		tb.QuorumThreshold = c.q
		b, _ := RenderTrustBaseJSON(&tb)
		_, err := LoadTrustInput(b)
		require.NoError(t, err, "N=%d q=%d", c.n, c.q)
		tb.QuorumThreshold = c.q - 1
		b, _ = RenderTrustBaseJSON(&tb)
		_, err = LoadTrustInput(b)
		require.ErrorIs(t, err, ErrTrustConfig, "N=%d q=%d", c.n, c.q-1)
	}
}

// A quorum certificate signed by a member outside the selected trust base fails.
func TestLockProofForeignSigner(t *testing.T) {
	e := newEnv(t)
	rogue, err := NewAuthority("rogue")
	require.NoError(t, err)
	e.Auth = rogue // certificates signed by the rogue; the installed document stays the pinned one
	h, _ := e.backedToken(t, 5, amt, oneKey())
	// The proof names the rogue's trust base id? No: it names the pinned id, so UC verification fails.
	lpb := *mustProof(t, h)
	id := e.Trust.ID()
	lpb.TrustBaseID = id
	hh := e.remint(t, &lpb, func(*LockProof) {})
	require.ErrorIs(t, VerifyMintBacking(e.F.Cfg, hh, e.Trust, e.Pin), ErrLockUC)
}

func mustProof(t testing.TB, h *History) *LockProof {
	t.Helper()
	root, err := scanOne(h.Mint.Justification)
	require.NoError(t, err)
	lp, err := decodeLockProof(&root.kids[0].kids[5])
	require.NoError(t, err)
	return lp
}

// --- bounds: each cap is accepted exactly and rejected one over --------------------

func TestEvidenceBounds(t *testing.T) {
	f := fix()
	parse := func(mut func(lp *LockProof)) error {
		lp := f.StructuralProof(5)
		mut(lp)
		_, _, err := ParseJustification(f.Cfg, MintJustification(f.Cfg.ChainID, f.Cfg.Vault, f.Cfg.ZeroAddress, 5, lp))
		return err
	}
	fill := func(n int) []byte { return bytes.Repeat([]byte{7}, n) }
	nodes := func(n, size int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = fill(size)
		}
		return out
	}
	for _, c := range []struct {
		name string
		at   func(lp *LockProof)
		over func(lp *LockProof)
	}{
		{"pdr", func(lp *LockProof) { lp.PDR = fill(MaxLockPDRBytes) }, func(lp *LockProof) { lp.PDR = fill(MaxLockPDRBytes + 1) }},
		{"uc", func(lp *LockProof) { lp.UC = fill(MaxLockUCBytes) }, func(lp *LockProof) { lp.UC = fill(MaxLockUCBytes + 1) }},
		{"header", func(lp *LockProof) { lp.Header = fill(MaxLockHeaderBytes) }, func(lp *LockProof) { lp.Header = fill(MaxLockHeaderBytes + 1) }},
		{"node size", func(lp *LockProof) { lp.AccountNodes = nodes(1, MaxMPTNodeBytes) }, func(lp *LockProof) { lp.AccountNodes = nodes(1, MaxMPTNodeBytes+1) }},
		{"node count", func(lp *LockProof) { lp.AccountNodes = nodes(MaxMPTNodes, 8) }, func(lp *LockProof) { lp.AccountNodes = nodes(MaxMPTNodes+1, 8) }},
		{"combined mpt bytes", func(lp *LockProof) {
			lp.AccountNodes = nodes(12, MaxMPTNodeBytes)
			lp.StorageNodes = nodes(12, MaxMPTNodeBytes)
		}, func(lp *LockProof) {
			lp.AccountNodes = nodes(12, MaxMPTNodeBytes)
			lp.StorageNodes = append(nodes(12, MaxMPTNodeBytes), fill(1))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			require.NoError(t, parse(c.at))
			err := parse(c.over)
			require.ErrorIs(t, err, ErrLockProofTooLarge)
			require.ErrorIs(t, err, ErrBudget)
		})
	}
	// Shape: empty parts and empty node lists are not proofs.
	require.ErrorIs(t, parse(func(lp *LockProof) { lp.UC = nil }), ErrLockProofShape)
	require.ErrorIs(t, parse(func(lp *LockProof) { lp.AccountNodes = nil }), ErrLockProofShape)
	require.ErrorIs(t, parse(func(lp *LockProof) { lp.StorageNodes = nil }), ErrLockProofShape)
	// J itself: the justification bound is checked before any scan.
	j := make([]byte, MaxJustificationBytes+1)
	_, _, err := ParseJustification(f.Cfg, j)
	require.ErrorIs(t, err, ErrJustificationTooLarge)
	require.ErrorIs(t, err, ErrBudget)
	// LockProof arity and version are exact.
	lp := f.StructuralProof(5)
	good := lp.Bytes()
	for name, bad := range map[string][]byte{
		"version 2": CArr(CUint(2), CBytes(lp.Cfg[:]), CBytes(lp.TrustBaseID[:]), CBytes(lp.PDR), CBytes(lp.UC), CBytes(lp.Header), CArr(CBytes(lp.AccountNodes[0])), CArr(CBytes(lp.StorageNodes[0]))),
		"arity 7":   CArr(CUint(1), CBytes(lp.Cfg[:]), CBytes(lp.TrustBaseID[:]), CBytes(lp.PDR), CBytes(lp.UC), CBytes(lp.Header), CArr(CBytes(lp.AccountNodes[0]))),
		"arity 9":   append(append([]byte{0x89}, good[1:]...), 0xf6),
		"receipt":   CArr(CUint(1), CBytes(lp.Cfg[:]), CBytes(lp.TrustBaseID[:]), CBytes(lp.PDR), CBytes(lp.UC), CBytes(lp.Header), CArr(CBytes(lp.AccountNodes[0])), CBytes(lp.StorageNodes[0])),
	} {
		jj := CTag(TagMintLock, CArr(CUint(2), CUint(f.Cfg.ChainID), CBytes(f.Cfg.Vault[:]), CBytes(f.Cfg.ZeroAddress[:]), CUint(5), bad))
		_, _, err := ParseJustification(f.Cfg, jj)
		require.ErrorIs(t, err, ErrLockProofShape, name)
	}
	// Missing embedded proof is a rejection (null in its place), not a fetch.
	jn := CTag(TagMintLock, CArr(CUint(2), CUint(f.Cfg.ChainID), CBytes(f.Cfg.Vault[:]), CBytes(f.Cfg.ZeroAddress[:]), CUint(5), CNull))
	_, _, err = ParseJustification(f.Cfg, jn)
	require.ErrorIs(t, err, ErrLockProofShape)
}

// The SDK's count quorum for unit-weight committees: N - (N-1)/3 distinct
// valid signers accept; one fewer rejects.
func TestLockProofCountQuorumBoundaries(t *testing.T) {
	for _, c := range []struct{ n, q int }{{1, 1}, {3, 3}, {4, 3}, {7, 5}} {
		for _, signers := range []int{c.q, c.q - 1} {
			if signers < 1 {
				continue
			}
			e := newEnv(t)
			auth, err := NewCommittee("committee", c.n)
			require.NoError(t, err)
			tb, err := auth.TrustBase(3, 1)
			require.NoError(t, err)
			b, err := RenderTrustBaseJSON(tb)
			require.NoError(t, err)
			e.Trust, err = LoadTrustInput(b)
			require.NoError(t, err)
			auth.Signers = signers
			e.Auth = auth
			h, _ := e.backedToken(t, 5, amt, oneKey())
			err = VerifyMintBacking(e.F.Cfg, h, e.Trust, e.Pin)
			if signers == c.q {
				require.NoError(t, err, "N=%d signers=%d", c.n, signers)
			} else {
				require.ErrorIs(t, err, ErrLockUC, "N=%d signers=%d", c.n, signers)
			}
		}
	}
}
