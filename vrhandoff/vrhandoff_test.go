package vrhandoff_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
)

func certInput(f *fixture, in vrhandoff.Intent, d [32]byte, c vrhandoff.ViewCertificate, committedView uint64) vradmit.CertificateInput {
	body, err := vrhandoff.DeriveBody(in, f.rc.RootEpoch, sha256.Sum256(c.Assembly.Candidate), f.bc)
	require.NoError(f.t, err)
	_, tb, err := vrhandoff.TrustBase(in, f.rc.RootEpoch)
	require.NoError(f.t, err)
	keys, _ := f.incumbents()
	return vradmit.CertificateInput{Certificate: c, IntentDigest: d, CommittedView: committedView, Incumbents: keys, CandidateBytes: c.Assembly.Candidate,
		Successors: f.j, Body: body, Attempt: in.Attempt, TrustBaseBytes: tb}
}

// Stages 0 to 4 end to end: the derived intent, sticky PoPs, the assembly of view 0 by its assembler, every successor's readiness and the
// certificate Freeze validity accepts.
func TestTheProtocolProducesACertificateFreezeAccepts(t *testing.T) {
	f := newFixture(t)
	in, d := f.intent()
	require.EqualValues(t, 4400, in.AnchorRound, "max(certRootRound, attemptOpenRound)")
	require.EqualValues(t, 4416, vrhandoff.EarliestActivation(in))
	c, err := vrhandoff.CandidateOf(in)
	require.NoError(t, err)
	require.Empty(t, c.PoPs, "the intent's candidate is unsigned")
	require.EqualValues(t, vrschema.VerdictAccepted, c.RegistryChanges[0].Verdict, "verdicts are set at the intent")
	require.Equal(t, f.j, c.Identities)

	a := f.assembly(in, d, 0, f.pops(in))
	got, err := vrhandoff.VerifyAssembly(in, a)
	require.NoError(t, err)
	require.Len(t, got.PoPs, len(f.j))
	keys, _ := f.incumbents()
	require.NoError(t, vrhandoff.VerifyAssemblySig(a, keys))
	cert, _, _ := f.certificate(in, a)
	require.NoError(t, vrhandoff.VerifyCertificate(certInput(f, in, d, cert, 0)))

	// the admission of the same candidate (H3 checks, verdicts, certificate) over VR's output: the candidate is what admission accepts
	cand, err := vrschema.DecodeCandidateV6(a.Candidate)
	require.NoError(t, err)
	ci := certInput(f, in, d, cert, 0)
	successor := make([]evmassign.RootMember, 0)
	for _, m := range ci.Body.Members {
		successor = append(successor, evmassign.RootMember{NodeID: m.NodeID, Key: m.ConsensusKey, Weight: m.Weight})
	}
	_, err = vradmit.VerifyRegistryOutput(vradmit.Admission{Deployment: f.dep, Candidate: cand, State: f.out.State, Acknowledged: vrschema.GenesisResult,
		Verify: evmassign.VerifyContext{BindingContext: evmassign.BindingContext{ControlPartition: 0xFFFFFFFD, SuccessorRoot: successor,
			PoPContext: evmassign.PoPContext{Network: network, Predecessor: f.rc.Predecessor, Attempt: in.Attempt}, Rules: nil},
			Current: f.rc.Installed, CurrentRoot: rootsOf(f.k)},
		Lifecycle: f.rc.Lifecycle, Fold: f.rc.Fold, EVMAcked: true, Certificate: ci})
	require.NoError(t, err, "the assembled candidate is the registry output admission accepts")
}

func rootsOf(ids []evmassign.Identity) []evmassign.RootMember {
	out := []evmassign.RootMember{}
	for _, i := range ids {
		out = append(out, evmassign.RootMember{NodeID: i.RootNodeID, Key: i.RootKey, Weight: i.Weight})
	}
	return out
}

// Two roots at different committed rounds, served the members and changes in different orders, derive the same intent and body.
func TestTwoRootsDeriveTheSameIntentAndBody(t *testing.T) {
	f := newFixture(t)
	a, da := f.intent()
	g := newFixture(t)
	g.out.Members = []evmassign.Identity{g.j[3], g.j[1], g.j[0], g.j[2]}
	b, db := g.intent()
	require.Equal(t, da, db)
	ra, err := a.Encode()
	require.NoError(t, err)
	rb, err := b.Encode()
	require.NoError(t, err)
	require.Equal(t, ra, rb)
	cd := sha256.Sum256([]byte("an assembled candidate"))
	ba, err := vrhandoff.DeriveBody(a, f.rc.RootEpoch, cd, f.bc)
	require.NoError(t, err)
	bb, err := vrhandoff.DeriveBody(b, g.rc.RootEpoch, cd, g.bc)
	require.NoError(t, err)
	require.Equal(t, ba.Identity(), bb.Identity())

	// the anchor is the later of the source's certifying round and the attempt's opening
	g.rc.AttemptOpenRound = 5000
	c, _ := g.intent()
	require.EqualValues(t, 5000, c.AnchorRound)
	require.EqualValues(t, 5016, vrhandoff.EarliestActivation(c))
}

// The served preimages are trusted only through VR's proven digests; R must be the open Published output with nothing pending.
func TestTheIntentRefusesWhatVRDidNotCommit(t *testing.T) {
	refused := func(name string, mutate func(*fixture)) {
		t.Helper()
		f := newFixture(t)
		mutate(f)
		_, _, err := vrhandoff.NewIntent(f.rc, f.src, f.out)
		require.ErrorIs(t, err, vrhandoff.ErrIntent, name)
	}
	refused("a served member key VR did not capture", func(f *fixture) {
		m := f.out.Members[0]
		m.RootKey = mkKey(t, 99).pub
		f.out.Members[0] = m
	})
	refused("a member left out", func(f *fixture) { f.out.Members = f.out.Members[1:] })
	refused("another change payload", func(f *fixture) {
		f.out.Changes[0].Payload = append([]byte(nil), f.out.Changes[0].Payload...)
		f.out.Changes[0].Payload[63] ^= 1
	})
	refused("K is not the acknowledged committee", func(f *fixture) { f.rc.Lifecycle.Incumbent = f.j })
	refused("R not Published", func(f *fixture) { f.out.State.Output.State = vrschema.OutReserved })
	refused("R not open", func(f *fixture) { f.out.State.OpenOutput = vrschema.Word{} })
	refused("a pending pair", func(f *fixture) { f.out.State.PendingPair = vrschema.Word{1} })
	refused("an unacknowledged assignment", func(f *fixture) { f.rc.Lifecycle.Pending = 1 })
	refused("another deployment", func(f *fixture) { f.rc.Deployment.NetworkWord = vrschema.Word{9} })
	refused("a source of another output commit", func(f *fixture) { f.src.OutputCommit = make([]byte, 32) })
	refused("a tampered output commit", func(f *fixture) { f.out.State.Output.OutputCommit = vrschema.Word{7} })
}

// Two different valid PoP encodings both verify, both assemble (to different candidates and bodies) and both certify; a second proof of a
// member is ignored (sticky); an assembly that is not the intent's candidate plus valid proofs is refused.
func TestPoPsAndAssemblies(t *testing.T) {
	f := newFixture(t)
	in, d := f.intent()
	pops := f.pops(in)

	// another valid proof of the same member: an ECDSA signature with another nonce (canonical low s, recovering the key)
	alt := pops[0]
	alt.PoP.Signature = resign(t, 21, alt.PoP.Signature, in, f)
	require.NotEqual(t, pops[0].PoP.Signature, alt.PoP.Signature)
	require.NoError(t, vrhandoff.VerifyPoP(in, alt))
	a1 := f.assembly(in, d, 0, pops)
	a2 := f.assembly(in, d, 0, append([]vrhandoff.PoPOffer{alt}, pops[1:]...))
	require.NotEqual(t, a1.Candidate, a2.Candidate)
	for _, a := range []vrhandoff.Assembly{a1, a2} {
		_, err := vrhandoff.VerifyAssembly(in, a)
		require.NoError(t, err)
		c, _, _ := f.certificate(in, a)
		require.NoError(t, vrhandoff.VerifyCertificate(certInput(f, in, d, c, 0)))
	}
	// the high-s twin of a proof is not a second encoding: one signature has exactly one accepted encoding
	twin := pops[0]
	sig := bytes.Clone(twin.PoP.Signature)
	hs := new(big.Int).Sub(ethcrypto.S256().Params().N, new(big.Int).SetBytes(sig[32:64]))
	twin.PoP.Signature = append(append(sig[:32:32], hs.FillBytes(make([]byte, 32))...), sig[64]^1)
	require.ErrorIs(t, vrhandoff.VerifyPoP(in, twin), vrhandoff.ErrAssembly)

	// sticky: a second, invalid proof of a member after a valid one is ignored; before it, it is refused
	bad := pops[1]
	bad.PoP.Signature = bytes.Clone(pops[0].PoP.Signature)
	_, _, _, err := vrhandoff.Assemble(in, append(append([]vrhandoff.PoPOffer(nil), pops...), bad))
	require.NoError(t, err)
	_, _, _, err = vrhandoff.Assemble(in, append([]vrhandoff.PoPOffer{bad}, pops...))
	require.ErrorIs(t, err, vrhandoff.ErrAssembly)
	_, _, _, err = vrhandoff.Assemble(in, pops[1:])
	require.ErrorIs(t, err, vrhandoff.ErrAssembly, "a proof missing")
	other := pops[0]
	other.IntentDigest = make([]byte, 32)
	require.ErrorIs(t, vrhandoff.VerifyPoP(in, other), vrhandoff.ErrAssembly, "a proof of another intent")

	a := f.assembly(in, d, 0, pops)
	c, err := vrschema.DecodeCandidateV6(a.Candidate)
	require.NoError(t, err)
	c.Identities[0].Weight = 2
	raw, err := c.Encode()
	require.NoError(t, err)
	forged := a
	forged.Candidate = raw
	_, err = vrhandoff.VerifyAssembly(in, forged)
	require.ErrorIs(t, err, vrhandoff.ErrAssembly, "the candidate is not the intent's")
	c, err = vrschema.DecodeCandidateV6(a.Candidate)
	require.NoError(t, err)
	c.PoPs[1], c.PoPs[2] = c.PoPs[2], c.PoPs[1]
	raw, err = c.Encode()
	require.NoError(t, err)
	forged.Candidate = raw
	_, err = vrhandoff.VerifyAssembly(in, forged)
	require.ErrorIs(t, err, vrhandoff.ErrAssembly, "proofs out of EVM node order")
	keys, _ := f.incumbents()
	wrong := a
	wrong.Slot = 1
	require.ErrorIs(t, vrhandoff.VerifyAssemblySig(wrong, keys), vrhandoff.ErrAssembly, "signed by view 0's assembler, not view 1's")
}

// Freeze validity over certificates: a certificate of a view not yet committed is refused, a late one of an earlier view stays valid
// after advancement to h + 6 (I-RET), and a certificate missing a member's readiness is refused.
func TestCertificatesAcrossViews(t *testing.T) {
	f := newFixture(t)
	in, d := f.intent()
	pops := f.pops(in)
	a := f.assembly(in, d, 1, pops)
	c, _, _ := f.certificate(in, a)
	require.Error(t, vrhandoff.VerifyCertificate(certInput(f, in, d, c, 0)), "view 1 is not committed")
	require.NoError(t, vrhandoff.VerifyCertificate(certInput(f, in, d, c, 1)))
	require.NoError(t, vrhandoff.VerifyCertificate(certInput(f, in, d, c, 7)), "I-RET: a certificate of view h is usable at h + 6")
	require.True(t, vrhandoff.CertificateAdmissible(1, 7, false))
	short := c
	short.Readiness = c.Readiness[:3]
	require.Error(t, vrhandoff.VerifyCertificate(certInput(f, in, d, short, 1)))
	_, err := vrhandoff.Certificate(a, f.j, map[string]vrhandoff.Readiness{f.j[0].RootNodeID: c.Readiness[0]}, [32]byte(c.Readiness[0].BodyID))
	require.ErrorIs(t, err, vrhandoff.ErrReadiness)
}

// resign signs the PoP message of the first successor validator again with the member's key (seed) and a fresh random nonce.
func resign(t *testing.T, seed byte, _ []byte, in vrhandoff.Intent, f *fixture) []byte {
	ctx, succ, err := vrhandoff.PoPContext(in)
	require.NoError(t, err)
	msg, err := evmassign.PoPMessage(ctx, succ, f.members[1].evm)
	require.NoError(t, err)
	z := sha256.Sum256(msg)
	curve := ethcrypto.S256()
	n := curve.Params().N
	d := new(big.Int).SetBytes(bytes.Repeat([]byte{seed}, 32))
	for {
		k, err := rand.Int(rand.Reader, n)
		require.NoError(t, err)
		if k.Sign() == 0 {
			continue
		}
		x, _ := curve.ScalarBaseMult(k.FillBytes(make([]byte, 32)))
		r := new(big.Int).Mod(x, n)
		if r.Sign() == 0 {
			continue
		}
		s := new(big.Int).Mul(r, d)
		s.Add(s, new(big.Int).SetBytes(z[:]))
		s.Mul(s, new(big.Int).ModInverse(k, n))
		s.Mod(s, n)
		if s.Sign() == 0 {
			continue
		}
		if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
			s.Sub(n, s)
		}
		sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		for v := byte(0); v < 2; v++ {
			cand := append(append([]byte(nil), sig...), v)
			if pub, err := ethcrypto.SigToPub(z[:], cand); err == nil && bytes.Equal(ethcrypto.CompressPubkey(pub), f.members[1].ek.pub) {
				return cand
			}
		}
	}
}
