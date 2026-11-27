package signingauthority

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
)

const posChain = 7

func posPin() PosPolicy {
	return PosPolicy{Network: [32]byte{1}, ChainID: [32]byte{31: posChain}, Election: [20]byte{0xE1}, IDs: []uint64{5}}
}

func posRequest() PosPoPRequest {
	return PosPoPRequest{ResultID: [32]byte{1}, AssignmentID: [32]byte{2}, Snapshot: [32]byte{3}, Attempt: 2, ID: 5, Generation: 1}
}

// fakePos is the execution client's view of the deployment: the derived fields, the ids VR binds to the queried node and key, and an
// error to answer with instead (a pending one models an endpoint that is down).
type fakePos struct {
	view  PosDeploymentView
	bound map[uint64]bool
	err   error
	calls int
	last  PosQuery
}

func newFakePos() *fakePos {
	p := posPin()
	return &fakePos{view: PosDeploymentView{Network: p.Network, ChainID: p.ChainID, Election: p.Election}, bound: map[uint64]bool{5: true, 6: true}}
}

func (f *fakePos) ReadPosDeployment(_ context.Context, q PosQuery) (PosDeploymentView, error) {
	f.calls++
	f.last = q
	if f.err != nil {
		return PosDeploymentView{}, f.err
	}
	v := f.view
	for _, id := range q.IDs {
		if !f.bound[id] {
			if v.Unbound == nil {
				v.Unbound = map[uint64][20]byte{}
			}
			v.Unbound[id] = [20]byte{0x0a} // the identity's VR owner
		}
	}
	return v, nil
}

// enrolledOn stands for the completed enrollment of a shard configuration whose chain_id is chain (the fixture enrolls with a hash only).
func enrolledOn(a *Authority, chain uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.confChain, a.confChainKnown, a.confSeen = chain, true, true
}

func newPosAuthority(t *testing.T, src *fakePos, opts ...Option) *Authority {
	t.Helper()
	f := newFixture(t, 1)
	if src != nil {
		opts = append([]Option{WithPosSource(src, 0)}, opts...)
	}
	a, err := New(f.enroll, trustStub{tb: f.tb}, opts...)
	require.NoError(t, err)
	enrolledOn(a, posChain)
	return a
}

func pinned(t *testing.T) *Authority {
	t.Helper()
	a := newPosAuthority(t, newFakePos())
	require.NoError(t, a.SetPosPolicy(context.Background(), posPin()))
	return a
}

// The proof is the digest of the contracts' Election.popDigest (evmassign.PoPDigest) for the pinned election, signed by the authority's key.
func TestPosPoPIsThePinnedElectionsDigest(t *testing.T) {
	pin := posPin()
	a := pinned(t)
	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	r := posRequest()
	pop, err := a.SignPosPoP(r)
	require.NoError(t, err)
	require.Equal(t, uint64(5), pop.ID)
	require.Equal(t, pub, pop.EVMKey)
	var d evmassign.ElectionDeployment
	d.NetworkWord, d.ChainID, d.Election = pin.Network, pin.ChainID, pin.Election
	want := evmassign.PoPDigest(d, r.ResultID, r.AssignmentID, r.Snapshot, r.Attempt, r.ID, r.Generation, pub)
	sig := append([]byte(nil), pop.Signature...)
	sig[64] -= 27
	got, err := ethSigToPub(want, sig)
	require.NoError(t, err)
	require.Equal(t, pub, got)
	require.False(t, a.Status().HasReservation, "no certification round is touched")
}

func TestPosPoPScope(t *testing.T) {
	t.Run("no pin refuses", func(t *testing.T) {
		_, err := newPosAuthority(t, nil).SignPosPoP(posRequest())
		require.ErrorIs(t, err, ErrPosPolicy)
	})
	a := pinned(t)
	t.Run("another identity", func(t *testing.T) {
		r := posRequest()
		r.ID = 4
		_, err := a.SignPosPoP(r)
		require.ErrorIs(t, err, ErrPosPolicy)
	})
	t.Run("empty fields", func(t *testing.T) {
		r := posRequest()
		r.Snapshot = [32]byte{}
		_, err := a.SignPosPoP(r)
		require.ErrorIs(t, err, ErrContextMismatch)
	})
	t.Run("a pin without ids is refused at start", func(t *testing.T) {
		f := newFixture(t, 1)
		bad := posPin()
		bad.IDs = nil
		_, err := New(f.enroll, trustStub{tb: f.tb}, WithPosPolicy(bad))
		require.ErrorIs(t, err, ErrPosPolicy)
	})
}

// #1222: the pin's deployment is derived, so a pin of ids alone is complete, and the source is asked about this node and key.
func TestPosPolicyIsDerived(t *testing.T) {
	src := newFakePos()
	a := newPosAuthority(t, src)
	require.NoError(t, a.SetPosPolicy(context.Background(), PosPolicy{IDs: []uint64{5}}))
	require.Equal(t, testNodeID, src.last.NodeID)
	require.Equal(t, mustPub(t, a), src.last.EVMKey)
	require.Equal(t, []uint64{5}, src.last.IDs)
	pin := posPin()
	require.Equal(t, pin.Network, a.pos.Network)
	require.Equal(t, pin.ChainID, a.pos.ChainID)
	require.Equal(t, pin.Election, a.pos.Election)
	_, err := a.SignPosPoP(posRequest())
	require.NoError(t, err)
}

// #1222: each field the operator states wrongly is refused, and so is a source whose chain is not the authority's or an id VR does not
// bind to this node and key. A refused pin installs nothing: the right one is accepted afterwards.
func TestPosPolicyWrongFieldIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(p *PosPolicy, src *fakePos){
		"network word":        func(p *PosPolicy, _ *fakePos) { p.Network = [32]byte{2} },
		"chain id":            func(p *PosPolicy, _ *fakePos) { p.ChainID = [32]byte{31: 8} },
		"election":            func(p *PosPolicy, _ *fakePos) { p.Election = [20]byte{0xE2} },
		"execution chain":     func(_ *PosPolicy, src *fakePos) { src.view.ChainID = [32]byte{31: 8} },
		"unbound identity":    func(p *PosPolicy, _ *fakePos) { p.IDs = []uint64{5, 9} },
		"deployment refused":  func(_ *PosPolicy, src *fakePos) { src.err = fmt.Errorf("VR's active module is not the PoS adapter") },
		"no derived election": func(_ *PosPolicy, src *fakePos) { src.view.Election = [20]byte{} },
	} {
		t.Run(name, func(t *testing.T) {
			src := newFakePos()
			a := newPosAuthority(t, src)
			pin := posPin()
			mutate(&pin, src)
			err := a.SetPosPolicy(context.Background(), pin)
			require.ErrorIs(t, err, ErrPosPolicy)
			require.NotErrorIs(t, err, ErrPosPending)
			_, err = a.SignPosPoP(posRequest())
			require.ErrorIs(t, err, ErrPosPolicy, "nothing is signed under a refused pin")

			fixed := newFakePos()
			*src = *fixed
			require.NoError(t, a.SetPosPolicy(context.Background(), posPin()), "a refused pin does not lock the authority")
		})
	}
}

// A pin set on a running authority is final: the same pin again is a no-op (also with the derived fields omitted), another election or
// identity set is refused, and a delegation outside it too.
func TestPosPolicyIsPinnedOnce(t *testing.T) {
	a := pinned(t)
	pin := posPin()
	ctx := context.Background()
	require.NoError(t, a.SetPosPolicy(ctx, pin))
	require.NoError(t, a.SetPosPolicy(ctx, PosPolicy{IDs: []uint64{5}}))
	other := posPin()
	other.Election = [20]byte{0xE2}
	require.ErrorIs(t, a.SetPosPolicy(ctx, other), ErrPosPolicyConflict)
	other = posPin()
	other.IDs = []uint64{5, 6}
	require.ErrorIs(t, a.SetPosPolicy(ctx, other), ErrPosPolicyConflict)
	_, err := a.SignPosPoP(posRequest())
	require.NoError(t, err)

	req := DelegationPossessionRequest{Network: pin.Network, Chain: pin.ChainID, Election: [20]byte{0xE2}}
	req.Request.Id = 5
	_, err = a.SignDelegationPossession(req)
	require.ErrorIs(t, err, ErrPosPolicy, "a pinned authority signs delegations for its election only")
}

// A source that cannot be read leaves the pin pending: nothing is installed or signed, the error says retry, and the same pin succeeds once
// the source answers. An authority without a source refuses a pin outright; one whose fence (and so its source) is still pending says pending.
func TestPosPolicyPendingSource(t *testing.T) {
	src := newFakePos()
	src.err = fmt.Errorf("%w: the endpoint is down", ErrPosPending)
	a := newPosAuthority(t, src)
	require.ErrorIs(t, a.SetPosPolicy(context.Background(), posPin()), ErrPosPending)
	_, err := a.SignPosPoP(posRequest())
	require.ErrorIs(t, err, ErrPosPolicy)
	src.err = nil
	_, err = a.SignPosPoP(posRequest())
	require.NoError(t, err, "the pending pin is verified by the next signing request once the source answers")
	require.NoError(t, a.SetPosPolicy(context.Background(), posPin()), "and is then final")

	t.Run("a pending late pin is replaced, not locked in", func(t *testing.T) {
		src := newFakePos()
		src.err = fmt.Errorf("%w: down", ErrPosPending)
		a := newPosAuthority(t, src)
		wrong := posPin()
		wrong.IDs = []uint64{9}
		require.ErrorIs(t, a.SetPosPolicy(context.Background(), wrong), ErrPosPending)
		require.ErrorIs(t, a.SetPosPolicy(context.Background(), posPin()), ErrPosPending, "another pending pin replaces it")
		src.err = nil
		installed, err := a.VerifyPosPolicy(context.Background())
		require.NoError(t, err)
		require.True(t, installed)
		require.Equal(t, []uint64{5}, a.pos.IDs)
	})
	t.Run("a pending late pin that the source refuses is dropped", func(t *testing.T) {
		src := newFakePos()
		src.err = fmt.Errorf("%w: down", ErrPosPending)
		a := newPosAuthority(t, src)
		wrong := posPin()
		wrong.IDs = []uint64{9}
		require.ErrorIs(t, a.SetPosPolicy(context.Background(), wrong), ErrPosPending)
		src.err = nil
		_, err := a.VerifyPosPolicy(context.Background())
		require.ErrorIs(t, err, ErrPosPolicy)
		require.Nil(t, a.posWant)
		require.NoError(t, a.SetPosPolicy(context.Background(), posPin()))
	})

	err = newPosAuthority(t, nil).SetPosPolicy(context.Background(), posPin())
	require.ErrorIs(t, err, ErrPosPolicy)
	require.NotErrorIs(t, err, ErrPosPending)

	b := newPosAuthority(t, nil, WithFencePending())
	require.ErrorIs(t, b.SetPosPolicy(context.Background(), posPin()), ErrPosPending)
	require.NoError(t, b.ProvisionPosSource(newFakePos(), 0))
	require.Error(t, b.ProvisionPosSource(newFakePos(), 0), "once")
	require.NoError(t, b.SetPosPolicy(context.Background(), posPin()))
}

// The chain a pin is verified against: the b1 profile's before the enrollment is complete, the enrolled configuration's after; a later
// configuration with another chain id latches the authority faulted.
func TestPosPolicyChainReference(t *testing.T) {
	t.Run("before enrollment: the b1 profile's chain", func(t *testing.T) {
		f := newFixture(t, 1)
		enroll := f.enroll
		enroll.ShardConfHash = nil
		a, err := New(enroll, trustStub{tb: f.tb}, WithPosSource(newFakePos(), posChain))
		require.NoError(t, err)
		require.NoError(t, a.SetPosPolicy(context.Background(), posPin()), "a joiner pins and signs its delegation before enrollment")

		conf := ownConf(t, a)
		conf.PartitionParams = map[string]string{"chain_id": "8"}
		require.ErrorIs(t, a.CompleteEnrollment(conf), ErrStateUntrusted)
		require.True(t, a.Status().Faulted, "a configuration on another chain than the pin's latches the authority")
		_, err = a.SignPosPoP(posRequest())
		require.Error(t, err)
	})
	t.Run("the enrolled chain agrees", func(t *testing.T) {
		f := newFixture(t, 1)
		enroll := f.enroll
		enroll.ShardConfHash = nil
		a, err := New(enroll, trustStub{tb: f.tb}, WithPosSource(newFakePos(), posChain))
		require.NoError(t, err)
		require.NoError(t, a.SetPosPolicy(context.Background(), posPin()))
		conf := ownConf(t, a)
		conf.PartitionParams = map[string]string{"chain_id": "7"}
		require.NoError(t, a.CompleteEnrollment(conf))
		_, err = a.SignPosPoP(posRequest())
		require.NoError(t, err)
	})
	t.Run("after enrollment the configuration's chain wins over the b1 profile's", func(t *testing.T) {
		f := newFixture(t, 1)
		enroll := f.enroll
		enroll.ShardConfHash = nil
		a, err := New(enroll, trustStub{tb: f.tb}, WithPosSource(newFakePos(), posChain))
		require.NoError(t, err)
		conf := ownConf(t, a)
		conf.PartitionParams = map[string]string{"chain_id": "9"}
		require.NoError(t, a.CompleteEnrollment(conf), "no pin yet: nothing to disagree with")
		require.ErrorIs(t, a.SetPosPolicy(context.Background(), PosPolicy{IDs: []uint64{5}}), ErrPosPolicy, "the execution client is on 7")
	})
	t.Run("an enrolled configuration without chain_id", func(t *testing.T) {
		f := newFixture(t, 1)
		enroll := f.enroll
		enroll.ShardConfHash = nil
		a, err := New(enroll, trustStub{tb: f.tb}, WithPosSource(newFakePos(), posChain))
		require.NoError(t, err)
		require.NoError(t, a.CompleteEnrollment(ownConf(t, a)))
		require.ErrorIs(t, a.SetPosPolicy(context.Background(), posPin()), ErrPosPolicy)
	})
	t.Run("no chain reference before enrollment", func(t *testing.T) {
		f := newFixture(t, 1)
		enroll := f.enroll
		enroll.ShardConfHash = nil
		a, err := New(enroll, trustStub{tb: f.tb}, WithPosSource(newFakePos(), 0))
		require.NoError(t, err)
		require.ErrorIs(t, a.SetPosPolicy(context.Background(), posPin()), ErrPosPending)
	})
}

// A startup pin goes through the same check: nothing is signed until it is verified, the first signing request (or VerifyPosPolicy)
// verifies it, a source that is down leaves it pending, and a late pin must agree with it.
func TestStartupPosPolicyIsVerified(t *testing.T) {
	src := newFakePos()
	src.err = fmt.Errorf("%w: down", ErrPosPending)
	a := newPosAuthority(t, src, WithPosPolicy(PosPolicy{IDs: []uint64{5}}))
	_, err := a.SignPosPoP(posRequest())
	require.ErrorIs(t, err, ErrPosPolicy, "pending: not signed")
	_, err = a.VerifyPosPolicy(context.Background())
	require.ErrorIs(t, err, ErrPosPending)
	other := posPin()
	other.IDs = []uint64{6}
	require.ErrorIs(t, a.SetPosPolicy(context.Background(), other), ErrPosPolicyConflict, "the startup pin stands while it is pending")
	src.err = nil
	_, err = a.SignPosPoP(posRequest())
	require.NoError(t, err, "the signing request verified the startup pin")
	require.NoError(t, a.SetPosPolicy(context.Background(), posPin()), "an equivalent late pin is a no-op")

	t.Run("a wrong startup field is refused", func(t *testing.T) {
		bad := posPin()
		bad.Election = [20]byte{0xEE}
		b := newPosAuthority(t, newFakePos(), WithPosPolicy(bad))
		_, err := b.VerifyPosPolicy(context.Background())
		require.ErrorIs(t, err, ErrPosPolicy)
		require.NotNil(t, b.posWant, "a refused startup pin stays: the operator channel cannot replace it")
		require.ErrorIs(t, b.SetPosPolicy(context.Background(), posPin()), ErrPosPolicyConflict)
		_, err = b.SignPosPoP(posRequest())
		require.ErrorIs(t, err, ErrPosPolicy)
	})
}

func ethSigToPub(digest [32]byte, sig []byte) ([]byte, error) {
	pub, err := ethcrypto.SigToPub(digest[:], sig)
	if err != nil {
		return nil, err
	}
	return ethcrypto.CompressPubkey(pub), nil
}

// electionPoPForPin is the election possession fixture with a P85 source deriving its deployment, on its chain.
func electionPoPForPin(t *testing.T) (*Authority, ElectionPoPRequest, *fakePos) {
	t.Helper()
	a, req, _ := electionPoPFixture(t)
	d := req.Deployment
	src := &fakePos{view: PosDeploymentView{Network: d.NetworkWord, ChainID: d.ChainID, Election: d.Election}, bound: map[uint64]bool{}}
	require.NoError(t, a.ProvisionPosSource(src, 0))
	enrolledOn(a, new(big.Int).SetBytes(d.ChainID[:]).Uint64())
	return a, req, src
}

// The pin binds the older election possession (SignElectionPoP) as well: the same PoPDigest must not be obtainable outside it.
func TestPosPolicyBindsTheElectionPoPToo(t *testing.T) {
	a, req, src := electionPoPForPin(t)
	_, id, err := evmassign.ElectionPoPDigest(req.Candidate, req.Deployment, req.Attempt, mustPub(t, a), testNodeID)
	require.NoError(t, err)
	src.bound[id] = true
	d := req.Deployment
	pin := PosPolicy{Network: d.NetworkWord, ChainID: d.ChainID, Election: d.Election, IDs: []uint64{id}}
	require.NoError(t, a.SetPosPolicy(context.Background(), pin))
	_, err = a.SignElectionPoP(req)
	require.NoError(t, err, "inside the pin")

	other := req
	other.Deployment.Election = [20]byte{0xEE}
	_, err = a.SignElectionPoP(other)
	require.ErrorIs(t, err, ErrPosPolicy, "another election")
	other = req
	other.Deployment.ChainID = [32]byte{31: 9}
	_, err = a.SignElectionPoP(other)
	require.ErrorIs(t, err, ErrPosPolicy, "another chain")
}

// All three P85 operations are refused until a pin is verified: with --require-pos-policy, and on any authority with a P85 source.
func TestPosOperationsRefusedUntilVerified(t *testing.T) {
	for name, opts := range map[string][]Option{
		"required":    {WithRequirePosPolicy()},
		"with source": nil,
	} {
		t.Run(name, func(t *testing.T) {
			src := newFakePos()
			a := newPosAuthority(t, src, opts...)
			_, err := a.SignPosPoP(posRequest())
			require.ErrorIs(t, err, ErrPosPolicy)
			_, err = a.SignDelegationPossession(DelegationPossessionRequest{})
			require.ErrorIs(t, err, ErrPosPolicy)
			// a valid candidate: the refusal is the pin's, not the candidate validation's
			ea, ereq, _ := electionPoPForPin(t)
			if len(opts) > 0 {
				ea.requirePos = true
			}
			_, err = ea.SignElectionPoP(ereq)
			require.ErrorIs(t, err, ErrPosPolicy)
			require.NoError(t, a.SetPosPolicy(context.Background(), posPin()))
			_, err = a.SignPosPoP(posRequest())
			require.NoError(t, err)
		})
	}
}

func mustPub(t *testing.T, a *Authority) []byte {
	pub, err := a.SigningPublicKey()
	require.NoError(t, err)
	return pub
}

// Startup installation: two different pins conflict, and a reused option does not share state between authorities.
func TestStartupPosPolicyConflictAndReuse(t *testing.T) {
	f := newFixture(t, 1)
	other := posPin()
	other.Election = [20]byte{0xEE}
	_, err := New(f.enroll, trustStub{tb: f.tb}, WithPosPolicy(posPin()), WithPosPolicy(other))
	require.ErrorIs(t, err, ErrPosPolicyConflict)

	pin := posPin()
	opt := WithPosPolicy(pin)
	a := newPosAuthority(t, newFakePos(), opt)
	b := newPosAuthority(t, newFakePos(), opt)
	pin.IDs[0] = 9 // the caller's slice is not the authority's
	_, err = a.SignPosPoP(posRequest())
	require.NoError(t, err)
	_, err = b.SignPosPoP(posRequest())
	require.NoError(t, err)
	require.NotSame(t, a.pos, b.pos)
	require.NotSame(t, &a.pos.IDs[0], &b.pos.IDs[0])
}

// A key change or recovery signs the P85 delegation before VR stages the new binding, so VR does not bind the new key yet: the pin is
// accepted when the registration policy authorizes this authority's binding of that identity for its VR owner, and refused otherwise.
func TestPosPolicyRekeyNeedsTheBindingAuthorization(t *testing.T) {
	policy := func(owner [20]byte, id uint64, domain string) Option {
		return WithRegistrationPolicy(RegistrationPolicy{Deployment: RegistrationDeployment{Network: [32]byte{1}, ChainID: [32]byte{31: posChain}, Registry: [20]byte{3}},
			Authorized: []RegistrationAuthorization{{Domain: domain, Owner: owner, ID: id, RootNodeID: "root", RootKey: testRootKey(t), Payee: owner}}})
	}
	rekey := PosPolicy{IDs: []uint64{9}}
	for name, c := range map[string]struct {
		opt Option
		ok  bool
	}{
		"authorized binding":        {policy([20]byte{0x0a}, 9, vrschema.BindingDomainText), true},
		"another owner":             {policy([20]byte{0x0b}, 9, vrschema.BindingDomainText), false},
		"another identity":          {policy([20]byte{0x0a}, 8, vrschema.BindingDomainText), false},
		"a registration, not a key": {policy([20]byte{0x0a}, 0, vrschema.RegisterDomainText), false},
	} {
		t.Run(name, func(t *testing.T) {
			a := newPosAuthority(t, newFakePos(), c.opt)
			err := a.SetPosPolicy(context.Background(), rekey)
			if c.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrPosPolicy)
		})
	}
	require.ErrorIs(t, newPosAuthority(t, newFakePos()).SetPosPolicy(context.Background(), rekey), ErrPosPolicy, "no registration policy")
}

func testRootKey(t *testing.T) []byte {
	k, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	return ethcrypto.CompressPubkey(&k.PublicKey)
}
