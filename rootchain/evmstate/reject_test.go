package evmstate

import (
	"context"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// fixtureReservedAt is the reservation progress of the fixture's result: PublicationFixture.t.sol reserves it at clock(100_000, ...), the
// registry progress ElectionPolicy stamps into Result.progress.
const fixtureReservedAt = 100_000

// rejectWorld is the certified state a RejectResult is judged against, from the contracts' own fixtures: Election and custody as the
// publication fixture left them (reserved, published, or published and lost), and the registry Election and custody both point at,
// holding a canonical progress.
type rejectWorld struct {
	fx       pubFx
	pins     Pins
	resultID word32
	election map[word32]word32
	custody  map[word32]word32
	registry map[word32]word32
}

func newRejectWorld(t testing.TB, scenario string, progress uint64) rejectWorld {
	p := newPrimaryWorld(t, scenario)
	w := rejectWorld{fx: p.fx, pins: p.pins, resultID: hexWord(t, p.fx.ResultID), election: p.election, custody: p.custody,
		registry: map[word32]word32{registryKey("records.progress"): bigWord(progress)}}
	roots := w.election[baseSlot(electionRoots)]
	require.Equal(t, roots, w.custody[baseSlot(custodyRoots)], "premise: Election and custody name one registry")
	copy(w.pins.Registry[:], roots[12:])
	w.pins.RegistryCode = [32]byte(ethcrypto.Keccak256Hash([]byte("registry code")))
	return w
}

func (r rejectWorld) world(t testing.TB) *world {
	return buildWorld(t,
		contract{addr: r.pins.Election, codeHash: r.pins.ElectionCode, storage: r.election},
		contract{addr: r.pins.Custody, codeHash: r.pins.CustodyCode, storage: r.custody},
		contract{addr: r.pins.Registry, codeHash: r.pins.RegistryCode, storage: r.registry})
}

// witness is what the readers read, proven from the world; a refusal ends the read early and the witness holds what was read.
func (r rejectWorld) witness(t testing.TB) (raw []byte, root word32) {
	w := r.world(t)
	reads := map[[20]byte]*recorder{r.pins.Election: newRecorder(r.election), r.pins.Custody: newRecorder(r.custody), r.pins.Registry: newRecorder(r.registry)}
	var f storage.RejectFacts
	_ = readReject(reads[r.pins.Election], reads[r.pins.Custody], reads[r.pins.Registry], r.pins, r.resultID, &f)
	return witnessFor(t, w, reads), w.root
}

func (r rejectWorld) verify(t testing.TB) (storage.RejectFacts, error) {
	raw, root := r.witness(t)
	return Authority{Pins: r.pins}.VerifyReject(raw, root, r.resultID)
}

// The facts of the fixture's result, in each state the contracts left it: reserved, published, and published and then lost. The
// election's attempt is the fixture's (1), unlike any root attempt the control may name: the facts carry no attempt at all.
func TestRejectFactsAreProvenFromTheCertifiedState(t *testing.T) {
	for _, c := range []struct {
		scenario string
		lost     bool
	}{{"reserved", false}, {"reservedLost", true}, {"published", false}, {"lost", true}} {
		w := newRejectWorld(t, c.scenario, fixtureReservedAt+7)
		got, err := w.verify(t)
		require.NoError(t, err, c.scenario)
		require.Equal(t, storage.RejectFacts{ResultID: w.resultID, Reserved: true, Unresolved: true, Bound: true, NoInstalledSession: true,
			ReservedAt: fixtureReservedAt, Progress: fixtureReservedAt + 7, Lost: c.lost}, got, c.scenario)
	}
	require.EqualValues(t, 1, loadPubFx(t).Attempt, "premise: the election's attempt is 1")
}

// The age is judged on proven words, in the registry's progress clock: 1,023 rounds after the reservation the result is not due, 1,024
// rounds after it is, and a lost one is due at once (test 3 and 4 of the design, with the three-account proof replayed).
func TestRejectDueIsJudgedOnProvenProgress(t *testing.T) {
	for _, c := range []struct {
		scenario string
		progress uint64
		due      bool
	}{
		{"reserved", fixtureReservedAt + storage.ResultReservationLifetimeProgress - 1, false},
		{"reserved", fixtureReservedAt + storage.ResultReservationLifetimeProgress, true},
		{"published", fixtureReservedAt + storage.ResultReservationLifetimeProgress - 1, false},
		{"published", fixtureReservedAt + storage.ResultReservationLifetimeProgress, true},
		{"lost", fixtureReservedAt, true},
		{"lost", fixtureReservedAt - 1, false}, // a registry behind the reservation is no proof of anything
	} {
		f, err := newRejectWorld(t, c.scenario, c.progress).verify(t)
		require.NoError(t, err)
		require.Equal(t, c.due, storage.RejectDue(f), "%s at progress %d", c.scenario, c.progress)
	}
}

// Each fact follows its own proven word: changing only that word changes only that fact.
func TestRejectFactsFollowTheProvenWords(t *testing.T) {
	session := func(w rejectWorld) word32 { return mapSlot(baseSlot(custodySessions), w.resultID[:]) }
	result := func(w rejectWorld) word32 { return mapSlot(baseSlot(electionResults), w.resultID[:]) }
	for name, c := range map[string]struct {
		mutate func(w rejectWorld)
		check  func(f storage.RejectFacts) bool
	}{
		"another open result": {func(w rejectWorld) { w.election[baseSlot(electionOpenResult)] = bigWord(9) },
			func(f storage.RejectFacts) bool { return !f.Reserved && f.Unresolved && f.Bound }},
		"the result is no longer reserved": {func(w rejectWorld) {
			h := w.election[slotWord(result(w), resultStateWord)]
			h[31] = 5 // Closed
			w.election[slotWord(result(w), resultStateWord)] = h
		}, func(f storage.RejectFacts) bool { return !f.Reserved && f.Unresolved && f.Bound }},
		"the session is closed": {func(w rejectWorld) { w.custody[slotWord(session(w), sessionStateSlot)] = bigWord(3) },
			func(f storage.RejectFacts) bool { return f.Reserved && !f.Unresolved && f.Bound }},
		"the result names another predecessor than the session": {func(w rejectWorld) { w.election[slotWord(result(w), resultPredecessor)] = bigWord(9) },
			func(f storage.RejectFacts) bool {
				return f.Reserved && f.Unresolved && !f.Bound && f.NoInstalledSession
			}},
		"the result names another assignment than the session": {func(w rejectWorld) { w.election[slotWord(result(w), resultAssignment)] = bigWord(9) },
			func(f storage.RejectFacts) bool {
				return f.Reserved && f.Unresolved && !f.Bound && f.NoInstalledSession
			}},
		"another assignment was acknowledged": {func(w rejectWorld) { w.custody[baseSlot(custodyLastAckedAssignment)] = bigWord(9) },
			func(f storage.RejectFacts) bool {
				return f.Reserved && f.Unresolved && f.Bound && !f.NoInstalledSession
			}},
		"the registry progress moves": {func(w rejectWorld) { w.registry[registryKey("records.progress")] = bigWord(fixtureReservedAt + 5_000) },
			func(f storage.RejectFacts) bool {
				return f.Progress == fixtureReservedAt+5_000 && f.ReservedAt == fixtureReservedAt
			}},
	} {
		w := newRejectWorld(t, "reserved", fixtureReservedAt)
		c.mutate(w)
		f, err := w.verify(t)
		require.NoError(t, err, name)
		require.True(t, c.check(f), "%s: %+v", name, f)
	}
	// the lost bit alone: the published and the lost fixture differ only in the publication's flags word
	pub, lost := newRejectWorld(t, "published", fixtureReservedAt), newRejectWorld(t, "lost", fixtureReservedAt)
	fp, err := pub.verify(t)
	require.NoError(t, err)
	fl, err := lost.verify(t)
	require.NoError(t, err)
	fp.Lost = true
	require.Equal(t, fp, fl)
}

// The witness is bound to the pinned deployment: the three accounts by address and code hash, Election's network, custody and registry
// pointers, custody's network and registry pointer. A uint64 progress is all the registry word may hold.
func TestRejectWitnessIsPinnedToTheDeployment(t *testing.T) {
	_, err := newRejectWorld(t, "reserved", fixtureReservedAt).verify(t)
	require.NoError(t, err)
	for name, c := range map[string]struct {
		mutate func(w *rejectWorld)
		want   error
	}{
		"election names another custody":  {func(w *rejectWorld) { w.election[baseSlot(electionCustody)] = bigWord(9) }, ErrProof},
		"election names another registry": {func(w *rejectWorld) { w.election[baseSlot(electionRoots)] = bigWord(9) }, ErrProof},
		"custody names another registry":  {func(w *rejectWorld) { w.custody[baseSlot(custodyRoots)] = bigWord(9) }, ErrProof},
		"election network differs":        {func(w *rejectWorld) { w.election[baseSlot(electionNetwork)] = bigWord(9) }, ErrProof},
		"custody network differs":         {func(w *rejectWorld) { w.custody[baseSlot(custodyNetwork)] = bigWord(9) }, ErrProof},
		"a pointer word with high bits set": {func(w *rejectWorld) {
			v := w.election[baseSlot(electionRoots)]
			v[0] = 1
			w.election[baseSlot(electionRoots)] = v
		}, ErrProof},
		"a registry progress beyond a uint64": {func(w *rejectWorld) { w.registry[registryKey("records.progress")] = word32{7: 1} }, ErrProof},
	} {
		w := newRejectWorld(t, "reserved", fixtureReservedAt)
		c.mutate(&w)
		_, err := w.verify(t)
		require.ErrorIs(t, err, c.want, name)
	}
	w := newRejectWorld(t, "reserved", fixtureReservedAt)
	raw, root := w.witness(t)
	for name, mutate := range map[string]func(p *Pins){
		"another election code":    func(p *Pins) { p.ElectionCode[0] ^= 1 },
		"another custody code":     func(p *Pins) { p.CustodyCode[0] ^= 1 },
		"another registry code":    func(p *Pins) { p.RegistryCode[0] ^= 1 },
		"another network word":     func(p *Pins) { p.NetworkWord[0] ^= 1 },
		"another election address": func(p *Pins) { p.Election[0] ^= 1 },
		"no election pinned":       func(p *Pins) { p.Election = [20]byte{} },
		"another registry address": func(p *Pins) { p.Registry[0] ^= 1 },
	} {
		p := w.pins
		mutate(&p)
		_, err := Authority{Pins: p}.VerifyReject(raw, root, w.resultID)
		require.Error(t, err, name)
		require.True(t, errIs(err, ErrProof) || errIs(err, ErrWitness), "%s: %v", name, err)
	}
}

// Exactly the three accounts and exactly the slots the verifier reads: a missing account, an extra one or an extra proven slot is refused.
func TestRejectWitnessShapeIsExact(t *testing.T) {
	w := newRejectWorld(t, "reserved", fixtureReservedAt)
	raw, root := w.witness(t)
	got, err := decodeWitness(raw)
	require.NoError(t, err)
	require.Len(t, got.Accounts, 3)
	run := func(a []accountProof) error {
		_, err := Authority{Pins: w.pins}.VerifyReject(encode(t, a), root, w.resultID)
		return err
	}
	require.NoError(t, run(got.Accounts))
	require.ErrorIs(t, run(got.Accounts[:2]), ErrWitness, "two accounts")
	world := w.world(t)
	extraAccount := accountProof{Addr: []byte{19: 0xee}, Proofs: world.accountProof(t, [20]byte{0: 0xee, 19: 1})}
	require.ErrorIs(t, run(append(cloneAccounts(got.Accounts), extraAccount)), ErrWitness, "four accounts")
	for i := range got.Accounts {
		accounts := cloneAccounts(got.Accounts)
		var addr [20]byte
		copy(addr[:], accounts[i].Addr)
		extra := baseSlot(200)
		accounts[i].Slots = append(accounts[i].Slots, slotProof{Slot: extra[:], Value: make([]byte, 32), Proofs: world.slotProof(t, addr, extra)})
		sortSlots(accounts[i].Slots)
		err := run(accounts)
		require.ErrorIs(t, err, ErrWitness, "an extra slot on account %x", addr)
	}
}

// BuildRejectWitness builds, from eth_getProof-shaped answers, exactly the witness the readers read; it verifies, and the facts it returns
// are the verified ones. A source that fails or lies yields no witness, or one the verifier refuses.
func TestBuiltRejectWitnessEqualsTheReadersAndVerifies(t *testing.T) {
	w := newRejectWorld(t, "lost", fixtureReservedAt+3)
	world := w.world(t)
	src := &worldSource{t: t, w: world}
	built, facts, err := BuildRejectWitness(context.Background(), src, w.pins, w.resultID)
	require.NoError(t, err)
	require.LessOrEqual(t, src.calls, 4, "one call per account, and custody's assignment slot")
	read, _ := w.witness(t)
	require.Equal(t, read, built)
	verified, err := Authority{Pins: w.pins}.VerifyReject(built, world.root, w.resultID)
	require.NoError(t, err)
	require.Equal(t, verified, facts)
	require.True(t, storage.RejectDue(facts), "lost")

	_, _, err = BuildRejectWitness(context.Background(), &worldSource{t: t, w: world, failOn: w.pins.Registry}, w.pins, w.resultID)
	require.ErrorIs(t, err, ErrBuild)
	lying, _, err := BuildRejectWitness(context.Background(), &worldSource{t: t, w: world, lieSlot: true}, w.pins, w.resultID)
	if err == nil {
		_, err = Authority{Pins: w.pins}.VerifyReject(lying, world.root, w.resultID)
	}
	require.Error(t, err, "a lying source yields no witness the verifier accepts")
	noElection := w.pins
	noElection.Election = [20]byte{}
	_, _, err = BuildRejectWitness(context.Background(), src, noElection, w.resultID)
	require.ErrorIs(t, err, ErrBuild)
}
