package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network"
)

// Q4 #51 (A): canonical identity/weight fixtures for the weighted adversarial gate. Everything here is test-only: the keys are
// derived from a seed so that a run is replayable, they are never production key material, and nothing in this file activates
// anything. The expected arithmetic (totals, thresholds, subsets) is computed by the integer helpers of q4_oracle_test.go, not by the
// production quorum code, which is only compared against it as a premise.

var (
	errQ4DuplicateIdentity   = errors.New("q4: duplicate identity")
	errQ4ZeroWeight          = errors.New("q4: zero weight")
	errQ4WeightBound         = errors.New("q4: weight above the supported bound")
	errQ4WeightOverflow      = errors.New("q4: total weight overflows")
	errQ4NotCanonical        = errors.New("q4: vector is not in canonical (peer ID) order")
	errQ4SharedKey           = errors.New("q4: a key is shared between identities or roles")
	errQ4TurnoverTooLarge    = errors.New("q4: one third or more of the validators changed")
	errQ4RetainedBelowQuorum = errors.New("q4: retained weight is below the quorum")
	errQ4UnknownTarget       = errors.New("q4: fault target is not an identity of the roster")
	errQ4BadRole             = errors.New("q4: fault target role is not root or evm")
	errQ4EVMNotCovered       = errors.New("q4: evm target in a root-only scenario")
	errQ4TargetOverlap       = errors.New("q4: identity is both Byzantine and unavailable")
	errQ4NoDeadline          = errors.New("q4: manifest has no frozen deadline")
)

// q4MaxWeight is the supported per-identity weight bound of the fixtures; three of it overflow a uint64 total.
const q4MaxWeight = uint64(1) << 62

// q4Entity is one validator entity: a root signing key and root peer identity, and a separate EVM role key.
type q4Entity struct {
	Name     string
	ID       peer.ID
	Signer   abcrypto.Signer
	Verifier abcrypto.Verifier
	PeerKey  *network.PeerKeyPair
	EVMKey   []byte // compressed public key of the entity's EVM role key
}

func q4Derive(seed string, index int, role string) []byte {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], uint64(index))
	h := sha256.Sum256(bytes.Join([][]byte{[]byte("q4/key/v1"), []byte(seed), idx[:], []byte(role)}, []byte{0}))
	return h[:]
}

// q4Pool derives n entities from the seed and returns them in canonical order, sorted by the canonical peer ID string, which is the
// order the trust base and the leader schedule use. Names are assigned later by the roster.
func q4Pool(t testing.TB, seed string, n int) []*q4Entity {
	t.Helper()
	pool := make([]*q4Entity, n)
	for i := range pool {
		signer, err := abcrypto.NewInMemorySecp256K1SignerFromKey(q4Derive(seed, i, "root-sig"))
		require.NoError(t, err)
		verifier, err := signer.Verifier()
		require.NoError(t, err)
		priv, err := crypto.UnmarshalSecp256k1PrivateKey(q4Derive(seed, i, "root-peer"))
		require.NoError(t, err)
		raw, err := priv.Raw()
		require.NoError(t, err)
		pubRaw, err := priv.GetPublic().Raw()
		require.NoError(t, err)
		id, err := network.NodeIDFromPublicKeyBytes(pubRaw)
		require.NoError(t, err)
		evm, err := abcrypto.NewInMemorySecp256K1SignerFromKey(q4Derive(seed, i, "evm"))
		require.NoError(t, err)
		evmVerifier, err := evm.Verifier()
		require.NoError(t, err)
		evmPub, err := evmVerifier.MarshalPublicKey()
		require.NoError(t, err)
		pool[i] = &q4Entity{ID: id, Signer: signer, Verifier: verifier, PeerKey: &network.PeerKeyPair{PublicKey: pubRaw, PrivateKey: raw}, EVMKey: evmPub}
	}
	slices.SortFunc(pool, func(a, b *q4Entity) int { return strings.Compare(a.ID.String(), b.ID.String()) })
	return pool
}

// q4Set is a weight vector in descending role order with the role names; EVM is false for a root-only scenario.
type q4Set struct {
	Name    string
	Names   []string
	Weights []uint64
	EVM     bool
}

func q4Lights(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d", prefix, i+1)
	}
	return out
}

var (
	q4SetA          = q4Set{"A", []string{"H", "a", "b", "c"}, []uint64{6, 1, 1, 1}, true}
	q4SetB          = q4Set{"B", []string{"H1", "H2", "n2", "n1"}, []uint64{3, 3, 2, 1}, true}
	q4SetManySmall  = q4Set{"many-small", append([]string{"H"}, q4Lights("l", 9)...), []uint64{18, 1, 1, 1, 1, 1, 1, 1, 1, 1}, false}
	q4SetOutageCtrl = q4Set{"outage-control", append([]string{"H"}, q4Lights("l", 4)...), []uint64{3, 2, 2, 2, 2}, true}
)

// q4Arrangements are the distinct placements of the set's weights over the canonical positions (4 for A, 12 for B, 10 for many-small).
func q4Arrangements(weights []uint64) [][]uint64 {
	var out [][]uint64
	seen := map[string]bool{}
	var rec func(rest []uint64, cur []uint64)
	rec = func(rest, cur []uint64) {
		if len(rest) == 0 {
			if key := fmt.Sprint(cur); !seen[key] {
				seen[key] = true
				out = append(out, slices.Clone(cur))
			}
			return
		}
		for i := range rest {
			next := append(slices.Clone(rest[:i]), rest[i+1:]...)
			rec(next, append(slices.Clone(cur), rest[i]))
		}
	}
	rec(weights, nil)
	return out
}

// q4Roster is the canonical vector of one scenario instance: entity i in canonical position i carries Weights[i].
type q4Roster struct {
	Set      q4Set
	Seed     string
	Entities []*q4Entity
	Weights  []uint64
}

// q4NewRoster places the set's weights over the pool's canonical positions as given by arrangement. Names follow the role order:
// the heaviest weight class first, ties in canonical position order.
func q4NewRoster(t testing.TB, set q4Set, seed string, arrangement []uint64) *q4Roster {
	t.Helper()
	pool := q4Pool(t, seed, len(set.Weights))
	order := make([]int, len(arrangement))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int {
		switch {
		case arrangement[a] > arrangement[b]:
			return -1
		case arrangement[a] < arrangement[b]:
			return 1
		}
		return 0
	})
	for rank, pos := range order {
		require.Equal(t, set.Weights[rank], arrangement[pos], "premise: the arrangement is a permutation of the set")
		pool[pos].Name = set.Names[rank]
	}
	r := &q4Roster{Set: set, Seed: seed, Entities: pool, Weights: slices.Clone(arrangement)}
	require.NoError(t, r.Validate())
	return r
}

func q4DefaultRoster(t testing.TB, set q4Set) *q4Roster {
	return q4NewRoster(t, set, "q4-"+set.Name, set.Weights)
}

// Validate is the pure canonical-vector check: unique identities, positive and bounded weights, checked total, canonical order and
// distinct keys across all identities and roles.
func (r *q4Roster) Validate() error {
	var total uint64
	keys := map[string]string{}
	for i, e := range r.Entities {
		for _, k := range [][]byte{e.PeerKey.PublicKey, q4PubKey(e.Verifier), e.EVMKey} {
			if prev, dup := keys[string(k)]; dup {
				return fmt.Errorf("%w: %s and %s", errQ4SharedKey, prev, e.Name)
			}
			keys[string(k)] = e.Name
		}
		for _, o := range r.Entities[:i] {
			if o.Name == e.Name || o.ID == e.ID {
				return fmt.Errorf("%w: %s", errQ4DuplicateIdentity, e.Name)
			}
		}
		if i > 0 && strings.Compare(r.Entities[i-1].ID.String(), e.ID.String()) >= 0 {
			return fmt.Errorf("%w: position %d", errQ4NotCanonical, i)
		}
		switch w := r.Weights[i]; {
		case w == 0:
			return fmt.Errorf("%w: %s", errQ4ZeroWeight, e.Name)
		case w > q4MaxWeight:
			return fmt.Errorf("%w: %s", errQ4WeightBound, e.Name)
		case total > math.MaxUint64-w:
			return errQ4WeightOverflow
		default:
			total += w
		}
	}
	return nil
}

func q4PubKey(v abcrypto.Verifier) []byte {
	b, err := v.MarshalPublicKey()
	if err != nil {
		panic(err)
	}
	return b
}

func (r *q4Roster) Index(name string) int {
	for i, e := range r.Entities {
		if e.Name == name {
			return i
		}
	}
	return -1
}

func (r *q4Roster) Total() uint64     { return q4Sum(r.Weights) }
func (r *q4Roster) Quorum() uint64    { return q4Threshold(r.Total()) }
func (r *q4Roster) Faulty() uint64    { return r.Total() - r.Quorum() }
func (r *q4Roster) EVMQuorum() uint64 { return r.Total()/2 + 1 }

// Weight is the combined root weight of the named identities.
func (r *q4Roster) Weight(names ...string) uint64 {
	var w uint64
	for _, n := range names {
		w += r.Weights[r.Index(n)]
	}
	return w
}

func (r *q4Roster) Names() []string {
	out := make([]string, len(r.Entities))
	for i, e := range r.Entities {
		out[i] = e.Name
	}
	return out
}

// NodeInfos is the trust base member list, in canonical order.
func (r *q4Roster) NodeInfos() []*types.NodeInfo {
	infos := make([]*types.NodeInfo, len(r.Entities))
	for i, e := range r.Entities {
		infos[i] = &types.NodeInfo{NodeID: e.ID.String(), SigKey: q4PubKey(e.Verifier), Stake: r.Weights[i]}
	}
	return infos
}

// q4EpochMap is the per-epoch role map of one scenario: independent root and EVM assignments by entity name.
type q4EpochMap struct {
	Epoch uint64
	Root  map[string]uint64
	EVM   map[string]uint64
}

type q4Turnover struct {
	Changed, Total           int
	RetainedOld, RetainedNew uint64
	QuorumOld, QuorumNew     uint64
}

// q4CheckTurnover is the pure boundary check: strictly fewer than one third of the old validators are not carried over, and the
// carried-over validators are still a quorum in both epochs, with the weight each of them has in that epoch.
func q4CheckTurnover(old, next q4EpochMap) (q4Turnover, error) {
	rep := q4Turnover{Total: len(old.Root), QuorumOld: q4Threshold(q4SumMap(old.Root)), QuorumNew: q4Threshold(q4SumMap(next.Root))}
	for name, w := range old.Root {
		if nw, kept := next.Root[name]; kept {
			rep.RetainedOld += w
			rep.RetainedNew += nw
		} else {
			rep.Changed++
		}
	}
	if 3*rep.Changed >= rep.Total {
		return rep, fmt.Errorf("%w: %d of %d", errQ4TurnoverTooLarge, rep.Changed, rep.Total)
	}
	if rep.RetainedOld < rep.QuorumOld || rep.RetainedNew < rep.QuorumNew {
		return rep, fmt.Errorf("%w: old %d/%d, new %d/%d", errQ4RetainedBelowQuorum, rep.RetainedOld, rep.QuorumOld, rep.RetainedNew, rep.QuorumNew)
	}
	return rep, nil
}

func q4SumMap(m map[string]uint64) uint64 {
	var s uint64
	for _, w := range m {
		s += w
	}
	return s
}

// q4Target names an identity and the role the fault applies to; fault and durable-store targets are never positional.
type q4Target struct{ Name, Role string }

// q4Manifest is the replayable declaration of one scenario instance.
type q4Manifest struct {
	Seed        string
	Set         string
	Coverage    string // ORACLE-ONLY, IN-PROCESS or REAL-PROCESS
	EVM         bool
	Byzantine   []q4Target
	Unavailable []q4Target
	Delta       time.Duration
	Deadline    time.Duration
}

func (m *q4Manifest) Validate(r *q4Roster) error {
	byz := map[string]bool{}
	for _, tg := range append(slices.Clone(m.Byzantine), m.Unavailable...) {
		if r.Index(tg.Name) < 0 {
			return fmt.Errorf("%w: %q", errQ4UnknownTarget, tg.Name)
		}
		switch tg.Role {
		case "root":
		case "evm":
			if !m.EVM {
				return fmt.Errorf("%w: %q", errQ4EVMNotCovered, tg.Name)
			}
		default:
			return fmt.Errorf("%w: %q", errQ4BadRole, tg.Role)
		}
	}
	for _, tg := range m.Byzantine {
		byz[tg.Name+"/"+tg.Role] = true
	}
	for _, tg := range m.Unavailable {
		if byz[tg.Name+"/"+tg.Role] {
			return fmt.Errorf("%w: %q", errQ4TargetOverlap, tg.Name)
		}
	}
	if m.Deadline == 0 {
		return errQ4NoDeadline
	}
	return nil
}

func q4Names(ts []q4Target, role string) []string {
	var out []string
	for _, t := range ts {
		if t.Role == role {
			out = append(out, t.Name)
		}
	}
	return out
}

// Class is IN-BOUND when the declared Byzantine root weight is at most F, otherwise OUTSIDE-ASSUMPTIONS.
func (m *q4Manifest) Class(r *q4Roster) string {
	if r.Weight(q4Names(m.Byzantine, "root")...) <= r.Faulty() {
		return "IN-BOUND"
	}
	return "OUTSIDE-ASSUMPTIONS"
}

// Responsive is the root weight that is neither Byzantine nor unavailable.
func (m *q4Manifest) Responsive(r *q4Roster) uint64 {
	return r.Total() - r.Weight(q4Names(m.Byzantine, "root")...) - r.Weight(q4Names(m.Unavailable, "root")...)
}

func TestQ4Fixture(t *testing.T) {
	t.Run("A, B, many-small and the outage control are representable with the stated totals", func(t *testing.T) {
		for _, tc := range []struct {
			set                                       q4Set
			total, quorum, faulty, evmQuorum, parties uint64
		}{
			{q4SetA, 9, 7, 2, 5, 4},
			{q4SetB, 9, 7, 2, 5, 4},
			{q4SetManySmall, 27, 19, 8, 14, 10},
			{q4SetOutageCtrl, 11, 8, 3, 6, 5},
		} {
			r := q4DefaultRoster(t, tc.set)
			require.Equal(t, tc.total, r.Total(), tc.set.Name)
			require.Equal(t, tc.quorum, r.Quorum(), tc.set.Name)
			require.Equal(t, tc.faulty, r.Faulty(), tc.set.Name)
			if tc.set.Name != "outage-control" {
				require.Equal(t, tc.evmQuorum, r.EVMQuorum(), tc.set.Name)
			}
			require.EqualValues(t, tc.parties, len(r.Entities))
			// premise: the production trust base carries exactly this vector and threshold
			trust, err := q4TrustBase(r)
			require.NoError(t, err)
			require.Equal(t, tc.quorum, trust.QuorumThreshold)
			for i, n := range trust.RootNodes {
				require.Equal(t, r.Entities[i].ID.String(), n.NodeID)
				require.Equal(t, r.Weights[i], n.Stake)
			}
		}
		// the heavy member of A needs one light member for the root quorum 7 but meets the mirrored EVM request quorum 5 alone
		a := q4DefaultRoster(t, q4SetA)
		require.Less(t, a.Weight("H"), a.Quorum())
		require.GreaterOrEqual(t, a.Weight("H"), a.EVMQuorum())
		require.Equal(t, uint64(8), q4DefaultRoster(t, q4SetOutageCtrl).Weight("l1", "l2", "l3", "l4"), "the outage control keeps exactly its quorum without the heavy member")
	})

	t.Run("every arrangement is canonical, replayable from the seed and independent of input order", func(t *testing.T) {
		require.Len(t, q4Arrangements(q4SetA.Weights), 4)
		require.Len(t, q4Arrangements(q4SetB.Weights), 12)
		require.Len(t, q4Arrangements(q4SetManySmall.Weights), 10)
		for n, arr := range q4Arrangements(q4SetB.Weights) {
			r1 := q4NewRoster(t, q4SetB, "q4-seed", arr)
			r2 := r1
			if n < 3 { // a second derivation from the same seed (key derivation is the slow part)
				r2 = q4NewRoster(t, q4SetB, "q4-seed", arr)
			}
			require.Equal(t, r1.Names(), r2.Names(), "the same seed gives the same identities")
			for i := range r1.Entities {
				require.Equal(t, r1.Entities[i].ID, r2.Entities[i].ID)
				require.Equal(t, r1.Entities[i].EVMKey, r2.Entities[i].EVMKey)
			}
			// the canonical identity of a vector does not depend on the order it is given in
			infos := r1.NodeInfos()
			shuffled := slices.Clone(infos)
			slices.Reverse(shuffled)
			require.Equal(t, q4CanonicalVector(infos), q4CanonicalVector(shuffled))
		}
		require.NotEqual(t, q4DefaultRoster(t, q4SetA).Entities[0].ID, q4NewRoster(t, q4SetA, "another-seed", q4SetA.Weights).Entities[0].ID)
	})

	t.Run("duplicate, zero, oversized and overflowing vectors and shared keys are rejected", func(t *testing.T) {
		mutate := func(f func(r *q4Roster)) error {
			r := q4DefaultRoster(t, q4SetA)
			f(r)
			return r.Validate()
		}
		require.ErrorIs(t, mutate(func(r *q4Roster) { r.Entities[1].Name = r.Entities[0].Name }), errQ4DuplicateIdentity)
		require.ErrorIs(t, mutate(func(r *q4Roster) { r.Entities[1].ID = r.Entities[0].ID }), errQ4DuplicateIdentity)
		require.ErrorIs(t, mutate(func(r *q4Roster) { r.Weights[2] = 0 }), errQ4ZeroWeight)
		require.ErrorIs(t, mutate(func(r *q4Roster) { r.Weights[2] = q4MaxWeight + 1 }), errQ4WeightBound)
		require.ErrorIs(t, mutate(func(r *q4Roster) { r.Weights = []uint64{q4MaxWeight, q4MaxWeight, q4MaxWeight, q4MaxWeight} }), errQ4WeightOverflow)
		require.ErrorIs(t, mutate(func(r *q4Roster) { r.Entities[0], r.Entities[1] = r.Entities[1], r.Entities[0] }), errQ4NotCanonical)
		require.ErrorIs(t, mutate(func(r *q4Roster) { r.Entities[1].EVMKey = r.Entities[1].PeerKey.PublicKey }), errQ4SharedKey, "the EVM role key is not the root key")
		require.ErrorIs(t, mutate(func(r *q4Roster) { r.Entities[1].EVMKey = r.Entities[0].EVMKey }), errQ4SharedKey, "two entities do not share an EVM key")
		require.NoError(t, mutate(func(*q4Roster) {}), "control: the unmutated vector is valid")
		// the three roles of one entity have three different keys
		e := q4DefaultRoster(t, q4SetB).Entities[0]
		require.NotEqual(t, e.PeerKey.PublicKey, q4PubKey(e.Verifier))
		require.NotEqual(t, e.EVMKey, q4PubKey(e.Verifier))
	})

	t.Run("A to B turns one of four identities over and keeps weight 8 in both epochs", func(t *testing.T) {
		oldMap := q4EpochMap{1, map[string]uint64{"H": 6, "a": 1, "b": 1, "c": 1}, map[string]uint64{"H": 6, "a": 1, "b": 1, "c": 1}}
		newMap := q4EpochMap{2, map[string]uint64{"H": 3, "a": 3, "b": 2, "d": 1}, map[string]uint64{"H": 3, "a": 3, "b": 2, "d": 1}}
		rep, err := q4CheckTurnover(oldMap, newMap)
		require.NoError(t, err)
		require.Equal(t, 1, rep.Changed)
		require.EqualValues(t, 8, rep.RetainedOld, "H+a+b in epoch 1: 6+1+1")
		require.EqualValues(t, 8, rep.RetainedNew, "H+a+b in epoch 2: 3+3+2, the same keys with their epoch-2 weights")
		require.EqualValues(t, 7, rep.QuorumOld)
		require.EqualValues(t, 7, rep.QuorumNew)
		require.NotEqual(t, oldMap.Root["H"], newMap.Root["H"], "reweighting is explicit, not counted as unchanged stake")

		// heavy replacement: only one of four changes, but the carried weight is 3 < 7
		heavyGone := q4EpochMap{2, map[string]uint64{"d": 3, "a": 3, "b": 2, "c": 1}, nil}
		_, err = q4CheckTurnover(oldMap, heavyGone)
		require.ErrorIs(t, err, errQ4RetainedBelowQuorum)
		// two of four identities replaced: turnover is not below one third
		_, err = q4CheckTurnover(oldMap, q4EpochMap{2, map[string]uint64{"H": 3, "a": 3, "d": 2, "e": 1}, nil})
		require.ErrorIs(t, err, errQ4TurnoverTooLarge)
		// retained identities that fall below the new epoch's quorum
		_, err = q4CheckTurnover(oldMap, q4EpochMap{2, map[string]uint64{"H": 1, "a": 1, "b": 1, "d": 8}, nil})
		require.ErrorIs(t, err, errQ4RetainedBelowQuorum)
		// many-small: replacing one of ten keeps the carried quorum
		many := map[string]uint64{"H": 18}
		for _, n := range q4Lights("l", 9) {
			many[n] = 1
		}
		next := map[string]uint64{"H": 18, "x": 1}
		for _, n := range q4Lights("l", 8) {
			next[n] = 1
		}
		_, err = q4CheckTurnover(q4EpochMap{1, many, nil}, q4EpochMap{2, next, nil})
		require.NoError(t, err)
	})

	t.Run("manifest targets are identities and roles, the class follows the Byzantine weight", func(t *testing.T) {
		a := q4DefaultRoster(t, q4SetA)
		ok := &q4Manifest{Seed: a.Seed, Set: "A", Coverage: "IN-PROCESS", Byzantine: []q4Target{{"b", "root"}, {"c", "root"}}, Unavailable: []q4Target{{"a", "root"}}, Deadline: time.Minute}
		require.NoError(t, ok.Validate(a))
		require.Equal(t, "IN-BOUND", ok.Class(a))
		require.EqualValues(t, 6, ok.Responsive(a), "H alone is responsive: 9 - 2 - 1")
		heavy := &q4Manifest{Byzantine: []q4Target{{"H", "root"}}, Deadline: time.Minute}
		require.Equal(t, "OUTSIDE-ASSUMPTIONS", heavy.Class(a))
		for name, tc := range map[string]struct {
			m    q4Manifest
			want error
		}{
			"unknown target":              {q4Manifest{Byzantine: []q4Target{{"nobody", "root"}}, Deadline: 1}, errQ4UnknownTarget},
			"bad role":                    {q4Manifest{Byzantine: []q4Target{{"a", "storage"}}, Deadline: 1}, errQ4BadRole},
			"evm in a root-only scenario": {q4Manifest{Unavailable: []q4Target{{"a", "evm"}}, Deadline: 1}, errQ4EVMNotCovered},
			"byzantine and unavailable":   {q4Manifest{Byzantine: []q4Target{{"a", "root"}}, Unavailable: []q4Target{{"a", "root"}}, Deadline: 1}, errQ4TargetOverlap},
			"no frozen deadline":          {q4Manifest{Byzantine: []q4Target{{"a", "root"}}}, errQ4NoDeadline},
		} {
			require.ErrorIs(t, tc.m.Validate(a), tc.want, name)
		}
		// many-small is root-only: no EVM coverage is claimed, and the EVM request quorum is recorded for the coupled run
		ms := q4DefaultRoster(t, q4SetManySmall)
		require.False(t, ms.Set.EVM, "root-only: EVM coverage absent")
		require.EqualValues(t, 14, ms.EVMQuorum())
	})
}
