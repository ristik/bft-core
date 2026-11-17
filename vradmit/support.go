package vradmit

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Rule support (design section 7.3, schema section 10.4). A commitment is signed by one binding's root key; it counts only for that exact
// binding (stakingID, generation, rootKeyHash), so a binding replacement invalidates it. The committed table is part of the control
// state digest and holds at most 16 members x 64 rules.

var (
	// ErrSupport reports a commitment that is malformed, by another key or for another binding, or a support gate that does not hold.
	ErrSupport = errors.New("vradmit: rule support")
	// ErrSupportWait reports a gate that does not hold yet: no Prepare is ordered and the incumbents continue (never a fault).
	ErrSupportWait = fmt.Errorf("%w: support is not sufficient yet", ErrSupport)
)

// VerifyCommitment checks that c is m's exact binding's commitment: the staking id and generation are m's, rootKeyHash is
// keccak256(m.RootKey), and the signature verifies by m.RootKey over the commitment's signed bytes.
func VerifyCommitment(c vrschema.SupportCommitment, m evmassign.Identity) error {
	kh := ethcrypto.Keccak256(m.RootKey)
	if !bytes.Equal(c.StakingID, m.StakingID) || c.Generation != m.Generation || !bytes.Equal(c.RootKeyHash, kh) {
		return fmt.Errorf("%w: commitment is not by the current binding of %x", ErrSupport, m.StakingID)
	}
	msg, err := c.SignedBytes()
	if err != nil {
		return errors.Join(ErrSupport, err)
	}
	if len(c.Sig) != 65 {
		return fmt.Errorf("%w: signature length", ErrSupport)
	}
	if err := vrschema.Verify(m.RootKey, c.Sig, msg); err != nil {
		return errors.Join(ErrSupport, err)
	}
	return nil
}

// SupportTable is the committed support table: commitments strictly ascending by (stakingID, ruleId), one per pair.
type SupportTable struct {
	Entries []vrschema.SupportCommitment
}

type tableWire struct {
	_       struct{} `cbor:",toarray"`
	Domain  string
	Version uint64
	Entries []vrschema.SupportCommitment
}

const supportTableDomain = "UNICITY_VR_SUPPORT_TABLE"

func less(a, b vrschema.SupportCommitment) int {
	if k := bytes.Compare(a.StakingID, b.StakingID); k != 0 {
		return k
	}
	return bytes.Compare(a.RuleID, b.RuleID)
}

func (t SupportTable) check() error {
	members := 0
	for i, e := range t.Entries {
		if _, err := e.SignedBytes(); err != nil || len(e.Sig) != 65 {
			return fmt.Errorf("%w: table entry %d", ErrSupport, i)
		}
		if i > 0 && less(t.Entries[i-1], e) >= 0 {
			return fmt.Errorf("%w: table not strictly ascending", ErrSupport)
		}
		if i == 0 || !bytes.Equal(t.Entries[i-1].StakingID, e.StakingID) {
			members++
		}
	}
	rules := map[string]bool{}
	for _, e := range t.Entries {
		rules[string(e.RuleID)] = true
	}
	if members > vrschema.SupportMembers || len(rules) > vrschema.SupportRules {
		return fmt.Errorf("%w: table exceeds %d members x %d rules", ErrSupport, vrschema.SupportMembers, vrschema.SupportRules)
	}
	return nil
}

// Encode is the canonical CBOR of the table.
func (t SupportTable) Encode() ([]byte, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	es := t.Entries
	if es == nil {
		es = []vrschema.SupportCommitment{}
	}
	return types.Cbor.Marshal(tableWire{Domain: supportTableDomain, Version: 1, Entries: es})
}

// DecodeSupportTable accepts exactly the canonical encoding.
func DecodeSupportTable(b []byte) (SupportTable, error) {
	var w tableWire
	if err := types.Cbor.Unmarshal(b, &w); err != nil || w.Domain != supportTableDomain || w.Version != 1 {
		return SupportTable{}, fmt.Errorf("%w: table encoding", ErrSupport)
	}
	t := SupportTable{Entries: w.Entries}
	again, err := t.Encode()
	if err != nil || !bytes.Equal(again, b) {
		return SupportTable{}, fmt.Errorf("%w: table not canonical", ErrSupport)
	}
	return t, nil
}

// Find returns the committed commitment whose digest is ref.
func (t SupportTable) Find(ref []byte) (vrschema.SupportCommitment, bool) {
	for _, e := range t.Entries {
		if d, err := e.Digest(); err == nil && bytes.Equal(d[:], ref) {
			return e, true
		}
	}
	return vrschema.SupportCommitment{}, false
}

// Add inserts verified commitments, each replacing the pair's earlier entry, and refuses a result over the table bound. The caller has
// verified each commitment against its binding (VerifyCommitment).
func (t SupportTable) Add(cs ...vrschema.SupportCommitment) (SupportTable, error) {
	out := append([]vrschema.SupportCommitment(nil), t.Entries...)
	for _, c := range cs {
		i := sort.Search(len(out), func(i int) bool { return less(out[i], c) >= 0 })
		if i < len(out) && less(out[i], c) == 0 {
			out[i] = c
			continue
		}
		out = append(out, vrschema.SupportCommitment{})
		copy(out[i+1:], out[i:])
		out[i] = c
	}
	n := SupportTable{Entries: out}
	return n, n.check()
}

// Prune drops the entries of every binding outside keep: the acknowledged committee and any pending K (design section 7.3). An entry of a
// kept staking id whose generation or key is no longer that binding's is dropped too, because it can never count again.
func (t SupportTable) Prune(keep []evmassign.Identity) SupportTable {
	var out []vrschema.SupportCommitment
	for _, e := range t.Entries {
		for _, m := range keep {
			if bytes.Equal(e.StakingID, m.StakingID) && e.Generation == m.Generation && bytes.Equal(e.RootKeyHash, ethcrypto.Keccak256(m.RootKey)) {
				out = append(out, e)
				break
			}
		}
	}
	return SupportTable{Entries: out}
}

// ApplyRuleSupport is control op 4: 1 to 64 commitments (strictly ascending by (stakingID, ruleId), checked by the codec), each by the
// exact current binding of a member of the acknowledged committee or of a pending K, on the root network, for a rule of the committed
// schedule. They enter the table.
func ApplyRuleSupport(t SupportTable, network uint64, cs []vrschema.SupportCommitment, members []evmassign.Identity, schedule []vrschema.Activation) (SupportTable, error) {
	if len(cs) == 0 || len(cs) > vrschema.MaxRuleSupportCommitments {
		return t, fmt.Errorf("%w: %d commitments", ErrSupport, len(cs))
	}
	eff := vrschema.Effective(schedule)
	for i, c := range cs {
		if c.Network != network {
			return t, fmt.Errorf("%w: commitment %d names network %d", ErrSupport, i, c.Network)
		}
		if _, ok := eff[vrschema.Word(c.RuleID)]; !ok {
			return t, fmt.Errorf("%w: commitment %d names no scheduled rule", ErrSupport, i)
		}
		m, ok := memberByID(members, c.StakingID)
		if !ok {
			return t, fmt.Errorf("%w: commitment %d is not by a committee binding", ErrSupport, i)
		}
		if err := VerifyCommitment(c, m); err != nil {
			return t, fmt.Errorf("commitment %d: %w", i, err)
		}
	}
	return t.Add(cs...)
}

func memberByID(ms []evmassign.Identity, id []byte) (evmassign.Identity, bool) {
	for _, m := range ms {
		if bytes.Equal(m.StakingID, id) {
			return m, true
		}
	}
	return evmassign.Identity{}, false
}

// SupportInput is the rule-support gate of a Prepare (and its Freeze) for a primary J at successor epoch e_J (design section 7.3).
type SupportInput struct {
	Network        uint64
	SuccessorEpoch uint64
	// Schedule is the root's committed schedule (root-latched entries included).
	Schedule []vrschema.Activation
	Table    SupportTable
	Evidence vrschema.RuleSupportEvidence
	// Readiness is the certificate's readiness, one per successor in identity order; J the successor identities, K the acknowledged
	// committee with its exact current bindings and committed weights.
	Readiness    []vrschema.Readiness
	IntentDigest []byte
	J, K         []evmassign.Identity
}

// requiredRules lists every effective rule with E <= e_J + 1, the epoch J's recovery would reach.
func requiredRules(schedule []vrschema.Activation, e uint64) []vrschema.Activation {
	var out []vrschema.Activation
	for _, a := range vrschema.Effective(schedule) {
		if e == ^uint64(0) || a.RootEpoch <= e+1 {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].RuleID[:], out[j].RuleID[:]) < 0 })
	return out
}

// VerifyRuleSupport is the gate, for every effective rule with E <= e_J + 1:
//
//	(a) fresh support from every member of J, in its readiness; a latched rule may instead be covered by that member's committed
//	    table entry (a latched rule needs no new commitment);
//	(b) for every rule not yet latched, committed support by K members' exact current bindings over strictly more than 2/3 of K's
//	    committed weight, from referenced table entries, fresh commitments or this intent's K-member readiness. A latched rule is
//	    already in force for K.
//
// Evidence that is malformed or by another binding refuses; insufficient support is ErrSupportWait.
func VerifyRuleSupport(in SupportInput) error {
	rules := requiredRules(in.Schedule, in.SuccessorEpoch)
	if len(rules) == 0 {
		return nil
	}
	ev := in.Evidence
	// every evidence item must verify, whether or not it is needed
	var pool []vrschema.SupportCommitment
	for _, ref := range ev.Refs {
		c, ok := in.Table.Find(ref)
		if !ok {
			return fmt.Errorf("%w: reference %x is not a committed table entry", ErrSupport, ref)
		}
		pool = append(pool, c)
	}
	byID := func(id []byte) (evmassign.Identity, bool) {
		if m, ok := memberByID(in.K, id); ok {
			return m, true
		}
		return memberByID(in.J, id)
	}
	for i, c := range ev.Fresh {
		m, ok := byID(c.StakingID)
		if !ok || c.Network != in.Network {
			return fmt.Errorf("%w: fresh commitment %d is not by a J or K binding", ErrSupport, i)
		}
		if err := VerifyCommitment(c, m); err != nil {
			return err
		}
		pool = append(pool, c)
	}
	for i, r := range ev.KReadiness {
		if !bytes.Equal(r.IntentDigest, in.IntentDigest) {
			return fmt.Errorf("%w: K readiness %d is for another intent", ErrSupport, i)
		}
		id, err := vrschema.KReadinessStakingID(r)
		if err != nil {
			return errors.Join(ErrSupport, err)
		}
		m, ok := memberByID(in.K, id)
		if !ok {
			return fmt.Errorf("%w: K readiness %d is not by a K member", ErrSupport, i)
		}
		env, err := r.EnvelopeBytes()
		if err != nil {
			return errors.Join(ErrSupport, err)
		}
		if err := vrschema.Verify(m.RootKey, r.EnvelopeSig, env); err != nil {
			return fmt.Errorf("%w: K readiness %d envelope: %w", ErrSupport, i, err)
		}
		for _, c := range r.Commitments {
			if c.Network != in.Network {
				return fmt.Errorf("%w: K readiness %d names another network", ErrSupport, i)
			}
			if err := VerifyCommitment(c, m); err != nil {
				return err
			}
			pool = append(pool, c)
		}
	}
	covers := func(cs []vrschema.SupportCommitment, m evmassign.Identity, rule vrschema.Word) bool {
		kh := ethcrypto.Keccak256(m.RootKey)
		for _, c := range cs {
			if bytes.Equal(c.StakingID, m.StakingID) && c.Generation == m.Generation && bytes.Equal(c.RootKeyHash, kh) &&
				bytes.Equal(c.RuleID, rule[:]) && c.Network == in.Network {
				return true
			}
		}
		return false
	}
	if len(in.Readiness) != len(in.J) {
		return fmt.Errorf("%w: %d readiness for %d successors", ErrSupport, len(in.Readiness), len(in.J))
	}
	for _, a := range rules {
		// (a)
		for i, m := range in.J {
			if covers(in.Readiness[i].Commitments, m, a.RuleID) {
				continue
			}
			if a.State == vrschema.ActLatched && covers(in.Table.Entries, m, a.RuleID) {
				continue
			}
			return fmt.Errorf("%w: successor %x lacks support for rule %x", ErrSupportWait, m.StakingID, a.RuleID)
		}
		// (b)
		if a.State == vrschema.ActLatched {
			continue
		}
		var have, total uint64
		for _, m := range in.K {
			total += m.Weight
			if covers(pool, m, a.RuleID) {
				have += m.Weight
			}
		}
		if total == 0 || !(3*have > 2*total) {
			return fmt.Errorf("%w: K support %d of %d for rule %x", ErrSupportWait, have, total, a.RuleID)
		}
	}
	return nil
}

// MaterializeJ is the table after a primary acknowledgement of J: J's entries come from J's own readiness (design section 7.3), and
// bindings outside the new committee (and any pending K) are pruned.
func MaterializeJ(t SupportTable, readiness []vrschema.Readiness, keep []evmassign.Identity) (SupportTable, error) {
	var cs []vrschema.SupportCommitment
	for _, r := range readiness {
		cs = append(cs, r.Commitments...)
	}
	n, err := t.Add(cs...)
	if err != nil {
		return t, err
	}
	return n.Prune(keep), nil
}
