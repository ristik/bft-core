package vrschema

import (
	"fmt"
	"sort"
)

// Member is one output member: ten words, abi.encode order.
type Member struct {
	ID             uint64   `json:"id"`
	Generation     uint64   `json:"generation"`
	Weight         uint64   `json:"weight"`
	RawWeight      uint64   `json:"rawWeight"`
	RootNodeWord   Word     `json:"-"`
	RootKeyHash    Word     `json:"-"`
	EVMNodeWord    Word     `json:"-"`
	EVMKeyHash     Word     `json:"-"`
	Payee          [20]byte `json:"-"`
	ExposureDigest Word     `json:"-"`
}

// MemberWords is the number of words of one member.
const MemberWords = 10

// Words is abi.encode(member).
func (m Member) Words() []byte {
	return words(U64(m.ID), U64(m.Generation), U64(m.Weight), U64(m.RawWeight), m.RootNodeWord, m.RootKeyHash, m.EVMNodeWord,
		m.EVMKeyHash, AddrWord(m.Payee), m.ExposureDigest)
}

// DecodeMember reads ten words; narrow fields must be zero-padded.
func DecodeMember(b []byte) (Member, error) {
	var m Member
	if len(b) != 32*MemberWords {
		return m, ErrLength
	}
	var err error
	for i, p := range []*uint64{&m.ID, &m.Generation, &m.Weight, &m.RawWeight} {
		if *p, err = WordU64(wordAt(b, i)); err != nil {
			return m, err
		}
	}
	m.RootNodeWord, m.RootKeyHash, m.EVMNodeWord, m.EVMKeyHash = wordAt(b, 4), wordAt(b, 5), wordAt(b, 6), wordAt(b, 7)
	if m.Payee, err = WordAddr(wordAt(b, 8)); err != nil {
		return m, err
	}
	m.ExposureDigest = wordAt(b, 9)
	return m, nil
}

// MemberHash is h_i = keccak256(abi.encode(member)).
func MemberHash(m Member) Word { return keccak(m.Words()) }

// MembersDigest is keccak256(abi.encode(MEMBERS_DOMAIN, n, h_1..h_n)) over members in strictly ascending id.
func MembersDigest(ms []Member) (Word, error) {
	parts := [][]byte{MembersDomain[:], func() []byte { w := U64(uint64(len(ms))); return w[:] }()}
	for i, m := range ms {
		if i > 0 && ms[i-1].ID >= m.ID {
			return Word{}, ErrOrder
		}
		h := MemberHash(m)
		parts = append(parts, h[:])
	}
	return keccak(parts...), nil
}

// BoundChange is one entry of the changes digest.
type BoundChange struct {
	ID          uint64 `json:"id"`
	Kind        uint8  `json:"kind"`
	PayloadHash Word   `json:"-"`
}

// ChangesDigest is keccak256(abi.encode(CHANGES_DOMAIN, n_c, (id, kind, payloadHash)...)) over strictly ascending ids.
func ChangesDigest(cs []BoundChange) (Word, error) {
	n := U64(uint64(len(cs)))
	parts := [][]byte{ChangesDomain[:], n[:]}
	for i, c := range cs {
		if i > 0 && cs[i-1].ID >= c.ID {
			return Word{}, ErrOrder
		}
		parts = append(parts, words(U64(c.ID), U64(uint64(c.Kind)), c.PayloadHash))
	}
	return keccak(parts...), nil
}

// PayloadHash is keccak256(payload).
func PayloadHash(payload []byte) Word { return keccak(payload) }

// OutputCommitInput is everything outputCommit binds.
type OutputCommitInput struct {
	Network        Word
	ChainID        Word
	Registry       [20]byte
	ResultID       Word
	Predecessor    Word
	Attempt        uint64
	ModuleTag      Word
	Native         bool
	SnapshotDigest Word
	PolicyDigest   Word
	MembersDigest  Word
	KDigest        Word
	ChangesDigest  Word
}

// OutputCommit is word9 of the output record.
func OutputCommit(in OutputCommitInput) Word {
	return keccak(words(OutputDomain, in.Network, in.ChainID, AddrWord(in.Registry), in.ResultID, in.Predecessor, U64(in.Attempt),
		in.ModuleTag, BoolWord(in.Native), in.SnapshotDigest, in.PolicyDigest, in.MembersDigest, in.KDigest, in.ChangesDigest))
}

// NativeResultID is keccak256(abi.encode(VR_RESULT_DOMAIN, network, chainid, VR, lastAcked, attempt, origin)).
func NativeResultID(network, chainID Word, registry [20]byte, lastAcked Word, attempt uint64, origin Word) Word {
	return keccak(words(NativeResult, network, chainID, AddrWord(registry), lastAcked, U64(attempt), origin))
}

// Registration is the VR registration struct.
type Registration struct {
	RootNodeID string   `json:"rootNodeId"`
	RootKey    []byte   `json:"rootKey"`
	EVMNodeID  string   `json:"evmNodeId"`
	EVMKey     []byte   `json:"evmKey"`
	Payee      [20]byte `json:"-"`
	Nonce      uint64   `json:"nonce"`
}

// ValidShape is the structural check of design section 3.1: node ids 1..128 bytes, 33-byte keys that differ, a nonzero payee. (Curve
// membership is checked by KeyLib at registration.)
func (r Registration) ValidShape() error {
	switch {
	case len(r.RootNodeID) < 1 || len(r.RootNodeID) > 128, len(r.EVMNodeID) < 1 || len(r.EVMNodeID) > 128:
		return fmt.Errorf("%w: node id length", ErrLength)
	case len(r.RootKey) != 33 || len(r.EVMKey) != 33 || (r.RootKey[0] != 2 && r.RootKey[0] != 3) || (r.EVMKey[0] != 2 && r.EVMKey[0] != 3):
		return fmt.Errorf("%w: key", ErrLength)
	case string(r.RootKey) == string(r.EVMKey):
		return fmt.Errorf("%w: rootKey == evmKey", ErrRange)
	case r.Payee == [20]byte{}:
		return fmt.Errorf("%w: zero payee", ErrRange)
	}
	return nil
}

// RegistrationDigest is the digest both keys sign (65-byte low-s r||s||v, v in {27, 28}, over the digest itself): keccak256(abi.encode(
// DOMAIN, network, chainid, VR, msg.sender, id_or_0, keccak(rootNodeID), keccak(rootKey), keccak(evmNodeID), keccak(evmKey), payee,
// nonce)) with DOMAIN = keccak256("unicity.vr.register") for register (id 0) or keccak256("unicity.vr.binding") for proposeBinding.
func RegistrationDigest(binding bool, network, chainID Word, registry, sender [20]byte, id uint64, r Registration) Word {
	d := RegisterDomain
	if binding {
		d = BindingDomain
	}
	return keccak(words(d, network, chainID, AddrWord(registry), AddrWord(sender), U64(id), keccak([]byte(r.RootNodeID)), keccak(r.RootKey),
		keccak([]byte(r.EVMNodeID)), keccak(r.EVMKey), AddrWord(r.Payee), U64(r.Nonce)))
}

// MemberOf is the member words of a binding.
func MemberOf(id, generation, weight, rawWeight uint64, r Registration, exposure Word) Member {
	return Member{ID: id, Generation: generation, Weight: weight, RawWeight: rawWeight, RootNodeWord: keccak([]byte(r.RootNodeID)),
		RootKeyHash: keccak(r.RootKey), EVMNodeWord: keccak([]byte(r.EVMNodeID)), EVMKeyHash: keccak(r.EVMKey), Payee: r.Payee, ExposureDigest: exposure}
}

// PoaExposureDigest is the PoA member exposureDigest (design section 3.7.3): the evmassign custody exposure formula ExposureID with
// deployment = (network word, chain id, VR address), keccak256(abi.encode(keccak256("unicity.p85.exposure"), network, chainid, VR,
// assignment, uint256(id))), where the assignment word is the output's resultId (the one per-output identifier a module holds when it
// composes; freeze decision FD-6).
func PoaExposureDigest(network, chainID Word, registry [20]byte, resultID Word, id uint64) Word {
	return keccak(words(P85ExposureDomain, network, chainID, AddrWord(registry), resultID, U64(id)))
}

// RuleID is keccak256(bytes("unicity.rule/" + name)).
func RuleID(name string) Word { return keccak([]byte(RulePrefix + name)) }

// RetirementV2Key is the SealRegistry dedup key keccak256(abi.encode(RECORDS_RETIREMENT_V2, holder, id, generation)).
func RetirementV2Key(holder uint8, id, generation uint64) Word {
	return keccak(words(RetirementV2, U64(uint64(holder)), U64(id), U64(generation)))
}

// SortMembers orders members by id.
func SortMembers(ms []Member) { sort.Slice(ms, func(i, j int) bool { return ms[i].ID < ms[j].ID }) }
