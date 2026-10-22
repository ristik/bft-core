// Package archivepolicy derives, from the authenticated installed validator set, the archive replicas a shard validator publishes to and the number of
// verified remote copies that permits pruning (bft-core#751). It is storage availability, not a consensus quorum: the writer's own archive never counts.
//
// The rule: sort the distinct peer IDs, take the next three validators after the writer in circular order (the writer excluded) as the eligible replicas, and
// require k = 2 independent verified remote copies. With exactly two other validators the policy is 2 of 2 and reports that a single outage stops progress; with
// fewer than two no policy exists. The same function is used by every consumer; explicit configuration must match it.
package archivepolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/libp2p/go-libp2p/core/peer"
)

// K is the number of independent verified remote copies that authorizes pruning. It is fixed: the policy never lowers it on a timeout or because a peer is down.
const K = 2

// MaxReplicas is the number of eligible replicas.
const MaxReplicas = 3

// Version of the policy metadata encoding.
const Version byte = 1

const domain = "M2ARCHPOLICY"

var (
	// ErrTooFewValidators: fewer than two other validators exist, so two independent remote copies are impossible.
	ErrTooFewValidators = errors.New("archivepolicy: fewer than two other validators: pruning cannot be enabled")
	ErrInvalid          = errors.New("archivepolicy: invalid policy")
	ErrVersion          = errors.New("archivepolicy: unsupported policy version")
)

// Policy is the pinned archive replica policy of one writer under one installed membership.
type Policy struct {
	Version    byte
	Writer     peer.ID
	Epoch      uint64    // the installed membership epoch the set was derived from
	Membership [32]byte  // digest of the sorted distinct validator IDs it was derived from (the writer included when it is one of them)
	Replicas   []peer.ID // two or three eligible replicas, ascending by ID bytes
	K          int
}

// sortedDistinct returns the distinct IDs in ascending byte order, dropping empty IDs.
func sortedDistinct(ids []peer.ID) []peer.ID {
	seen := make(map[peer.ID]struct{}, len(ids))
	out := make([]peer.ID, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}

// MembershipDigest is the digest of the sorted distinct validator set, as pinned in the policy.
func MembershipDigest(validators []peer.ID) [32]byte {
	h := sha256.New()
	h.Write([]byte(domain + "/membership"))
	for _, id := range sortedDistinct(validators) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(id)))
		h.Write(n[:])
		h.Write([]byte(id))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Select derives the policy of writer under the installed validator set (writer may or may not be listed). epoch is the installed membership epoch. It returns
// ErrTooFewValidators, wrapped with the count, when fewer than two other validators exist.
func Select(writer peer.ID, validators []peer.ID, epoch uint64) (Policy, error) {
	if writer == "" {
		return Policy{}, fmt.Errorf("%w: no writer", ErrInvalid)
	}
	all := sortedDistinct(validators)
	others := make([]peer.ID, 0, len(all))
	for _, id := range all {
		if id != writer {
			others = append(others, id)
		}
	}
	if len(others) < K {
		return Policy{}, fmt.Errorf("%w: %d other validators", ErrTooFewValidators, len(others))
	}
	// the first other validator after the writer in circular byte order
	start := sort.Search(len(others), func(i int) bool { return string(others[i]) > string(writer) })
	count := len(others)
	if count > MaxReplicas {
		count = MaxReplicas
	}
	chosen := make([]peer.ID, 0, count)
	for i := 0; i < count; i++ {
		chosen = append(chosen, others[(start+i)%len(others)])
	}
	sort.Slice(chosen, func(i, j int) bool { return string(chosen[i]) < string(chosen[j]) })
	p := Policy{Version: Version, Writer: writer, Epoch: epoch, Membership: MembershipDigest(validators), Replicas: chosen, K: K}
	return p, p.Validate()
}

// Validate checks the structural invariants every consumer relies on.
func (p Policy) Validate() error {
	if p.Version != Version {
		return ErrVersion
	}
	if p.Writer == "" || p.K != K || len(p.Replicas) < K || len(p.Replicas) > MaxReplicas {
		return ErrInvalid
	}
	for i, id := range p.Replicas {
		if id == "" || id == p.Writer {
			return ErrInvalid
		}
		if i > 0 && string(p.Replicas[i-1]) >= string(id) {
			return ErrInvalid // ascending and distinct
		}
	}
	return nil
}

// Tolerant reports whether one replica may be down without stopping progress. With exactly two eligible replicas it is false: a single outage stops pruning
// (and is reported so), the policy never silently lowers K.
func (p Policy) Tolerant() bool { return len(p.Replicas) > p.K }

// Eligible reports whether id is one of the policy's replicas.
func (p Policy) Eligible(id peer.ID) bool {
	for _, r := range p.Replicas {
		if r == id {
			return true
		}
	}
	return false
}

// Matches reports whether explicitly configured replicas are exactly this policy's set (in any order).
func (p Policy) Matches(configured []peer.ID) bool {
	got := sortedDistinct(configured)
	if len(got) != len(configured) || len(got) != len(p.Replicas) {
		return false
	}
	for i := range got {
		if got[i] != p.Replicas[i] {
			return false
		}
	}
	return true
}

// Encode is the canonical, versioned encoding that is persisted as the policy metadata.
func (p Policy) Encode() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(domain)
	b.WriteByte(p.Version)
	putID(&b, p.Writer)
	_ = binary.Write(&b, binary.BigEndian, p.Epoch)
	b.Write(p.Membership[:])
	b.WriteByte(byte(p.K))
	b.WriteByte(byte(len(p.Replicas)))
	for _, id := range p.Replicas {
		putID(&b, id)
	}
	sum := sha256.Sum256(b.Bytes())
	b.Write(sum[:])
	return b.Bytes(), nil
}

func putID(b *bytes.Buffer, id peer.ID) {
	_ = binary.Write(b, binary.BigEndian, uint16(len(id)))
	b.WriteString(string(id))
}

// Digest identifies the policy generation: acknowledgments and coverage records bind to it.
func (p Policy) Digest() ([32]byte, error) {
	raw, err := p.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

// Decode parses an encoded policy strictly: the checksum, the structure and the canonical re-encoding must all hold.
func Decode(raw []byte) (Policy, error) {
	if len(raw) < len(domain)+1+32 || !bytes.HasPrefix(raw, []byte(domain)) {
		return Policy{}, ErrInvalid
	}
	if raw[len(domain)] != Version {
		return Policy{}, ErrVersion
	}
	payload, sum := raw[:len(raw)-32], raw[len(raw)-32:]
	if s := sha256.Sum256(payload); !bytes.Equal(s[:], sum) {
		return Policy{}, ErrInvalid
	}
	r := bytes.NewReader(payload[len(domain)+1:])
	getID := func() (peer.ID, bool) {
		var n uint16
		if binary.Read(r, binary.BigEndian, &n) != nil || n == 0 || int(n) > r.Len() || n > 512 {
			return "", false
		}
		id := make([]byte, n)
		if _, err := r.Read(id); err != nil {
			return "", false
		}
		return peer.ID(id), true
	}
	p := Policy{Version: Version}
	var ok bool
	if p.Writer, ok = getID(); !ok {
		return Policy{}, ErrInvalid
	}
	if binary.Read(r, binary.BigEndian, &p.Epoch) != nil {
		return Policy{}, ErrInvalid
	}
	if _, err := r.Read(p.Membership[:]); err != nil {
		return Policy{}, ErrInvalid
	}
	k, err := r.ReadByte()
	if err != nil {
		return Policy{}, ErrInvalid
	}
	n, err := r.ReadByte()
	if err != nil || n > MaxReplicas {
		return Policy{}, ErrInvalid
	}
	p.K = int(k)
	for i := 0; i < int(n); i++ {
		id, ok := getID()
		if !ok {
			return Policy{}, ErrInvalid
		}
		p.Replicas = append(p.Replicas, id)
	}
	if r.Len() != 0 {
		return Policy{}, ErrInvalid
	}
	again, err := p.Encode()
	if err != nil || !bytes.Equal(again, raw) {
		return Policy{}, ErrInvalid
	}
	return p, nil
}
