package b1state

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"unicode/utf8"
)

const UpdateDomain = "UNICITY_B1_UPDATE"

type Update struct {
	Network                                uint16
	RootGenesisID, ProfileHash, ParentHash [32]byte
	ExecutionChainID                       uint64
	BlockNumber, OriginEpoch, OriginRound  uint64
	OriginIdentity                         [32]byte
	PriorTipEpoch                          uint64
	OldTipEnd                              *uint64
	NewEntries                             []Entry
}

func head(b []byte, major byte, v uint64) []byte {
	switch {
	case v < 24:
		return append(b, major<<5|byte(v))
	case v <= 255:
		return append(b, major<<5|24, byte(v))
	case v <= 65535:
		return append(b, major<<5|25, byte(v>>8), byte(v))
	case v <= 0xffffffff:
		b = append(b, major<<5|26)
		return binary.BigEndian.AppendUint32(b, uint32(v))
	default:
		b = append(b, major<<5|27)
		return binary.BigEndian.AppendUint64(b, v)
	}
}
func array(b []byte, n uint64) []byte     { return head(b, 4, n) }
func uintValue(b []byte, n uint64) []byte { return head(b, 0, n) }
func textValue(b []byte, s string) []byte { return append(head(b, 3, uint64(len(s))), s...) }
func bytesValue(b, v []byte) []byte       { return append(head(b, 2, uint64(len(v))), v...) }
func optional(b []byte, v *uint64) []byte {
	if v == nil {
		return append(b, 0xf6)
	}
	return uintValue(b, *v)
}
func entryBytes(b []byte, e Entry) []byte {
	b = array(b, 9)
	b = uintValue(b, e.Epoch)
	b = uintValue(b, e.BodyKind)
	b = bytesValue(b, e.BodyID[:])
	b = bytesValue(b, e.ActivationCommitID[:])
	b = uintValue(b, e.Start)
	b = optional(b, e.End)
	b = uintValue(b, e.SigningScheme)
	b = bytesValue(b, e.SigningConfigHash[:])
	b = array(b, uint64(len(e.Members)))
	for _, m := range e.Members {
		b = array(b, 3)
		b = textValue(b, m.NodeID)
		b = bytesValue(b, m.Key[:])
		b = uintValue(b, m.Weight)
	}
	return b
}
func (u Update) Bytes() []byte {
	b := array(nil, 13)
	b = textValue(b, UpdateDomain)
	b = uintValue(b, uint64(u.Network))
	b = bytesValue(b, u.RootGenesisID[:])
	b = uintValue(b, u.ExecutionChainID)
	for _, h := range [][32]byte{u.ProfileHash, u.ParentHash} {
		b = bytesValue(b, h[:])
	}
	for _, v := range []uint64{u.BlockNumber, u.OriginEpoch, u.OriginRound} {
		b = uintValue(b, v)
	}
	b = bytesValue(b, u.OriginIdentity[:])
	b = uintValue(b, u.PriorTipEpoch)
	b = optional(b, u.OldTipEnd)
	b = array(b, uint64(len(u.NewEntries)))
	for _, e := range u.NewEntries {
		b = entryBytes(b, e)
	}
	return b
}
func (u Update) Hash() [32]byte { return sha256.Sum256(u.Bytes()) }

// wireReader is schema-directed and allocation-free during the first pass.
// It cannot recurse: the only admitted nesting is Update/entries/entry/members/member.
type wireReader struct {
	b             []byte
	pos           int
	tokens, limit uint64
	err           error
}

func (r *wireReader) readHead() (byte, uint64) {
	r.tokens++
	if r.tokens > r.limit || r.pos >= len(r.b) {
		r.err = ErrEncoding
		return 0, 0
	}
	v := r.b[r.pos]
	r.pos++
	major, ai := v>>5, v&31
	if ai < 24 {
		return major, uint64(ai)
	}
	if ai > 27 {
		r.err = ErrEncoding
		return 0, 0
	}
	n := 1 << uint(ai-24)
	if len(r.b)-r.pos < n {
		r.err = ErrEncoding
		return 0, 0
	}
	var x uint64
	for _, b := range r.b[r.pos : r.pos+n] {
		x = x<<8 | uint64(b)
	}
	r.pos += n
	if (n == 1 && x < 24) || (n == 2 && x <= 255) || (n == 4 && x <= 65535) || (n == 8 && x <= 0xffffffff) {
		r.err = ErrEncoding
	}
	return major, x
}
func (r *wireReader) arity(n uint64) {
	m, v := r.readHead()
	if m != 4 || v != n {
		r.err = ErrEncoding
	}
}
func (r *wireReader) uint() uint64 {
	m, v := r.readHead()
	if m != 0 {
		r.err = ErrEncoding
	}
	return v
}
func (r *wireReader) string(major byte, min, max uint64) []byte {
	m, n := r.readHead()
	if m != major || n < min || n > max || n > uint64(len(r.b)-r.pos) {
		r.err = ErrEncoding
		return nil
	}
	b := r.b[r.pos : r.pos+int(n)]
	r.pos += int(n)
	if major == 3 && !utf8.Valid(b) {
		r.err = ErrEncoding
	}
	return b
}
func (r *wireReader) hash() (h [32]byte) { copy(h[:], r.string(2, 32, 32)); return }
func (r *wireReader) optional(decode bool) *uint64 {
	if r.pos < len(r.b) && r.b[r.pos] == 0xf6 {
		r.tokens++
		r.pos++
		if r.tokens > r.limit {
			r.err = ErrEncoding
		}
		return nil
	}
	if !decode {
		r.uint()
		return nil
	}
	n := r.uint()
	return &n
}
func (r *wireReader) parse(k uint64, decode bool) (u Update, total uint64) {
	r.arity(13)
	if !bytes.Equal(r.string(3, uint64(len(UpdateDomain)), uint64(len(UpdateDomain))), []byte(UpdateDomain)) {
		r.err = ErrEncoding
	}
	network := r.uint()
	if network > 65535 {
		r.err = ErrEncoding
	}
	u.Network = uint16(network)
	u.RootGenesisID = r.hash()
	u.ExecutionChainID = r.uint()
	u.ProfileHash = r.hash()
	u.ParentHash = r.hash()
	u.BlockNumber = r.uint()
	u.OriginEpoch = r.uint()
	u.OriginRound = r.uint()
	u.OriginIdentity = r.hash()
	u.PriorTipEpoch = r.uint()
	u.OldTipEnd = r.optional(decode)
	m, a := r.readHead()
	if m != 4 || a > k || a > uint64(len(r.b)-r.pos) {
		r.err = ErrEncoding
		return
	}
	if decode {
		u.NewEntries = make([]Entry, 0, a)
	}
	for i := uint64(0); i < a && r.err == nil; i++ {
		start := r.pos
		r.arity(9)
		e := Entry{Epoch: r.uint(), BodyKind: r.uint()}
		e.BodyID = r.hash()
		e.ActivationCommitID = r.hash()
		e.Start = r.uint()
		e.End = r.optional(decode)
		e.SigningScheme = r.uint()
		e.SigningConfigHash = r.hash()
		m, n := r.readHead()
		if m != 4 || n == 0 || n > MaxMembers || n > uint64(len(r.b)-r.pos) {
			r.err = ErrEncoding
			return
		}
		total += n // a<=K and the profile's checked token bound also bounds 64*K
		if decode {
			e.Members = make([]Member, 0, n)
		}
		for j := uint64(0); j < n && r.err == nil; j++ {
			r.arity(3)
			id := r.string(3, 1, MaxNodeIDBytes)
			key := r.string(2, 33, 33)
			weight := r.uint()
			if decode {
				member := Member{NodeID: string(id), Weight: weight}
				copy(member.Key[:], key)
				e.Members = append(e.Members, member)
			}
		}
		if r.pos-start > MaxEntryBytes {
			r.err = ErrEncoding
		}
		if decode {
			u.NewEntries = append(u.NewEntries, e)
		}
	}
	if r.pos != len(r.b) {
		r.err = ErrEncoding
	}
	return
}

// Admit reserves the scan debit before looking inside raw, then scans without
// allocation, reserves the member debit, and only then allocates/parses points,
// hashes or validates semantics. It mirrors one execution admission charge.
func Admit(raw []byte, p Profile, budget uint64) (Update, uint64, error) {
	if err := p.Validate(); err != nil {
		return Update{}, 0, err
	}
	k, c, t, _ := p.Bounds()
	if uint64(len(raw)) > c {
		return Update{}, 0, ErrEncoding
	}
	scanGas := uint64(2000) + 16*uint64(len(raw))
	if scanGas > budget {
		return Update{}, 0, ErrBudget
	}
	r := wireReader{b: raw, limit: t}
	_, members := r.parse(k, false)
	if r.err != nil {
		return Update{}, scanGas, r.err
	}
	if members > (budget-scanGas)/1000 {
		return Update{}, scanGas, ErrBudget
	}
	gas := scanGas + 1000*members
	r = wireReader{b: raw, limit: t}
	u, _ := r.parse(k, true)
	if r.err != nil {
		return Update{}, gas, r.err
	}
	if !bytes.Equal(u.Bytes(), raw) {
		return Update{}, gas, ErrEncoding
	}
	hash, err := p.Hash()
	if err != nil {
		return Update{}, gas, err
	}
	if u.Network != p.Network || u.RootGenesisID != p.RootGenesisID || u.ExecutionChainID != p.ExecutionChainID || u.ProfileHash != hash || u.ParentHash == ([32]byte{}) || u.BlockNumber == 0 || u.OriginIdentity == ([32]byte{}) {
		return Update{}, gas, ErrBinding
	}
	for i, e := range u.NewEntries {
		if err := e.Validate(); err != nil {
			return Update{}, gas, err
		}
		if e.BodyKind == 1 || e.Epoch <= u.PriorTipEpoch || e.Start > u.OriginRound || (e.End != nil && (*e.End <= lower(u.OriginRound, p.WCert) || *e.End > u.OriginRound)) {
			return Update{}, gas, ErrInterval
		}
		if i > 0 {
			prev := u.NewEntries[i-1]
			if e.Epoch != prev.Epoch+1 || prev.End == nil || *prev.End != e.Start {
				return Update{}, gas, ErrInterval
			}
		}
	}
	if len(u.NewEntries) > 0 {
		if u.OldTipEnd == nil || *u.OldTipEnd > u.NewEntries[0].Start || (u.NewEntries[0].Epoch == u.PriorTipEpoch+1 && *u.OldTipEnd != u.NewEntries[0].Start) {
			return Update{}, gas, ErrInterval
		}
		tail := u.NewEntries[len(u.NewEntries)-1]
		if tail.End != nil || tail.Epoch != u.OriginEpoch {
			return Update{}, gas, ErrInterval
		}
	} else if u.OldTipEnd != nil || u.PriorTipEpoch != u.OriginEpoch {
		return Update{}, gas, ErrInterval
	}
	return u, gas, nil
}
