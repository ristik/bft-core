package s1ref

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// SigningConfig is Q1's authenticated signing configuration of one epoch:
// (scheme, network, fixed root-chain genesis identity G). It must come from the
// complete authenticated activation history; a missing record is never a
// legacy default. A known pre-activation epoch carries scheme 1 and zero G.
type SigningConfig struct {
	Scheme  uint64
	Network uint64
	Genesis [32]byte
}

// EpochEntry is the authenticated context of one voting epoch. A zero ViewHash
// means the epoch is unknown. Start is inclusive; End is exclusive, zero
// meaning the interval is open. Both are the actual activation boundaries,
// never the earliest eligible activation.
type EpochEntry struct {
	ViewHash   [32]byte
	SourceKind uint64
	BodyID     [32]byte
	Start      uint64
	End        uint64
	Signing    SigningConfig
}

// Context is everything the builtin takes from authenticated state, separately
// from the request bytes: network N, the per-voting-epoch entries and the
// authenticated indication of the current open epoch. In this package it is an
// injected precondition: the caller asserts it is authenticated, and nothing
// here establishes that. A Context built by a test is a simulation, not
// authority. There is no W_cert age gate and no committed-frontier ceiling:
// evidence may concern uncommitted voting rounds.
type Context struct {
	Network   uint16
	OpenEpoch uint64
	Epochs    map[uint64]EpochEntry
}

// KindRootVote is the offence kind of a root vote.
const KindRootVote = 1

// Offence is the authenticated offence context of a true verdict. Every field
// is derived only after successful authentication. For scheme 1 DomainHash and
// ConflictID are zero: the legacy signature carries no network or domain
// binding, so a scheme 1 result is historical signature verification only and
// never asserts a slashable offence. ContentB is zero for a single vote; for a
// pair ContentA and ContentB are the sorted content digests.
type Offence struct {
	Scheme     uint64
	Network    uint16
	DomainHash [32]byte
	SignerID   [32]byte
	Epoch      uint64 // voting epoch, from the authenticated VoteInfo
	Round      uint64 // voting round, from the authenticated VoteInfo
	Kind       uint64
	ConflictID [32]byte
	ContentA   [32]byte
	ContentB   [32]byte
}

// Verdict is the outcome of a well-formed call. Why is nil when Valid and
// otherwise wraps ErrInvalid. Gas is the full charge, independent of where a
// false relation failed. Offence is set exactly when Valid.
type Verdict struct {
	Valid   bool
	Why     error
	Gas     uint64
	Offence *Offence
}

// call is a structurally admitted request.
type call struct {
	view   *trustView
	ev     []*evidence
	size   uint64
	charge uint64
}

// Verify evaluates an S1 input. The error is non-nil exactly for malformed
// input (it wraps ErrMalformed). Full structural scanning of the whole request
// precedes every semantic decision, so a malformed second vote wins over a
// semantically false first one.
func Verify(in []byte, ctx *Context) (Verdict, error) {
	c, err := parse(in)
	if err != nil {
		return Verdict{}, err
	}
	return finish(c, ctx), nil
}

// Output is the successful EVM return data: abi.encode(uint256(1), bool(false))
// for a false verdict (64 bytes) and the twelve words
// (1, 1, scheme, N, domainHash, signerID, votingEpoch, votingRound, kind,
// conflictID, contentA, contentB) for a true one (384 bytes).
func Output(v Verdict) []byte {
	if !v.Valid || v.Offence == nil {
		out := make([]byte, 64)
		out[31] = outputVersion
		return out
	}
	o := v.Offence
	out := make([]byte, 384)
	word := func(i int, b []byte) { copy(out[32*i+32-len(b):32*i+32], b) }
	u64 := func(n uint64) []byte { var b [8]byte; binary.BigEndian.PutUint64(b[:], n); return b[:] }
	word(0, u64(outputVersion))
	word(1, u64(1))
	word(2, u64(o.Scheme))
	word(3, u64(uint64(o.Network)))
	word(4, o.DomainHash[:])
	word(5, o.SignerID[:])
	word(6, u64(o.Epoch))
	word(7, u64(o.Round))
	word(8, u64(o.Kind))
	word(9, o.ConflictID[:])
	word(10, o.ContentA[:])
	word(11, o.ContentB[:])
	return out
}

// Run is the EVM-facing wrapper of one builtin call with a gas limit: it
// returns the return data and the gas used, or an error with all forwarded gas
// consumed. The byte bound and the base-plus-byte charge are checked before
// scanning, the full charge (known from the structural scan alone) before
// point parsing, hashing or any signature verification.
func Run(in []byte, ctx *Context, gas uint64) (out []byte, used uint64, err error) {
	if uint64(len(in)) > MaxInputBytes {
		return nil, gas, ErrInputTooLarge
	}
	if gas < baseGas+gasPerByte*uint64(len(in)) {
		return nil, gas, ErrOutOfGas
	}
	c, err := parse(in)
	if err != nil {
		return nil, gas, err
	}
	if gas < c.charge {
		return nil, gas, ErrOutOfGas
	}
	v := finish(c, ctx)
	return Output(v), v.Gas, nil
}

type reader struct {
	b   []byte
	pos int
}

func (r *reader) left() uint64 { return uint64(len(r.b) - r.pos) }

func (r *reader) take(n uint64) ([]byte, error) {
	if n > r.left() {
		return nil, ErrTruncated
	}
	out := r.b[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return out, nil
}

func (r *reader) u32() (uint64, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return uint64(binary.BigEndian.Uint32(b)), nil
}

// parse decodes and bound-checks a whole call:
// header[4] | viewLength:u32 | TrustView | (evidenceLength:u32 | Evidence)[count].
func parse(in []byte) (*call, error) {
	if len(in) > MaxInputBytes {
		return nil, ErrInputTooLarge
	}
	if len(in) < 4 {
		return nil, ErrTruncated
	}
	if in[0] != 1 {
		return nil, ErrVersion
	}
	if in[1] != 0 {
		return nil, ErrFlags
	}
	count := int(binary.BigEndian.Uint16(in[2:4]))
	if count < 1 || count > MaxCount {
		return nil, ErrCount
	}
	r := &reader{b: in, pos: 4}
	tokens := 0

	viewLen, err := r.u32()
	if err != nil {
		return nil, err
	}
	if viewLen > MaxViewBytes {
		return nil, ErrViewTooLarge
	}
	viewRaw, err := r.take(viewLen)
	if err != nil {
		return nil, err
	}
	view, err := scanView(viewRaw, &tokens)
	if err != nil {
		return nil, fmt.Errorf("trust view: %w", err)
	}
	c := &call{view: view, size: uint64(len(in))}
	sigs := uint64(count)
	for i := 0; i < count; i++ {
		n, err := r.u32()
		if err != nil {
			return nil, err
		}
		if n > MaxEvidenceBytes {
			return nil, ErrEvidenceTooLarge
		}
		raw, err := r.take(n)
		if err != nil {
			return nil, err
		}
		e, err := scanEvidence(raw, &tokens)
		if err != nil {
			return nil, fmt.Errorf("evidence %d: %w", i, err)
		}
		if e.sealSig != nil {
			sigs++
		}
		c.ev = append(c.ev, e)
	}
	if r.left() != 0 {
		return nil, ErrTrailingBytes
	}
	c.charge = Gas(c.size, uint64(len(view.members)), sigs, uint64(count))
	return c, nil
}

// finish is everything after the structural scan. Run calls it only once the
// full charge is reserved.
func finish(c *call, ctx *Context) Verdict {
	v := Verdict{Gas: c.charge}
	off, why := evaluate(c, ctx)
	if why != nil {
		v.Why = why
		return v
	}
	v.Valid, v.Offence = true, off
	return v
}

func evaluate(c *call, ctx *Context) (*Offence, error) {
	entry, err := admit(c.view, ctx)
	if err != nil {
		return nil, err
	}
	if err := c.view.check(); err != nil {
		return nil, err
	}
	if err := c.view.decodePoints(); err != nil {
		return nil, err
	}
	facts := make([]*voteFacts, len(c.ev))
	for i, e := range c.ev {
		f, err := relation(c.view, e, ctx, entry)
		if err != nil {
			return nil, fmt.Errorf("evidence %d: %w", i, err)
		}
		facts[i] = f
	}
	if len(facts) == 1 {
		return facts[0].offence(ctx), nil
	}
	return pair(ctx, facts[0], facts[1])
}

// admit authenticates the carried view against the injected context: network,
// known epoch, view commitment, body and source kind, and a valid signing
// configuration. The view is an untrusted preimage of the context's viewHash,
// never a caller-selected authority.
func admit(view *trustView, ctx *Context) (EpochEntry, error) {
	if ctx == nil {
		return EpochEntry{}, ErrUnknownEpoch
	}
	if view.network != ctx.Network && !skipped("network") {
		return EpochEntry{}, ErrNetwork
	}
	entry, ok := ctx.Epochs[view.epoch]
	if (!ok || entry.ViewHash == [32]byte{}) && !skipped("unknown-epoch") {
		return EpochEntry{}, ErrUnknownEpoch
	}
	if entry.ViewHash != view.hash && !skipped("view-hash") {
		return EpochEntry{}, ErrViewHash
	}
	if entry.BodyID != view.bodyID && !skipped("body-id") {
		return EpochEntry{}, ErrBodyID
	}
	if entry.SourceKind != view.sourceKind && !skipped("source-kind") {
		return EpochEntry{}, ErrSourceKind
	}
	cfg := votesig.Config{Scheme: entry.Signing.Scheme, Network: entry.Signing.Network, Genesis: entry.Signing.Genesis}
	if (cfg.Validate() != nil || cfg.Network != uint64(ctx.Network)) && !skipped("signing-config") {
		return EpochEntry{}, ErrSigningConfig
	}
	return entry, nil
}

// voteFacts is what one authenticated vote contributes to the offence.
type voteFacts struct {
	scheme   uint64
	signerID [32]byte
	epoch    uint64
	round    uint64
	domain   string // Dv, scheme 2 only
	pv       []byte // the signed vote preimage, scheme 2 only
	content  [32]byte
}

func (f *voteFacts) domainHash() (h [32]byte) {
	if f.scheme == votesig.SchemeDomainBound {
		h = sha256.Sum256([]byte(f.domain))
	}
	return h
}

// conflictID is SHA256(C(["S1_CONFLICT_V1", signerID, N, Dv, epoch, round, 1])).
// It is defined for scheme 2 only; scheme 1 is zero.
func (f *voteFacts) conflictID(n uint16) (id [32]byte) {
	if f.scheme != votesig.SchemeDomainBound {
		return id
	}
	b := appendArrayHead(nil, 7)
	b = appendText(b, "S1_CONFLICT_V1")
	b = appendBytes(b, f.signerID[:])
	b = appendUint(b, uint64(n))
	b = appendText(b, f.domain)
	b = appendUint(b, f.epoch)
	b = appendUint(b, f.round)
	b = appendUint(b, KindRootVote)
	return sha256.Sum256(b)
}

func (f *voteFacts) offence(ctx *Context) *Offence {
	return &Offence{Scheme: f.scheme, Network: ctx.Network, DomainHash: f.domainHash(), SignerID: f.signerID,
		Epoch: f.epoch, Round: f.round, Kind: KindRootVote, ConflictID: f.conflictID(ctx.Network), ContentA: f.content}
}

// relation verifies one vote against the authenticated context and view. The
// epoch and round it reports come exclusively from the authenticated VoteInfo,
// never from the commit info.
func relation(view *trustView, e *evidence, ctx *Context, entry EpochEntry) (*voteFacts, error) {
	if e.epoch != view.epoch && !skipped("epoch-mismatch") {
		return nil, ErrEpochMismatch
	}
	if entry.End == 0 && view.epoch != ctx.OpenEpoch && !skipped("interval-open") {
		return nil, ErrOpenInterval
	}
	if e.round < entry.Start && !skipped("interval-start") {
		return nil, ErrBeforeStart
	}
	if entry.End != 0 && e.round >= entry.End && !skipped("interval-end") {
		return nil, ErrAfterEnd
	}
	if e.scheme != entry.Signing.Scheme && !skipped("scheme-epoch") {
		return nil, ErrSchemeEpoch
	}
	m := view.lookup(e.author)
	if m == nil && !skipped("unknown-author") {
		return nil, ErrUnknownAuthor
	}
	f := &voteFacts{scheme: e.scheme, epoch: e.epoch, round: e.round}
	if m != nil {
		f.signerID = sha256.Sum256(m.key)
	}
	var err error
	if e.scheme == votesig.SchemeLegacy {
		err = legacyRelation(m, e, f)
	} else {
		cfg := votesig.Config{Scheme: entry.Signing.Scheme, Network: entry.Signing.Network, Genesis: entry.Signing.Genesis}
		err = domainBoundRelation(m, e, cfg, ctx, f)
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

// legacyRelation is scheme 1: native RoundInfo.IsValid, RoundInfo.Hash equal to
// the commit info previous hash, and the vote signature over native
// LedgerCommitInfo.SigBytes. No domain prefix is invented and the vote is never
// reinterpreted as scheme 2. The full UnicitySeal.IsValid is not applied: a
// non-committing vote legitimately has zero seal epoch and round and no seal
// hash or signature map.
func legacyRelation(m *member, e *evidence, f *voteFacts) error {
	if e.sealSig != nil && !skipped("seal-sig-forbidden") {
		return ErrSealSigForbidden
	}
	if err := e.roundInfo.IsValid(); err != nil && !skipped("vote-info") {
		return fmt.Errorf("%w: %v", ErrVoteInfo, err)
	}
	vh, err := e.roundInfo.Hash(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVoteInfo, err)
	}
	if !bytes.Equal(vh, e.seal.PreviousHash) && !skipped("binding") {
		return ErrBinding
	}
	sigBytes, err := e.seal.SigBytes()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStatement, err)
	}
	if err := checkSignature(m, e.voteSig, sigBytes); err != nil {
		return err
	}
	f.content = sha256.Sum256(sigBytes)
	return nil
}

// domainBoundRelation is scheme 2: derive Dv, VI and VH from the context,
// require VH == PreviousHash, apply Q1's statement rules, derive PV exactly as
// votesig does and verify the vote signature over PV (and, for a committing
// vote, the seal signature over native SigBytes with the same key). The
// round, epoch, parent and commit consistency rules that the preimage encoder
// itself enforces are reported through its errors; the rules it does not
// enforce (commit network and epoch, empty seal of a non-committing vote) are
// checked here.
func domainBoundRelation(m *member, e *evidence, cfg votesig.Config, ctx *Context, f *voteFacts) error {
	vi := votesig.VoteInfo{Epoch: e.epoch, Round: e.round, Parent: e.parent, Exec: e.exec}
	vh, err := cfg.VoteInfoHash(vi)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStatement, err)
	}
	if !bytes.Equal(vh[:], e.seal.PreviousHash) && !skipped("binding") {
		return ErrBinding
	}
	committing := len(e.seal.Hash) != 0 || e.seal.RootChainRoundNumber != 0
	var commit votesig.Commit
	if committing {
		if (e.seal.NetworkID != types.NetworkID(ctx.Network) || e.seal.Epoch == 0 || e.seal.Epoch > e.epoch) && !skipped("commit-context") {
			return fmt.Errorf("%w: commit network or epoch", ErrStatement)
		}
		if e.sealSig == nil && !skipped("seal-sig-missing") {
			return ErrSealSigMissing
		}
		commit = votesig.Commit{Hash: e.seal.Hash, Round: e.seal.RootChainRoundNumber}
	} else {
		if (e.seal.Epoch != 0 || e.seal.NetworkID != 0 || e.seal.Timestamp != 0) && !skipped("noncommit-zero") {
			return fmt.Errorf("%w: non-committing vote with commit data", ErrStatement)
		}
		if e.sealSig != nil && !skipped("seal-sig-forbidden") {
			return ErrSealSigForbidden
		}
	}
	pv, err := cfg.VotePreimage(vi, commit)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStatement, err)
	}
	if err := checkSignature(m, e.voteSig, pv); err != nil {
		return err
	}
	if committing {
		sealBytes, err := e.seal.SigBytes()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrStatement, err)
		}
		if err := checkSignature(m, e.sealSig, sealBytes); err != nil {
			return err
		}
	}
	f.domain, f.pv, f.content = cfg.VoteDomain(), pv, sha256.Sum256(pv)
	return nil
}

var curveN = ethcrypto.S256().Params().N

// checkSignature canonicalizes and verifies one signature against the named
// member's key. The 64/65-byte shape and v in {0,1} were checked structurally,
// and v is discarded: identity is never recovered from it and recovery parity
// is never matched. Zero or out-of-range r, zero or high s and a wrong
// signature are false. msg is the byte string the Go verifier hashes with
// SHA-256 itself (the preimage, never a digest of it).
func checkSignature(m *member, sig, msg []byte) error {
	if len(sig) != 64 && len(sig) != 65 {
		return ErrSigInvalid // absent or unshaped signature (only reachable with a disabled check)
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	halfN := new(big.Int).Rsh(curveN, 1)
	if (r.Sign() == 0 || r.Cmp(curveN) >= 0 || s.Sign() == 0 || s.Cmp(halfN) > 0) && !skipped("sig-range") {
		return ErrSigRange
	}
	if m == nil || m.ver == nil {
		return ErrSigInvalid
	}
	work("signature")
	if err := m.ver.VerifyBytes(sig, msg); err != nil && !skipped("sig-invalid") {
		return ErrSigInvalid
	}
	return nil
}

// pair is the equivocation relation over two individually verified votes: both
// scheme 2, the same signer, network, domain, voting epoch, voting round and
// kind, and different signed preimages. Signature bytes, recovery form, author
// spelling, seal representation and delivery order never enter it; the output
// is identical in either order.
func pair(ctx *Context, a, b *voteFacts) (*Offence, error) {
	if (a.scheme != votesig.SchemeDomainBound || b.scheme != votesig.SchemeDomainBound) && !skipped("pair-scheme") {
		return nil, ErrPairScheme
	}
	if a.signerID != b.signerID && !skipped("pair-signer") {
		return nil, ErrPairSigner
	}
	if (a.domain != b.domain || a.epoch != b.epoch || a.round != b.round) && !skipped("pair-context") {
		return nil, ErrPairContext
	}
	if bytes.Equal(a.pv, b.pv) && !skipped("pair-same-statement") {
		return nil, ErrPairSameStatement
	}
	off := a.offence(ctx)
	lo, hi := a.content, b.content
	if bytes.Compare(lo[:], hi[:]) > 0 {
		lo, hi = hi, lo
	}
	off.ContentA, off.ContentB = lo, hi
	return off, nil
}
