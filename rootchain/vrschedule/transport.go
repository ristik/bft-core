package vrschedule

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The peer protocol /unicity/vr-handoff/1.0.0 (design section 5.3.4): only the incumbents, the current intent's successors and the K
// members are admitted; one message is at most 256 KiB, at most 64 are queued per peer, and the service holds at most 2 intents. A
// stream carries one request: a pushed message (no answer) or GetStage(intent, fromView), answered with the stage set.

const (
	ProtocolID       = "/unicity/vr-handoff/1.0.0"
	MaxMessageBytes  = 256 << 10
	MaxStageBytes    = 8 << 20
	StreamDeadline   = 10 * time.Second
	MaxQueuedPerPeer = BufferPerPeer
	// StageInterval is the least time between two GetStage answers to one peer (a stage set is up to about 1 MiB: no amplification by an
	// admitted peer asking in a loop).
	StageInterval = 2 * time.Second
)

const (
	kindPoP       = 1
	kindAssembly  = 2
	kindReadiness = 3
	kindGetStage  = 4
	kindGetSource = 5
)

// ErrWire reports a malformed exchange.
var ErrWire = errors.New("vrschedule: vr-handoff exchange malformed")

type wireMessage struct {
	_         struct{} `cbor:",toarray"`
	Kind      uint64
	PoP       *vrhandoff.PoPOffer
	Assembly  *vrhandoff.Assembly
	Readiness *vrhandoff.Readiness
	Intent    []byte
	FromView  uint64
	Result    []byte // kindGetSource: the result id whose committed source is asked for
}

// wireSource answers a GetSource: the committed source of the result when this root observed it.
type wireSource struct {
	_     struct{} `cbor:",toarray"`
	Found bool
	Entry SourceEntry
}

type wireStage struct {
	_          struct{} `cbor:",toarray"`
	PoPs       []vrhandoff.PoPOffer
	Assemblies []vrhandoff.Assembly
	Readiness  []vrhandoff.Readiness
}

func encodeMessage(m Message) ([]byte, error) {
	w := wireMessage{PoP: m.PoP, Assembly: m.Assembly, Readiness: m.Readiness}
	switch {
	case m.PoP != nil:
		w.Kind = kindPoP
	case m.Assembly != nil:
		w.Kind = kindAssembly
	case m.Readiness != nil:
		w.Kind = kindReadiness
	default:
		return nil, ErrWire
	}
	return types.Cbor.Marshal(w)
}

// Stream is the part of a libp2p stream the protocol uses.
type Stream interface {
	io.ReadWriter
	SetDeadline(time.Time) error
	CloseWrite() error
	Close() error
	Reset() error
}

// Opener opens a stream to a peer.
type Opener interface {
	CreateStream(ctx context.Context, to peer.ID, protocol string) (Stream, error)
}

type Libp2p interface {
	CreateStream(ctx context.Context, to peer.ID, protocol string) (libp2pnetwork.Stream, error)
}

type libp2pOpener struct{ host Libp2p }

// FromLibp2p is the Opener of a libp2p host.
func FromLibp2p(host Libp2p) Opener { return libp2pOpener{host} }

func (o libp2pOpener) CreateStream(ctx context.Context, to peer.ID, protocol string) (Stream, error) {
	return o.host.CreateStream(ctx, to, protocol)
}

func writeFrame(w io.Writer, b []byte) error {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], uint32(len(b)))
	if _, err := w.Write(p[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readFrame(r io.Reader, max int) ([]byte, error) {
	var p [4]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(p[:])
	if int64(n) > int64(max) {
		return nil, fmt.Errorf("%w: a frame of %d bytes", ErrWire, n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

// Server admits the peers the service names (Members) into its verification queue and answers GetStage, at most once per StageInterval
// per peer.
type Server struct {
	svc   *Service
	queue *Queue
	// allowed adds the peers the caller always admits (the installed root committee); nil admits only the service's members.
	allowed func(peer.ID) bool
	// sources answers GetSource (nil: not served)
	sources *Sources
	now     func() time.Time

	mu     sync.Mutex
	served map[peer.ID]time.Time
}

func NewServer(svc *Service, queue *Queue, allowed func(peer.ID) bool) *Server {
	return &Server{svc: svc, queue: queue, allowed: allowed, now: time.Now, served: map[peer.ID]time.Time{}}
}

// stageDue records a GetStage answer to from: false when it had one less than StageInterval ago.
// WithSources makes the server answer GetSource from the root's observed sources.
func (s *Server) WithSources(src *Sources) *Server {
	s.sources = src
	return s
}

func (s *Server) stageDue(from peer.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if t, ok := s.served[from]; ok && now.Sub(t) < StageInterval {
		return false
	}
	if len(s.served) > 256 {
		for p, t := range s.served {
			if now.Sub(t) >= StageInterval {
				delete(s.served, p)
			}
		}
	}
	s.served[from] = now
	return true
}

func (s *Server) admitted(from peer.ID) bool {
	if s.allowed != nil && s.allowed(from) {
		return true
	}
	return s.svc.Members()[from.String()]
}

func (s *Server) Handler(st libp2pnetwork.Stream) { s.Serve(st.Conn().RemotePeer(), st) }

// Serve handles one stream from a peer.
func (s *Server) Serve(from peer.ID, st Stream) {
	defer func() { _ = st.Close() }()
	if !s.admitted(from) {
		_ = st.Reset()
		return
	}
	if err := st.SetDeadline(time.Now().Add(StreamDeadline)); err != nil {
		_ = st.Reset()
		return
	}
	raw, err := readFrame(st, MaxMessageBytes)
	if err != nil {
		_ = st.Reset()
		return
	}
	var w wireMessage
	if err := types.Cbor.Unmarshal(raw, &w); err != nil {
		_ = st.Reset()
		return
	}
	switch w.Kind {
	case kindPoP, kindAssembly, kindReadiness:
		m := Message{PoP: w.PoP, Assembly: w.Assembly, Readiness: w.Readiness}
		if (w.Kind == kindPoP) != (m.PoP != nil) || (w.Kind == kindAssembly) != (m.Assembly != nil) || (w.Kind == kindReadiness) != (m.Readiness != nil) {
			_ = st.Reset()
			return
		}
		_ = s.queue.Submit(from.String(), m) // over the queue's bounds the message is dropped
	case kindGetStage:
		if len(w.Intent) != 32 || !s.stageDue(from) {
			_ = st.Reset()
			return
		}
		set, _ := s.svc.Stage([32]byte(w.Intent), w.FromView)
		b, err := types.Cbor.Marshal(wireStage{PoPs: set.PoPs, Assemblies: set.Assemblies, Readiness: set.Readiness})
		if err != nil || len(b) > MaxStageBytes {
			_ = st.Reset()
			return
		}
		_ = writeFrame(st, b)
	case kindGetSource:
		if s.sources == nil || len(w.Result) != 32 || !s.stageDue(from) {
			_ = st.Reset()
			return
		}
		e, found := s.sources.Get(vrschema.Word(w.Result))
		b, err := types.Cbor.Marshal(wireSource{Found: found, Entry: e})
		if err != nil {
			_ = st.Reset()
			return
		}
		_ = writeFrame(st, b)
	default:
		_ = st.Reset()
	}
}

// Push sends one message to every peer, best effort.
func Push(ctx context.Context, opener Opener, peers []peer.ID, m Message) error {
	b, err := encodeMessage(m)
	if err != nil {
		return err
	}
	if len(b) > MaxMessageBytes {
		return fmt.Errorf("%w: a message of %d bytes", ErrWire, len(b))
	}
	var errs []error
	for _, p := range peers {
		if err := pushOne(ctx, opener, p, b); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

func pushOne(ctx context.Context, opener Opener, p peer.ID, b []byte) error {
	ctx, cancel := context.WithTimeout(ctx, StreamDeadline)
	defer cancel()
	st, err := opener.CreateStream(ctx, p, ProtocolID)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	_ = st.SetDeadline(time.Now().Add(StreamDeadline))
	if err := writeFrame(st, b); err != nil {
		_ = st.Reset()
		return err
	}
	return st.CloseWrite()
}

// GetStage asks one peer for the stage set of intent from fromView: what a restarted root rebuilds its view state from.
func GetStage(ctx context.Context, opener Opener, p peer.ID, intent [32]byte, fromView uint64) (StageSet, error) {
	ctx, cancel := context.WithTimeout(ctx, StreamDeadline)
	defer cancel()
	st, err := opener.CreateStream(ctx, p, ProtocolID)
	if err != nil {
		return StageSet{}, err
	}
	defer func() { _ = st.Close() }()
	_ = st.SetDeadline(time.Now().Add(StreamDeadline))
	b, err := types.Cbor.Marshal(wireMessage{Kind: kindGetStage, Intent: intent[:], FromView: fromView})
	if err != nil {
		return StageSet{}, err
	}
	if err := writeFrame(st, b); err != nil {
		_ = st.Reset()
		return StageSet{}, err
	}
	if err := st.CloseWrite(); err != nil {
		return StageSet{}, err
	}
	raw, err := readFrame(st, MaxStageBytes)
	if err != nil {
		return StageSet{}, err
	}
	var w wireStage
	if err := types.Cbor.Unmarshal(raw, &w); err != nil {
		return StageSet{}, errors.Join(ErrWire, err)
	}
	return StageSet{PoPs: w.PoPs, Assemblies: w.Assemblies, Readiness: w.Readiness}, nil
}

// Offers are the messages of a stage set, in the order a service judges them (proofs, assemblies, readiness).
func (s StageSet) Offers() []Message {
	var out []Message
	for i := range s.PoPs {
		out = append(out, Message{PoP: &s.PoPs[i]})
	}
	for i := range s.Assemblies {
		out = append(out, Message{Assembly: &s.Assemblies[i]})
	}
	for i := range s.Readiness {
		out = append(out, Message{Readiness: &s.Readiness[i]})
	}
	return out
}

// GetSource asks one peer for the committed source it observed of a result (stage 0 of a handoff this root joined after its publication).
func GetSource(ctx context.Context, opener Opener, p peer.ID, result [32]byte) (SourceEntry, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, StreamDeadline)
	defer cancel()
	st, err := opener.CreateStream(ctx, p, ProtocolID)
	if err != nil {
		return SourceEntry{}, false, err
	}
	defer func() { _ = st.Close() }()
	_ = st.SetDeadline(time.Now().Add(StreamDeadline))
	b, err := types.Cbor.Marshal(wireMessage{Kind: kindGetSource, Result: result[:]})
	if err != nil {
		return SourceEntry{}, false, err
	}
	if err := writeFrame(st, b); err != nil {
		_ = st.Reset()
		return SourceEntry{}, false, err
	}
	if err := st.CloseWrite(); err != nil {
		return SourceEntry{}, false, err
	}
	raw, err := readFrame(st, MaxMessageBytes)
	if err != nil {
		return SourceEntry{}, false, err
	}
	var w wireSource
	if err := types.Cbor.Unmarshal(raw, &w); err != nil {
		return SourceEntry{}, false, errors.Join(ErrWire, err)
	}
	return w.Entry, w.Found, nil
}

// SourceFaulty is the voting weight the Byzantine roots may hold at most among incumbents of total weight total: strictly less than a third.
func SourceFaulty(total uint64) uint64 {
	if total == 0 {
		return 0
	}
	return (total - 1) / 3
}

// WeightedPeer is an incumbent root and its committed voting weight, read from one installed trust-base snapshot.
type WeightedPeer struct {
	ID     peer.ID
	Weight uint64
}

// FetchSource asks the weighted peers for the source of result and returns it once identical answers of distinct authenticated peers carry a
// combined weight strictly above SourceFaulty(total), where total is the installed committee's total weight (this root's own included when it
// is one) and the peers and total come from ONE trust-base snapshot: at least one honest root observed exactly this source, whatever the weights.
// Each peer counts once, whatever it sends; answers that differ in an attested field do not combine (the height is not attested: the returned
// entry's height must be re-derived with ResolveFetched); a peer that did not observe it, or does not answer, counts for
// nothing. Honest incumbents observed the same first Published block, so honest answers are identical (stage 0 is fixed by committed history).
func FetchSource(ctx context.Context, opener Opener, peers []WeightedPeer, result [32]byte, total uint64) (SourceEntry, error) {
	type ans struct {
		w  uint64
		e  SourceEntry
		ok bool
	}
	seen := map[peer.ID]bool{}
	var distinct []WeightedPeer
	var asked uint64
	for _, p := range peers {
		if !seen[p.ID] {
			seen[p.ID] = true
			distinct = append(distinct, p)
			asked += p.Weight
		}
	}
	total = max(total, asked)
	need := SourceFaulty(total) // the combined weight must exceed this
	res := make(chan ans, len(distinct))
	for _, p := range distinct {
		go func(p WeightedPeer) {
			e, ok, err := GetSource(ctx, opener, p.ID, result)
			res <- ans{p.Weight, e, ok && err == nil}
		}(p)
	}
	weights := map[string]uint64{}
	for range distinct {
		a := <-res
		if !a.ok || a.e.ResultID == nil || !bytes.Equal(a.e.ResultID, result[:]) {
			continue
		}
		// the peers attest the result, the certified block hash, the round, the time and the commitment; the HEIGHT is not attested (a
		// pre-fix incumbent reports the shard round, a fixed one the EVM number): answers are grouped without it and the caller derives the
		// height itself (ResolveFetched), so mixed-version replies agree
		blind := a.e
		blind.EVMBlockNumber = 0
		k, err := types.Cbor.Marshal(blind)
		if err != nil {
			continue
		}
		weights[string(k)] += a.w // one answer per distinct peer: the channel carries exactly one per peer queried
		if weights[string(k)] > need {
			return a.e, nil // its height is whatever this peer said: never used as it stands
		}
	}
	return SourceEntry{}, fmt.Errorf("%w: no identical answers above weight %d for the source of %x", ErrUnavailable, need, result[:8])
}

// ResolveFetched is the local verification of a fetched source (mixed-version rollout): the incumbents' agreement fixes the result, the
// block hash, the round and the commitment, but never the height, which a pre-fix incumbent still reports as the shard round. The height is
// re-derived by resolving the certified hash to its execution header (hash verified) and the entry is returned with that verified number.
// An unresolvable header returns the error: the source is not recorded yet and the fetch is retried.
func ResolveFetched(ctx context.Context, hr HeaderReader, e SourceEntry) (SourceEntry, error) {
	if hr == nil {
		return SourceEntry{}, errors.New("vrschedule: no header resolver: a fetched height is never trusted")
	}
	if len(e.EVMBlockHash) != 32 {
		return SourceEntry{}, errors.New("vrschedule: a fetched source without a block hash")
	}
	var h [32]byte
	copy(h[:], e.EVMBlockHash)
	n, err := hr.HeaderNumber(ctx, h)
	if err != nil {
		return SourceEntry{}, err
	}
	e.EVMBlockNumber = n
	return e, nil
}
