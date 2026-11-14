package network

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	libp2pNetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/unicitynetwork/bft-core/logger"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

type (
	MsgQueue interface {
		// Len - returns message queue len
		Len() int
		// PopFront - remove and return first message from queue (queue len is reduced by 1)
		PopFront() any
	}

	SendProtocolDescription struct {
		ProtocolID string
		MsgType    any           // value of the message type of the protocol
		Timeout    time.Duration // timeout per receiver
		// Retries is how many more times a message is sent to a receiver after an attempt that did not deliver it (the stream could not be
		// opened or the message not written, mostly the Timeout running out on a loaded host), while the host is still connected to the
		// receiver. Each attempt has its own Timeout; a receiver that is not connected (down, or never reached) gets no retry.
		Retries int
	}

	ReceiveProtocolDescription struct {
		ProtocolID string
		// constructor which returns pointer to a data struct into which
		// received message can be stored
		TypeFn  func() any
		Handler libp2pNetwork.StreamHandler
		// AdmitPeer is optional. When set, it is called with the authenticated remote peer ID
		// (s.Conn().RemotePeer()) before every frame is read from a stream, so before anything is
		// decoded or enqueued, and again before each later frame on a stream that survives. A
		// rejected stream is reset and the rejection is logged at a limited rate. It must be cheap
		// and safe for concurrent use. Nil admits everyone (the default). It cannot be combined
		// with Handler, which receives the stream directly and has to do its own admission.
		AdmitPeer func(peer.ID) bool
		// RevalidatePeer is optional and meant to be used together with AdmitPeer. It is called
		// with the authenticated remote peer after a frame has been read and decoded, immediately
		// before the message is enqueued, so a peer whose admission was revoked while the handler
		// was blocked waiting for the frame is not delivered. It must be a cheap, side effect free
		// membership test (unlike AdmitPeer it must not consume a per-peer quota). A rejection
		// resets the stream like an AdmitPeer rejection. Nil does nothing.
		RevalidatePeer func(peer.ID) bool
		// when non-zero, frames with CBOR payload larger than this are rejected before
		// allocation and the payload must be consumed exactly.
		MaxFrameSize uint64
		// Ingress, with MaxFrameSize, reserves each frame's declared bytes before its payload is read and keeps the reservation
		// while the message is queued, until the consumer takes it from ReceivedChannel. Register it before ReceivedChannel is called.
		Ingress *IngressBudget
	}

	sendProtocolData struct {
		protocolID string
		timeout    time.Duration // per receiver timeout, ie when sending batch this is for each msg!
		retries    int           // more attempts per receiver after an undelivered one (SendProtocolDescription.Retries)
	}

	Observability interface {
		Tracer(name string, options ...trace.TracerOption) trace.Tracer
		Meter(name string, opts ...metric.MeterOption) metric.Meter
		Logger() *slog.Logger
	}
)

/*
LibP2PNetwork implements "unicity network" using libp2p.

Zero value is not useable, use one of the constructors to create network!
*/
type LibP2PNetwork struct {
	self          *Peer
	sendProtocols map[reflect.Type]*sendProtocolData
	receivedMsgs  chan any // messages from LibP2PNetwork sent to this peer
	tracer        trace.Tracer
	log           *slog.Logger

	// limits the log of streams rejected by a ReceiveProtocolDescription.AdmitPeer callback
	rejectLog rateLimitedLog

	// framesHook, when set (tests), observes the per dispatch certification frames cache
	framesHook func(*certificationFrames)

	// ingress are the budgets of the protocols registered with one, released as the consumer takes a message (ReceivedChannel)
	ingressMu sync.Mutex
	ingress   []*IngressBudget
	outOnce   sync.Once
	out       <-chan any
	// done is closed by Close: the forwarder stops, and everything queued or received afterwards is dropped with its reservation released
	done       chan struct{}
	closeOnce  sync.Once
	forwarding atomic.Bool // the forwarder runs (it drains on Close); otherwise Close drains

	// streamReadTimeout, when set (tests), replaces defaultStreamReadTimeout. Set before the first stream arrives, never changed afterwards.
	streamReadTimeout time.Duration

	// sendData sends one message to one receiver (sendMsg; a test seam), connected reports whether the host has a connection to the peer
	sendData  func(ctx context.Context, host *Peer, protocolID string, data []byte, receiverID peer.ID) error
	connected func(peer.ID) bool
	fault     atomic.Pointer[SendFault] // SetSendFault
}

// defaultStreamReadTimeout bounds the whole life of an incoming stream on the receiving side, from the start of its handler until the sender
// closes it (the loop in streamHandlerForProtocol waits for a next frame until the sender's Close): it is not per frame.
const defaultStreamReadTimeout = 1000 * time.Millisecond

/*
NewLibP2PNetwork creates a new libp2p network without protocols (protocols need to be
registered separately to make the network actually useful).

In case of slow consumer up to "capacity" messages are buffered, after that messages will be dropped.

Logger (log) is assumed to already have node_id attribute added, won't be added by NW component!
*/
func NewLibP2PNetwork(self *Peer, capacity uint, obs Observability) (*LibP2PNetwork, error) {
	if self == nil {
		return nil, errors.New("peer is nil")
	}

	n := &LibP2PNetwork{
		self:          self,
		sendProtocols: make(map[reflect.Type]*sendProtocolData),
		receivedMsgs:  make(chan any, capacity),
		done:          make(chan struct{}),
		tracer:        obs.Tracer("LibP2PNetwork"),
		log:           obs.Logger(),
		sendData:      sendMsg,
	}
	n.connected = func(id peer.ID) bool { return self.Network().Connectedness(id) == libp2pNetwork.Connected }
	return n, nil
}

// ReceivedChannel is the channel of received messages. Without an ingress budget it is the buffered receive queue itself, so a consumer
// sees the backlog (len) and can coalesce it. With an ingress budget registered, a forwarder hands each queued message over and releases
// its reservation once the consumer takes it, whoever the consumer is; the channel is then unbuffered.
func (n *LibP2PNetwork) ReceivedChannel() <-chan any {
	n.outOnce.Do(func() {
		n.ingressMu.Lock()
		budgets := n.ingress
		n.ingressMu.Unlock()
		if len(budgets) == 0 {
			n.out = n.receivedMsgs
			return
		}
		out := make(chan any)
		n.out = out
		n.forwarding.Store(true)
		go n.forward(out)
	})
	return n.out
}

// Send - send a single message to one or more peers asynchronously
func (n *LibP2PNetwork) Send(ctx context.Context, msg any, receivers ...peer.ID) error {
	if len(receivers) == 0 {
		return nil // no one to send message in single-node partition
		// it seems that current codebase depends on this behavior (returning nil instead of error)
		//return errors.New("at least one receiver ID must be provided")
	}

	p, f := n.sendProtocols[reflect.TypeOf(msg)]
	if !f {
		return fmt.Errorf("no protocol registered for messages of type %T", msg)
	}
	if err := n.sendAsync(ctx, p, msg, receivers); err != nil {
		return fmt.Errorf("sending message: %w", err)
	}
	return nil
}

// SendMsgs - synchronously send a collection of the same type messages to peer (method can block)
// Returns successfully when all bytes have been written to the output buffer
// If during writing, the other side closes or resets the stream, an error will be returned
// However, this does not mean application level synchronization; messages can still be lost without the sender knowing
func (n *LibP2PNetwork) SendMsgs(ctx context.Context, messages MsgQueue, receiver peer.ID) (resErr error) {
	ctx, span := n.tracer.Start(ctx, "network.SenMsgs", trace.WithAttributes(attribute.Stringer("receiver", receiver)))
	defer span.End()
	var stream libp2pNetwork.Stream
	var err error
	for messages.Len() > 0 {
		msg := messages.PopFront()
		// create a stream with first message
		if stream == nil {
			p, f := n.sendProtocols[reflect.TypeOf(msg)]
			if !f {
				return fmt.Errorf("no protocol registered for messages of type %T", msg)
			}
			stream, err = n.self.CreateStream(ctx, receiver, p.protocolID)
			if err != nil {
				return fmt.Errorf("opening p2p stream %w", err)
			}
		}
		var data []byte
		data, err = serializeMsg(msg)
		if err != nil {
			// if serialization fails, then still try to send the rest
			resErr = errors.Join(resErr, fmt.Errorf("serializing message: %w", err))
			continue
		}

		// write message
		if _, err = stream.Write(data); err != nil {
			// return error on stream write error; it is unlikely that the other side is still able to process messages
			return errors.Join(resErr, fmt.Errorf("stream write error: %w", err))
		}
	}
	return nil
}

func (n *LibP2PNetwork) sendAsync(ctx context.Context, protocol *sendProtocolData, msg any, receivers []peer.ID) error {
	ctx, span := n.tracer.Start(ctx, "LibP2PNetwork.sendAsync")
	defer span.End()

	data, err := serializeMsg(msg)
	if err != nil {
		return fmt.Errorf("serializing message: %w", err)
	}

	for _, receiver := range receivers {
		// loop-back for self-messages as libp2p would otherwise error:
		// open stream error: failed to dial: dial to self attempted
		if receiver == n.self.ID() {
			if err = n.receivedMsg(n.self.ID(), protocol.protocolID, msg); err != nil {
				// todo: this must be improved loop-back should not fail
				n.log.WarnContext(ctx, "message loop-back failed", logger.Error(err))
			}
			continue
		}
		go func(host *Peer, receiverID peer.ID) {
			ctx, span := n.tracer.Start(ctx, "LibP2PNetwork.sendAsync.func", trace.WithNewRoot(), trace.WithLinks(trace.LinkFromContext(ctx)), trace.WithAttributes(attribute.String("protocol", protocol.protocolID)))
			defer span.End()
			// network nodes
			attempts, err := n.sendWithRetries(ctx, host, protocol, data, receiverID)
			if err != nil {
				n.log.WarnContext(ctx, fmt.Sprintf("sending %s to %v (%d attempts)", protocol.protocolID, receiverID, attempts), logger.Error(err))
			}
		}(n.self, receiver)
	}
	return nil
}

// sendWithRetries sends data to the receiver, each attempt with the protocol's timeout, and again (up to protocol.retries more times) while
// an attempt did not deliver it and the host is connected to the receiver. It returns the number of attempts and the last error.
//
// The root consensus has no other repair for a lost proposal or vote, and timeout votes are repeated only every local timeout: on a loaded
// host the per-message deadline loses messages to live peers (11-30% of the timeout votes in the 128-root runs), and with exactly a quorum
// live every lost one stalls the round (#982). A retry is sent only when the stream could not be opened or the message not written, so the
// receiver did not get it; a receiver handles a repeated message as it does any duplicate. The delay before attempt k is k times 100-200 ms,
// spreading the repeats of a burst; it ends when ctx does.
func (n *LibP2PNetwork) sendWithRetries(ctx context.Context, host *Peer, protocol *sendProtocolData, data []byte, receiverID peer.ID) (int, error) {
	attempts := 0
	attempt := func() error {
		attempts++
		if f := n.fault.Load(); f != nil {
			if err := (*f)(protocol.protocolID, receiverID, attempts); err != nil {
				return err
			}
		}
		sendCtx, cancel := context.WithTimeout(ctx, protocol.timeout)
		defer cancel()
		return n.sendData(sendCtx, host, protocol.protocolID, data, receiverID)
	}
	err := attempt()
	for err != nil && attempts <= protocol.retries && errors.Is(err, ErrNotDelivered) && n.connected(receiverID) {
		delay := time.Duration(attempts) * (100*time.Millisecond + rand.N(100*time.Millisecond)) // #nosec G404 jitter, not security
		select {
		case <-ctx.Done():
			return attempts, errors.Join(err, ctx.Err())
		case <-time.After(delay):
		}
		err = attempt()
	}
	return attempts, err
}

// ErrNotDelivered marks a send whose message did not reach the receiver: the stream was not opened or the message not written.
var ErrNotDelivered = errors.New("message not delivered")

// notDelivered is a send error that is ErrNotDelivered, with the message of the error it wraps.
type notDelivered struct{ err error }

func (e notDelivered) Error() string        { return e.err.Error() }
func (e notDelivered) Unwrap() error        { return e.err }
func (e notDelivered) Is(target error) bool { return target == ErrNotDelivered }

// SendFault decides the fate of one send attempt before it is made (attempt counts from 1): a non-nil error fails the attempt with it. An
// error wrapping ErrNotDelivered is a lost message, which the network may send again; any other is final.
type SendFault func(protocolID string, receiver peer.ID, attempt int) error

// SetSendFault puts f in front of every send attempt to another peer: a fault injection point for tests of lossy links (nil removes it). It
// is never set in production.
func (n *LibP2PNetwork) SetSendFault(f SendFault) {
	if f == nil {
		n.fault.Store(nil)
		return
	}
	n.fault.Store(&f)
}

func sendMsg(ctx context.Context, host *Peer, protocolID string, data []byte, receiverID peer.ID) (err error) {
	s, err := host.CreateStream(ctx, receiverID, protocolID)
	if err != nil {
		err = fmt.Errorf("open p2p stream: %w", err)
		if lazyHandshakeRefused(err) {
			return err // the peer does not speak the protocol: a repeat would be refused too
		}
		return notDelivered{err}
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("closing p2p stream: %w", closeErr))
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err = s.SetWriteDeadline(deadline); err != nil {
			return notDelivered{fmt.Errorf("error setting write deadline: %w", err)}
		}
	}
	if _, err = s.Write(data); err != nil {
		err = fmt.Errorf("writing data to p2p stream: %w", err)
		if lazyHandshakeRefused(err) {
			return err
		}
		return notDelivered{err}
	}
	// done close the stream
	return nil
}

// rejectLogInterval is the minimum time between two log lines about rejected peers.
const rejectLogInterval = 10 * time.Second

// rateLimitedLog allows one log line per interval and counts the rest.
type rateLimitedLog struct {
	mu         sync.Mutex
	last       time.Time
	suppressed uint64
}

// allow reports whether a line may be logged now and, if so, how many were suppressed since the
// previous one.
func (l *rateLimitedLog) allow(now time.Time) (bool, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() && now.Sub(l.last) < rejectLogInterval {
		l.suppressed++
		return false, 0
	}
	l.last = now
	n := l.suppressed
	l.suppressed = 0
	return true, n
}

func (n *LibP2PNetwork) logRejectedPeer(protocolID string, from peer.ID) {
	if ok, suppressed := n.rejectLog.allow(time.Now()); ok {
		n.log.Warn(fmt.Sprintf("rejected %q stream from peer %s that is not admitted (%d similar rejections not logged)", protocolID, from, suppressed))
	}
}

/*
streamHandlerForProtocol returns libp2p stream handler for given protocolID.
The "ctor" is constructor which returns pointer to a data struct into which
incoming message can be stored.
*/
// forward hands each queued message to the consumer and releases its reservation once taken. On Close it stops: the message it holds
// and everything still queued are dropped and released, each exactly once (Delivered forgets a message it released).
func (n *LibP2PNetwork) forward(out chan<- any) {
	defer close(out)
	for {
		select {
		case <-n.done:
			n.drain()
			return
		case msg := <-n.receivedMsgs:
			select {
			case out <- msg:
				n.Delivered(msg)
			case <-n.done:
				n.Delivered(msg)
				n.drain()
				return
			}
		}
	}
}

// drain drops every queued message, releasing its reservation.
func (n *LibP2PNetwork) drain() {
	for {
		select {
		case msg := <-n.receivedMsgs:
			n.Delivered(msg)
		default:
			return
		}
	}
}

// Close stops the delivery of received messages: every message queued now or received later is dropped, with its reservation released
// under an ingress budget. It is idempotent. The consumer's channel is closed only for a network with an ingress budget, once its
// forwarder has stopped. An unbudgeted network's channel is the receive queue itself, which stream handlers may still be sending to, so it
// is never closed: its consumer stops through its own context.
func (n *LibP2PNetwork) Close() {
	n.closeOnce.Do(func() {
		close(n.done)
		if !n.forwarding.Load() {
			n.drain()
		}
	})
}

// Delivered releases the ingress reservation of a message taken from the receive queue (a no-op for other messages).
func (n *LibP2PNetwork) Delivered(msg any) {
	n.ingressMu.Lock()
	budgets := n.ingress
	n.ingressMu.Unlock()
	for _, b := range budgets {
		if b.delivered(msg) {
			return
		}
	}
}

func (n *LibP2PNetwork) streamHandlerForProtocol(protocolID string, ctor func() any, maxFrame uint64, admit, revalidate func(peer.ID) bool, ingress *IngressBudget) libp2pNetwork.StreamHandler {
	return func(s libp2pNetwork.Stream) {
		success := false
		defer func() {
			if success {
				if err := s.Close(); err != nil {
					n.log.Warn(fmt.Sprintf("closing p2p stream %q", protocolID), logger.Error(err))
				}
			} else {
				// stop writing to us, we have stopped reading
				if err := s.Reset(); err != nil {
					n.log.Warn(fmt.Sprintf("reset p2p stream %q", protocolID), logger.Error(err))
				}
			}
		}()
		// set reader timeout - node should not wait here forever
		timeout := n.streamReadTimeout
		if timeout == 0 {
			timeout = defaultStreamReadTimeout
		}
		err := s.SetReadDeadline(time.Now().Add(timeout))
		if err != nil {
			n.log.Warn(fmt.Sprintf("failed to set read deadline for stream %q", protocolID))
			return
		}
		reader := bufio.NewReader(s)
		remote := s.Conn().RemotePeer()
		for {
			// admission is decided on the authenticated peer before a frame is read, and again for
			// every later frame of a stream that survives (the stream is reset on rejection)
			if admit != nil && !admit(remote) {
				n.logRejectedPeer(protocolID, remote)
				return
			}
			msg := ctor()
			var reserved int64
			switch {
			case ingress != nil:
				var length uint64
				if length, err = readFrameLength(reader, maxFrame); err == nil {
					reserved = int64(length) /* #nosec G115 bounded by maxFrame */
					if !ingress.reserve(remote, reserved) {
						n.log.Warn(fmt.Sprintf("refusing a %d byte %q frame from %s: ingress budget exhausted", length, protocolID, remote))
						return
					}
					if err = readFramePayload(reader, msg, length); err != nil {
						ingress.release(remote, reserved)
					}
				}
			case maxFrame > 0:
				err = deserializeMsgLimited(reader, msg, maxFrame)
			default:
				err = deserializeMsg(reader, msg)
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				n.log.Warn(fmt.Sprintf("reading %q message", protocolID), logger.Error(err))
				return
			}
			// the check above ran before a possibly long wait for this frame: the peer may have been
			// revoked meanwhile, and a frame written after the revocation must not be delivered
			if revalidate != nil && !revalidate(remote) {
				if ingress != nil {
					ingress.release(remote, reserved)
				}
				n.logRejectedPeer(protocolID, remote)
				return
			}
			if ingress != nil {
				ingress.queue(msg, remote, reserved) // before it is visible to the consumer, so Delivered always finds it
			}
			if err = n.receivedMsg(s.Conn().RemotePeer(), protocolID, msg); err != nil {
				if ingress != nil {
					ingress.delivered(msg) // dropped: released
				}
				// log error, but also reset the stream to signal that node is not able to consume more messages
				n.log.Warn(fmt.Sprintf("failed to process message: %v", err))
				return
			}
		}
		success = true
	}
}

func (n *LibP2PNetwork) receivedMsg(from peer.ID, protocolID string, msg any) error {
	select {
	case <-n.done:
		return fmt.Errorf("dropping %s message from %s: the network is closed", protocolID, from)
	default:
	}
	select {
	case n.receivedMsgs <- msg:
	default:
		return fmt.Errorf("dropping %s message from %s because of slow consumer", protocolID, from)
	}
	select {
	case <-n.done: // closed while this message was being enqueued: whoever drained before it arrived missed it
		n.drain()
	default:
	}
	return nil
}

func (n *LibP2PNetwork) RegisterReceiveProtocols(protocols []ReceiveProtocolDescription) error {
	if len(protocols) == 0 {
		return errors.New("at least one protocol description must be given")
	}

	for _, p := range protocols {
		if err := n.registerReceiveProtocol(p); err != nil {
			return fmt.Errorf("registering protocol %q: %w", p.ProtocolID, err)
		}
	}

	return nil
}

func (n *LibP2PNetwork) registerReceiveProtocol(protoc ReceiveProtocolDescription) error {
	if protoc.ProtocolID == "" {
		return errors.New("protocol ID must be assigned")
	}
	if slices.Contains(n.self.host.Mux().Protocols(), protocol.ID(protoc.ProtocolID)) {
		return fmt.Errorf("protocol %q is already registered", protoc.ProtocolID)
	}

	if protoc.Handler != nil {
		if protoc.AdmitPeer != nil {
			return errors.New("peer admission can not be combined with a custom stream handler")
		}
		n.self.RegisterProtocolHandler(protoc.ProtocolID, protoc.Handler)
		return nil
	}

	if protoc.TypeFn == nil {
		return errors.New("data struct constructor or handler must be assigned")
	}
	msg := protoc.TypeFn()
	if msg == nil {
		return errors.New("data struct constructor returns nil")
	}
	switch typ := reflect.TypeOf(msg); typ.Kind() {
	case reflect.Pointer:
		if typ.Elem().Kind() != reflect.Struct {
			return fmt.Errorf("data struct constructor must return pointer to struct but returns %s", typ)
		}
		if reflect.ValueOf(msg).IsNil() {
			return fmt.Errorf("data struct constructor returns uninitialized pointer")
		}
	default:
		return fmt.Errorf("data struct constructor must return pointer to struct but returns %s", typ)
	}

	if protoc.Ingress != nil {
		if protoc.MaxFrameSize == 0 {
			return errors.New("an ingress budget needs a frame limit")
		}
		n.ingressMu.Lock()
		n.ingress = append(n.ingress, protoc.Ingress)
		n.ingressMu.Unlock()
	}
	n.self.RegisterProtocolHandler(protoc.ProtocolID, n.streamHandlerForProtocol(protoc.ProtocolID, protoc.TypeFn, protoc.MaxFrameSize, protoc.AdmitPeer, protoc.RevalidatePeer, protoc.Ingress))
	return nil
}

/*
RegisterSendProtocols allows to register multiple send protocols with single call.
It calls "registerSendProtocol" for each element in the "protocols" parameter.
*/
func (n *LibP2PNetwork) RegisterSendProtocols(protocols []SendProtocolDescription) error {
	if len(protocols) == 0 {
		return errors.New("at least one protocol description must be given")
	}

	for _, pd := range protocols {
		if err := n.registerSendProtocol(pd); err != nil {
			return fmt.Errorf("registering protocol %q: %w", pd.ProtocolID, err)
		}
	}
	return nil
}

func (n *LibP2PNetwork) registerSendProtocol(protocol SendProtocolDescription) error {
	if protocol.ProtocolID == "" {
		return errors.New("protocol ID must be assigned")
	}

	if protocol.Timeout < 0 {
		return fmt.Errorf("negative duration is not allowed for timeout, got %s for %s", protocol.Timeout, protocol.ProtocolID)
	}

	typ := reflect.TypeOf(protocol.MsgType)
	if typ == nil {
		return errors.New("message data type must be assigned")
	}
	if typ.Kind() != reflect.Struct {
		return fmt.Errorf("message data type must be struct, got %T", protocol.MsgType)
	}

	if spd, ok := n.sendProtocols[typ]; ok {
		return fmt.Errorf("data type %s has been already registered for protocol %s", typ, spd.protocolID)
	}

	if protocol.Retries < 0 {
		return fmt.Errorf("negative retry count is not allowed, got %d for %s", protocol.Retries, protocol.ProtocolID)
	}
	spx := &sendProtocolData{protocolID: protocol.ProtocolID, timeout: protocol.Timeout, retries: protocol.Retries}
	n.sendProtocols[typ] = spx
	n.sendProtocols[reflect.PointerTo(typ)] = spx
	return nil
}
