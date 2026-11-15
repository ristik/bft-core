package network

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	libp2pprotocol "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/routing"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	ma "github.com/multiformats/go-multiaddr"
	msmux "github.com/multiformats/go-multistream"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	defaultAddress                    = "/ip4/0.0.0.0/tcp/0"
	dhtProtocolPrefix                 = "/ab/dht/0.1.0"
	defaultBootstrapConnectRetry      = 0
	defaultBootstrapConnectRetryDelay = 1
)

var (
	ErrPeerConfigurationIsNil = errors.New("peer configuration is nil")
)

type (
	// PeerConfiguration includes single peer configuration values.
	PeerConfiguration struct {
		ID                    peer.ID         // peer identifier derived from the KeyPair.PublicKey.
		Address               string          // address to listen for incoming connections. Uses libp2p multiaddress format.
		AnnounceAddrs         []ma.Multiaddr  // callback addresses to announce to other peers, if specified then overwrites any and all default listen addresses
		KeyPair               *PeerKeyPair    // keypair for the peer.
		BootstrapPeers        []peer.AddrInfo // a list of seed peers to connect to.
		BootstrapConnectRetry *BootstrapConnectRetry
		// Gater, when set, gates every connection (see RoleGater).
		Gater *RoleGater
	}

	// BootstrapConnectRetry contains the number of times to retry connecting to bootstrap peers and the delay between retries.
	BootstrapConnectRetry struct {
		Count int // number of times to retry connecting to bootstrap peers
		Delay int // delay in seconds
	}

	// PeerKeyPair contains node's public and private key.
	PeerKeyPair struct {
		PublicKey  []byte
		PrivateKey []byte // #nosec G117
	}

	// Peer represents a single node in p2p network. It is a wrapper around the libp2p host.Host.
	Peer struct {
		host host.Host
		conf *PeerConfiguration
		dht  *dht.IpfsDHT

		// memberDials is the host-wide budget of member dials (MaxMemberDials), shared by every MemberProtector of this peer
		memberDialsOnce sync.Once
		memberDials     chan struct{}
	}
)

// NewPeer constructs a new peer node with given configuration. If no peer key is provided, it generates a random
// Secp256k1 key-pair and derives a new identity from it. If no transport and listen addresses are provided, the node
// listens to the multiaddresses "/ip4/0.0.0.0/tcp/0".
func NewPeer(ctx context.Context, conf *PeerConfiguration, log *slog.Logger, prom prometheus.Registerer) (*Peer, error) {
	return newPeer(ctx, conf, log, prom)
}

// newPeer is NewPeer with additional libp2p options (tests).
func newPeer(ctx context.Context, conf *PeerConfiguration, log *slog.Logger, prom prometheus.Registerer, extra ...config.Option) (*Peer, error) {
	if conf == nil {
		return nil, ErrPeerConfigurationIsNil
	}
	// keys
	privateKey, _, err := readKeyPair(conf)
	if err != nil {
		return nil, err
	}

	// address
	address := defaultAddress
	if conf.Address != "" {
		address = conf.Address
	}

	// create a new peerstore
	peerStore, err := newPeerStore()
	if err != nil {
		return nil, err
	}

	var kademliaDHT *dht.IpfsDHT

	opts := []config.Option{
		libp2p.ListenAddrStrings(address),
		libp2p.Identity(privateKey),
		libp2p.Peerstore(peerStore),
		// Let this host use the DHT to find other hosts
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			kademliaDHT, err = newDHT(ctx, h, conf.BootstrapPeers, dht.ModeServer, log)
			return kademliaDHT, err
		}),

		libp2p.Ping(true), // make sure ping service is enabled
	}
	if prom != nil {
		opts = append(opts, libp2p.PrometheusRegisterer(prom))
	}
	if len(conf.AnnounceAddrs) > 0 {
		addrsFactory := libp2p.AddrsFactory(func(_ []ma.Multiaddr) []ma.Multiaddr {
			// completely overwrite default announce addresses with provided values
			// and make a defensive copy, consumers can modify the slice elements
			res := make([]ma.Multiaddr, len(conf.AnnounceAddrs))
			copy(res, conf.AnnounceAddrs)
			return res
		})
		opts = append(opts, addrsFactory)
	}
	if conf.Gater != nil {
		opts = append(opts, libp2p.ConnectionGater(conf.Gater))
	}
	opts = append(opts, extra...)
	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}
	if err = kademliaDHT.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrapping DHT: %w", err)
	}
	log.DebugContext(ctx, fmt.Sprintf("addresses=%v; bootstrap peers=%v", h.Addrs(), conf.BootstrapPeers))

	return &Peer{
		host: h,
		conf: conf,
		dht:  kademliaDHT,
	}, nil
}

// bootstrapPeers filters out the self peer from the list of bootnodes.
// This is necessary because we don't want to attempt to connect to self.
func bootstrapPeers(bootnodes []peer.AddrInfo, self peer.ID) []peer.AddrInfo {
	var filtered []peer.AddrInfo
	for _, bootnode := range bootnodes {
		if bootnode.ID != self {
			filtered = append(filtered, bootnode)
		}
	}
	return filtered
}

func isBootnode(peerID peer.ID, bootNodes []peer.AddrInfo) bool {
	for _, peerAddr := range bootNodes {
		if peerID == peerAddr.ID {
			return true
		}
	}
	return false
}

// This code is borrowed from the go-ipfs bootstrap process
func (p *Peer) BootstrapConnect(ctx context.Context, log *slog.Logger) error {
	bootstrapPeers := bootstrapPeers(p.conf.BootstrapPeers, p.host.ID())
	if len(bootstrapPeers) == 0 {
		return nil
	}
	isBootnode := isBootnode(p.host.ID(), p.conf.BootstrapPeers)

	errs := make(chan error, len(bootstrapPeers))
	var wg sync.WaitGroup
	for _, peerAddr := range bootstrapPeers {
		// performed asynchronously because when performed synchronously, if
		// one `Connect` call hangs, subsequent calls are more likely to
		// fail/abort due to an expiring context.
		// Also, performed asynchronously for dial speed.
		wg.Add(1)
		go func(peerAddr peer.AddrInfo) {
			defer wg.Done()
			p.host.Peerstore().AddAddrs(peerAddr.ID, peerAddr.Addrs, peerstore.PermanentAddrTTL)

			countdown := p.conf.BootstrapConnectRetry.Count
			if countdown < 0 {
				countdown = int(^uint(0) >> 1) // Set to maximum value of int
			}
			if isBootnode {
				countdown = 0
			}
			retryDelay := time.Duration(p.conf.BootstrapConnectRetry.Delay) * time.Second

			for ; ; countdown-- {
				err := p.host.Connect(ctx, peerAddr)
				if err == nil {
					log.DebugContext(ctx, fmt.Sprintf("Bootstrap dial %s to %s: success", p.host.ID(), peerAddr.ID))
					return
				}
				if countdown <= 0 {
					log.WarnContext(ctx, fmt.Sprintf("Bootstrap dial %s to %s failed: %s", p.host.ID(), peerAddr.ID, err))
					errs <- err
					return
				}
				log.DebugContext(ctx, fmt.Sprintf("Bootstrap dial %s to %s failed: %s, retry in %s", p.host.ID(), peerAddr.ID, err, retryDelay))
				select {
				case <-time.After(retryDelay):
					continue
				case <-ctx.Done():
					return
				}
			}

		}(peerAddr)
	}
	wg.Wait()

	// our failure condition is when no connection attempt succeeded.
	// So drain the errs channel, counting the results.
	close(errs)
	count := 0
	var allErr error
	for err := range errs {
		if err != nil {
			count++
			allErr = errors.Join(allErr, err)
		}
	}
	if count == len(bootstrapPeers) {
		err := fmt.Errorf("failed to bootstrap: %w", allErr)
		if isBootnode {
			log.DebugContext(ctx, fmt.Sprintf("Failed to dial other bootnodes: %s", err))
			return nil
		}
		return err
	}
	return p.dht.Bootstrap(ctx)
}

// ID returns the identifier associated with this Peer.
func (p *Peer) ID() peer.ID {
	return p.host.ID()
}

// String returns short representation of node id
func (p *Peer) String() string {
	id := p.ID().String()
	if len(id) <= 10 {
		return fmt.Sprintf("NodeID:%s", id)
	}
	return fmt.Sprintf("NodeID:%s*%s", id[:2], id[len(id)-6:])
}

// MultiAddresses the address associated with this Peer.
func (p *Peer) MultiAddresses() []ma.Multiaddr {
	return p.host.Addrs()
}

// Network returns the Network of the Peer.
func (p *Peer) Network() network.Network {
	return p.host.Network()
}

// RegisterProtocolHandler sets the protocol stream handler for given protocol.
func (p *Peer) RegisterProtocolHandler(protocolID string, handler network.StreamHandler) {
	gater := p.gater()
	if gater == nil {
		p.host.SetStreamHandler(libp2pprotocol.ID(protocolID), handler)
		return
	}
	p.host.SetStreamHandler(libp2pprotocol.ID(protocolID), func(s network.Stream) {
		if gater.denied(s.Conn().RemotePeer()) { // a stream over a connection opened before the role changed
			_ = s.Reset()
			return
		}
		handler(s)
	})
}

// MemberProtector keeps one set of member peers warm (phase 2): connected, and protected from the connection manager's trimming under its
// tag, so that the channels a node will use the moment it becomes active are open before it needs them. Set replaces the whole set
// (astra on #1054): the peers it drops are unprotected at once, connected or not; the peers it keeps or adds are protected at once, by
// ID, and dialled in the background. Protection is changed only inside Set, under its lock, so a warm-up of an earlier set, which Set
// also cancels, can never re-protect a peer the current set dropped. A peer the role gater denies is neither protected nor dialled.
type MemberProtector struct {
	p         *Peer
	tag       string
	mu        sync.Mutex
	protected map[peer.ID]struct{}
	cancel    context.CancelFunc

	// the dialling of Set's warm-up and of Maintain, shared (#1082, astra on #1088): one dial per member at a time, a per-host budget of
	// concurrent dials, and each member's retry state, reset by a successful dial and by Set (an authenticated change of the set)
	dialMu      sync.Mutex
	inflight    map[peer.ID]bool
	retry       map[peer.ID]*memberRetry
	windowStart time.Time
	connect     func(ctx context.Context, ai peer.AddrInfo) error // the host's Connect; a test replaces it
}

type memberRetry struct {
	failures int
	next     time.Time
}

// MaxMemberDials is the host-wide bound on concurrent member dials: every MemberProtector of one Peer (a shard node keeps two) shares it,
// Set's warm-up and Maintain alike. MemberDialTimeout bounds one of
// Set's warm-up dials (Maintain's are bounded by its own configuration).
const (
	MaxMemberDials    = 16
	MemberDialTimeout = 5 * time.Second
)

// NewMemberProtector is a protector of the member set under tag.
func (p *Peer) NewMemberProtector(tag string) *MemberProtector {
	return &MemberProtector{p: p, tag: tag, protected: map[peer.ID]struct{}{}, inflight: map[peer.ID]bool{}, retry: map[peer.ID]*memberRetry{},
		windowStart: time.Now(), connect: p.host.Connect}
}

// Set makes ids the protected, warmed member set. A dial runs at most until ctx ends or the next Set. A new set restarts the members'
// retry state and Maintain's rapid-reconnect window.
func (m *MemberProtector) Set(ctx context.Context, ids []peer.ID) {
	cm := m.p.host.ConnManager()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel() // a superseded warm-up stops dialling
	}
	want := make(map[peer.ID]struct{}, len(ids))
	for _, id := range ids {
		if id == m.p.host.ID() || m.p.gater().denied(id) {
			continue
		}
		want[id] = struct{}{}
	}
	for id := range m.protected {
		if _, keep := want[id]; !keep {
			cm.Unprotect(id, m.tag)
			delete(m.protected, id)
		}
	}
	var dial []peer.ID
	for id := range want {
		if _, had := m.protected[id]; !had {
			cm.Protect(id, m.tag)
			m.protected[id] = struct{}{}
		}
		if len(m.p.host.Network().ConnsToPeer(id)) == 0 {
			dial = append(dial, id)
		}
	}
	m.dialMu.Lock()
	m.retry, m.windowStart = map[peer.ID]*memberRetry{}, time.Now()
	m.dialMu.Unlock()
	warm, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	// the warm-up of every member, drained through the host's budget: a member waits for a free slot, never dropped (astra on #1088 r2).
	// A superseding Set or the end of ctx cancels warm, which stops the drain and every dial of this warm-up still in flight.
	go func() {
		for _, id := range dial {
			if warm.Err() != nil {
				return
			}
			if m.p.host.Network().Connectedness(id) == network.Connected {
				continue
			}
			m.startDial(warm, id, nil)
		}
	}()
}

// memberDialSlots is the peer's host-wide member dial budget.
func (p *Peer) memberDialSlots() chan struct{} {
	p.memberDialsOnce.Do(func() { p.memberDials = make(chan struct{}, MaxMemberDials) })
	return p.memberDials
}

// MaintainConfig paces Maintain.
type MaintainConfig struct {
	// Interval is the tick; inside RapidWindow (from the start, or the last Set) a member is retried every tick.
	Interval    time.Duration
	RapidWindow time.Duration
	// BackoffMax caps the exponential backoff after the window (Interval doubled per failure, with jitter of +-50%).
	BackoffMax time.Duration
	// DialTimeout bounds one dial; PerTick is how many dials one tick may start (with MaxMemberDials in flight at most).
	DialTimeout time.Duration
	PerTick     int
}

// Maintain keeps the protected set connected until ctx ends (#1082): it dials each protected member it holds no connection to, one dial
// per member at a time, within the host's dial budget. It is the outbound half of reaching a member that cannot be dialled: a node
// behind NAT or an isolated bridge dials the others itself, and they reach it over that connection (libp2p opens a stream on any existing
// connection, whichever side dialled it). Inside the rapid window (the handoff: every root has just restarted) a member is retried every
// tick, past the swarm's per-address dial backoff, which would otherwise hold a just-restarted member unreachable for 5 s and more; after
// it, a member that keeps failing is retried with capped exponential backoff and jitter. A successful dial resets its state.
func (m *MemberProtector) Maintain(ctx context.Context, cfg MaintainConfig) {
	if cfg.Interval <= 0 {
		cfg.Interval = 250 * time.Millisecond
	}
	if cfg.PerTick <= 0 {
		cfg.PerTick = MaxMemberDials
	}
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		now := time.Now()
		started := 0
		missing := m.Disconnected()
		rand.Shuffle(len(missing), func(i, j int) { missing[i], missing[j] = missing[j], missing[i] })
		for _, id := range missing {
			if started >= cfg.PerTick {
				break
			}
			m.dialMu.Lock()
			st := m.retry[id]
			due := st == nil || !now.Before(st.next)
			m.dialMu.Unlock()
			if due && m.startDial(ctx, id, &cfg) {
				started++
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// startDial dials id in the background unless a dial of it is in flight; it reports whether it started one. pace is Maintain's (a
// forced, bounded dial; a failure schedules the member's next attempt, and a spent budget skips the member until a later tick); nil is
// Set's warm-up (an ordinary bounded dial, which waits for a free slot of the budget until ctx ends).
func (m *MemberProtector) startDial(ctx context.Context, id peer.ID, pace *MaintainConfig) bool {
	slots := m.p.memberDialSlots()
	m.dialMu.Lock()
	busy := m.inflight[id]
	m.dialMu.Unlock()
	if busy {
		return false
	}
	if pace != nil {
		select {
		case slots <- struct{}{}:
		default:
			return false
		}
	} else {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return false
		}
	}
	m.dialMu.Lock()
	if m.inflight[id] { // another dial of it started while this one waited for its slot
		m.dialMu.Unlock()
		<-slots
		return false
	}
	m.inflight[id] = true
	connect := m.connect
	m.dialMu.Unlock()
	go func() {
		defer func() { <-slots }()
		dial, timeout := ctx, MemberDialTimeout
		if pace != nil {
			dial = network.WithForceDirectDial(dial, "committee member")
			if pace.DialTimeout > 0 {
				timeout = pace.DialTimeout
			}
		}
		dial, cancel := context.WithTimeout(dial, timeout)
		defer cancel()
		err := connect(dial, peer.AddrInfo{ID: id, Addrs: m.p.host.Peerstore().Addrs(id)})
		m.dialMu.Lock()
		defer m.dialMu.Unlock()
		delete(m.inflight, id)
		if err == nil {
			delete(m.retry, id)
			return
		}
		if pace == nil {
			return // Set's warm-up: Maintain owns the retry schedule
		}
		st := m.retry[id]
		if st == nil {
			st = &memberRetry{}
			m.retry[id] = st
		}
		st.failures++
		delay := pace.Interval
		if time.Since(m.windowStart) >= pace.RapidWindow {
			delay = pace.Interval << min(st.failures, 16)
			if pace.BackoffMax > 0 && delay > pace.BackoffMax {
				delay = pace.BackoffMax
			}
			delay = delay/2 + time.Duration(rand.Int64N(int64(delay)+1)) // +-50% jitter
		}
		st.next = time.Now().Add(delay)
	}()
	return true
}

// Disconnected is the protected members this node holds no connection to.
func (m *MemberProtector) Disconnected() []peer.ID {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []peer.ID
	for id := range m.protected {
		if m.p.host.Network().Connectedness(id) != network.Connected {
			out = append(out, id)
		}
	}
	return out
}

// Protected is the member set currently protected (for status and tests).
func (m *MemberProtector) Protected() []peer.ID {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]peer.ID, 0, len(m.protected))
	for id := range m.protected {
		out = append(out, id)
	}
	return out
}

// gater is the configured role gater, nil without one (or without a configuration, as some tests build a Peer).
func (p *Peer) gater() *RoleGater {
	if p.conf == nil {
		return nil
	}
	return p.conf.Gater
}

// RevokeDenied closes every open connection to a peer the gater now denies (a role change or a newly learned root). New connections and
// streams are refused by the gater itself; this ends the ones that already exist.
func (p *Peer) RevokeDenied() int {
	gater := p.gater()
	if gater == nil {
		return 0
	}
	closed := 0
	for _, id := range p.host.Network().Peers() {
		if gater.denied(id) {
			_ = p.host.Network().ClosePeer(id)
			closed++
		}
	}
	return closed
}

// RemoveProtocolHandler removes the given protocol handler.
func (p *Peer) RemoveProtocolHandler(protocolID string) {
	p.host.RemoveStreamHandler(libp2pprotocol.ID(protocolID))
}

// CreateStream opens a new stream to given peer p, and writes a libp2p protocol header with given ProtocolID.
func (p *Peer) CreateStream(ctx context.Context, peerID peer.ID, protocolID string) (network.Stream, error) {
	if p.gater().denied(peerID) {
		return nil, ErrGated
	}
	return p.host.NewStream(ctx, peerID, libp2pprotocol.ID(protocolID))
}

// CreateStreamPreferred opens a new stream to given peer for the first of the protocols (in the order
// of preference) which the peer announced via identify on its current connection. It waits for identify
// but not for the remote end: the multistream header is sent together with the first payload write, so
// there is no negotiation round trip before the payload. Only if the peer announced none of the
// protocols does libp2p negotiate explicitly. The chosen protocol is available via stream.Protocol()
// before the first write. A refusal of the protocol is reported by Read (see lazyHandshakeRefused).
func (p *Peer) CreateStreamPreferred(ctx context.Context, peerID peer.ID, protocolIDs ...string) (network.Stream, error) {
	if len(protocolIDs) == 0 {
		return nil, errors.New("at least one protocol must be offered")
	}
	if p.gater().denied(peerID) {
		return nil, ErrGated
	}
	ids := make([]libp2pprotocol.ID, len(protocolIDs))
	for i, id := range protocolIDs {
		ids[i] = libp2pprotocol.ID(id)
	}
	return p.host.NewStream(ctx, peerID, ids...)
}

// lazyHandshakeRefused returns true if err tells that the remote end refused the protocol of a stream
// opened by the lazy path of host.NewStream.
func lazyHandshakeRefused(err error) bool {
	return errors.Is(err, msmux.ErrNotSupported[libp2pprotocol.ID]{})
}

// Configuration returns peer configuration
func (p *Peer) Configuration() *PeerConfiguration {
	return p.conf
}

// Close shuts down the libp2p host and related services.
func (p *Peer) Close() error {
	var err error
	if cerr := p.dht.Close(); cerr != nil {
		err = fmt.Errorf("closing the DHT: %w", cerr)
	}
	// close libp2p host
	if cerr := p.host.Close(); cerr != nil {
		err = errors.Join(err, fmt.Errorf("closing the host: %w", cerr))
	}
	return err
}

func (p *Peer) Advertise(ctx context.Context, topic string) error {
	routingDiscovery := drouting.NewRoutingDiscovery(p.dht)
	_, err := routingDiscovery.Advertise(ctx, topic)
	return err
}

func (p *Peer) Discover(ctx context.Context, topic string) (<-chan peer.AddrInfo, error) {
	routingDiscovery := drouting.NewRoutingDiscovery(p.dht)
	return routingDiscovery.FindPeers(ctx, topic)
}

func NewPeerConfiguration(
	addr string,
	announceAddrs []string,
	keyPair *PeerKeyPair,
	bootstrapPeers []peer.AddrInfo,
	bootstrapConnectRetry *BootstrapConnectRetry,
) (*PeerConfiguration, error) {

	if keyPair == nil {
		return nil, fmt.Errorf("missing key pair")
	}

	peerID, err := NodeIDFromPublicKeyBytes(keyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid key pair: %w", err)
	}

	var announceMultiAddrs []ma.Multiaddr
	for _, announceAddr := range announceAddrs {
		announceMultiAddr, err := ma.NewMultiaddr(announceAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert announce address '%s' to libp2p multiaddress format: %w", announceAddr, err)
		}
		announceMultiAddrs = append(announceMultiAddrs, announceMultiAddr)
	}

	if bootstrapConnectRetry == nil {
		bootstrapConnectRetry = &BootstrapConnectRetry{
			Count: defaultBootstrapConnectRetry,
			Delay: defaultBootstrapConnectRetryDelay,
		}
	}

	return &PeerConfiguration{
		ID:                    peerID,
		Address:               addr,
		AnnounceAddrs:         announceMultiAddrs,
		KeyPair:               keyPair,
		BootstrapPeers:        bootstrapPeers,
		BootstrapConnectRetry: bootstrapConnectRetry,
	}, nil
}

func NodeIDFromPublicKeyBytes(pubKey []byte) (peer.ID, error) {
	pub, err := crypto.UnmarshalSecp256k1PublicKey(pubKey)
	if err != nil {
		return "", err
	}
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return "", err
	}
	return id, nil
}

func newDHT(ctx context.Context, h host.Host, bootstrapPeers []peer.AddrInfo, opt dht.ModeOpt, log *slog.Logger) (*dht.IpfsDHT, error) {
	kdht, err := dht.New(ctx, h, dht.ProtocolPrefix(dhtProtocolPrefix), dht.BootstrapPeers(bootstrapPeers...), dht.Mode(opt))
	if err != nil {
		return nil, fmt.Errorf("creating DHT: %w", err)
	}
	routingTable := kdht.RoutingTable()
	peerRemovedCb := routingTable.PeerRemoved
	peerAddedCb := routingTable.PeerAdded
	routingTable.PeerRemoved = func(pid peer.ID) {
		peerRemovedCb(pid)
		log.DebugContext(ctx, fmt.Sprintf("peer %s removed from routing table", pid.String()))
		// meter routing table size? -> decrease
	}
	routingTable.PeerAdded = func(pid peer.ID) {
		peerAddedCb(pid)
		log.DebugContext(ctx, fmt.Sprintf("peer %s added to routing table", pid.String()))
		// meter routing table size? -> increase?
	}
	return kdht, nil
}

func newPeerStore() (peerstore.Peerstore, error) {
	peerStore, err := pstoremem.NewPeerstore()
	if err != nil {
		return nil, err
	}
	return peerStore, nil
}

func readKeyPair(conf *PeerConfiguration) (privateKey crypto.PrivKey, publicKey crypto.PubKey, err error) {
	if conf.KeyPair == nil {
		return nil, nil, fmt.Errorf("missing peer key")
	}

	privateKey, err = crypto.UnmarshalSecp256k1PrivateKey(conf.KeyPair.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid private key: %w", err)
	}
	publicKey, err = crypto.UnmarshalSecp256k1PublicKey(conf.KeyPair.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public key: %w", err)
	}
	return privateKey, publicKey, nil
}
