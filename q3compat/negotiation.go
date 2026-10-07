// Package q3compat is the compatibility layer of the Q3 upgrade: authenticated protocol negotiation, so that a peer without the
// Q3 protocol fails closed, and candidate-bound readiness, so that no successor candidate is proposed unless every successor
// validator entity has checked its own BFT node, its delegated shard/authority service and its paired execution client.
//
// It is inactive: no production package imports it. Neither a hello nor a capability report authenticates history. They say
// what a peer or a client claims to run, bound to a key and a session; the authority for a configuration remains the verified
// q3format.History, and a report is never an input to it.
package q3compat

import (
	"bytes"
	"errors"
	"fmt"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	// ErrLegacyPeer is returned for a peer that offers no Q3 hello: it speaks the existing handshake, which carries only the
	// partition, shard and node id (network/protocol/handshake) and is checked for membership alone (rootchain/node.go).
	ErrLegacyPeer = errors.New("q3compat: peer offers no Q3 hello")
	// ErrProtocol is returned for a hello naming a protocol other than the required one.
	ErrProtocol = errors.New("q3compat: peer does not run the required protocol")
	// ErrChain is returned for a hello bound to another network or root genesis.
	ErrChain = errors.New("q3compat: peer is bound to another network or genesis")
	// ErrRole is returned for a hello whose role is not the one the connection is for.
	ErrRole = errors.New("q3compat: unexpected peer role")
	// ErrUnknownPeer is returned when no role key is configured for the hello's node.
	ErrUnknownPeer = errors.New("q3compat: no configured key for the peer")
	// ErrHelloSignature is returned when the hello is not signed, for this session, by the configured role key.
	ErrHelloSignature = errors.New("q3compat: invalid hello signature")
	// ErrConfiguration is returned when the peer's installed epoch, body or activation is neither ours nor a verified past one.
	ErrConfiguration = errors.New("q3compat: peer's installed configuration is not ours")
)

const (
	// HelloVersion is the version of the hello encoding.
	HelloVersion = 1
	helloDomain  = "UNICITY_Q3_HELLO_V1"
	maxHello     = 1 << 10
	maxText      = 64
	maxSig       = 128
	// ProtocolRootHello and ProtocolShardHello are the new live-protocol ids the hello is exchanged on. They are not registered
	// anywhere in this slice; the integration slice registers them and stops routing live traffic on the legacy ids.
	ProtocolRootHello  = "/ab/q3-root-hello/1.0.0"
	ProtocolShardHello = "/ab/q3-shard-hello/1.0.0"
)

// Role is which service a hello speaks for. Each role has its own configured key.
type Role uint64

const (
	RoleRoot Role = iota + 1
	RoleShard
	RoleAuthority
)

// Identity is the installed configuration a peer claims: epoch, V3 body, activation record and protocol tuple.
type Identity struct {
	Epoch                        uint64
	BodyID, ActivationID, Config [32]byte
}

// Hello is one side's authenticated statement of what it runs. The signature covers the verifier's challenge and both
// transport identities as well, so a hello cannot be replayed on another session or relayed to a third party.
type Hello struct {
	_            struct{} `cbor:",toarray"`
	Version      uint64
	Role         Role
	Network      uint64
	Genesis      []byte
	Protocol     string
	Epoch        uint64
	BodyID       []byte
	ActivationID []byte
	Config       []byte
	NodeID       string
	Signature    []byte
}

// Session is what a signature is bound to besides the hello: the challenge the verifier issued and both transport identities.
type Session struct {
	Challenge        []byte
	Signer, Verifier string // transport (peer) identities of the hello's sender and of the party verifying it
}

func (h Hello) message(s Session) []byte {
	b, err := types.Cbor.Marshal([]any{helloDomain, h.Version, uint64(h.Role), h.Network, h.Genesis, h.Protocol, h.Epoch, h.BodyID,
		h.ActivationID, h.Config, h.NodeID, s.Challenge, s.Signer, s.Verifier})
	if err != nil {
		panic(fmt.Sprintf("q3compat: encoding hello message: %v", err)) // fixed kinds; never input-dependent
	}
	return b
}

// NewHello signs the statement that role runs protocol at id, for session s, with the node's role key.
func NewHello(role Role, network uint64, genesis [32]byte, protocol string, id Identity, nodeID string, s Session, signer abcrypto.Signer) (Hello, error) {
	h := Hello{Version: HelloVersion, Role: role, Network: network, Genesis: genesis[:], Protocol: protocol, Epoch: id.Epoch,
		BodyID: id.BodyID[:], ActivationID: id.ActivationID[:], Config: id.Config[:], NodeID: nodeID}
	sig, err := signer.SignBytes(h.message(s))
	h.Signature = sig
	return h, err
}

// Encode is the wire form of the hello.
func (h Hello) Encode() ([]byte, error) { return types.Cbor.Marshal(h) }

// DecodeHello parses a hello. Anything that is not exactly one, including the bytes of the existing handshake, is ErrLegacyPeer.
func DecodeHello(raw []byte) (Hello, error) {
	if len(raw) == 0 || len(raw) > maxHello {
		return Hello{}, fmt.Errorf("%w: %d bytes", ErrLegacyPeer, len(raw))
	}
	var h Hello
	if err := types.Cbor.Unmarshal(raw, &h); err != nil {
		return Hello{}, fmt.Errorf("%w: %v", ErrLegacyPeer, err)
	}
	if h.Version != HelloVersion || len(h.Protocol) > maxText || len(h.NodeID) > maxText || len(h.Signature) > maxSig ||
		len(h.Genesis) != 32 || len(h.BodyID) != 32 || len(h.ActivationID) != 32 || len(h.Config) != 32 {
		return Hello{}, fmt.Errorf("%w: malformed hello", ErrLegacyPeer)
	}
	return h, nil
}

// Admission is what a verified hello entitles the peer to.
type Admission int

const (
	// Live admits current votes, timeouts and requests: the peer's installed configuration is exactly ours.
	Live Admission = iota + 1
	// Historical admits bounded historical retrieval only: the peer is on an earlier verified epoch of our own history.
	Historical
)

// Expectation is what a verifier requires of a peer of a given role.
type Expectation struct {
	Role     Role
	Network  uint64
	Genesis  [32]byte
	Protocol string
	// Installed is the configuration this node runs. Past, when set, resolves an earlier epoch of the same verified history
	// (built from q3format.History, never from a peer or a query), so a lagging upgraded peer is recognised; without it only an
	// exact match is admitted.
	Installed Identity
	Past      func(epoch uint64) (Identity, bool)
	// KeyOf resolves the configured key of a node for the role; it must come from verified configuration, never from the hello.
	KeyOf func(role Role, nodeID string) ([]byte, bool)
}

// Verify admits the peer a hello came from, or refuses it. The checks are ordered so that a peer that is old, on another
// chain or unauthenticated is refused before its claimed configuration is considered. A claimed protocol never selects a rule.
func (e Expectation) Verify(h *Hello, s Session) (Admission, error) {
	if h == nil {
		return 0, ErrLegacyPeer
	}
	if h.Protocol != e.Protocol || e.Protocol == "" {
		return 0, fmt.Errorf("%w: %q, want %q", ErrProtocol, h.Protocol, e.Protocol)
	}
	if h.Network != e.Network || !bytes.Equal(h.Genesis, e.Genesis[:]) {
		return 0, ErrChain
	}
	if h.Role != e.Role {
		return 0, fmt.Errorf("%w: %d, want %d", ErrRole, h.Role, e.Role)
	}
	key, ok := e.KeyOf(h.Role, h.NodeID)
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrUnknownPeer, h.NodeID)
	}
	if v, err := abcrypto.NewVerifierSecp256k1(key); err != nil || v.VerifyBytes(h.Signature, h.message(s)) != nil {
		return 0, fmt.Errorf("%w: %q", ErrHelloSignature, h.NodeID)
	}
	got := Identity{Epoch: h.Epoch, BodyID: [32]byte(h.BodyID), ActivationID: [32]byte(h.ActivationID), Config: [32]byte(h.Config)}
	if got == e.Installed {
		return Live, nil
	}
	if e.Past != nil && got.Epoch < e.Installed.Epoch {
		if past, ok := e.Past(got.Epoch); ok && past == got {
			return Historical, nil
		}
	}
	return 0, ErrConfiguration
}
