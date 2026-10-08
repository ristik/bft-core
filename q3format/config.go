package q3format

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// ErrConfig is returned for a protocol tuple that is not exactly the one Q3 tuple.
var ErrConfig = errors.New("q3format: invalid protocol configuration")

const (
	configDomain   = "UNICITY_Q3_PROTOCOL_CONFIG"
	configFields   = 9
	maxConfigText  = 32
	ConfigRevision = 2
)

// LeaderPolicyLegacy is the leader selection of every epoch that has no Q3 tuple.
const LeaderPolicyLegacy = "legacy"

// LeaderPolicyWeightedV1 is the leader selection of a Q3 epoch: the fixed-epoch weighted proposer-priority selector, reset to
// zero priorities at the epoch's activation round (rootchain/consensus/leader.Weighted).
const LeaderPolicyWeightedV1 = "root-wrr-v1"

// ProtocolConfig is the one immutable protocol tuple a successor root epoch activates: bounded root weights, Q1 signing
// scheme 2 with vote codec 2, the D3 quorum profile, the weighted proposer-priority leader selector, the mirrored EVM request
// policy and unit aggregators. A deployment has one
// protocol and one registry layout, so the tuple names no protocol version to negotiate and no layout to select. Network and
// Genesis are the chain's, not an epoch's.
// There is no independently configurable member: any value other than the Q3 one, and so any partial combination, is invalid.
type ProtocolConfig struct {
	Revision                 uint64
	Network                  uint64
	Genesis                  [32]byte // the trusted root-genesis identity, never the changing epoch-anchor id
	SigningScheme, VoteCodec uint64
	QuorumProfile            string
	LeaderPolicy             string
	EVMRequestPolicy         string
	AggregatorPolicy         string
}

// Q3Config is the single valid tuple for a chain.
func Q3Config(network uint64, genesis [32]byte) ProtocolConfig {
	return ProtocolConfig{Revision: ConfigRevision, Network: network, Genesis: genesis, SigningScheme: 2, VoteCodec: 2,
		QuorumProfile: "D3", LeaderPolicy: LeaderPolicyWeightedV1, EVMRequestPolicy: "mirrored-root-v1", AggregatorPolicy: "unit-v1"}
}

// Validate refuses a tuple that differs from Q3Config in any field, naming the first field that differs.
func (c ProtocolConfig) Validate() error {
	if c.Network == 0 || c.Genesis == ([32]byte{}) {
		return fmt.Errorf("%w: network and genesis are required", ErrConfig)
	}
	w := Q3Config(c.Network, c.Genesis)
	for _, f := range []struct {
		name      string
		got, want any
	}{{"revision", c.Revision, w.Revision}, {"signingScheme", c.SigningScheme, w.SigningScheme}, {"voteCodec", c.VoteCodec, w.VoteCodec},
		{"quorumProfile", c.QuorumProfile, w.QuorumProfile}, {"leaderPolicy", c.LeaderPolicy, w.LeaderPolicy}, {"evmRequestPolicy", c.EVMRequestPolicy, w.EVMRequestPolicy},
		{"aggregatorPolicy", c.AggregatorPolicy, w.AggregatorPolicy}} {
		if f.got != f.want {
			return fmt.Errorf("%w: %s is %v, want %v", ErrConfig, f.name, f.got, f.want)
		}
	}
	return nil
}

func (c ProtocolConfig) fields() []any {
	return []any{c.Revision, c.Network, c.Genesis[:], c.SigningScheme, c.VoteCodec, c.QuorumProfile, c.LeaderPolicy, c.EVMRequestPolicy,
		c.AggregatorPolicy}
}

// Identity is the hash of the tuple alone; the activation and the readiness receipts name it.
func (c ProtocolConfig) Identity() [32]byte { return sha256.Sum256(enc(configDomain, c.fields())) }

func readConfig(r *reader) (ProtocolConfig, error) {
	f := r.sub(configFields)
	var c ProtocolConfig
	c.Revision, c.Network = f.uint(), f.uint()
	copy(c.Genesis[:], f.bytes(32, 32))
	c.SigningScheme, c.VoteCodec = f.uint(), f.uint()
	c.QuorumProfile, c.LeaderPolicy = f.text(maxConfigText), f.text(maxConfigText)
	c.EVMRequestPolicy, c.AggregatorPolicy = f.text(maxConfigText), f.text(maxConfigText)
	if err := f.done(); err != nil {
		return ProtocolConfig{}, err
	}
	return c, nil
}
