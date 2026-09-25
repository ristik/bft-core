package consensus

import (
	"crypto"
	"time"

	"github.com/unicitynetwork/bft-core/trusthistorystore"
)

const (
	BlockRate     = 900
	LocalTimeout  = 10000
	HashAlgorithm = crypto.SHA256
)

type (
	// Parameters are basic consensus parameters that need to be the same in all root validators.
	// Extracted from root genesis where all validators in the root cluster must have signed them to signal agreement
	Parameters struct {
		BlockRate             time.Duration // also known as T3
		LocalTimeout          time.Duration
		ConsensusThreshold    uint32
		HashAlgorithm         crypto.Hash
		NetworkProfileVersion uint64 // 1 is the legacy root profile; 2 enables handoff
	}
	// Optional are common optional parameters for consensus managers
	Optional struct {
		Params           *Parameters
		FrontierSampler  *FrontierSamplerConfig
		FrontierSigning  bool
		RecoveryProfile2 bool
		RecoveryHistory  *trusthistorystore.Store
	}

	Option func(c *Optional)
)

func NewConsensusParams() *Parameters {
	return &Parameters{
		BlockRate:     time.Duration(BlockRate) * time.Millisecond,
		LocalTimeout:  time.Duration(LocalTimeout) * time.Millisecond,
		HashAlgorithm: HashAlgorithm,
	}
}

func WithConsensusParams(params Parameters) Option {
	return func(c *Optional) {
		c.Params = &params
	}
}

// WithFrontierSampler opts into the local, unsigned diagnostic sampler.
func WithFrontierSampler(config FrontierSamplerConfig) Option {
	return func(c *Optional) { c.FrontierSampler = &config }
}

// WithFrontierSigning opts into root-signed frontier responses. It requires
// WithFrontierSampler and does not register a transport or production caller.
func WithFrontierSigning() Option {
	return func(c *Optional) { c.FrontierSigning = true }
}

// WithRecoveryProfile2 enables per-certificate historical LastCR verification.
func WithRecoveryProfile2(history *trusthistorystore.Store) Option {
	return func(c *Optional) { c.RecoveryProfile2, c.RecoveryHistory = true, history }
}

func LoadConf(opts []Option) (*Optional, error) {
	conf := &Optional{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(conf)
	}

	if conf.Params == nil {
		conf.Params = NewConsensusParams()
	}

	return conf, nil
}
