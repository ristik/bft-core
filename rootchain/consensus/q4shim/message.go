package q4shim

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

var (
	// ErrCopy is returned when a message does not survive its serialized copy: the recorded bytes do not decode, or the decoded
	// copy does not encode back to them. The shim then holds or duplicates nothing it cannot reproduce exactly.
	ErrCopy = errors.New("q4shim: message does not survive its serialized copy")
	// ErrStatement is returned when the signed statement of a scheme 2 message cannot be derived (no signing configuration for its
	// epoch, or a malformed message).
	ErrStatement = errors.New("q4shim: signed statement cannot be derived")
)

// Class is the phase of a root message: a proposal opens a round, a vote goes to the next collector, a timeout leaves the round.
type Class string

const (
	Proposal Class = "proposal"
	Vote     Class = "vote"
	Timeout  Class = "timeout"
	Other    Class = "other"
)

// Msg is the immutable description of one root message: class, epoch, round, author, the canonical signed statement and the
// serialized bytes. The statement is the scheme 2 preimage for a domain-bound message and the legacy signed bytes otherwise.
type Msg struct {
	Class     Class
	Type      string
	Epoch     uint64
	Round     uint64
	Author    string
	Scheme    uint64
	Statement []byte
	Raw       []byte
}

// SigningFor resolves the authenticated signing configuration of an epoch (the trust base store's SigningConfig).
type SigningFor func(epoch uint64) (votesig.Config, error)

// Describe classifies a message and records its statement and serialized form. A message class the shim does not schedule (state
// sync, change requests, handoff approvals) is Other: passed on untouched and traced by type only.
func Describe(msg any, signing SigningFor) (Msg, error) {
	var m Msg
	var err error
	switch v := msg.(type) {
	case *abdrc.VoteMsg:
		if v.VoteInfo == nil || v.LedgerCommitInfo == nil {
			return Msg{Class: Vote, Type: "vote"}, fmt.Errorf("%w: vote without vote info", ErrStatement)
		}
		m = Msg{Class: Vote, Type: "vote", Epoch: v.VoteInfo.Epoch, Round: v.VoteInfo.RoundNumber, Author: v.Author, Scheme: schemeOf(v.Scheme)}
		if v.Scheme == votesig.SchemeDomainBound {
			m.Statement, err = voteStatement(v, signing)
		} else {
			m.Statement, err = v.LedgerCommitInfo.SigBytes()
		}
	case *abdrc.TimeoutMsg:
		if v.Timeout == nil {
			return Msg{Class: Timeout, Type: "timeout"}, fmt.Errorf("%w: timeout without body", ErrStatement)
		}
		m = Msg{Class: Timeout, Type: "timeout", Epoch: v.Timeout.Epoch, Round: v.Timeout.Round, Author: v.Author, Scheme: schemeOf(v.Scheme)}
		if v.Scheme == votesig.SchemeDomainBound {
			var cfg votesig.Config
			if cfg, err = configOf(signing, v.Timeout.Epoch); err == nil {
				m.Statement, err = v.Preimage(cfg)
			}
		} else {
			m.Statement = v.Bytes()
		}
	case *abdrc.ProposalMsg:
		if v.Block == nil {
			return Msg{Class: Proposal, Type: "proposal"}, fmt.Errorf("%w: proposal without block", ErrStatement)
		}
		m = Msg{Class: Proposal, Type: "proposal", Epoch: v.Block.Epoch, Round: v.Block.Round, Author: v.Block.Author, Scheme: votesig.SchemeLegacy}
		m.Statement, err = v.Block.Hash(crypto.SHA256)
	default:
		return Msg{Class: Other, Type: fmt.Sprintf("%T", msg)}, nil
	}
	if err != nil {
		return m, err
	}
	m.Raw, err = types.Cbor.Marshal(msg)
	return m, err
}

func schemeOf(s uint64) uint64 {
	if s == votesig.SchemeDomainBound {
		return s
	}
	return votesig.SchemeLegacy
}

func configOf(signing SigningFor, epoch uint64) (votesig.Config, error) {
	if signing == nil {
		return votesig.Config{}, fmt.Errorf("%w: no signing configuration source", ErrStatement)
	}
	cfg, err := signing(epoch)
	if err != nil {
		return votesig.Config{}, fmt.Errorf("%w: epoch %d: %w", ErrStatement, epoch, err)
	}
	return cfg, nil
}

func voteStatement(v *abdrc.VoteMsg, signing SigningFor) ([]byte, error) {
	cfg, err := configOf(signing, v.VoteInfo.Epoch)
	if err != nil {
		return nil, err
	}
	pv, _, _, err := drctypes.DomainBoundStatement(cfg, v.VoteInfo, v.LedgerCommitInfo, len(v.SealSignature) != 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStatement, err)
	}
	return pv, nil
}

// Copy decodes the recorded bytes into a fresh message and checks that it encodes back to the same bytes. A class the shim does not
// describe has no copy (nil, nil): the caller passes the original on.
func Copy(m Msg) (any, error) {
	var out any
	switch m.Class {
	case Vote:
		out = new(abdrc.VoteMsg)
	case Timeout:
		out = new(abdrc.TimeoutMsg)
	case Proposal:
		out = new(abdrc.ProposalMsg)
	default:
		return nil, nil
	}
	if err := types.Cbor.Unmarshal(m.Raw, out); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCopy, err)
	}
	again, err := types.Cbor.Marshal(out)
	if err != nil || !bytes.Equal(again, m.Raw) {
		return nil, fmt.Errorf("%w: %s round %d", ErrCopy, m.Class, m.Round)
	}
	return out, nil
}
