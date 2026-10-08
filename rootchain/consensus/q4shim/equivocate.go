package q4shim

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"slices"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

type equivState struct {
	Equivocation
	sent int
	done map[uint64]struct{} // rounds already answered
}

// equivocate sends the Byzantine variants of an own vote that was just routed to one receiver. It runs once per round, on the send to
// the first receiver the vote goes to, and delivers straight to the equivocation's recipients: the variant is not subject to the
// rules (a rule that holds honest votes must not hold the Byzantine one). The caller holds n.mu.
func (n *Net) equivocate(ctx context.Context, msg any, to peer.ID, m Msg) error {
	vote, ok := msg.(*abdrc.VoteMsg)
	if !ok || m.Author != string(n.cfg.Self) {
		return nil
	}
	for _, e := range n.equivs {
		if (e.Epoch != 0 && e.Epoch != m.Epoch) || m.Round < e.RoundMin || (e.RoundMax != 0 && m.Round > e.RoundMax) {
			continue
		}
		if _, dup := e.done[m.Round]; dup {
			continue
		}
		e.done[m.Round] = struct{}{}
		if n.cfg.Signer == nil {
			err := ErrNoSigner
			n.fault(err)
			return err
		}
		variant, err := n.variantOf(vote, e.Variant)
		if err != nil {
			n.fault(err)
			return err
		}
		vm, err := Describe(variant, n.cfg.Signing)
		if err != nil {
			n.fault(fmt.Errorf("describing the Byzantine variant: %w", err))
			return err
		}
		for _, r := range e.Recipients {
			rid := peer.ID(r)
			if rid == n.cfg.Self {
				continue
			}
			n.record(Event{Kind: "equivocate", From: string(n.cfg.Self), To: r, Rule: e.Name}, vm)
			cp, err := Copy(vm)
			if err != nil {
				n.fault(err)
				return err
			}
			if err := n.inner.Send(ctx, cp, rid); err != nil {
				n.record(Event{Kind: "fault", To: r, Rule: e.Name, Error: err.Error()}, vm)
				continue
			}
			e.sent++
		}
	}
	return nil
}

func (n *Net) variantOf(vote *abdrc.VoteMsg, variant string) (*abdrc.VoteMsg, error) {
	raw, err := types.Cbor.Marshal(vote)
	if err != nil {
		return nil, err
	}
	var v abdrc.VoteMsg
	if err := types.Cbor.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	switch variant {
	case "rebroadcast":
		return &v, nil
	case "state":
		v.VoteInfo.CurrentRootHash = bytes.Repeat([]byte{0xbb}, 32)
		if v.Scheme == votesig.SchemeDomainBound {
			cfg, err := configOf(n.cfg.Signing, v.VoteInfo.Epoch)
			if err != nil {
				return nil, err
			}
			vi := votesig.VoteInfo{Epoch: v.VoteInfo.Epoch, Round: v.VoteInfo.RoundNumber, Parent: v.VoteInfo.ParentRoundNumber, Timestamp: v.VoteInfo.Timestamp}
			copy(vi.Exec[:], v.VoteInfo.CurrentRootHash)
			h, err := cfg.VoteInfoHash(vi)
			if err != nil {
				return nil, err
			}
			v.LedgerCommitInfo.PreviousHash = h[:]
			if err := v.SignDomainBound(n.cfg.Signer, cfg); err != nil {
				return nil, err
			}
			return &v, nil
		}
		h, err := v.VoteInfo.Hash(crypto.SHA256)
		if err != nil {
			return nil, err
		}
		v.LedgerCommitInfo.PreviousHash = h
		if err := v.Sign(n.cfg.Signer); err != nil {
			return nil, err
		}
		return &v, nil
	}
	return nil, fmt.Errorf("%w: equivocation variant %q", ErrBadControl, variant)
}

// SetEquivocations replaces the Byzantine adapter's instructions.
func (n *Net) SetEquivocations(es []Equivocation) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []*equivState
	for _, e := range es {
		if e.Variant != "state" && e.Variant != "rebroadcast" {
			return fmt.Errorf("%w: equivocation %q variant %q", ErrBadControl, e.Name, e.Variant)
		}
		if len(e.Recipients) == 0 {
			return fmt.Errorf("%w: equivocation %q has no recipients", ErrBadControl, e.Name)
		}
		if prev := n.equivByName(e.Name); prev != nil {
			out = append(out, prev) // an unchanged instruction keeps its progress
			continue
		}
		out = append(out, &equivState{Equivocation: e, done: map[uint64]struct{}{}})
	}
	n.equivs = out
	return nil
}

func (n *Net) equivByName(name string) *equivState {
	i := slices.IndexFunc(n.equivs, func(e *equivState) bool { return e.Name == name })
	if i < 0 {
		return nil
	}
	return n.equivs[i]
}

// Sent is how many Byzantine messages the instruction delivered to the wrapped network.
func (n *Net) Sent(equivocation string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	if e := n.equivByName(equivocation); e != nil {
		return e.sent
	}
	return 0
}
