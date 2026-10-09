package q4shim

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"slices"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// Forgery makes this node send, next to each of its own votes and timeouts of a round (once per round and class), one message that an
// honest receiver must refuse: the authentication-refusal representatives of the live lane. Variant:
//
//	impersonate     the message re-signed with this node's key under the author Impersonate (a member's identity: its weight must not count)
//	unknown-signer  signed by a fresh key that no trust base names, under that key's own identity
//	bad-signature   the honest message with its signature corrupted
//	wrong-domain    scheme 2 signed over another root-chain genesis (domain) than the epoch's
//	old-form        the signing policy of another scheme: a legacy (scheme 1) signature in a scheme 2 epoch
//	old-epoch       claims the previous epoch and is signed by that epoch's rule (a valid signature of the wrong epoch)
//	future-epoch    claims the next epoch, for which no configuration is installed
//	stale           this node's own message of the same class from an earlier round, unchanged (validly signed, stale)
//
// A forgery is not an equivocation: the trace records it as kind "forge", and the offline checker does not count its statement for the
// claimed author (for impersonate the claimed author never signed it). Only a lane or a test reaches it, through the control document.
type Forgery struct {
	Name        string   `json:"name"`
	Recipients  []string `json:"recipients"`
	Variant     string   `json:"variant"`
	Impersonate string   `json:"impersonate,omitempty"`
	Class       Class    `json:"class,omitempty"` // vote or timeout; empty is both
	Require     bool     `json:"require,omitempty"`
}

var forgeryVariants = []string{"impersonate", "unknown-signer", "bad-signature", "wrong-domain", "old-form", "old-epoch", "future-epoch", "stale"}

type forgeState struct {
	Forgery
	sent int
	done map[string]struct{} // class/round already answered
}

type ownMsg struct {
	round uint64
	m     Msg
}

// SetForgeries replaces the forgery instructions; an unchanged one (same name) keeps its progress.
func (n *Net) SetForgeries(fs []Forgery) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []*forgeState
	for _, f := range fs {
		if !slices.Contains(forgeryVariants, f.Variant) {
			return fmt.Errorf("%w: forgery %q variant %q", ErrBadControl, f.Name, f.Variant)
		}
		if f.Class != "" && f.Class != Vote && f.Class != Timeout {
			return fmt.Errorf("%w: forgery %q class %q", ErrBadControl, f.Name, f.Class)
		}
		if len(f.Recipients) == 0 {
			return fmt.Errorf("%w: forgery %q has no recipients", ErrBadControl, f.Name)
		}
		for _, r := range append(slices.Clone(f.Recipients), f.Impersonate) {
			if r == "" {
				continue
			}
			if _, err := peer.Decode(r); err != nil {
				return fmt.Errorf("%w: forgery %q peer %q: %w", ErrBadControl, f.Name, r, err)
			}
		}
		if (f.Variant == "impersonate") != (f.Impersonate != "") {
			return fmt.Errorf("%w: forgery %q: impersonate names the claimed author, and only that variant takes one", ErrBadControl, f.Name)
		}
		if i := slices.IndexFunc(n.forges, func(o *forgeState) bool { return o.Name == f.Name }); i >= 0 {
			out = append(out, n.forges[i])
			continue
		}
		out = append(out, &forgeState{Forgery: f, done: map[string]struct{}{}})
	}
	n.forges = out
	return nil
}

// Forged is how many forged messages the instruction delivered to the wrapped network.
func (n *Net) Forged(name string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, f := range n.forges {
		if f.Name == name {
			return f.sent
		}
	}
	return 0
}

// forge sends the forgeries for an own vote or timeout that was just routed. The caller holds n.mu.
func (n *Net) forge(ctx context.Context, m Msg) error {
	if m.Author != n.cfg.Self.String() || (m.Class != Vote && m.Class != Timeout) {
		return nil
	}
	// the stale variant needs this node's message of an earlier round: keep the latest two rounds per class
	if last, ok := n.ownLast[m.Class]; !ok || m.Round > last.round {
		if ok {
			n.ownPrev[m.Class] = last
		}
		n.ownLast[m.Class] = ownMsg{round: m.Round, m: m}
	}
	for _, f := range n.forges {
		if f.Class != "" && f.Class != m.Class {
			continue
		}
		key := fmt.Sprintf("%s/%d", m.Class, m.Round)
		if _, dup := f.done[key]; dup {
			continue
		}
		var out any
		var err error
		if f.Variant == "stale" {
			prev, ok := n.ownPrev[m.Class]
			if !ok || prev.round >= m.Round {
				continue // nothing older yet: the next round may have it
			}
			out, err = Copy(prev.m)
		} else {
			out, err = n.forgeOf(m, f.Forgery)
		}
		f.done[key] = struct{}{}
		if err != nil {
			n.fault(fmt.Errorf("forgery %s: %w", f.Name, err))
			return err
		}
		fm, err := Describe(out, n.cfg.Signing)
		if err != nil {
			// a forged epoch has no configuration to describe its statement with: the trace keeps class, epoch, round and author only
			fm = describeForged(out, m)
		}
		for _, r := range f.Recipients {
			rid, err := peer.Decode(r)
			if err != nil || rid == n.cfg.Self {
				continue
			}
			n.record(Event{Kind: "forge", From: n.cfg.Self.String(), To: r, Rule: f.Name}, fm)
			if err := n.inner.Send(ctx, out, rid); err != nil {
				n.record(Event{Kind: "fault", To: r, Rule: f.Name, Error: err.Error()}, fm)
				continue
			}
			f.sent++
		}
	}
	return nil
}

func describeForged(out any, honest Msg) Msg {
	fm := Msg{Class: honest.Class, Type: honest.Type, Round: honest.Round}
	switch v := out.(type) {
	case *abdrc.VoteMsg:
		fm.Epoch, fm.Author, fm.Scheme = v.VoteInfo.Epoch, v.Author, schemeOf(v.Scheme)
	case *abdrc.TimeoutMsg:
		fm.Epoch, fm.Author, fm.Scheme = v.Timeout.Epoch, v.Author, schemeOf(v.Scheme)
	}
	fm.Raw, _ = types.Cbor.Marshal(out)
	return fm
}

// forgeOf builds one forged variant from a decoded copy of the honest message m.
func (n *Net) forgeOf(m Msg, f Forgery) (any, error) {
	if n.cfg.Signer == nil {
		return nil, ErrNoSigner
	}
	cp, err := Copy(m)
	if err != nil {
		return nil, err
	}
	cfg, err := configOf(n.cfg.Signing, m.Epoch)
	if err != nil {
		return nil, err
	}
	signer, author := n.cfg.Signer, ""
	switch f.Variant {
	case "bad-signature":
		corrupt := func(sig []byte) []byte {
			s := bytes.Clone(sig)
			if len(s) > 0 {
				s[len(s)/2] ^= 0xff
			}
			return s
		}
		switch v := cp.(type) {
		case *abdrc.VoteMsg:
			v.Signature = corrupt(v.Signature)
		case *abdrc.TimeoutMsg:
			v.Signature = corrupt(v.Signature)
		}
		return cp, nil
	case "impersonate":
		author = f.Impersonate
	case "unknown-signer":
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		if err != nil {
			return nil, err
		}
		if author, err = peerOf(s); err != nil {
			return nil, err
		}
		signer = s
	case "wrong-domain":
		if cfg.Scheme != votesig.SchemeDomainBound {
			return nil, fmt.Errorf("%w: wrong-domain needs a scheme 2 epoch, epoch %d is scheme %d", ErrBadControl, m.Epoch, cfg.Scheme)
		}
		cfg.Genesis[0] ^= 0xff
	case "old-form":
		if cfg.Scheme != votesig.SchemeDomainBound {
			return nil, fmt.Errorf("%w: old-form needs a scheme 2 epoch, epoch %d is scheme %d", ErrBadControl, m.Epoch, cfg.Scheme)
		}
		cfg = votesig.Config{Scheme: votesig.SchemeLegacy}
	case "old-epoch":
		if m.Epoch <= 1 {
			return nil, fmt.Errorf("%w: old-epoch needs an epoch above 1", ErrBadControl)
		}
		if cfg, err = configOf(n.cfg.Signing, m.Epoch-1); err != nil {
			return nil, err
		}
		setEpoch(cp, m.Epoch-1)
	case "future-epoch":
		setEpoch(cp, m.Epoch+1)
	}
	if err := resign(cp, signer, author, cfg); err != nil {
		return nil, err
	}
	return cp, nil
}

func setEpoch(msg any, epoch uint64) {
	switch v := msg.(type) {
	case *abdrc.VoteMsg:
		v.VoteInfo.Epoch = epoch
	case *abdrc.TimeoutMsg:
		v.Timeout.Epoch = epoch
	}
}

// resign sets the author (when given) and signs the message under cfg's scheme with signer; a vote's commit info is first bound to its
// vote info by that scheme's rule.
func resign(msg any, signer abcrypto.Signer, author string, cfg votesig.Config) error {
	switch v := msg.(type) {
	case *abdrc.VoteMsg:
		if author != "" {
			v.Author = author
		}
		if cfg.Scheme == votesig.SchemeDomainBound {
			vi := votesig.VoteInfo{Epoch: v.VoteInfo.Epoch, Round: v.VoteInfo.RoundNumber, Parent: v.VoteInfo.ParentRoundNumber, Timestamp: v.VoteInfo.Timestamp}
			copy(vi.Exec[:], v.VoteInfo.CurrentRootHash)
			h, err := cfg.VoteInfoHash(vi)
			if err != nil {
				return err
			}
			v.LedgerCommitInfo.PreviousHash = h[:]
			return v.SignDomainBound(signer, cfg)
		}
		h, err := v.VoteInfo.Hash(crypto.SHA256)
		if err != nil {
			return err
		}
		v.LedgerCommitInfo.PreviousHash, v.SealSignature, v.Scheme = h, nil, votesig.SchemeLegacy
		return v.Sign(signer)
	case *abdrc.TimeoutMsg:
		if author != "" {
			v.Author = author
		}
		if cfg.Scheme == votesig.SchemeDomainBound {
			return v.SignDomainBound(signer, cfg)
		}
		v.Scheme = votesig.SchemeLegacy
		return v.Sign(signer)
	}
	return fmt.Errorf("%w: cannot re-sign %T", ErrBadControl, msg)
}

// peerOf is the libp2p identity of a secp256k1 signer's public key: the node identifier a root of that key would have.
func peerOf(s abcrypto.Signer) (string, error) {
	v, err := s.Verifier()
	if err != nil {
		return "", err
	}
	raw, err := v.MarshalPublicKey()
	if err != nil {
		return "", err
	}
	pub, err := libp2pcrypto.UnmarshalSecp256k1PublicKey(raw)
	if err != nil {
		return "", err
	}
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
