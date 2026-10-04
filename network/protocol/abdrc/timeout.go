package abdrc

import (
	"bytes"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	abdrc "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

type TimeoutMsg struct {
	_         struct{}           `cbor:",toarray"`
	Timeout   *abdrc.Timeout     `json:"timeout"`
	Author    string             `json:"author"`
	Signature hex.Bytes          `json:"signature"`
	LastTC    *abdrc.TimeoutCert `json:"lastTc,omitempty"` // TC for Timeout.Round−1 if Timeout.HighQC.Round != Timeout.Round−1 (nil otherwise)
	// Scheme is the signing scheme of the wire form: 0 or 1 is the legacy form, 2 the domain-bound form [2, payload]. It is not
	// part of the legacy encoding; the epoch of the timeout decides which one a verifier accepts.
	Scheme uint64 `cbor:"-" json:"-"`
}

type timeoutMsgWire TimeoutMsg

type timeoutMsgV2Wire struct {
	_       struct{} `cbor:",toarray"`
	Scheme  uint64
	Payload timeoutMsgWire
}

// MarshalCBOR writes the legacy array, or the scheme wrapper for a scheme 2 message.
func (x TimeoutMsg) MarshalCBOR() ([]byte, error) {
	if x.Scheme == votesig.SchemeDomainBound {
		return types.Cbor.Marshal(timeoutMsgV2Wire{Scheme: x.Scheme, Payload: timeoutMsgWire(x)})
	}
	return types.Cbor.Marshal(timeoutMsgWire(x))
}

// UnmarshalCBOR reads the legacy array or the scheme 2 wrapper; any other wrapper version is refused before anything is
// verified.
func (x *TimeoutMsg) UnmarshalCBOR(data []byte) error {
	wrapped, err := votesig.PeekWrapper(data)
	if err != nil {
		return err
	}
	if wrapped {
		var w timeoutMsgV2Wire
		if err := types.Cbor.Unmarshal(data, &w); err != nil {
			return err
		}
		*x = TimeoutMsg(w.Payload)
		x.Scheme = votesig.SchemeDomainBound
		return nil
	}
	var legacy timeoutMsgWire
	if err := types.Cbor.Unmarshal(data, &legacy); err != nil {
		return err
	}
	*x = TimeoutMsg(legacy)
	x.Scheme = 0
	return nil
}

func (x *TimeoutMsg) signingScheme() uint64 {
	if x.Scheme == votesig.SchemeDomainBound {
		return votesig.SchemeDomainBound
	}
	return votesig.SchemeLegacy
}

// Preimage is the scheme 2 bytes this timeout signs (PT) under cfg.
func (x *TimeoutMsg) Preimage(cfg votesig.Config) ([]byte, error) {
	t := votesig.Timeout{Epoch: x.Timeout.Epoch, Round: x.Timeout.Round, HighQcRound: x.Timeout.GetHqcRound(), Author: x.Author}
	if a := x.Timeout.Anchor; a != nil {
		if len(a.GenesisID) != 32 {
			return nil, fmt.Errorf("%w: anchor genesis id is %d bytes", votesig.ErrStatement, len(a.GenesisID))
		}
		t.Anchor = &votesig.Anchor{Epoch: a.Epoch, Slot: a.Slot}
		copy(t.Anchor.GenesisID[:], a.GenesisID)
	}
	return cfg.TimeoutPreimage(t)
}

// SignDomainBound signs the scheme 2 preimage with the same key and marks the message as scheme 2.
func (x *TimeoutMsg) SignDomainBound(s crypto.Signer, cfg votesig.Config) error {
	if err := x.IsValid(); err != nil {
		return fmt.Errorf("timeout validation failed, %w", err)
	}
	pt, err := x.Preimage(cfg)
	if err != nil {
		return err
	}
	sig, err := s.SignBytes(pt)
	if err != nil {
		return fmt.Errorf("sign error, %w", err)
	}
	x.Signature, x.Scheme = sig, votesig.SchemeDomainBound
	return nil
}

// NewTimeoutMsg constructs a new atomic broadcast timeout message
func NewTimeoutMsg(timeout *abdrc.Timeout, author string, lastTC *abdrc.TimeoutCert) *TimeoutMsg {
	return &TimeoutMsg{Timeout: timeout, Author: author, LastTC: lastTC}
}

func (x *TimeoutMsg) Bytes() []byte {
	var b bytes.Buffer
	b.Write(util.Uint64ToBytes(x.Timeout.Round))
	b.Write(util.Uint64ToBytes(x.Timeout.Epoch))
	b.Write(util.Uint64ToBytes(x.Timeout.GetHqcRound()))
	if x.Timeout.Anchor != nil {
		b.WriteByte(1)
		b.Write(x.Timeout.Anchor.GenesisID)
		b.Write(util.Uint64ToBytes(x.Timeout.Anchor.Epoch))
		b.Write(util.Uint64ToBytes(x.Timeout.Anchor.Slot))
	}
	b.Write([]byte(x.Author))
	return b.Bytes()
}

func (x *TimeoutMsg) IsValid() error {
	if x.Timeout == nil {
		return fmt.Errorf("timeout info is nil")
	}
	if err := x.Timeout.IsValid(); err != nil {
		return fmt.Errorf("invalid timeout data: %w", err)
	}
	if x.Author == "" {
		return fmt.Errorf("timeout message is missing author")
	}

	// if highQC is not for previous round we must have TC for previous round
	if prevRound := x.GetRound() - 1; prevRound != x.Timeout.GetHqcRound() {
		if x.LastTC == nil {
			return fmt.Errorf("last TC is missing for round %d", prevRound)
		}
		if err := x.LastTC.IsValid(); err != nil {
			return fmt.Errorf("invalid timeout certificate: %w", err)
		}
		if prevRound != x.LastTC.GetRound() {
			return fmt.Errorf("last TC must be for round %d but is for round %d", prevRound, x.LastTC.GetRound())
		}
	}
	return nil
}

func (x *TimeoutMsg) Verify(tbs *trustbase.TrustBaseStore) error {
	if err := x.IsValid(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	timeoutTrustBase, err := tbs.GetByEpoch(x.Timeout.Epoch)
	if err != nil {
		return fmt.Errorf("failed to get trust base for timeout verification, epoch %d: %w", x.Timeout.Epoch, err)
	}
	cfg, err := tbs.SigningConfig(x.Timeout.Epoch)
	if err != nil {
		return err
	}
	if x.signingScheme() != cfg.Scheme {
		return fmt.Errorf("%w: timeout is scheme %d, epoch %d requires scheme %d", votesig.ErrScheme, x.signingScheme(), x.Timeout.Epoch, cfg.Scheme)
	}
	signed := x.Bytes()
	if cfg.Scheme == votesig.SchemeDomainBound {
		if err := votesig.CheckSignatureShape(x.Signature); err != nil {
			return err
		}
		if signed, err = x.Preimage(cfg); err != nil {
			return err
		}
	}
	if _, err := timeoutTrustBase.VerifySignature(signed, x.Signature, x.Author); err != nil {
		return fmt.Errorf("signature verification failed: %w", votesig.BadSignature(err))
	}
	if err := x.Timeout.Verify(tbs); err != nil {
		return fmt.Errorf("timeout data verification failed: %w", err)
	}
	if x.LastTC != nil {
		if err := x.LastTC.Verify(tbs); err != nil {
			return fmt.Errorf("invalid last TC: %w", err)
		}
	}
	return nil
}

func (x *TimeoutMsg) Sign(s crypto.Signer) error {
	if err := x.IsValid(); err != nil {
		return fmt.Errorf("timeout validation failed, %w", err)
	}
	sig, err := s.SignBytes(x.Bytes())
	if err != nil {
		return fmt.Errorf("sign error, %w", err)
	}
	x.Signature = sig
	return nil
}

func (x *TimeoutMsg) GetRound() uint64 {
	if x == nil || x.Timeout == nil {
		return 0
	}
	return x.Timeout.Round
}
