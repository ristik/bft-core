package rootinput

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/internal/b1authority"
	"github.com/unicitynetwork/bft-core/registryproof"
)

var ErrB1Admission = errors.New("b1paired: missing or inconsistent authenticated pair evidence")

// B1Config is local deployment configuration. Proofs fetches untrusted storage
// proof nodes for the named verified parent; it cannot grant authority.
type B1Config struct {
	Profile b1state.Profile
	// Authority is minted by q3active.Runtime.B1Authority.
	Authority *b1authority.Source
	Proofs    func(context.Context, registryproof.Snapshot, []common.Hash) ([][][]byte, error)
}
type B1Result struct {
	Update       []byte
	Hash         [32]byte
	AdmissionGas uint64
}

func (c *B1Config) Derive(ctx context.Context, parent registryproof.Snapshot, o VerifiedObservationV2) (B1Result, error) {
	if c == nil || c.Authority == nil || !parent.Valid() || !o.Valid() {
		return B1Result{}, ErrB1Admission
	}
	p := c.Profile
	if err := b1registry.ValidateProfile(p); err != nil {
		return B1Result{}, err
	}
	f := parent.Fields()
	origin := o.Origin()
	profileHash, _ := p.Hash()
	if f.Layout != registryproof.FreshB1 || f.B1Network != uint64(p.Network) || f.B1WCert != p.WCert || f.B1ProfileHash != common.Hash(profileHash) || origin.NetworkID != uint64(p.Network) || parent.VerifiedContext().RegistryCodeHash != common.Hash(p.RuntimeHash) {
		return B1Result{}, ErrB1Admission
	}
	h, err := c.Authority.B1History(origin.RootRound)
	if err != nil {
		return B1Result{}, err
	}
	if h.Genesis() != p.RootGenesisID || h.Network() != uint64(p.Network) {
		return B1Result{}, ErrB1Admission
	}
	if err = h.Ordinary(origin.RootEpoch, origin.RootRound); err != nil {
		return B1Result{}, err
	}
	committee, err := h.ForEpoch(origin.RootEpoch)
	if err != nil {
		return B1Result{}, err
	}
	if err = o.VerifyRootCommittee(committee.Projection()); err != nil {
		return B1Result{}, err
	}
	history, err := h.B1Entries(origin.RootRound)
	if err != nil {
		return B1Result{}, err
	}
	parentOrigin := f.ClockRootRound
	if parent.Genesis() {
		parentOrigin = history[0].Start
	} // genesis installs authority before the operational clock starts
	expected, err := b1state.Select(history, parentOrigin, p.WCert)
	if err != nil {
		return B1Result{}, err
	}
	if uint64(len(expected)) != f.B1Count || f.B1Head > p.WCert || (!parent.Genesis() && f.OriginRootEpoch != expected[len(expected)-1].Epoch) {
		return B1Result{}, ErrB1Admission
	}
	words := make(map[common.Hash]common.Hash)
	for i, e := range expected {
		words[common.Hash(b1state.QueueSlot((f.B1Head+uint64(i))%(p.WCert+1)))] = common.Hash(b1state.Word(e.Epoch))
		ew, err := b1state.EntryStorage(e)
		if err != nil {
			return B1Result{}, err
		}
		for k, v := range ew {
			words[common.Hash(k)] = common.Hash(v)
		}
	}
	keys := make([]common.Hash, 0, len(words))
	for k := range words {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	if c.Proofs == nil {
		return B1Result{}, ErrB1Admission
	}
	// The fetcher owns its query copy, never the admission key inventory.
	proofs, err := c.Proofs(ctx, parent, append([]common.Hash(nil), keys...))
	if err != nil {
		return B1Result{}, err
	}
	got, err := parent.VerifyWords(keys, proofs)
	if err != nil {
		return B1Result{}, err
	}
	for i, k := range keys {
		if got[i] != words[k] {
			return B1Result{}, b1state.ErrHistory
		}
	}
	end, entries, err := b1state.Delta(history, expected, parentOrigin, origin.RootRound, p.WCert)
	if err != nil {
		return B1Result{}, err
	}
	if parent.Number() == math.MaxUint64 {
		return B1Result{}, b1state.ErrOverflow
	}
	u := b1state.Update{Network: p.Network, RootGenesisID: p.RootGenesisID, ExecutionChainID: p.ExecutionChainID, ProfileHash: profileHash, ParentHash: [32]byte(parent.ParentHash()), BlockNumber: parent.Number() + 1, OriginEpoch: origin.RootEpoch, OriginRound: origin.RootRound, OriginIdentity: [32]byte(origin.Identity()), PriorTipEpoch: expected[len(expected)-1].Epoch, OldTipEnd: end, NewEntries: entries}
	raw := u.Bytes()
	_, gas, err := b1state.Admit(raw, p, p.SystemGas)
	if err != nil {
		return B1Result{}, err
	}
	return B1Result{Update: raw, Hash: u.Hash(), AdmissionGas: gas}, nil
}

// Compare rederives on this pair for import, replay and crash recovery. The
// execution block hash is checked separately by the existing payload verifier.
func (c *B1Config) Compare(ctx context.Context, parent registryproof.Snapshot, o VerifiedObservationV2, raw []byte, hash []byte) (B1Result, error) {
	expected, err := c.Derive(ctx, parent, o)
	if err != nil {
		return B1Result{}, err
	}
	if !bytes.Equal(expected.Update, raw) || !bytes.Equal(expected.Hash[:], hash) {
		return B1Result{}, b1state.ErrBinding
	}
	return expected, nil
}
