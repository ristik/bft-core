package rootinput

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/b1registry"
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/b1authority"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

var ErrB1Admission = errors.New("b1paired: missing or inconsistent authenticated pair evidence")

// ErrRecordsAdmission reports a root-record import that cannot be derived or differs from the one this pair derives.
var ErrRecordsAdmission = errors.New("rootinput: root-record import missing or inconsistent with the authenticated source log")

// RecordsSource is the authenticated root-record source of one pair: the retained log and its cursor as of a committed root origin.
type RecordsSource interface {
	rootrecords.Source
	// Cursor is the current progress and UC time, and the length and tip of the complete source log, as of the committed root block
	// the origin names. The origin carries what authenticates it (its unicity tree root, round, epoch and reference time), so a source
	// can check the state it is served against it. Records ordered after that block are not part of it.
	Cursor(ctx context.Context, origin evmroot.RootOriginV2) (rootrecords.Cursor, error)
}

// B1Config is local deployment configuration. Proofs fetches untrusted storage
// proof nodes for the named verified parent; it cannot grant authority.
type B1Config struct {
	Profile b1state.Profile
	// Authority is minted by q3active.Runtime.B1Authority.
	Authority *b1authority.Source
	Proofs    func(context.Context, registryproof.Snapshot, []common.Hash) ([][][]byte, error)
	// Records derives the mandatory root-record import. A fresh profile cannot admit a block without it.
	Records RecordsSource
}
type RecordsResult struct {
	Import       []byte
	Hash         [32]byte
	AdmissionGas uint64
	Entries      int
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

// DeriveRecords derives the import this block owes: exactly the next min(32, targetCount - registryCount) records of the source log as
// of the origin's committed root block, with the origin's anchors. Nothing is supplied by a relayer; a second pair derives the same
// bytes from the same authenticated source and parent registry words, and the registry's own acceptance rule is checked here first.
func (c *B1Config) DeriveRecords(ctx context.Context, parent registryproof.Snapshot, o VerifiedObservationV2) (RecordsResult, error) {
	if c == nil || c.Records == nil || !parent.Valid() || !o.Valid() {
		return RecordsResult{}, ErrRecordsAdmission
	}
	f := parent.Fields()
	if f.Layout != registryproof.FreshB1 {
		return RecordsResult{}, ErrRecordsAdmission
	}
	cursor, err := c.Records.Cursor(ctx, o.Origin())
	if err != nil {
		return RecordsResult{}, errors.Join(ErrRecordsAdmission, err)
	}
	reg := rootrecords.Registry{Count: f.RecordsCount, Progress: f.RecordsProgress, UCTime: f.RecordsUCTime, TargetCount: f.RecordsTargetCount,
		Tip: [32]byte(f.RecordsTip), TargetTip: [32]byte(f.RecordsTargetTip)}
	if f.RecordsCount > 0 {
		last, err := c.Records.Record(f.RecordsCount - 1)
		if err != nil || last.ID != reg.Tip {
			return RecordsResult{}, errors.Join(ErrRecordsAdmission, errors.New("the registry's tip is not the source log's record"), err)
		}
		reg.Last = &last
	}
	imp, err := rootrecords.BuildImport(c.Records, cursor, reg)
	if err != nil {
		return RecordsResult{}, errors.Join(ErrRecordsAdmission, err)
	}
	raw, err := imp.Encode()
	if err != nil {
		return RecordsResult{}, errors.Join(ErrRecordsAdmission, err)
	}
	if _, gas, err := rootrecords.AdmitImport(raw, c.Profile.SystemGas); err != nil {
		return RecordsResult{}, errors.Join(ErrRecordsAdmission, err)
	} else {
		return RecordsResult{Import: raw, Hash: sha256.Sum256(raw), AdmissionGas: gas, Entries: len(imp.Entries)}, nil
	}
}

// CompareRecords rederives on this pair for import, replay and crash recovery.
func (c *B1Config) CompareRecords(ctx context.Context, parent registryproof.Snapshot, o VerifiedObservationV2, raw []byte, hash []byte) (RecordsResult, error) {
	expected, err := c.DeriveRecords(ctx, parent, o)
	if err != nil {
		return RecordsResult{}, err
	}
	if !bytes.Equal(expected.Import, raw) || !bytes.Equal(expected.Hash[:], hash) {
		return RecordsResult{}, ErrRecordsAdmission
	}
	return expected, nil
}
