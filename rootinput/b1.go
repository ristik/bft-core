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
	if f.Layout != registryproof.FreshB1 || f.B1Network != uint64(p.Network) || f.B1Format != 2 || f.B1ProfileHash != common.Hash(profileHash) || origin.NetworkID != uint64(p.Network) || parent.VerifiedContext().RegistryCodeHash != common.Hash(p.RuntimeHash) {
		return B1Result{}, ErrB1Admission
	}
	g, tip := f.B1GenesisEpoch, f.B1ImportedTip
	if tip < g || tip > origin.RootEpoch {
		return B1Result{}, ErrB1Admission
	}
	// Only the run from the imported tip onward is converted and admitted: the work of this block does not depend on how many epochs precede the tip
	// (they were admitted when imported), and a proposal whose origin is far ahead costs O(B), not O(gap): the run is capped one past what B allows.
	limit := int(c.Profile.MaxEpochsPerUpdate) + 2
	h, seg, err := c.Authority.B1Run(origin.RootRound, tip, limit)
	if err != nil {
		return B1Result{}, err
	}
	if h.Genesis() != p.RootGenesisID || h.Network() != uint64(p.Network) || h.FirstEpoch() != g { // the registry's genesis epoch is the history's first
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
	if err = b1state.ValidateSegment(seg, g); err != nil {
		return B1Result{}, err
	}
	if seg[0].Epoch != tip {
		return B1Result{}, ErrB1Admission
	}
	if seg[len(seg)-1].Epoch != origin.RootEpoch {
		if len(seg) == limit { // the cap was hit before the origin's epoch: more than B epochs are missing
			return B1Result{}, errors.Join(ErrB1Admission, b1state.ErrTooManyEpochs)
		}
		return B1Result{}, ErrB1Admission
	}
	tipEntry := seg[0]
	tipEntry.End = nil // the open tip, as the state holds it
	missing := seg[1:]
	if uint64(len(missing)) > c.Profile.MaxEpochsPerUpdate {
		return B1Result{}, errors.Join(ErrB1Admission, b1state.ErrTooManyEpochs)
	}
	// The words to authenticate against the parent: the open tip (the usable entry: a ready parent has U = I) and the absence of every entry about to be installed.
	// Nothing else is read: the steady path never enumerates the history.
	ready := f.B1OriginReady == 1
	expected := make(map[common.Hash]common.Hash)
	deployment := b1state.Deployment{GenesisCommitment: f.GenesisCommitment, ProfileHash: profileHash}
	prove := func(e b1state.Entry) error {
		ew, err := b1state.EntryStorage(e, deployment)
		if err != nil {
			return err
		}
		for k, v := range ew {
			expected[common.Hash(k)] = common.Hash(v)
		}
		return nil
	}
	if err = prove(tipEntry); err != nil {
		return B1Result{}, err
	}
	for _, e := range missing {
		expected[common.Hash(b1state.EntrySlot(e.Epoch, 0))] = common.Hash{}
	}
	keys := make([]common.Hash, 0, len(expected))
	for k := range expected {
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
		if got[i] != expected[k] {
			return B1Result{}, b1state.ErrHistory
		}
	}
	if parent.Number() == math.MaxUint64 {
		return B1Result{}, b1state.ErrOverflow
	}
	var oldTipEnd *uint64
	entries := make([]b1state.Entry, 0, len(missing))
	for i, e := range missing {
		e.End = nil
		if i+1 < len(missing) {
			end := missing[i+1].Start
			e.End = &end
		}
		entries = append(entries, e)
	}
	if len(entries) > 0 {
		end := entries[0].Start
		oldTipEnd = &end
	}
	u := b1state.Update{Network: p.Network, RootGenesisID: p.RootGenesisID, ExecutionChainID: p.ExecutionChainID, ProfileHash: profileHash, ParentHash: [32]byte(parent.ParentHash()), BlockNumber: parent.Number() + 1, OriginEpoch: origin.RootEpoch, OriginRound: origin.RootRound, OriginIdentity: [32]byte(origin.Identity()), PriorTipEpoch: tip, OldTipEnd: oldTipEnd, NewEntries: entries}
	// The registry's own write guards, on the proven parent (a ready parent whose usable epoch is not its imported tip is refused by ParentRegistry,
	// never repaired by this block): this block is refused here exactly when the runtime would refuse it.
	pr, err := b1state.ParentRegistry(g, tip, ready, f.OriginRootEpoch, f.ClockRootRound, tipEntry)
	if err != nil {
		return B1Result{}, err
	}
	if _, _, err = pr.Apply(u, p.MaxEpochsPerUpdate); err != nil {
		return B1Result{}, err
	}
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
