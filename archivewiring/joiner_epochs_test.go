package archivewiring

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredadmission"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// joinerEpochs certifies blocks 1-3 in root epoch 1, 4-6 in epoch 2 and 7 on in epoch 3: two root handoffs.
func joinerEpochs(height int) uint64 {
	switch {
	case height <= 3:
		return 1
	case height <= 6:
		return 2
	}
	return 3
}

// bft-core#1309. A joiner restored from the shipped epoch-1 seed (the pin certifies block 1 in root epoch 1) after two root handoffs
// reaches the tip: its head follower takes the newest certified record from a replica's public reads, verified against the joiner's
// own installed history (nothing is offered for an epoch it has not installed), and its execution recovery replays the certified
// blocks across both epoch boundaries from the archive. After a restart (the journal reopened with the installed epoch already at 3,
// as the replayed activations leave it) the completed restore is an ordinary node's store and follows the chain on.
func TestJoinerFromTheEpochOneSeedCatchesUpAcrossTwoRootHandoffsAndAfterARestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const firstRun, total = 9, 12
	src := newWiringFixtureOpts(t, wiringOpts{blocks: total, limits: configuredprogress.JournalLimits{Candidates: 64, Observations: 128, Bytes: 32 << 20},
		epochs: joinerEpochs})
	sort.Slice(src.entries, func(i, j int) bool { return src.entries[i].Candidate.Number < src.entries[j].Candidate.Number })
	for i, e := range src.entries {
		require.EqualValues(t, i+1, e.Candidate.Number)
		require.Equal(t, joinerEpochs(i+1), e.ResultingUC.GetRootEpoch(), "block %d", i+1)
	}

	// two incumbents' archive replicas; the joiner is no validator and reads through their public read budget only
	joiner := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	var replicas []peer.ID
	var stores []*archive.Store
	for range 2 {
		host := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		joiner.Network().Peerstore().AddAddrs(host.ID(), host.MultiAddresses(), peerstore.PermanentAddrTTL)
		store, err := archive.Open(t.TempDir())
		require.NoError(t, err)
		server, err := NewServer(store, src.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"validator"}, DefaultLimits())
		require.NoError(t, err)
		require.NoError(t, server.SetPublicReads(Limits{Deadline: 5 * time.Second, Pending: 4, PerPeer: 2}))
		server.Register(ctx, host)
		replicas, stores = append(replicas, host.ID()), append(stores, store)
	}
	serve := func(from, to int) {
		for h := from; h <= to; h++ {
			q, rec := src.record(t, h-1)
			for _, store := range stores {
				require.NoError(t, store.Put(q, rec))
			}
		}
	}
	serve(1, firstRun)

	// the joiner's own verified history: the pinned genesis trust base only, until it installs the handoffs
	installed := &fixtureEpoch{}
	installed.epoch.Store(1)
	srcTrust := src.context.Observation.TrustBases.(fixtureEpochTrust)
	trust := fixtureEpochTrust{1: srcTrust[1]}
	jc := src.context
	jc.Observation.TrustBases, jc.Record.TrustBases = trust, trust
	jc.Observation.EpochAuthority, jc.Record.EpochAuthority = installed, installed
	var journal *configuredprogress.Store
	// the shard installer's order for a verified activation of `epoch`: the terminal certificate of the epoch it ends (the last block
	// that epoch certified) is authenticated under the still-current epoch and committed to the journal, then the epoch activates
	install := func(epoch uint64) {
		t.Helper()
		last := 0
		for h := 1; joinerEpochs(h) < epoch; h++ {
			last = h
		}
		terminal := src.entries[last-1]
		o, err := rootinput.AuthenticateObservationV2(ctx, jc.Observation, terminal.ResultingUC, terminal.ResultingTR)
		require.NoError(t, err)
		prepared, _, err := journal.PrepareObservation(ctx, jc, o)
		require.NoError(t, err)
		_, _, err = journal.CommitObservation(prepared)
		require.NoError(t, err)
		trust[epoch] = srcTrust[epoch]
		installed.epoch.Store(epoch)
	}

	path := t.TempDir() + "/execution-journal.db"
	limits := configuredprogress.JournalLimits{Candidates: 16, Observations: 32, Bytes: 16 << 20}
	open := func() *configuredprogress.Store {
		store, err := configuredprogress.OpenConfiguredV2(path, configuredprogress.Settings{Retain: 16})
		require.NoError(t, err)
		_, _, err = store.Initialize(ctx, jc)
		require.NoError(t, err)
		require.NoError(t, store.EnableJournal(ctx, jc, limits))
		return store
	}
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	genesis := shardnode.BlockRef{Hash: jc.Origin.BlockHash().Bytes(), StateRoot: jc.Origin.StateRoot().Bytes()}
	exec := newRestoreExecutorFixture(genesis) // the execution client: its blocks survive the restart

	// first run: the restore from the seed pin, at the pin's root epoch
	journal = open()
	seed := src.entries[0]
	restore := &ArchiveRestore{Journal: journal, Context: jc, JournalLimits: limits, Archive: local, Subject: src.subject,
		Replicas: replicas, Host: joiner, Limits: DefaultLimits(), Adapter: exec, Genesis: genesis,
		TipUC: seed.ResultingUC, TipTR: seed.ResultingTR}
	require.NoError(t, restore.Restore(ctx))
	require.EqualValues(t, 1, exec.finalized.Number, "the restore replays the seed's block")

	newRecovery := func(journal *configuredprogress.Store) *configuredadmission.ExecutionRecovery {
		source := &RecoverySource{Context: jc, Subject: src.subject, Local: local, Host: joiner, Replicas: replicas,
			Limits: DefaultLimits(), MaxBlocks: 4}
		return &configuredadmission.ExecutionRecovery{Store: journal, Context: jc, JournalLimits: limits, Executor: exec,
			Gate: shardnode.NewFinalityGate(), Genesis: genesis,
			Limits:       configuredadmission.RecoveryLimits{Blocks: 4, Bytes: 4 << 20, Deadline: 20 * time.Second},
			FetchArchive: source.FetchSuffix, ArchiveCatchUp: &CatchUp{Source: source}}
	}
	follow := func(journal *configuredprogress.Store, height int) {
		t.Helper()
		recovery := newRecovery(journal)
		var offered *types.UnicityCertificate
		var offeredTR *certification.TechnicalRecord
		heads := &HeadFollower{Binding: CertifiedBinding{Context: jc, Subject: src.subject}, Host: joiner, Limits: DefaultLimits(),
			Sources: func() []peer.ID { return replicas }, Active: func() bool { return false },
			Offer: func(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) bool {
				offered, offeredTR = uc, tr
				return true
			}}
		require.True(t, heads.Poll(ctx), "the newest record verifies under the installed history")
		target := src.entries[height-1]
		require.Equal(t, target.ResultingUC.GetRootRoundNumber(), offered.GetRootRoundNumber(), "the replica's newest certified record is offered")
		require.EqualValues(t, 3, offered.GetRootEpoch())
		// the node's admission of the offered head, repeated as the follower re-offers an unaccepted head: the certificate is acquired
		// (the journal's own observations first, then the archive catch-up pages the gap in) until it is durable, then executed
		var head shardnode.BlockRef
		for calls := 1; ; calls++ {
			require.LessOrEqual(t, calls, 40, "the gap to %d is closed", height)
			err := recovery.AcquireForCertificate(ctx, offered, offeredTR)
			if err == nil {
				if head, err = recovery.Recover(ctx, offered); err == nil {
					break
				}
			}
			require.ErrorIs(t, err, configuredadmission.ErrRecoveryUnavailable, "call %d: a catch-up in progress, never a refusal", calls)
			require.False(t, recovery.Terminal(err), "call %d: %v", calls, err)
		}
		require.EqualValues(t, height, head.Number)
		require.EqualValues(t, height, exec.finalized.Number, "the execution client is finalized at the tip")
		state, _, err := journal.Load(ctx, jc)
		require.NoError(t, err)
		latest, ok := state.Observed()
		require.True(t, ok)
		require.EqualValues(t, 3, latest.Certificate().GetRootEpoch())
		require.Equal(t, []byte(target.Candidate.Hash), []byte(latest.Certificate().InputRecord.BlockHash))
	}

	// a record certified in an epoch the joiner has not installed is not offered: no tip is trusted because a source names it
	none := &HeadFollower{Binding: CertifiedBinding{Context: jc, Subject: src.subject}, Host: joiner, Limits: DefaultLimits(),
		Sources: func() []peer.ID { return replicas }, Active: func() bool { return false },
		Offer: func(*types.UnicityCertificate, *certification.TechnicalRecord) bool {
			t.Fatal("an unverifiable head was offered")
			return false
		}}
	require.False(t, none.Poll(ctx))
	install(2)
	require.False(t, none.Poll(ctx), "epoch 3 is still not installed")
	install(3)
	// what the joiner reached before the fix: with no certificate source but the installed handoffs' terminal certificates, the
	// recovery stops at the last block of root epoch 2 (block 78 on the public candidate)
	stalled := newRecovery(journal)
	for calls := 1; ; calls++ {
		require.LessOrEqual(t, calls, 20)
		head, err := stalled.Recover(ctx, nil)
		if err == nil {
			require.EqualValues(t, 6, head.Number, "the terminal certificate of root epoch 2")
			break
		}
		require.ErrorIs(t, err, configuredadmission.ErrRecoveryUnavailable, "call %d", calls)
	}
	follow(journal, firstRun)
	require.NoError(t, journal.Close())

	// restart: the replayed activations install epochs 2 and 3 before the journal opens. The restore completed, so the command starts
	// the node as `shard-node run` does (checkRestorePaths), never replaying the epoch-1 pin under epoch 3 again.
	checkpoint, complete, err := configuredprogress.ReadArchiveRestoreState(path)
	require.NoError(t, err)
	require.True(t, complete, "the restore installed its tip and anchor")
	pin, err := RestorePinID(seed.ResultingUC, seed.ResultingTR, [32]byte{})
	require.NoError(t, err)
	require.Equal(t, pin, checkpoint.Pin, "the completed checkpoint is still the seed pin's")
	journal = open()
	t.Cleanup(func() { _ = journal.Close() })
	require.NoError(t, journal.CheckArchiveRestoreComplete())
	serve(firstRun+1, total)
	follow(journal, total)
}
