package rootchain

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/utb"
	"github.com/unicitynetwork/bft-core/utbstore"
)

type utbMember struct {
	id     string
	key    []byte
	signer abcrypto.Signer
}

func utbCommittee(t *testing.T) []utbMember {
	var out []utbMember
	for i := 0; i < 4; i++ {
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{byte(i + 1)}, 32))
		require.NoError(t, err)
		v, _ := s.Verifier()
		pk, _ := v.MarshalPublicKey()
		pub, err := crypto.UnmarshalSecp256k1PublicKey(pk)
		require.NoError(t, err)
		id, err := peer.IDFromPublicKey(pub)
		require.NoError(t, err)
		out = append(out, utbMember{id.String(), pk, s})
	}
	return out
}

// storeWithEpochs is a store holding the genesis (epoch 1) and entries up to the given epoch, every entry signed by the first three members.
func storeWithEpochs(t *testing.T, upTo uint64) *utbstore.Store {
	ms := utbCommittee(t)
	facts := func(epoch, start uint64) utb.SuccessorFacts {
		var members []utb.Member
		for _, m := range ms {
			members = append(members, utb.Member{NodeID: m.id, Key: m.key, Weight: 1})
		}
		return utb.SuccessorFacts{Network: 5, Epoch: epoch, EpochStart: start, Members: members, Threshold: 3,
			StateHash: bytes.Repeat([]byte{0x22}, 32), ChangeRecordHash: bytes.Repeat([]byte{0x33}, 32)}
	}
	g, err := utb.BuildUnsigned(nil, facts(1, 1))
	require.NoError(t, err)
	id, err := g.EntryID()
	require.NoError(t, err)
	store, err := utbstore.Open(memorydb.New(), g, id)
	require.NoError(t, err)
	prev := g
	for e := uint64(2); e <= upTo; e++ {
		next, err := utb.BuildUnsigned(prev, facts(e, e*100))
		require.NoError(t, err)
		for _, m := range ms[:3] {
			require.NoError(t, next.Sign(m.id, m.signer))
		}
		raw, err := next.MarshalCBOR()
		require.NoError(t, err)
		_, err = store.Append(raw)
		require.NoError(t, err)
		prev = next
	}
	return store
}

func epochsOf(t *testing.T, entries [][]byte) []uint64 {
	var out []uint64
	for _, raw := range entries {
		e, err := types.DecodeRootTrustBaseV2(raw)
		require.NoError(t, err)
		out = append(out, e.Epoch)
	}
	return out
}

func TestStoreOffersChooseAtMostTwoEntriesBoundToTheUCsSignerEpoch(t *testing.T) {
	store := storeWithEpochs(t, 6)
	o := NewStoreOffers(store)
	r := generateNodeID(t)

	got, sent := o.Offer(r, 2)
	require.Equal(t, []uint64{2, 3}, epochsOf(t, got), "the signer epoch's own successor and the one before it; never the genesis")
	for i, raw := range got {
		stored, _ := store.Get(uint64(i + 2))
		require.Equal(t, stored, raw, "the stored bytes, as stored")
	}
	require.NotNil(t, sent)

	// not sent yet: offered again, unchanged
	again, _ := o.Offer(r, 2)
	require.Equal(t, []uint64{2, 3}, epochsOf(t, again))

	sent()
	none, nilSent := o.Offer(r, 2)
	require.Empty(t, none)
	require.Nil(t, nilSent, "what was offered is not offered again")

	// the next epoch's UC: only what is newer than the hint, up to the signer epoch's successor
	got, sent = o.Offer(r, 3)
	require.Equal(t, []uint64{4}, epochsOf(t, got))
	sent()

	// a repeated OLD UC never carries an entry newer than its signer epoch's successor, whatever the store has finalized since
	fresh := generateNodeID(t)
	got, _ = o.Offer(fresh, 1)
	require.Equal(t, []uint64{2}, epochsOf(t, got))

	// a recipient several epochs behind gets the two newest eligible entries (the rest is fetched, never attached)
	got, sent = o.Offer(fresh, 5)
	require.Equal(t, []uint64{5, 6}, epochsOf(t, got))
	sent()

	// the signer epoch is the tip: its successor is not final yet
	other := generateNodeID(t)
	got, _ = o.Offer(other, 6)
	require.Equal(t, []uint64{5, 6}, epochsOf(t, got))

	// no signer epoch (a certificate without a seal) offers nothing
	none, _ = o.Offer(other, 0)
	require.Empty(t, none)

	// a handshake or reconnect starts the recipient over
	o.Reset(r)
	got, _ = o.Offer(r, 2)
	require.Equal(t, []uint64{2, 3}, epochsOf(t, got))
}

func TestStoreOffersOnAStoreWithOnlyTheGenesisOfferNothing(t *testing.T) {
	o := NewStoreOffers(storeWithEpochs(t, 1))
	got, sent := o.Offer(generateNodeID(t), 1)
	require.Empty(t, got)
	require.Nil(t, sent)
}

func TestStoreOffersHintsAreBounded(t *testing.T) {
	o := NewStoreOffers(storeWithEpochs(t, 3))
	for i := 0; i < maxOfferHints+50; i++ {
		_, sent := o.Offer(generateNodeID(t), 2)
		sent()
	}
	require.LessOrEqual(t, len(o.hints), maxOfferHints)
}

type recordingSender struct {
	mu       sync.Mutex
	msgs     []any
	receiver [][]peer.ID
	fail     map[peer.ID]bool
}

func (s *recordingSender) send(_ context.Context, msg any, receivers ...peer.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs = append(s.msgs, msg)
	s.receiver = append(s.receiver, receivers)
	for _, r := range receivers {
		if s.fail[r] {
			return context.DeadlineExceeded
		}
	}
	return nil
}

func ucResponse(epoch uint64) *certification.CertificationResponse {
	return &certification.CertificationResponse{Partition: 1, Technical: certification.TechnicalRecord{Round: 7},
		UC: types.UnicityCertificate{InputRecord: &types.InputRecord{Hash: []byte{1}, BlockHash: []byte{2}}, UnicitySeal: &types.UnicitySeal{Epoch: epoch}}}
}

// Subscribers get their own version 2 message; the offer is recorded only for those whose send succeeded.
func TestSubscriptionsSendVersion2WithPerRecipientEntries(t *testing.T) {
	store := storeWithEpochs(t, 4)
	offers := NewStoreOffers(store)
	a, b := generateNodeID(t), generateNodeID(t)
	snd := &recordingSender{fail: map[peer.ID]bool{b: true}}
	subs, err := NewSubscriptions(snd.send, observability.Default(t))
	require.NoError(t, err)
	subs.offers = offers
	t.Cleanup(subs.Wait)
	require.NoError(t, subs.Subscribe(1, types.ShardID{}, a.String()))
	require.NoError(t, subs.Subscribe(1, types.ShardID{}, b.String()))

	subs.Send(context.Background(), ucResponse(2))
	subs.Wait()
	require.Len(t, snd.msgs, 2)
	for i, msg := range snd.msgs {
		v2, ok := msg.(*certification.CertificationResponseV2)
		require.True(t, ok, "%T", msg)
		require.Len(t, snd.receiver[i], 1, "one message per recipient")
		require.Equal(t, []uint64{2, 3}, epochsOf(t, func() [][]byte {
			var out [][]byte
			for _, u := range v2.TrustBaseUpdates {
				out = append(out, u)
			}
			return out
		}()))
		require.EqualValues(t, 7, v2.Technical.Round)
	}
	require.Contains(t, offers.hints, a, "a successful send is recorded")
	require.NotContains(t, offers.hints, b, "a failed send leaves the update pending")
}

func TestWithoutOffersTheLegacyResponseIsSentToAllAtOnce(t *testing.T) {
	a, b := generateNodeID(t), generateNodeID(t)
	snd := &recordingSender{}
	subs, err := NewSubscriptions(snd.send, observability.Default(t))
	require.NoError(t, err)
	t.Cleanup(subs.Wait)
	require.NoError(t, subs.Subscribe(1, types.ShardID{}, a.String()))
	require.NoError(t, subs.Subscribe(1, types.ShardID{}, b.String()))
	subs.Send(context.Background(), ucResponse(2))
	subs.Wait()
	require.Len(t, snd.msgs, 1)
	_, ok := snd.msgs[0].(*certification.CertificationResponse)
	require.True(t, ok)
	require.Len(t, snd.receiver[0], 2)
}

func TestWithOffersTreatsAResponseWithoutASealAsEpochZero(t *testing.T) {
	store := storeWithEpochs(t, 3)
	cr := ucResponse(2)
	cr.UC.UnicitySeal = nil
	msg, sent := withOffers(NewStoreOffers(store), generateNodeID(t), cr)
	v2, ok := msg.(*certification.CertificationResponseV2)
	require.True(t, ok)
	require.Empty(t, v2.TrustBaseUpdates)
	require.Nil(t, sent)
}

// The lane's capture writes the exact message about to be sent, once per recipient and highest epoch, and changes nothing about what is sent.
func TestResponseCaptureWritesTheMessageThatIsSent(t *testing.T) {
	store := storeWithEpochs(t, 3)
	offers := NewStoreOffers(store)
	dir := t.TempDir()
	tap, err := NewResponseCapture(dir)
	require.NoError(t, err)
	offers.SetTap(tap)
	a := generateNodeID(t)
	snd := &recordingSender{}
	subs, err := NewSubscriptions(snd.send, observability.Default(t))
	require.NoError(t, err)
	subs.offers = offers
	t.Cleanup(subs.Wait)
	require.NoError(t, subs.Subscribe(1, types.ShardID{}, a.String()))
	subs.Send(context.Background(), ucResponse(2))
	subs.Wait()
	files, err := filepath.Glob(filepath.Join(dir, "ucresp-e3-*.cbor"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	captured, err := os.ReadFile(files[0])
	require.NoError(t, err)
	sent, err := types.Cbor.Marshal(snd.msgs[0])
	require.NoError(t, err)
	require.Equal(t, sent, captured, "the exact bytes of the message sent")
	var v2 certification.CertificationResponseV2
	require.NoError(t, types.Cbor.Unmarshal(captured, &v2))
	require.Len(t, v2.TrustBaseUpdates, 2)

	// a message with no entries is not captured; the same recipient and epoch is not captured twice
	offers.Reset(a)
	subs.Send(context.Background(), ucResponse(2))
	subs.Wait()
	files, _ = filepath.Glob(filepath.Join(dir, "*.cbor"))
	require.Len(t, files, 1)
}
