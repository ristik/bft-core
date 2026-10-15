package rootchain

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	"go.opentelemetry.io/otel/metric"

	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/observability"
	"github.com/unicitynetwork/bft-go-base/types"
)

const responsesPerSubscription = 2

type Subscriptions struct {
	mu     sync.RWMutex
	subs   map[partitionShard]map[peer.ID]int
	sender func(ctx context.Context, msg any, receivers ...peer.ID) error

	// sending tracks the goroutines spawned by Send. Without it those goroutines
	// outlive their caller unobserved: the node has no way to drain them at
	// shutdown, and a test has no way to know the send it triggered has finished
	// logging - which is how CI run 34102642015 attempt 1 died, with the testing
	// package panicking on "Log in goroutine after Test_Subscriptions/send,_not_
	// subscribed has completed".
	sending sync.WaitGroup

	// offers, when set, makes every response a version 2 response with the entries chosen for its recipient
	offers EntryOffers

	log *slog.Logger

	bcRespSent metric.Int64Counter // number of Block Certification Responses sent
}

func NewSubscriptions(sender func(ctx context.Context, msg any, receivers ...peer.ID) error, obs Observability) (*Subscriptions, error) {
	r := &Subscriptions{
		subs:   map[partitionShard]map[peer.ID]int{},
		sender: sender,
		log:    obs.Logger(),
	}

	meter := obs.Meter("rootchain.node")

	var err error
	r.bcRespSent, err = meter.Int64Counter("block.cert.rsp", metric.WithDescription("Number of Block Certification Responses sent (ie how many subscribers the node had)"))
	if err != nil {
		return nil, fmt.Errorf("creating Block Certification Responses counter: %w", err)
	}

	return r, nil
}

func (s *Subscriptions) Subscribe(partition types.PartitionID, shard types.ShardID, nodeId string) error {
	peerID, err := peer.Decode(nodeId)
	if err != nil {
		return fmt.Errorf("invalid receiver id: %w", err)
	}
	id := partitionShard{partition: partition, shard: shard.Key()}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, found := s.subs[id]; !found {
		s.subs[id] = make(map[peer.ID]int)
	}
	s.subs[id][peerID] = responsesPerSubscription
	return nil
}

func (s *Subscriptions) Send(ctx context.Context, cr *certification.CertificationResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	subs := s.subs[partitionShard{cr.Partition, cr.Shard.Key()}]
	recipients := make([]peer.ID, 0, len(subs))
	for peerID, cnt := range subs {
		if cnt == 0 {
			delete(subs, peerID)
			continue
		}

		subs[peerID]--
		recipients = append(recipients, peerID)
	}

	s.sending.Add(1)
	go func() {
		defer s.sending.Done()
		s.log.DebugContext(ctx, fmt.Sprintf("sending CertificationResponse, %d receivers, R_next: %d, IR Hash: %X, Block Hash: %X",
			len(recipients), cr.Technical.Round, cr.UC.InputRecord.Hash, cr.UC.InputRecord.BlockHash), logger.Shard(cr.Partition, cr.Shard))
		if len(recipients) > 0 {
			if s.offers != nil {
				// the entries differ per recipient (what it was already offered), so each gets its own message
				for _, r := range recipients {
					msg, sent := withOffers(s.offers, r, cr)
					if err := s.sender(ctx, msg, r); err != nil {
						s.log.WarnContext(ctx, "sending certification result", logger.Error(err), logger.Shard(cr.Partition, cr.Shard))
					} else if sent != nil {
						sent()
					}
				}
			} else if err := s.sender(ctx, cr, recipients...); err != nil {
				s.log.WarnContext(ctx, "sending certification result", logger.Error(err), logger.Shard(cr.Partition, cr.Shard))
			}
			s.bcRespSent.Add(ctx, int64(len(recipients)), observability.Shard(cr.Partition, cr.Shard))
		}
	}()
}

/*
Wait blocks until every goroutine spawned by Send so far has finished. It does not
stop new Sends - the caller is responsible for having closed the path that triggers
them (cancelling the context the node runs under) before waiting.
*/
func (s *Subscriptions) Wait() { s.sending.Wait() }

// withOffers is the message to send to one recipient: the response itself, or the version 2 response with the entries chosen for it, and the function that
// records the offer once the send succeeded. The attachments are chosen from the UC's own signer epoch, so a repeated old UC is never described as signed
// by a newer committee.
func withOffers(offers EntryOffers, recipient peer.ID, cr *certification.CertificationResponse) (any, func()) {
	if offers == nil {
		return cr, nil
	}
	var epoch uint64
	if cr.UC.UnicitySeal != nil {
		epoch = cr.UC.UnicitySeal.Epoch
	}
	entries, sent := offers.Offer(recipient, epoch)
	msg := certification.NewCertificationResponseV2(cr, entries)
	if t, ok := offers.(tapper); ok {
		t.Tap(recipient, msg)
	}
	return msg, sent
}
