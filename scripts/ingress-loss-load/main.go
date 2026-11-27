// ingress-loss-load supplies a single f8batch transition from each load-only shard.
// The EVM shard uses its own validators and never uses this generator.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/cli/ubft/cmd"
	"github.com/unicitynetwork/bft-core/internal/testutils/rsmtbatch"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
	"github.com/unicitynetwork/bft-core/observability"
)

func main() {
	conf := flag.String("conf", "", "load shard configuration")
	keys := flag.String("keys", "", "load shard keys")
	roots := flag.String("roots", "", "comma-separated loopback root multiaddresses")
	ready := flag.String("ready", "", "file created when the pre-state is certified")
	start := flag.String("start", "", "file that starts the batch")
	keyBit := flag.Int("key-bit", -1, "first key bit for a split shard")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := run(ctx, *conf, *keys, *roots, *ready, *start, *keyBit); err != nil {
		log.Fatal(err)
	}
}

func readJSON(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

func run(ctx context.Context, confPath, keyPath, addresses, ready, start string, keyBit int) error {
	var conf types.PartitionDescriptionRecord
	if err := readJSON(confPath, &conf); err != nil {
		return err
	}
	var keys cmd.KeyConf
	if err := readJSON(keyPath, &keys); err != nil {
		return err
	}
	var roots []peer.AddrInfo
	var ids []peer.ID
	for _, addr := range strings.Split(addresses, ",") {
		if !strings.HasPrefix(addr, "/ip4/127.0.0.1/") {
			return fmt.Errorf("expected a loopback root address, got %q", addr)
		}
		root, err := peer.AddrInfoFromString(addr)
		if err != nil {
			return err
		}
		roots, ids = append(roots, *root), append(ids, root.ID)
	}
	auth, err := keys.AuthKeyPair()
	if err != nil {
		return err
	}
	signer, err := keys.Signer()
	if err != nil {
		return err
	}
	pc, err := network.NewPeerConfiguration("/ip4/127.0.0.1/tcp/0", nil, auth, roots, nil)
	if err != nil {
		return err
	}
	p, err := network.NewPeer(ctx, pc, slog.Default(), nil)
	if err != nil {
		return err
	}
	defer p.Close()
	metrics, err := observability.NewFactory().Observability("", "")
	if err != nil {
		return err
	}
	defer metrics.Shutdown()
	net, err := network.NewShardNetwork(p, observability.WithLogger(metrics, slog.Default()), network.DefaultShardNetworkOptions)
	if err != nil {
		return err
	}
	defer net.Close()
	if err := p.BootstrapConnect(ctx, slog.Default()); err != nil {
		return err
	}
	id := p.ID().String()
	if err := net.Send(ctx, &handshake.Handshake{PartitionID: conf.PartitionID, ShardID: conf.ShardID, NodeID: id}, ids...); err != nil {
		return err
	}
	batch := rsmtbatch.New(fmt.Sprintf("%s/%s", conf.PartitionID, conf.ShardID), keyBit, 10_000, 1_000)
	pre := batch.PreRoot()
	var last *certification.CertificationResponse
	var sentRound uint64
	sent := make(map[[32]byte]bool)
	prepared := false
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for load shard %s/%s: %w", conf.PartitionID, conf.ShardID, ctx.Err())
		case <-poll.C:
		case msg := <-net.ReceivedChannel():
			var cr *certification.CertificationResponse
			switch response := msg.(type) {
			case *certification.CertificationResponse:
				cr = response
			case *certification.CertificationResponseV2:
				cr = &response.Response
			case *certification.CertificationResponseV3:
				cr = &response.Response
			}
			if cr == nil || cr.Partition != conf.PartitionID || !cr.Shard.Equal(conf.ShardID) || cr.UC.InputRecord == nil || cr.UC.UnicitySeal == nil {
				continue
			}
			if cr.Status == certification.CertStatusProofInvalid || cr.Status == certification.CertStatusFatal {
				return fmt.Errorf("load request rejected: %s", cr.Message)
			}
			if last != nil && cr.UC.GetRootRoundNumber() <= last.UC.GetRootRoundNumber() {
				continue
			}
			last = cr
		}
		if last == nil {
			continue
		}
		prev := last.UC.InputRecord.Hash
		if len(prev) == 32 && sent[[32]byte(prev)] {
			log.Printf("batch certified shard=%s round=%d root_round=%d state=%x", conf.ShardID, last.UC.GetRoundNumber(), last.UC.GetRootRoundNumber(), prev)
			return nil
		}
		if !prepared && bytes.Equal(pre[:], prev) {
			if err := os.WriteFile(ready, nil, 0600); err != nil {
				return err
			}
			prepared = true
		}
		if prepared {
			if _, err := os.Stat(start); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
		}
		tr := last.Technical
		if tr.Round <= sentRound {
			continue
		}
		ref := last.UC.UnicitySeal.Timestamp
		hash := pre
		var proof []byte
		if prepared {
			var stats rsmtbatch.Stats
			proof, hash, stats, err = batch.Envelope(ref)
			if err != nil {
				return err
			}
			log.Printf("batch sent partition=%s shard=%s round=%d bytes=%d pre=%d inserted=%d state=%x",
				conf.PartitionID, conf.ShardID, tr.Round, stats.Bytes, stats.PreLeaves, stats.Inserted, hash)
			sent[hash] = true
		}
		req := &certification.BlockCertificationRequest{
			PartitionID: conf.PartitionID, ShardID: conf.ShardID, NodeID: id, ZkProof: proof,
			InputRecord: &types.InputRecord{Version: 1, Epoch: tr.Epoch, RoundNumber: tr.Round, Timestamp: ref,
				PreviousHash: prev, Hash: hash[:], BlockHash: hash[:], SummaryValue: []byte{1}},
		}
		if err := req.Sign(signer); err != nil {
			return err
		}
		if err := net.Send(ctx, req, ids...); err != nil {
			return err
		}
		sentRound = tr.Round
	}
}
