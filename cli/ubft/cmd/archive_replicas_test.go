package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	p2ptest "github.com/libp2p/go-libp2p/core/test"
	"github.com/unicitynetwork/bft-core/archivewiring"
)

func TestConfiguredArchiveReplicasRequireOtherShardValidators(t *testing.T) {
	self, err := p2ptest.RandPeerID()
	if err != nil {
		t.Fatal(err)
	}
	first, err := p2ptest.RandPeerID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := p2ptest.RandPeerID()
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := p2ptest.RandPeerID()
	if err != nil {
		t.Fatal(err)
	}
	validators := []peer.ID{first, second}
	for _, pair := range [][]string{{self.String(), second.String()}, {first.String(), foreign.String()}, {first.String(), first.String()}} {
		if _, err := configuredArchiveReplicas(pair, validators, self); !errors.Is(err, archivewiring.ErrConfig) {
			t.Fatalf("accepted invalid replicas %v: %v", pair, err)
		}
	}
	got, err := configuredArchiveReplicas([]string{first.String(), second.String()}, validators, self)
	if err != nil || got[0] != first || got[1] != second {
		t.Fatalf("configured replicas: %v %v", got, err)
	}
}

func TestArchivePruneRequiresArchiveStore(t *testing.T) {
	if err := shardNodeRun(context.Background(), &shardNodeRunFlags{ArchivePrune: true}, nil); !errors.Is(err, archivewiring.ErrConfig) {
		t.Fatalf("pruning without archive configuration: %v", err)
	}
}
