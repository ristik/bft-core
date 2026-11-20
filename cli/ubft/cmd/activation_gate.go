package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ethereum/go-ethereum/rpc"

	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrrules"
)

const activationSourceUsage = "optional EVM JSON-RPC URL of a node that serves the validator registry (e.g. the --eth-url of an engine-api shard node): the node then reads the committed " +
	"activation schedule from it, warns when it holds a rule this binary lacks, and refuses to install or sign for a root epoch >= E of such a rule (design 7.4). " +
	"Empty: no fence source, the upgrade fence relies on the roots"

const activationWatchInterval = time.Minute

// newActivationGate is the fence of a non-root role over VR's activation schedule read at url; with an empty url there is no source and
// the nil gate fences nothing (logged once). The returned close releases the RPC connection.
func newActivationGate(ctx context.Context, log *slog.Logger, url string) (*vrrules.Gate, func(), error) {
	if url == "" {
		return vrrules.NewGate(nil, nil, log), func() {}, nil
	}
	c, err := rpc.DialContext(ctx, url)
	if err != nil {
		return nil, nil, fmt.Errorf("activation schedule source %q: %w", url, err)
	}
	return vrrules.NewGate(vrclient.ScheduleSource{Client: vrclient.New(c, [20]byte{})}, nil, log), c.Close, nil
}
