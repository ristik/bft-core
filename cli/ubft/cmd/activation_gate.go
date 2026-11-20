package cmd

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/rpc"

	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrrules"
	"github.com/unicitynetwork/bft-core/vrschema"
)

const activationSourceUsage = "EVM JSON-RPC URL of the node that serves the validator registry: the node reads the committed activation schedule from it (one pinned block, " +
	"the VR deployment checked), warns when it holds a rule this binary lacks, and refuses to install or sign for a root epoch >= E of such a rule (design 7.4). " +
	"On a VR generation a shard node defaults to its own --eth-url and the fence is mandatory; on other generations empty means no fence source (the upgrade fence relies on the roots)"

const activationWatchInterval = time.Minute

// errVRFenceRequired refuses to start a role on a VR generation without its upgrade fence.
var errVRFenceRequired = errors.New("this deployment pins the validator registry, so the activation-schedule fence is mandatory")

// vrFence is what a role knows of its VR generation: whether genesis pins one and, then, its pinned registry runtime code hash.
type vrFence struct {
	VR       bool
	CodeHash *[32]byte
	// GenesisHash is this deployment's execution genesis hash and NetworkWord VR's network word (optional): the generation the endpoint must be.
	GenesisHash, NetworkWord *[32]byte
	// Anchor names the node's own certified EVM block for the read (nil: the endpoint's head).
	Anchor func(ctx context.Context) ([32]byte, uint64, error)
}

// newActivationGate is the fence of a non-root role over VR's activation schedule read at url. On a VR generation an empty url is an
// error (errVRFenceRequired) and the code hash pin is required; otherwise an empty url yields the nil gate, which fences nothing
// (logged once). The returned close releases the RPC connection.
func newActivationGate(ctx context.Context, log *slog.Logger, url string, g vrFence) (*vrrules.Gate, func(), error) {
	if url == "" {
		if g.VR {
			return nil, nil, fmt.Errorf("%w: give --activation-source-url (the shard's execution client serving VR)", errVRFenceRequired)
		}
		return vrrules.NewGate(nil, nil, log), func() {}, nil
	}
	if g.VR && g.CodeHash == nil {
		return nil, nil, fmt.Errorf("%w: the VR registry code hash pin is missing", errVRFenceRequired)
	}
	if g.VR && g.GenesisHash == nil {
		return nil, nil, fmt.Errorf("%w: the deployment's execution genesis hash pin is missing (the generation the endpoint must be)", errVRFenceRequired)
	}
	c, err := rpc.DialContext(ctx, url)
	if err != nil {
		return nil, nil, fmt.Errorf("activation schedule source %q: %w", url, err)
	}
	src := vrclient.ScheduleSource{Client: vrclient.New(c, [20]byte{}), RegistryCode: g.CodeHash, GenesisHash: g.GenesisHash, NetworkWord: g.NetworkWord, Anchor: g.Anchor}
	return vrrules.NewGate(src, nil, log), c.Close, nil
}

// parseCodeHash reads a 0x-prefixed 32-byte hex pin.
func parseCodeHash(s string) (*[32]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("a pin must be 32 bytes of hex")
	}
	var out [32]byte
	copy(out[:], b)
	return &out, nil
}

// gateCheckpoint is the gate's decision over an authenticated checkpoint schedule (nil for no gate: the roots fence).
func gateCheckpoint(g *vrrules.Gate) func(uint64, []vrschema.Activation) error {
	if g == nil {
		return nil
	}
	return g.CheckCheckpoint
}
