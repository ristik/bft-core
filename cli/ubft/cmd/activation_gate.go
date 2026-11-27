package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"go.opentelemetry.io/otel/metric"
	"log/slog"
	"os"
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
	// B1Chain is the trusted b1 profile's ExecutionChainID (zero: no profile): a signing authority's P85 chain reference before its
	// enrollment is complete (#1222).
	B1Chain uint64
}

// posDeploymentSource is a signing authority's P85 deployment source (#1222): the PoS deployment read from the same execution client and
// under the same pins as the activation fence.
type posDeploymentSource struct{ r vrclient.PosDeploymentReader }

func (s posDeploymentSource) ReadPosDeployment(ctx context.Context, q signingauthority.PosQuery) (signingauthority.PosDeploymentView, error) {
	var v signingauthority.PosDeploymentView
	d, err := s.r.Read(ctx, q.NodeID, q.EVMKey, q.IDs)
	if err != nil {
		if errors.Is(err, vrclient.ErrPosUnavailable) {
			return v, fmt.Errorf("%w: %w", signingauthority.ErrPosPending, err)
		}
		return v, err
	}
	if d.ChainID == nil || d.ChainID.Sign() <= 0 || d.ChainID.BitLen() > 256 {
		return v, fmt.Errorf("the execution client reports no chain id")
	}
	d.ChainID.FillBytes(v.ChainID[:])
	v.Network, v.Election = d.Network, [20]byte(d.Election)
	return v, nil
}

// newPosSource is the P85 deployment source of a VR generation's authority over the activation source url, or nil without one. The
// returned close releases its RPC connection.
func newPosSource(ctx context.Context, url string, g vrFence) (signingauthority.PosSource, func(), error) {
	if url == "" || !g.VR || g.CodeHash == nil || g.GenesisHash == nil {
		return nil, func() {}, nil
	}
	c, err := rpc.DialContext(ctx, url)
	if err != nil {
		return nil, nil, fmt.Errorf("P85 deployment source %q: %w", url, err)
	}
	return posDeploymentSource{vrclient.PosDeploymentReader{RPC: c, GenesisHash: g.GenesisHash, RegistryCode: g.CodeHash, NetworkWord: g.NetworkWord}}, c.Close, nil
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

// fenceProvision is the file that ends an authority's pre-genesis enrollment mode.
type fenceProvision struct {
	B1Profile            string `json:"b1Profile"`
	ActivationSourceURL  string `json:"activationSourceUrl"`
	ExecutionGenesisHash string `json:"executionGenesisHash"`
}

// provisionFenceWhenReady waits for the provisioning file, builds the gate from it and hands it to the authority, which then signs. A file
// that does not provide a complete VR fence is reported and the authority stays disabled.
func provisionFenceWhenReady(ctx context.Context, log *slog.Logger, path string, start vrFence, startURL string, a *signingauthority.Authority, meter metric.Meter, epoch func() uint64) {
	for ctx.Err() == nil {
		raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
		if err == nil {
			if err := provisionFence(ctx, log, raw, start, startURL, a, meter, epoch); err != nil {
				log.Error("the fence provisioning is refused; the authority keeps signing nothing", "file", path, "error", err)
			}
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func provisionFence(ctx context.Context, log *slog.Logger, raw []byte, start vrFence, startURL string, a *signingauthority.Authority, meter metric.Meter, epoch func() uint64) error {
	var p fenceProvision
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return err
	}
	// a field the startup already supplied need not be in the file: the b1 profile (the registry code hash) is read only when it is there or
	// the startup has no code hash, and the genesis hash below only when the file has one
	var fileCode *[32]byte
	b1Chain := start.B1Chain
	if p.B1Profile != "" || start.CodeHash == nil {
		prof, pf, err := readB1ProfileFile(p.B1Profile)
		if err != nil {
			return fmt.Errorf("the b1 profile: %w", err)
		}
		if pf.VRHookMeasurement == nil {
			return errors.New("the b1 profile is not a VR generation's")
		}
		fileCode = &pf.VRHookMeasurement.RegistryCodeHash
		if b1Chain != 0 && b1Chain != prof.ExecutionChainID {
			return fmt.Errorf("the b1 profile given at startup is for chain %d, the provisioned one for %d", b1Chain, prof.ExecutionChainID)
		}
		b1Chain = prof.ExecutionChainID
	}
	var genesis *[32]byte // omitted in the file: the startup pin (if any) stands
	if p.ExecutionGenesisHash != "" {
		g, gerr := parseCodeHash(p.ExecutionGenesisHash)
		if gerr != nil {
			return fmt.Errorf("executionGenesisHash: %w", gerr)
		}
		genesis = g
	}
	pins, url, err := mergePins(start, startURL, p.ActivationSourceURL, fileCode, genesis)
	if err != nil {
		return err
	}
	gate, _, err := newActivationGate(ctx, log, url, pins)
	if err != nil {
		return err
	}
	if gate == nil {
		return errors.New("no activation source")
	}
	if err := gate.RegisterMetric(meter); err != nil {
		return err
	}
	// the P85 deployment source before the fence: an operator that pins as soon as signing is enabled finds it in place
	pos, _, err := newPosSource(ctx, url, pins)
	if err != nil {
		return err
	}
	if pos != nil {
		if err := a.ProvisionPosSource(pos, b1Chain); err != nil {
			return err
		}
	}
	if err := a.ProvisionFence(gate); err != nil {
		return err
	}
	go gate.Watch(ctx, activationWatchInterval, epoch)
	log.Info("signing authority fence provisioned: signing is enabled", "source", p.ActivationSourceURL)
	return nil
}

// mergePins resolves the deferred fence's pins: those the operator gave at startup (flags, registration policy) and those the provisioning
// file and its b1 profile supply. A pin present on one side and omitted on the other stands; only two present, different values conflict
// (and refuse the provisioning, so signing is never enabled over a contradiction). The gate of a deferred start thereby has the pins of an
// immediate start. It returns the pins and the activation source URL to use.
func mergePins(start vrFence, startURL, fileURL string, fileCode, fileGenesis *[32]byte) (vrFence, string, error) {
	out := start
	out.VR = true
	pick := func(name string, have, file *[32]byte) (*[32]byte, error) {
		switch {
		case have != nil && file != nil && *have != *file:
			return nil, fmt.Errorf("the %s given at startup (%x) is not the provisioned one (%x)", name, have[:], file[:])
		case have != nil:
			return have, nil
		default:
			return file, nil
		}
	}
	var err error
	if out.CodeHash, err = pick("registry code hash", start.CodeHash, fileCode); err != nil {
		return out, "", err
	}
	if out.GenesisHash, err = pick("execution genesis hash", start.GenesisHash, fileGenesis); err != nil {
		return out, "", err
	}
	url := startURL
	switch {
	case startURL != "" && fileURL != "" && startURL != fileURL:
		return out, "", fmt.Errorf("the activation source given at startup (%s) is not the provisioned one (%s)", startURL, fileURL)
	case url == "":
		url = fileURL
	}
	return out, url, nil
}
