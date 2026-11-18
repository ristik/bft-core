package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// evmAuthorityConfig selects a signing authority as the holder of the validator's EVM key (VT-10, #1201): the authority's operator socket
// and credential, and the enrolled public identity (the node info `signing-authority node-info` wrote). The registration proof of the EVM
// key is then the authority's SignRegistration; no private EVM key is on this host's disk.
type evmAuthorityConfig struct {
	Socket     string `json:"socket"`
	Credential string `json:"credential"`
	NodeInfo   string `json:"nodeInfo"`
}

// evmAuthority is a loaded evmAuthorityConfig: the enrolled identity and the way to reach the authority.
type evmAuthority struct {
	cfg    evmAuthorityConfig
	nodeID string
	pub    []byte
}

func (c evmAuthorityConfig) validate() error {
	if c.Socket == "" || c.Credential == "" || c.NodeInfo == "" {
		return fmt.Errorf("%w: evmAuthority needs socket, credential and nodeInfo", ErrValidator)
	}
	return nil
}

// loadEVMAuthority reads the enrolled identity from the node info file (paths already resolved).
func loadEVMAuthority(c evmAuthorityConfig) (*evmAuthority, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(c.NodeInfo) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, fmt.Errorf("%w: EVM authority node info: %w", ErrValidator, err)
	}
	var ni types.NodeInfo
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&ni); err != nil || ni.NodeID == "" || len(ni.SigKey) != 33 {
		return nil, fmt.Errorf("%w: %s is not a node info naming an EVM node and its 33-byte key (made by `signing-authority node-info`)", ErrValidator, c.NodeInfo)
	}
	return &evmAuthority{cfg: c, nodeID: ni.NodeID, pub: ni.SigKey}, nil
}

// Node and Public are the enrolled identity.
func (a *evmAuthority) Node() string   { return a.nodeID }
func (a *evmAuthority) Public() []byte { return bytes.Clone(a.pub) }

// Prove asks the authority for the EVM proof of the registration. It first reads the authority's enrollment and refuses unless it is the
// configured node and key; the authority computes the digest itself (the request carries typed fields, not the digest).
func (a *evmAuthority) Prove(ctx context.Context, req vrclient.ProofRequest) ([]byte, error) {
	op, err := openOperator(a.cfg.Socket, a.cfg.Credential)
	if err != nil {
		return nil, err
	}
	defer func() { _ = op.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	enrolled, key, err := op.Enrollment(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the authority's enrollment: %w", err)
	}
	if enrolled.NodeID != a.nodeID || !bytes.Equal(key, a.pub) {
		return nil, fmt.Errorf("the authority at %s is node %s with another key than the configured EVM identity %s", a.cfg.Socket, enrolled.NodeID, a.nodeID)
	}
	domain := vrschema.RegisterDomainText
	if req.Binding {
		domain = vrschema.BindingDomainText
	}
	r := req.Registration
	return op.SignRegistration(ctx, signingauthority.RegistrationRequest{Domain: domain, Owner: req.Sender, ID: req.ID, Registration: vrschema.Registration{
		RootNodeID: r.RootNodeID, RootKey: r.RootKey, EVMNodeID: r.EvmNodeID, EVMKey: r.EvmKey, Payee: r.Payee, Nonce: r.Nonce}})
}

var _ vrclient.Prover = (*evmAuthority)(nil)

// registrationPolicyFile is the JSON of `signing-authority run --registration-policy`.
type registrationPolicyFile struct {
	Network    string `json:"network"`
	ChainID    uint64 `json:"chainId"`
	Registry   string `json:"registry"`
	Authorized []struct {
		Action     string `json:"action"` // "register" or "binding"
		Owner      string `json:"owner"`
		ID         uint64 `json:"id,omitempty"`
		RootNodeID string `json:"rootNodeId"`
		RootKey    string `json:"rootKey"`
		Payee      string `json:"payee"`
	} `json:"authorized"`
}

func readRegistrationPolicy(path string) (signingauthority.RegistrationPolicy, error) {
	var p signingauthority.RegistrationPolicy
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return p, err
	}
	var f registrationPolicyFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return p, fmt.Errorf("registration policy %s: %w", path, err)
	}
	nw, err := hexutil.Decode(f.Network)
	if err != nil || len(nw) != 32 || !common.IsHexAddress(f.Registry) {
		return p, fmt.Errorf("registration policy %s: network is 32 bytes of 0x-hex and registry an address", path)
	}
	copy(p.Deployment.Network[:], nw)
	p.Deployment.ChainID = vrschema.U64(f.ChainID)
	p.Deployment.Registry = common.HexToAddress(f.Registry)
	for i, x := range f.Authorized {
		a := signingauthority.RegistrationAuthorization{ID: x.ID, RootNodeID: x.RootNodeID}
		switch x.Action {
		case "register":
			a.Domain = vrschema.RegisterDomainText
		case "binding":
			a.Domain = vrschema.BindingDomainText
		default:
			return p, fmt.Errorf("registration policy %s: entry %d: action %q is register or binding", path, i, x.Action)
		}
		rk, err := hexutil.Decode(x.RootKey)
		if err != nil || !common.IsHexAddress(x.Owner) || !common.IsHexAddress(x.Payee) {
			return p, fmt.Errorf("registration policy %s: entry %d: owner and payee are addresses, rootKey 0x-hex", path, i)
		}
		a.RootKey = rk
		a.Owner, a.Payee = common.HexToAddress(x.Owner), common.HexToAddress(x.Payee)
		p.Authorized = append(p.Authorized, a)
	}
	return p, nil
}
