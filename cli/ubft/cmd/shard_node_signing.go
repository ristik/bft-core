package cmd

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
)

// shardNodeSigningFlags select how a shard node signs its certification requests.
type shardNodeSigningFlags struct {
	SigningAuthoritySocket     string
	SigningAuthorityCredential string
	SigningAuthorityTimeout    time.Duration
}

func (f *shardNodeSigningFlags) addSigningAuthorityFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.SigningAuthoritySocket, "signing-authority-socket", "",
		"sign certification requests through the signing authority on this Unix socket (#105). The node then keeps no local signer, "+
			"and abstains whenever the authority refuses or cannot be reached. Not set: the key configuration's signing key signs, as before")
	cmd.Flags().StringVar(&f.SigningAuthorityCredential, "signing-authority-credential", "",
		"with --signing-authority-socket: path to the client credential written by `signing-authority replace-session`")
	cmd.Flags().DurationVar(&f.SigningAuthorityTimeout, "signing-authority-timeout", 0,
		"with --signing-authority-socket: bound on one authority operation (default: the shard's T2 timeout)")
}

// certificationSigning is how this node signs certification requests. Exactly one of local and
// authority is set.
type certificationSigning struct {
	// local is the key configuration's signer. It is nil when an authority signs: that node neither
	// keeps nor passes on a local signer, so the round has none to fall back to. (localSigningKey
	// builds a temporary one only to derive the public key it compares against the configuration.)
	local abcrypto.Signer
	// authority is installed on the round in place of the local key.
	authority shardnode.CertificationSigner
	// deferred is set instead of a fixed expected key when a RESTORING node's shard configuration does not name it yet (a joiner): the
	// key is bound from the verified handoff history (noteJoinerStep, finishJoinerKey), and the signer signs nothing until then.
	deferred *shardnode.DeferredAuthoritySigner
	nodeID   string
	// joinerKey is the key the LATEST verified installed step that names this node gives it, recorded as the steps are replayed and bound
	// once (finishJoinerKey) when the replay is complete. localKey is the key configuration's own signing key, which no installed
	// configuration may name for a node signed by an authority.
	joinerKey   abcrypto.Verifier
	joinerEpoch uint64
	localKey    []byte
	describe    string
	close       func()
}

/*
buildCertificationSigning decides, once at startup, whether the local key or a signing authority
signs.

With an authority, every trust decision the shard side makes comes from this node's own
configuration and nothing else:

  - The key responses must verify under is the one the shard configuration names for this node,
    which is the key the root chain verifies this node's requests under. It is never read from the
    authority.
  - A configuration naming the key configuration's own signing key is refused. An authority cannot
    hold that key (it has no import), so every response would fail verification; more to the point,
    such a configuration means this validator is still set up to sign locally.
  - The node holds a client credential and nothing else. It cannot replace a session, read the
    authority's state or complete its enrollment: those need the operator credential, which is not
    a flag of this command.

Setting an authority flag without the socket is refused rather than ignored, so that a mistyped
deployment does not start signing with the local key.
*/
func buildCertificationSigning(flags *shardNodeSigningFlags, keyConf *KeyConf, shardConf *types.PartitionDescriptionRecord, deriveKey bool) (*certificationSigning, error) {
	if flags.SigningAuthoritySocket == "" {
		if flags.SigningAuthorityCredential != "" || flags.SigningAuthorityTimeout != 0 {
			return nil, errors.New("--signing-authority-credential or --signing-authority-timeout is set without --signing-authority-socket; " +
				"refusing to sign with the local key when an authority was configured")
		}
		signer, err := keyConf.Signer()
		if err != nil {
			return nil, fmt.Errorf("creating signer: %w", err)
		}
		return &certificationSigning{local: signer, describe: "local key", close: func() {}}, nil
	}
	if flags.SigningAuthorityCredential == "" {
		return nil, errors.New("--signing-authority-socket requires --signing-authority-credential")
	}

	nodeID, err := keyConf.NodeID()
	if err != nil {
		return nil, err
	}
	var named *types.NodeInfo
	for _, v := range shardConf.Validators {
		if v.NodeID == nodeID.String() {
			named = v
			break
		}
	}
	if named == nil && deriveKey {
		// A joiner starts (restoring, or restarting) before the genesis configuration names it: the authority's expected key comes from the
		// activated assignment of a verified, installed handoff bundle (catch-up on a restore; the persisted steps replayed on a restart),
		// never from a flag. deriveKey is set only when there is verified handoff history to derive it from.
		credential, err := readCredentialFile(flags.SigningAuthorityCredential)
		if err != nil {
			return nil, fmt.Errorf("loading the signing authority credential: %w", err)
		}
		timeout := flags.SigningAuthorityTimeout
		if timeout <= 0 {
			timeout = shardConf.T2Timeout
		}
		client, err := service.NewClient(service.ClientConfig{
			Dial: service.UnixDialer(flags.SigningAuthoritySocket), Credential: credential, Timeout: timeout,
		})
		if err != nil {
			return nil, err
		}
		deferred, err := shardnode.NewDeferredAuthoritySigner(client)
		if err != nil {
			_ = client.Close()
			return nil, err
		}
		return &certificationSigning{
			authority: deferred, deferred: deferred, nodeID: nodeID.String(), localKey: localSigningKeyBytes(keyConf),
			describe: fmt.Sprintf("signing authority at %s, key to be bound from the verified handoff history", flags.SigningAuthoritySocket),
			close:    func() { _ = client.Close() },
		}, nil
	}
	if named == nil {
		return nil, fmt.Errorf("the shard configuration does not name this node (%s), so there is no authority key to verify responses under", nodeID)
	}
	authorityKey, err := abcrypto.NewVerifierSecp256k1(named.SigKey)
	if err != nil {
		return nil, fmt.Errorf("the shard configuration's signing key for this node: %w", err)
	}
	if local, ok := localSigningKey(keyConf); ok && bytes.Equal(local, named.SigKey) {
		return nil, errors.New("the shard configuration names this node's local signing key from the key configuration, not a signing authority's key; " +
			"generate the configuration from `signing-authority node-info`")
	}

	credential, err := readCredentialFile(flags.SigningAuthorityCredential)
	if err != nil {
		return nil, fmt.Errorf("loading the signing authority credential: %w", err)
	}
	// A signature that arrives after T2 is of no use to this round, so T2 is the natural bound.
	timeout := flags.SigningAuthorityTimeout
	if timeout <= 0 {
		timeout = shardConf.T2Timeout
	}
	client, err := service.NewClient(service.ClientConfig{
		Dial: service.UnixDialer(flags.SigningAuthoritySocket), Credential: credential, Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}
	signer, err := shardnode.NewAuthoritySigner(client, authorityKey)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	fingerprint := sha256.Sum256(named.SigKey)
	return &certificationSigning{
		authority: signer,
		describe:  fmt.Sprintf("signing authority at %s, key fingerprint %x", flags.SigningAuthoritySocket, fingerprint),
		close:     func() { _ = client.Close() },
	}, nil
}

// localSigningKey is the public half of the key configuration's signing key, when it has a usable
// one. The signer built to derive it is not kept.
func localSigningKey(keyConf *KeyConf) ([]byte, bool) {
	if len(keyConf.SigKey.PrivateKey) == 0 {
		return nil, false
	}
	signer, err := keyConf.Signer()
	if err != nil {
		return nil, false
	}
	verifier, err := signer.Verifier()
	if err != nil {
		return nil, false
	}
	pub, err := verifier.MarshalPublicKey()
	if err != nil {
		return nil, false
	}
	return pub, true
}

// localSigningKeyBytes is the key configuration's own public signing key, nil when it has none.
func localSigningKeyBytes(keyConf *KeyConf) []byte {
	key, _ := localSigningKey(keyConf)
	return key
}
