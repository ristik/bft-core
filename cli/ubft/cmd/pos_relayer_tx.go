package cmd

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/posrelayer"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
)

// joinerFile is a joiner's identity as the operator keeps it: three secp256k1 keys (hex), two addresses and two peer ids.
type joinerFile struct {
	OwnerKey   string `json:"ownerKey"`
	RootKey    string `json:"rootKey"`
	EVMKey     string `json:"evmKey,omitempty"` // absent when the EVM key lives in a signing authority (--evm-authority-socket)
	Withdrawal string `json:"withdrawal"`
	Payee      string `json:"payee"`
	RootNodeID string `json:"rootNodeId"`
	EVMNodeID  string `json:"evmNodeId"`
	Expiry     uint64 `json:"expiry"`
}

func readECDSA(s string) (*ecdsa.PrivateKey, error) {
	b, err := hexutil.Decode(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%w: a private key must be 0x-prefixed hex", ErrPosRelayer)
	}
	return ethcrypto.ToECDSA(b)
}

func readKeyFile(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return nil, err
	}
	return readECDSA(string(raw))
}

// authorityEVM is a joiner's EVM key held by its signing authority: the delegation possession is the authority's SignDelegationPossession,
// which recomputes the digest from the payload and signs only that.
type authorityEVM struct {
	op  *service.OperatorClient
	key []byte
}

func (a authorityEVM) PublicKey() []byte { return a.key }

func (a authorityEVM) Possess(ctx context.Context, network, chain [32]byte, election [20]byte, r posrelayer.DelegationRequest) ([]byte, error) {
	return a.op.SignDelegationPossession(ctx, signingauthority.DelegationPossessionRequest{Network: network, Chain: chain, Election: election, Request: r})
}

// openOperator dials a signing authority's operator channel.
func openOperator(socket, credentialPath string) (*service.OperatorClient, error) {
	credential, err := readCredentialFile(credentialPath)
	if err != nil {
		return nil, fmt.Errorf("loading the authority operator credential: %w", err)
	}
	return service.NewOperatorClient(service.ClientConfig{Dial: service.UnixDialer(socket), Credential: credential, Timeout: 15 * time.Second})
}

func readJoiner(path string) (posrelayer.Joiner, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator supplied local file
	if err != nil {
		return posrelayer.Joiner{}, err
	}
	var f joinerFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return posrelayer.Joiner{}, fmt.Errorf("decoding joiner %q: %w", path, err)
	}
	var j posrelayer.Joiner
	var errs []error
	var e error
	if j.OwnerKey, e = readECDSA(f.OwnerKey); e != nil {
		errs = append(errs, e)
	}
	if j.RootKey, e = readECDSA(f.RootKey); e != nil {
		errs = append(errs, e)
	}
	if f.EVMKey != "" {
		var k *ecdsa.PrivateKey
		if k, e = readECDSA(f.EVMKey); e != nil {
			errs = append(errs, e)
		} else {
			j.EVM = posrelayer.LocalEVM(k)
		}
	}
	w, e1 := hexutil.Decode(f.Withdrawal)
	p, e2 := hexutil.Decode(f.Payee)
	errs = append(errs, e1, e2)
	if err := errors.Join(errs...); err != nil {
		return posrelayer.Joiner{}, fmt.Errorf("joiner %q: %w", path, err)
	}
	if len(w) != 20 || len(p) != 20 {
		return posrelayer.Joiner{}, fmt.Errorf("%w: joiner %q: withdrawal and payee are 20-byte addresses", ErrPosRelayer, path)
	}
	copy(j.Withdrawal[:], w)
	copy(j.Payee[:], p)
	j.RootNodeID, j.EVMNodeID, j.Expiry = f.RootNodeID, f.EVMNodeID, f.Expiry
	return j, nil
}

// txEnv is what every transaction command shares.
type txEnv struct {
	ethRPC, deployment, senderKey string
	client                        *rpc.Client
	mods                          posrelayer.Modules
	chain                         *big.Int
}

func (e *txEnv) flags(cmd *cobra.Command, senderRequired bool) {
	cmd.Flags().StringVar(&e.ethRPC, "eth-rpc", "", "the execution client's JSON-RPC URL")
	cmd.Flags().StringVar(&e.deployment, "pos-deployment", "", "the P85 deployment file, with the election pinned")
	cmd.Flags().StringVar(&e.senderKey, "sender-key", "", "file holding the 0x-hex private key of the account that pays for the transaction")
	_ = cmd.MarkFlagRequired("eth-rpc")
	_ = cmd.MarkFlagRequired("pos-deployment")
	if senderRequired {
		_ = cmd.MarkFlagRequired("sender-key")
	}
}

func (e *txEnv) open() error {
	dep, _, err := loadPosDeployment(e.deployment, 0)
	if err != nil {
		return err
	}
	if dep.Election == ([20]byte{}) {
		return fmt.Errorf("%w: the deployment file pins no election", ErrPosRelayer)
	}
	e.mods = posrelayer.Modules{Election: dep.Election, Custody: dep.Custody}
	e.chain = new(big.Int).SetBytes(dep.ChainID[:])
	if e.client, err = rpc.Dial(e.ethRPC); err != nil {
		return errors.Join(ErrPosRelayer, err)
	}
	return nil
}

func (e *txEnv) sender(key *ecdsa.PrivateKey) posrelayer.Sender {
	return posrelayer.Sender{Client: e.client, Key: key, ChainID: e.chain}
}

func (e *txEnv) send(cmd *cobra.Command, key *ecdsa.PrivateKey, to [20]byte, value *big.Int, data []byte, what string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Minute)
	defer cancel()
	h, err := e.sender(key).Send(ctx, to, value, data)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrPosRelayer, what, err)
	}
	cmd.PrintErrf("%s: %s\n", what, h)
	return nil
}

// newPosTxCmd is `ubft pos-relayer tx`: the relayer's transactions on the election and custody modules. None of them needs authority: the
// possession-proof submission and the finalization are open to anyone, and a joiner's onboarding is signed by the joiner's own keys.
func newPosTxCmd() *cobra.Command {
	root := &cobra.Command{Use: "tx", Short: "send the relayer's transactions to the election and custody modules"}

	var env txEnv
	var resultHex, popsFile string
	resultID := func() ([32]byte, error) {
		var r [32]byte
		b, err := hex.DecodeString(strings.TrimPrefix(resultHex, "0x"))
		if err != nil || len(b) != 32 {
			return r, fmt.Errorf("%w: --result-id must be 32 bytes of hex", ErrPosRelayer)
		}
		copy(r[:], b)
		return r, nil
	}
	submit := &cobra.Command{
		Use:   "submit-pops",
		Short: "submit the members' EVM possession proofs for a published result (election.submitAssignmentPoPs)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := resultID()
			if err != nil {
				return err
			}
			pops, err := readPoPFiles(popsFile)
			if err != nil {
				return err
			}
			key, err := readKeyFile(env.senderKey)
			if err != nil {
				return err
			}
			if err := env.open(); err != nil {
				return err
			}
			defer env.client.Close()
			data, err := posrelayer.SubmitPoPsCalldata(r, pops)
			if err != nil {
				return err
			}
			return env.send(cmd, key, env.mods.Election, nil, data, "submitAssignmentPoPs")
		},
	}
	env.flags(submit, true)
	submit.Flags().StringVar(&resultHex, "result-id", "", "the election result")
	submit.Flags().StringVar(&popsFile, "evm-pops", "", "the collected EVM possession proofs (`pos-relayer assemble` output), in member order")
	_ = submit.MarkFlagRequired("result-id")
	_ = submit.MarkFlagRequired("evm-pops")

	var fenv txEnv
	var fres string
	finalize := &cobra.Command{
		Use:   "finalize",
		Short: "finalize a result whose possession proofs are in (election.finalizeCandidate)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resultHex = fres
			r, err := resultID()
			if err != nil {
				return err
			}
			key, err := readKeyFile(fenv.senderKey)
			if err != nil {
				return err
			}
			if err := fenv.open(); err != nil {
				return err
			}
			defer fenv.client.Close()
			data, err := posrelayer.FinalizeCalldata(r)
			if err != nil {
				return err
			}
			return fenv.send(cmd, key, fenv.mods.Election, nil, data, "finalizeCandidate")
		},
	}
	fenv.flags(finalize, true)
	finalize.Flags().StringVar(&fres, "result-id", "", "the election result")
	_ = finalize.MarkFlagRequired("result-id")

	var jenv txEnv
	var joinerPath, valueWei, evmSocket, evmCredential string
	var idFlag uint64
	join := &cobra.Command{
		Use:   "join register|bond|admit",
		Short: "onboard a joiner: register its identity, bond its stake, admit its delegation (the nomination of its EVM validator)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			j, err := readJoiner(joinerPath)
			if err != nil {
				return err
			}
			if evmSocket != "" || evmCredential != "" {
				if j.EVM != nil {
					return errBothKeyHolders
				}
				if evmSocket == "" || evmCredential == "" {
					return fmt.Errorf("%w: --evm-authority-socket needs --evm-authority-credential", ErrPosRelayer)
				}
				op, err := openOperator(evmSocket, evmCredential)
				if err != nil {
					return err
				}
				defer func() { _ = op.Close() }()
				_, key, err := op.Enrollment(cmd.Context())
				if err != nil {
					return fmt.Errorf("%w: the authority's key: %v", ErrPosRelayer, err)
				}
				j.EVM = authorityEVM{op: op, key: key}
			}
			if j.EVM == nil {
				return fmt.Errorf("%w: the joiner has no EVM key: give evmKey in the joiner file or --evm-authority-socket", ErrPosRelayer)
			}
			sender := j.OwnerKey
			if jenv.senderKey != "" {
				if sender, err = readKeyFile(jenv.senderKey); err != nil {
					return err
				}
			}
			if err := jenv.open(); err != nil {
				return err
			}
			defer jenv.client.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			rd := posrelayer.RPCReader{Client: jenv.client}
			switch args[0] {
			case "register":
				data, id, err := j.RegisterCalldata(ctx, rd, jenv.mods, jenv.chain)
				if err != nil {
					return err
				}
				if err := jenv.send(cmd, j.OwnerKey, jenv.mods.Custody, nil, data, "register"); err != nil {
					return err
				}
				cmd.PrintErrf("custody id %d\n", id)
				fmt.Fprintln(cmd.OutOrStdout(), id)
				return nil
			case "bond":
				v, ok := new(big.Int).SetString(valueWei, 10)
				if !ok || v.Sign() <= 0 || idFlag == 0 {
					return fmt.Errorf("%w: bond needs --id and --value-wei", ErrPosRelayer)
				}
				data, err := posrelayer.BondCalldata(idFlag)
				if err != nil {
					return err
				}
				return jenv.send(cmd, sender, jenv.mods.Custody, v, data, "bond")
			case "admit":
				if idFlag == 0 {
					return fmt.Errorf("%w: admit needs --id", ErrPosRelayer)
				}
				data, err := j.AdmitCalldata(ctx, rd, jenv.mods, jenv.chain, idFlag)
				if err != nil {
					return err
				}
				return jenv.send(cmd, sender, jenv.mods.Election, nil, data, "admitDelegation")
			}
			return fmt.Errorf("%w: unknown join step %q (register, bond, admit)", ErrPosRelayer, args[0])
		},
	}
	jenv.flags(join, false)
	join.Flags().StringVar(&joinerPath, "joiner", "", "the joiner's identity file (ownerKey, rootKey, evmKey, withdrawal, payee, rootNodeId, evmNodeId, expiry)")
	join.Flags().Uint64Var(&idFlag, "id", 0, "the joiner's custody id (register prints it)")
	join.Flags().StringVar(&valueWei, "value-wei", "", "bond: the stake in wei")
	join.Flags().StringVar(&evmSocket, "evm-authority-socket", "", "operator socket of the signing authority that holds the joiner's EVM key (instead of evmKey in the joiner file)")
	join.Flags().StringVar(&evmCredential, "evm-authority-credential", "", "operator credential of that authority")
	_ = join.MarkFlagRequired("joiner")

	root.AddCommand(submit, finalize, join)
	return root
}
