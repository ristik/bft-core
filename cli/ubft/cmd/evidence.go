package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/cobra"

	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-core/posrelayer"
	"github.com/unicitynetwork/bft-core/rootevidence"
)

// ErrEvidence is a refusal of the evidence command.
var ErrEvidence = errors.New("evidence")

// newEvidenceCmd is `ubft evidence`: the permissionless side of the root vote evidence service (S3). It reads observer journals (copies: a
// running root holds its file) and submits actual signed conflicts through the Evidence contract. It holds a funded EVM account only, never a
// root or owner key.
func newEvidenceCmd() *cobra.Command {
	root := &cobra.Command{Use: "evidence", Short: "root vote evidence: scan observer journals, submit and settle offences"}

	var journals []string
	var ethRPC, evidenceHex, senderKey, offenderKey string
	var assignments []string
	var settle bool

	scan := &cobra.Command{
		Use:   "scan",
		Short: "merge the observer journals and list the offences (slots with two different signed statements)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			col, closeAll, err := collectJournals(journals)
			if err != nil {
				return err
			}
			defer closeAll()
			type row struct {
				Author, Key      string
				Epoch, Round     uint64
				DigestA, DigestB string
			}
			var rows []row
			for _, p := range col.Pairs() {
				a, b := p.First.Digest(), p.Second.Digest()
				rows = append(rows, row{p.Author, hex.EncodeToString(p.Key), p.Epoch, p.Round, hex.EncodeToString(a[:]), hex.EncodeToString(b[:])})
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				Pairs []row
				Slots int
				Gaps  int
			}{rows, len(col.Slots), col.Gaps})
		},
	}
	scan.Flags().StringArrayVar(&journals, "journal", nil, "an observer journal file (repeat for several roots)")
	_ = scan.MarkFlagRequired("journal")

	submit := &cobra.Command{
		Use:   "submit",
		Short: "submit every offence found in the journals through Evidence.submitEvidence, once, and optionally settle the cases",
		RunE: func(cmd *cobra.Command, _ []string) error {
			col, closeAll, err := collectJournals(journals)
			if err != nil {
				return err
			}
			defer closeAll()
			ev, err := parseAddress20(evidenceHex)
			if err != nil {
				return err
			}
			var ids [][32]byte
			for _, a := range assignments {
				b, err := hex.DecodeString(strings.TrimPrefix(a, "0x"))
				if err != nil || len(b) != 32 {
					return fmt.Errorf("%w: --assignment must be 32 bytes of hex", ErrEvidence)
				}
				ids = append(ids, [32]byte(b))
			}
			key, err := readKeyFile(senderKey)
			if err != nil {
				return err
			}
			client, err := rpc.Dial(strings.TrimSpace(strings.Split(ethRPC, ",")[0]))
			if err != nil {
				return errors.Join(ErrEvidence, err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
			defer cancel()
			var chainHex string
			if err := client.CallContext(ctx, &chainHex, "eth_chainId"); err != nil {
				return err
			}
			chain, ok := new(big.Int).SetString(strings.TrimPrefix(chainHex, "0x"), 16)
			if !ok {
				return fmt.Errorf("%w: bad chain id %q", ErrEvidence, chainHex)
			}
			// reads at the head, not at a block pinned before the first transaction: the submitter reads the case it just created and the settlement cursor after each
			// transaction (a pinned reader reported a successful submission as "the case does not exist" on the live devnet)
			rd := evidenceReader(client)
			// a comma-separated --eth-rpc sends every transaction to each client (the lane's validators do not gossip); reads and the first answer use the first
			urls := strings.Split(ethRPC, ",")
			var also []*rpc.Client
			for _, u := range urls[1:] {
				c, err := rpc.Dial(strings.TrimSpace(u))
				if err != nil {
					return errors.Join(ErrEvidence, err)
				}
				defer c.Close()
				also = append(also, c)
			}
			s := &rootevidence.Submitter{Reader: rd, Sender: posrelayer.Sender{Client: client, Key: key, ChainID: chain, Also: also}, Evidence: ev, ChainID: chain, Assignments: ids}
			pairs, err := pairsOfOffender(col.Pairs(), offenderKey)
			if err != nil {
				return err
			}
			var firstErr error
			for _, p := range pairs {
				res, err := s.Submit(ctx, p)
				if err != nil {
					cmd.PrintErrf("epoch %d round %d %s: %v\n", p.Epoch, p.Round, p.Author, err)
					firstErr = errors.Join(firstErr, err)
					continue
				}
				cmd.Printf("epoch %d round %d %s: %s case=%x tx=%s %s\n", p.Epoch, p.Round, p.Author, res.Outcome, res.CaseID, res.TxHash, res.Reason)
				if settle && (res.Outcome == rootevidence.Submitted || res.Outcome == rootevidence.AlreadyAdmitted) {
					n, err := s.Settle(ctx, res.CaseID)
					if err != nil {
						firstErr = errors.Join(firstErr, err)
						continue
					}
					cmd.Printf("  settled in %d transactions\n", n)
				}
			}
			return firstErr
		},
	}
	submit.Flags().StringArrayVar(&journals, "journal", nil, "an observer journal file (repeat for several roots)")
	submit.Flags().StringVar(&ethRPC, "eth-rpc", "", "the execution client's JSON-RPC URL; a comma-separated list sends every transaction to each of them (reads and the first answer use the first), for validators whose pools do not gossip")
	submit.Flags().StringVar(&evidenceHex, "evidence", "", "the deployed Evidence module (20-byte hex)")
	submit.Flags().StringArrayVar(&assignments, "assignment", nil, "a candidate assignment id the offence's exposure is resolved among (repeat)")
	submit.Flags().StringVar(&senderKey, "sender-key", "", "file holding the 0x-hex private key of the funded account that sends the transactions")
	submit.Flags().StringVar(&offenderKey, "offender-key", "", "submit only the offences of this public key (hex, as `evidence scan` prints it); default: every offence in the journals")
	submit.Flags().BoolVar(&settle, "settle", false, "also settle each admitted case (permissionless, resumable)")
	for _, f := range []string{"journal", "eth-rpc", "evidence", "assignment", "sender-key"} {
		_ = submit.MarkFlagRequired(f)
	}
	root.AddCommand(scan, submit)
	return root
}

// evidenceReader reads the execution client's latest state: every transaction the submitter sends changes what its next read must see.
func evidenceReader(client *rpc.Client) posrelayer.RPCReader {
	return posrelayer.RPCReader{Client: client}
}

// pairsOfOffender keeps the paired slots of one offender key (hex, optional 0x); an empty key keeps all of them. A key which matches nothing is an error, not a silent no-op.
func pairsOfOffender(pairs []*rootevidence.SlotRecord, keyHex string) ([]*rootevidence.SlotRecord, error) {
	if keyHex == "" {
		return pairs, nil
	}
	key, err := hex.DecodeString(strings.TrimPrefix(keyHex, "0x"))
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("%w: --offender-key is not hex", ErrEvidence)
	}
	var out []*rootevidence.SlotRecord
	for _, p := range pairs {
		if bytes.Equal(p.Key, key) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no offence of key %s in the journals", ErrEvidence, keyHex)
	}
	return out, nil
}

func parseAddress20(s string) ([20]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 20 {
		return [20]byte{}, fmt.Errorf("%w: --evidence must be a 20-byte address", ErrEvidence)
	}
	return [20]byte(b), nil
}

func collectJournals(paths []string) (*rootevidence.Collection, func(), error) {
	var js []*rootevidence.Journal
	var closers []func()
	closeAll := func() {
		for _, c := range closers {
			c()
		}
	}
	for _, p := range paths {
		db, err := boltdb.New(p)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("%w: journal %q: %v", ErrEvidence, p, err)
		}
		closers = append(closers, func() { _ = db.Close() })
		j, err := rootevidence.NewJournal(db, 0)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		js = append(js, j)
	}
	col, err := rootevidence.Collect(js...)
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	return col, closeAll, nil
}
