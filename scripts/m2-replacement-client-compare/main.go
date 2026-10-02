// Command m2-replacement-client-compare checks that archive catch-up plus
// paired replay produced the same receipt-complete certified history as a
// continuously running source node.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/archivewiring"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	unicitytypes "github.com/unicitynetwork/bft-go-base/types"
)

type blockEvidence struct {
	Height                uint64   `json:"height"`
	Hash                  string   `json:"blockHash"`
	StateRoot             string   `json:"stateRoot"`
	ReceiptsRoot          string   `json:"receiptsRoot"`
	RootEpoch             uint64   `json:"authorizingRootEpoch"`
	RootRound             uint64   `json:"authorizingRootRound"`
	TransactionCount      int      `json:"transactionCount"`
	SuccessfulReceipts    int      `json:"successfulReceipts"`
	ReceiptTypes          []string `json:"receiptTypes"`
	CanonicalInputSHA256  string   `json:"canonicalInputSha256"`
	AuthorizingUCSHA256   string   `json:"authorizingCertificateSha256"`
	ResultingUCSHA256     string   `json:"resultingCertificateSha256"`
	SourceAdmissionLogged bool     `json:"sourceCertificateAdmissionLogged"`
}

type report struct {
	Result               string          `json:"result"`
	SourceArchive        string          `json:"sourceArchive"`
	ReplacementArchive   string          `json:"replacementArchive"`
	SourceValidator      int             `json:"sourceValidator"`
	ReplacementValidator int             `json:"replacementValidator"`
	ComparedBlocks       int             `json:"comparedBlocks"`
	FirstHeight          uint64          `json:"firstHeight"`
	LastHeight           uint64          `json:"lastHeight"`
	Epochs               []uint64        `json:"authorizingRootEpochs"`
	PaidBlocksPerEpoch   map[uint64]int  `json:"paidBlocksPerEpoch"`
	IdleBlocksPerEpoch   map[uint64]int  `json:"idleBlocksPerEpoch"`
	Blocks               []blockEvidence `json:"blocks"`
	ReplacementRestore   string          `json:"replacementRestore"`
}

type storedBlock struct {
	request archive.Request
	record  *archive.Record
	header  gethtypes.Header
	body    gethtypes.Body
	uc      *unicitytypes.UnicityCertificate
	result  *unicitytypes.UnicityCertificate
	input   []byte
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("m2-replacement-client-compare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	sourceDir := flags.String("source-archive", "", "source node's immutable receipt-complete archive")
	replacementDir := flags.String("replacement-archive", "", "restored node's immutable receipt-complete archive")
	sourceLog := flags.String("source-log", "", "continuously running source validator debug log")
	replacementLog := flags.String("replacement-log", "", "restored validator log")
	outPath := flags.String("out", "", "machine-readable comparison report")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *sourceDir == "" || *replacementDir == "" || *sourceLog == "" || *replacementLog == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "source archive, replacement archive, both logs and --out are required")
		return 2
	}

	result, err := compare(*sourceDir, *replacementDir, *sourceLog, *replacementLog)
	if err != nil {
		fmt.Fprintln(os.Stderr, "m2-replacement-client-compare: FAIL:", err)
		return 1
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "m2-replacement-client-compare: encode report:", err)
		return 1
	}
	if err := os.WriteFile(*outPath, append(encoded, '\n'), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "m2-replacement-client-compare: write report:", err)
		return 1
	}
	fmt.Printf("PASS: compared %d certified blocks B%d..B%d; root epochs %v; paid and idle blocks present in every compared epoch; archived headers, state/receipt roots, canonical root inputs, typed receipts and BFT certificate bytes agree\n",
		result.ComparedBlocks, result.FirstHeight, result.LastHeight, result.Epochs)
	fmt.Printf("report: %s\n", *outPath)
	return 0
}

// The comparison's refusals, one sentinel each so callers and tests can tell which check refused.
var (
	ErrTooFewBlocks            = errors.New("too few receipt-complete certified blocks")
	ErrNoRestoreEvidence       = errors.New("replacement log lacks authenticated restore, handoff activation and post-boundary epoch-3 activity")
	ErrNoPostBoundaryAdmission = errors.New("replacement did not admit a certificate after the epoch boundary")
	ErrHeightGap               = errors.New("common archived range has a height gap")
	ErrNotParentLinked         = errors.New("compared source history is not parent-linked")
	ErrMissingAdmission        = errors.New("source validator has no certificate-admitted log entry for the block")
	ErrMissingRootInput        = errors.New("source validator has no verified canonical rootInput log entry for the block")
	ErrRootInputMismatch       = errors.New("source verified-execution log rootInput differs from its receipt-complete archive")
	ErrNoSuccessfulReceipt     = errors.New("paid history has no successful typed receipt")
	ErrEpochCoverage           = errors.New("root epoch lacks both paid and idle blocks")
	ErrNoEpochCrossing         = errors.New("compared history does not cross root epoch 1 -> 2")
	ErrNoRestoredBlock         = errors.New("restored validator's post-restore epoch-3 admitted block is absent from the compared history")
	ErrBlockMismatch           = errors.New("source and replacement differ")
)

// historyInput is everything compareHistories judges: the two archives' verified blocks and what the two logs say about them.
type historyInput struct {
	sourceDir, replacementDir string
	source, replacement       map[uint64]*storedBlock
	sourceAdmissions          map[string]bool
	sourceRootInputs          map[string][]byte
	replacementText           []byte
	replacementEpoch3         map[string]bool
}

func compare(sourceDir, replacementDir, sourceLog, replacementLog string) (*report, error) {
	source, err := readArchive(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("source archive: %w", err)
	}
	replacement, err := readArchive(replacementDir)
	if err != nil {
		return nil, fmt.Errorf("replacement archive: %w", err)
	}
	if len(source) < 4 || len(replacement) < 4 {
		return nil, fmt.Errorf("%w: need at least four in both archives; source=%d replacement=%d", ErrTooFewBlocks, len(source), len(replacement))
	}
	sourceAdmissions, err := certificateAdmissions(sourceLog)
	if err != nil {
		return nil, err
	}
	restoreText, err := os.ReadFile(replacementLog)
	if err != nil {
		return nil, fmt.Errorf("read replacement log: %w", err)
	}
	replacementEpoch3, err := certifiedEpoch3Hashes(replacementLog)
	if err != nil {
		return nil, err
	}
	sourceRootInputs, err := verifiedInputs(sourceLog)
	if err != nil {
		return nil, err
	}
	return compareHistories(historyInput{sourceDir: sourceDir, replacementDir: replacementDir, source: source, replacement: replacement,
		sourceAdmissions: sourceAdmissions, sourceRootInputs: sourceRootInputs, replacementText: restoreText, replacementEpoch3: replacementEpoch3})
}

func compareHistories(in historyInput) (*report, error) {
	if !bytes.Contains(in.replacementText, []byte("execution journal restored")) ||
		!bytes.Contains(in.replacementText, []byte("handoff activated")) ||
		!bytes.Contains(in.replacementText, []byte("rootEpoch=3")) {
		return nil, ErrNoRestoreEvidence
	}
	if !regexp.MustCompile(`msg="certificate admitted" .*rootEpoch=3`).Match(in.replacementText) {
		return nil, ErrNoPostBoundaryAdmission
	}
	commonHeights := make([]uint64, 0, len(in.source))
	for height := range in.source {
		if in.replacement[height] != nil {
			commonHeights = append(commonHeights, height)
		}
	}
	if len(commonHeights) < 4 {
		return nil, fmt.Errorf("%w: source and replacement share only %d", ErrTooFewBlocks, len(commonHeights))
	}
	sort.Slice(commonHeights, func(i, j int) bool { return commonHeights[i] < commonHeights[j] })
	for i := 1; i < len(commonHeights); i++ {
		if commonHeights[i] != commonHeights[i-1]+1 {
			return nil, fmt.Errorf("%w: B%d -> B%d", ErrHeightGap, commonHeights[i-1], commonHeights[i])
		}
	}

	out := &report{Result: "PASS", SourceArchive: in.sourceDir, ReplacementArchive: in.replacementDir,
		SourceValidator: 2, ReplacementValidator: 1, ComparedBlocks: len(commonHeights),
		FirstHeight: commonHeights[0], LastHeight: commonHeights[len(commonHeights)-1],
		PaidBlocksPerEpoch: map[uint64]int{}, IdleBlocksPerEpoch: map[uint64]int{},
		ReplacementRestore: "restore log includes execution journal restored, handoffs through root epoch 3, and a post-restore epoch-3 certificate admission"}
	epochSet := map[uint64]bool{}
	replacementBlockSeen := map[string]bool{}
	var previous *storedBlock
	for _, height := range commonHeights {
		a, b := in.source[height], in.replacement[height]
		if err := equalCertifiedBlock(height, a, b); err != nil {
			return nil, err
		}
		if previous != nil && a.header.ParentHash != previous.header.Hash() {
			return nil, fmt.Errorf("%w: at B%d", ErrNotParentLinked, height)
		}
		hash := fmt.Sprintf("%x", a.request.BlockHash)
		if !in.sourceAdmissions[hash] {
			return nil, fmt.Errorf("%w: B%d %s", ErrMissingAdmission, height, hash)
		}
		if rootInput, ok := in.sourceRootInputs[hash]; ok && !bytes.Equal(rootInput, a.input) {
			return nil, fmt.Errorf("%w: at B%d", ErrRootInputMismatch, height)
		} else if !ok {
			return nil, fmt.Errorf("%w: B%d %s", ErrMissingRootInput, height, hash)
		}
		epoch := a.uc.GetRootEpoch()
		epochSet[epoch] = true
		if in.replacementEpoch3[hash] {
			replacementBlockSeen[hash] = true
		}
		receiptEnvelopes, decodeErr := archivewiring.DecodeReceiptList(a.record)
		if decodeErr != nil {
			return nil, fmt.Errorf("decode receipts at B%d: %w", height, decodeErr)
		}
		typesAtHeight := make([]string, 0, len(receiptEnvelopes))
		successful := 0
		for _, raw := range receiptEnvelopes {
			var receipt gethtypes.Receipt
			if err := receipt.UnmarshalBinary(raw); err != nil {
				return nil, fmt.Errorf("decode receipt at B%d: %w", height, err)
			}
			typesAtHeight = append(typesAtHeight, fmt.Sprintf("0x%x", receipt.Type))
			if receipt.Status == gethtypes.ReceiptStatusSuccessful {
				successful++
			}
		}
		if len(a.body.Transactions) != 0 {
			if successful == 0 {
				return nil, fmt.Errorf("%w: at B%d", ErrNoSuccessfulReceipt, height)
			}
			out.PaidBlocksPerEpoch[epoch]++
		} else {
			out.IdleBlocksPerEpoch[epoch]++
		}
		out.Blocks = append(out.Blocks, blockEvidence{
			Height: height, Hash: a.header.Hash().Hex(), StateRoot: a.header.Root.Hex(),
			ReceiptsRoot: a.header.ReceiptHash.Hex(), RootEpoch: epoch,
			RootRound: a.uc.GetRootRoundNumber(), TransactionCount: len(a.body.Transactions), SuccessfulReceipts: successful,
			ReceiptTypes: typesAtHeight, CanonicalInputSHA256: digest(a.input),
			AuthorizingUCSHA256: digest(a.record.OriginalUC), ResultingUCSHA256: digest(a.record.ResultingUC),
			SourceAdmissionLogged: true,
		})
		previous = a
	}
	for epoch := range epochSet {
		out.Epochs = append(out.Epochs, epoch)
		if out.PaidBlocksPerEpoch[epoch] == 0 || out.IdleBlocksPerEpoch[epoch] == 0 {
			return nil, fmt.Errorf("%w: epoch %d (paid=%d idle=%d)", ErrEpochCoverage, epoch, out.PaidBlocksPerEpoch[epoch], out.IdleBlocksPerEpoch[epoch])
		}
	}
	sort.Slice(out.Epochs, func(i, j int) bool { return out.Epochs[i] < out.Epochs[j] })
	if !epochSet[1] || !epochSet[2] {
		return nil, fmt.Errorf("%w (epochs=%v)", ErrNoEpochCrossing, out.Epochs)
	}
	if len(replacementBlockSeen) == 0 {
		return nil, ErrNoRestoredBlock
	}
	return out, nil
}

func readArchive(dir string) (map[uint64]*storedBlock, error) {
	store, err := archive.Open(dir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	blocks := make(map[uint64]*storedBlock)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "v2-") {
			continue
		}
		manifest, err := os.ReadFile(filepath.Join(dir, entry.Name(), "manifest"))
		if err != nil || len(manifest) < 12 || string(manifest[:8]) != "ARCHIVE2" {
			return nil, fmt.Errorf("invalid v2 archive manifest %s", entry.Name())
		}
		requestLen := binary.BigEndian.Uint32(manifest[8:12])
		if requestLen == 0 || uint64(requestLen)+12 > uint64(len(manifest)) {
			return nil, fmt.Errorf("invalid archive request length in %s", entry.Name())
		}
		q, err := archive.DecodeRequest(manifest[12 : 12+requestLen])
		if err != nil {
			return nil, fmt.Errorf("decode request in %s: %w", entry.Name(), err)
		}
		rec, err := store.GetReceiptComplete(q)
		if err != nil {
			return nil, fmt.Errorf("read receipt-complete record %s: %w", entry.Name(), err)
		}
		var header gethtypes.Header
		var body gethtypes.Body
		if rlp.DecodeBytes(rec.Header, &header) != nil || rlp.DecodeBytes(rec.Body, &body) != nil || header.Number == nil {
			return nil, fmt.Errorf("decode header/body in %s", entry.Name())
		}
		if header.Hash() != commonHash(q.BlockHash) || crypto.Keccak256Hash(rec.Header) != commonHash(q.BlockHash) {
			return nil, fmt.Errorf("BFT archive request does not bind header hash in %s", entry.Name())
		}
		if header.TxHash != gethtypes.DeriveSha(gethtypes.Transactions(body.Transactions), trie.NewStackTrie(nil)) {
			return nil, fmt.Errorf("transaction root does not match at B%d", header.Number.Uint64())
		}
		if err := archivewiring.ValidateReceiptCommitments(rec); err != nil {
			return nil, fmt.Errorf("receipt commitment validation at B%d: %w", header.Number.Uint64(), err)
		}
		if len(rec.CanonicalRootInput) == 0 {
			return nil, fmt.Errorf("canonical root input is missing at B%d", header.Number.Uint64())
		}
		commitment := sha256.Sum256(rec.CanonicalRootInput)
		if !bytes.Equal(header.Extra, commitment[:]) {
			return nil, fmt.Errorf("header extraData does not commit to canonical root input at B%d", header.Number.Uint64())
		}
		var original, resulting unicitytypes.UnicityCertificate
		var originalTR, resultingTR certification.TechnicalRecord
		if decodeCanonical(rec.OriginalUC, &original) != nil || decodeCanonical(rec.ResultingUC, &resulting) != nil ||
			decodeCanonical(rec.OriginalTR, &originalTR) != nil || decodeCanonical(rec.ResultingTR, &resultingTR) != nil ||
			original.InputRecord == nil || resulting.InputRecord == nil {
			return nil, fmt.Errorf("archive BFT certificate/technical-record pair is absent or noncanonical at B%d", header.Number.Uint64())
		}
		if !bytes.Equal(resulting.InputRecord.BlockHash, q.BlockHash[:]) || !bytes.Equal(resulting.InputRecord.Hash, header.Root[:]) {
			return nil, fmt.Errorf("resulting BFT certificate does not bind block/state at B%d", header.Number.Uint64())
		}
		var companion struct {
			RootInput string   `json:"rootInput"`
			Witnesses []string `json:"witnesses"`
		}
		if json.Unmarshal(rec.Companion, &companion) != nil || len(companion.Witnesses) != 2 {
			return nil, fmt.Errorf("seal companion is absent or malformed at B%d", header.Number.Uint64())
		}
		inputHex, err := decodeHexData(companion.RootInput)
		if err != nil || !bytes.Equal(inputHex, rec.CanonicalRootInput) {
			return nil, fmt.Errorf("companion rootInput differs from canonical archive input at B%d", header.Number.Uint64())
		}
		ucWitness, err := decodeHexData(companion.Witnesses[0])
		if err != nil || !bytes.Equal(ucWitness, rec.OriginalUC) {
			return nil, fmt.Errorf("companion witness 0 is not the archived authorizing UC at B%d", header.Number.Uint64())
		}
		trWitness, err := decodeHexData(companion.Witnesses[1])
		if err != nil || !bytes.Equal(trWitness, rec.OriginalTR) {
			return nil, fmt.Errorf("companion witness 1 is not the archived authorizing TR at B%d", header.Number.Uint64())
		}
		height := header.Number.Uint64()
		if blocks[height] != nil {
			return nil, fmt.Errorf("archive contains multiple certified records for B%d", height)
		}
		blocks[height] = &storedBlock{request: q, record: rec, header: header, body: body,
			uc: &original, result: &resulting, input: bytes.Clone(rec.CanonicalRootInput)}
	}
	return blocks, nil
}

func equalCertifiedBlock(height uint64, a, b *storedBlock) error {
	if a.header.Hash() != b.header.Hash() || a.header.Root != b.header.Root || a.header.ReceiptHash != b.header.ReceiptHash {
		return fmt.Errorf("%w: block, state or receipt root at B%d", ErrBlockMismatch, height)
	}
	fields := []struct {
		name string
		a, b []byte
	}{
		{"header", a.record.Header, b.record.Header}, {"body", a.record.Body, b.record.Body},
		{"canonical root input", a.record.CanonicalRootInput, b.record.CanonicalRootInput},
		{"authorizing UC", a.record.OriginalUC, b.record.OriginalUC}, {"authorizing TR", a.record.OriginalTR, b.record.OriginalTR},
		{"resulting UC", a.record.ResultingUC, b.record.ResultingUC}, {"resulting TR", a.record.ResultingTR, b.record.ResultingTR},
		{"seal companion", a.record.Companion, b.record.Companion},
		{"receipt list", a.record.Extensions[archive.ReceiptListKey], b.record.Extensions[archive.ReceiptListKey]},
	}
	for _, field := range fields {
		if !bytes.Equal(field.a, field.b) {
			return fmt.Errorf("%w: %s at B%d", ErrBlockMismatch, field.name, height)
		}
	}
	return nil
}

func certificateAdmissions(path string) (map[string]bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read source log: %w", err)
	}
	pattern := regexp.MustCompile(`msg="certificate admitted" block=([0-9a-fA-F]{64}) height=([1-9][0-9]*)`)
	out := map[string]bool{}
	for _, match := range pattern.FindAllSubmatch(content, -1) {
		out[strings.ToLower(string(match[1]))] = true
	}
	return out, nil
}

func certifiedEpoch3Hashes(path string) (map[string]bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read replacement log: %w", err)
	}
	pattern := regexp.MustCompile(`msg="certificate admitted" block=([0-9a-fA-F]{64}) height=[1-9][0-9]* .*rootEpoch=3(?:\s|$)`)
	out := map[string]bool{}
	for _, match := range pattern.FindAllSubmatch(content, -1) {
		out[strings.ToLower(string(match[1]))] = true
	}
	return out, nil
}

func verifiedInputs(path string) (map[string][]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read source log: %w", err)
	}
	blockField := regexp.MustCompile(`(?:^|\s)blockHash=([0-9a-fA-F]{64})(?:\s|$)`)
	inputField := regexp.MustCompile(`(?:^|\s)rootInput=([0-9a-fA-F]+)(?:\s|$)`)
	out := map[string][]byte{}
	for _, line := range bytes.Split(content, []byte{'\n'}) {
		if !bytes.Contains(line, []byte(`msg="verified execution payload"`)) {
			continue
		}
		block := blockField.FindSubmatch(line)
		input := inputField.FindSubmatch(line)
		if block == nil || input == nil {
			continue
		}
		decoded, err := hex.DecodeString(string(input[1]))
		if err != nil {
			return nil, fmt.Errorf("source verified-execution log has malformed rootInput: %w", err)
		}
		out[strings.ToLower(string(block[1]))] = decoded
	}
	return out, nil
}

func decodeCanonical(raw []byte, target any) error {
	if err := unicitytypes.Cbor.Unmarshal(raw, target); err != nil {
		return err
	}
	encoded, err := unicitytypes.Cbor.Marshal(target)
	if err != nil || !bytes.Equal(encoded, raw) {
		return errors.New("noncanonical CBOR")
	}
	return nil
}

func decodeHexData(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "0x") {
		return nil, errors.New("missing 0x data prefix")
	}
	return hex.DecodeString(value[2:])
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", sum)
}

func commonHash(raw [32]byte) common.Hash { return common.Hash(raw) }
