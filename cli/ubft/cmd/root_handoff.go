package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-go-base/types"
)

type rootHandoffOperator interface {
	BuildHandoffPlan(*types.RootTrustBaseV1, []byte) (abdrc.HandoffApprovalMsg, error)
	BuildAndEndorseHandoff(context.Context, *types.RootTrustBaseV1, []byte) (abdrc.HandoffApprovalMsg, error)
	EndorseHandoff(context.Context, abdrc.HandoffApprovalMsg) error
}

type rootHandoffAbortOperator interface {
	SubmitHandoffAbort(context.Context, abdrc.HandoffAbortTarget) (abdrc.HandoffAbortStatus, error)
	HandoffAbortStatus(abdrc.HandoffAbortTarget) (abdrc.HandoffAbortStatus, error)
}

type rootHandoffPlanRequest struct {
	NextTrustBase *types.RootTrustBaseV1 `json:"nextTrustBase"`
	FrozenParent  string                 `json:"frozenParent"`
}

func localOperatorRequest(w http.ResponseWriter, r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		http.Error(w, "local operator access required", http.StatusForbidden)
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || r.Header.Get("Origin") != "" {
		http.Error(w, "application/json without Origin required", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

func rootHandoffPlanHandler(operator rootHandoffOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var request rootHandoffPlanRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request) != nil {
			http.Error(w, "invalid handoff plan request", http.StatusBadRequest)
			return
		}
		parent, err := hex.DecodeString(strings.TrimPrefix(request.FrozenParent, "0x"))
		if err != nil {
			http.Error(w, "invalid frozen parent", http.StatusBadRequest)
			return
		}
		plan, err := operator.BuildAndEndorseHandoff(r.Context(), request.NextTrustBase, parent)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(plan)
	}
}

func rootHandoffEndorseHandler(operator rootHandoffOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var plan abdrc.HandoffApprovalMsg
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&plan) != nil {
			http.Error(w, "invalid handoff endorsement", http.StatusBadRequest)
			return
		}
		if err := operator.EndorseHandoff(r.Context(), plan); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func rootHandoffAbortHandler(operator rootHandoffAbortOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var target abdrc.HandoffAbortTarget
		if err := decodeHandoffAbortTarget(w, r, &target); err != nil {
			http.Error(w, "invalid handoff abort target", http.StatusBadRequest)
			return
		}
		status, err := operator.SubmitHandoffAbort(r.Context(), target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(status)
	}
}

func rootHandoffAbortStatusHandler(operator rootHandoffAbortOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var target abdrc.HandoffAbortTarget
		if err := decodeHandoffAbortTarget(w, r, &target); err != nil {
			http.Error(w, "invalid handoff abort target", http.StatusBadRequest)
			return
		}
		status, err := operator.HandoffAbortStatus(target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	}
}

func decodeHandoffAbortTarget(w http.ResponseWriter, r *http.Request, target *abdrc.HandoffAbortTarget) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{Use: "root", Short: "Root chain operator commands"}
	handoff := &cobra.Command{Use: "handoff", Short: "Profile-2 validator handoff"}
	var nextFile, parent, rootRPCs string
	var parentStatusURL string
	propose := &cobra.Command{Use: "propose", Short: "Request old-validator endorsements for a new root trust base", RunE: func(cmd *cobra.Command, _ []string) error {
		var parentBytes []byte
		if parent != "" {
			var err error
			parentBytes, err = hex.DecodeString(strings.TrimPrefix(parent, "0x"))
			if err != nil || len(parentBytes) != 32 {
				return errors.New("frozen parent must be a 32-byte hex block hash")
			}
		}
		if parent == "" || parentStatusURL != "" {
			if parentStatusURL == "" {
				return ErrCertifiedParentUnavailable
			}
			statusCtx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			pin, latestParent, err := certifiedParentFromStatus(statusCtx, parentStatusURL)
			cancel()
			if err != nil {
				return err
			}
			if len(parentBytes) != 0 && !bytes.Equal(parentBytes, latestParent) {
				return fmt.Errorf("%w: supplied=0x%x latest=0x%x at height %d", ErrStaleCertifiedParent, parentBytes, latestParent, pin.Height)
			}
			if len(parentBytes) == 0 {
				parentBytes = latestParent
				parent = fmt.Sprintf("0x%x", latestParent)
				fmt.Fprintf(cmd.ErrOrStderr(), "using latest certified EVM parent from %s: height=%d hash=%s\n", parentStatusURL, pin.Height, parent)
			}
		}
		raw, err := os.ReadFile(nextFile)
		if err != nil {
			return err
		}
		var next types.RootTrustBaseV1
		if err = json.Unmarshal(raw, &next); err != nil {
			return err
		}
		endpoints := strings.Split(rootRPCs, ",")
		if len(endpoints) == 0 {
			return errors.New("root RPC endpoints required")
		}
		client := &http.Client{Timeout: 5 * time.Second}
		request, err := json.Marshal(rootHandoffPlanRequest{NextTrustBase: &next, FrozenParent: parent})
		if err != nil {
			return err
		}
		var plan abdrc.HandoffApprovalMsg
		if err = handoffPost(cmd.Context(), client, strings.TrimRight(endpoints[0], "/")+"/api/v1/handoff/plan", request, &plan); err != nil {
			return err
		}
		data, err := json.Marshal(plan)
		if err != nil {
			return err
		}
		var wg sync.WaitGroup
		results := make(chan error, len(endpoints))
		for _, endpoint := range endpoints[1:] {
			wg.Add(1)
			go func(endpoint string) {
				defer wg.Done()
				results <- handoffPost(cmd.Context(), client, strings.TrimRight(strings.TrimSpace(endpoint), "/")+"/api/v1/handoff/endorse", data, nil)
			}(endpoint)
		}
		wg.Wait()
		close(results)
		accepted := 1 // the plan endpoint already endorsed the same checkpoint
		var refusals []error
		for result := range results {
			if result == nil {
				accepted++
			} else {
				refusals = append(refusals, result)
			}
		}
		if accepted < len(endpoints)*2/3+1 {
			return fmt.Errorf("only %d/%d validators endorsed: %w", accepted, len(endpoints), errors.Join(refusals...))
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "submitted %d root endorsements for epoch %d\n", accepted, next.Epoch)
		return err
	}}
	propose.Flags().StringVar(&nextFile, "next-trust-base", "", "next epoch trust base JSON")
	propose.Flags().StringVar(&parent, "frozen-parent", "", "certified EVM parent block hash (32-byte hex); defaults to current tip when --certified-parent-status-url is set")
	propose.Flags().StringVar(&parentStatusURL, "certified-parent-status-url", "", "base URL of a shard node's read-only operator status server; selects the current tip if --frozen-parent is omitted")
	propose.Flags().StringVar(&rootRPCs, "root-rpc", "", "comma-separated local old validator RPC URLs")
	_ = propose.MarkFlagRequired("next-trust-base")
	_ = propose.MarkFlagRequired("root-rpc")
	handoff.AddCommand(propose)
	var networkID, oldEpoch, attempt uint64
	var predecessorBodyID, nextBodyID, abortRPCs string
	var abortTimeout time.Duration
	abort := &cobra.Command{Use: "abort", Short: "Request an old-validator quorum abort of a prepared root handoff", RunE: func(cmd *cobra.Command, _ []string) error {
		predecessor, err := parseHandoffID(predecessorBodyID)
		if err != nil {
			return fmt.Errorf("predecessor body id: %w", err)
		}
		next, err := parseHandoffID(nextBodyID)
		if err != nil {
			return fmt.Errorf("next body id: %w", err)
		}
		endpoints := splitHandoffRPCs(abortRPCs)
		if len(endpoints) == 0 {
			return errors.New("root RPC endpoints required")
		}
		target := abdrc.HandoffAbortTarget{Network: networkID, OldEpoch: oldEpoch,
			PredecessorBodyID: predecessor, Attempt: attempt, NextBodyID: next}
		requestBody, err := json.Marshal(target)
		if err != nil {
			return err
		}
		client := &http.Client{Timeout: 5 * time.Second}
		var wg sync.WaitGroup
		accepted := make(chan error, len(endpoints))
		for _, endpoint := range endpoints {
			wg.Add(1)
			go func(endpoint string) {
				defer wg.Done()
				var status abdrc.HandoffAbortStatus
				accepted <- handoffPost(cmd.Context(), client, strings.TrimRight(endpoint, "/")+"/api/v1/handoff/abort", requestBody, &status)
			}(endpoint)
		}
		wg.Wait()
		close(accepted)
		submitted := false
		var submitErrors []error
		for err := range accepted {
			if err == nil {
				submitted = true
			} else {
				submitErrors = append(submitErrors, err)
			}
		}
		if !submitted {
			for _, endpoint := range endpoints {
				var status abdrc.HandoffAbortStatus
				if err := handoffPost(cmd.Context(), client, strings.TrimRight(endpoint, "/")+"/api/v1/handoff/abort/status", requestBody, &status); err != nil {
					continue
				}
				if status.State == "committed" {
					_, err := fmt.Fprintf(cmd.OutOrStdout(), "Abort already committed: record %s ordered at round %d; committed root block %s at round %d\n", status.RecordID, status.OrderedRound, status.CommittedRootID, status.CommittedRootRound)
					return err
				}
				if status.State == "too_late" {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "too late: matching handoff H is committed as record %s at round %d; Abort was not ordered\n", status.RecordID, status.OrderedRound)
					return errors.New("handoff already committed; operator abort cannot rewind it")
				}
			}
			return fmt.Errorf("abort approval was not submitted: %w", errors.Join(submitErrors...))
		}
		if abortTimeout <= 0 {
			abortTimeout = 2 * time.Minute
		}
		deadline := time.Now().Add(abortTimeout)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		last := abdrc.HandoffAbortStatus{State: "pending", Target: target}
		for {
			pollCtx, cancel := context.WithDeadline(cmd.Context(), deadline)
			for _, endpoint := range endpoints {
				var status abdrc.HandoffAbortStatus
				if err := handoffPost(pollCtx, client, strings.TrimRight(endpoint, "/")+"/api/v1/handoff/abort/status", requestBody, &status); err == nil {
					last = status
					if status.State == "committed" {
						cancel()
						_, err := fmt.Fprintf(cmd.OutOrStdout(), "committed Abort record %s ordered at round %d; committed root block %s at round %d\n", status.RecordID, status.OrderedRound, status.CommittedRootID, status.CommittedRootRound)
						return err
					}
					if status.State == "too_late" {
						cancel()
						_, _ = fmt.Fprintf(cmd.OutOrStdout(), "too late: matching handoff H is committed as record %s at round %d; Abort was not ordered\n", status.RecordID, status.OrderedRound)
						return errors.New("handoff already committed; operator abort cannot rewind it")
					}
				}
			}
			cancel()
			if time.Now().After(deadline) {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "abort approval submitted; outcome %s/unknown (record %s, ordered round %d)\n", last.State, last.RecordID, last.OrderedRound)
				return errors.New("timed out waiting for committed Abort evidence")
			}
			select {
			case <-cmd.Context().Done():
				return cmd.Context().Err()
			case <-ticker.C:
			}
		}
	}}
	abort.Flags().Uint64Var(&networkID, "network", 0, "network id of the old trust base")
	abort.Flags().Uint64Var(&oldEpoch, "old-epoch", 0, "old root epoch")
	abort.Flags().StringVar(&predecessorBodyID, "predecessor-body-id", "", "old trust-base body id (32-byte hex)")
	abort.Flags().Uint64Var(&attempt, "attempt", 0, "exact ordered attempt to abort")
	abort.Flags().StringVar(&nextBodyID, "next-body-id", "", "attempt's successor body id (32-byte hex)")
	abort.Flags().StringVar(&abortRPCs, "root-rpc", "", "comma-separated old validator loopback RPC URLs (through controlled tunnels)")
	abort.Flags().DurationVar(&abortTimeout, "timeout", 2*time.Minute, "maximum wait for committed Abort evidence")
	_ = abort.MarkFlagRequired("network")
	_ = abort.MarkFlagRequired("old-epoch")
	_ = abort.MarkFlagRequired("predecessor-body-id")
	_ = abort.MarkFlagRequired("attempt")
	_ = abort.MarkFlagRequired("next-body-id")
	_ = abort.MarkFlagRequired("root-rpc")
	handoff.AddCommand(abort)
	root.AddCommand(handoff)
	return root
}

func splitHandoffRPCs(value string) []string {
	var endpoints []string
	for _, endpoint := range strings.Split(value, ",") {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints
}

func parseHandoffID(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("must be exactly 32 bytes of hexadecimal data")
	}
	return decoded, nil
}

func handoffPost(ctx context.Context, client *http.Client, url string, body []byte, out any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("%s: %s: %s", url, response.Status, string(data))
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(out)
	}
	return nil
}
