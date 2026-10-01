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
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-go-base/types"
)

type rootHandoffOperator interface {
	PlanHandoff(*types.RootTrustBaseV1, *evmassign.Proposal) (abdrc.HandoffApprovalMsg, error)
	AcceptHandoffIntent(abdrc.HandoffApprovalMsg) error
	EndorseHandoff(context.Context, abdrc.HandoffApprovalMsg) error
}

type rootHandoffAbortOperator interface {
	SubmitHandoffAbort(context.Context, abdrc.HandoffAbortTarget) (abdrc.HandoffAbortStatus, error)
	HandoffAbortStatus(abdrc.HandoffAbortTarget) (abdrc.HandoffAbortStatus, error)
}

type rootHandoffPlanRequest struct {
	NextTrustBase *types.RootTrustBaseV1 `json:"nextTrustBase"`
	// EVMAssignment asks for an EVM-only assignment change (H3). The root members of NextTrustBase must be
	// the installed ones; combining a root and an EVM membership change is refused.
	EVMAssignment *evmassign.Proposal `json:"evmAssignment,omitempty"`
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
		// The plan names no EVM parent: the root binds it when the Prepare is ordered.
		plan, err := operator.PlanHandoff(request.NextTrustBase, request.EVMAssignment)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(plan)
	}
}

// rootHandoffIntentHandler registers a plan another validator's endpoint built, so that whichever validator leads can order the
// Prepare for it.
func rootHandoffIntentHandler(operator rootHandoffOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var plan abdrc.HandoffApprovalMsg
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&plan) != nil {
			http.Error(w, "invalid handoff intent", http.StatusBadRequest)
			return
		}
		if err := operator.AcceptHandoffIntent(plan); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusNoContent)
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
	var nextFile, rootRPCs, nextEVMAssignment string
	var prepareTimeout time.Duration
	propose := &cobra.Command{Use: "propose", Short: "Request old-validator endorsements for a new root trust base", Long: "Plans the handoff, has the root order a Prepare for it (which freezes the EVM and binds the frozen parent), and then collects the\n" +
		"old validators' endorsements of that Prepare-bound state. The plan names no EVM parent. Endorsements are refused until the Prepare\n" +
		"is committed, so this command waits for it (--prepare-timeout); a Prepare that gets no Freeze within the lapse window is dead and the\n" +
		"command must be run again for the next attempt.", RunE: func(cmd *cobra.Command, _ []string) error {
		raw, err := os.ReadFile(nextFile)
		if err != nil {
			return err
		}
		var next types.RootTrustBaseV1
		if err = json.Unmarshal(raw, &next); err != nil {
			return err
		}
		var endpoints []string
		for _, endpoint := range strings.Split(rootRPCs, ",") {
			if endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/"); endpoint != "" {
				endpoints = append(endpoints, endpoint)
			}
		}
		if len(endpoints) == 0 {
			return errors.New("root RPC endpoints required")
		}
		client := &http.Client{Timeout: 5 * time.Second}
		planRequest := rootHandoffPlanRequest{NextTrustBase: &next}
		if nextEVMAssignment != "" {
			if planRequest.EVMAssignment, err = readEVMAssignment(nextEVMAssignment); err != nil {
				return err
			}
			if err = checkCoupledProposal(&next, planRequest.EVMAssignment); err != nil {
				return err
			}
		}
		request, err := json.Marshal(planRequest)
		if err != nil {
			return err
		}
		// 1. Plan: the first validator builds it, every validator holds it as its intent, so the leader of the moment can order the
		// Prepare.
		var plan abdrc.HandoffApprovalMsg
		if err = handoffPost(cmd.Context(), client, endpoints[0]+"/api/v1/handoff/plan", request, &plan); err != nil {
			return err
		}
		data, err := json.Marshal(plan)
		if err != nil {
			return err
		}
		for _, endpoint := range endpoints[1:] {
			if err = handoffPost(cmd.Context(), client, endpoint+"/api/v1/handoff/intent", data, nil); err != nil {
				return fmt.Errorf("validator %s refused the plan: %w", endpoint, err)
			}
		}
		// 2. Endorse the Prepare-bound state: each validator refuses until it has committed the Prepare of this plan.
		deadline := time.Now().Add(prepareTimeout)
		var wg sync.WaitGroup
		results := make(chan error, len(endpoints))
		for _, endpoint := range endpoints {
			wg.Add(1)
			go func(endpoint string) {
				defer wg.Done()
				for {
					err := handoffPost(cmd.Context(), client, endpoint+"/api/v1/handoff/endorse", data, nil)
					if err == nil || !strings.Contains(err.Error(), "before the handoff is prepared") || time.Now().After(deadline) {
						results <- err
						return
					}
					select {
					case <-cmd.Context().Done():
						results <- cmd.Context().Err()
						return
					case <-time.After(time.Second):
					}
				}
			}(endpoint)
		}
		wg.Wait()
		close(results)
		accepted := 0
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
	propose.Flags().StringVar(&nextEVMAssignment, "next-evm-assignment", "",
		"coupled validator assignment change (JSON: validators and one proof of possession per successor key, see `handoff evm-pop`)")
	propose.Flags().DurationVar(&prepareTimeout, "prepare-timeout", 60*time.Second, "how long to wait for the root to commit the Prepare before endorsing")
	propose.Flags().StringVar(&rootRPCs, "root-rpc", "", "comma-separated local old validator RPC URLs")
	_ = propose.MarkFlagRequired("next-trust-base")
	_ = propose.MarkFlagRequired("root-rpc")
	handoff.AddCommand(propose)
	handoff.AddCommand(newEVMContextCmd(), newEVMPoPCmd(), newEVMAssembleCmd(), newShardAssembleCmd())
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
