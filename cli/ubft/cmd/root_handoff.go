package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-go-base/types"
)

type rootHandoffOperator interface {
	BuildHandoffPlan(*types.RootTrustBaseV1, []byte) (abdrc.HandoffApprovalMsg, error)
	EndorseHandoff(context.Context, abdrc.HandoffApprovalMsg) error
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
		plan, err := operator.BuildHandoffPlan(request.NextTrustBase, parent)
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

func newRootCmd() *cobra.Command {
	root := &cobra.Command{Use: "root", Short: "Root chain operator commands"}
	handoff := &cobra.Command{Use: "handoff", Short: "Profile-2 validator handoff"}
	var nextFile, parent, rootRPCs string
	propose := &cobra.Command{Use: "propose", Short: "Request old-validator endorsements for a new root trust base", RunE: func(cmd *cobra.Command, _ []string) error {
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
		for _, endpoint := range endpoints {
			if err = handoffPost(cmd.Context(), client, strings.TrimRight(strings.TrimSpace(endpoint), "/")+"/api/v1/handoff/endorse", data, nil); err != nil {
				return err
			}
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "submitted %d root endorsements for epoch %d\n", len(endpoints), next.Epoch)
		return err
	}}
	propose.Flags().StringVar(&nextFile, "next-trust-base", "", "next epoch trust base JSON")
	propose.Flags().StringVar(&parent, "frozen-parent", "", "certified EVM parent block hash (32-byte hex)")
	propose.Flags().StringVar(&rootRPCs, "root-rpc", "", "comma-separated local old validator RPC URLs")
	_ = propose.MarkFlagRequired("next-trust-base")
	_ = propose.MarkFlagRequired("frozen-parent")
	_ = propose.MarkFlagRequired("root-rpc")
	handoff.AddCommand(propose)
	root.AddCommand(handoff)
	return root
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
