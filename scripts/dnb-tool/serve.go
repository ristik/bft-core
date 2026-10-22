package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// lockProofServe is the testnet's lock-proof endpoint (TN-B, briefs/tnb-without-host.md): stateless, read-only (a read-only archive mount and eth_getProof on
// the paired client) and rate limited. It serves exactly what `dnb-tool lockproof` writes:
//
//	dnb-tool lockproof-serve --listen 0.0.0.0:8090 --archive /archive --eth-url http://shard1:8545 --vault 0x.. --cfg 0x.. --full-shard-conf F --trust-bundle B
//
//	GET /v1/lockproof?block=0x<32-byte hash>&nonce=<decimal>  200 application/cbor (the canonical LockProof)
//	                                                          400 malformed, 404 block not archived (yet) or no lock with that nonce there,
//	                                                          429 rate limited or busy, 502 the paired client failed
//	GET /healthz                                              200
func lockProofServe(args []string) error {
	fs := flag.NewFlagSet("lockproof-serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8090", "listen address")
	archiveDir := fs.String("archive", "", "a validator's immutable archive v2 directory (mounted read-only)")
	ethURL := fs.String("eth-url", "", "the paired client's plain endpoint")
	vaultText := fs.String("vault", "", "vault address")
	fullConf := fs.String("full-shard-conf", "", "the EVM shard's full configuration (as registered with the root chain)")
	trustBundlePath := fs.String("trust-bundle", "", "the trust-base release bundle (trust-bundle)")
	cfgHash := fs.String("cfg", "", "the vault's CFG")
	trustedProxy := fs.String("trusted-proxy", "", "the one peer address whose X-Forwarded-For names the client")
	if err := fs.Parse(args); err != nil {
		return err
	}
	src, err := newLockProofSource(*archiveDir, *ethURL, *vaultText, *fullConf, *trustBundlePath, *cfgHash)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: *listen, Handler: newProofHandler(src, *trustedProxy, defaultProofLimits), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	log.Printf("lock-proof endpoint on %s (vault %s)", *listen, src.vault)
	return srv.ListenAndServe()
}

type proofBuilder interface {
	build(ctx context.Context, blockHash common.Hash, nonce uint64) ([]byte, error)
}

// proofLimits: a proof is an archive read plus one eth_getProof, so the bounds are per client and global per second, and on concurrent builds.
type proofLimits struct {
	perClient, global, concurrent int
	timeout                       time.Duration
	maxClients                    int
}

var defaultProofLimits = proofLimits{perClient: 2, global: 20, concurrent: 4, timeout: 30 * time.Second, maxClients: 10000}

type proofHandler struct {
	src          proofBuilder
	trustedProxy string
	limits       proofLimits
	slots        chan struct{}

	mu      sync.Mutex
	window  time.Time
	budget  int
	clients map[string]int // requests per client in the current one-second window
	now     func() time.Time
}

func newProofHandler(src proofBuilder, trustedProxy string, l proofLimits) *proofHandler {
	return &proofHandler{src: src, trustedProxy: trustedProxy, limits: l, slots: make(chan struct{}, l.concurrent), clients: map[string]int{}, now: time.Now}
}

var blockParam = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)

func (h *proofHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		reply(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	switch r.URL.Path {
	case "/healthz":
		reply(w, http.StatusOK, "ok")
		return
	case "/v1/lockproof":
	default:
		reply(w, http.StatusNotFound, "not found")
		return
	}
	client, ok := h.client(r)
	if !ok {
		reply(w, http.StatusBadRequest, "invalid proxy address")
		return
	}
	if !h.allowed(client) {
		reply(w, http.StatusTooManyRequests, "rate limit")
		return
	}
	q := r.URL.Query()
	block, nonceText := q.Get("block"), q.Get("nonce")
	nonce, err := strconv.ParseUint(nonceText, 10, 64)
	if len(q) != 2 || !blockParam.MatchString(block) || err != nil || nonce == 0 || nonceText != strconv.FormatUint(nonce, 10) {
		reply(w, http.StatusBadRequest, "want exactly block=0x<64 hex> and nonce=<decimal, nonzero>")
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		reply(w, http.StatusTooManyRequests, "busy")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.limits.timeout)
	defer cancel()
	proof, err := h.src.build(ctx, common.HexToHash(block), nonce)
	switch {
	case errors.Is(err, errNotFound):
		reply(w, http.StatusNotFound, err.Error())
	case err != nil:
		log.Printf("lock proof %s/%d: %v", block, nonce, err)
		reply(w, http.StatusBadGateway, "proof unavailable")
	default:
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Content-Length", strconv.Itoa(len(proof)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(proof)
	}
}

// client is the peer's address, or X-Forwarded-For's when the peer is the trusted proxy (the package gateway's rule).
func (h *proofHandler) client(r *http.Request) (string, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if h.trustedProxy == "" || host != h.trustedProxy {
		return host, true
	}
	ip := net.ParseIP(r.Header.Get("X-Forwarded-For"))
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

func (h *proofHandler) allowed(client string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if now := h.now(); now.Sub(h.window) >= time.Second {
		h.window, h.budget = now, h.limits.global
		clear(h.clients)
	}
	n := h.clients[client]
	if n == 0 && len(h.clients) >= h.limits.maxClients {
		return false
	}
	h.clients[client] = n + 1
	h.budget--
	return n < h.limits.perClient && h.budget >= 0
}

func reply(w http.ResponseWriter, status int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintln(w, text)
}
