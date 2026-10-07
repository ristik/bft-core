# Public test UCT faucet (TN-1)

Test UCT has **no real value**. The testnet may reset arbitrarily; balances and
other assets may disappear without notice or obligation. This service distributes
gas funds, not TGE allocations. One bare-metal server can run this stack alongside
the paired validator containers. No public server/domain has been provisioned by
this PR; the owner supplies them. Public readiness also depends on the #432
deployment rehearsal.

## Reuse decision and pins

Reuse [chainflag/eth-faucet](https://github.com/chainflag/eth-faucet/tree/e7572628addc86c634d8acc3a61d5899667f0e33),
MIT, revision `e7572628addc86c634d8acc3a61d5899667f0e33` (v1.2.1).
Its Go signer already supports native EVM transfers, EIP-1559, keystores,
hCaptcha, per-address/IP caps and serialized nonce allocation. UCT is the native
gas asset; no ERC20 adapter or protocol change is needed. The upstream archive's
SHA-256 is checked in Dockerfile.backend. Its MIT notice ships in the image.
We build only its backend, with the unmodified pinned Go module graph; its embedded
frontend is replaced by an internal placeholder. The public UI lives here.

Upstream alone discovers the chain from RPC, lacks a genesis pin and health API,
and loses caps on restart. Rather than create another signer, gateway.py adds
network validation and a persistent SQLite budget. PoWFaucet is an alternative
with browser proof-of-work and a larger configuration/session subsystem; that
extra machinery is unnecessary for the initial single-host hCaptcha deployment.
See its [upstream documentation](https://github.com/pk910/PoWFaucet).

relay.py checks every validator's chain ID and block-zero hash before forwarding
RPC calls. It broadcasts signed transactions to every paired ureth mempool,
because the M1 execution profile disables transaction gossip. The relay and signer
have no published ports. RPC URLs are operator-controlled, private endpoints.
The gateway never receives a signing key. These HTTP services are trusted local
deployment components, not new consensus or public general-purpose RPC services.

## Configure and start

1. Make a **new dedicated EVM faucet account**, offline, and export an encrypted
   Ethereum V3 keystore. Never mount a validator, root, signing-authority, treasury
   or Engine JWT key. Keep the faucet account separate from the refill account.
   Keep only a small test balance in it, and never use its nonce outside this signer.
2. The server operator owns refill/alerts. Fund the faucet address with test UCT
   from the testnet's allocation/treasury account (or explicitly allocate it in a
   fresh testnet genesis). The disposable Hardhat account used by the acceptance
   lane is not a public-testnet funding source.
3. Copy network.example.json to network.json. Fill in the approved chain ID,
   **actual `eth_getBlockByNumber("0x0", false).hash`**, faucet address, all validator
   RPC URLs and hCaptcha site key. Verify the block-zero hash against the approved
   network/genesis manifest and every paired node, not just an untrusted public RPC.
   It is not the SHA-256 of the genesis JSON file. Default chain ID 31337 is a local
   example, not a reservation of the public testnet identity.
4. Set HCAPTCHA_SITEKEY to the same site key and register the public domain in
   hCaptcha. Place the encrypted keystore, password and hCaptcha secret outside
   the checkout. Set the following in an untracked `.env` (paths, not secret contents):

   ```dotenv
   FAUCET_KEYSTORE_FILE=/srv/faucet-secrets/keystore.json
   FAUCET_PASSWORD_FILE=/srv/faucet-secrets/password
   HCAPTCHA_SECRET_FILE=/srv/faucet-secrets/hcaptcha-secret
   HCAPTCHA_SITEKEY=your-site-key
   VALIDATOR_NETWORK=your-private-validator-network
   ```

   Make these files readable only by host root and the container UID 10001
   (for example UID 10001 ownership and mode 0400). Compose local secrets are
   read-only mounts, not an encrypted secret store. Restrict host access.
5. Set VALIDATOR_NETWORK to the validators' existing private Docker network so
   the configured names resolve; Compose joins only the relay to that network.
   Do not expose Engine API or the relay/signer to the public Internet. The
   gateway's default bridge subnet must not overlap another server network.
6. From this directory run `docker compose config --quiet`, then
   `docker compose up --build -d`. Check `docker compose ps` and
   `curl --fail http://127.0.0.1:8088/healthz` before publishing the hostname.
7. Install nginx.conf.example in the host nginx HTTP context, set the domain and
   TLS certificate paths, validate nginx configuration and reload it. Its
   X-Forwarded-For must **overwrite**, not append to, the supplied header.
   The gateway trusts only the configured Docker bridge host IP, by default
   `172.30.88.1`. Verify that the actual socket peer matches this on the Linux host;
   otherwise set the exact proxy IP before first startup. Keep port 8088 loopback-only.
   The nginx per-IP connection/request limits are part of the public deployment.

The UI is `https://<faucet-host>/`. A connected injected EVM wallet supplies the
recipient, chain ID and genesis hash. Both the UI and API reject wrong network or
an old reset genesis. An EVM address alone cannot identify a network. Manual API
clients must POST JSON `{address, chain_id, genesis_hash}` to `/api/claim` and supply
an hCaptcha token in `h-captcha-response`. `/api/network` reports the public pin.
Never disable CAPTCHA publicly. `dev_only` allows loopback-only native testing;
the provided Compose deployment cannot publish that mode through its container IP.

## Limits, failure and monitoring

Each claim is 0.01 UCT (18 decimals), one reservation per normalized address and
IP per rolling 24 hours, with at most 100 reservations (1 UCT) in any 24 hours.
The signer additionally enforces upstream's address/IP limits and verifies
hCaptcha. Gateway reservations survive process/container restarts and are committed
**before** submitting to the signer. Failed CAPTCHA tokens, backend failures and
ambiguous timeouts consume a reservation, intentionally. A client can receive
503 after a transaction was accepted; inspect the wallet/chain before intervening.
Never automatically replay a request. Shared NAT users share the IP cap.

400 means malformed address/body or missing CAPTCHA; 409 means the client network
pin differs; 429 means address/IP/global reservation limits; 503 means unavailable,
exhausted, mismatched backend/network or uncertain submission. A 200 response
contains the broadcast transaction hash, not a finality guarantee. Check its
successful receipt and certified/finalized state before relying on the funds.
Only simple EOA wallets are supported (upstream uses a fixed 21,000 transfer gas).

`GET /healthz` is the monitoring endpoint: 200 includes remaining claims and the
faucet balance in wei; 503 is fail-closed. It checks chain/genesis, signer address,
payout, CAPTCHA site key, minimum balance and the rolling budget. Default minimum
balance is 0.02 UCT; this is an operational reserve, not a guaranteed gas quote.
Insufficient gas funds or a stuck nonce also cause the signer to refuse transfers.
Alert on Docker unhealthy status, 503s, low balance and signer broadcast errors;
inspect `docker compose logs --tail=100 signer gateway relay`. No transaction is
signed by the health endpoint. Rate-limit or restrict monitoring access at nginx
if necessary. No separate metrics stack is required for this initial deployment.

To refill, send test UCT to the configured funding_address from the separate
refill account; wait for a successful receipt/certified state and healthy status.
No restart is needed. If a broadcast outcome is uncertain or the signer nonce is
stuck, stop public claims, inspect all validator mempools/receipts, and reconcile
the dedicated account's pending nonce before restarting the signer. Upstream only
refreshes its cached nonce automatically on nonce errors; never run two signers
for one key. The global budget remains in place even after refill/restart.

## Arbitrary reset / reconfiguration

Stop nginx routing and `docker compose down` before resetting validators. Capture
the old network pin/evidence and back up the claims volume if needed. Regenerate
the approved network manifest, configure wallets and every validator, then obtain
and independently verify the new block-zero hash/chain ID. Generate a fresh faucet
key and fund it on the new network; replace the secrets and network.json. Start
with a **new Compose project name**, e.g. `docker compose -p faucet-reset-20261008
up --build -d`, so it gets a fresh claims volume. Keep the old volume for evidence,
and update monitoring's project name. Any config change with the old database
is refused at startup; changes are never silently adopted. For a same-network
operational config change, stop the service and deliberately carry forward the
claims into a reviewed replacement database rather than erase active caps.

Check `/healthz`, a new fresh-wallet claim and a paid transaction before restoring
public routing. Old wallet pins must receive 409; a new pin aimed at old validators
must fail health/broadcast checks. Reconfiguration of chain identity must restart
the signer too: its signing chain ID is selected at startup. Inform testers that
old balances/assets are gone and have no real value. No compatibility or migration
promise is made for a reset.

## Verification

CI runs the gateway/relay refusal and concurrency tests and builds both images.
Local command: `python3 -m unittest discover -s deploy/testnet/faucet -v`.
For real paired-node evidence, prebuild the pinned upstream backend and evmtx,
then use the shared devnet lock (from the repository root):

```sh
../briefs/devnet-lock.sh faucet-dev4 env SIGNING=authority FAUCET_PROBE=1 M2_PROFILE2=1 \
  POST_M2A_URETH_BIN=/path/to/pinned/unicity-reth POST_M2A_URETH_COMMIT=<full-commit> \
  FAUCET_BACKEND_BIN=/path/to/pinned/eth-faucet \
  FAUCET_EVMTX_BIN=/path/to/evmtx bash scripts/reth-paired-devnet.sh 4 10
```

`devnet_probe.py` funds a new random faucet account from the lane's disposable
genesis account, verifies a zero-balance fresh wallet, claims and pays gas, checks
duplicate/IP/restart/invalid/network/reset/exhaustion cases, and writes only public
evidence to test-nodes/faucet-evidence.json. Temporary keys are discarded. Faucet
mode stops before unrelated handoff/continuous-execution tests. Local
native tests disable CAPTCHA and do not establish public TLS, DNS, real hCaptcha
credentials, server firewall configuration or public deployment readiness. Preserve
pinned lane binaries in /private/tmp. Independent internal PR review is required
before acceptance/merge; this implementation does not record its own independent
approval or close #435.

For an actual fresh-genesis reset demonstration, preserve the first run's
faucet-evidence.json outside test-nodes, then repeat the locked command with
`FAUCET_PREVIOUS_EVIDENCE=/absolute/path/to/first-evidence.json`. The probe requires
a different genesis, refuses the previous database identity and wallet pin, then
dispenses and pays gas on the new network with a new faucet key/state.
