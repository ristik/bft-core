# Native paired-devnet acceptance, 2026-10-07

`before-reset/` and `after-reset/` retain the public EVM genesis, full shard
configuration, probe result, lane transcript and each validator's certificate
admission records. No private keys, credentials, passwords or Engine JWTs are
retained. The network was deliberately regenerated between runs; the second
probe uses the first result as FAUCET_PREVIOUS_EVIDENCE.

Exact source revisions, native binary SHA-256 values and compiler version are in
[pins.json](pins.json). BFT Go code was built from that source revision; this PR
adds the faucet-only lane callback and Python probe. The upstream backend was
built without source changes, with only an embedded placeholder web/dist/index.html
because the public UI is served by the gateway. Native build commands:

```sh
go build -o build/ubft ./cli/ubft
go build -o /private/tmp/agre-faucet-evmtx ./scripts/evmtx
git clone https://github.com/chainflag/eth-faucet.git /private/tmp/agre-faucet-upstream
git -C /private/tmp/agre-faucet-upstream checkout e7572628addc86c634d8acc3a61d5899667f0e33
mkdir -p /private/tmp/agre-faucet-upstream/web/dist
printf '%s' 'Internal signer' > /private/tmp/agre-faucet-upstream/web/dist/index.html
(cd /private/tmp/agre-faucet-upstream && go build -o /private/tmp/agre-faucet-backend .)
```

Both successful runs use the operator guide's locked profile-2 command, with
`POST_M2A_URETH_BIN=/private/tmp/t6-ureth/unicity-reth-b4e7cb0` and
`POST_M2A_URETH_COMMIT=b4e7cb0ace07eee70e753241e0139c4d42b516d4`.
The reset run additionally sets FAUCET_PREVIOUS_EVIDENCE to before-reset/result.json.
The corresponding full source pins and generated genesis hashes appear in each
lane transcript. Before resetting, preserve the first artifacts outside test-nodes.

Limits: local native backend, disposable funded accounts, CAPTCHA disabled only
for loopback dev mode. These are successful receipts plus internal authenticated
certificate-admission log observations, not exported independently verified
certification proofs. CI builds and starts the version command in the pinned
container image separately; this local host had no running Docker daemon. Real
hCaptcha credentials, TLS/DNS, the bare-metal firewall and #432's deployment
rehearsal remain public-operations prerequisites. Independent internal PR review
is pending; no self-approval or issue closure is recorded.

Earlier failed attempts are retained outside the repository in
`briefs/devnet-runs/faucet-20261007/`: legacy profile lacking bootstrap-frontier
support, a probe log-hash prefix mismatch, and zero-argument geth RPC calls omitting
params. The successful runs use profile 2 and the corrected probe/relay; the RPC
form has a regression test. Failed attempts are not acceptance evidence.
