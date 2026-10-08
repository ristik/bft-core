# TN-1 operator guide (single server, container per validator)

Setting up this testnet **is** the independent rehearsal (H6 #23, T6-TEST #432). Follow only this page and its
links; record every gap as a documentation defect (section 9) instead of asking the authors.

## 1. What you run
N validator pods (default 4), each a BFT root node, a paired EVM shard node, its ureth execution client and an
in-memory signing authority; plus one aggregator, a public JSON-RPC gateway (`rpc`), the faucet (`faucet`,
`signer`, `relay`) and Prometheus, all on one Docker host. Consensus is PoA.
Read [NOTICE.txt](../../../deploy/testnet/NOTICE.txt) first. **Test UCT has no value, the network is reset
arbitrarily, and one host/disk/operator failure stops the whole testnet.** Authority keys exist only in memory:
**never restart an `authorityN` container**, and never run `docker compose down`, `up --force-recreate` or a host
reboot on a network you intend to keep. Design detail: [deploy/testnet/README.md](../../../deploy/testnet/README.md).

## 2. Prerequisites
- Linux server, root access, Docker Engine with the Compose v2 plugin (versions are not pinned: record yours).
  Plan 24 GiB RAM, 8 cores, 100 GiB SSD for N=4 (budgets, not measurements) plus off-host backup space.
- Build host: Debian 12/bookworm (the runtime glibc). Go 1.27.1, Rust 1.97.1 (rustup), clang/libclang, make,
  git, Python 3.11+, jq, curl. `go` must also be on the server's PATH: the generator checks `ubft` with `go version -m`.
- Public: TCP 443 (and 80 only for certificate renewal), SSH for operators. Ports 8545 (RPC), 8088 (faucet) and
  9090 (Prometheus) bind host loopback only; never publish them or any validator port. Docker subnets
  172.30.88.0/24 and 172.30.89.0/24 must be free. DNS names, TLS certificates and hCaptcha keys come from the owner.

## 3. Build images from exact revisions
`/srv/src/pkg` is this repository at this guide's commit; the other three are clean checkouts of the exact
revisions in [pins.json](../../../deploy/testnet/pins.json). Never use `main` or a moving tag.

```sh
set -eo pipefail
git clone https://github.com/ristik/bft-core.git /srv/src/pkg   # then check out this guide's commit
for r in bft:bft-core ureth:ureth rugregator:rugregator; do n=${r%%:*}; pin=$(jq -r .$n /srv/src/pkg/deploy/testnet/pins.json)
  git clone https://github.com/ristik/${r#*:}.git /srv/src/$n-pinned && git -C /srv/src/$n-pinned fetch -q origin $pin
  git -C /srv/src/$n-pinned checkout --detach $pin; done
cd /srv/src/pkg
python3 deploy/testnet/build-images.py --bft-source /srv/src/bft-pinned \
  --ureth-source /srv/src/ureth-pinned --rugregator-source /srv/src/rugregator-pinned
go build -o build/tn-keygen ./deploy/testnet/keygen
```

Success: it prints the path of `deploy/testnet/artifacts/images.json` (pins, binary SHA-256, local image IDs).

## 4. Generate a fresh generation and start it
```sh
umask 077; G=/srv/testnet/tn-$(date -u +%Y%m%d)     # name must be tn-<lowercase>, must not exist
sudo -E python3 deploy/testnet/generate.py --out $G --validators 4 --chain-id 31337 \
  --ubft /srv/src/bft-pinned/build/ubft --captcha-sitekey SITE_KEY --captcha-secret-file /srv/secrets/hcaptcha-secret
sudo chown -R 10001:10001 $G && cd $G && docker compose config --quiet
SERVICES=$(docker compose config --services | sed '/^authority/d')   # authorities are already running
docker compose up -d $SERVICES && docker compose ps
```

The generator makes fresh root/shard/authority keys per validator, the trust base, a layout-2 genesis that funds
**only** a new random faucet account (1000 test UCT), Engine JWTs and `manifest.json`. Success: it prints the
block-zero hash, the manifest and `Authorities are live and enrolled. Do NOT restart them.`; `docker compose ps`
shows nothing restarting. On failure: `docker compose down`, delete the directory, retry under a new name.
Configure nginx from [nginx.conf.example](../../../deploy/testnet/nginx.conf.example) and
[faucet/nginx.conf.example](../../../deploy/testnet/faucet/nginx.conf.example) (real names, TLS, `nginx -t`, reload).
**No container step of this guide has yet run on a live server** ([evidence](../../../deploy/testnet/evidence/README.md)).

## 5. Verify before opening to the public
```sh
curl -fsS http://127.0.0.1:8545/healthz; curl -fsS http://127.0.0.1:8088/healthz   # {"head":...}; budget/balance
docker compose exec -T rpc python3 - <<'EOF'   # every node must print True (chain ID and block zero match)
import json, urllib.request as u
m = json.load(open('/network/network.json'))
for url in m['validator_rpc_urls']:
    c = lambda meth, p: json.load(u.urlopen(u.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': meth,
        'params': p}).encode(), {'Content-Type': 'application/json'}), timeout=5))['result']
    print(url, int(c('eth_chainId', []), 16) == m['chain_id'] and c('eth_getBlockByNumber', ['0x0', False])['hash'] == m['genesis_hash'])
EOF
for i in 1 2 3 4; do docker compose exec -T shard$i ubft shard-node certified-parent --url http://127.0.0.1:9101; done
```

`certified-parent` prints the certified tip hash (height and root round on stderr); repeat after a minute: heights
must rise on every shard, and `docker compose logs shard1 | grep 'certificate admitted'` keeps growing.
Then, from a fresh browser wallet on the manifest's chain ID and `https://rpc.<domain>/`, claim at
`https://<faucet-host>/` (200 with a tx hash) and send a native transfer. Check both:

```sh
curl -s https://rpc.DOMAIN/ -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":["0xTXHASH"]}' | jq .result.status   # "0x1"
```

and a certified shard height at or above the receipt's `blockNumber` (a receipt alone is not certification).
The gateway allows basic `eth_*` reads, call/estimate and `eth_sendRawTransaction` only (no `eth_feeHistory`, no
batches, 16 KiB bodies, 10 req/s per IP). Open nginx routing last.

## 6. Routine operations
**Restart one validator (authority stays live).** Success: the shard logs `execution journal restored`, then new
`certificate admitted` lines, and the other shards never stop advancing.

```sh
docker compose restart ureth2 root2 shard2 && docker compose logs --since 5m shard2 | grep -E 'journal restored|certificate admitted'
docker compose exec -T authority2 ubft signing-authority status --operator-socket /authority/operator.sock \
  --operator-credential /authority/operator.cred | jq '{generation,reservedRound,faulted,keyLost}'   # same generation, higher round
```

**Backup and restore (whole generation).** Stop public routing first. `backup` stops every non-authority service;
restore works only while the authorities have not signed since. To resume instead, `docker compose up -d $SERVICES` in `$G`.

```sh
sudo -E python3 /srv/src/pkg/deploy/testnet/backup.py backup $G /srv/backups/$(basename $G).tar.gz
#   -> "Non-authority services stopped; authorities MUST stay live. SHA256: ..."
sudo -E python3 /srv/src/pkg/deploy/testnet/backup.py restore /srv/testnet/tn-restored \
  /srv/backups/$(basename $G).tar.gz --live-generation $G     # -> "Restored offline. ..."
sudo chown -R 10001:10001 /srv/testnet/tn-restored && cd /srv/testnet/tn-restored && docker compose up -d $SERVICES
```

**Not yet supported in the container stack (record as such, do not improvise):** coupled validator rotation,
operator Abort of a rotation attempt, and archive restore of a *single* validator. No tooling creates a successor
pod. Native procedures: rotation [H6 §3](../h6/scenarios.md#3-coupled-key-rotation-stalled-successors-and-archive-backed-restore)
and [H3](../h3-evm-assignment-runbook.md), Abort [H6 §2](../h6/scenarios.md#2-abort-before-h-retry-then-refuse-abort-after-h)
and [root-handoff-abort.md](../root-handoff-abort.md), restore [M2 §3](../m2-runbook.md#3-replace-a-validator-after-complete-disk-loss); H6 is validated on macOS x86_64 only.

## 7. Reset to a fresh genesis (destroys all assets)
Stop nginx routing; take a backup for evidence if wanted. This deletes the old generation, keys and balances.
```sh
sudo -E python3 /srv/src/pkg/deploy/testnet/reset.py --old $G --lose-all-assets -- --out /srv/testnet/tn-NEWNAME \
  --validators 4 --chain-id 31337 --ubft /srv/src/bft-pinned/build/ubft \
  --keygen /srv/src/pkg/build/tn-keygen --captcha-sitekey SITE_KEY --captcha-secret-file /srv/secrets/hcaptcha-secret
```

Success: `Old balances, transactions and keys destroyed. ...`. Start and verify as in sections 4–5; require a new
block-zero hash and faucet address, and faucet 409 for the old wallet pin. Announce the reset.

## 8. Troubleshooting
| Symptom / log line | Cause and fix |
|---|---|
| `build on Linux for the server, not macOS`, `source pin mismatch`, `dirty source` | Rebuild on Debian 12 from clean checkouts of pins.json. |
| `image source pins differ`, `ubft must be built from clean pinned BFT source` | images.json or ubft come from another pin: rerun section 3. |
| `authority startup timeout` (generator) | `docker compose logs authority1`; discard the generation (section 4 failure path). |
| `authorityN` exited, or `keyLost`/`faulted` in its status | That validator's signing key is gone. No repair exists: keep N−1 running, plan a reset (section 7). |
| `keep ALL authorities live and ALL other services stopped` | backup/restore precondition: `docker compose stop` the listed non-authority services. |
| `authority lifetime/state advanced since backup` | The network signed after the backup; this archive cannot be restored. Resume `$G`, or reset. |
| faucet `/healthz` 503 `Check RPC, identity, backend, balance and daily budget` | `docker compose logs --tail=100 signer faucet relay`; refill or wait out the 24 h budget ([faucet README](../../../deploy/testnet/faucet/README.md)). |
| Every public client gets 429 `rate limit` | nginx is not the trusted proxy peer (172.30.88.1 faucet, 172.30.89.1 rpc), so all clients share one bucket: fix the peer. |
| `Pool overlaps with other one on this address space` | 172.30.88/89.0/24 in use: free them (the subnets are fixed in generate.py). |
| Handoff or archive-restore refusals | See the [H6 table](../h6/evidence.md#troubleshooting-stop-at-the-first-unexplained-refusal). |

## 9. Rehearsal evidence to record
- Operator name, date, this guide's commit, host specs, Docker/Compose versions, `images.json`, `manifest.json`.
- Every command with its output and exit code; UTC timestamps; `docker compose ps` before/after each operation.
- Section 5: identity check, certified heights twice, claim and transfer hashes, receipt, certified height.
- Section 6: restart log lines and authority status before/after, backup SHA-256, then section 5 after restore.
- Section 7: old/new block-zero hashes and faucet addresses, old pin 409, then section 5 on the new generation.
- 24 h observation: certified heights, restarts, disk/RAM each minute; any stall, its duration and recovery.
- Rotation, Abort and single-validator restore as **not supported here** unless done via the H6 lanes.
- Every documentation defect: where you were stuck, what you guessed, what worked. Publish only public output:
  never keystores, `secrets.env`, credentials, `docker inspect` output or private state.
