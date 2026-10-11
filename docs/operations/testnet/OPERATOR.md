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
- One Debian 12/bookworm server (the runtime glibc). It builds the images too: `images.json` records *local* image IDs.
  Plan 24 GiB RAM, 8 cores, 100 GiB SSD for N=4 (budgets, not measurements) plus off-host backup space.
- Docker Engine with the Compose v2 plugin (not pinned: record versions), Go 1.27.1 (official tarball), Rust 1.97.1
  (rustup), clang/libclang, make, git, Python 3.11+, jq, curl. Work as a non-root user in the `docker` group who
  owns `/srv/src`; only the commands shown with `sudo` need root (they keep your PATH, so `go` is found).
- Public: TCP 443 (and 80 only for certificate renewal), SSH for operators. Ports 8545 (RPC), 8088 (faucet) and
  9090 (Prometheus) bind host loopback only; never publish them or any validator port. Docker subnets
  172.30.88.0/24 and 172.30.89.0/24 must be free. DNS names, TLS certificates and hCaptcha keys come from the owner.

**Keep root RPC private.** The root (and shard node) RPC address has no operator authentication of its own: `PUT /api/v1/trustbases` is
unguarded and the `/api/v1/handoff/*` and `/api/v1/q3/*` endpoints only require a loopback TCP peer, which a reverse proxy on the same host defeats.
Bind it to loopback or an isolated operator network (the containers' internal Docker network, port not published); never publish it or
proxy it through the public JSON-RPC gateway. The start-up `WARN` "RPC address is not loopback" is expected inside the testnet containers.
What each endpoint can do if reached: [root-rpc-exposure.md](../root-rpc-exposure.md) ([#533](https://github.com/ristik/bft-core/issues/533)).

## 3. Build images from exact revisions
`/srv/src/pkg` is this repository at the guide commit you were given (`main` lacks the package); the other three
are clean checkouts of the exact revisions in [pins.json](../../../deploy/testnet/pins.json). Set `GUIDE_COMMIT` first.
```sh
GUIDE_COMMIT=REPLACE_WITH_GIVEN_COMMIT bash -eo pipefail <<'EOF'   # stops at the first error, keeps your shell
git clone -b integration/enshrined-evm https://github.com/ristik/bft-core.git /srv/src/pkg
git -C /srv/src/pkg checkout --detach "$GUIDE_COMMIT"
for r in bft:bft-core ureth:ureth rugregator:rugregator; do n=${r%%:*}; pin=$(jq -r .$n /srv/src/pkg/deploy/testnet/pins.json)
  git clone https://github.com/ristik/${r#*:}.git /srv/src/$n-pinned && git -C /srv/src/$n-pinned fetch -q origin $pin
  git -C /srv/src/$n-pinned checkout --detach $pin; done
cd /srv/src/pkg
python3 deploy/testnet/build-images.py --bft-source /srv/src/bft-pinned \
  --ureth-source /srv/src/ureth-pinned --rugregator-source /srv/src/rugregator-pinned
go build -o build/tn-keygen ./deploy/testnet/keygen
go build -C /srv/src/bft-pinned -o build/b1genesis ./scripts/b1genesis   # the independent genesis-registry regeneration, from the pinned source
EOF
```
Success: it prints the path of `deploy/testnet/artifacts/images.json` (pins, binary SHA-256, local image IDs).

## 4. Generate a fresh generation and start it
```sh
cd /srv/src/pkg; umask 077; G=/srv/testnet/tn-$(date -u +%Y%m%d)   # tn-<lowercase>, must not exist
sudo env PATH="$PATH" python3 deploy/testnet/generate.py --out $G --validators 4 --chain-id 31337 \
  --ubft /srv/src/bft-pinned/build/ubft --b1genesis /srv/src/bft-pinned/build/b1genesis --captcha-sitekey SITE_KEY --captcha-secret-file /srv/secrets/hcaptcha-secret
sudo chown -R 10001:10001 $G && cd $G && docker compose config --quiet
SERVICES=$(docker compose config --services | sed '/^authority/d')   # authorities are already running
docker compose up -d $SERVICES && docker compose ps
```
The roots and shard nodes serve the Q3/handoff operator endpoints, which accept loopback TCP peers only, and their operator listeners now **bind to 127.0.0.1** (8002 root, 9101 shard): nothing on the shared Docker network can reach them, including their unguarded write endpoints. Each validator entity's root and shard node share one network namespace, owned by a small holder container `pod<i>` (it carries the DNS names `root<i>` and `shard<i>`; a `metrics<i>` relay in it serves only `/root/metrics` and `/shard/metrics` to Prometheus). Reach the operator endpoints with `docker compose exec root<i>` / `shard<i>` (either one: both see the same loopback), as the examples below do. **Lifecycle:** never restart `pod<i>` alone (the containers in its namespace would be left with a dead one): `docker compose up -d --force-recreate pod<i> root<i> shard<i> metrics<i>`. Recreating only `root<i>` (the install restart) or restarting only `shard<i>` is safe. Authorities stay outside (unix sockets) and are never recreated.
The generator makes fresh root/shard/authority keys per validator, the trust base, a B1 genesis (registry layout 3 from one `b1-profile`, checked by `b1genesis --verify`) that funds
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

## 5a. Proof-of-stake profile (groundwork for the isolated PoS rehearsal, [#437](https://github.com/ristik/bft-core/issues/437))
The package can generate the PoS genesis instead of the PoA one: the contracts' genesis state (custody, election, evidence, selection, policy, reader) is allocated into
the EVM genesis, the b1-profile pins the records hook and the election to them, and the roots run on the P85 flags (`--pos-deployment`, `--pos-genesis-identities`,
`--pos-evm-rpc`; they replace `--genesis-identities`). It is the P85 lane's genesis (`scripts/lib/p85-lib.sh`), with the lane's rule: **the custody names the genesis
assignment id of the FULL shard configuration**, never of the base one. A custody deployed with the base configuration's id halts the shard at the first
`CloseLiability` (the roots close the full configuration's id; P85 runs 25 and 26). The generator therefore finalizes once without the PoS accounts, takes the id from
that full configuration, builds the contracts genesis from it, merges the accounts, finalizes for real and runs `ubft pos-relayer verify-genesis` on the result.

Extra prerequisites: a clean checkout of `unicity-pos-contracts` at `contracts` in [pins.json](../../../deploy/testnet/pins.json) with its submodules, and `forge` v1.8.1 on
PATH (the contracts' own CI pin: the registry's bytecode and code hash are protocol surface). Build `ubft` from the pinned `bft` revision, which must contain
`pos-relayer verify-genesis`.
```sh
git clone https://github.com/ristik/unicity-pos-contracts.git /srv/src/contracts-pinned && cd /srv/src/contracts-pinned
git checkout --detach "$(jq -r .contracts /srv/src/pkg/deploy/testnet/pins.json)" && git submodule update --init --recursive
cd /srv/src/pkg; umask 077; G=/srv/testnet/tn-pos-$(date -u +%Y%m%d)
sudo env PATH="$PATH:$HOME/.foundry/bin" python3 deploy/testnet/generate.py --out $G --validators 4 --chain-id 31337 \
  --ubft /srv/src/bft-pinned/build/ubft --b1genesis /srv/src/bft-pinned/build/b1genesis --captcha-sitekey SITE_KEY --captcha-secret-file /srv/secrets/hcaptcha-secret \
  --pos --pos-contracts /srv/src/contracts-pinned
```
The generator refuses a contracts checkout that is not clean at the pin (the contracts' `p85-genesis.sh` writes a temporary directory inside that checkout and removes it on exit: after a failed run `git status` there may briefly show it; remove it by hand and rerun). It prints `pos: the genesis assignment of the base configuration (…) is not the full configuration's (…)`
when it had to prepare the contracts genesis again (it always does: the base id is never the deployed one). Success adds to the manifest a `pos` block (`genesis_assignment`,
`first_pass_assignment`, the custody and election addresses, the cadence) and to `network/`: `pos-deployment.json`, `pos-genesis-identities.json`, `pos-plan.json`,
`pos-contracts-genesis.json`, `pos-genesis-assignment.txt`. **Cadence:** the election is due 400 ordinary root rounds and 300 UC seconds after the last acknowledged rotation
(`--pos-cadence-rounds`, `--pos-cadence-seconds`): the P85 lane's rehearsal values, not a testnet decision; set the rehearsal's own before generating. The weight-distance
bound is the package's churn budget (1/2), committed in the shard configuration and in the contracts.

**Verify the ids once more on the shipped files, before `docker compose up`** (the generator did it; this is the independent check, and it needs no node):
```sh
N=$G/network; /srv/src/bft-pinned/build/ubft pos-relayer verify-genesis --plan $N/pos-plan.json --trust-base $N/trust-base.json \
  --shard-conf $N/full-shard-conf.json --contracts-genesis $N/pos-contracts-genesis.json
# genesis assignment 0x… is the full shard configuration's   (it must equal $(cat $N/pos-genesis-assignment.txt) and manifest.pos.genesis_assignment)
```
**Owner keys.** The lane's plan derives each genesis identity's `owner`, `withdrawal` and `payee` addresses from the root node id by hash: addresses nobody holds the key of, so
no identity could top up, exit, withdraw or claim a reward. The package's ceremony instead generates, per identity, three fresh secp256k1 keys (`tn-keygen owners`) and puts
their addresses in `pos-plan.json` (public: the assignment id does not depend on them, `verify-genesis` recomputes from that plan). The keys are in
`$G/pos-owner-keys/identity-<stakingId>/{owner,withdrawal,payee}.key` (hex, mode 0600, directory 0700), generated at ceremony time, never in `network/`, never mounted into a
container and never committed. Handling is that of `faucet-secrets/`: private host material; `backup.py` archives the whole generation (mode-0600 archive), so keep the archive
as private as the directory; the section 4 `chown -R 10001` makes them readable only by that uid, so `sudo chown -R "$USER" $G/pos-owner-keys` before use. The owners hold
no balance at genesis (a genesis balance would change the supply the bond accounting is audited against): fund the owner of an identity from the faucet account for gas and
bonds when rehearsing, e.g. `cast send OWNER --value 1ether --keystore ... --rpc-url $R`. Which custody calls each key makes is the contracts' interface, not this package's.
Without `--pos` nothing of this exists.

A different id fails with both ids printed; do not start such a package. Start as in section 4. **PoS smoke** (after `docker compose up -d`; the chain RPC is the gateway's, `cast` from
`foundry`; `REG=0xff00000000000000000000000000000000000002`, `CUSTODY` and `ELECTION` are in `network/pos-deployment.json`):
```sh
R=http://127.0.0.1:8545; D=$G/network/pos-deployment.json; CUSTODY=$(jq -r .custody $D); ELECTION=$(jq -r .election $D)
for a in $REG $CUSTODY $ELECTION; do cast code $a --rpc-url $R | wc -c; done                       # all three non-trivial (code is in the genesis)
cast call $REG 'progress()(uint64)' --rpc-url $R; sleep 60; cast call $REG 'progress()(uint64)' --rpc-url $R   # the clock ticks: must rise
cast call $ELECTION 'thresholds()(uint256,uint256)' --rpc-url $R                                   # (cadence rounds, cadence seconds) past the anchors
cast call $REG 'recordCount()(uint64)' --rpc-url $R; cast call $CUSTODY 'recordCursor()(uint64)' --rpc-url $R   # equal: custody has applied every root record
docker compose logs root1 | grep -ci 'revert\|AssignmentNotActive'                                    # 0
```
Expect `progress` to rise while shard heights rise (section 5), `recordCursor == recordCount` after each epoch boundary, and no `AssignmentNotActive` anywhere. The first closure-bearing
epoch boundary needs a handoff (the P85 lane's recovery steps, `scripts/p85-recovery-steps.sh`); this package's CI cannot run it, so the rehearsal does. The CI probe
(`validate-pos.py`, in `testnet-package`) proves what needs no EVM node: the ids agree and a contracts genesis of the base configuration's id is refused naming both, the EVM
genesis carries the contracts' code at the deployed addresses, the deployment file pins the profile's registry code hash, and the four roots start from the generated entrypoints on
the P85 flags and certify rounds. It does **not** start the EVM shard, so it says nothing about the first blocks or the election clock: that is this smoke.

## 6. Routine operations
In a new shell, first: `G=/srv/testnet/tn-…; cd $G && SERVICES=$(docker compose config --services | sed '/^authority/d')`.

**Restart one validator (authority stays live).** Success: the shard logs `execution journal restored`, then new
`certificate admitted` lines, and the other shards never stop advancing.
```sh
docker compose restart ureth2 root2 shard2 && docker compose logs --since 5m shard2 | grep -E 'journal restored|certificate admitted'
docker compose exec -T authority2 ubft signing-authority status --operator-socket /authority/operator.sock \
  --operator-credential /authority/operator.cred | jq '{generation,reservedRound,faulted,keyLost}'   # same generation, higher round
```

**Backup and restore (whole generation).** Stop public routing first. `backup` stops every non-authority service;
restore works only while the authorities have not signed since. To resume instead, `docker compose up -d $SERVICES` in `$G`.
Copy the archive **and its `.sha256` sidecar** off host (restore refuses without it). After a restore, operate only from
the restored directory (same Compose project, authority mounts under the old `$G`); never delete `$G` while its authorities run.
```sh
sudo env PATH="$PATH" python3 /srv/src/pkg/deploy/testnet/backup.py backup $G /srv/backups/$(basename $G).tar.gz
#   -> "Non-authority services stopped; authorities MUST stay live. SHA256: ..."
sudo env PATH="$PATH" python3 /srv/src/pkg/deploy/testnet/backup.py restore /srv/testnet/tn-restored \
  /srv/backups/$(basename $G).tar.gz --live-generation $G     # -> "Restored offline. ..."
sudo chown -R 10001:10001 /srv/testnet/tn-restored && cd /srv/testnet/tn-restored && docker compose up -d $SERVICES
```

**Not yet supported in the container stack (record as such, do not improvise):** coupled validator rotation,
operator Abort of a rotation attempt, and archive restore of a *single* validator. No tooling creates a successor
pod. Native procedures: rotation [H6 §1](../h6/scenarios.md#1-coupled-key-rotation-joiners-stalled-successors-and-supersession-h3)
and [H3](../h3-evm-assignment-runbook.md), Abort [H6 §6](../h6/scenarios.md#6-abort-before-and-after-h)
and [root-handoff-abort.md](../root-handoff-abort.md), restore [M2 §3](../m2-runbook.md#3-replace-a-validator-after-complete-disk-loss); H6 is validated on macOS x86_64 only.

**Turnover policy (PoS election profile).** Normal handoffs should replace only a small subset of validators.
The election measures normalized L1 weight distance `D = Σ|newWeight/newTotal − oldWeight/oldTotal|`;
`D/2` is total variation, and replacing k of n unit-weight members with new identities gives `D = 2k/n`.
The production default `D <= 1/4` is a conservative safety recommendation, not a fixed protocol rule;
the testnet PoS profile uses `D <= 1/2`. The configured distance gate and other continuity checks remain enforced;
no additional headcount-turnover gate is introduced. Emergency supersession to the exact authorized recovery
committee K exists in PoA and PoS and must be rehearsed on testnet; it is not routine turnover.

## 7. Reset to a fresh genesis (destroys all assets)
Stop nginx routing; take a backup for evidence if wanted. This deletes the old generation, keys and balances.
```sh
sudo env PATH="$PATH" python3 /srv/src/pkg/deploy/testnet/reset.py --old $G --lose-all-assets -- --out /srv/testnet/tn-NEWNAME \
  --validators 4 --chain-id 31337 --ubft /srv/src/bft-pinned/build/ubft --b1genesis /srv/src/bft-pinned/build/b1genesis \
  --keygen /srv/src/pkg/build/tn-keygen --captcha-sitekey SITE_KEY --captcha-secret-file /srv/secrets/hcaptcha-secret
```
Success: `Old balances, transactions and keys destroyed. ...`. Start and verify as in sections 4–5; require a new
block-zero hash and faucet address. The old pin must get 409 (checked before the captcha); then announce the reset:
`curl -s -XPOST http://127.0.0.1:8088/api/claim -d "{\"address\":\"0x$(printf %040d 1)\",\"chain_id\":31337,\"genesis_hash\":\"$(jq -r .genesis_hash $G.retired-manifest.json)\"}"`

## 8. Troubleshooting
| Symptom / log line | Cause and fix |
|---|---|
| `FileNotFoundError: ... 'go'` (generate/reset) | sudo dropped your PATH: use `sudo env PATH="$PATH" …` as shown, or link `go` into `/usr/local/bin`. |
| `build on Linux for the server, not macOS`, `source pin mismatch`, `dirty source` | Rebuild on Debian 12 from clean checkouts of pins.json. |
| `image source pins differ`, `ubft must be built from clean pinned BFT source` (also `b1genesis`) | images.json or ubft come from another pin: rerun section 3. |
| `b1genesis --verify: the genesis registry differs from its regeneration` (generator) | Nothing was started that matters yet: discard the generation; the pinned `ubft` and `b1genesis` must be the same revision. |
| `authority startup timeout` (generator) | `docker compose logs authority1`; discard the generation (section 4 failure path). |
| `authorityN` exited, or `keyLost`/`faulted` in its status | That validator's signing key is gone. No repair exists: keep N−1 running, plan a reset (section 7). |
| `keep ALL authorities live and ALL other services stopped` | backup/restore precondition: `docker compose stop` the listed non-authority services. |
| `authority lifetime/state advanced since backup` | The network signed after the backup; this archive cannot be restored. Resume `$G`, or reset. |
| faucet `/healthz` 503 `Check RPC, identity, backend, balance and daily budget` | `docker compose logs --tail=100 signer faucet relay`; refill or wait out the 24 h budget ([faucet README](../../../deploy/testnet/faucet/README.md)). |
| Every public client gets 429 `rate limit` | nginx is not the trusted proxy peer (172.30.88.1 faucet, 172.30.89.1 rpc), so all clients share one bucket: fix the peer. |
| `Pool overlaps with other one on this address space` | 172.30.88/89.0/24 in use: free them (the subnets are fixed in generate.py). |
| Handoff or archive-restore refusals | See the [H6 table](../h6/evidence.md#refusals-stop-at-the-first-unexplained-one). |

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
