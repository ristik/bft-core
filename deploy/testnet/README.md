# Single-server PoA testnet package (TN-OPS groundwork)

Read [NOTICE.txt](NOTICE.txt) before using this network. All test UCT and other
assets are disposable. This package supports #434 and the deployment/reset part
of #432; it does not close either issue. The bare-metal server, DNS and
hCaptcha credentials are supplied by the deployment, not by this package. No public deployment,
independent second-operator rehearsal or production readiness is claimed.

Each validator entity is a **four-container pod**: root, paired ureth, shard,
signing authority. Separate containers give each process bounded resources,
observable logs and independent restarts without a custom process supervisor.
Each pod has separate root/shard/authority keys, Engine JWT, journals and archive.
Only its shard and authority share the authority directory/Unix sockets. Operator
credentials are privileged host material; these pods are not a hostile-container
security boundary. Never mount one validator's private directory into another.
Authority keys exist only in process memory by protocol design. Authorities use
`restart: no`; all other services use `unless-stopped`. Restarting an authority
changes its key and requires a separately authorized validator replacement. The
generator enrolls keys inside the long-lived Docker authorities, never in a
throwaway init process. Full host/daemon loss requires a fresh testnet reset.
The one aggregator is aggregator-go (owner decision 40): partition 7, one full-range
shard, a single instance without high availability, its state in a single-node
MongoDB replica set (`mongo` service, pinned image, no authentication, on its own
internal network that only validator 1's namespace joins, data in `<generation>/mongo`). It runs in validator 1's network namespace, because it reads
the trust bases of later root epochs from root 1's loopback-only operator endpoint.
**The aggregator partition has no `proof_type`:** aggregator-go sends no SMT
consistency proof, so the root checks only the aggregator's signature (one signer),
not its SMT root transitions; rugregator's `aggregator_rsmt_v1` check is not in this
package. EVM is partition 8/full range. This is PoA with profile-2 authenticated history,
the single B1 registry (permanent layout, one `ubft engine-api b1-profile` shared by genesis, ureth and the shard nodes) and no bridge or staking allocation. The registry bytecode and
engine protocol are supplied by the pinned BFT/ureth builds.

The generated `compose.yaml` is JSON (valid YAML), default N=4, configurable N=3..16 (the registry's committee ceiling; a PoS generation is further limited to the election cap, 6).
All services have CPU/memory/PID limits, explicit restart policies, read-only root filesystems
and bounded Docker JSON logs (30 MiB/service). Each pod caps memory at about 2.7 GiB (2.625 GiB of its four services, plus a 16 MiB namespace holder and a 64 MiB metrics relay);
shared services cap another 1.625 GiB, approximately **12.5 GiB for N=4** and
**9.75 GiB for N=3**, plus Docker/OS/page cache/build overhead. Plan at least 24 GiB
server RAM, 8 cores, 100 GiB initial SSD and off-host backup space; these are initial
planning budgets, not measured capacity. On the shared 16 GiB development Mac use
N=3 only when memory is available. Never build Rust while rehearsing the cluster.
Monitor disks: retention bounds metrics/logs but does not bound chain databases.

Only public RPC (8545), faucet (8088) and Prometheus (9090) bind **host loopback**.
No root admin, shard admin, authority or Engine endpoint has a published port.
The validator network is internal (each ureth serves `eth,net,web3,debug` there: the shard node needs `debug_getRawHeader`; the public gateway allow-lists methods and has no `debug_*`). The faucet's isolated signer has Internet
access for hCaptcha but cannot reach validators; only its relay bridges networks.
RPC permits an explicit public method list, no batches, bodies <=16 KiB, eight
concurrent upstream jobs, five-second client read timeout, ten requests/IP/second,
100 requests/second overall and bounded client bookkeeping. Expensive log scans,
trace/debug and signing methods are excluded. `eth_call`/estimate run under these
limits and upstream deadlines; transaction fanout reuses faucet/relay.py and checks
every validator's chain ID/genesis before sending. A partial broadcast is ambiguous:
inspect its hash on every node; do not automatically retry.

## Build artifacts on Linux

Use the compatible exact source revisions in [pins.json](pins.json), including the
ureth and aggregator already exercised by [H6](../../docs/operations/h6/README.md)
and the [faucet evidence](faucet/evidence/README.md). The BFT pin includes the merged
faucet. Fetch three separate clean source checkouts at those commits; never use
`main`, a moving tag or the old fake-executor docker-compose.evm.yml for this stack.
Build on Debian 12/bookworm (the runtime ABI); building on a newer glibc host
can produce incompatible ELF files. Build requirements and Go/Rust versions are in [the operator guide](../../docs/operations/testnet/OPERATOR.md#2-prerequisites).
Linux packaging is new groundwork; H6's native macOS evidence does not validate it.

From this PR's repository root, on the target Linux build host:

```sh
python3 deploy/testnet/build-images.py \
  --bft-source /srv/src/bft-pinned \
  --ureth-source /srv/src/ureth-pinned \
  --aggregator-go-source /srv/src/aggregator-go-pinned
go build -o build/tn-keygen ./deploy/testnet/keygen
```

The builder reuses `make build`, `cargo build --locked` (ureth), `go build` with cgo (aggregator-go) and the existing faucet
Dockerfiles. It checks clean source revisions, builds Linux ELF binaries and
checks their `--help` inside the runtime image. Exact base-image digests are pinned;
OS package installation is resolved at build time. `artifacts/images.json` records
source pins, binary hashes and immutable **final local image IDs**, so subsequent
starts/restores cannot silently change even if a builder tag is reassigned.
Preserve this manifest and export these images with `docker save`; transfer/load
them on the server and backup host. Local image IDs require image loading on a
new host; this package does not assume a registry publication or signing service.
Keep the PR checkout used for packaging too. Do not use CI fixture image IDs.

## Generate and deploy (second operator)

Run with Bash `set -eo pipefail`. Use a dedicated private state parent outside the
checkout. Use generation directory names beginning `tn-`. On a shared local
machine take `../briefs/devnet-lock.sh tnops <command...>` around any full rehearsal;
the lock releases on exit. Do not remove a live lock or run alongside its owner.

```sh
umask 077
sudo -E python3 deploy/testnet/generate.py --out /srv/testnet/tn-20261007 \
  --validators 4 --chain-id 31337 \
  --ubft /srv/src/bft-pinned/build/ubft \
  --captcha-sitekey YOUR_SITE_KEY \
  --captcha-secret-file /srv/secrets/hcaptcha-secret
sudo chown -R 10001:10001 /srv/testnet/tn-20261007
cd /srv/testnet/tn-20261007
docker compose config --quiet
# Authorities already run; start only the remaining services, preserving lifetimes.
SERVICES=$(docker compose config --services | sed '/^authority/d')
docker compose up -d $SERVICES
docker compose ps
curl --fail http://127.0.0.1:8545/healthz
curl --fail http://127.0.0.1:8088/healthz
```

The generator must run as host root on Linux to assign UID 10001 ownership;
containers run without root privileges. Never run `docker compose down`,
`restart authorityN`, `up --force-recreate`, or reboot on a network you intend to
keep. If generation fails after authorities start, keep ingress closed, inspect
the error, then deliberately `docker compose down` and discard that incomplete
generation before retrying a new name.

Generator initializes and signs the trust base using ubft, enrolls independent
signing authorities using existing CLI commands, finalizes the B1 genesis (verified against an independent `b1genesis --verify` regeneration before anything starts) and
funds **only a random dedicated faucet account** with 1000 disposable UCT. Its V3
keystore and random password stay in private files. It creates no known Hardhat
allocation. Engine JWTs and reset entropy are fresh. The printed block-zero hash
is derived by ubft from the finalized genesis, not its file SHA-256. It writes that
identity directly into the faucet config and public manifest. Verify every node's
`eth_chainId` and `eth_getBlockByNumber("0x0", false)` against the manifest before
opening routing. On Linux `docker compose exec ureth1 ...` has no curl; use a
trusted client container joined to the project's internal validator network, or
`docker compose exec rpc python3 -c` with urllib. Never publish Engine/admin ports
to make verification easier. Startup races retry through restart policies;
persistent restart loops are failures, not readiness.

Configure host nginx with [nginx.conf.example](nginx.conf.example) and the
[faucet nginx example](faucet/nginx.conf.example); provide real names and TLS
certificates, `nginx -t`, then reload. Only open host TCP 443 (80 for certificate
renewal if needed), with SSH restricted to operators. Do not publish 8545/8088/9090.
Bridge subnets 172.30.88.0/24 and 172.30.89.0/24 must be unused. Verify Docker's
actual proxy socket peer: faucet trusts only 172.30.88.1 and RPC only 172.30.89.1;
nginx must overwrite X-Forwarded-For. Adjust the exact peer config deliberately if
the host differs. Never disable hCaptcha publicly. Publish NOTICE.txt, the current
chain/genesis manifest, wallet setup, status URL and the incident-owner role's reporting channel.
[TESTER.md](../../docs/operations/testnet/TESTER.md) is the wallet and transaction page for external testers; it points them at `tester-check.py`, which checks an endpoint against the published chain ID and block-zero hash.

Use a fresh external wallet pinned to the generated chain ID/genesis. Claim test
UCT via the faucet, wait for a successful receipt, then submit a signed native
transfer through `https://rpc.<domain>/`. Record hash, successful receipt, block
hash and certified shard head. Gateway responses alone do not prove certification.
Reject old genesis wallet pins, signing/admin/Engine methods, batches, malformed
JSON, >16 KiB bodies and burst traffic. Capture 400/429 results and verify ordinary
RPC still responds afterwards. A raw externally signed transaction must enter
**all** paired mempools; the RPC relay handles that fanout.

## Monitoring, logs and incidents

Prometheus scrapes root `/api/v1/metrics` and RPC counters, keeps seven days / 1 GiB
and is accessible only on loopback port 9090 (SSH tunnel for operators).
`TestnetTargetDown` and `TestnetRPCFailures` appear in `/alerts`; connect an approved
Alertmanager route when the deployment supplies one. No alert delivery is claimed
until that route is tested. Watch gateway `/healthz`, faucet `/healthz` (budget,
balance, network pin), aggregator internal `/health` (port 8080 in validator 1's namespace), the `mongo` healthcheck, `docker compose ps`, restart
counts, host disk/RAM and shard logs. A responding root metrics target alone does
not prove consensus progress; compare root roundInfo and certified shard heads
between samples. Notify the incident owner if certified heads stop for 2 minutes,
any pod repeatedly restarts, disk >80%, or faucet balance falls below its reserve.
Pause claims on uncertain nonce outcomes; follow the faucet runbook for refill.

Docker collects every container's stdout/stderr with rotation. Export incidents:
`docker compose logs --no-color --timestamps --since 1h > /secure/path/incident.log`.
For each incident record generation, manifest, UTC start/end, affected services,
transaction hashes, heads, restarts and recovery decision. Never publish env-file
secrets, keystores, authority stores or `docker inspect` output containing keys.
Roles, not persons: the **network operator** owns pause/restart and routine operation,
the **incident owner** owns an incident from detection to the recorded recovery decision
and restore verification, the **release manager** owns the pinned manifest and approves
a destructive reset, and the **faucet operator** owns refill and the faucet's alerts.
Before public launch the deployment records which people hold these roles in its own
handover and verifies the public status URL is reachable. This package creates no
production SLA.

## Quiesced backup and same-generation restore

**There is no signing-authority key export, backup or restore.** Do not add key
persistence to work around this protocol property. Authorities must survive a
same-generation recovery, as in [H6 scenarios](../../docs/operations/h6/scenarios.md).
The single host is therefore a shared key-loss failure domain as well as a
shared availability failure domain. Total host/daemon loss requires fresh genesis;
archives can preserve evidence but cannot revive the lost authority lifetimes.

[backup.py](backup.py) stops **all non-authority services**, checks every authority
is live/enrolled/healthy, records its fingerprint, session, enrollment and signing
reservation, then archives the quiesced paired DBs/trust history, ureth DBs,
execution journals, archives, faucet caps, configs and credentials. Credentials
are not signing keys; no tar file contains those memory-only keys.

```sh
# Stop public routing/claims first. Destination must be outside generation.
sudo -E python3 /path/to/repo/deploy/testnet/backup.py backup \
  /srv/testnet/tn-20261007 /srv/backups/tn-20261007.tar.gz
# Keep authorities LIVE. For an immediate recovery drill, leave other services stopped.
sudo -E python3 /path/to/repo/deploy/testnet/backup.py restore \
  /srv/testnet/tn-restored /srv/backups/tn-20261007.tar.gz \
  --live-generation /srv/testnet/tn-20261007
sudo chown -R 10001:10001 /srv/testnet/tn-restored
cd /srv/testnet/tn-restored
docker compose config --quiet
SERVICES=$(docker compose config --services | sed '/^authority/d')
docker compose up -d $SERVICES
```

The restore refuses missing, stopped, changed or advanced authority state. It
rewrites authority mounts to the **surviving original directories**, retains the
original Compose project identity and leaves authority containers untouched.
Run only one producer copy. Verify every node's genesis/certified head, original
successful receipt, authority fingerprint/session/high-water status and preserved
faucet duplicate cap, then a fresh funded transaction. Keep ingress closed until
all checks pass. For periodic backup, resume only non-authority services using
the same explicit service list; after signing state advances, an older archive
cannot be blindly restored by this command. Use the existing H6 archive replay
procedure against the surviving authority, not a bare DB rollback or clone.

Copy encrypted archives, digest, exact `docker save` images and checkout off host.
Check decrypt/load before relying on them. Backups contain disposable root/shard
keys, Engine JWTs, faucet key/password, operator/client credentials, the aggregator
key (`aggregator/keys.json`) and the aggregator's MongoDB data; restrict access. SHA-256 checks integrity, not authentication against a
malicious supplier. Off-host archives support investigation and retained history;
they are **not full-host same-network disaster recovery**. Coupled rotation,
interrupted handoff/abort and replay remain #432 acceptance work. If those
constraints prevent recovery, use the explicitly asset-losing reset below.

## ASSET-LOSING arbitrary reset

Stop public nginx routing/claims; export public evidence and a quiesced backup if
wanted. The following **deletes the old generation, including all balances,
history, keys, authority state and faucet budgets**. It records the old public
manifest beside the old directory and builds a new network. A failed regeneration
leaves the old network destroyed: retain a backup first when recovery is desired.

```sh
sudo -E python3 /path/to/repo/deploy/testnet/reset.py \
  --old /srv/testnet/tn-20261007 --lose-all-assets -- \
  --out /srv/testnet/tn-20261008 --validators 4 --chain-id 31337 \
  --ubft /srv/src/bft-pinned/build/ubft \
  --keygen /path/to/repo/build/tn-keygen \
  --captcha-sitekey YOUR_SITE_KEY --captcha-secret-file /srv/secrets/hcaptcha-secret
sudo chown -R 10001:10001 /srv/testnet/tn-20261008
```

Start as above. Require changed block-zero hash, new keys/account, all validators
matching the new manifest, old wallet claim 409, new-wallet faucet claim and a
paid external-client transaction. Update public manifests/wallets/status and
announce asset loss before restoring ingress. No compatibility or migration.

## Reward pool (PoS profile)

The roots' `pos-deployment.json` carries the funded reward pool (`rewardPool`, `rewardPoolCodeHash`), and generation checks the pool's code hash and its exact
funding against the genesis state. The pool's commands are the relayer's `ubft pos-relayer tx reward` (each takes `--eth-rpc`, `--pos-deployment` and `--sender-key`,
the account that pays for the transaction):

- `settle`: anyone. It reads the pool's next authenticated root records and closes the next intervals until the pool accepts no more (`--max-steps` bounds a run).
  No operator privilege is involved: the pool decides from the authenticated records.
- `claim`: the payee, the sender being the payee (`--amount-wei`, `--to` the recipient). It pays out a credit the payee has earned.
- `fund`: adds value to the pool (`--value-wei`). Only value sent through `fund` is allocated to rewards: a plain transfer to the pool address is not.

## Observation/fault campaign and evidence limits

Second operator records checkout, pins, image IDs/hashes, host specs, exact commands
and public outputs. Run a 24-hour initial observation (no SLA): sample certified
heads/rounds, health, restarts, memory/disk and public RPC/faucet each minute. With
N=4 stop/restart **one validator's root/shard/ureth at a time while keeping its authority alive**, check survivor progress and convergence,
then quiesced backup/restore and deliberate reset. N=3 is a constrained local smoke
profile: it does not establish one-validator fault tolerance. Never claim a
single-host run proves independent failure domains. Test malformed/limited requests
during observation and confirm recovery of normal requests. Preserve receipts,
certification logs and before/after manifest IDs. Record failures as failures.

The sampler is `observe.py` (read-only: no key, credential or signing method): `python3 deploy/testnet/observe.py $G --out /secure/path/observe` takes one sample a minute for 24 hours (`--interval`, `--duration`, `--samples`): every root's certified epoch and round, the gateway's `/healthz` and block number, the faucet guard's `/healthz` (its body, with the budget and balance, is kept for the OPERATOR to compare with the reserve: not judged by the tool; the aggregator's `/health` and the `mongo` healthcheck are likewise manual), every service's state, health and restart count, memory of this project's containers and disk use. It prints an `ALERT` and exits 1 for the notification rules above: certified heads stopped for `--stall` seconds (120; no root's round moved, or the execution chain's block at the gateway did not: the roots keep certifying while a stuck shard does not), a service not running or unhealthy, a restart count that went up, disk above `--disk-limit` percent (80), the gateway or faucet not answering 200. The rehearsal runs it as a four-sample smoke (stage `observe`, `--no-faucet`: the faucet guard's health needs the signer, which a rehearsal does not start); that proves the collection and the alert rules on a runner, not a day on the host.

For a generation made with `--pos`, `pos_sample.py` (same options, same read-only rule, reuses `observe.collect` and `observe.Watch`) adds the contracts' clock and books to every sample, read through the gateway: the registry's `progress()`, `ucTime()`, `recordCount()`, the custody's `recordCursor()`, the election's `thresholds()`, `openResult()`, `liveCount()`, and the reward pool's balance, `available()`, `totalCredits()`, `accounted()`, `nextStart()`. Extra alerts: registry progress stopped (`--stall`), the custody behind the registry's record count for more than `--lag` s, an election result open for more than `--open-limit` s (while one is open the pool closes the tail only up to the reservation progress, contracts#72), the pool holding less than it has accounted for, no funded balance left, an unreadable view. On a rehearsal runner use `--no-faucet`; the gateway needs the forwarded address, which the sampler sets. It samples the package where it runs; it says nothing about a host unless it runs on that host.

CI runs gateway refusal/topology tests, existing faucet tests, two fresh genesis
ceremonies with fixture image IDs, Compose validation, Prometheus rule/config
validation and RPC-image build. It does not run four ureths. Native previous
faucet evidence is retained; its explicit limits still apply. Local Docker bring-up,
external client transfer, faucet dispense, restart, quiesced restore and real reset
are **pending** when no daemon/server is available; see evidence/README.md. Do not
close #432/#434 without server rehearsal, second-operator results and independent
internal review. No merge is authorized by this package.

## Package regression checks

PR CI requires `docker compose config --quiet` for generated fixture topologies
N=3,4,7; this parsing step needs no Docker daemon. Package tests check the
signer's generated invocation against the tracked script permissions (the image
copies a readable script and invokes it through `/bin/sh`), the aggregator-go and
MongoDB service settings, and rejection of an otherwise valid allowed JSON-RPC request larger
than 16 KiB before any relay call.

CI also builds aggregator-go from `pins.json`'s revision and runs
`validate-generation.py --aggregator <pinned-binary>`: a native three-root probe
using generated keys, partition configurations and aggregator environment, with
host paths and loopback transport addresses substituted, against the pinned MongoDB
image started in Docker as a one-member replica set. It checks that the aggregator
partition asks for no consistency proof, submits a real SDK request, waits for its certified inclusion proof, and requires the root's
partition-7 certified round and state root to advance. HTTP admission or empty
rounds alone cannot pass. No EVM validator or faucet is started by this probe;
it does not supply the owner-server deployment, recovery or campaign evidence
required above. Local validation is deferred to PR CI for this revision.
