# Single-server PoA testnet package (TN-OPS groundwork)

Read [NOTICE.txt](NOTICE.txt) before using this network. All test UCT and other
assets are disposable. This package supports #434 and the deployment/reset part
of #432; it does not close either issue. The owner's bare-metal server, DNS,
contacts and hCaptcha credentials are still to be supplied. No public deployment,
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
The one aggregator uses the existing F8 RSMT profile, partition 9/full range;
EVM is partition 8/full range. This is PoA with profile-2 authenticated history,
layout-2 registry and no bridge or staking allocation. The registry bytecode and
engine protocol are supplied by the pinned BFT/ureth builds.

The generated `compose.yaml` is JSON (valid YAML), default N=4, configurable N=3..32.
All services have CPU/memory/PID limits, explicit restart policies, read-only root filesystems
and bounded Docker JSON logs (30 MiB/service). Each pod caps memory at 2.625 GiB;
shared services cap another 1.625 GiB, approximately **12.125 GiB for N=4** and
**9.5 GiB for N=3**, plus Docker/OS/page cache/build overhead. Plan at least 24 GiB
server RAM, 8 cores, 100 GiB initial SSD and off-host backup space; these are initial
planning budgets, not measured capacity. On the shared 16 GiB development Mac use
N=3 only when memory is available. Never build Rust while rehearsing the cluster.
Monitor disks: retention bounds metrics/logs but does not bound chain databases.

Only public RPC (8545), faucet (8088) and Prometheus (9090) bind **host loopback**.
No root admin, shard admin, authority or Engine endpoint has a published port.
The validator network is internal. The faucet's isolated signer has Internet
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
can produce incompatible ELF files. Build requirements and Go/Rust versions follow [H6 build](../../docs/operations/h6/build.md).
Linux packaging is new groundwork; H6's native macOS evidence does not validate it.

From this PR's repository root, on the target Linux build host:

```sh
python3 deploy/testnet/build-images.py \
  --bft-source /srv/src/bft-pinned \
  --ureth-source /srv/src/ureth-pinned \
  --rugregator-source /srv/src/rugregator-pinned
go build -o build/tn-keygen ./deploy/testnet/keygen
```

The builder reuses `make build`, `cargo build --locked` and the existing faucet
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
signing authorities using existing CLI commands, finalizes layout-2 genesis and
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
chain/genesis manifest, wallet setup, status URL and actual support contacts.

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
Alertmanager/duty channel when the owner supplies it. No alert delivery is claimed
until that route is tested. Watch gateway `/healthz`, faucet `/healthz` (budget,
balance, network pin), aggregator internal `/health`, `docker compose ps`, restart
counts, host disk/RAM and shard logs. A responding root metrics target alone does
not prove consensus progress; compare root roundInfo and certified shard heads
between samples. Page the duty operator if certified heads stop for 2 minutes,
any pod repeatedly restarts, disk >80%, or faucet balance falls below its reserve.
Pause claims on uncertain nonce outcomes; follow the faucet runbook for refill.

Docker collects every container's stdout/stderr with rotation. Export incidents:
`docker compose logs --no-color --timestamps --since 1h > /secure/path/incident.log`.
For each incident record generation, manifest, UTC start/end, affected services,
transaction hashes, heads, restarts and recovery decision. Never publish env-file
secrets, keystores, authority stores or `docker inspect` output containing keys.
Before public launch fill duty operator, backup operator, owner escalation and
public support/status URL in the operational handover; verify reachability. The
duty operator owns pause/restart, backup operator owns restore verification and
owner decides destructive reset. This initial package creates no production SLA.

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
keys, Engine JWTs, faucet key/password, operator/client credentials and aggregator
keys; restrict access. SHA-256 checks integrity, not authentication against a
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

CI runs gateway refusal/topology tests, existing faucet tests, two fresh genesis
ceremonies with fixture image IDs, Compose validation, Prometheus rule/config
validation and RPC-image build. It does not run four ureths. Native previous
faucet evidence is retained; its explicit limits still apply. Local Docker bring-up,
external client transfer, faucet dispense, restart, quiesced restore and real reset
are **pending** when no daemon/server is available; see evidence/README.md. Do not
close #432/#434 without server rehearsal, second-operator results and independent
internal review. No merge is authorized by this package.
