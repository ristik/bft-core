# TN-1 release review: checklist and record template (#436 X-TEST)

For the independent internal review of the assembled TN-1 release. The reviewer is a role (release reviewer), not the author of the package, and does not share a checkout
with the person who built the images. This page is the prepared pack: what to check, where to look, how, and the record to fill. It does not review anything by itself,
it does not replace the second operator's run or the measured envelope on the host, and closing #436 records only #436's acceptance: it authorizes no production deployment,
issuance, real-value custody or production PoS switch.

Prerequisites (#436): #434, #435, #433 closed with their evidence. Findings that are material to correctness are closed, or the affected feature is disabled and this
review is repeated on the release without it.

## 0. Pin the release under review

Record, before anything else, and refuse to continue on a mismatch:

| item | how | record |
|---|---|---|
| bft-core revision | `git rev-parse HEAD` in a clean clone; must equal `pins.json` `bft` or be reviewed with the diff stated | |
| ureth, aggregator-go revisions; the MongoDB image reference | `deploy/testnet/pins.json` | |
| image IDs | `docker image inspect --format '{{.Id}}' <image>` for each image in `deploy/testnet/artifacts/images.json`; equal to the manifest | |
| generation and manifest | `manifest.json` of the deployed generation: `generation`, `chain_id`, `genesis_hash`, `artifacts` | |
| `config_sha256` | recompute `sha256sum network/*.json` in the generation; equal to `manifest.json` `config_sha256` | |
| public values | `python3 deploy/testnet/tester-check.py --rpc <rpc-url> --manifest <manifest.json>` (exit 0) | |

## 1. Checklist

**Read the generated `compose.yaml` directly** (it is JSON); do not attach `docker compose config` output to the record. No service takes a secret through `env_file` or its environment (row 15), but `docker compose config` would expand one if a later change added it.

Each row: the check, where to look, and what a pass is. Record `PASS`, `FAIL` (with the finding id) or `N/A` (with the reason), and the exact command and output for anything not obvious.

### 1.1 Manifest and code permissions

| # | check | where / how | pass |
|---|---|---|---|
| 1 | The pinned sources are the built ones | `build-images.py` refuses a pin mismatch or a dirty tree; compare its output and `images.json` with section 0 | revisions equal; no local patch |
| 2 | Genesis and trust base are the ceremony's | `manifest.json` `genesis_hash`, `network/trust-base.json`; `generate.py` ran from the pinned revision | block-zero hash equals the manifest on every validator (`rehearse.py` `identity` does this); `sha256sum network/trust-base.json` equals its entry in `manifest.json` `config_sha256` (section 0) |
| 3 | Files the containers read are not writable by them where they should not be | `ls -ln` of the generation: `network/` read-only mounts (`:ro` in `compose.yaml`), per-validator state owned by UID 10001 only | no state directory is shared between two validators |
| 4 | The authorities cannot be restarted by accident | `compose.yaml` `authority*` has `restart: "no"`; the handoff and restore procedures keep them live | as stated |
| 5 | No compatibility or migration code is relied on | NOTICE.txt states arbitrary reset; `reset.py` is the only path to a new generation | as stated |

### 1.2 Exposed services

| # | check | where / how | pass |
|---|---|---|---|
| 6 | Only the intended host ports exist | the `ports` entries of the generated `compose.yaml` (read the file; it is JSON; see the warning below on `docker compose config`); `ss -ltnp` on the host | `127.0.0.1:8545` (rpc), `127.0.0.1:8088` (faucet guard), `127.0.0.1:9090` (Prometheus) only; nothing on 0.0.0.0 except the host's reverse proxy on 443 (and 80 for renewal) and SSH restricted to operators |
| 7 | No Engine, admin, root-operator or authority endpoint is published | same listing | none present |
| 8 | The validator network is internal | `compose.yaml` `networks.validators.internal: true`; only `rpc` (also on `edge`), `relay` and `prometheus` (also on `faucet`) join another network, and the guard (`faucet`) and `signer` are on `faucet` only | `validators.internal: true`. The `faucet` network is not internal (the signer needs egress for hCaptcha), so `relay` and `prometheus` bridge the validator network to a network with Internet egress: record that `relay` serves only its method list and `prometheus` only scrapes |
| 9 | Gateway refuses what it should | `python3 deploy/testnet/rehearse.py --stages gateway-limits` on a rehearsal generation, or the same requests by hand against the host | signing, admin, Engine, debug, batch, malformed, oversized and wrong-path requests all refused; per-address limit answers 429 |
| 10 | Proxy trust is exact | the reverse proxy overwrites `X-Forwarded-For`; Docker's proxy peer is `172.30.88.1` (faucet) and `172.30.89.1` (rpc) on this host | a request with a forged `X-Forwarded-For` from outside does not change the address the gateway limits |
| 11 | The public journey needs a funded, pinned wallet | `TESTER.md` followed on a fresh wallet (its `cast send` needs `--legacy`; the gateway refuses `eth_feeHistory`): faucet claim, receipt, paid transfer through `https://rpc.<domain>/` | each step as the page says; a wallet pinned to another chain ID or block-zero hash is refused |
| 12 | hCaptcha is on in public | faucet configuration has a site key; the signer holds the secret | a claim without a token is refused (that is the guard's check; on the host also send a claim with an invalid token: the signer must ask hCaptcha and refuse it) |

### 1.3 Key isolation

| # | check | where / how | pass |
|---|---|---|---|
| 13 | Each validator's signing key is held by its own authority only | `compose.yaml` mounts: `validator%d/auth` (the authority's key, sockets and credentials) is mounted by `authority%d` and by that validator's own `shard%d` (client socket and credential) and by nothing else | no container mounts another validator's `auth`; the root nodes and every other service mount none |
| 14 | Faucet key and captcha secret are Docker secrets | `compose.yaml` `secrets:`; `faucet-secrets/` modes | readable only by the signer; not in `compose.yaml`, environment or images |
| 15 | The aggregator's key is a private file | `aggregator/keys.json` mode and owner (10001, 0600), mounted read-only by `aggregator` only; the `aggregator` and `mongo` services have no `env_file` and no key, secret or password in their environment in the generated `compose.yaml` | as stated |
| 16 | Containers are least-privilege | the generated `compose.yaml`: every service has `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, a non-root user (only `prometheus` and `mongo` set `user` in `compose.yaml`; for the others `docker image inspect --format '{{.Config.User}}' <id>` for each image in `images.json` must print a non-root user), `mem_limit`, `cpus`, `pids_limit`. `mongo` has no authentication: it is on its own internal `aggregator` network, which only `pod1` joins, so every container in validator 1's namespace (`root1`, `shard1`, `metrics1`, `aggregator`) reaches it. That is validator 1's trust domain (the co-hosted entity is trusted, validator-entity model); no other service reaches it | no exceptions without a written reason |
| 17 | The generation directory and backups carry no secret in a public place | backup archive location, mode; the manifest and `network/` contain no private key; the review record itself (no key, no `docker compose config` output) | as stated |

### 1.4 Resource bounds

| # | check | where / how | pass |
|---|---|---|---|
| 18 | Per-container limits are set and sum below the host | `mem_limit`/`cpus` totals from `compose.yaml` against `free -m`, `nproc` on the host | total below the host with headroom stated |
| 19 | Logs, metrics and the journal are bounded | `logging.options` (10 MiB x 3), Prometheus `retention.size`, shard `--journal-candidates`, `--archive-prune` | as stated |
| 20 | Request size and rate limits hold | 16 KiB body (raw transactions, `eth_call` and `eth_estimateGas` 4.5 MiB, two at once), 10 requests/s per address, 100/s overall; the aggregator route 64 KiB, 10/s per address, 50/s overall; faucet body 2 KiB | refusals observed (row 9) |
| 21 | Measured envelope | the host's own measurements of memory, CPU, disk growth and RPC/proof capacity under the load generator at the selected limits (`loadgen.py`) | numbers recorded with the host and revision; a hosted-runner figure does not count |

### 1.5 Replay and recovery

| # | check | where / how | pass |
|---|---|---|---|
| 22 | One validator entity down and back | `rehearse.py --stages pod-restart` evidence (and the host run) | the public gateway fails closed while down; survivors certify; the entity rejoins on the same block |
| 23 | Quiesced backup and same-generation restore | `backup.py` run on the host; `rehearse.py --stages backup-restore` evidence | archive and sha256 exist; restored validators agree on blocks and the funded nonce |
| 24 | Reset | `reset.py`; `rehearse.py --stages reset` evidence | block-zero hash changed; old wallet pin gets 409; new network pays a transfer |
| 25 | Replay of its own history | the native lane evidence (T6) and the archive restore rows X-29 to X-31 of the failure matrix | cited rows MET at the revision under review, or the limit stated; the archive replicas became a derived two-of-three set in #751, so re-check these rows against that change |
| 26 | A second operator performed the procedure | that operator's record | present, with interruption times; if absent the release is not reviewable here (X-32, X-57) |

### 1.6 Disclosed assumptions

| # | check | where / how | pass |
|---|---|---|---|
| 27 | Central operator, one host, arbitrary reset, no value and no SLA are disclosed to users | `NOTICE.txt`, the faucet page, `TESTER.md` | each of the four is stated and reachable from the faucet and RPC landing text |
| 28 | The failure matrix covers the slice | `docs/pos/x1-failure-matrix.md` sections 13 (TN-1 slice, #766) and 14 (TN-S PoS handoff slice, X-58..X-65, X-81, X-82; the PoS profile is reviewed only if it is in the release). X-81 (unequal weights) is MET-BY-DECISION, owner §42 (Q21 = A): not reachable at D ≤ 1/2, `nMax` 6; the native Q3 lane is the weighted-epoch evidence | every row MET, MET-BY-DECISION, MET-WITH-LIMIT with the limit read, or MISSING and listed in the residual limits below |
| 29 | Docs name roles, not persons | `deploy/testnet`, `docs/operations/testnet` | no personal names, handles or addresses |
| 30 | The single aggregator is trusted, not verified | `network/aggregator-conf.json` has no `proof_type` (aggregator-go sends no SMT consistency proof); `NOTICE.txt` and `TESTER.md` | disclosed: the root accepts the single aggregator's signed state roots without verifying its tree |

## 2. T1 to T4 evidence cross-check

For each of the accepted T1 to T4 evidence items in the TN-1 tree (clean build, supply, WUCT and SELFDESTRUCT scope, native lane), fill one row. Evidence stays valid only for the artifacts it was produced for.

| evidence item | artifact it covers (revision) | changed since? (`git diff <rev>..<release> -- <paths>`) | status: retained with its scope / refreshed / invalid |
|---|---|---|---|
| | | | |

A row whose artifact changed is refreshed or its limit is written down in the record; it is not carried over silently.

## 3. Review record (copy this block into the review PR or issue comment)

```
TN-1 release review record
Reviewer role: release reviewer            Date (UTC):
Release: bft-core <rev>   ureth <rev>   aggregator-go <rev>   mongo <image digest>   generation <name>
Image IDs: <per image>     manifest chain_id/genesis_hash: <values>
Environment: <host or runner; kernel, Docker version, cores, memory, disk>

Checks:   section 1 rows 1-29: PASS <n>  FAIL <n>  N/A <n>   (attach the filled table)
T1-T4:    <retained n / refreshed n / invalid n>   (attach the filled table)
Commands and outputs: <attach, with the exact commands run>

Findings:
  F1  <severity: material correctness | other>  <what, where, evidence>  <closed in <PR> | feature disabled | open>
  ...
Residual limits (carried to the release notes):
  - <each MISSING or MET-WITH-LIMIT row that still applies, with its owner>
Planned observation/fault campaign: <24 h sampling and the one-validator-at-a-time faults, per deploy/testnet/README.md, with the start date and who runs it>

Conclusion: ACCEPT / ACCEPT WITH LIMITS / REJECT   (this closes #436's acceptance only)
```
