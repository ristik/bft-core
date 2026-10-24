"""Crash recovery of a validator entity on the PoS network (TN-S #430, P8-TEST #437; bft-core issue #843): the unclean counterpart of pos-restart.

OPT-IN stages, not in the default list: today an entity does NOT recover whenever its EXECUTION CLIENT (ureth) is SIGKILLed, alone or with the shard node or the root, at root
epoch 1, 2 or 3 (issue #843: the survivors keep certifying, but the restarted ureth stays at its old block and the shard node cannot re-feed it, e.g. `execution recovery:
finalized-branch conflict`). Killing only the shard node or only the root recovers. A failing expectation cannot be in the default run; these stages are named explicitly
(`--stages` / the workflow's `pos_stages`) to reproduce and to localize it.

Stages (each kills ONE entity, never pod<i> (the namespace holder: its loss strands root and shard, OPERATOR lifecycle note) and never authority<i> (a restarted authority has a
new key, README)); they differ in WHAT is killed and WHEN:
  pos-crash          ureth + root + shard, epoch 3 (after pos-handoff-2 and pos-recreate; run before pos-owner, which must stay last)
  pos-crash-ureth    the execution client only          pos-crash-shard   the shard node only        pos-crash-root   the root only
  pos-crash-ureth-shard  execution client and shard node
  pos-crash-e1       all three at epoch 1 (genesis, after pos-smoke)        pos-crash-e2   all three at epoch 2 (after pos-advance)
Each scenario is its own rehearsal run: a broken entity cannot be repaired, and 3 of 4 roots (the threshold) must stay up for the next one.

Per scenario: `docker compose kill -s KILL` (no shutdown hook, no flush); the three survivors keep certifying (their root rounds advance) and mine a transaction; the containers
the containers carry `restart: unless-stopped`, but `docker compose kill` marks a container as manually stopped, so Docker's restart policy is ignored by design (the first run
showed it was not applied); the stage still waits RESTART_WAIT s in case it is, then `compose start`s the killed ones (as pos-restart does: the container, install flag included,
is kept); then it waits CONVERGE_WAIT s for the entity's execution client to have the survivors' transaction (the
same block) and its root head to be at the epoch within LAG rounds of the survivors'. EXPECTED (and failing today whenever ureth is killed, alone or with the shard node or the
root): it converges by that first restart. If it does not, the stage still records, in evidence/pos-crash-<tag>.json, whether (2) a graceful restart of the execution client, (3) a graceful stop and start of all
three, recovers it, and keeps the logs of the entity (evidence/pos-crash-<tag>-<service>.log, whole, from the kill): is the conflict a retry loop or permanent state. Only then
does it fail.

NOT shown: that a restarted root VOTES (an advancing head shows it follows the chain; 3 of 4 certify without it, the pos-recreate lesson).
"""
import json
import re
import subprocess
import sys
import time

import handoff_ops

RESTART_WAIT = 90
CONVERGE_WAIT = 180
LAG = 8            # rounds the restarted root's head may trail the best survivor's once it has converged
BAD = re.compile(r'panic:|panicked at', re.I)
WARN = re.compile(r'\b(ERROR|WARN)\b|level=(error|warn)', re.I)


def scan_log(text):
    """(panics, warnings) line counts of a container log."""
    lines = text.splitlines()
    return sum(1 for x in lines if BAD.search(x)), sum(1 for x in lines if WARN.search(x))


def restart_counts(r, names):
    """{service: RestartCount} of the containers of `names` (None for a service without a container)."""
    counts = {}
    for name in names:
        cid = r.compose('ps', '-a', '-q', name, check=False).strip()
        out = subprocess.run(['docker', 'inspect', '--format', '{{.RestartCount}}', cid], text=True, capture_output=True).stdout.strip() if cid else ''
        counts[name] = int(out) if out.isdigit() else None
    return counts


def head(r, i, transport):
    """(epoch, round) of root i's committed certificate, or None."""
    try:
        status, body = transport.post(i, '/api/v1/q3/signers', b'{}')
        data = json.loads(body) if status == 200 else None
        return (data['epoch'], data['round']) if data else None
    except Exception:   # a root that is down does not answer: "not yet"
        return None


def block_number(r, i):
    try:
        return int(r.ureth(i, 'eth_blockNumber'), 16)
    except Exception:
        return None


def scenario(r, tag, parts, epoch):
    """Kill the `parts` ('ureth', 'root', 'shard') of every entity in r.pods (one at a time), restart, check convergence. Writes evidence/pos-crash-<tag>.json."""
    transport = handoff_ops.DockerTransport(r.gen)
    deployment = json.loads((r.gen / 'network' / 'pos-deployment.json').read_text())
    sender, to = r.manifest['faucet_address'], '0x' + '55' * 20
    r.expect(all((head(r, j, transport) or (None,))[0] == epoch for j in range(1, r.n + 1)), f'precondition: every root certifies at epoch {epoch}')
    rows = []
    for i in r.pods:
        names = [f'{p}{i}' for p in parts]
        everything = [f'ureth{i}', f'root{i}', f'shard{i}']
        survivors = [j for j in range(1, r.n + 1) if j != i]
        row = {'entity': i, 'killed': names, 'epoch': epoch}
        rows.append(row)
        before_rounds = {j: head(r, j, transport)[1] for j in survivors}
        before_restarts = restart_counts(r, names)
        since = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        r.say(f'  SIGKILL of {" ".join(names)} (restart counts {before_restarts}), epoch {epoch}')
        try:
            r.compose('kill', '-s', 'KILL', *names)
            for j in survivors:
                r.wait(f'survivor root {j} certifies past round {before_rounds[j]} with {" ".join(names)} killed',
                       lambda j=j: (head(r, j, transport) or (0, 0))[1] > before_rounds[j] + 2, 180)
            r.expect(True, f'the {len(survivors)} surviving roots keep certifying while {" ".join(names)} are killed')
            row['survivors_certify'] = True
            nonce = int(r.ureth(survivors[0], 'eth_getTransactionCount', [sender, 'latest']), 16)
            raw = r.raw_tx(to, nonce, int(r.ureth(survivors[0], 'eth_gasPrice'), 16))
            tx = r.cast_run('keccak', raw)
            for j in survivors:
                reply = r.inner_reply(f'http://ureth{j}:8545', 'eth_sendRawTransaction', [raw])
                error = str(reply.get('error', '')).lower()
                known = 'already known' in error or ('nonce too low' in error and r.ureth(j, 'eth_getTransactionReceipt', [tx]) is not None)
                r.expect(reply.get('result') == tx or known, f'survivor {j} accepts the transaction', json.dumps(reply)[:200])
            blocks = set()
            for j in survivors:
                receipt = r.wait(f'survivor {j} mines it with {" ".join(names)} killed', lambda j=j: r.ureth(j, 'eth_getTransactionReceipt', [tx]), 240)
                r.expect(receipt['status'] == '0x1', f'survivor {j} has a successful receipt', receipt['blockHash'])
                blocks.add(receipt['blockHash'])
            r.expect(len(blocks) == 1, 'the survivors agree on the including block')
            row['survivors_mine'] = True

            def running():
                return set(names) <= set(r.compose('ps', '--services', '--status', 'running').split())

            try:   # docker compose kill marks the container manually stopped: `restart: unless-stopped` is ignored by design; waiting is only a check
                r.wait('the restart policy brings the killed containers back', running, RESTART_WAIT)
                row['restart'] = 'policy'
            except Exception:
                r.say(f'  not running again after {RESTART_WAIT} s; starting them with compose start (the containers and their install flag are kept)')
                r.compose('start', *names)
                row['restart'] = 'compose start'
            r.wait('the killed containers are running', running, 120)
            row['restart_counts'] = {'before': before_restarts, 'after': restart_counts(r, names)}

            def converged():
                receipt = r.ureth(i, 'eth_getTransactionReceipt', [tx])
                mine = head(r, i, transport)
                best = max((head(r, j, transport) or (0, 0))[1] for j in survivors)
                return (receipt is not None and receipt['blockHash'] in blocks and mine is not None and mine[0] == epoch and mine[1] + LAG >= best)

            def try_converge(label, seconds):
                try:
                    r.wait(f'entity {i} converges ({label})', converged, seconds)
                    return True
                except Exception:
                    return False

            row['converged_after_restart'] = try_converge('after the restart', CONVERGE_WAIT)
            row['ureth_block'] = block_number(r, i)
            row['survivor_block'] = block_number(r, survivors[0])
            if not row['converged_after_restart']:
                r.say(f'  entity {i} did not converge (ureth block {row["ureth_block"]}, survivor {row["survivor_block"]}); trying a graceful restart of ureth{i}')
                r.compose('restart', f'ureth{i}')
                row['converged_after_ureth_restart'] = try_converge('after a graceful restart of ureth', CONVERGE_WAIT)
                if not row['converged_after_ureth_restart']:
                    r.say(f'  still not; graceful stop and start of {" ".join(everything)}')
                    r.compose('stop', *everything)
                    r.compose('start', *everything)
                    row['converged_after_full_graceful_restart'] = try_converge('after a graceful stop/start of all three', CONVERGE_WAIT)
                    row['ureth_block_final'] = block_number(r, i)
        finally:
            for service in everything:
                log = r.compose('logs', '--no-color', '--since', since, service, check=False)
                (r.evidence / f'pos-crash-{tag}-{service}.log').write_text(log)
                panics, warnings = scan_log(log)
                row.setdefault('logs', {})[service] = {'lines': len(log.splitlines()), 'error_warn': warnings, 'panics': panics}
            (r.evidence / f'pos-crash-{tag}.json').write_text(json.dumps(rows, indent=1) + '\n')
            r.say(f'  record: {json.dumps(row)[:900]}')
        r.expect(row['converged_after_restart'], f'entity {i} converges after SIGKILL of {" ".join(names)} and a restart (bft-core #843: fails today whenever ureth is killed)', json.dumps(row)[:600])
        r.expect(all(v['panics'] == 0 for v in row['logs'].values()), f'no panic in the logs of entity {i} after the crash', json.dumps(row['logs']))

        def applied():
            count = r.view(r.REGISTRY, 'recordCount()(uint64)')[0]
            return count if count == r.view(deployment['custody'], 'recordCursor()(uint64)')[0] else None

        r.expect(r.wait('the custody has applied every root record', lambda: applied() is not None, 300), 'recordCursor equals recordCount after the crash', str(applied()))
        r.wait('the public gateway is healthy again', lambda: r.http(sys.modules[type(r).__module__].PUBLIC_RPC, 'GET', '/healthz')[0] == 200, 180)
        gateway = json.loads(r.send_via_gateway(r.gen / 'faucet-secrets', '0x' + '66' * 20))
        r.expect(gateway['status'] == '0x1', f'a transaction through the public gateway succeeds after entity {i} was crashed', gateway['transactionHash'])
        for j in range(1, r.n + 1):
            got = r.wait(f'validator {j} has it', lambda j=j: r.ureth(j, 'eth_getTransactionReceipt', [gateway['transactionHash']]), 120)
            r.expect(got['blockHash'] == gateway['blockHash'], f'validator {j} has it in the same block')


# the opt-in stages: (rehearsal stage name, method name, what is killed, root epoch)
SCENARIOS = (('pos-crash', 'pos_crash', ('ureth', 'root', 'shard'), 3),
             ('pos-crash-ureth', 'pos_crash_ureth', ('ureth',), 3),
             ('pos-crash-shard', 'pos_crash_shard', ('shard',), 3),
             ('pos-crash-root', 'pos_crash_root', ('root',), 3),
             ('pos-crash-ureth-shard', 'pos_crash_ureth_shard', ('ureth', 'shard'), 3),
             ('pos-crash-e1', 'pos_crash_e1', ('ureth', 'root', 'shard'), 1),
             ('pos-crash-e2', 'pos_crash_e2', ('ureth', 'root', 'shard'), 2))
STAGES = tuple((name, method) for name, method, _, _ in SCENARIOS)


def _stage(name, parts, epoch):
    def stage(r):
        scenario(r, name, parts, epoch)
    stage.__doc__ = f'{name}: SIGKILL of {" + ".join(parts)} of one entity at root epoch {epoch} (see the module docstring; opt-in, bft-core #843).'
    return stage


METHODS = {method: _stage(name, parts, epoch) for name, method, parts, epoch in SCENARIOS}
