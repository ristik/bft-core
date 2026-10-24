"""Crash recovery of a validator entity on the switched PoS network (TN-S #430, P8-TEST #437): the unclean counterpart of pos-restart.

Stage `pos-crash`, registered before `pos-owner` (which declares an identity's retirement and so must stay last; this stage changes nothing in the contracts). Precondition:
the epoch-3 network that pos-handoff-2 and pos-recreate leave. Per entity in --pods (one at a time): its execution client, root and shard node are SIGKILLed together
(`docker compose kill -s KILL`: no shutdown hook, no flush). Never the pod<i> namespace holder (its loss strands root and shard, OPERATOR lifecycle note) and never authority<i>
(a restarted authority has a new key, README). The containers carry `restart: unless-stopped`, which Docker applies to a killed container, so the stage first LETS the policy bring
them back and records that it did; only if they are not running again within RESTART_WAIT seconds does it `compose start` them (as pos-restart does: the container, install flag
included, is kept) and says so.

Asserted, each entity: the three survivors (threshold 3 of 4) keep certifying (their root rounds advance) and mine a transaction while the entity is down or restarting; the entity's
three containers run again; its execution client has the transaction mined without it, in the same block; its root's certified head is back at epoch 3 and within a few rounds of
the survivors'; the custody has applied every root record; a transaction through the public gateway succeeds and every validator has it in the same block. Recorded, not
asserted: what the entity's root, shard and execution client logged on the unclean start (evidence/pos-crash-<i>.log, counts in the output). A line `panic:`/`panicked at` in
those logs is a failure.

NOT shown: that the restarted root VOTES (a head that advances shows it follows and persists the chain; 3 of 4 certify without it, the pos-recreate lesson). That needs a second
fault with a different root down, a later stage.
"""
import json
import re
import subprocess
import sys
import time

import handoff_ops

RESTART_WAIT = 90
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


def pos_crash(r):
    transport = handoff_ops.DockerTransport(r.gen)
    deployment = json.loads((r.gen / 'network' / 'pos-deployment.json').read_text())
    sender, to = r.manifest['faucet_address'], '0x' + '55' * 20
    r.expect(all((head(r, j, transport) or (None,))[0] == 3 for j in range(1, r.n + 1)), 'precondition: every root certifies at epoch 3 (run the handoffs first)')
    for i in r.pods:
        names = [f'ureth{i}', f'root{i}', f'shard{i}']
        survivors = [j for j in range(1, r.n + 1) if j != i]
        before_rounds = {j: head(r, j, transport)[1] for j in survivors}
        before_restarts = restart_counts(r, names)
        since = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        r.say(f'  SIGKILL of validator {i}: {" ".join(names)} (restart counts {before_restarts})')
        r.compose('kill', '-s', 'KILL', *names)
        # the survivors keep certifying
        for j in survivors:
            r.wait(f'survivor root {j} certifies past round {before_rounds[j]} with validator {i} killed',
                   lambda j=j: (head(r, j, transport) or (0, 0))[1] > before_rounds[j] + 2, 180)
        r.expect(True, f'the {len(survivors)} surviving roots keep certifying while validator {i} is killed')
        # a transaction the survivors mine (driven directly: the gateway fails closed while a validator is down)
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
            receipt = r.wait(f'survivor {j} mines it with validator {i} killed', lambda j=j: r.ureth(j, 'eth_getTransactionReceipt', [tx]), 240)
            r.expect(receipt['status'] == '0x1', f'survivor {j} has a successful receipt', receipt['blockHash'])
            blocks.add(receipt['blockHash'])
        r.expect(len(blocks) == 1, 'the survivors agree on the including block')
        # did the restart policy bring the entity back? otherwise start it, and say which
        def running():
            return set(names) <= set(r.compose('ps', '--services', '--status', 'running').split())
        try:
            r.wait(f'the restart policy brings validator {i} back', running, RESTART_WAIT)
            r.say(f'  validator {i}: Docker restarted the killed containers by its own policy (restart counts {restart_counts(r, names)})')
            by = 'the restart policy'
        except Exception:
            r.say(f'  validator {i}: not running again after {RESTART_WAIT} s; starting it with compose start (the container and its install flag are kept)')
            r.compose('start', *names)
            by = 'compose start'
        r.wait(f'validator {i} is running', running, 120)
        after = restart_counts(r, names)
        if by == 'the restart policy':
            r.expect(all((after[n] or 0) > (before_restarts[n] or 0) for n in names), f'validator {i}: every killed container shows a restart (policy)', f'{before_restarts} -> {after}')
        # convergence
        receipt = r.wait(f'validator {i} catches up to the transaction mined without it', lambda: r.ureth(i, 'eth_getTransactionReceipt', [tx]), 300)
        r.expect(receipt['blockHash'] in blocks, f'validator {i} has the same block after the crash', receipt['blockHash'])
        def converged():
            mine = head(r, i, transport)
            best = max((head(r, j, transport) or (0, 0))[1] for j in survivors)
            return mine is not None and mine[0] == 3 and mine[1] + LAG >= best
        r.wait(f'root {i} is back at epoch 3 within {LAG} rounds of the survivors', converged, 300)
        r.expect(True, f'root {i} certifies at epoch 3 again, close to the survivors (it follows the chain; that it votes is not shown)')
        # what the unclean start logged
        log = r.compose('logs', '--no-color', '--since', since, *names, check=False)
        (r.evidence / f'pos-crash-{i}.log').write_text(log)
        panics, warnings = scan_log(log)
        r.say(f'  validator {i} unclean start: {len(log.splitlines())} log lines, {warnings} error/warn lines, {panics} panics (evidence/pos-crash-{i}.log)')
        r.expect(panics == 0, f'no panic in the logs of validator {i} after the crash', f'{panics} lines')
        def applied():
            count = r.view(r.REGISTRY, 'recordCount()(uint64)')[0]
            return count if count == r.view(deployment['custody'], 'recordCursor()(uint64)')[0] else None
        r.expect(r.wait('the custody has applied every root record', lambda: applied() is not None, 300), 'recordCursor equals recordCount after the crash', str(applied()))
        r.wait('the public gateway is healthy again', lambda: r.http(sys.modules[type(r).__module__].PUBLIC_RPC, 'GET', '/healthz')[0] == 200, 180)
        gateway = json.loads(r.send_via_gateway(r.gen / 'faucet-secrets', '0x' + '66' * 20))
        r.expect(gateway['status'] == '0x1', f'a transaction through the public gateway succeeds after validator {i} was crashed', gateway['transactionHash'])
        for j in range(1, r.n + 1):
            got = r.wait(f'validator {j} has it', lambda j=j: r.ureth(j, 'eth_getTransactionReceipt', [gateway['transactionHash']]), 120)
            r.expect(got['blockHash'] == gateway['blockHash'], f'validator {j} has it in the same block')
