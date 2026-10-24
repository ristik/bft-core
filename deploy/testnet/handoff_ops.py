#!/usr/bin/env python3
"""The host wrapper of the packaged handoff (#437 item 1; arch ruling briefs/package-operator-rpc-ruling.md).

`ubft root handoff propose` runs the plan, intent and endorse phases of ONE attempt in one process against every old root's loopback-only operator endpoint.
In the package each validator entity's root and shard share a private network namespace and the operator listeners bind to the generation's loopback address
(`generate.py --rpc-bind`, 127.0.0.1 by default; read from the generated compose.yaml, which must carry the same address on every root), so no process outside an
entity's namespace may call them (and no forwarder exists). This wrapper therefore performs the same phases from the host, each HTTP call made INSIDE the
target entity's namespace by a one-shot helper container (`docker run --network container:<pod>`), and it keeps what `propose` guarantees:

  * ONE plan: the request is built once by the pinned `ubft root handoff plan-request` (the code `propose` uses), posted to the first entity's root only, and
    the plan it returns is distributed byte for byte as every other root's intent; the endorsements of an attempt are requests for that plan only. Independent
    `propose` commands would each build their own attempt and are never run.
  * Prepare-bound endorsements: every root is asked to endorse in parallel; a refusal "before the handoff is prepared" is retried until --prepare-timeout; a
    lapsed Prepare ("the Prepare's freeze has lapsed") ends the attempt and re-plans, at most --max-attempts times (the typed outcome is `HandoffLapsed`).
  * A quorum of endorsements is len(roots) * 2 // 3 + 1, as in propose.

Inputs (trust base, candidate, receipts, assignment) are files written by the host; outputs go to the generation directory's `handoff/` with a record of the
SHA-256 of the request and of the plan and of every attempt (`handoff/log.jsonl`). No key and no authority credential passes through these files.

    handoff_ops.py propose <generation> --ubft UBFT --next-trust-base F [--next-evm-assignment F] [--readiness-receipts F,F] [--q3]
    handoff_ops.py hold    <generation> --ubft UBFT --next-trust-base F [--old-trust-base F] [...the propose options]   (rehearsal: plan, intents, ONE endorsement; prints the abort target)
    handoff_ops.py abort   <generation> -- <the `ubft root handoff abort` flags except --root-rpc>
"""
import argparse
import base64
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess
import time

import operator_rpc

NOT_PREPARED = 'before the handoff is prepared'
LATER_ATTEMPT = 'committed state plans attempt'   # the root's refusal of an intent whose attempt's Prepare has lapsed (its text names the attempt it plans now)
LAPSED = "the Prepare's freeze has lapsed"

# stdlib only: runs in the rpc image, inside one entity's namespace. Prints the status on the first line and the body after it.
HELPER = r'''
import sys, urllib.request, urllib.error
request = urllib.request.Request(sys.argv[1], sys.stdin.buffer.read(), {'Content-Type': 'application/json'}, method='POST')
try:
    with urllib.request.urlopen(request, timeout=int(sys.argv[2])) as response:
        status, body = response.status, response.read(1 << 20)
except urllib.error.HTTPError as error:
    status, body = error.code, error.read(1024)
sys.stdout.buffer.write(str(status).encode() + b'\n' + body)
'''


class HandoffError(RuntimeError):
    pass


class HandoffLapsed(HandoffError):
    """No Freeze followed the Prepare in time: the attempt is dead and the bounded re-plans are used up."""


JOINER_OVERRIDE = 'compose.joiner.json'
RESTORE_OVERRIDE = 'compose.joiner-restore.json'   # exists only while the joiner's shard node is being restored


def compose_files(generation):
    """The `-f` arguments of the generation's Compose files: compose.yaml and, once joiner.py prepared an entity, its override (the joiner's pod, root, shard node,
    authority and execution client are then entities of every operation like the genesis ones)."""
    generation = Path(generation)
    files = ['-f', str(generation / 'compose.yaml')]
    for name in (JOINER_OVERRIDE, RESTORE_OVERRIDE):
        if (generation / name).is_file():
            files += ['-f', str(generation / name)]
    return files


def load_compose(generation):
    """compose.yaml with the joiner override's services added (see compose_files)."""
    generation = Path(generation)
    compose = json.loads((generation / 'compose.yaml').read_text())
    if (generation / JOINER_OVERRIDE).is_file():
        compose['services'] = {**compose['services'], **json.loads((generation / JOINER_OVERRIDE).read_text())['services']}
    if (generation / RESTORE_OVERRIDE).is_file():
        for name, change in json.loads((generation / RESTORE_OVERRIDE).read_text())['services'].items():
            compose['services'][name] = {**compose['services'][name], **change}
    return compose


class DockerTransport:
    """HTTP POSTs to an entity's root operator endpoint from inside that entity's network namespace."""

    def __init__(self, generation, project=None):
        self.generation = Path(generation)
        self.files = compose_files(self.generation)
        compose = load_compose(self.generation)
        self.project = project or compose['name']
        self.image = compose['services']['rpc']['image']
        self.root_rpc = operator_rpc.common_urls(compose)[0]   # the listener the generated Compose file configured, the same on every root
        self.entities = sorted(int(n[3:]) for n in compose['services'] if n.startswith('pod') and n[3:].isdigit())

    def holder(self, i):
        done = subprocess.run(['docker', 'compose', *self.files, 'ps', '-q', f'pod{i}'], text=True, capture_output=True)
        cid = done.stdout.strip()
        if done.returncode != 0 or not cid:
            raise HandoffError(f'pod{i} is not running: {done.stderr.strip()}')
        return cid

    def command(self, i, path, timeout):
        # a one-node sidecar of that entity's namespace: read-only, no capabilities, no mounts, the helper script on stdin of python -c
        return ['docker', 'run', '--rm', '-i', '--network', f'container:{self.holder(i)}', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--user', '10001:10001', '--entrypoint', 'python3', self.image, '-c', HELPER, self.root_rpc + path, str(timeout)]

    def post(self, i, path, body, timeout=10):
        done = subprocess.run(self.command(i, path, timeout), input=body, capture_output=True, timeout=timeout + 30)
        if done.returncode != 0:
            raise HandoffError(f'entity {i}: the helper failed: {done.stderr.decode(errors="replace")[:500]}')
        status, _, payload = done.stdout.partition(b'\n')
        return int(status), payload


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Wrapper:
    def __init__(self, transport, entities, log, prepare_timeout=60.0, max_attempts=3, sleep=time.sleep, now=time.monotonic, intent_delay=0.0):
        self.transport, self.entities, self.log = transport, list(entities), log
        self.prepare_timeout, self.max_attempts, self.sleep, self.now = prepare_timeout, max_attempts, sleep, now
        self.intent_delay = intent_delay   # a pause before each intent: slow delivery on purpose (the rehearsal reproduces #795 with it)

    def record(self, **row):
        self.log(dict(row, time=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())))

    def plan(self, request, attempt):
        """ONE plan, from the first entity's root. A re-plan right after a lapse may find a root that has not committed far enough to see the lapse: retried for 30 s."""
        first = self.entities[0]
        deadline = self.now() + (30 if attempt > 1 else 0)
        while True:
            status, body = self.transport.post(first, '/api/v1/handoff/plan', request)
            if 200 <= status < 300:
                return body
            if self.now() >= deadline:
                raise HandoffError(f'entity {first} refused the plan: {status} {body.decode(errors="replace")}')
            self.sleep(1)

    def endorse(self, entity, plan, deadline):
        while True:
            status, body = self.transport.post(entity, '/api/v1/handoff/endorse', plan)
            text = body.decode(errors='replace')
            if 200 <= status < 300:
                return None
            if NOT_PREPARED not in text or self.now() > deadline:
                return f'entity {entity}: {status} {text}'
            self.sleep(1)

    def intent(self, entity, plan, number):
        """The plan as this root's intent. A refusal that says this validator's committed state already plans a LATER attempt is a lapse: the plan's Prepare was
        ordered and ran out its freeze window before the intent arrived, so the attempt is dead and propose re-plans (the root accepts a late intent for a Prepare
        that is still open, #795). Any other refusal is final and recorded."""
        if self.intent_delay:
            self.sleep(self.intent_delay)
        status, body = self.transport.post(entity, '/api/v1/handoff/intent', plan)
        if 200 <= status < 300:
            return
        text = body.decode(errors='replace')
        self.record(event='intent-refused', attempt=number, entity=entity, status=status, body=text)
        if LATER_ATTEMPT in text:
            raise HandoffLapsed(f'validator {entity}: {text.strip()}')
        raise HandoffError(f'validator {entity} refused the plan: {status} {text}')

    def attempt(self, request, number):
        plan = self.plan(request, number)
        try:
            planned, next_body_id = plan_identity(plan)
        except (ValueError, KeyError, TypeError):   # an opaque plan (a fake transport's): the rows say nothing about its identity, and pos-too-late then refuses to run
            planned = next_body_id = None
        self.record(event='plan', attempt=number, request_sha256=sha(request), plan_sha256=sha(plan), entity=self.entities[0], plan_attempt=planned, next_body_id=next_body_id)
        for entity in self.entities[1:]:
            self.intent(entity, plan, number)
        self.record(event='intent', attempt=number, plan_sha256=sha(plan), entities=self.entities[1:])
        deadline = self.now() + self.prepare_timeout
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.entities)) as pool:
            results = list(pool.map(lambda e: self.endorse(e, plan, deadline), self.entities))
        refusals = [r for r in results if r]
        accepted = len(results) - len(refusals)
        self.record(event='endorse', attempt=number, plan_sha256=sha(plan), accepted=accepted, of=len(results), refusals=refusals)
        if accepted < len(results) * 2 // 3 + 1:
            if any(LAPSED in r for r in refusals):
                raise HandoffLapsed('; '.join(refusals))
            raise HandoffError(f'only {accepted}/{len(results)} validators endorsed: ' + '; '.join(refusals))
        return accepted

    def hold(self, request):
        """A rehearsal of Abort: the plan and every intent as `attempt` does, then the endorsement of the FIRST entity only (its weight is below the quorum, so no Freeze
        follows). Returns the plan; the Prepare has been ordered when this returns, and lapses by itself after PrepareFreezeLapseRounds."""
        plan = self.plan(request, 1)
        self.record(event='plan', attempt=1, request_sha256=sha(request), plan_sha256=sha(plan), entity=self.entities[0])
        for entity in self.entities[1:]:
            self.intent(entity, plan, 1)
        refusal = self.endorse(self.entities[0], plan, self.now() + self.prepare_timeout)
        self.record(event='hold', plan_sha256=sha(plan), endorsed=[self.entities[0]] if not refusal else [], refusal=refusal)
        if refusal:
            raise HandoffError(refusal)
        return plan

    def propose(self, request):
        for number in range(1, self.max_attempts + 1):
            try:
                return self.attempt(request, number)
            except HandoffLapsed as lapse:
                self.record(event='lapsed', attempt=number)
                if number >= self.max_attempts:
                    raise HandoffLapsed(f'gave up after {number} attempts: {lapse}') from None
        raise AssertionError('unreachable')


def abort_commands(generation, entities, flags):
    """Manual Abort: the same target is dispatched locally to every old root (exec in that entity, one --root-rpc), each result collected by the caller."""
    compose = ['docker', 'compose', *compose_files(generation)]
    root_rpc = operator_rpc.common_urls(load_compose(generation))[0]
    return {i: compose + ['exec', '-T', f'root{i}', 'ubft', 'root', 'handoff', 'abort', *flags, '--root-rpc', root_rpc] for i in entities}


def abort_context(transport, entity):
    """The root's context (network, predecessor, the attempt it plans). Read BEFORE the plan: the root answers only while idle, a committed Prepare makes it refuse."""
    status, body = transport.post(entity, '/api/v1/handoff/evm-assignment/context', b'{}')
    if status != 200:
        raise HandoffError(f'entity {entity} refused the context: {status} {body.decode(errors="replace")}')
    return json.loads(body)


def plan_identity(plan):
    """(attempt, successor body identity) of a plan: the SHA-256 of its canonical body is what Abort names as the next body."""
    held = json.loads(plan)
    return held['Attempt'], '0x' + sha(base64.b64decode(held['Body'], validate=True))


def abort_target(context, plan, old_epoch):
    """The exact target of Abort for the plan held (the fields scripts/h6/prepare-handoff.py derives): network, predecessor and attempt from the context read before
    the plan, the successor body identity as the SHA-256 of the plan's canonical body."""
    attempt, next_body_id = plan_identity(plan)
    if attempt != context['attempt']:
        raise HandoffError(f'the context planned attempt {context["attempt"]}, the plan is attempt {attempt}')
    return {'network': context['network'], 'oldEpoch': old_epoch, 'predecessorBodyId': '0x' + context['predecessor'].removeprefix('0x'),
            'attempt': attempt, 'nextBodyId': next_body_id}


def build_request(ubft, out, next_trust_base, assignment=None, receipts=None, q3=False):
    args = [str(ubft), 'root', 'handoff', 'plan-request', '--next-trust-base', str(next_trust_base), '--out', str(out)]
    if assignment: args += ['--next-evm-assignment', str(assignment)]
    if receipts: args += ['--readiness-receipts', str(receipts)]
    if q3: args.append('--q3')
    done = subprocess.run(args, text=True, capture_output=True)
    if done.returncode != 0:
        raise HandoffError('plan-request failed: ' + done.stdout + done.stderr)
    return Path(out).read_bytes().rstrip(b'\n')


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='action', required=True)
    q = sub.add_parser('propose')
    q.add_argument('generation', type=Path)
    q.add_argument('--ubft', type=Path, required=True)
    q.add_argument('--next-trust-base', type=Path, required=True)
    q.add_argument('--next-evm-assignment', type=Path)
    q.add_argument('--readiness-receipts')
    q.add_argument('--q3', action='store_true')
    q.add_argument('--prepare-timeout', type=float, default=60)
    q.add_argument('--max-attempts', type=int, default=3)
    q.add_argument('--intent-delay', type=float, default=0.0, help='seconds to wait before handing each validator the intent (testing slow delivery)')
    q.add_argument('--committee', help='comma separated entities of the committee being LEFT (default: every entity of the generation); a joiner is not one of them: it gets no intent and endorses nothing')
    h = sub.add_parser('hold')
    h.add_argument('generation', type=Path)
    h.add_argument('--ubft', type=Path, required=True)
    h.add_argument('--old-trust-base', type=Path, help='the trust base of the epoch being left (default: the generation\'s network/trust-base.json, the first handoff\'s)')
    h.add_argument('--next-trust-base', type=Path, required=True)
    h.add_argument('--next-evm-assignment', type=Path)
    h.add_argument('--readiness-receipts')
    h.add_argument('--q3', action='store_true')
    h.add_argument('--prepare-timeout', type=float, default=60)
    r = sub.add_parser('abort')
    r.add_argument('generation', type=Path)
    r.add_argument('flags', nargs=argparse.REMAINDER)
    a = p.parse_args()
    transport = DockerTransport(a.generation)
    if getattr(a, 'committee', None):
        transport.entities = sorted(int(x) for x in a.committee.split(','))
    if a.action == 'abort':
        # all at once: each command waits for the COMMITTED Abort, which needs the approvals of a quorum, so one after another the first would wait out its timeout
        commands = abort_commands(a.generation, transport.entities, [f for f in a.flags if f != '--'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(commands)) as pool:
            done = dict(zip(commands, pool.map(lambda c: subprocess.run(c, text=True, capture_output=True), commands.values())))
        for i, result in done.items():
            print(f'entity {i}: exit {result.returncode}\n{result.stdout}{result.stderr}')
        raise SystemExit(1 if any(result.returncode for result in done.values()) else 0)
    work = a.generation / 'handoff'
    work.mkdir(mode=0o700, exist_ok=True)
    request = build_request(a.ubft, work / f'plan-request-{int(time.time())}.json', a.next_trust_base, a.next_evm_assignment, a.readiness_receipts, a.q3)
    if a.action == 'hold':
        old_epoch = json.loads((a.old_trust_base or Path(a.generation, 'network', 'trust-base.json')).read_text())['epoch']
        with (work / 'log.jsonl').open('a') as log:
            wrapper = Wrapper(transport, transport.entities, lambda row: (log.write(json.dumps(row, sort_keys=True) + '\n'), log.flush()), a.prepare_timeout)
            context = abort_context(transport, transport.entities[0])
            plan = wrapper.hold(request)
        print(json.dumps(abort_target(context, plan, old_epoch), sort_keys=True))
        return
    with (work / 'log.jsonl').open('a') as log:
        wrapper = Wrapper(transport, transport.entities, lambda row: (log.write(json.dumps(row, sort_keys=True) + '\n'), log.flush(), print(json.dumps(row, sort_keys=True))),
                          a.prepare_timeout, a.max_attempts, intent_delay=a.intent_delay)
        accepted = wrapper.propose(request)
    print(f'submitted {accepted} root endorsements')


if __name__ == '__main__':
    main()
