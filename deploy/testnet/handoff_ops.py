#!/usr/bin/env python3
"""The host wrapper of the packaged handoff (#437 item 1; arch ruling briefs/package-operator-rpc-ruling.md).

`ubft root handoff propose` runs the plan, intent and endorse phases of ONE attempt in one process against every old root's loopback-only operator endpoint.
In the package each validator entity's root and shard share a private network namespace and the operator listeners bind to 127.0.0.1, so no process outside an
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
    handoff_ops.py abort   <generation> -- <the `ubft root handoff abort` flags except --root-rpc>
"""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT_RPC = 'http://127.0.0.1:8002'
NOT_PREPARED = 'before the handoff is prepared'
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


class DockerTransport:
    """HTTP POSTs to an entity's root operator endpoint from inside that entity's network namespace."""

    def __init__(self, generation, project=None):
        self.generation = Path(generation)
        compose = json.loads((self.generation / 'compose.yaml').read_text())
        self.project = project or compose['name']
        self.image = compose['services']['rpc']['image']
        self.entities = sorted(int(n[3:]) for n in compose['services'] if n.startswith('pod') and n[3:].isdigit())

    def holder(self, i):
        done = subprocess.run(['docker', 'compose', '-f', str(self.generation / 'compose.yaml'), 'ps', '-q', f'pod{i}'], text=True, capture_output=True)
        cid = done.stdout.strip()
        if done.returncode != 0 or not cid:
            raise HandoffError(f'pod{i} is not running: {done.stderr.strip()}')
        return cid

    def command(self, i, path, timeout):
        # a one-node sidecar of that entity's namespace: read-only, no capabilities, no mounts, the helper script on stdin of python -c
        return ['docker', 'run', '--rm', '-i', '--network', f'container:{self.holder(i)}', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--user', '10001:10001', '--entrypoint', 'python3', self.image, '-c', HELPER, ROOT_RPC + path, str(timeout)]

    def post(self, i, path, body, timeout=10):
        done = subprocess.run(self.command(i, path, timeout), input=body, capture_output=True, timeout=timeout + 30)
        if done.returncode != 0:
            raise HandoffError(f'entity {i}: the helper failed: {done.stderr.decode(errors="replace")[:500]}')
        status, _, payload = done.stdout.partition(b'\n')
        return int(status), payload


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Wrapper:
    def __init__(self, transport, entities, log, prepare_timeout=60.0, max_attempts=3, sleep=time.sleep, now=time.monotonic):
        self.transport, self.entities, self.log = transport, list(entities), log
        self.prepare_timeout, self.max_attempts, self.sleep, self.now = prepare_timeout, max_attempts, sleep, now

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

    def attempt(self, request, number):
        plan = self.plan(request, number)
        self.record(event='plan', attempt=number, request_sha256=sha(request), plan_sha256=sha(plan), entity=self.entities[0])
        for entity in self.entities[1:]:
            status, body = self.transport.post(entity, '/api/v1/handoff/intent', plan)
            if not 200 <= status < 300:
                raise HandoffError(f'validator {entity} refused the plan: {status} {body.decode(errors="replace")}')
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
    compose = ['docker', 'compose', '-f', str(Path(generation) / 'compose.yaml')]
    return {i: compose + ['exec', '-T', f'root{i}', 'ubft', 'root', 'handoff', 'abort', *flags, '--root-rpc', ROOT_RPC] for i in entities}


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
    r = sub.add_parser('abort')
    r.add_argument('generation', type=Path)
    r.add_argument('flags', nargs=argparse.REMAINDER)
    a = p.parse_args()
    transport = DockerTransport(a.generation)
    if a.action == 'abort':
        failed = False
        for i, command in abort_commands(a.generation, transport.entities, [f for f in a.flags if f != '--']).items():
            done = subprocess.run(command, text=True, capture_output=True)
            print(f'entity {i}: exit {done.returncode}\n{done.stdout}{done.stderr}')
            failed = failed or done.returncode != 0
        raise SystemExit(1 if failed else 0)
    work = a.generation / 'handoff'
    work.mkdir(mode=0o700, exist_ok=True)
    request = build_request(a.ubft, work / f'plan-request-{int(time.time())}.json', a.next_trust_base, a.next_evm_assignment, a.readiness_receipts, a.q3)
    with (work / 'log.jsonl').open('a') as log:
        wrapper = Wrapper(transport, transport.entities, lambda row: (log.write(json.dumps(row, sort_keys=True) + '\n'), log.flush(), print(json.dumps(row, sort_keys=True))),
                          a.prepare_timeout, a.max_attempts)
        accepted = wrapper.propose(request)
    print(f'submitted {accepted} root endorsements')


if __name__ == '__main__':
    main()
