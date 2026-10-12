#!/usr/bin/env python3
"""CI dry form of the packaged handoff (#437 item 1): no container, no devnet. It proves what a file can.

  * every `ubft` command and flag the operator runbook (OPERATOR.md 5b) and the host wrapper use exists in the PINNED binary (a flag the pin does not know is a
    runbook that cannot run);
  * the compose file renders (`docker compose config`) with and without the install override of an epoch, the override changes only the roots' entrypoints
    (the install flag appended) and every root keeps its entity's namespace;
  * the host wrapper, on this generation's entities, builds ONE plan request with the pinned `plan-request`, posts it to the first entity only, distributes the
    returned plan byte for byte as the others' intent, and asks every root to endorse that plan (a fake transport: nothing listens); its helper commands join the
    entity's namespace and mount nothing; the abort is dispatched to every root with a single local endpoint each.
NOT covered: any live behaviour (that is the rehearsal host's job).
"""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import handoff
import handoff_ops

# command -> the flags the runbook (docs/operations/testnet/OPERATOR.md 5b) / wrapper pass (transcribed from scripts/p85-recovery-steps.sh and the q3/h3/m2 libraries).
# A second copy of the runbook's commands: a flag added to 5b must be added here (nothing ties the two).
CLI = {
    'root handoff plan-request': ['next-trust-base', 'next-evm-assignment', 'readiness-receipts', 'q3', 'out'],
    'root handoff q3-readiness': ['candidate', 'key-conf', 'root-rpc', 'shard-rpc', 'eth-url', 'engine-url', 'jwt-secret', 'execution-genesis-hash', 'execution-code-hash', 'out'],
    'root handoff q3-candidate': ['next-trust-base', 'next-evm-assignment', 'root-rpc', 'out-dir'],
    'root handoff q3-activation': ['root-rpc', 'epoch', 'out'],
    'root handoff abort': ['network', 'old-epoch', 'predecessor-body-id', 'attempt', 'next-body-id', 'root-rpc', 'timeout'],
    'root handoff propose': ['next-trust-base', 'next-evm-assignment', 'root-rpc', 'readiness-receipts', 'q3', 'max-attempts', 'prepare-timeout'],
    'root handoff evm-context': ['root-rpc', 'out'],
    'root handoff evm-pop': ['context', 'validators', 'identities', 'node-id', 'authority-socket', 'authority-credential'],
    'root handoff evm-assemble': ['context', 'validators', 'identities', 'authorization', 'pops', 'bindings', 'out', 'recovery', 'supersede'],
    'q3 signers': ['root-rpc'],
    'q3 history': ['root-rpc', 'out'],
    'q3 shard-conf': ['root-rpc', 'epoch', 'partition', 'out'],
    'pos-relayer proposal': ['eth-rpc', 'pos-deployment', 'context', 'result-id', 'node-ids', 'trust-base', 'out-dir', 'reserved', 'evm-pops'],
    'pos-relayer candidate': ['context', 'assignment', 'next-trust-base', 'out'],
    'pos-relayer sign-pop': ['candidate', 'pos-deployment', 'attempt', 'authority-socket', 'authority-credential', 'out'],
    'pos-relayer assemble': ['candidate', 'pos-deployment', 'attempt', 'pop', 'out'],
    'pos-relayer tx submit-pops': ['eth-rpc', 'pos-deployment', 'sender-key', 'result-id', 'evm-pops'],
    'pos-relayer tx finalize': ['eth-rpc', 'pos-deployment', 'sender-key', 'result-id'],
    'signing-authority advance-epoch': ['operator-socket', 'operator-credential', 'trust-base', 'shard-conf'],
    'signing-authority replace-session': ['operator-socket', 'operator-credential', 'out'],
    'trust-base generate': ['network-id', 'epoch', 'epoch-start', 'previous-trust-base', 'root-weights', 'output-file-name', 'node-info'],
    'trust-base sign': ['trust-base'],
}
FLAG = re.compile(r'(?m)^\s+(?:-\w, )?--([a-z0-9-]+)')


def flags_of(help_text):
    return set(FLAG.findall(help_text))


def check_cli(ubft, table=CLI):
    problems = []
    for command, wanted in table.items():
        done = subprocess.run([str(ubft), *command.split(), '--help'], text=True, capture_output=True)
        if done.returncode != 0:
            problems.append(f'`ubft {command}` does not exist in the pinned binary')
            continue
        missing = sorted(set(wanted) - flags_of(done.stdout))
        if missing:
            problems.append(f'`ubft {command}` lacks --' + ', --'.join(missing))
    if problems:
        raise AssertionError('the pinned ubft cannot run the handoff runbook:\n  ' + '\n  '.join(problems))
    return len(table)


class Fake:
    def __init__(self):
        self.calls = []

    def post(self, entity, path, body, timeout=10):
        self.calls.append((entity, path, body))
        if path.endswith('/plan'):
            return 200, b'{"plan":"synthetic"}'
        return 204, b''


def compose_config(compose_files):
    args = ['docker', 'compose']
    for f in compose_files:
        args += ['-f', str(f)]
    done = subprocess.run(args + ['--profile', 'OFFLINE-VALIDATION-DO-NOT-START', 'config', '--format', 'json'], text=True, capture_output=True)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)['services']


def validate(generation, ubft):
    generation = Path(generation)
    compose = json.loads((generation / 'compose.yaml').read_text())
    n = len([s for s in compose['services'] if s.startswith('pod') and s[3:].isdigit()])
    assert n >= 3, 'no pod holders in the generated compose file'
    commands = check_cli(ubft)
    base = compose_config([generation / 'compose.yaml'])
    with tempfile.TemporaryDirectory(prefix='tnops-handoff-') as tmp:
        tmp = Path(tmp)
        override = tmp / 'compose.install-epoch-2.json'
        override.write_text(json.dumps(handoff.install_override(compose, 2)))
        installed = compose_config([generation / 'compose.yaml', override])
        for i in range(1, n + 1):
            before, after = base[f'root{i}'], installed[f'root{i}']
            assert after['entrypoint'] == before['entrypoint'] + ['--install-handoff-epoch', '2'], f'root{i}: the override changed more than the install flag'
            assert after['network_mode'] == before['network_mode'] == f'service:pod{i}', f'root{i} left its entity namespace'
            assert after['volumes'] == before['volumes']
            for other in (f'shard{i}', f'pod{i}', f'authority{i}', f'ureth{i}'):
                assert installed[other] == base[other], f'{other} changed with the install override'
        # the wrapper on this generation: a real plan request from the pinned binary, a fake transport
        trust = json.loads((generation / 'network/trust-base.json').read_text())
        trust['epoch'] = 2
        (tmp / 'next-trust-base.json').write_text(json.dumps(trust))
        request = handoff_ops.build_request(ubft, tmp / 'request.json', tmp / 'next-trust-base.json')
        assert json.loads(request)['nextTrustBase']['epoch'] == 2
        fake, rows = Fake(), []
        entities = handoff_ops.DockerTransport.__new__(handoff_ops.DockerTransport)
        entities.generation, entities.project = generation, compose['name']
        entities.image = compose['services']['rpc']['image']
        entities.entities = sorted(int(s[3:]) for s in compose['services'] if s.startswith('pod') and s[3:].isdigit())
        wrapper = handoff_ops.Wrapper(fake, entities.entities, rows.append, sleep=lambda s: None)
        assert wrapper.propose(request) == n
        plans = [c for c in fake.calls if c[1].endswith('/plan')]
        intents = [c for c in fake.calls if c[1].endswith('/intent')]
        endorsements = [c for c in fake.calls if c[1].endswith('/endorse')]
        assert [(c[0], c[2]) for c in plans] == [(1, request)] and fake.calls[0] == plans[0]
        assert sorted(c[0] for c in intents) == list(range(2, n + 1)) and {c[2] for c in intents} == {b'{"plan":"synthetic"}'}
        assert sorted(c[0] for c in endorsements) == list(range(1, n + 1)) and {c[2] for c in endorsements} == {b'{"plan":"synthetic"}'}
        # helper commands: namespace of that entity's holder, unprivileged, no mounts
        entities.holder = lambda i: f'HOLDER{i}'
        for i in entities.entities:
            command = entities.command(i, '/api/v1/handoff/endorse', 10)
            assert f'container:HOLDER{i}' in command and '--read-only' in command and '-v' not in command and '--volume' not in command and '--privileged' not in command
        aborts = handoff_ops.abort_commands(generation, entities.entities, ['--network', '3'])
        assert sorted(aborts) == entities.entities and all(c.count('--root-rpc') == 1 and c[-1] == 'http://127.0.0.1:8002' for c in aborts.values())
    return {'handoff_cli_commands_checked': commands, 'handoff_install_override_renders': 'PASS', 'handoff_wrapper_dry_run': 'PASS', 'entities': n}


if __name__ == '__main__':
    print(json.dumps(validate(Path(sys.argv[1]), Path(sys.argv[2])), indent=2))
