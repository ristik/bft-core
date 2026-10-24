"""A joiner on the PoS package (TN-S #437): an identity that is not in the genesis registers, bonds and is delegated, and its entity starts as a follower.

Stage `pos-joiner`, run on a FRESH PoS generation (it changes the election's input, so it comes before any election result: up, identity, first-tx, pos-smoke,
pos-joiner). Not in the default list yet: the stages that hand off to five members follow. Part 1, the entity (joiner.py prepare): keys, directories and the
Compose services beside the generation; its signing authority starts at the genesis scope and its operator channel gives the EVM key and node-info. Part 2, the
contract path with `pos-relayer tx join register|bond|admit` (the EVM key stays in the authority): a new custody identity owned by a fresh owner key, ONE lot of one
bond unit (weight 1), a delegation the election's eligibility reads; the live index then holds five identities. Part 3, the follower: pod, ureth and root of the
joiner start; the root reports itself a follower (not a member of the genesis epoch).

The module only uses what `Rehearsal` already provides; nothing here changes those. Keys are the generation's throwaway ones: the joiner's private keys are
written under validator<i>/ (mode 0600, directory 0700) and never to network/.
"""
import json
import os
import re
import subprocess
from pathlib import Path

import handoff_ops
import joiner as joiner_lib

BOND_UNIT = 100 * 10 ** 18


def joiner_file(owner_key, root_key, withdrawal, payee, root_node_id, evm_node_id, expiry=2 ** 62):
    """The identity file `pos-relayer tx join` takes. No evmKey: the signing authority holds it (--evm-authority-socket)."""
    return {'ownerKey': owner_key, 'rootKey': root_key, 'withdrawal': withdrawal, 'payee': payee, 'rootNodeId': root_node_id, 'evmNodeId': evm_node_id, 'expiry': expiry}


def compose(r, *args, check=True):
    """docker compose with the generation's file AND the joiner override."""
    return subprocess.run(['docker', 'compose', '-f', str(r.gen / 'compose.yaml'), '-f', str(r.gen / 'compose.joiner.json'), *args], check=check, text=True, capture_output=True).stdout


def new_wallet(r):
    """{'address', 'private_key'} of a fresh key. `cast wallet new` prints them as text ("Address: 0x..", "Private key: 0x..") and, with --json, as an object or a list
    of objects whose key names differ between Foundry versions: the 20-byte and the 32-byte hex strings are read from whatever it prints."""
    text = r.cast_run('wallet', 'new', '--json')
    address = re.search(r'0x[0-9a-fA-F]{40}(?![0-9a-fA-F])', text)
    key = re.search(r'0x[0-9a-fA-F]{64}(?![0-9a-fA-F])', text)
    if not address or not key:
        raise RuntimeError('cast wallet new printed no address and private key')
    return {'address': address.group(0), 'private_key': key.group(0)}


def exec_in(r, service, *command):
    """`docker compose exec` of a joiner service (the base file does not know it)."""
    run = subprocess.run(['docker', 'compose', '-f', str(r.gen / 'compose.yaml'), '-f', str(r.gen / 'compose.joiner.json'), 'exec', '-T', service, *command], text=True, capture_output=True)
    if run.returncode:
        raise RuntimeError(f'{service}: {" ".join(command[:4])}: exit {run.returncode}: {run.stderr.strip()[-400:]}')
    return run.stdout


def pos_joiner(r):
    deployment = json.loads((r.gen / 'network' / 'pos-deployment.json').read_text())
    election, custody = deployment['election'], deployment['custody']
    live = r.view(election, 'liveCount()(uint32)')[0]
    r.expect(live == r.n, f'precondition: the live index holds the {r.n} genesis identities (a fresh generation)', str(live))

    # --- part 1: the entity ------------------------------------------------------------------------------------------------------
    info = joiner_lib.prepare(r.gen, r.ubft)
    index = info['index']
    r.say(f'  joiner entity {index}: root {info["root"]}, evm {info["evm"]}')
    val = r.gen / f'validator{index}'
    compose(r, 'up', '-d', '--no-deps', f'authority{index}')
    auth = f'authority{index}'
    operator = ['--operator-socket', '/authority/operator.sock', '--operator-credential', '/authority/operator.cred']
    r.wait('the joiner\'s signing authority answers', lambda: exec_in(r, auth, 'ubft', 'signing-authority', 'status', *operator), 60)
    exec_in(r, auth, 'ubft', 'signing-authority', 'node-info', *operator, '--out', '/authority/node-info.json')
    r.expect((val / 'auth' / 'node-info.json').is_file(), 'the authority wrote its node-info (the EVM validator the successor shard configuration will name)')

    # --- part 2: register, bond, admit ---------------------------------------------------------------------------------------------
    owner = new_wallet(r)
    withdrawal, payee = new_wallet(r)['address'], new_wallet(r)['address']
    root_key = json.loads((val / 'root' / 'keys.json').read_text())['sigKey']['privateKey']
    identity = val / 'joiner-identity.json'
    fd = os.open(identity, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(joiner_file(owner['private_key'], root_key, withdrawal, payee, info['root'], info['evm']), out)
    r.faucet_send(owner['address'], BOND_UNIT + 10 ** 18)   # the one bond unit and the gas of three transactions
    mounts = [f'{val / "auth"}:/auth']
    evm = ['--evm-authority-socket', '/auth/operator.sock', '--evm-authority-credential', '/auth/operator.cred']
    status, out = r.relayer(identity, 'join', 'register', *evm, joiner=True, mounts=mounts)
    r.expect(status == 0, 'join register: the joiner has a custody identity', out.strip()[-300:])
    found = re.search(r'custody id (\d+)', out)   # the relayer prints the id on stderr
    ident = int(found.group(1)) if found else 0
    r.expect(ident > r.n, f'the new identity is numbered after the {r.n} genesis identities', str(ident))
    status, out = r.relayer(identity, 'join', 'bond', '--id', str(ident), '--value-wei', str(BOND_UNIT), *evm, joiner=True, mounts=mounts)
    r.expect(status == 0, 'join bond: one lot of one bond unit', out.strip()[-300:])
    status, out = r.relayer(identity, 'join', 'admit', '--id', str(ident), *evm, joiner=True, mounts=mounts)
    r.expect(status == 0, 'join admit: the delegation to the joiner\'s root and EVM keys', out.strip()[-300:])
    r.wait('the live index holds five identities', lambda: r.view(election, 'liveCount()(uint32)')[0] == r.n + 1, 120)
    r.expect(r.view(election, 'isIndexed(uint64)(bool)', str(ident))[0] in (True, 'true'), 'the joiner is in the live index', str(ident))
    lots = r.view_text(custody, 'generationLots(uint64,uint64)(uint256[])', str(ident), '1').strip('[]').replace(',', ' ').split()
    r.expect(len(lots) == 1, 'the joiner has one lot (lMax 1)', str(lots))
    (r.evidence / 'joiner.json').write_text(json.dumps({'index': index, 'stakingId': ident, 'owner': owner['address'], 'withdrawal': withdrawal, 'payee': payee,
                                                         'rootNodeId': info['root'], 'evmNodeId': info['evm']}, indent=1, sort_keys=True) + '\n')

    # --- part 3: the follower -----------------------------------------------------------------------------------------------------
    compose(r, 'up', '-d', '--no-deps', f'pod{index}', f'ureth{index}')
    compose(r, 'up', '-d', '--no-deps', f'metrics{index}', f'root{index}')
    transport = handoff_ops.DockerTransport(r.gen, override=r.gen / 'compose.joiner.json')
    def follower():
        try:
            code, body = transport.post(index, '/api/v1/q3/status', b'{}')
            return code == 200 and json.loads(body).get('follower') is True
        except (handoff_ops.HandoffError, ValueError):
            return False
    r.expect(r.wait('the joiner\'s root reports itself a follower', follower, 180), 'the joiner\'s root is a follower of the genesis epoch (not a member)')

