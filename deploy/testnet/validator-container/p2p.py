#!/usr/bin/env python3
"""Plan direct TCP forwarding and public libp2p announcements for a VR Compose generation."""
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess

ROLES = {'root': (8000, 26662), 'shard': (9000, 28111)}


def plan(compose, address, pod_addresses, offset):
    routes = []
    for i, pod in enumerate(pod_addresses, 1):
        ipaddress.IPv4Address(pod)
        for role, (inner, start) in ROLES.items():
            name = f'{role}{i}'
            entry = compose['services'][name]['entrypoint']
            if f'/ip4/0.0.0.0/tcp/{inner}' not in entry or '--announce-addresses' in entry:
                raise ValueError(f'{name}: expected the original dedicated P2P listener')
            outer = start + i - 1 + offset
            entry.extend(('--announce-addresses', f'/ip4/{address}/tcp/{outer}'))
            routes.append((name, outer, pod, inner))
    if set(compose['services']) >= {f'root{len(pod_addresses) + 1}', f'shard{len(pod_addresses) + 1}'}:
        raise ValueError('pod address list omits a validator')
    return routes


def inspect(generation, compose, n):
    project = compose['name']
    routes = []
    for i in range(1, n + 1):
        result = subprocess.check_output(['docker', 'inspect', '--format={{json .NetworkSettings.Networks}}',
                                         f'{project}-pod{i}-1'], text=True)
        routes.append(json.loads(result)[f'{project}_validators']['IPAddress'])
    return routes


def commands(address, routes, name, source):
    """Dedicated iptables chains. Add only exact P2P destinations and original ports."""
    ingress = ['-d', address, '-p', 'tcp']
    if source:
        ingress.extend(('-s', source))
    rules = []
    for role, port, node, internal in routes:
        rules.append(f'-A {name} -d {address} -p tcp --dport {port} -j DNAT --to-destination {node}:{internal}')
    cross = []
    forward = []
    for _, port, node, internal in routes:
        match = f'-d {node} -p tcp --dport {internal} -m conntrack --ctorigdst {address} --ctorigdstport {port}'
        forward.append(f'-A {name} {match} -j ACCEPT')
        forward.append(f'-A {name} -s {node} -p tcp --sport {internal} -m conntrack --ctstate ESTABLISHED '
                       f'--ctdir REPLY --ctorigdst {address} --ctorigdstport {port} -j ACCEPT')
        # Validator pods are on an internal Docker network and have no default
        # route. Translate the return path only for these forwarded P2P flows.
        cross.append(f'-A {name}_OUT {match} -j MASQUERADE')
    scope = ' '.join(ingress)
    # Keep a separate iptables-restore transaction per table. The plan is applied
    # without --flush so Docker's rules and unrelated services are left alone.
    return '\n'.join([
        '*nat', f':{name} - [0:0]', f':{name}_OUT - [0:0]',
        *rules, *cross, f'-I PREROUTING 1 {scope} -j {name}', f'-I OUTPUT 1 {scope} -j {name}',
        f'-I POSTROUTING 1 -p tcp -m conntrack --ctorigdst {address} -j {name}_OUT', 'COMMIT',
        '*filter', f':{name} - [0:0]', *forward, f'-I DOCKER-USER 1 -j {name}', 'COMMIT', '',
    ])


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('generation', type=Path)
    cli.add_argument('--public-ip', required=True, type=ipaddress.IPv4Address)
    cli.add_argument('--out', required=True, type=Path)
    cli.add_argument('--offset', type=int, choices=(0, 1000, 2000, 3000), default=0)
    cli.add_argument('--source', type=ipaddress.IPv4Network, help='limit private rehearsal traffic to this joiner subnet')
    a = cli.parse_args()
    compose = json.loads((a.generation/'compose.yaml').read_text())
    manifest = json.loads((a.generation/'manifest.json').read_text())
    if (manifest.get('pos') or {}).get('profile') != 'vr-pos16' or manifest['validators'] != 4:
        cli.error('expected the four-incumbent VR generation')
    if not a.public_ip.is_global:
        cli.error('use the host’s publicly routable IPv4 address')
    address = str(a.public_ip)
    if not a.offset and a.source:
        cli.error('--source is only for private rehearsal plans')
    routes = plan(compose, address, inspect(a.generation, compose, manifest['validators']), a.offset)
    a.out.mkdir(mode=0o700)
    prefix = 'TNVC' + str(a.offset)
    (a.out/'announce.json').write_text(json.dumps(compose, indent=2)+'\n')
    (a.out/'forward.rules').write_text(commands(address, routes, prefix, str(a.source) if a.source else None))
    (a.out/'routes.json').write_text(json.dumps(routes, indent=2)+'\n')


if __name__ == '__main__':
    main()
