#!/usr/bin/env python3
"""The public routes of one generation under ONE host name, for the host's nginx, and the static files they serve:

    public_routes.py GENERATION --hostname pos.staging.unicity.network [--web-root /var/www/pos-staging] [--out GENERATION/public]

It writes, and changes nothing else (no nginx reload, no copy into the web root):
  OUT/nginx/zones.conf   the limit_req/limit_conn zones the routes name (nginx `http` context; include once)
  OUT/nginx/routes.conf  the locations (nginx `server` context: the host's server block includes it), every upstream on the host loopback port the
                         generation's compose files publish:
                           /rpc                 the RPC gateway (JSON-RPC POST)
                           /aggregator          the gateway's aggregator route (POST), and /api/v1/trustbases (GET)
                           /faucet/             the faucet page, with /api/network and /api/claim (its script calls them by absolute path)
                           /lockproof/          the lock-proof endpoint (GET), when the bridge is deployed (compose.bridge.yaml)
                           /bridge/             WEB_ROOT/bridge: the published bridge files, when the bridge is deployed
                           /demo/               WEB_ROOT/demo: a static wallet build, deployed separately
  OUT/bridge/            GENERATION/bridge/public with tester-config.json naming the PUBLIC URLs (https://HOSTNAME/rpc, /aggregator, /lockproof).
                         The generation's own bridge/public/tester-config.json keeps the internal names: the rehearsal's tester runs on the validators network.

Install (an operator act; nginx -t before every reload):
    sudo install -d -m 0755 WEB_ROOT/bridge WEB_ROOT/demo && sudo cp -r OUT/bridge/. WEB_ROOT/bridge/
    include OUT/nginx/zones.conf in the http context (once per host) and OUT/nginx/routes.conf in the host's server block
    sudo nginx -t && sudo systemctl reload nginx

The endpoints behind the routes keep their own limits (the gateway's methods and bodies, the guard's claims, the lock-proof endpoint's per-client rate);
they trust X-Forwarded-For only from the generation's edge/faucet network gateways, which is where the published loopback ports arrive from.
"""
import argparse
import json
import re
import shutil
from pathlib import Path

ZONES = """# Rate-limit zones of the public routes (public_routes.py); nginx http context, once per host.
limit_req_zone $binary_remote_addr zone=tn_rpc:10m rate=5r/s;
limit_req_zone $binary_remote_addr zone=tn_agg:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=tn_lockproof:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=faucet:10m rate=1r/s;
limit_conn_zone $binary_remote_addr zone=tn_conn:10m;
"""

HOSTNAME = re.compile(r'(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
WEB_ROOT = re.compile(r'/[A-Za-z0-9._/-]+')


def loopback_port(compose, service, container_port):
    """The host port SERVICE publishes for CONTAINER_PORT, which must be bound to 127.0.0.1 (the package never publishes anything else)."""
    for spec in compose['services'][service].get('ports', []):
        parts = str(spec).split(':')
        if len(parts) == 3 and parts[2] == str(container_port):
            if parts[0] != '127.0.0.1':
                raise SystemExit(f'{service} publishes {container_port} on {parts[0]}, not on the host loopback')
            return int(parts[1])
    raise SystemExit(f'{service} publishes no port {container_port}')


def upstreams(gen):
    """{'rpc', 'faucet', 'lockproof' (None without the bridge)}: the loopback ports of GEN's compose files."""
    compose = json.loads((gen / 'compose.yaml').read_text())
    ports = {'rpc': loopback_port(compose, 'rpc', 8545), 'faucet': loopback_port(compose, 'faucet', 8080), 'lockproof': None}
    overlay = gen / 'compose.bridge.yaml'
    if overlay.is_file():
        ports['lockproof'] = loopback_port(json.loads(overlay.read_text()), 'lockproof', 8090)
    return ports


def routes(ports, web_root, generation):
    """routes.conf: the locations, for nginx's server context."""
    proxy = '    proxy_set_header X-Forwarded-For $remote_addr;\n    proxy_set_header Host $host;\n'
    out = [f'# Public routes of generation {generation} (written by deploy/testnet/public_routes.py). Upstreams bind the host loopback.\n',
           f"""# RPC: the gateway takes JSON-RPC POSTs at its "/".
location = /rpc {{
    limit_except POST {{ deny all; }}
    limit_conn tn_conn 4;
    limit_req zone=tn_rpc burst=10 nodelay;
    # the gateway allows 16 KiB per method except eth_sendRawTransaction, eth_call and eth_estimateGas (4.5 MiB); it checks the method itself
    client_max_body_size 5m;
    client_body_timeout 30s;
{proxy}    proxy_connect_timeout 2s;
    proxy_read_timeout 45s;
    proxy_send_timeout 30s;
    proxy_pass http://127.0.0.1:{ports['rpc']}/;
}}
# the aggregator (the gateway's /aggregator route) and its trust-base pages
location = /aggregator {{
    limit_except POST {{ deny all; }}
    limit_conn tn_conn 4;
    limit_req zone=tn_agg burst=20 nodelay;
    client_max_body_size 64k;
{proxy}    proxy_connect_timeout 2s;
    proxy_read_timeout 35s;
    proxy_send_timeout 10s;
    proxy_pass http://127.0.0.1:{ports['rpc']};
}}
location = /api/v1/trustbases {{
    limit_except GET {{ deny all; }}
    limit_conn tn_conn 4;
    limit_req zone=tn_agg burst=20 nodelay;
{proxy}    proxy_connect_timeout 2s;
    proxy_read_timeout 35s;
    proxy_pass http://127.0.0.1:{ports['rpc']};
}}
# Faucet: the page under /faucet/; its script calls /api/network and /api/claim by absolute path.
location = /faucet {{ return 301 /faucet/; }}
location /faucet/ {{
    limit_req zone=faucet burst=5 nodelay;
    client_max_body_size 2k;
    client_body_timeout 10s;
{proxy}    proxy_read_timeout 30s;
    proxy_pass http://127.0.0.1:{ports['faucet']}/;
}}
location = /api/network {{
    limit_req zone=faucet burst=5 nodelay;
{proxy}    proxy_read_timeout 30s;
    proxy_pass http://127.0.0.1:{ports['faucet']};
}}
location = /api/claim {{
    limit_except POST {{ deny all; }}
    limit_req zone=faucet burst=5 nodelay;
    client_max_body_size 2k;
    client_body_timeout 10s;
{proxy}    proxy_read_timeout 30s;
    proxy_pass http://127.0.0.1:{ports['faucet']};
}}
"""]
    if ports['lockproof'] is not None:
        out.append(f"""# The lock-proof endpoint (dnb-tool lockproof-serve): GET /lockproof/v1/lockproof?block=0x..&nonce=N and /lockproof/healthz.
# It trusts X-Forwarded-For only from the generation's edge gateway, and it limits each client itself (2/s, 20/s total, 4 builds).
location = /lockproof {{ return 301 /lockproof/; }}
location /lockproof/ {{
    limit_except GET {{ deny all; }}
    limit_conn tn_conn 4;
    limit_req zone=tn_lockproof burst=20 nodelay;
{proxy}    proxy_connect_timeout 2s;
    proxy_read_timeout 45s;
    proxy_send_timeout 10s;
    proxy_pass http://127.0.0.1:{ports['lockproof']}/;
}}
# The generation's public bridge files (public_routes.py OUT/bridge: tester-config.json with the public URLs): static, read-only.
location = /bridge {{ return 301 /bridge/; }}
location /bridge/ {{
    limit_except GET {{ deny all; }}
    limit_req zone=tn_agg burst=20 nodelay;
    alias {web_root}/bridge/;
    index index.html;
    types {{ text/html html; application/json json; application/cbor cbor; }}
    default_type text/plain;
}}
""")
    out.append(f"""# A static wallet build, deployed separately into {web_root}/demo.
location = /demo {{ return 301 /demo/; }}
location /demo/ {{
    limit_except GET {{ deny all; }}
    alias {web_root}/demo/;
    index index.html;
}}
""")
    return ''.join(out)


def public_tester_config(config, base):
    """The bridge tester's configuration with the public URLs under BASE (https://HOSTNAME). No redeemEthUrl: the package's gateway takes redemptions."""
    out = {k: v for k, v in config.items() if k != 'redeemEthUrl'}
    out.update(ethUrl=f'{base}/rpc', aggUrl=f'{base}/aggregator', lockProofUrl=f'{base}/lockproof')
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('generation', type=Path)
    p.add_argument('--hostname', required=True, help='the one public host name (TLS is the host server block\'s)')
    p.add_argument('--web-root', default='/var/www/pos-staging', help='where the static /bridge/ and /demo/ directories live on the host')
    p.add_argument('--out', type=Path, help='output directory (default GENERATION/public); it must not exist')
    a = p.parse_args(argv)
    if not HOSTNAME.fullmatch(a.hostname):
        p.error(f'--hostname {a.hostname!r} is not a lowercase DNS name')
    web_root = a.web_root.rstrip('/')
    if not WEB_ROOT.fullmatch(web_root) or '..' in web_root.split('/'):
        p.error(f'--web-root {a.web_root!r} must be an absolute path of letters, digits, ".", "_", "-" and "/"')
    gen = a.generation.resolve()
    out = (a.out or gen / 'public').resolve()
    if out.exists():
        p.error(f'{out} exists: choose a new directory')
    ports = upstreams(gen)
    published = gen / 'bridge/public'
    if ports['lockproof'] is not None and not (published / 'tester-config.json').is_file():
        p.error('compose.bridge.yaml exists but bridge/public has no tester-config.json: run the bridge deploy (rehearse_bridge.py --stages deploy,serve)')
    (out / 'nginx').mkdir(parents=True)
    (out / 'nginx/zones.conf').write_text(ZONES)
    (out / 'nginx/routes.conf').write_text(routes(ports, web_root, gen.name))
    if ports['lockproof'] is not None:
        (out / 'bridge').mkdir()
        for f in sorted(published.iterdir()):
            if f.is_file() and f.name != 'tester-config.json':
                shutil.copyfile(f, out / 'bridge' / f.name)
        tester = public_tester_config(json.loads((published / 'tester-config.json').read_text()), f'https://{a.hostname}')
        (out / 'bridge/tester-config.json').write_text(json.dumps(tester, indent=2) + '\n')
    print(json.dumps({'generation': gen.name, 'hostname': a.hostname, 'out': str(out), 'upstreams': ports,
                      'routes': ['/rpc', '/aggregator', '/api/v1/trustbases', '/faucet/', '/api/network', '/api/claim']
                      + (['/lockproof/', '/bridge/'] if ports['lockproof'] is not None else []) + ['/demo/']}, indent=2))


if __name__ == '__main__':
    main()
