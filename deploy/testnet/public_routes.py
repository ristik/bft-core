#!/usr/bin/env python3
"""The public routes of one generation under ONE host name, for the host's nginx, and the static files they serve:

    public_routes.py GENERATION --hostname pos.staging.unicity.network [--web-root /var/www/pos-staging] [--out GENERATION/public]

It writes, and changes nothing else (no nginx reload, no copy into the web root):
  OUT/nginx/zones.conf   the limit_req/limit_conn zones the routes name (nginx `http` context; include once). It REPLACES the zones of
                         nginx.conf.example and faucet/nginx.conf.example (same names): a host that has those must drop them, or nginx -t
                         fails with a duplicate zone
  OUT/nginx/routes.conf  the locations (nginx `server` context: the host's server block includes it), every upstream on the host loopback port the
                         generation's compose files publish:
                           /rpc                 the RPC gateway (JSON-RPC POST)
                           /aggregator          the gateway's aggregator route (POST), and /api/v1/trustbases (GET)
                           /faucet/             the faucet page, with /api/network and /api/claim (its script calls them by absolute path)
                           /demo/               WEB_ROOT/demo: a static wallet build, deployed separately
                           /release/            WEB_ROOT/release: public, checksummed operator and wallet files
The protocol 6/7 bridge's /lockproof/ and /bridge/ routes were removed with that bridge (bft-core#1106, #1139); publishing the native bridge v2
files (GENERATION/bridge/nb2/public) is bft-core#1178.

Install (an operator act; nginx -t before every reload):
    sudo install -d -m 0755 WEB_ROOT/demo WEB_ROOT/release
    include OUT/nginx/zones.conf in the http context (once per host) and OUT/nginx/routes.conf in the host's server block
    sudo nginx -t && sudo systemctl reload nginx

The endpoints behind the routes keep their own limits (the gateway's methods and bodies, the guard's claims);
they trust X-Forwarded-For only from the generation's edge/faucet network gateways, which is where the published loopback ports arrive from.
"""
import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath

ZONES = """# Rate-limit zones of the public routes (public_routes.py); nginx http context, once per host.
limit_req_zone $binary_remote_addr zone=tn_rpc:10m rate=5r/s;
limit_req_zone $binary_remote_addr zone=tn_agg:10m rate=10r/s;
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
    """{'rpc', 'faucet'}: the loopback ports of GEN's compose file."""
    compose = json.loads((gen / 'compose.yaml').read_text())
    return {'rpc': loopback_port(compose, 'rpc', 8545), 'faucet': loopback_port(compose, 'faucet', 8080)}


def routes(ports, web_root, generation):
    """routes.conf: the locations, for nginx's server context."""
    proxy = '    proxy_set_header X-Forwarded-For $remote_addr;\n    proxy_set_header Host $host;\n'
    out = [f'# Public routes of generation {generation} (written by deploy/testnet/public_routes.py). Upstreams bind the host loopback.\n',
           f"""# RPC: the gateway takes JSON-RPC POSTs at its "/". POST only, on purpose: no OPTIONS, so no CORS preflight; the clients are same-origin (/demo/) or not browsers.
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
    out.append(f"""# A static wallet build, deployed separately into {web_root}/demo.
location = /demo {{ return 301 /demo/; }}
location /demo/ {{
    limit_except GET {{ deny all; }}
    alias {web_root}/demo/;
    index index.html;
}}
# Stage only the public files listed in the release's SHA256SUMS.
location = /release {{ return 301 /release/; }}
location /release/ {{
    limit_except GET {{ deny all; }}
    limit_conn tn_conn 4;
    limit_req zone=tn_agg burst=20 nodelay;
    alias {web_root}/release/;
    autoindex off;
    disable_symlinks on;
}}
""")
    return ''.join(out)


@contextmanager
def release_file(source, name):
    """Open a regular file below source without following symbolic links."""
    parts = PurePosixPath(name).parts
    with ExitStack() as stack:
        folder = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, folder)
        for part in parts[:-1]:
            folder = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=folder)
            stack.callback(os.close, folder)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
        with os.fdopen(fd, 'rb') as file:
            if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                raise ValueError(f'{name}: expected a regular release file')
            yield file


def stage_release(source, destination):
    """Publish SHA256SUMS and its verified regular files into a fresh directory."""
    with release_file(source, 'SHA256SUMS') as file:
        manifest = file.read()
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.release-') as temp:
        stage = Path(temp) / 'release'
        stage.mkdir(mode=0o755)
        names = set()
        for line in manifest.decode('ascii').splitlines():
            match = re.fullmatch(r'([0-9a-f]{64}) [ *]([A-Za-z0-9._/-]+)', line)
            if not match:
                raise ValueError('invalid SHA256SUMS entry')
            digest, name = match.groups()
            path = PurePosixPath(name)
            if (path.is_absolute() or not path.parts or path.as_posix() != name or '..' in path.parts or
                    name == 'SHA256SUMS' or name in names):
                raise ValueError(f'{name}: invalid or duplicate release path')
            names.add(name)
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with release_file(source, name) as src, target.open('x+b') as dst:
                shutil.copyfileobj(src, dst)
                dst.seek(0)
                if hashlib.file_digest(dst, 'sha256').hexdigest() != digest:
                    raise ValueError(f'{name}: checksum mismatch')
            target.chmod(0o644)
        if not names:
            raise ValueError('empty SHA256SUMS')
        (stage / 'SHA256SUMS').write_bytes(manifest)
        stage.rename(destination)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('generation', type=Path)
    p.add_argument('--hostname', required=True, help='the one public host name (TLS is the host server block\'s)')
    p.add_argument('--web-root', default='/var/www/pos-staging', help='where the static /demo/ directory lives on the host')
    p.add_argument('--out', type=Path, help='output directory (default GENERATION/public); it must not exist')
    p.add_argument('--release-source', type=Path, help='optionally verify and stage the SHA256SUMS release into OUT/release')
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
    (out / 'nginx').mkdir(parents=True)
    (out / 'nginx/zones.conf').write_text(ZONES)
    (out / 'nginx/routes.conf').write_text(routes(ports, web_root, gen.name))
    if a.release_source:
        try:
            stage_release(a.release_source, out / 'release')
        except (ValueError, OSError) as error:
            p.error(f'cannot stage release: {error}')
    print(json.dumps({'generation': gen.name, 'hostname': a.hostname, 'out': str(out), 'upstreams': ports,
                      'routes': ['/rpc', '/aggregator', '/api/v1/trustbases', '/faucet/', '/api/network', '/api/claim', '/demo/', '/release/']}, indent=2))


if __name__ == '__main__':
    main()
