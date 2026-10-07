"""Network guard and durable budget for the pinned chainflag transfer service."""
from contextlib import contextmanager
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import urllib.error
import urllib.request


def request(url, data=None, headers=None):
    payload = None if data is None else json.dumps(data).encode()
    req = urllib.request.Request(url, payload, headers or {})
    with urllib.request.urlopen(req, timeout=8) as response:
        return json.load(response)


class Guard:
    def __init__(self, config, state):
        self.cfg = config
        if not isinstance(config['chain_id'], int) or config['chain_id'] <= 0:
            raise ValueError('positive chain_id required')
        if not re.fullmatch(r'0x[0-9a-f]{64}', config['genesis_hash']):
            raise ValueError('exact lowercase block-zero hash required')
        if not re.fullmatch(r'0x[0-9a-fA-F]{40}', config['funding_address']):
            raise ValueError('funding_address required')
        if config['daily_claims'] <= 0 or config['minimum_balance_wei'] <= 0:
            raise ValueError('positive budget and reserve required')
        if not config.get('dev_only') and not config.get('captcha_sitekey'):
            raise ValueError('public faucet requires hCaptcha')
        self.state = state
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS identity (pin TEXT NOT NULL)')
            pin = json.dumps(config, sort_keys=True)
            old = db.execute('SELECT pin FROM identity').fetchone()
            if old and old[0] != pin:
                raise ValueError('configuration changed: use a fresh state volume after reset')
            if not old:
                db.execute('INSERT INTO identity VALUES (?)', (pin,))
            db.execute('CREATE TABLE IF NOT EXISTS claims (ts REAL, address TEXT, ip TEXT)')

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.state, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def rpc(self, method, params):
        result = request(self.cfg['rpc_url'], dict(jsonrpc='2.0', id=1, method=method, params=params),
                         {'Content-Type': 'application/json'})
        if 'error' in result or result.get('result') is None:
            raise ValueError('RPC unavailable')
        return result['result']

    def health(self):
        if int(self.rpc('eth_chainId', []), 16) != self.cfg['chain_id']:
            raise ValueError('RPC chain mismatch')
        if self.rpc('eth_getBlockByNumber', ['0x0', False])['hash'].lower() != self.cfg['genesis_hash']:
            raise ValueError('RPC genesis mismatch')
        info = request(self.cfg['backend_url'] + '/api/info')
        if info['account'].lower() != self.cfg['funding_address'].lower() or info['payout'] != '0.01':
            raise ValueError('backend funding account or payout mismatch')
        if not self.cfg.get('dev_only') and info.get('hcaptcha_sitekey') != self.cfg['captcha_sitekey']:
            raise ValueError('backend captcha mismatch')
        balance = int(self.rpc('eth_getBalance', [info['account'], 'latest']), 16)
        if balance < self.cfg['minimum_balance_wei']:
            raise ValueError('faucet exhausted: refill required')
        with self.db() as db:
            remaining = self.cfg['daily_claims'] - db.execute(
                'SELECT count(*) FROM claims WHERE ts > ?', (time.time() - 86400,)).fetchone()[0]
        if remaining <= 0:
            raise ValueError('daily budget exhausted')
        return dict(status='ready', balance_wei=str(balance), remaining_claims=remaining)

    def reserve(self, address, ip):
        # Commit before calling the signer. Timeout/crash is ambiguous; never automatically
        # refund a reservation, which could permit a second transfer after a lost response.
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM claims WHERE ts <= ?', (time.time() - 86400,))
            if db.execute('SELECT 1 FROM claims WHERE address=? OR ip=?', (address, ip)).fetchone():
                return False
            if db.execute('SELECT count(*) FROM claims').fetchone()[0] >= self.cfg['daily_claims']:
                return False
            db.execute('INSERT INTO claims VALUES (?, ?, ?)', (time.time(), address, ip))
        return True


class Handler(http.server.BaseHTTPRequestHandler):
    def reply(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/':
            body = Path(__file__).with_name('index.html').read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/api/network':
            cfg = self.server.guard.cfg
            self.reply(200, {k: cfg[k] for k in ('chain_id', 'genesis_hash', 'captcha_sitekey')})
        elif self.path == '/healthz':
            try:
                self.reply(200, self.server.guard.health())
            except Exception:
                self.reply(503, dict(status='unavailable', message='Check RPC, identity, backend, balance and daily budget'))
        else:
            self.reply(404, dict(message='Not found'))

    def do_POST(self):
        if self.path != '/api/claim':
            self.reply(404, dict(message='Not found'))
            return
        self.connection.settimeout(10)
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 2048 or self.headers.get('Transfer-Encoding'):
                raise ValueError('bounded JSON body required')
            body = json.loads(self.rfile.read(length))
            address = body['address']
            if not isinstance(address, str) or not re.fullmatch(r'0x[0-9a-fA-F]{40}', address) or int(address, 16) == 0:
                raise ValueError('invalid address')
        except (ValueError, KeyError, TypeError):
            self.reply(400, dict(message='Invalid address or JSON body'))
            return
        guard = self.server.guard
        cfg = guard.cfg
        if body.get('chain_id') != cfg['chain_id'] or body.get('genesis_hash') != cfg['genesis_hash']:
            self.reply(409, dict(message='Wrong network or reset genesis; reconnect your wallet'))
            return
        # Only the explicitly configured local TLS proxy may supply the client IP.
        ip = self.client_address[0]
        if ip == cfg.get('trusted_proxy_ip'):
            try:
                ip = str(ipaddress.ip_address(self.headers.get('X-Forwarded-For', '')))
            except ValueError:
                self.reply(400, dict(message='Proxy must overwrite X-Forwarded-For with one client IP'))
                return
        token = self.headers.get('h-captcha-response', '')
        if not cfg.get('dev_only') and not token:
            self.reply(400, dict(message='Complete hCaptcha'))
            return
        try:
            guard.health()
            if not guard.reserve(address.lower(), ip):
                self.reply(429, dict(message='One claim per address and IP per 24 hours; daily total capped'))
                return
            result = request(cfg['backend_url'] + '/api/claim', {'address': address},
                             {'Content-Type': 'application/json', 'h-captcha-response': token,
                              'X-Forwarded-For': ip})
            self.reply(200, result)
        except Exception as error:
            # Never echo upstream errors (RPC credentials, internal URLs, signer details).
            print('claim unavailable:', type(error).__name__, flush=True)
            self.reply(503, dict(message='Unavailable or outcome uncertain. Do not retry; inspect wallet and contact operator.'))


def main():
    cfg = json.loads(Path(os.environ.get('FAUCET_CONFIG', '/config/network.json')).read_text())
    guard = Guard(cfg, os.environ.get('FAUCET_STATE', '/state/claims.sqlite'))
    # Public mode listens inside the container; dev mode cannot be exposed remotely.
    host = '127.0.0.1' if cfg.get('dev_only') else '0.0.0.0'
    server = http.server.ThreadingHTTPServer((host, int(os.environ.get('PORT', '8080'))), Handler)
    server.guard = guard
    server.serve_forever()


if __name__ == '__main__':
    main()
