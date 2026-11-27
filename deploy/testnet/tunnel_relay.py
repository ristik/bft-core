#!/usr/bin/env python3
"""A byte forwarder for the remote joiner's SSH tunnel (remote_joiner.py), standard library only (it runs in the package's rpc image).

    tunnel_relay.py --forward LISTEN=TARGET [--forward ...]
        LISTEN, TARGET:  tcp:PORT (listen on 0.0.0.0) | tcp:HOST:PORT | unix:PATH

On the host it is the container `<generation>-laptop-relay` on the generation's internal `validators` network, with the aliases root<J> and shard<J> of the
laptop's entity J. It listens on 8000 and 9000 and forwards to the Unix sockets the laptop's `ssh -R` binds in the relay's socket directory (sshd has
GatewayPorts no, and a container on an internal network cannot reach host loopback; a Unix socket needs neither), and it makes one Unix socket per
genesis root, shard node and execution client (root<i>.sock -> root<i>:8000, ...) that the laptop's `ssh -L` connects to. On the laptop the same script is
each peer stub peer<i> (aliases root<i>, shard<i>, ureth<i>): 8000/9000/8545 forwarded to the Mac's loopback, where the `ssh -L` listeners are.

libp2p authenticates peers by their ids, so the forwarder is transparent: it never parses what it carries.
"""
import argparse
import asyncio
import os
import sys
import time


def parse_end(text):
    kind, _, rest = text.partition(':')
    if kind == 'unix' and rest.startswith('/'):
        return ('unix', rest)
    if kind == 'tcp':
        host, _, port = rest.rpartition(':')
        if port.isdigit():
            return ('tcp', host or '0.0.0.0', int(port))
    raise argparse.ArgumentTypeError(f'not tcp:[HOST:]PORT or unix:/PATH: {text!r}')


def parse_forward(text):
    listen, sep, target = text.partition('=')
    if not sep:
        raise argparse.ArgumentTypeError(f'--forward wants LISTEN=TARGET, got {text!r}')
    return parse_end(listen), parse_end(target)


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


class Forward:
    def __init__(self, listen, target):
        self.listen, self.target = listen, target
        self.open = self.total = self.failed = 0

    def label(self):
        return f'{":".join(map(str, self.listen))} -> {":".join(map(str, self.target))}'

    async def handle(self, reader, writer):
        try:
            if self.target[0] == 'unix':
                up_reader, up_writer = await asyncio.wait_for(asyncio.open_unix_connection(self.target[1]), 10)
            else:
                up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(self.target[1], self.target[2]), 10)
        except (OSError, asyncio.TimeoutError) as error:
            self.failed += 1
            if self.failed in (1, 10, 100) or self.failed % 1000 == 0:
                print(f'{time.strftime("%H:%M:%SZ", time.gmtime())} {self.label()}: target unreachable ({type(error).__name__}), {self.failed} so far', flush=True)
            writer.close()
            return
        self.open += 1
        self.total += 1
        try:
            await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
        finally:
            self.open -= 1

    async def start(self):
        if self.listen[0] == 'unix':
            path = self.listen[1]
            if os.path.exists(path):
                os.unlink(path)   # a socket left by an earlier run of this relay
            return await asyncio.start_unix_server(self.handle, path)
        return await asyncio.start_server(self.handle, self.listen[1], self.listen[2], reuse_address=True)


async def run(forwards, report=300):
    servers = [await f.start() for f in forwards]
    print(f'{time.strftime("%H:%M:%SZ", time.gmtime())} forwarding: ' + '; '.join(f.label() for f in forwards), flush=True)
    try:
        while True:
            await asyncio.sleep(report)
            print(f'{time.strftime("%H:%M:%SZ", time.gmtime())} ' + '; '.join(f'{f.label()} open {f.open} total {f.total} failed {f.failed}' for f in forwards), flush=True)
    finally:
        for s in servers:
            s.close()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--forward', action='append', type=parse_forward, required=True)
    p.add_argument('--report', type=int, default=300, help='seconds between connection-count lines')
    a = p.parse_args(argv)
    os.umask(0o077)   # the Unix sockets: the relay's user (the ssh user) only
    asyncio.run(run([Forward(*f) for f in a.forward], a.report))


if __name__ == '__main__':
    sys.exit(main())
