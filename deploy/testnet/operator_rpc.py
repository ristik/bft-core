"""The bind address of the root and shard operator RPC listeners (deploy/testnet).

Those listeners have no authentication of their own; their guarded endpoints accept loopback TCP peers only (docs/operations/root-rpc-exposure.md). The owner's
decision (2026-10-14, Q25) is loopback only, taken from configuration rather than written into the topology: `generate.py --rpc-bind` carries it, its default is
127.0.0.1 and it must be an IPv4 address in 127.0.0.0/8 (::1 is not accepted: not exercised in the containers), and everything that reaches the listeners (the metrics relay, the handoff wrapper, the validators) reads the generated Compose file, which holds the
one value. A non-loopback address is refused: it would put an unauthenticated operator endpoint on a network, and the guard would refuse the operator's own
loopback-only tooling reaching it from the same namespace anyway.
"""
import ipaddress

DEFAULT_BIND = '127.0.0.1'
ROOT_PORT = 8002
SHARD_PORT = 9101


class BindError(ValueError):
    pass


def check_bind(value):
    """The bind address as given, when it is an IPv4 literal in 127.0.0.0/8."""
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        raise BindError(f'--rpc-bind {value!r} is not an IPv4 address literal (IPv6 and host names are not accepted)') from None
    if not address.is_loopback:
        raise BindError(f'--rpc-bind {value}: the operator RPC has no authentication and is loopback only (owner decision Q25); use an address in 127.0.0.0/8')
    return value


def listen(bind, port):
    """host:port for --rpc-server-address."""
    return f'{bind}:{port}'


def url_of(entrypoint):
    """The http base URL of the --rpc-server-address in a generated entrypoint: what a client in the same namespace uses."""
    return 'http://' + entrypoint[entrypoint.index('--rpc-server-address') + 1]


def address_of(entrypoint):
    return entrypoint[entrypoint.index('--rpc-server-address') + 1]


def common_urls(compose):
    """(root URL, shard URL) of a generated Compose file, when EVERY root carries one operator address and every shard one: the wrapper and the
    abort commands address all entities by the same one, so a file whose roots differ is refused rather than half-followed."""
    out = []
    for kind in ('root', 'shard'):
        found = {n: address_of(s['entrypoint']) for n, s in compose['services'].items() if n.startswith(kind) and n[len(kind):].isdigit()}
        if not found:
            raise BindError(f'the Compose file has no {kind} services')
        if len(set(found.values())) != 1:
            raise BindError(f'the {kind}s carry different operator RPC addresses: ' + ', '.join(f'{n}={a}' for n, a in sorted(found.items())))
        out.append('http://' + next(iter(found.values())))
    return tuple(out)
