"""The bind address of the root and shard operator RPC listeners (deploy/testnet).

Those listeners have no authentication of their own; their guarded endpoints accept loopback TCP peers only (docs/operations/root-rpc-exposure.md). The owner's
decision (2026-10-14, Q25) is loopback only, taken from configuration rather than written into the topology: `generate.py --rpc-bind` carries it, its default is
127.0.0.1, and everything that reaches the listeners (the metrics relay, the handoff wrapper, the validators) reads the generated Compose file, which holds the
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
    """The bind address as given, when it is a loopback IP literal (127.0.0.0/8 or ::1)."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise BindError(f'--rpc-bind {value!r} is not an IP address literal') from None
    if not address.is_loopback:
        raise BindError(f'--rpc-bind {value}: the operator RPC has no authentication and is loopback only (owner decision Q25); use a loopback address')
    return value


def listen(bind, port):
    """host:port for --rpc-server-address (an IPv6 literal in brackets)."""
    return f'[{bind}]:{port}' if ':' in bind else f'{bind}:{port}'


def url_of(entrypoint):
    """The http base URL of the --rpc-server-address in a generated entrypoint: what a client in the same namespace uses."""
    return 'http://' + entrypoint[entrypoint.index('--rpc-server-address') + 1]
