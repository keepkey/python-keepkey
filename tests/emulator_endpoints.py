"""Exact loopback UDP endpoints leased by test-owned emulator processes."""

from contextlib import contextmanager

_owned = set()


def is_owned_endpoint(endpoint):
    return endpoint in _owned


@contextmanager
def owned_emulator_pair(port):
    if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65535:
        raise ValueError("emulator port must leave room for its debug port")
    endpoints = {("127.0.0.1", port), ("127.0.0.1", port + 1)}
    if endpoints & _owned:
        raise RuntimeError("emulator endpoints already leased")
    _owned.update(endpoints)
    try:
        yield
    finally:
        _owned.difference_update(endpoints)
