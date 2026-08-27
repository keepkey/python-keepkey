"""The authoritative suite's only network capability is emulator UDP."""

import socket

import pytest
import requests


def test_non_emulator_local_transports_are_denied():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(AssertionError):
            tcp.connect(("127.0.0.1", 11044))
    finally:
        tcp.close()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(AssertionError):
            udp.sendto(b"probe", ("127.0.0.1", 1))
    finally:
        udp.close()

    if hasattr(socket, "AF_UNIX"):
        unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with pytest.raises(AssertionError):
                unix.connect("/tmp/keepkey-network-policy-probe")
        finally:
            unix.close()

    with pytest.raises(AssertionError):
        requests.get("http://127.0.0.1:1/forbidden")
