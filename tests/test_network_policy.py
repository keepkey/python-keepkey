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


def test_owned_emulator_lease_allows_only_its_udp_pair_and_expires():
    from emulator_endpoints import owned_emulator_pair

    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(1)
        port = receiver.getsockname()[1]
        if port == 65535:
            pytest.skip("allocated port has no adjacent debug port")
        with owned_emulator_pair(port):
            sender.sendto(b"owned", ("127.0.0.1", port))
            assert receiver.recv(5) == b"owned"
            with pytest.raises(AssertionError):
                sender.sendto(b"forbidden", ("192.0.2.1", port))
            with pytest.raises(AssertionError):
                sender.sendto(b"forbidden", ("127.0.0.1", 1))
        with pytest.raises(AssertionError):
            sender.sendto(b"expired", ("127.0.0.1", port))
    finally:
        sender.close()
        receiver.close()
