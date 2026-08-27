"""Fail-closed controls for authoritative offline transaction fixtures."""

import json
import os
import socket
import tempfile
import unittest
from pathlib import Path

import common  # Configures the absolute, offline-only fixture directory.
import requests
from keepkeylib import tx_api
from tx_fixture_manifest import build_manifest, validate_test_network_surface


FIXTURE_DIR = Path(common.TX_FIXTURE_DIR)
MANIFEST = FIXTURE_DIR / "manifest.json"


class TestTransactionFixtureIntegrity(unittest.TestCase):
    def test_manifest_matches_every_fixture_and_canonical_txid(self):
        checked_in = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(checked_in, build_manifest(FIXTURE_DIR))

    def test_no_unapproved_network_code_exists_under_tests(self):
        validate_test_network_surface(FIXTURE_DIR.parent)

    def test_lookup_is_cwd_independent(self):
        old_cwd = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.chdir(tmp)
                tx = tx_api.TxApiBitcoin.get_tx(
                    "d5f65ee80147b4bcc70b75e4bbf2d738"
                    "2021b871bd8867ef8fa525ef50864882")
                self.assertEqual(tx.version, 1)
                self.assertEqual(len(tx.inputs), 2)
                self.assertEqual(len(tx.bin_outputs), 1)
        finally:
            os.chdir(old_cwd)

    def test_missing_fixture_never_falls_back_to_http(self):
        with self.assertRaisesRegex(
                tx_api.OfflineFixtureError,
                "network=insight_bitcoin resource=tx id=0{64}"):
            tx_api.TxApiBitcoin.get_tx("0" * 64)

    def test_network_denial_control_blocks_dns_and_http(self):
        # The only network exception is the emulator transport selected by the
        # harness. In firmware CI this is kkemu:11044/11045; in standalone
        # python-keepkey CI it is the published emulator on loopback.
        endpoint = os.environ.get(
            "KK_TRANSPORT_MAIN", "127.0.0.1:11044")
        host, port = endpoint.rsplit(":", 1)
        self.assertTrue(socket.getaddrinfo(host, int(port)))
        with self.assertRaisesRegex(
                AssertionError,
                "authoritative test attempted external network access"):
            socket.getaddrinfo("example.com", 443)
        with self.assertRaisesRegex(
                AssertionError,
                "authoritative test attempted HTTP access"):
            requests.get("https://example.com")


if __name__ == "__main__":
    unittest.main()
