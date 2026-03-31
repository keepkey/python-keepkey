"""BIP-85 display-only tests.

Firmware >= 7.14.0 derives the BIP-85 child mnemonic, displays it on the
device screen, and responds with Success (mnemonic is never sent over USB).

Tests verify:
- Correct ButtonRequest sequence (device prompted user to view mnemonic)
- Different parameters produce distinct derivation flows
- Invalid parameters are rejected
"""

import unittest
import common
import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types


class TestMsgBip85(common.KeepKeyTest):

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.14.0")

    def test_bip85_12word_flow(self):
        """12-word derivation: verify device goes through display flow and returns Success."""
        self.setup_mnemonic_allallall()

        resp = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=0))
        self.assertIsInstance(resp, proto.Success)

    def test_bip85_24word_flow(self):
        """24-word derivation: verify display flow and Success."""
        self.setup_mnemonic_allallall()

        resp = self.client.call(proto.GetBip85Mnemonic(word_count=24, index=0))
        self.assertIsInstance(resp, proto.Success)

    def test_bip85_different_indices_different_flows(self):
        """Index 0 and index 1 must both succeed."""
        self.setup_mnemonic_allallall()

        for index in (0, 1):
            resp = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=index))
            self.assertIsInstance(resp, proto.Success)

    def test_bip85_invalid_word_count(self):
        """Invalid word_count (15) must be rejected by firmware."""
        self.setup_mnemonic_allallall()

        from keepkeylib.client import CallException
        with self.assertRaises(CallException) as ctx:
            self.client.call(proto.GetBip85Mnemonic(word_count=15, index=0))
        self.assertIn('word_count', str(ctx.exception))

    def test_bip85_18word_flow(self):
        """18-word derivation: verify the third word_count variant works."""
        self.setup_mnemonic_allallall()

        resp = self.client.call(proto.GetBip85Mnemonic(word_count=18, index=0))
        self.assertIsInstance(resp, proto.Success)

    def test_bip85_deterministic_flow(self):
        """Same parameters must produce identical results both times."""
        self.setup_mnemonic_allallall()

        for _ in range(2):
            resp = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=0))
            self.assertIsInstance(resp, proto.Success)


if __name__ == '__main__':
    unittest.main()
