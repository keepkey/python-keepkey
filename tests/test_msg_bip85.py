"""BIP-85 display-only tests.

Firmware >= 7.14.0 derives the BIP-85 child mnemonic, displays it on the
device screen, and responds with Success (mnemonic is never sent over USB).
"""

import unittest
import common
import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types


class TestMsgBip85(common.KeepKeyTest):

    def test_bip85_12word(self):
        """Derive a 12-word child mnemonic at index 0 — device displays, returns Success."""
        self.requires_firmware("7.14.0")
        self.setup_mnemonic_allallall()

        resp = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=0))

        # Firmware display-only mode returns Success
        self.assertTrue(
            isinstance(resp, proto.Success),
            "Expected Success response, got %s" % type(resp).__name__
        )

    def test_bip85_24word(self):
        """Derive a 24-word child mnemonic at index 0 — device displays, returns Success."""
        self.requires_firmware("7.14.0")
        self.setup_mnemonic_allallall()

        resp = self.client.call(proto.GetBip85Mnemonic(word_count=24, index=0))

        self.assertTrue(
            isinstance(resp, proto.Success),
            "Expected Success response, got %s" % type(resp).__name__
        )

    def test_bip85_different_indices(self):
        """Index 0 and index 1 both succeed (different seeds displayed on device)."""
        self.requires_firmware("7.14.0")
        self.setup_mnemonic_allallall()

        resp0 = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=0))
        resp1 = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=1))

        self.assertTrue(
            isinstance(resp0, proto.Success),
            "Expected Success for index 0, got %s" % type(resp0).__name__
        )
        self.assertTrue(
            isinstance(resp1, proto.Success),
            "Expected Success for index 1, got %s" % type(resp1).__name__
        )

    def test_bip85_deterministic(self):
        """Same parameters succeed consistently (determinism verified by device display)."""
        self.requires_firmware("7.14.0")
        self.setup_mnemonic_allallall()

        resp1 = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=0))
        resp2 = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=0))

        self.assertTrue(
            isinstance(resp1, proto.Success),
            "Expected Success (call 1), got %s" % type(resp1).__name__
        )
        self.assertTrue(
            isinstance(resp2, proto.Success),
            "Expected Success (call 2), got %s" % type(resp2).__name__
        )


if __name__ == '__main__':
    unittest.main()
