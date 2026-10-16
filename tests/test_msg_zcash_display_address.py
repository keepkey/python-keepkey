# Zcash unified address display/verification tests.
#
# Tests ZcashDisplayAddress message which verifies that a unified address
# contains an Orchard receiver derived from this device's seed.
#
# The device derives its own Orchard unified address from address_n/account
# and returns it (ZcashAddress) after on-screen confirmation. It can also
# verify an expected_seed_fingerprint to pin the attestation to this device.

import unittest
import common

from keepkeylib import messages_zcash_pb2 as zcash_proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

# Hardened offset
H = 0x80000000


class TestMsgZcashDisplayAddress(common.KeepKeyTest):
    """Test Zcash unified address display and verification."""

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.15.0")
        self.requires_message("ZcashDisplayAddress")

    def test_zcash_display_address_basic(self):
        """Verify a unified address using FVK components from the device."""
        self.setup_mnemonic_allallall()

        # First get the FVK from the device
        fvk_resp = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 0],
            account=0,
        )
        self.assertIsNotNone(fvk_resp.ak)
        self.assertIsNotNone(fvk_resp.nk)
        self.assertIsNotNone(fvk_resp.rivk)

        # The device derives its OWN unified address from address_n/account
        # (the host does not supply address/FVK — those fields are reserved).
        # No message returns the UA without displaying it and there is no
        # independent vector, so this proves only that the screen shows all of
        # the address the device returns.
        resp = self.assert_shows_address(
            lambda: self.client.call(
                zcash_proto.ZcashDisplayAddress(
                    address_n=[H + 32, H + 133, H + 0],
                    account=0,
                )
            ), lambda resp: resp.address)

        # Device returns the confirmed UA bound to its seed.
        self.assertIsInstance(resp, zcash_proto.ZcashAddress)
        self.assertTrue(resp.address.startswith("u1"))
        self.assertTrue(resp.HasField("seed_fingerprint"))
        self.assertEqual(len(resp.seed_fingerprint), 32)

    def test_zcash_display_address_bad_path_rejected(self):
        """A path that is neither m/32'/133'/account' nor an explicit account
        is rejected with a SyntaxError (no silent wrong-account derivation)."""
        self.setup_mnemonic_allallall()

        # Without account=, the path itself selects the approved account.
        valid = self.client.zcash_display_address(
            address_n=[H + 32, H + 133, H + 0])
        explicit = self.client.zcash_display_address(account=0)
        self.assertIsInstance(valid, zcash_proto.ZcashAddress)
        self.assertEqual(valid.address, explicit.address)

        with self.assertRaises(CallException) as caught:
            self.client.call(
                zcash_proto.ZcashDisplayAddress(
                    address_n=[H + 44, H + 133, H + 0],  # wrong purpose (44')
                )
            )
        self.assertEqual(caught.exception.args[0], proto_types.Failure_SyntaxError)
        self.assertEqual(caught.exception.args[1],
                         "Require account field or ZIP-32 path m/32'/133'/account'")


if __name__ == '__main__':
    unittest.main()
