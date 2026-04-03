# Zcash unified address display/verification tests.
#
# Tests ZcashDisplayAddress message which verifies that a unified address
# contains an Orchard receiver derived from this device's seed.
#
# The host provides the unified address + FVK components (ak, nk, rivk).
# The device re-derives its own Orchard keys and compares them.

import unittest
import common

from keepkeylib import messages_zcash_pb2 as zcash_proto
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

        # Use a placeholder unified address -- real address construction
        # requires librustzcash (host-side). The firmware verifies the FVK
        # matches its own derivation, not the address encoding.
        # For a real test, construct a proper unified address externally.
        resp = self.client.call(
            zcash_proto.ZcashDisplayAddress(
                address_n=[H + 32, H + 133, H + 0],
                account=0,
                address="u1placeholder",
                ak=fvk_resp.ak,
                nk=fvk_resp.nk,
                rivk=fvk_resp.rivk,
            )
        )

        # Device should verify FVK matches and return the address
        self.assertIsInstance(resp, zcash_proto.ZcashAddress)

    def test_zcash_display_address_wrong_fvk_rejected(self):
        """Device rejects address when FVK doesn't match its own derivation."""
        self.setup_mnemonic_allallall()

        import pytest
        from keepkeylib.client import CallException

        # Send bogus FVK -- device should reject
        with pytest.raises(CallException):
            self.client.call(
                zcash_proto.ZcashDisplayAddress(
                    address_n=[H + 32, H + 133, H + 0],
                    account=0,
                    address="u1placeholder",
                    ak=b'\x00' * 32,
                    nk=b'\x00' * 32,
                    rivk=b'\x00' * 32,
                )
            )


if __name__ == '__main__':
    unittest.main()
