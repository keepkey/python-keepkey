# Pure-Python tests for the ZIP-32 §6.1 seed fingerprint helper.
#
# This module deliberately does NOT import `common`, `keepkeylib.transport`,
# or any protobuf bindings — those would require a device/emulator to be
# wired up. Tests here run on any plain dev box:
#
#   pytest tests/test_zcash_seed_fingerprint_helper.py

import unittest

from keepkeylib.zcash import calculate_seed_fingerprint


class TestSeedFingerprintHelper(unittest.TestCase):

    def test_reference_vector(self):
        """Cross-check against keystone3-firmware
        rust/keystore/src/algorithms/zcash/mod.rs::test_keystore_derive_zcash_ufvk:

            seed = 000102...1f (32 bytes)
            fp   = deff604c246710f7176dead02aa746f2fd8d5389f7072556dcb555fdbe5e3ae3
        """
        seed = bytes(range(32))
        fp = calculate_seed_fingerprint(seed)
        self.assertEqual(
            fp.hex(),
            "deff604c246710f7176dead02aa746f2fd8d5389f7072556dcb555fdbe5e3ae3",
        )

    def test_rejects_trivial_seeds(self):
        with self.assertRaises(ValueError):
            calculate_seed_fingerprint(b"\x00" * 32)
        with self.assertRaises(ValueError):
            calculate_seed_fingerprint(b"\xff" * 32)

    def test_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            calculate_seed_fingerprint(b"\x01" * 31)  # too short
        with self.assertRaises(ValueError):
            calculate_seed_fingerprint(b"\x01" * 253)  # too long

    def test_length_prefix_domain_separation(self):
        """Two seeds where one is a prefix of the other must produce
        distinct fingerprints (this is what the I2LEBSP_8(len) prefix buys us)."""
        seed_short = bytes(range(32))
        seed_long = bytes(range(33))
        self.assertNotEqual(
            calculate_seed_fingerprint(seed_short),
            calculate_seed_fingerprint(seed_long),
        )


if __name__ == '__main__':
    unittest.main()
