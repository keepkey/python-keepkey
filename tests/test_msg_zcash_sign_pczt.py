# Zcash Orchard PCZT signing protocol tests.
#
# Tests the ZcashSignPCZT / ZcashPCZTAction / ZcashPCZTActionAck flow
# via the zcash_sign_pczt() client helper against the emulator.

import unittest
import common
import os


class TestZcashSignPCZT(common.KeepKeyTest):
    """Test Zcash Orchard PCZT signing protocol."""

    def _make_action(self, index, sighash=None, value=10000, is_spend=True):
        """Build a minimal action dict for testing."""
        action = {
            'alpha': os.urandom(32),
            'value': value,
            'is_spend': is_spend,
        }
        if sighash is not None:
            action['sighash'] = sighash
        return action

    def test_single_action_legacy_sighash(self):
        """Single-action signing with host-provided sighash (legacy mode)."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        sighash = b'\xab' * 32

        actions = [self._make_action(0, sighash=sighash)]

        resp = self.client.zcash_sign_pczt(
            address_n=address_n,
            actions=actions,
            total_amount=10000,
            fee=1000,
        )

        self.assertEqual(len(resp.signatures), 1)
        self.assertEqual(len(resp.signatures[0]), 64)

    def test_multi_action_legacy_sighash(self):
        """Multi-action signing with host-provided sighash."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        sighash = b'\xcd' * 32

        actions = [
            self._make_action(0, sighash=sighash, value=5000),
            self._make_action(1, sighash=sighash, value=5000),
        ]

        resp = self.client.zcash_sign_pczt(
            address_n=address_n,
            actions=actions,
            total_amount=10000,
            fee=1000,
        )

        self.assertEqual(len(resp.signatures), 2)
        for sig in resp.signatures:
            self.assertEqual(len(sig), 64)

    def test_signatures_are_64_bytes(self):
        """Every returned signature must be exactly 64 bytes."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        sighash = b'\xef' * 32

        actions = [self._make_action(i, sighash=sighash) for i in range(3)]

        resp = self.client.zcash_sign_pczt(
            address_n=address_n,
            actions=actions,
            total_amount=30000,
            fee=1000,
        )

        self.assertEqual(len(resp.signatures), 3)
        for i, sig in enumerate(resp.signatures):
            self.assertEqual(len(sig), 64,
                             "Signature %d must be 64 bytes, got %d" % (i, len(sig)))
            self.assertTrue(sig != b'\x00' * 64,
                            "Signature %d must be nonzero" % i)

    def test_different_accounts_different_signatures(self):
        """Same transaction with different accounts must produce different sigs."""
        self.setup_mnemonic_allallall()

        sighash = b'\x11' * 32
        alpha = b'\x01' * 31 + b'\x00'

        actions_0 = [{'alpha': alpha, 'sighash': sighash,
                      'value': 10000, 'is_spend': True}]
        actions_1 = [{'alpha': alpha, 'sighash': sighash,
                      'value': 10000, 'is_spend': True}]

        resp0 = self.client.zcash_sign_pczt(
            address_n=[0x80000000 + 32, 0x80000000 + 133, 0x80000000],
            actions=actions_0,
            total_amount=10000,
            fee=1000,
        )
        resp1 = self.client.zcash_sign_pczt(
            address_n=[0x80000000 + 32, 0x80000000 + 133, 0x80000001],
            actions=actions_1,
            total_amount=10000,
            fee=1000,
        )

        self.assertTrue(resp0.signatures[0] != resp1.signatures[0],
                        "Different accounts must produce different signatures")


if __name__ == '__main__':
    unittest.main()
