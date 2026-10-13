# Device-backed tests for ZIP-32 §6.1 seed_fingerprint binding.
#
# Pure-Python helper tests live in test_zcash_seed_fingerprint_helper.py
# (no common.KeepKeyTest dependency — runs offline).

import unittest
import pytest

import common

from keepkeylib import messages_zcash_pb2 as zcash_proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.zcash import calculate_seed_fingerprint

from test_msg_zcash_sign_pczt_device import (
    PADDING_BUNDLE, bundle_digest, fabricated_action, sign_kwargs,
)

# Hardened offset
H = 0x80000000


class TestMsgZcashSeedFingerprint(common.KeepKeyTest):
    """Binding behavior on a real device. Wipes/initializes the device."""

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.15.0")
        self.requires_message("ZcashGetOrchardFVK")

    def test_get_orchard_fvk_returns_seed_fingerprint(self):
        """ZcashGetOrchardFVK response now includes a 32-byte seed_fingerprint."""
        self.setup_mnemonic_allallall()

        fvk = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 0],
            account=0,
        )
        self.assertTrue(fvk.HasField("seed_fingerprint"))
        self.assertEqual(len(fvk.seed_fingerprint), 32)
        # Defensive: BLAKE2b should never produce all-zero output for a real seed
        self.assertNotEqual(fvk.seed_fingerprint, b"\x00" * 32)

    def test_fingerprint_stable_across_accounts(self):
        """Fingerprint is bound to the seed, not the account."""
        self.setup_mnemonic_allallall()

        fvk0 = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 0], account=0)
        fvk1 = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 1], account=1)
        self.assertEqual(fvk0.seed_fingerprint, fvk1.seed_fingerprint)

    # ── ZcashDisplayAddress: through client.zcash_display_address(...) ──
    # These tests exercise the new expected_seed_fingerprint kwarg on the
    # public client helper, not just raw protobuf.

    def test_display_address_helper_accepts_matching_fingerprint(self):
        """Helper passes expected_seed_fingerprint through; matching fp succeeds."""
        self.setup_mnemonic_allallall()

        fvk = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 0], account=0)

        resp = self.client.zcash_display_address(
            address_n=[H + 32, H + 133, H + 0],
            account=0,
            expected_seed_fingerprint=fvk.seed_fingerprint,
        )
        self.assertIsInstance(resp, zcash_proto.ZcashAddress)
        self.assertTrue(resp.HasField("seed_fingerprint"))
        self.assertEqual(resp.seed_fingerprint, fvk.seed_fingerprint)

    def test_display_address_helper_rejects_wrong_fingerprint(self):
        """Helper passes expected_seed_fingerprint through; wrong fp rejected."""
        self.setup_mnemonic_allallall()

        fvk = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 0], account=0)

        bad = bytearray(fvk.seed_fingerprint)
        bad[0] ^= 0xFF

        with pytest.raises(CallException):
            self.client.zcash_display_address(
                address_n=[H + 32, H + 133, H + 0],
                account=0,
                expected_seed_fingerprint=bytes(bad),
            )

    def test_display_address_helper_backward_compat(self):
        """Helper without expected_seed_fingerprint still works (existing flow)."""
        self.setup_mnemonic_allallall()

        fvk = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 0], account=0)

        resp = self.client.zcash_display_address(
            address_n=[H + 32, H + 133, H + 0],
            account=0,
        )
        self.assertIsInstance(resp, zcash_proto.ZcashAddress)
        # Device populates seed_fingerprint on responses regardless of request
        self.assertTrue(resp.HasField("seed_fingerprint"))
        self.assertEqual(resp.seed_fingerprint, fvk.seed_fingerprint)

    def test_device_fingerprint_matches_python_helper(self):
        """Cross-check: device-derived fingerprint == calculate_seed_fingerprint(seed)
        for the all-allallall mnemonic seed. Ties firmware C and python-keepkey
        helper to the same byte-for-byte output."""
        self.setup_mnemonic_allallall()

        fvk = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 0], account=0)

        # all-all-all mnemonic, empty passphrase, BIP-39 seed
        from mnemonic import Mnemonic
        seed = Mnemonic.to_seed("all all all all all all all all all all all all", "")
        expected_fp = calculate_seed_fingerprint(seed)
        self.assertEqual(fvk.seed_fingerprint, expected_fp)

    # ── ZcashSignPCZT: through client.zcash_sign_pczt(...) ──────────────

    def _signing_request(self):
        """A complete wallet spend accepted by the current firmware."""
        actions = [fabricated_action(v) for v in PADDING_BUNDLE]
        actions[1]['is_spend'] = False
        kwargs = sign_kwargs(actions, fee=10000, orchard_value_balance=10000,
                             total_amount=90000)
        kwargs['orchard_digest'] = bundle_digest(
            actions, False, 5, value_balance=10000)
        return kwargs

    def test_sign_pczt_helper_accepts_matching_fingerprint(self):
        """The same complete request signs with this seed's fingerprint."""
        self.setup_mnemonic_allallall()
        fvk = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H], account=0)
        result = self.client.zcash_sign_pczt(
            **self._signing_request(),
            expected_seed_fingerprint=fvk.seed_fingerprint,
        )
        self.assertIsInstance(result, zcash_proto.ZcashSignedPCZT)
        self.assertEqual(len(result.signatures), 1)
        self.assertEqual(len(result.signatures[0]), 64)

    def test_sign_pczt_helper_rejects_wrong_fingerprint(self):
        """A changed fingerprint alone causes the precise initial refusal."""
        self.setup_mnemonic_allallall()
        fvk = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H], account=0)
        wrong_fp = bytearray(fvk.seed_fingerprint)
        wrong_fp[0] ^= 0x01

        responses = []
        original = self.client.call_raw

        def capture(request):
            response = original(request)
            responses.append(response)
            return response

        self.client.call_raw = capture
        try:
            with pytest.raises(CallException) as caught:
                self.client.zcash_sign_pczt(
                    **self._signing_request(),
                    expected_seed_fingerprint=bytes(wrong_fp),
                )
        finally:
            self.client.call_raw = original

        self.assertEqual(caught.value.args[0], proto_types.Failure_Other)
        self.assertEqual(caught.value.args[1],
                         'Seed fingerprint mismatch — wrong device')
        self.assertFalse(any(isinstance(response, (
            zcash_proto.ZcashPCZTActionAck,
            zcash_proto.ZcashSignedPCZT,
            zcash_proto.ZcashTransparentSigned,
        )) for response in responses),
            'a mismatched seed must not start action streaming or release signatures')


if __name__ == '__main__':
    unittest.main()
