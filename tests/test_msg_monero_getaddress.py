"""Monero addresses and subaddresses (MoneroGetAddress), checked against
Monero Core fixtures (monero_fixtures.py)."""

import unittest

import common
import monero_fixtures as xmr
from keepkeylib import messages_monero_pb2 as monero_proto
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import CallException


class TestMsgMoneroGetAddress(common.KeepKeyTest):

    def setUp(self):
        super(TestMsgMoneroGetAddress, self).setUp()
        self.requires_firmware(common.CAPABILITIES_SINCE)
        self.requires_fullFeature()
        self.requires_release_capability('monero-signing')

    def check_wallet(self, wallet):
        for account in (0, 1):
            for (major, minor), expected in sorted(xmr.ADDRESSES[(wallet, account)].items()):
                with self.subTest(wallet=wallet, account=account, sub=(major, minor)):
                    address = self.client.monero_get_address(
                        xmr.path(account), account=major, minor=minor)
                    self.assertEqual(address.decode(), expected)

    def test_addresses_match_monero_core(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.check_wallet('alcohol')
        self.client.wipe_device()
        self.setup_mnemonic_abandon()
        self.check_wallet('abandon')

    def test_shows_the_full_address(self):
        self.setup_mnemonic_nopin_nopassphrase()
        for sub in ((0, 0), (0, 1), (100, 100)):
            expected = xmr.ADDRESSES[('alcohol', 0)][sub]
            with self.subTest(sub=sub), xmr.Screens(self.client) as screens:
                address = self.client.monero_get_address(
                    xmr.path(0), account=sub[0], minor=sub[1], show_display=True)
                self.assertEqual(address.decode(), expected)
                # Derivation, address (complete, never shortened), QR
                self.assertEqual(len(screens.layouts), 3)
                self.assertTrue(screens.shown(expected))
                self.assertTrue(screens.drawn(expected))
                self.assertTrue(screens.shown("Monero Mainnet"))
                if sub != (0, 0):
                    self.assertTrue(screens.shown("Subaddress %d/%d" % sub))

    def test_cancel_on_any_screen(self):
        self.setup_mnemonic_nopin_nopassphrase()
        for refused in range(3):
            answers = [True] * refused + [False]
            with self.subTest(screen=refused), xmr.Screens(self.client, answers) as screens:
                with self.assertRaises(CallException) as caught:
                    self.client.monero_get_address(xmr.path(0), show_display=True)
                self.assertEqual(caught.exception.args[0],
                                 proto_types.Failure_ActionCancelled)
                self.assertEqual(len(screens.layouts), refused + 1)

    def test_networks_use_their_prefixes(self):
        self.setup_mnemonic_nopin_nopassphrase()
        # The leading base58 digits of each network's address prefixes
        prefixes = {0: ('4', '8'), 1: ('9A', 'B'), 2: ('5', '7')}
        for network, (primary, sub) in prefixes.items():
            with self.subTest(network=network):
                main = self.client.monero_get_address(xmr.path(0), network=network)
                subaddress = self.client.monero_get_address(
                    xmr.path(0), network=network, minor=1)
                self.assertEqual(len(main), 95)
                self.assertEqual(len(subaddress), 95)
                self.assertIn(main[:1].decode(), primary)
                self.assertIn(subaddress[:1].decode(), sub)

    def test_testnet_is_named_on_the_screen(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with xmr.Screens(self.client) as screens:
            self.client.monero_get_address(xmr.path(0), network=1, show_display=True)
        self.assertTrue(screens.shown("Monero Testnet"))

    def test_invalid_requests_are_refused(self):
        self.setup_mnemonic_nopin_nopassphrase()
        bad = [
            dict(address_n=[xmr.H + 44, xmr.H + 128]),
            dict(address_n=xmr.path(0) + [0]),
            dict(address_n=[xmr.H + 44, xmr.H + 128, 0]),
            dict(address_n=[xmr.H + 44, xmr.H + 133, xmr.H]),
            dict(address_n=xmr.path(0), payment_id=b'\x01' * 8),
            dict(address_n=xmr.path(0), network_type=None),
        ]
        for fields in bad:
            with self.subTest(fields=fields):
                msg = monero_proto.MoneroGetAddress(
                    **{k: v for k, v in fields.items() if v is not None})
                if 'network_type' in fields:
                    msg.MergeFromString(xmr.UNKNOWN_NETWORK_3)
                with self.assertRaises(CallException) as caught:
                    self.client.call(msg)
                self.assertEqual(caught.exception.args[0],
                                 proto_types.Failure_SyntaxError)

    def test_pin_is_required(self):
        self.setup_mnemonic_pin_nopassphrase()
        self.client.clear_session()
        with self.client:
            self.client.set_expected_responses([proto.PinMatrixRequest(),
                                                monero_proto.MoneroAddress()])
            address = self.client.monero_get_address(xmr.path(0))
        self.assertEqual(address.decode(), xmr.ADDRESSES[('alcohol', 0)][(0, 0)])

    def test_passphrase_changes_the_wallet(self):
        self.setup_mnemonic_pin_passphrase()
        self.client.set_passphrase('TREZOR')
        address = self.client.monero_get_address(xmr.path(0))
        self.assertEqual(len(address), 95)
        self.assertNotEqual(address.decode(), xmr.ADDRESSES[('alcohol', 0)][(0, 0)])


if __name__ == '__main__':
    unittest.main()
