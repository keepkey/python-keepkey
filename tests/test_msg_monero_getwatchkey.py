"""Monero view-key export (MoneroGetWatchKey): fresh consent every time, and
the key and address match Monero Core fixtures (monero_fixtures.py)."""

import unittest

import common
import monero_fixtures as xmr
from keepkeylib import messages_monero_pb2 as monero_proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import CallException

WARNING = ("This computer can see incoming payments for all subaddresses on "
           "all networks at this path. It cannot spend.")


class TestMsgMoneroGetWatchKey(common.KeepKeyTest):

    def setUp(self):
        super(TestMsgMoneroGetWatchKey, self).setUp()
        self.requires_firmware(common.CAPABILITIES_SINCE)
        self.requires_fullFeature()
        self.requires_release_capability('monero-signing')

    def test_view_key_matches_monero_core(self):
        for wallet, setup in (('alcohol', self.setup_mnemonic_nopin_nopassphrase),
                              ('abandon', self.setup_mnemonic_abandon)):
            self.client.wipe_device()
            setup()
            for account in (0, 1):
                for major in (0, 1):
                    with self.subTest(wallet=wallet, account=account, major=major):
                        resp = self.client.monero_get_watch_key(
                            xmr.path(account), account=major)
                        self.assertEqual(resp.watch_key.hex(),
                                         xmr.VIEW_KEYS[(wallet, account)])
                        self.assertEqual(resp.address.decode(),
                                         xmr.ADDRESSES[(wallet, account)][(major, 0)])

    def test_consent_shows_warning_and_full_address(self):
        self.setup_mnemonic_nopin_nopassphrase()
        expected = xmr.ADDRESSES[('alcohol', 0)][(1, 0)]
        with xmr.Screens(self.client) as screens:
            resp = self.client.monero_get_watch_key(xmr.path(0), account=1)
        self.assertEqual(resp.address.decode(), expected)
        self.assertTrue(screens.shown("Monero Mainnet"))
        self.assertTrue(screens.shown(WARNING))
        self.assertTrue(screens.shown(expected))
        self.assertTrue(screens.drawn(expected))
        titles = [title for title, _ in screens.confirmations()]
        self.assertEqual(titles, ['Export view key', 'Selected address'])

    def test_testnet_subaddress_exports_the_same_path_view_key(self):
        self.setup_mnemonic_nopin_nopassphrase()
        path = xmr.path(0)
        main = self.client.monero_get_watch_key(path)
        testnet = monero_proto.MONERO_NETWORK_TESTNET
        selected = self.client.monero_get_address(path, network=testnet, account=1)
        with xmr.Screens(self.client) as screens:
            other = self.client.monero_get_watch_key(path, network=testnet, account=1)
        self.assertEqual(other.watch_key, main.watch_key)
        self.assertEqual(other.address, selected)
        self.assertNotEqual(other.address, main.address)
        first, second = screens.confirmations()
        self.assertEqual(first[0], "Export view key")
        self.assertIn("Testnet", first[1])
        self.assertIn("44'/128'/0'", first[1])
        self.assertIn(WARNING, first[1])
        self.assertEqual(second, ("Selected address", selected.decode()))

    def test_every_request_asks_again(self):
        self.setup_mnemonic_nopin_nopassphrase()
        counts = []
        for _ in range(2):
            with xmr.Screens(self.client) as screens:
                self.client.monero_get_watch_key(xmr.path(0))
            counts.append(len(screens.layouts))
        self.assertGreaterEqual(counts[0], 2)
        self.assertEqual(counts[0], counts[1])

    def test_cancel_on_any_screen_exports_nothing(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with xmr.Screens(self.client) as screens:
            self.client.monero_get_watch_key(xmr.path(0))
        total = len(screens.layouts)
        for refused in range(total):
            answers = [True] * refused + [False]
            with self.subTest(screen=refused), xmr.Screens(self.client, answers):
                with self.assertRaises(CallException) as caught:
                    self.client.monero_get_watch_key(xmr.path(0))
                self.assertEqual(caught.exception.args[0],
                                 proto_types.Failure_ActionCancelled)

    def test_invalid_requests_are_refused(self):
        self.setup_mnemonic_nopin_nopassphrase()
        for fields in (dict(address_n=[xmr.H + 44, xmr.H + 128]),
                       dict(address_n=[xmr.H + 44, xmr.H + 128, 0]),
                       dict(address_n=xmr.path(0), network_type=None)):
            with self.subTest(fields=fields):
                msg = monero_proto.MoneroGetWatchKey(address_n=fields['address_n'])
                if 'network_type' in fields:
                    msg.MergeFromString(xmr.UNKNOWN_NETWORK_2)
                with self.assertRaises(CallException) as caught:
                    self.client.call(msg)
                self.assertEqual(caught.exception.args[0],
                                 proto_types.Failure_SyntaxError)


if __name__ == '__main__':
    unittest.main()
