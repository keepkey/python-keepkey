"""Osmosis MsgSend signing — with the confirm-screen amount as the point.

Osmosis had NO device tests at all: the confirm screens that render amounts
were covered only by host-side unit tests of the formatter in isolation. That
matters more than it sounds, because 7.15.0 CHANGED how every Osmosis amount
is drawn.

Before, fsm_msg_osmosis.h rendered amounts with atof() + "%.6f". A float
carries ~7 significant decimal digits, so a large amount was displayed
ROUNDED on the very screen the user approves:

    123456789123456 uosmo  ->  shown as "123456792.000000 OSMO"
                               actual     123456789.123456 OSMO

The signature was over the correct amount either way — the lie was only on
the screen, which is the half a hardware wallet exists to get right. It now
formats with bn_format_uint64 (integer math, exact at any magnitude).

These tests are paired with SECTIONS entries carrying screenshot hints, so
the rendered frame is captured as evidence. A test asserting only "it signed"
cannot prove what the OLED drew.

pyk's osmosis_sign_tx currently implements osmosis-sdk/MsgSend only; the
delegate/undelegate/LP/swap/IBC screens share the same formatter but are not
reachable from here until the client learns those message types.
"""
import unittest
import common

from binascii import hexlify

from keepkeylib.tools import parse_path

# Osmosis uses the Cosmos coin type (118), not one of its own.
DEFAULT_BIP32_PATH = "m/44h/118h/0h/0/0"


def make_send(from_address, to_address, amount, denom='uosmo'):
    return {
        'type': 'osmosis-sdk/MsgSend',
        'value': {
            'from_address': from_address,
            'to_address': to_address,
            'amount': [{'denom': denom, 'amount': str(amount)}],
        },
    }


class TestMsgOsmosisSignTx(common.KeepKeyTest):

    def _address(self):
        """Ask the device for its own osmo1 address.

        Deliberately NOT a hardcoded constant: the firmware bech32-decodes
        to_address and refuses a bad checksum, so a literal invented by
        swapping a cosmos1 prefix for osmo1 fails with the opaque "Failed to
        include send message in transaction". Deriving it keeps the fixture
        honest and makes these self-sends.
        """
        return self.client.osmosis_get_address(
            address_n=parse_path(DEFAULT_BIP32_PATH)
        ).address

    def _sign(self, amount, denom='uosmo'):
        addr = self._address()
        return self.client.osmosis_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=16359,
            chain_id="osmosis-1",
            fee=800,
            gas=290000,
            msgs=[make_send(addr, addr, amount, denom)],
            memo="",
            sequence=17,
        )

    def test_osmosis_sign_tx(self):
        """Baseline: a whole-OSMO send signs and returns a well-formed
        secp256k1 signature + compressed pubkey."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        sig = self._sign(1500000)  # 1.500000 OSMO
        self.assertEqual(len(sig.signature), 64)
        self.assertEqual(len(sig.public_key), 33)
        self.assertIn(hexlify(sig.public_key)[:2], (b'02', b'03'))

    def test_osmosis_send_amount_beyond_float_precision(self):
        """THE regression. 123456789123456 uosmo needs 15 significant digits;
        a float holds ~7, so the old atof()+"%.6f" path drew
        "123456792.000000 OSMO" over a transaction that actually moves
        123456789.123456 OSMO. The captured frame is the proof — assert here
        only that the device signs it, and read the amount off the screenshot.
        """
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        sig = self._sign(123456789123456)
        self.assertEqual(len(sig.signature), 64)

    def test_osmosis_send_subunit_amount(self):
        """500 uosmo is 0.000500 OSMO — six decimal places, no integer part.
        The formatter must not collapse it to "0" or drop the tail."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        sig = self._sign(500)
        self.assertEqual(len(sig.signature), 64)

    def test_osmosis_send_unknown_denom_shown_raw(self):
        """Only uosmo is scaled. The device does not know an arbitrary denom's
        precision, so it shows the base-unit integer verbatim rather than
        guessing a decimal point — guessing is how a 1000x display error
        happens."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        sig = self._sign(1500000, denom='uatom')
        self.assertEqual(len(sig.signature), 64)

    def test_osmosis_amount_is_committed_to_the_signature(self):
        """Guards the pairing between what is shown and what is signed: two
        sends differing ONLY in amount must produce different signatures. If
        they matched, the amount would not be in the digest and the confirm
        screen would be decorative."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        a = self._sign(1500000)
        b = self._sign(1500001)
        self.assertNotEqual(hexlify(a.signature), hexlify(b.signature))
        # Same key throughout — only the message differed.
        self.assertEqual(hexlify(a.public_key), hexlify(b.public_key))

    def test_osmosis_signing_is_deterministic(self):
        """RFC6979: identical input must yield an identical signature. A
        mismatch here means nonce generation is not deterministic, which is a
        key-recovery risk long before it is a display problem."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        first = self._sign(1500000)
        second = self._sign(1500000)
        self.assertEqual(hexlify(first.signature), hexlify(second.signature))


if __name__ == '__main__':
    unittest.main()
