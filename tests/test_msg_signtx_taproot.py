# This file is part of the KeepKey project.
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import common
import unittest

from binascii import hexlify, unhexlify

from common import KeepKeyTest
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from keepkeylib.tx_api import TxApiBitcoin



# Synthetic prev tx paying 100000 sat to the BIP-86 first receiving address of
# the "abandon abandon ... about" mnemonic
# (bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr).
# The fixture lives in tests/txcache and was produced together with the
# expected witness below by an independent Python implementation of
# BIP-340/341, keyed from BIP-86's own published xprv.
PREV_TXID = "6e32033911982f7550ab1d26232adfd08711293e15085f77cd27628be0a6ee37"
IN_AMOUNT = 100000
OUT_AMOUNT = 90000
OUT_ADDRESS = "1BitcoinEaterAddressDontSendf59kuE"

EXPECTED_WITNESS = (
    "afe221b16d648a1ad7329f9765930732380cc67765bd73af7ce13b5991146851"
    "2d9ee77e34af56fe1f59f98372011f7cb400ced614d808c690c5ba907fb62de9"
)

EXPECTED_CHANGE_WITNESS = (
    "e3c44408fe61256ad406733f100f1ee856eb31854335efa59e60a61ea5d41ab"
    "341802f0cccb55f644042a1ab390f0a406b9d3efe3996d05442b4ee43d5355eab"
)
EXPECTED_CHANGE_SCRIPT = (
    "5120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc"
)

MIXED_PREV_TXID = (
    "3e1fdf082678a8a2f378995ffc0e4f853942c55c4ddbc2771b348413eeeca9a4"
)
EXPECTED_MIXED_WITNESS = (
    "b596e1bbefb855af9852942797075d4f452b2d186cb17a76226892334a497a62"
    "adb9a02f7c1b4573e4d48b92e2307bb0b2282c97e2c5350bb3c21619fab855a2"
)


class TestMsgSigntxTaproot(KeepKeyTest):

    def test_send_p2tr(self):
        """Spend a P2TR input and compare the witness byte for byte.

        BIP-340 signing is deterministic given aux_rand, and the firmware
        signs with an all-zero aux, so this is an equality check against a
        signature computed independently of the firmware -- not a round trip
        through our own verifier, which would pass even if the device
        committed to the wrong transaction.
        """
        self.requires_taproot()
        self.setup_mnemonic_abandon()
        self.client.set_tx_api(TxApiBitcoin)

        inp1 = proto_types.TxInputType(
            address_n=parse_path("86'/0'/0'/0/0"),
            amount=IN_AMOUNT,
            prev_hash=unhexlify(PREV_TXID),
            prev_index=0,
            script_type=proto_types.SPENDTAPROOT,
        )
        out1 = proto_types.TxOutputType(
            address=OUT_ADDRESS,
            amount=OUT_AMOUNT,
            script_type=proto_types.PAYTOADDRESS,
        )

        (signatures, _) = self.client.sign_tx("Bitcoin", [inp1], [out1])

        self.assertEqual(len(signatures), 1)
        self.assertEqual(hexlify(signatures[0]).decode(), EXPECTED_WITNESS)

    def test_send_p2tr_with_change(self):
        """P2TR change is device-derived and omitted from recipient prompts."""
        self.requires_taproot()
        self.setup_mnemonic_abandon()
        self.client.set_tx_api(TxApiBitcoin)

        inp1 = proto_types.TxInputType(
            address_n=parse_path("86'/0'/0'/0/0"),
            amount=IN_AMOUNT,
            prev_hash=unhexlify(PREV_TXID),
            prev_index=0,
            script_type=proto_types.SPENDTAPROOT,
        )
        recipient = proto_types.TxOutputType(
            address=OUT_ADDRESS,
            amount=50000,
            script_type=proto_types.PAYTOADDRESS,
        )
        change = proto_types.TxOutputType(
            address_n=parse_path("86'/0'/0'/1/0"),
            amount=40000,
            script_type=proto_types.PAYTOTAPROOT,
        )

        (signatures, serialized) = self.client.sign_tx(
            "Bitcoin", [inp1], [recipient, change])

        self.assertEqual(hexlify(signatures[0]).decode(),
                         EXPECTED_CHANGE_WITNESS)
        self.assertIn(unhexlify(EXPECTED_CHANGE_SCRIPT), serialized)

    def test_send_mixed_p2tr_and_legacy(self):
        """A P2TR signature commits to the legacy input's real prevout."""
        self.requires_taproot()
        self.setup_mnemonic_abandon()
        self.client.set_tx_api(TxApiBitcoin)

        taproot = proto_types.TxInputType(
            address_n=parse_path("86'/0'/0'/0/0"),
            amount=100000,
            prev_hash=unhexlify(MIXED_PREV_TXID),
            prev_index=0,
            script_type=proto_types.SPENDTAPROOT,
        )
        legacy = proto_types.TxInputType(
            address_n=parse_path("44'/0'/0'/0/0"),
            amount=50000,
            prev_hash=unhexlify(MIXED_PREV_TXID),
            prev_index=1,
            script_type=proto_types.SPENDADDRESS,
        )
        recipient = proto_types.TxOutputType(
            address=OUT_ADDRESS,
            amount=140000,
            script_type=proto_types.PAYTOADDRESS,
        )

        (signatures, _) = self.client.sign_tx(
            "Bitcoin", [taproot, legacy], [recipient])

        self.assertEqual(len(signatures), 2)
        self.assertEqual(hexlify(signatures[0]).decode(),
                         EXPECTED_MIXED_WITNESS)
        self.assertTrue(signatures[1])

    def test_mixed_p2tr_requires_every_input_amount(self):
        """Fail closed instead of signing an incomplete BIP-341 commitment."""
        self.requires_taproot()
        self.setup_mnemonic_abandon()
        self.client.set_tx_api(TxApiBitcoin)

        taproot = proto_types.TxInputType(
            address_n=parse_path("86'/0'/0'/0/0"),
            amount=100000,
            prev_hash=unhexlify(MIXED_PREV_TXID),
            prev_index=0,
            script_type=proto_types.SPENDTAPROOT,
        )
        incomplete_legacy = proto_types.TxInputType(
            address_n=parse_path("44'/0'/0'/0/0"),
            prev_hash=unhexlify(MIXED_PREV_TXID),
            prev_index=1,
            script_type=proto_types.SPENDADDRESS,
        )
        recipient = proto_types.TxOutputType(
            address=OUT_ADDRESS,
            amount=140000,
            script_type=proto_types.PAYTOADDRESS,
        )

        with self.assertRaisesRegex(
                CallException,
                "Taproot transaction input without amount"):
            self.client.sign_tx(
                "Bitcoin", [taproot, incomplete_legacy], [recipient])


if __name__ == '__main__':
    unittest.main()
