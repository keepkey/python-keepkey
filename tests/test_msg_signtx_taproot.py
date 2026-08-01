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


if __name__ == '__main__':
    unittest.main()
