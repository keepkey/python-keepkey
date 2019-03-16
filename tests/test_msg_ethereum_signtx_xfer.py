# This file is part of the TREZOR project.
#
# Copyright (C) 2012-2016 Marek Palatinus <slush@satoshilabs.com>
# Copyright (C) 2012-2016 Pavol Rusnak <stick@satoshilabs.com>
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.
#
# The script has been modified for KeepKey Device.

import unittest
import common
import binascii
import struct

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian

class TestMsgEthereumSigntx(common.KeepKeyTest):
    def test_ethereum_tx_xfer_acc1(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)

        sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            value=1234567890,
            to_n=[0x8000002c, 0x8000003c, 0x80000001, 0, 0],
            address_type=proto_types.TRANSFER,
            chain_id=1,
            )

        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), '72b87b41a92dbad6dffcd7f9441102029adad4864291f867726abaaa3572dee7')
        self.assertEqual(binascii.hexlify(sig_s), '26814243d29bea4dddaef6da5b8af6836e499c2c7ccaa0877204f5465edc8290')
        self.assertEqual(binascii.hexlify(hash), 'f8cb6ffe80afaa7f651e66933e62667c3250a0168fcc29b1f46529511bf53fe6')
        self.assertEqual(binascii.hexlify(signature_der), '3044022072b87b41a92dbad6dffcd7f9441102029adad4864291f867726abaaa3572dee7022026814243d29bea4dddaef6da5b8af6836e499c2c7ccaa0877204f5465edc8290')

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_tx_xfer_acc2(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)

        sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            value=1234567890,
            to_n=[0x8000002c, 0x8000003c, 0x80000002, 0, 0],
            address_type=proto_types.TRANSFER,
            chain_id=1,
            )

        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), '24b978c585e12ef9bb816105718adcdd11824262919489c22b63d9c71873535f')
        self.assertEqual(binascii.hexlify(sig_s), '079f2a155bec09d7a7e23189aa5f6a4305df839605eed23a720486a919306259')
        self.assertEqual(binascii.hexlify(hash), '9d78419c4bbe60057b4ce5e3b8115b8a486589890dc9751b87c2bece0ed2f4a1')
        self.assertEqual(binascii.hexlify(signature_der), '3044022024b978c585e12ef9bb816105718adcdd11824262919489c22b63d9c71873535f0220079f2a155bec09d7a7e23189aa5f6a4305df839605eed23a720486a919306259')

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_xfer_account_path_error_0(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)

        sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            value=1234567890,
            to_n=[0x8000002c, 0x8000003c, 0x80000002, 0, 0],
            address_type=proto_types.TRANSFER,
            chain_id=1,
            )

        try:
            signature_der = self.client.ethereum_sign_tx(
                n=[0, 0],
                nonce=0,
                gas_price=20,
                gas_limit=20,
                to_n=[0x8000002c, 0x8000003c, 2, 0, 0],
                #error here                  -^-
                value=1234567890,
                address_type=proto_types.TRANSFER,
                chain_id=1,
                )
        except CallException as e:
            self.assertEndsWith(e.args[1], 'Failed to compile output')
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_xfer_account_path_error_1(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)

        # Really we should warn instead in this case, and show:
        #     "Transfer 0.001234 ETH to m/44'/60'/1'/0/0/"
        # on the device, rathern than erroring out.

        try:
            signature_der = self.client.ethereum_sign_tx(
                n=[0, 0],
                nonce=0,
                gas_price=20,
                gas_limit=20,
                to_n=[0x8000002c, 0x8000003c, 1, 0, 0],
                                 #error here -^-
                value=1234000000000000,
                address_type=proto_types.TRANSFER,
                chain_id=1,
                )
        except CallException as e:
            self.assertEndsWith(e.args[1], 'Failed to compile output')
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_xfer_account_path_error_2(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)


        try:
            signature_der = self.client.ethereum_sign_tx(
                n=[0, 0],
                nonce=0,
                gas_price=20,
                gas_limit=20,
                to_n=[0x8000002c, 0x8000003c, 1, 1, 0],
                                  #error here      -^-
                value=1234567890,
                address_type=proto_types.TRANSFER,
                chain_id=1,
                )
        except CallException as e:
            self.assertEndsWith(e.args[1], 'Failed to compile output')
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_xfer_account_path_error_3(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)

        try:
            signature_der = self.client.ethereum_sign_tx(
                n=[0, 0],
                nonce=0,
                gas_price=20,
                gas_limit=20,
                to_n=[0x8000002c, 0x8000003c, 1, 0, 1],
                                    #error here    -^-
                value=1234567890,
                address_type=proto_types.TRANSFER,
                chain_id=1,
                )
        except CallException as e:
            self.assertEndsWith(e.args[1], 'Failed to compile output')
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

if __name__ == '__main__':
    unittest.main()
