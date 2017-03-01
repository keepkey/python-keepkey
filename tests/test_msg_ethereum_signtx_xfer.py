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

from rlp.utils import int_to_big_endian

class TestMsgEthereumSigntx(common.KeepKeyTest):
    def test_ethereum_tx_xfer_acc1(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)

        sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            value=12345678901234567890,
	    to_n=[0x8000002c, 0x8000003c, 1, 0, 0],
            address_type=1,
            )

        self.assertEqual(sig_v, 27)
        self.assertEqual(binascii.hexlify(sig_r), '99f70cb618893ed3489add3de2adc0a3597bb59f683b67feb67f14145bef6766')
        self.assertEqual(binascii.hexlify(sig_s), '03c76425482270f1c720cb3c457a91b3d9e55848f21fdbde949e075fda344ab7')
        self.assertEqual(binascii.hexlify(hash), '4cc3cd55e89f68f3bab16eeb94bc50c53fec6e8946e749a85be390b06cd09f42')
        self.assertEqual(binascii.hexlify(signature_der), '304502210099f70cb618893ed3489add3de2adc0a3597bb59f683b67feb67f14145bef6766022003c76425482270f1c720cb3c457a91b3d9e55848f21fdbde949e075fda344ab7')

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
            value=12345678901234567890,
	    to_n=[0x8000002c, 0x8000003c, 2, 0, 0],
            address_type=1,
            )

        self.assertEqual(sig_v, 28)
        self.assertEqual(binascii.hexlify(sig_r), '1c1949e8a261f8abfc40f4b6230fd69d7ce14c8d5ca7629af61ceb4ba0ea0b45')
        self.assertEqual(binascii.hexlify(sig_s), '59c450dce64d38aba22527353a8708255859c9c25abbfca07a19cf180d5a3858')
        self.assertEqual(binascii.hexlify(hash), '77e95b8843f6fd5f27c37a3ced1a1369a236e566ed0fea45a7a57d278c590860')
        self.assertEqual(binascii.hexlify(signature_der), '304402201c1949e8a261f8abfc40f4b6230fd69d7ce14c8d5ca7629af61ceb4ba0ea0b45022059c450dce64d38aba22527353a8708255859c9c25abbfca07a19cf180d5a3858')

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
            value=12345678901234567890,
	    to_n=[0x8000002c, 0x8000003c, 2, 0, 0],
            address_type=1,
            )

        try:
	    signature_der = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
	    to_n=[0x8000002a, 0x8000003c, 1, 0, 0],  
            #error here   -^-
            value=12345678901234567890,
            address_type=1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Failed to compile output')
            print "Negative Test Passed (test_ethereum_xfer_account_path_error_0)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_xfer_account_path_error_1(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)

        try:
	    signature_der = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
	    to_n=[0x8000002c, 0x80000030, 1, 0, 0], 
                    #error here       -^- 
            value=12345678901234567890,
            address_type=1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Failed to compile output')
            print "Negative Test Passed (test_ethereum_xfer_account_path_error_1)!" 
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
            value=12345678901234567890,
            address_type=1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Failed to compile output')
            print "Negative Test Passed (test_ethereum_xfer_account_path_error_2)!" 
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
            value=12345678901234567890,
            address_type=1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Failed to compile output')
            print "Negative Test Passed (test_ethereum_xfer_account_path_error_2)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

if __name__ == '__main__':
    unittest.main()
