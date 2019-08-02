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
# The script has been modified for KeepKey device.

import unittest
import common
import binascii

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian

class TestMsgEthereumSigntxERC20(common.KeepKeyTest):

    def test_approve_none(self):
        self.setup_mnemonic_nopin_nopassphrase()

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            value=0,
            to=binascii.unhexlify('41e5560054824ea6b0732e656e3ad64e20e94e45'),
            chain_id=1,
            data=binascii.unhexlify('095ea7b3000000000000000000000000' + '1d1c328764a41bda0492b66baa30c4a339ff85ef' + '0000000000000000000000000000000000000000000000000000000000000000'),
            )

        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), '11118b6b82c3aa30462dfbd6da234027a208358500a3c0b1c493fafe1c13eb90')
        self.assertEqual(binascii.hexlify(sig_s), '03a733a7cfb176aa16a28349e92cc4c5d239f9b9176718507997e467c330eb84')

    def test_approve_some(self):
        self.setup_mnemonic_nopin_nopassphrase()

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            value=0,
            to=binascii.unhexlify('41e5560054824ea6b0732e656e3ad64e20e94e45'),
            chain_id=1,
            data=binascii.unhexlify('095ea7b3000000000000000000000000' + '1d1c328764a41bda0492b66baa30c4a339ff85ef' + '00000000000000000000000000000000000000000000000000000000FA56EA00'),
            )

        self.assertEqual(sig_v, 38)
        self.assertEqual(binascii.hexlify(sig_r), 'a6898a6fec0b063ce2809d783ba5524216c49b27e6514d5ef703bc9bc3a152fd')
        self.assertEqual(binascii.hexlify(sig_s), '5b8b0e5b7b8f6d5269ce4dc266e6901f3284079fa1f0cd358d2987336dc8ba3a')

    def test_approve_all(self):
        self.setup_mnemonic_nopin_nopassphrase()

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            value=0,
            to=binascii.unhexlify('41e5560054824ea6b0732e656e3ad64e20e94e45'),
            chain_id=1,
            data=binascii.unhexlify('095ea7b3000000000000000000000000' + '1d1c328764a41bda0492b66baa30c4a339ff85ef' + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
            )

        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), '3671acb6aed5241948de56635ef64554d5e834355e99d806c4ae30bf463eae57')
        self.assertEqual(binascii.hexlify(sig_s), '2b0aa2fdfabefb4ae687f3418b13cddf1111e62338bc8fd3ca4e0196352bb6f8')


if __name__ == '__main__':
    unittest.main()
