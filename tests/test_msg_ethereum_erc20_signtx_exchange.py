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

class TestMsgEthereumtxERC20_exch(common.KeepKeyTest):

    def test_cvc_to_ltc_exch(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)

        # POST this to https://cors.shapeshift.io/sendamountProto2
        # {
        #    'depositAmount': '100',
        #    'withdrawal': 'LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V',
        #    'pair': 'CVC_LTC',
        #    'returnAddress': '0x3f2329c9adfbccd9a84f52c906e936a42da18cb8',
        #    'apiKey': '6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'
        #}

        signed_exchange_out1=proto_exchange.SignedExchangeResponse()
        signed_exchange_out1.ParseFromString(binascii.unhexlify('12411f868812f620b6baaa5699b28ba3c3d39626b3620298410b0357aeda5616fe162d270817b6699b9c96a175ab8b6308486727157602befc6ab47b1473436bc2c4f01a83020a310a03637663122a307831643863653930323266363238346333613563333137663866333436323031303732313465353435120502540be400189aa2f8ddf52c220302e5512a290a036c746312224c6876786b6b774d436a4441777970724e48685957385045396f4e66367753643256320401206eac3a310a03637663122a30783366323332396339616466626363643961383466353263393036653933366134326461313863623842406ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b4a030124f852109a8a4233bf254d6295850bc4c4fc82ce'))

        exchange_type_out1=proto_types.ExchangeType(
            signed_exchange_response=signed_exchange_out1,
            withdrawal_coin_name='Litecoin',
            withdrawal_address_n=[2147483692,2147483650,2147483649,0,1],
            return_address_n=[2147483692,2147483708,2147483648,0,0]
            )

        # First sign using the deprecated token_to stuff (how the KeepKey client does it)
        sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            value=0,
            address_type=3,
            exchange_type=exchange_type_out1,
            chain_id=1,
            token_shortcut='CVC',
            token_to=binascii.unhexlify('1d8ce9022f6284c3a5c317f8f34620107214e545'),
            token_value=binascii.unhexlify('02540be400'),
            )

        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), '1238fd332545415f09a01470350a5a20abc784dbf875cf58f7460560e66c597f')
        self.assertEqual(binascii.hexlify(sig_s), '10efa4dd6fdb381c317db8f815252c2ac0d2a883bd364901dee3dec5b7d3660a')
        self.assertEqual(binascii.hexlify(hash), '3878462365df8bd2253c72dfe6e5cb744c64915e23fd5556f7077e43950a1afd')
        self.assertEqual(binascii.hexlify(signature_der), '304402201238fd332545415f09a01470350a5a20abc784dbf875cf58f7460560e66c597f022010efa4dd6fdb381c317db8f815252c2ac0d2a883bd364901dee3dec5b7d3660a')

        # Then do it through data_initial_chunk
        sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            value=0,
            to=binascii.unhexlify('41e5560054824ea6b0732e656e3ad64e20e94e45'),
            address_type=3,
            exchange_type=exchange_type_out1,
            chain_id=1,
            data=binascii.unhexlify('a9059cbb000000000000000000000000' + '1d8ce9022f6284c3a5c317f8f34620107214e545' + '00000000000000000000000000000000000000000000000000000002540be400')
            )

        self.assertEqual(sig_v, 37)
        self.assertEqual(binascii.hexlify(sig_r), '1238fd332545415f09a01470350a5a20abc784dbf875cf58f7460560e66c597f')
        self.assertEqual(binascii.hexlify(sig_s), '10efa4dd6fdb381c317db8f815252c2ac0d2a883bd364901dee3dec5b7d3660a')
        self.assertEqual(binascii.hexlify(hash), '3878462365df8bd2253c72dfe6e5cb744c64915e23fd5556f7077e43950a1afd')
        self.assertEqual(binascii.hexlify(signature_der), '304402201238fd332545415f09a01470350a5a20abc784dbf875cf58f7460560e66c597f022010efa4dd6fdb381c317db8f815252c2ac0d2a883bd364901dee3dec5b7d3660a')

        #reset policy ('ShapeShift')
        self.client.apply_policy('ShapeShift', 0)

if __name__ == '__main__':
    unittest.main()
