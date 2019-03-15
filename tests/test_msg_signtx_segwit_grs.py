# This file is part of the Trezor project.
#
# Copyright (C) 2012-2018 SatoshiLabs and contributors
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

from binascii import hexlify, unhexlify
import unittest

from keepkeylib import ckd_public as bip32
from common import KeepKeyTest

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from keepkeylib.tx_api import TxApiGroestlcoinTestnet

# https://blockbook-test.groestlcoin.org/tx/4ce0220004bdfe14e3dd49fd8636bcb770a400c0c9e9bff670b6a13bb8f15c72
class TestMsgSigntxSegwitGRS(KeepKeyTest):

    def test_send_p2sh(self):
        self.setup_mnemonic_allallall()
        self.client.set_tx_api(TxApiGroestlcoinTestnet)
        inp1 = proto_types.TxInputType(
            address_n=parse_path("49'/1'/0'/1/0"), # 2N1LGaGg836mqSQqiuUBLfcyGBhyZYBtBZ7
            amount=123456789,
            prev_hash=unhexlify('09a48bce2f9d5c6e4f0cb9ea1b32d0891855e8acfe5334f9ebd72b9ad2de60cf'),
            prev_index=0,
            sequence=0xfffffffe,
            script_type=proto_types.SPENDP2SHWITNESS,
        )
        out1 = proto_types.TxOutputType(
            address='mvbu1Gdy8SUjTenqerxUaZyYjmvedc787y',
            amount=12300000,
            script_type=proto_types.PAYTOADDRESS,
        )
        out2 = proto_types.TxOutputType(
            address='2N1LGaGg836mqSQqiuUBLfcyGBhyZYBtBZ7',
            script_type=proto_types.PAYTOADDRESS,
            amount=123456789 - 11000 - 12300000,
        )
        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures, serialized_tx) = self.client.sign_tx('GRS Testnet', [inp1], [out1, out2], lock_time=650756)

        self.assertEquals(hexlify(serialized_tx), b'01000000000101cf60ded29a2bd7ebf93453feace8551889d0321beab90c4f6e5c9d2fce8ba4090000000017160014d16b8c0680c61fc6ed2e407455715055e41052f5feffffff02e0aebb00000000001976a914a579388225827d9f2fe9014add644487808c695d88ac3df39f060000000017a91458b53ea7f832e8f096e896b8713a8c6df0e892ca8702483045022100b7ce2972bcbc3a661fe320ba901e680913b2753fcb47055c9c6ba632fc4acf81022001c3cfd6c2fe92eb60f5176ce0f43707114dd7223da19c56f2df89c13c2fef80012103e7bfe10708f715e8538c92d46ca50db6f657bbc455b7494e6a0303ccdb868b7904ee0900')

    def test_send_p2sh_change(self):
        self.setup_mnemonic_allallall()
        self.client.set_tx_api(TxApiGroestlcoinTestnet)
        inp1 = proto_types.TxInputType(
            address_n=parse_path("49'/1'/0'/1/0"), # 2N1LGaGg836mqSQqiuUBLfcyGBhyZYBtBZ7
            amount=123456789,
            prev_hash=unhexlify('09a48bce2f9d5c6e4f0cb9ea1b32d0891855e8acfe5334f9ebd72b9ad2de60cf'),
            prev_index=0,
            sequence=0xfffffffe,
            script_type=proto_types.SPENDP2SHWITNESS,
        )
        out1 = proto_types.TxOutputType(
            address='mvbu1Gdy8SUjTenqerxUaZyYjmvedc787y',
            amount=12300000,
            script_type=proto_types.PAYTOADDRESS,
        )
        out2 = proto_types.TxOutputType(
            address_n=parse_path("49'/1'/0'/1/0"),
            script_type=proto_types.PAYTOP2SHWITNESS,
            amount=123456789 - 11000 - 12300000,
        )
        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures, serialized_tx) = self.client.sign_tx('GRS Testnet', [inp1], [out1, out2], lock_time=650756)

        self.assertEquals(hexlify(serialized_tx), b'01000000000101cf60ded29a2bd7ebf93453feace8551889d0321beab90c4f6e5c9d2fce8ba4090000000017160014d16b8c0680c61fc6ed2e407455715055e41052f5feffffff02e0aebb00000000001976a914a579388225827d9f2fe9014add644487808c695d88ac3df39f060000000017a91458b53ea7f832e8f096e896b8713a8c6df0e892ca8702483045022100b7ce2972bcbc3a661fe320ba901e680913b2753fcb47055c9c6ba632fc4acf81022001c3cfd6c2fe92eb60f5176ce0f43707114dd7223da19c56f2df89c13c2fef80012103e7bfe10708f715e8538c92d46ca50db6f657bbc455b7494e6a0303ccdb868b7904ee0900')

if __name__ == '__main__':
    unittest.main()
