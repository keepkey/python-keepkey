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

# https://blockbook-test.groestlcoin.org/tx/9b5c4859a8a31e69788cb4402812bb28f14ad71cbd8c60b09903478bc56f79a3
class TestMsgSigntxNativeSegwitGRS(KeepKeyTest):

    def test_send_native(self):
        self.setup_mnemonic_allallall()
        self.client.set_tx_api(TxApiGroestlcoinTestnet)
        inp1 = proto_types.TxInputType(
            address_n=parse_path("84'/1'/0'/0/0"), # tgrs1qkvwu9g3k2pdxewfqr7syz89r3gj557l3ued7ja
            amount=12300000,
            prev_hash=unhexlify('4f2f857f39ed1afe05542d058fb0be865a387446e32fc876d086203f483f61d1'),
            prev_index=0,
            sequence=0xfffffffe,
            script_type=proto_types.SPENDWITNESS,
        )
        out1 = proto_types.TxOutputType(
            address='2N4Q5FhU2497BryFfUgbqkAJE87aKDv3V3e',
            amount=5000000,
            script_type=proto_types.PAYTOADDRESS,
        )
        out2 = proto_types.TxOutputType(
            address='tgrs1qejqxwzfld7zr6mf7ygqy5s5se5xq7vmt9lkd57',
            script_type=proto_types.PAYTOADDRESS,
            amount=12300000 - 11000 - 5000000,
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
            (signatures, serialized_tx) = self.client.sign_tx('GRS Testnet', [inp1], [out1, out2], lock_time=650713)

        self.assertEquals(hexlify(serialized_tx), b'01000000000101d1613f483f2086d076c82fe34674385a86beb08f052d5405fe1aed397f852f4f0000000000feffffff02404b4c000000000017a9147a55d61848e77ca266e79a39bfc85c580a6426c987a8386f0000000000160014cc8067093f6f843d6d3e22004a4290cd0c0f336b02483045022100ea8780bc1e60e14e945a80654a41748bbf1aa7d6f2e40a88d91dfc2de1f34bd10220181a474a3420444bd188501d8d270736e1e9fe379da9970de992ff445b0972e3012103adc58245cf28406af0ef5cc24b8afba7f1be6c72f279b642d85c48798685f862d9ed0900')

    def test_send_native_change(self):
        self.setup_mnemonic_allallall()
        self.client.set_tx_api(TxApiGroestlcoinTestnet)
        inp1 = proto_types.TxInputType(
            address_n=parse_path("84'/1'/0'/0/0"), # tgrs1qkvwu9g3k2pdxewfqr7syz89r3gj557l3ued7ja
            amount=12300000,
            prev_hash=unhexlify('4f2f857f39ed1afe05542d058fb0be865a387446e32fc876d086203f483f61d1'),
            prev_index=0,
            sequence=0xfffffffe,
            script_type=proto_types.SPENDWITNESS,
        )
        out1 = proto_types.TxOutputType(
            address='2N4Q5FhU2497BryFfUgbqkAJE87aKDv3V3e',
            amount=5000000,
            script_type=proto_types.PAYTOADDRESS,
        )
        out2 = proto_types.TxOutputType(
            address_n=parse_path("84'/1'/0'/1/0"), # tgrs1qejqxwzfld7zr6mf7ygqy5s5se5xq7vmt9lkd57
            script_type=proto_types.PAYTOWITNESS,
            amount=12300000 - 11000 - 5000000,
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
            (signatures, serialized_tx) = self.client.sign_tx('GRS Testnet', [inp1], [out1, out2], lock_time=650713)

        self.assertEquals(hexlify(serialized_tx), b'01000000000101d1613f483f2086d076c82fe34674385a86beb08f052d5405fe1aed397f852f4f0000000000feffffff02404b4c000000000017a9147a55d61848e77ca266e79a39bfc85c580a6426c987a8386f0000000000160014cc8067093f6f843d6d3e22004a4290cd0c0f336b02483045022100ea8780bc1e60e14e945a80654a41748bbf1aa7d6f2e40a88d91dfc2de1f34bd10220181a474a3420444bd188501d8d270736e1e9fe379da9970de992ff445b0972e3012103adc58245cf28406af0ef5cc24b8afba7f1be6c72f279b642d85c48798685f862d9ed0900')

if __name__ == '__main__':
    unittest.main()
