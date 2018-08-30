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

import unittest
import common
from binascii import hexlify, unhexlify

from keepkeylib.ckd_public import deserialize
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from keepkeylib import tx_api


class TestMsgSigntxBitcoinGold(common.KeepKeyTest):

    def test_send_bitcoin_gold_nochange(self):
        self.setup_mnemonic_allallall()
        self.client.set_tx_api(tx_api.TxApiBitcoinGold)
        inp1 = proto_types.TxInputType(
            address_n=parse_path("44'/156'/0'/1/0"),
            amount=1896050,
            prev_hash=unhexlify('25526bf06c76ad3082bba930cf627cdd5f1b3cd0b9907dd7ff1a07e14addc985'),
            prev_index=0,
            script_type=proto_types.SPENDADDRESS,
        )
        inp2 = proto_types.TxInputType(
            address_n=parse_path("44'/156'/0'/0/1"),
            # 1LRspCZNFJcbuNKQkXgHMDucctFRQya5a3
            amount=73452,
            prev_hash=unhexlify('db77c2461b840e6edbe7f9280043184a98e020d9795c1b65cb7cef2551a8fb18'),
            prev_index=1,
            script_type=proto_types.SPENDADDRESS,
        )
        out1 = proto_types.TxOutputType(
            address='GfDB1tvjfm3bukeoBTtfNqrJVFohS2kCTe',
            amount=1934960,
            script_type=proto_types.PAYTOADDRESS,
        )
        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures, serialized_tx) = self.client.sign_tx('BitcoinGold', [inp1, inp2], [out1])

        assert hexlify(serialized_tx) == b'010000000285c9dd4ae1071affd77d90b9d03c1b5fdd7c62cf30a9bb8230ad766cf06b5225000000006b483045022100928852076c9fab160c07564cd54691af1cbc37fb28f0b7bee7299c7925ef62f0022058856387afecc6508f2f04ecdfd292a13026a5b2107ebdd2cc789bdf8820d552412102a6c3998d0d4e5197ff41aab5c53580253b3b91f583f4c31f7624be7dc83ce15fffffffff18fba85125ef7ccb651b5c79d920e0984a18430028f9e7db6e0e841b46c277db010000006b483045022100faa2f4f01cc95e680349a093923aae0aa2ea01429873555aa8a84bf630ef33a002204c3f4bf567e2d20540c0f71dc278481d6ccb6b95acda2a2f87ce521c79d6b872412102d54a7e5733b1635e5e9442943f48179b1700206b2d1925250ba10f1c86878be8ffffffff0170861d00000000001976a914ea5f904d195079a350b534db4446433b3cec222e88ac00000000'


if __name__ == '__main__':
    unittest.main()
