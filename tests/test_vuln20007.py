# This file is part of the Keepkey project.
#
# Copyright (C) 2020 Shapeshift and contributors
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
from keepkeylib import tx_api


TXHASH_c6be22 = unhexlify('c6be22d34946593bcad1d2b013e12f74159e69574ffea21581dad115572e031c')
TXHASH_c63e24 = unhexlify('c63e24ed820c5851b60c54613fbc4bcb37df6cd49b4c96143e99580a472f79fb')
TXHASH_t = unhexlify('c6be22d34946593bcad1d2b013e12f74159e69574ffea21581dad115572e031c')
#TXHASH_t = unhexlify('6f90f3c7cbec2258b0971056ef3fe34128dbde30daa9c0639a898f9977299d54')

def Vuln20007TrapPrevent(client):
    ###################################################################################
    # vuln-20007 fix: 
    # Fix for this vuln prevents KK from signing sequential identical txs.
    # Insert this dummy tx between tests that use sequential identical txs to prevent trapping.
    TxApiSaved = client.get_tx_api()
    client.set_tx_api(tx_api.TxApiBitcoin)
    # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
    # input 0: 0.0039 BTC
    inp = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                     # amount=390000,
                     prev_hash=unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                     prev_index=0,
                     )
    out = proto_types.TxOutputType(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1',
                      amount=390000 - 10000,
                      script_type=proto_types.PAYTOADDRESS,
                      )
    with client: 
        client.set_expected_responses([
            proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
            proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
            proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
            proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
            proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
            proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
            proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
            proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
            proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
            proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
            proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
            proto.TxRequest(request_type=proto_types.TXFINISHED),
        ])
        client.sign_tx('Bitcoin', [inp, ], [out, ])
    client.set_tx_api(TxApiSaved)

class TestVuln20007(KeepKeyTest):

    def test_vuln(self):

      PREVHASH_1 = unhexlify("b6973acd5876ba8b050ae2d4c7d8b5c710ee4879af938be3c2c61a262f1730e0")
      PREVHASH_2 = unhexlify("3a3322e60f2f4c55394fe05dddacafd6e55ff6d40859fd98d64adefc8c169ac8")
      PREVHASH_3 = unhexlify("d58af7adaf3f04a0d5d30c145e8cfb48e863f49c8de594a8927c19c460fee9a3")
      PREVHASH_4 = unhexlify("3b586fcc54424f1df5669828f9d828e888298669a50a5983fd0d71e7f4d38110")

      self.setup_mnemonic_vuln20007()

      inp1 = proto_types.TxInputType(
                       # amount=150.0
                       address_n=parse_path("m/49'/1'/0'/0/0"),
                       prev_hash=PREVHASH_1,
                       amount=15000000000,
                       prev_index=1,
                       script_type=proto_types.SPENDP2SHWITNESS,
                       )
      inp2 = proto_types.TxInputType(
                       # amount=50.00000001,
                       address_n=parse_path("m/49'/1'/0'/0/1"),
                       prev_hash=PREVHASH_2,
                       amount=5000000001,
                       prev_index=1,
                       script_type=proto_types.SPENDP2SHWITNESS,
                       )
      inp3 = proto_types.TxInputType(
                       # amount=0.00000001,
                       address_n=parse_path("m/49'/1'/0'/0/2"),
                       prev_hash=PREVHASH_3,
                       amount=1,
                       prev_index=1,
                       script_type=proto_types.SPENDP2SHWITNESS,
                       )
      inp4 = proto_types.TxInputType(
                       # amount=,
                       address_n=parse_path("m/49'/1'/0'/0/3"),
                       prev_hash=PREVHASH_4,
                       amount=20000000000,
                       prev_index=1,
                       script_type=proto_types.SPENDP2SHWITNESS,
                       )

      out = proto_types.TxOutputType(address='2NA62MxEdTcBhSBN51QjD4LEam2J34ufotY',
                        amount=2000000000,
                        script_type=proto_types.PAYTOADDRESS,
                        )

      self.client.set_tx_api(tx_api.TxApiTestnet)

      with self.client:
        self.client.set_expected_responses([
            proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
            proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
            proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
            proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
            proto.ButtonRequest(code=proto_types.ButtonRequest_FeeOverThreshold),
            proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
            proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
            proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
            proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
            proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
            proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
            proto.TxRequest(request_type=proto_types.TXFINISHED),
        ])
        (signatures, serialized_tx) = self.client.sign_tx('Testnet', [inp1, inp2], [out, ])

      with self.client:
        self.client.set_expected_responses([
            proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
            proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
            proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
            proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
            proto.ButtonRequest(code=proto_types.ButtonRequest_Other),
            proto.Failure(code=proto_types.Failure_ActionCancelled),
        ])
        self.assertRaises(CallException, self.client.sign_tx, 'Testnet', [inp3, inp4], [out, ])


if __name__ == '__main__':
    unittest.main()
