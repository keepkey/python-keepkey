# This file is part of the KEEPKEY project.
#
# Copyright (c) 2025 markrypto
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
import itertools

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.tools import parse_path
from keepkeylib.client import CallException
from keepkeylib import tx_api


TXHASH_5c6661 = bytes.fromhex(
    "5c66611fecd82c893305ea50ed3e94cd5404cb33a6cf4bf49d1330a95fd0a046"
)

TXHASH_9b5d2b = bytes.fromhex(
    "9b5d2b22caa027cb8bcc0c2ab4963277b00c78e5a4b145391ec1d4cf2aa348f3"
)

def request_input(n: int, tx_hash: bytes = None) -> proto.TxRequest:
  return proto.TxRequest(
    request_type=proto_types.TXINPUT,
    details=proto_types.TxRequestDetailsType(request_index=n, tx_hash=tx_hash),
  )


def request_output(n: int, tx_hash: bytes = None) -> proto.TxRequest:
  return proto.TxRequest(
    request_type=proto_types.TXOUTPUT,
    details=proto_types.TxRequestDetailsType(request_index=n, tx_hash=tx_hash),
  )

def request_finished() -> proto.TxRequest:
  return proto.TxRequest(request_type=proto_types.TXFINISHED)


class TestMsgSigntx(common.KeepKeyTest):
  
  def test_send_p2tr_only(self):

    self.setup_mnemonic_nopin_nopassphrase()
    
    inp1 = proto_types.TxInputType(
      address_n=parse_path("m/84h/0h/0h/0/0"),
      amount=130642,
      prev_hash=TXHASH_5c6661,
      prev_index=0,
      script_type=proto_types.InputScriptType.SPENDP2SHWITNESS,
    )
    inp2 = proto_types.TxInputType(
      address_n=parse_path("m/84h/0h/0h/0/0"),
      amount=123214,
      prev_hash=TXHASH_9b5d2b,
      prev_index=0,
      script_type=proto_types.InputScriptType.SPENDP2SHWITNESS,
    )

    out1 = proto_types.TxOutputType(
      # 86'/1'/1'/0/0
      address="bc1plsk660nud549q0p5hnlc0ldvgvxxaamcek68r8zsgp9xmhjypp4s2d4xdc",
      amount=251476,
      script_type=proto_types.OutputScriptType.PAYTOTAPROOT,
    )
    
    with self.client:
      self.client.set_expected_responses(
        [
          request_input(0),
          request_input(1),
          request_output(0),
          proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
          proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
          request_input(0),
          request_input(1),
          request_output(0),
          request_input(0),
          request_input(1),
          request_finished(),
        ]
      )
      (signatures, serialized_tx) = self.client.sign_tx('Bitcoin', [inp1, inp2, ], [out1, ])
      self.assertEqual(binascii.hexlify(serialized_tx), "0100000000010246a0d05fa930139df44bcfa633cb0454cd943eed50ea0533892cd8ec1f61665c0000000017160014b586ae30647c6ab84aa1a285d505155711509914fffffffff348a32acfd4c11e3945b1a4e5780cb0773296b42a0ccc8bcb27a0ca222b5d9b0000000017160014b586ae30647c6ab84aa1a285d505155711509914ffffffff0154d6030000000000225120fc2dad3e7c6d2a503c34bcff87fdac430c6ef778cdb4719c50404a6dde44086b02483045022100e0a59a721fa26dcb9be43584b2b8db9764697f0c2bb6d2232b19d1224d4b171c022022fcd858c678934262c41ac15b65526073df01eb37c5a47d456b834b1ca3ef2d012103940149b62893ed8ca405da2c989fce46964ff77b7f2a2f554abfdf1cd746092102473044022051ae10a90d42d8ca7523e68fe5d04e6ee9c1c7ec78d9b847cba03c2dd2838b2902204512fb7d0caafcc7197260f970b9af671b20b1b5c9cd95590bbeea453d791393012103940149b62893ed8ca405da2c989fce46964ff77b7f2a2f554abfdf1cd746092100000000")


if __name__ == '__main__':
    unittest.main()

