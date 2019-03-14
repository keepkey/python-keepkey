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
import itertools

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib import tx_api

class TestMsgSigntxGRS(common.KeepKeyTest):
    def test_one_one_fee(self):
        # http://blockbook.groestlcoin.org/tx/f56521b17b828897f72b30dd21b0192fd942342e89acbb06abf1d446282c30f5
        # ptx1: http://blockbook.groestlcoin.org/tx/cb74c8478c5814742c87cffdb4a21231869888f8042fb07a90e015a9db1f9d4a

        self.setup_mnemonic_allallall()

        ptx1hash='cb74c8478c5814742c87cffdb4a21231869888f8042fb07a90e015a9db1f9d4a'

        inp1 = proto_types.TxInputType(address_n=[44 | 0x80000000, 17 | 0x80000000, 0 | 0x80000000, 0, 2],  #  FXHDsC5ZqWQHkDmShzgRVZ1MatpWhwxTAA
                prev_hash=binascii.unhexlify(ptx1hash),
                prev_index=0,
                )

        out1 = proto_types.TxOutputType(address='FtM4zAn9aVYgHgxmamWBgWPyZsb6RhvkA9',
                amount=210016 - 192,
                script_type=proto_types.PAYTOADDRESS,
                )

        with self.client:
            self.client.set_tx_api(tx_api.TxApiGroestlcoin)
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(ptx1hash))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify(ptx1hash))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify(ptx1hash))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])

            (signatures, serialized_tx) = self.client.sign_tx('Groestlcoin', [inp1, ], [out1, ])

        self.assertEqual(binascii.hexlify(serialized_tx), '01000000014a9d1fdba915e0907ab02f04f88898863112a2b4fdcf872c7414588c47c874cb000000006a47304402201fb96d20d0778f54520ab59afe70d5fb20e500ecc9f02281cf57934e8029e8e10220383d5a3e80f2e1eb92765b6da0f23d454aecbd8236f083d483e9a7430236876101210331693756f749180aeed0a65a0fab0625a2250bd9abca502282a4cf0723152e67ffffffff01a0330300000000001976a914fe40329c95c5598ac60752a5310b320cb52d18e688ac00000000')


if __name__ == '__main__':
    unittest.main()
