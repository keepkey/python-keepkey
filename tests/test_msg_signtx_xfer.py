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


class TestMsgSigntx(common.KeepKeyTest):

    def test_xfer_node_error(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        # Transfer Output address
        out1 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000000, 1, 0 ],
                                                                            #error    -^- 
                              amount=390000 - 10000, 
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=1,
                              )

        # Change Output address
        out2 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000000, 1, 1 ],
                              amount=8000,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=2,
                              )

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, out2])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
        else:
            self.assert_(False, "Failed to detect invalid Address node for transfer transaction")

    def test_xfer_addressT_error(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        # Spend Output address
        out1 = proto_types.TxOutputType(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1',
                              amount=390000 - 80000 - 12000 - 10000,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=0,
                              )
        # Transfer Output address
        out2 = proto_types.TxOutputType(address='1EfKbQupktEMXf4gujJ9kCFo83k1iMqwqK',
                               #error    -^- 
                              amount=10000,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=1,
                              )

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, out2])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
        else:
            self.assert_(False, "Failed to detect invalid Address Type for transfer transaction")

    def test_xfer_change_addressT_error(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        # Spend Output address
        out1 = proto_types.TxOutputType(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1',
                              amount=390000 - 80000 - 12000 - 10000,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=0,
                              )
        # Transfer Output address
        out2 = proto_types.TxOutputType(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz2',
                               #error    -^- 
                              amount=10000, 
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=2,
                              )

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, out2])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
        else:
            self.assert_(False, "Failed to detect invalid address type for change transaction")

    def test_xfer_spend_addressT_error(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        # Spend Output address
        out1 = proto_types.TxOutputType(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1',
                              amount=390000 - 80000 - 12000 - 10000,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=0,
                              )
        # Transfer Output address
        out2 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000000, 1, 0 ],
                                #error     -^-
                              amount=10000, 
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=0,
                              )
        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, out2])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
        else:
            self.assert_(False, "Failed to detect invalid address type for spend transaction")

    def test_xfer_change_fee(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        # Transfer Output address
        out1 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000000, 0, 0 ],
                              amount=390000 - 10000, 
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=1,
                              )

        # Change Output address
        out2 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000000, 1, 1 ],
                              amount=8000,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=2,
                              )

        with self.client:
#            self.client.set_tx_api(tx_api.TxApiTestnet)
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmTransferToAccount),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmTransferToAccount),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),

                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures, serialized_tx) = self.client.sign_tx('Bitcoin', [inp1, ], [out1, out2])

        self.assertEqual(binascii.hexlify(serialized_tx), '010000000182488650ef25a58fef6788bd71b8212038d7f2bbe4750bc7bcb44701e85ef6d5000000006a473044022029270ff6991d953cb89135dc43723a64f5be00a69db42efeb845f2918dec50c302201f6589bb44c9c4b6c8152966d5de9b56c2a6ca61172d0f63c6c62e48ad8975130121023230848585885f63803a0a8aecdd6538792d5c539215c91698e315bf0253b43dffffffff0260cc0500000000001976a9149c9d21f47382762df3ad81391ee0964b28dd951788ac401f0000000000001976a914db302d9f1dd36faa220d8dfd7ff18ff5e308a53688ac00000000')


    def test_xfer_multi_account(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        # Transfer Output address1
        out1 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000001, 0, 0 ],
                              amount= 10000,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=1,
                              )

        # Transfer Output address2
        out2 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000002, 0, 0 ],
                              amount= 10000,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=1,
                              )

        # Transfer Output address3
        out3 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000003, 0, 0 ],
                              amount= 390000 - 20000 - 90000,        #280000
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=1,
                              )
        # Change Output address
        out4 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000000, 1, 1 ],
                              amount=80000,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=2,
                              )

        with self.client:
#            self.client.set_tx_api(tx_api.TxApiTestnet)
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmTransferToAccount),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmTransferToAccount),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=2)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmTransferToAccount),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=3)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmTransferToAccount),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=2)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=3)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=2)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=3)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures, serialized_tx) = self.client.sign_tx('Bitcoin', [inp1, ], [out1, out2, out3, out4])

        self.assertEqual(binascii.hexlify(serialized_tx), '010000000182488650ef25a58fef6788bd71b8212038d7f2bbe4750bc7bcb44701e85ef6d5000000006a473044022001e609489d66ab9a96e26b23125e372e68990fe995a4026bbb0a2ee53dcf008b0220545ddfec0b6fd186623d793158437cdfcead11b6464507db533ca6a3f9c64a340121023230848585885f63803a0a8aecdd6538792d5c539215c91698e315bf0253b43dffffffff0410270000000000001976a914c5c94a31b13d1223520fa92f1e0a127dbfd82ed188ac10270000000000001976a9140d9d0435f01563c6f01b7c9a404590c21f4e2d0188acc0450400000000001976a914e68990fa670c2910e8eaec96c2db2568ec132c2288ac80380100000000001976a914db302d9f1dd36faa220d8dfd7ff18ff5e308a53688ac00000000')

    def test_one_three_fee(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        # Spend Output address
        out1 = proto_types.TxOutputType(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1',
                              amount=390000 - 80000 - 12000 - 10000,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=0,
                              )


        # Transfer Output address
        out2 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000000, 0, 0 ],
                              amount=10000,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=1,
                              )

        # Change Output address
        out3 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000000, 1, 1 ],
                              amount=80000,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=2,
                              )

        with self.client:
#            self.client.set_tx_api(tx_api.TxApiTestnet)
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmTransferToAccount),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=2)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmTransferToAccount),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=2)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=2)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures, serialized_tx) = self.client.sign_tx('Bitcoin', [inp1, ], [out1, out2, out3])

        self.assertEqual(binascii.hexlify(serialized_tx), '010000000182488650ef25a58fef6788bd71b8212038d7f2bbe4750bc7bcb44701e85ef6d5000000006b483045022100c3ceed2bd2365ccdb978d605e9ae6347790b978e2747bbbec623364270be723c022017680d050c2bf0dae4bd249d83b43bc93a33661c1a0b18c7e8a05eb47815f9aa0121023230848585885f63803a0a8aecdd6538792d5c539215c91698e315bf0253b43dffffffff0300650400000000001976a914de9b2a8da088824e8fe51debea566617d851537888ac10270000000000001976a9149c9d21f47382762df3ad81391ee0964b28dd951788ac80380100000000001976a914db302d9f1dd36faa220d8dfd7ff18ff5e308a53688ac00000000')

if __name__ == '__main__':
    unittest.main()
