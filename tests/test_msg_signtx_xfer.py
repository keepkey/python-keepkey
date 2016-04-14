import unittest
import common
import binascii
import itertools

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tx_api import TXAPITestnet

class TestMsgSigntx(common.KeepKeyTest):

    def test_btc_address_type_error_1(self):
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
                              amount=390000 - 10000, 
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=1,
                              )

        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
            ])

            try:
                self.client.sign_tx('Bitcoin', [inp1, ], [out1, out2])
            except CallException as e:
                self.assertEqual(e.args[0], proto_types.Failure_Other)
            else:
                self.assert_(False, "types.Invalid Address Type expected")

    
    def test_btc_address_type_error_2(self):
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
                              amount=390000 - 10000, 
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=2,
                              )

        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
            ])

            try:
                self.client.sign_tx('Bitcoin', [inp1, ], [out1, out2])
            except CallException as e:
                self.assertEqual(e.args[0], proto_types.Failure_Other)
            else:
                self.assert_(False, "types.Invalid Address Type expected")

    def test_xfer_address_type_error(self):
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
                              amount=390000 - 10000, 
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=0,
                              )

        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
            ])

            try:
                self.client.sign_tx('Bitcoin', [inp1, ], [out1, out2])
            except CallException as e:
                self.assertEqual(e.args[0], proto_types.Failure_Other)
            else:
                self.assert_(False, "types.Invalid Address Type expected")

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
        out1 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000000, 1, 0 ],
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
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmTransferToAccount),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),

                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures, serialized_tx) = self.client.sign_tx('Bitcoin', [inp1, ], [out1, out2])

        self.assertEqual(binascii.hexlify(serialized_tx), '010000000182488650ef25a58fef6788bd71b8212038d7f2bbe4750bc7bcb44701e85ef6d5000000006a47304402207c60797406ab334cfab1ffab8da487ebd9f346b66cfa7f71d5ffcdca99065c4002206d1c95638fb8fb00487c5f8f8fd8e55fea6c3410a915f27a89265d8cb5701da30121023230848585885f63803a0a8aecdd6538792d5c539215c91698e315bf0253b43dffffffff0260cc0500000000001976a9141c07afb85ee3408f8fd1fc9c5b5361800c28d2eb88ac401f0000000000001976a914db302d9f1dd36faa220d8dfd7ff18ff5e308a53688ac00000000')
    
    
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
        out2 = proto_types.TxOutputType(address_n=[0x8000002c, 0x80000000, 0x80000000, 1, 0 ],
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

        self.assertEqual(binascii.hexlify(serialized_tx), '010000000182488650ef25a58fef6788bd71b8212038d7f2bbe4750bc7bcb44701e85ef6d5000000006b483045022100fddbb36159890132d479cf88f706a866560dca04563b35c0db9297dd237b0fe0022047498dcebf88416a9bc5d81d7870a2b4457a0ba9fd5c0668d55e2971dd843ab40121023230848585885f63803a0a8aecdd6538792d5c539215c91698e315bf0253b43dffffffff0300650400000000001976a914de9b2a8da088824e8fe51debea566617d851537888ac10270000000000001976a9141c07afb85ee3408f8fd1fc9c5b5361800c28d2eb88ac80380100000000001976a914db302d9f1dd36faa220d8dfd7ff18ff5e308a53688ac00000000')

if __name__ == '__main__':
    unittest.main()
