import unittest
import common
import binascii
import itertools

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.client import CallException
from keepkeylib.tx_api import TXAPITestnet

class TestMsgSigntxExchange(common.KeepKeyTest):
    def test_btc_to_ltc_exchange(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('Exchange1', 1)
        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         deposit_amount=22,
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='Litecoin',
                                                #Respect to Litecoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                                address='Li9Hjd2NFuEz8c1ffd9C1huEED6qvDuJSh') ,
  
                                         withdrawal_amount=390000 - 10000, 
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='Bitcoin',
                                                address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='Bitcoin',
                                                #Respect to Bitcoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                                address='1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCG') ,
                                         expiration=5,
                                         quoted_rate=2,
                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         ),
                                signature=binascii.unhexlify('d16d4a3fa8fe21a389d97bde1837d2a314e3cdf8cb86d9e8aa9e1c485506b1ec241958f727905ed0f4ec5d691313f8a410c56e5ccf9ffc0a1da29188de0e7571')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              deposit_coin_name='Litecoin',
                              deposit_address_n=[0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ],
                              return_coin_name='Bitcoin',
                              return_address_n=[0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=0,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )
        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignExchange),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignExchange),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])

            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])

    def test_ltc_to_btc_exchange(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('Exchange1', 1)

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         deposit_amount=22,
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='Bitcoin',
                                                address='1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCG') ,
  
                                         withdrawal_amount=390000 - 10000, 
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='Litecoin',
                                                address='LYtGrdDeqYUQnTkr5sHT2DKZLG7Hqg7HTK') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='Bitcoin',
                                                address='LZPNdpJWH6ffEzNCxUSp1eCanazMBBu6xQ') ,
                                         expiration=5,
                                         quoted_rate=2,
                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         ),
                                signature=binascii.unhexlify('7a4e353ac68b39de13be319e79ecbefb0c7d1a685b5f244257c19b2d318b65f76af5560b206349d03a0e82230d82cf2d2ae2a8571816395e77059d694b00077a')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              deposit_coin_name='Bitcoin',
                              deposit_address_n=[0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ],
                              return_coin_name='Litecoin',
                              return_address_n=[0x8000002c, 0x8000002c, 0x29, 0, 1 ],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=0,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )
        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignExchange),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignExchange),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])

            self.client.sign_tx('Litecoin', [inp1, ], [out1, ])


    def test_incorrect_withdrawal_amount(self):           
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('Exchange1', 1)
        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         deposit_amount=22,
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='Litecoin',
                                                #Respect to Litecoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                                address='Li9Hjd2NFuEz8c1ffd9C1huEED6qvDuJSh') ,
  
                                         withdrawal_amount=390000 - 1000,     
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='Bitcoin',
                                                address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='Bitcoin',
                                                #Respect to Bitcoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                                address='1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCG') ,
                                         expiration=5,
                                         quoted_rate=2,
                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         ),
                                signature=binascii.unhexlify('d16d4a3fa8fe21a389d97bde1837d2a314e3cdf8cb86d9e8aa9e1c485506b1ec241958f727905ed0f4ec5d691313f8a410c56e5ccf9ffc0a1da29188de0e7571')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              deposit_coin_name='Litecoin',
                              deposit_address_n=[0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ],
                              return_coin_name='Bitcoin',
                              return_address_n=[0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=0,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_incorrect_withdrawal_amount)!"
        else:
            self.assert_(False, "Failed to detect error condition")

    def test_deposit_address_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('Exchange1', 1)
        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         deposit_amount=22,
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='Litecoin',
                                                #Respect to Litecoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                                address='Li9Hjd2NFuEz8c1ffd9C1huEED6qvDuJSE') ,
  
                                         withdrawal_amount=390000 - 10000,     
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='Bitcoin',
                                                address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='Bitcoin',
                                                #Respect to Bitcoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                                address='1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCG') ,
                                         expiration=5,
                                         quoted_rate=2,
                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         ),
                                signature=binascii.unhexlify('d16d4a3fa8fe21a389d97bde1837d2a314e3cdf8cb86d9e8aa9e1c485506b1ec241958f727905ed0f4ec5d691313f8a410c56e5ccf9ffc0a1da29188de0e7571')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              deposit_coin_name='Litecoin',
                              deposit_address_n=[0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ],
                              return_coin_name='Bitcoin',
                              return_address_n=[0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=0,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_deposit_address_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

    def test_return_address_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('Exchange1', 1)
        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         deposit_amount=22,
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='Litecoin',
                                                #Respect to Litecoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                                address='Li9Hjd2NFuEz8c1ffd9C1huEED6qvDuJSh') ,
  
                                         withdrawal_amount=390000 - 10000,     
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='Bitcoin',
                                                address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='Bitcoin',
                                                #Respect to Bitcoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                                address='1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCH') ,
                                         expiration=5,
                                         quoted_rate=2,
                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         ),
                                signature=binascii.unhexlify('d16d4a3fa8fe21a389d97bde1837d2a314e3cdf8cb86d9e8aa9e1c485506b1ec241958f727905ed0f4ec5d691313f8a410c56e5ccf9ffc0a1da29188de0e7571')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              deposit_coin_name='Litecoin',
                              deposit_address_n=[0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ],
                              return_coin_name='Bitcoin',
                              return_address_n=[0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ],
                            )

        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=0,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )


        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_return_address_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

    def test_signature_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('Exchange1', 1)
        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         deposit_amount=22,
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='Litecoin',
                                                #Respect to Litecoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                                address='Li9Hjd2NFuEz8c1ffd9C1huEED6qvDuJSh') ,
  
                                         withdrawal_amount=390000 - 10000,     
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='Bitcoin',
                                                address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='Bitcoin',
                                                #Respect to Bitcoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                                address='1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCG') ,
                                         expiration=5,
                                         quoted_rate=2,
                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         ),
                                signature=binascii.unhexlify('d16d4a3fa8fe21a389d97bde1837d2a314e3cdf8cb86d9e8aa9e1c485506b1ec241958f727905ed0f4ec5d691313f8a410c56e5ccf9ffc0a1da29188de0e7570')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              deposit_coin_name='Litecoin',
                              deposit_address_n=[0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ],
                              return_coin_name='Bitcoin',
                              return_address_n=[0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=0,
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_signature_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

if __name__ == '__main__':
    unittest.main()

