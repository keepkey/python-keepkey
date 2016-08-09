import unittest
import common
import binascii
import itertools

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.client import CallException
from keepkeylib.tx_api import TXAPITestnet

#deposit    = External exchange designator
#withdrawal = KeepKey destination fund designator
#return     = KeepKey refund designator 

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
                                         withdrawal_amount=15464029,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LiBgFW3tMEb8XJEQz8noycuJNrrpX3hpqt') ,
  
                                         deposit_amount=100000, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='12Dzx46JE9tTV4eibmmyGtRw6SAHXzDPqR') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='17mN37zxz2aAZR2RU5N6meLSECVt1Fop5b') ,

                                         expiration=1470688914152,
                                         quoted_rate=15564029174,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=100000,
                                         order_id=binascii.unhexlify('72aa23548d7d4936a3c1c6d8538bb345'),
                                         ),
                                signature=binascii.unhexlify('20bd26ca9338ab6c11b15516e82dacb03cfd4834f52189580428128446c84ffa9b1c208677eb33c6f339b59fed7f4ac3725ff92d5b7c8bed9a2b45dc015b5408b6')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692, 2147483650, 2147483648, 0, 3 ],
                              return_address_n=[2147483692, 2147483648, 2147483648, 0, 11 ],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=100000, 
                              address='12Dzx46JE9tTV4eibmmyGtRw6SAHXzDPqR',
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
                proto.ButtonRequest(code=proto_types.ButtonRequest_FeeOverThreshold),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])

            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])

        #reset policy ("Exchange1")
        self.client.apply_policy('Exchange1', 0)

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
                                         withdrawal_amount=15464029,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LiBgFW3tMEb8XJEQz8noycuJNrrpX3hpqt') ,
  
#                                         deposit_amount=100000,   # error added here
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='12Dzx46JE9tTV4eibmmyGtRw6SAHXzDPqR') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='17mN37zxz2aAZR2RU5N6meLSECVt1Fop5b') ,

                                         expiration=1470688914152,
                                         quoted_rate=15564029174,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=100000,
                                         order_id=binascii.unhexlify('72aa23548d7d4936a3c1c6d8538bb345'),
                                         ),
                                signature=binascii.unhexlify('20bd26ca9338ab6c11b15516e82dacb03cfd4834f52189580428128446c84ffa9b1c208677eb33c6f339b59fed7f4ac3725ff92d5b7c8bed9a2b45dc015b5408b6')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692, 2147483650, 2147483648, 0, 3 ],
                              return_address_n=[2147483692, 2147483648, 2147483648, 0, 11 ],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=100000, 
                              address='12Dzx46JE9tTV4eibmmyGtRw6SAHXzDPqR',
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


        #reset policy ("Exchange1")
        self.client.apply_policy('Exchange1', 0)


    def test_withdrawal_cointype_error(self):
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
                                         withdrawal_amount=15464029,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LiBgFW3tMEb8XJEQz8noycuJNrrpX3hpqt') ,
  
                                         deposit_amount=100000, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='12Dzx46JE9tTV4eibmmyGtRw6SAHXzDPqR') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='17mN37zxz2aAZR2RU5N6meLSECVt1Fop5b') ,

                                         expiration=1470688914152,
                                         quoted_rate=15564029174,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=100000,
                                         order_id=binascii.unhexlify('72aa23548d7d4936a3c1c6d8538bb345'),
                                         ),
                                signature=binascii.unhexlify('20bd26ca9338ab6c11b15516e82dacb03cfd4834f52189580428128446c84ffa9b1c208677eb33c6f339b59fed7f4ac3725ff92d5b7c8bed9a2b45dc015b5408b6')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Bitcoin',  # << error added here!!!
                              withdrawal_address_n=[2147483692, 2147483650, 2147483648, 0, 3 ],
                              return_address_n=[2147483692, 2147483648, 2147483648, 0, 11 ],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=100000, 
                              address='12Dzx46JE9tTV4eibmmyGtRw6SAHXzDPqR',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_withdrawal_cointype_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("Exchange1")
        self.client.apply_policy('Exchange1', 0)

    def test_withdrawal_address_error(self):
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
                                         withdrawal_amount=15464029,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LiBgFW3tMEb8XJEQz8noycuJNrrpX3hpqt') ,
  
                                         deposit_amount=100000, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='12Dzx46JE9tTV4eibmmyGtRw6SAHXzDPqR') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='17mN37zxz2aAZR2RU5N6meLSECVt1Fop5b') ,

                                         expiration=1470688914152,
                                         quoted_rate=15564029174,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=100000,
                                         order_id=binascii.unhexlify('72aa23548d7d4936a3c1c6d8538bb345'),
                                         ),
                                signature=binascii.unhexlify('20bd26ca9338ab6c11b15516e82dacb03cfd4834f52189580428128446c84ffa9b1c208677eb33c6f339b59fed7f4ac3725ff92d5b7c8bed9a2b45dc015b5408b6')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',  
                              withdrawal_address_n=[2147483692, 2147483650, 2147483648, 0, 2 ], # << error added here!!!
                              return_address_n=[2147483692, 2147483648, 2147483648, 0, 11 ],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=100000, 
                              address='12Dzx46JE9tTV4eibmmyGtRw6SAHXzDPqR',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_withdrawal_address_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("Exchange1")
        self.client.apply_policy('Exchange1', 0)

        
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
                                         withdrawal_amount=15464029,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LiBgFW3tMEb8XJEQz8noycuJNrrpX3hpqt') ,
  
                                         deposit_amount=100000, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='12Dzx46JE9tTV4eibmmyGtRw6SAHXzDPqR') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='17mN37zxz2aAZR2RU5N6meLSECVt1Fop5b') ,

                                         expiration=1470688914152,
                                         quoted_rate=15564029174,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=100000,
                                         order_id=binascii.unhexlify('72aa23548d7d4936a3c1c6d8538bb345'),
                                         ),
                                signature=binascii.unhexlify('20bd26ca9338ab6c11b15516e82dacb03cfd4834f52189580428128446c84ffa9b1c208677eb33c6f339b59fed7f4ac3725ff92d5b7c8bed9a2b45dc015b5408b6')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692, 2147483650, 2147483648, 0, 3 ],
                              return_address_n=[2147483692, 2147483648, 2147483648, 0, 10 ], # added error here
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=100000, 
                              address='12Dzx46JE9tTV4eibmmyGtRw6SAHXzDPqR',
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


        #reset policy ("Exchange1")
        self.client.apply_policy('Exchange1', 0)

    def test_return_cointype_error(self):
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
                                         withdrawal_amount=15464029,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LiBgFW3tMEb8XJEQz8noycuJNrrpX3hpqt') ,
  
                                         deposit_amount=100000, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='12Dzx46JE9tTV4eibmmyGtRw6SAHXzDPqR') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='17mN37zxz2aAZR2RU5N6meLSECVt1Fop5b') ,

                                         expiration=1470688914152,
                                         quoted_rate=15564029174,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=100000,
                                         order_id=binascii.unhexlify('72aa23548d7d4936a3c1c6d8538bb345'),
                                         ),
                                signature=binascii.unhexlify('20bd26ca9338ab6c11b15516e82dacb03cfd4834f52189580428128446c84ffa9b1c208677eb33c6f339b59fed7f4ac3725ff92d5b7c8bed9a2b45dc015b5408b6')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',  
                              withdrawal_address_n=[2147483692, 2147483650, 2147483648, 0, 3 ], 
                              return_address_n=[2147483692, 2147483648, 2147483648, 0, 11 ],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=100000, 
                              address='12Dzx46JE9tTV4eibmmyGtRw6SAHXzDPqR',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )

        try:
            self.client.sign_tx('Litecoin', [inp1, ], [out1, ]) # << error added here!!!
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_return_cointype_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("Exchange1")
        self.client.apply_policy('Exchange1', 0)

    def test_ltc_to_btc_exchange(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('Exchange1', 1)
        # tx: 08ebb7932ff4cd631f82e999b4d2f4dba119a8519991f7d13cbf12dfb3d7f3b2
        # input 0: 5.83579345 BTC

        print "This is a test"
        inp1 = proto_types.TxInputType(address_n=[0],  # 1rExUsv6RScHtQiLeSUv4ERGaAdxJTmDg  
                             # amount=583579345,
                             prev_hash=binascii.unhexlify('08ebb7932ff4cd631f82e999b4d2f4dba119a8519991f7d13cbf12dfb3d7f3b2'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount=1244404,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='17mN37zxz2aAZR2RU5N6meLSECVt1Fop5b') ,
  
                                         deposit_amount=200000000, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='Lh9RqxT8BqYzLRoTem86cYoxeKc3tAHVhA') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LTcWLPkADYPm8Utf4GB5PDkSYV8KDNGBnq') ,

                                         expiration=1470769747488,
                                         quoted_rate=637202,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=30000,
                                         order_id=binascii.unhexlify('15694775f0984624adb26e9b1722ca48'),
                                         ),
                                signature=binascii.unhexlify('1fc89578e45d4d65b6f9f5e4c2eda23a8621a0d855b9f1a6223f045f626fddacca6032709b96367fab44336afd0396e0203ee27809227066da6a79506151f9c838')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Bitcoin',
                              withdrawal_address_n=[2147483692,2147483648,2147483648,0,11],
                              return_address_n=[2147483692,2147483650,2147483648,0,4],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=200000000, 
                              address='Lh9RqxT8BqYzLRoTem86cYoxeKc3tAHVhA',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )

        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify("08ebb7932ff4cd631f82e999b4d2f4dba119a8519991f7d13cbf12dfb3d7f3b2"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("08ebb7932ff4cd631f82e999b4d2f4dba119a8519991f7d13cbf12dfb3d7f3b2"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("08ebb7932ff4cd631f82e999b4d2f4dba119a8519991f7d13cbf12dfb3d7f3b2"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify("08ebb7932ff4cd631f82e999b4d2f4dba119a8519991f7d13cbf12dfb3d7f3b2"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignExchange),
                proto.ButtonRequest(code=proto_types.ButtonRequest_FeeOverThreshold),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])

            self.client.sign_tx('Litecoin', [inp1, ], [out1, ])

        #reset policy ("Exchange1")
        self.client.apply_policy('Exchange1', 0)



if __name__ == '__main__':
    unittest.main()

