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
        self.client.apply_policy('ShapeShift', 1)
        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC
        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount='47535135',
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,
  
                                         deposit_amount='300000', 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1AJaZuL6heuX8SJEthckaKKQPu2EbDMR3U') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='19nkmC2y4Rq3DXia7Um5YW9hxkRhwA5ABN') ,

                                         expiration=1471627016859,
                                         quoted_rate='15878378378',

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee='100000',
                                         order_id=binascii.unhexlify('f1c9ace477f04af79bcbc62f3756ae08'),
                                         ),
                                signature=binascii.unhexlify('1f3d840f06670c1688377255dbe5cfc53f8de8628aed7a73a09718d058aae4a13e24baf1b83838ffc580e1b9a0f479663027c14ab6da7069311a7c554157857680')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483648,0,1],
                              return_address_n=[2147483692,2147483648,2147483649,0,3],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=300000, 
                              address='1AJaZuL6heuX8SJEthckaKKQPu2EbDMR3U',
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
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])

            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_signature_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)
        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC
        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount='47535135',
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,
  
                                         deposit_amount='300000', 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1AJaZuL6heuX8SJEthckaKKQPu2EbDMR3U') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='19nkmC2y4Rq3DXia7Um5YW9hxkRhwA5ABN') ,

                                         expiration=1471627016859,
                                         quoted_rate='15878378371',                       #error added here1

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee='100000',
                                         order_id=binascii.unhexlify('f1c9ace477f04af79bcbc62f3756ae08'),
                                         ),
                                signature=binascii.unhexlify('1f3d840f06670c1688377255dbe5cfc53f8de8628aed7a73a09718d058aae4a13e24baf1b83838ffc580e1b9a0f479663027c14ab6da7069311a7c554157857680')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483648,0,1],
                              return_address_n=[2147483692,2147483648,2147483649,0,3],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=300000, 
                              address='1AJaZuL6heuX8SJEthckaKKQPu2EbDMR3U',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange signature error')
            print "Negative Test Passed (test_signature_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_withdrawal_cointype_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)
        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC
        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount='47535135',
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,
  
                                         deposit_amount='300000', 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1AJaZuL6heuX8SJEthckaKKQPu2EbDMR3U') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='19nkmC2y4Rq3DXia7Um5YW9hxkRhwA5ABN') ,

                                         expiration=1471627016859,
                                         quoted_rate='15878378378',                       #error added here1

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee='100000',
                                         order_id=binascii.unhexlify('f1c9ace477f04af79bcbc62f3756ae08'),
                                         ),
                                signature=binascii.unhexlify('1f3d840f06670c1688377255dbe5cfc53f8de8628aed7a73a09718d058aae4a13e24baf1b83838ffc580e1b9a0f479663027c14ab6da7069311a7c554157857680')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Bitcoin', # <<< error added here!!! 
                              withdrawal_address_n=[2147483692,2147483650,2147483648,0,1],
                              return_address_n=[2147483692,2147483648,2147483649,0,3],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=300000, 
                              address='1AJaZuL6heuX8SJEthckaKKQPu2EbDMR3U',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange withdrawal coin type error')
            print "Negative Test Passed (test_withdrawal_cointype_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_withdrawal_address_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)
        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC
        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount='47535135',
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,
  
                                         deposit_amount='300000', 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1AJaZuL6heuX8SJEthckaKKQPu2EbDMR3U') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='19nkmC2y4Rq3DXia7Um5YW9hxkRhwA5ABN') ,

                                         expiration=1471627016859,
                                         quoted_rate='15878378378',                 

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee='100000',
                                         order_id=binascii.unhexlify('f1c9ace477f04af79bcbc62f3756ae08'),
                                         ),
                                signature=binascii.unhexlify('1f3d840f06670c1688377255dbe5cfc53f8de8628aed7a73a09718d058aae4a13e24baf1b83838ffc580e1b9a0f479663027c14ab6da7069311a7c554157857680')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483648,0,0],      #error added here!
                              return_address_n=[2147483692,2147483648,2147483649,0,3],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=300000, 
                              address='1AJaZuL6heuX8SJEthckaKKQPu2EbDMR3U',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange withdrawal address error')
            print "Negative Test Passed (test_withdrawal_address_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

        
    def test_return_address_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)
        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC
        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount='47535135',
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,
  
                                         deposit_amount='300000', 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1AJaZuL6heuX8SJEthckaKKQPu2EbDMR3U') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='19nkmC2y4Rq3DXia7Um5YW9hxkRhwA5ABN') ,

                                         expiration=1471627016859,
                                         quoted_rate='15878378378',         

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee='100000',
                                         order_id=binascii.unhexlify('f1c9ace477f04af79bcbc62f3756ae08'),
                                         ),
                                signature=binascii.unhexlify('1f3d840f06670c1688377255dbe5cfc53f8de8628aed7a73a09718d058aae4a13e24baf1b83838ffc580e1b9a0f479663027c14ab6da7069311a7c554157857680')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483648,0,1],
                              return_address_n=[2147483692,2147483648,2147483649,0,4], # <<< error added here!!! 
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=300000, 
                              address='1AJaZuL6heuX8SJEthckaKKQPu2EbDMR3U',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange return address error')
            print "Negative Test Passed (test_return_address_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")


        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ltc_to_btc_exchange(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)
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
                                         withdrawal_amount='533594',
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='19nkmC2y4Rq3DXia7Um5YW9hxkRhwA5ABN') ,
  
                                         deposit_amount='90000000', 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LiZ9EjjyZYuKdkBSqzc7ZVHNQPubcUKuNC') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,

                                         expiration=1471629998149,
                                         quoted_rate='626216',

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee='30000',
                                         order_id=binascii.unhexlify('bfe3a6b0afc64126a4d47612d229debf'),
                                         ),
                                signature=binascii.unhexlify('20cb8e122ab35ea5d7e4344ce57f1da9d3deba6f19178c5e7184fb2091a3101848784035d315ccff7282d08dc018686b583f794f8b6f0ad006d8423df6b85e2977')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Bitcoin',
                              withdrawal_address_n=[2147483692,2147483648,2147483649,0,3],
                              return_address_n=[2147483692,2147483650,2147483649,0,1],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=90000000, 
                              address='LiZ9EjjyZYuKdkBSqzc7ZVHNQPubcUKuNC',
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

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ltc_to_btc_withdrawal_address_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)
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
                                         withdrawal_amount='533594',
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='19nkmC2y4Rq3DXia7Um5YW9hxkRhwA5ABN') ,
  
                                         deposit_amount='90000000', 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LiZ9EjjyZYuKdkBSqzc7ZVHNQPubcUKuNC') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,

                                         expiration=1471629998149,
                                         quoted_rate='626216',

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee='30000',
                                         order_id=binascii.unhexlify('bfe3a6b0afc64126a4d47612d229debf'),
                                         ),
                                signature=binascii.unhexlify('20cb8e122ab35ea5d7e4344ce57f1da9d3deba6f19178c5e7184fb2091a3101848784035d315ccff7282d08dc018686b583f794f8b6f0ad006d8423df6b85e2977')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Bitcoin',
                              withdrawal_address_n=[2147483692,2147483648,2147483649,0,5], #error added here!
                              return_address_n=[2147483692,2147483650,2147483649,0,1],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=90000000, 
                              address='LiZ9EjjyZYuKdkBSqzc7ZVHNQPubcUKuNC',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )


        try:
            self.client.sign_tx('Litecoin', [inp1, ], [out1, ]) # 
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange withdrawal address error')
            print "Negative Test Passed (test_ltc_to_btc_withdrawal_address_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ltc_to_btc_return_address_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)
        # tx: 08ebb7932ff4cd631f82e999b4d2f4dba119a8519991f7d13cbf12dfb3d7f3b2
        # input 0: 5.83579345 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 1rExUsv6RScHtQiLeSUv4ERGaAdxJTmDg  
                             # amount=583579345,
                             prev_hash=binascii.unhexlify('08ebb7932ff4cd631f82e999b4d2f4dba119a8519991f7d13cbf12dfb3d7f3b2'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount='533594',
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='19nkmC2y4Rq3DXia7Um5YW9hxkRhwA5ABN') ,
  
                                         deposit_amount='90000000', 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LiZ9EjjyZYuKdkBSqzc7ZVHNQPubcUKuNC') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,

                                         expiration=1471629998149,
                                         quoted_rate='626216',

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee='30000',
                                         order_id=binascii.unhexlify('bfe3a6b0afc64126a4d47612d229debf'),
                                         ),
                                signature=binascii.unhexlify('20cb8e122ab35ea5d7e4344ce57f1da9d3deba6f19178c5e7184fb2091a3101848784035d315ccff7282d08dc018686b583f794f8b6f0ad006d8423df6b85e2977')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Bitcoin',
                              withdrawal_address_n=[2147483692,2147483648,2147483649,0,3], 
                              return_address_n=[2147483692,2147483650,2147483649,0,2],  #error added here!
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=90000000, 
                              address='LiZ9EjjyZYuKdkBSqzc7ZVHNQPubcUKuNC',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )


        try:
            self.client.sign_tx('Litecoin', [inp1, ], [out1, ]) # << error added here!!!
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange return address error')
            print "Negative Test Passed (test_ltc_to_btc_return_address_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

if __name__ == '__main__':
    unittest.main()

