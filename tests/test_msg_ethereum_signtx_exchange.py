import unittest
import common
import binascii
import struct

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.client import CallException

from rlp.utils import int_to_big_endian

class TestMsgEthereumtx_exch(common.KeepKeyTest):

    def test_eth_to_doge_exch(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('6d4dc95317'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='doge',
                                                address='DQTjL9vfXVbMfCGM49KWeYvvvNzRPaoiFp') ,
  
                                         deposit_amount=binascii.unhexlify('02076f02a152b400'),
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='3d55d68b75d98ac3ac0d2ddf61554f00703d6357') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='3f2329c9adfbccd9a84f52c906e936a42da18cb8') ,

                                         expiration=1480978325881,
                                         quoted_rate=binascii.unhexlify('02ebe9834161'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('0bebc200'),
#                                         order_id=binascii.unhexlify('4a2320f8267b4b739fa452196d320abb'),
                                         order_id=binascii.unhexlify('4a2320f8267b4b739fa452196d320abb'),
                                         ),
                                signature=binascii.unhexlify('207f69cf0569f81d5758efb8f2e186e35bc84ce37ab198f88ef31342ef5213072942d063fb159aa7546dc7a8e72fc6d57932b0fcc62289bbf949ca508fea5e0e0c')
                             )
        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Dogecoin',
                              withdrawal_address_n=[2147483692,2147483651,2147483648,0,0],
                              return_address_n=[2147483692,2147483708,2147483648,0,0],
                            )
        sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify('3d55d68b75d98ac3ac0d2ddf61554f00703d6357'),
            value=146207570000000000,
            address_type=3,
            exchange_type=exchange_type_out1,
            )

        self.assertEqual(sig_v, 27)
        self.assertEqual(binascii.hexlify(sig_r), '442ef56b78c8ea8a0764fdb5527dc3f18086a8b672eefdee7249b5c661a584c6')
        self.assertEqual(binascii.hexlify(sig_s), '15a25a0704e46be3f60339443ce9183ac7193cbd7a49c564d14ffc41b571657a')
        self.assertEqual(binascii.hexlify(hash), 'ff73eec0846adace28b29aad84e53f97360e843947a079e7aeaaeb2fd92c9675')
        self.assertEqual(binascii.hexlify(signature_der), '30440220442ef56b78c8ea8a0764fdb5527dc3f18086a8b672eefdee7249b5c661a584c6022015a25a0704e46be3f60339443ce9183ac7193cbd7a49c564d14ffc41b571657a')

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_eth_to_ltc_exch(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('01a69189'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,
  
                                         deposit_amount=binascii.unhexlify('02076f02a152b400'),
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='8cfbb7ef910936ac801e4d07ae46599041206743') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='3f2329c9adfbccd9a84f52c906e936a42da18cb8') ,

                                         expiration=1480984776874,
                                         quoted_rate=binascii.unhexlify('0b54a1d6'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('0186a0'),
                                         order_id=binascii.unhexlify('1924ae6635e34cdca8137861434d9ede'),
                                         ),
                                signature=binascii.unhexlify('1f61697158580925b64ba9b93677a47f996deac9529d98e15ee90fcc240b098ab84f2324a4ccab092a38f8720537636ef1d012903ac27697f184cc43269975a420')
                             )
        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483649,0,1],
                              return_address_n=[2147483692,2147483708,2147483648,0,0]
                            )
        sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify('8cfbb7ef910936ac801e4d07ae46599041206743'),
            value=146207570000000000,
            address_type=3,
            exchange_type=exchange_type_out1,
            )

        self.assertEqual(sig_v, 27)
        self.assertEqual(binascii.hexlify(sig_r), 'b82354764f4a206507365e63c40182748948624bb9e62651e1f1121f3a9f9095')
        self.assertEqual(binascii.hexlify(sig_s), '53b582ea05874f87eb84d8256248ff16cab872ba585305eaa9ba4d732df7b2d5')
        self.assertEqual(binascii.hexlify(hash), 'ac4f6a5e7f2543ad921029a805ddf07480aaf708811645ae9e0116d6bf87a284')
        self.assertEqual(binascii.hexlify(signature_der), '3045022100b82354764f4a206507365e63c40182748948624bb9e62651e1f1121f3a9f9095022053b582ea05874f87eb84d8256248ff16cab872ba585305eaa9ba4d732df7b2d5')

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_exch_dep_cointype_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)
        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('01a69189'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,
  
                                         deposit_amount=binascii.unhexlify('02076f02a152b400'),
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='etx',
                                              #error here   -^-
                                                address='8cfbb7ef910936ac801e4d07ae46599041206743') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='3f2329c9adfbccd9a84f52c906e936a42da18cb8') ,

                                         expiration=1480984776874,
                                         quoted_rate=binascii.unhexlify('0b54a1d6'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('0186a0'),
                                         order_id=binascii.unhexlify('1924ae6635e34cdca8137861434d9ede'),
                                         ),
                                signature=binascii.unhexlify('1f61697158580925b64ba9b93677a47f996deac9529d98e15ee90fcc240b098ab84f2324a4ccab092a38f8720537636ef1d012903ac27697f184cc43269975a420')
                             )
        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483649,0,1],
                              return_address_n=[2147483692,2147483708,2147483648,0,0]
                            )
        
        try:
            sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify('8cfbb7ef910936ac801e4d07ae46599041206743'),
            value=146207570000000000,
            address_type=3,
            exchange_type=exchange_type_out1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange deposit coin type error')
            print "Negative Test Passed (test_ethereum_exch_dep_cointype_error)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_exch_dep_addr_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)
        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('01a69189'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,
  
                                         deposit_amount=binascii.unhexlify('02076f02a152b400'),
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='8cfbb7ef910936ac801e4d07ae46599041206744') ,
                                                                                 #error here   -^-

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='3f2329c9adfbccd9a84f52c906e936a42da18cb8') ,

                                         expiration=1480984776874,
                                         quoted_rate=binascii.unhexlify('0b54a1d6'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('0186a0'),
                                         order_id=binascii.unhexlify('1924ae6635e34cdca8137861434d9ede'),
                                         ),
                                signature=binascii.unhexlify('1f61697158580925b64ba9b93677a47f996deac9529d98e15ee90fcc240b098ab84f2324a4ccab092a38f8720537636ef1d012903ac27697f184cc43269975a420')
                             )
        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483649,0,1],
                              return_address_n=[2147483692,2147483708,2147483648,0,0]
                            )
        try:
            sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify('8cfbb7ef910936ac801e4d07ae46599041206743'),
            value=146207570000000000,
            address_type=3,
            exchange_type=exchange_type_out1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange deposit address error')
            print "Negative Test Passed (test_ethereum_exch_dep_addr_error)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_exch_dep_amount_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)
        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('01a69189'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,
  
                                         deposit_amount=binascii.unhexlify('02076f02a152b401'),
                                                                      #error here         -^-
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='8cfbb7ef910936ac801e4d07ae46599041206743') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='3f2329c9adfbccd9a84f52c906e936a42da18cb8') ,

                                         expiration=1480984776874,
                                         quoted_rate=binascii.unhexlify('0b54a1d6'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('0186a0'),
                                         order_id=binascii.unhexlify('1924ae6635e34cdca8137861434d9ede'),
                                         ),
                                signature=binascii.unhexlify('1f61697158580925b64ba9b93677a47f996deac9529d98e15ee90fcc240b098ab84f2324a4ccab092a38f8720537636ef1d012903ac27697f184cc43269975a420')
                             )
        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483649,0,1],
                              return_address_n=[2147483692,2147483708,2147483648,0,0]
                            )
        try:
            sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify('8cfbb7ef910936ac801e4d07ae46599041206743'),
            value=146207570000000000,
            address_type=3,
            exchange_type=exchange_type_out1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange deposit amount error')
            print "Negative Test Passed (test_ethereum_exch_dep_amount_error)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_exch_withdrawal_cointype_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)
        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('01a69189'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltx',
                                              #error here   -^-
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,
  
                                         deposit_amount=binascii.unhexlify('02076f02a152b400'),
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='8cfbb7ef910936ac801e4d07ae46599041206743') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='3f2329c9adfbccd9a84f52c906e936a42da18cb8') ,

                                         expiration=1480984776874,
                                         quoted_rate=binascii.unhexlify('0b54a1d6'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('0186a0'),
                                         order_id=binascii.unhexlify('1924ae6635e34cdca8137861434d9ede'),
                                         ),
                                signature=binascii.unhexlify('1f61697158580925b64ba9b93677a47f996deac9529d98e15ee90fcc240b098ab84f2324a4ccab092a38f8720537636ef1d012903ac27697f184cc43269975a420')
                             )
        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483649,0,1],
                              return_address_n=[2147483692,2147483708,2147483648,0,0]
                            )
        try:
            sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=01,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify('8cfbb7ef910936ac801e4d07ae46599041206743'),
            value=146207570000000000,
            address_type=3,
            exchange_type=exchange_type_out1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange withdrawal coin type error')
            print "Negative Test Passed (test_ethereum_exch_withdrawal_cointype_error)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

   
 
'''
    def test_ethereum_exch_withdrawal_addr_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount=struct.pack('<Q', 98765),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPg') , 
                                                                    #error here          -^-
  
                                         deposit_amount=int_to_big_endian(12345678901234567890),
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='1d1c328764a41bda0492b66baa30c4a339ff85ef') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='17ba4cfb053d3b2e56aec2ea36c041741dafc8ec') ,

                                         expiration=1471627016859,
                                         quoted_rate=struct.pack('<Q', 15878378378),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=struct.pack('<Q', 100000),
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

        try:
	    signature_der = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify('1d1c328764a41bda0492b66baa30c4a339ff85ef'),
            value=12345678901234567890,
            address_type=3,
            exchange_type=exchange_type_out1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange withdrawal address error')
            print "Negative Test Passed (test_ethereum_exch_withdrawal_addr_error)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_exch_return_cointype_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount=struct.pack('<Q', 98765),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,
  
                                         deposit_amount=int_to_big_endian(12345678901234567890),
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth', 
                                                address='1d1c328764a41bda0492b66baa30c4a339ff85ef') , 

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='etx',  
                                              #error here   -^-
                                                address='17ba4cfb053d3b2e56aec2ea36c041741dafc8ec') ,

                                         expiration=1471627016859,
                                         quoted_rate=struct.pack('<Q', 15878378378),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=struct.pack('<Q', 100000),
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

        try:
	    signature_der = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify('1d1c328764a41bda0492b66baa30c4a339ff85ef'),
            value=12345678901234567890,
            address_type=3,
            exchange_type=exchange_type_out1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange return coin type error')
            print "Negative Test Passed (test_ethereum_exch_return_cointype_error)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_exch_return_addr_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount=struct.pack('<Q', 98765),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,
  
                                         deposit_amount=int_to_big_endian(12345678901234567890),
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='1d1c328764a41bda0492b66baa30c4a339ff85ef') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='17ba4cfb053d3b2e56aec2ea36c041741dafc8ecx') , 
                                                                              #error here       -^-

                                         expiration=1471627016859,
                                         quoted_rate=struct.pack('<Q', 15878378378),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=struct.pack('<Q', 100000),
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

        try:
	    signature_der = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify('1d1c328764a41bda0492b66baa30c4a339ff85ef'),
            value=12345678901234567890,
            address_type=3,
            exchange_type=exchange_type_out1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Exchange return address error')
            print "Negative Test Passed (test_ethereum_exch_return_addr_error)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)
''' 

if __name__ == '__main__':
    unittest.main()
