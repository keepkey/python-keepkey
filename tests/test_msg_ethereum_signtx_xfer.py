import unittest
import common
import binascii
import struct

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.client import CallException

from rlp.utils import int_to_big_endian

class TestMsgEthereumSigntx(common.KeepKeyTest):

    def test_ethereum_tx_xfer_acc1(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount=struct.pack('<Q', 98765),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,
  
                                         deposit_amount=int_to_big_endian(1234567890123456789),
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
        sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            value=12345678901234567890,
	    to_n=[0x8000002c, 0x8000003c, 1, 0, 0],
            address_type=1,
            exchange_type=exchange_type_out1,
            )

        self.assertEqual(sig_v, 27)
        self.assertEqual(binascii.hexlify(sig_r), '99f70cb618893ed3489add3de2adc0a3597bb59f683b67feb67f14145bef6766')
        self.assertEqual(binascii.hexlify(sig_s), '03c76425482270f1c720cb3c457a91b3d9e55848f21fdbde949e075fda344ab7')
        self.assertEqual(binascii.hexlify(hash), '4cc3cd55e89f68f3bab16eeb94bc50c53fec6e8946e749a85be390b06cd09f42')
        self.assertEqual(binascii.hexlify(signature_der), '304502210099f70cb618893ed3489add3de2adc0a3597bb59f683b67feb67f14145bef6766022003c76425482270f1c720cb3c457a91b3d9e55848f21fdbde949e075fda344ab7')

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)


    def test_ethereum_tx_xfer_acc2(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount=struct.pack('<Q', 98765),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,
  
                                         deposit_amount=int_to_big_endian(1234567890123456789),
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
        sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            value=12345678901234567890,
	    to_n=[0x8000002c, 0x8000003c, 2, 0, 0],
            address_type=1,
            exchange_type=exchange_type_out1,
            )

        self.assertEqual(sig_v, 28)
        self.assertEqual(binascii.hexlify(sig_r), '1c1949e8a261f8abfc40f4b6230fd69d7ce14c8d5ca7629af61ceb4ba0ea0b45')
        self.assertEqual(binascii.hexlify(sig_s), '59c450dce64d38aba22527353a8708255859c9c25abbfca07a19cf180d5a3858')
        self.assertEqual(binascii.hexlify(hash), '77e95b8843f6fd5f27c37a3ced1a1369a236e566ed0fea45a7a57d278c590860')
        self.assertEqual(binascii.hexlify(signature_der), '304402201c1949e8a261f8abfc40f4b6230fd69d7ce14c8d5ca7629af61ceb4ba0ea0b45022059c450dce64d38aba22527353a8708255859c9c25abbfca07a19cf180d5a3858')

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_xfer_account_path_error_0(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount=struct.pack('<Q', 98765),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,
  
                                         deposit_amount=int_to_big_endian(1234567890123456789),
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
	    to_n=[0x8000002a, 0x8000003c, 1, 0, 0],  
            #error here   -^-
            value=12345678901234567890,
            address_type=1,
            exchange_type=exchange_type_out1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Failed to compile output')
            print "Negative Test Passed (test_ethereum_xfer_account_path_error_0)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)



    def test_ethereum_xfer_account_path_error_1(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount=struct.pack('<Q', 98765),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,
  
                                         deposit_amount=int_to_big_endian(1234567890123456789),
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
	    to_n=[0x8000002c, 0x80000030, 1, 0, 0], 
                    #error here       -^- 
            value=12345678901234567890,
            address_type=1,
            exchange_type=exchange_type_out1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Failed to compile output')
            print "Negative Test Passed (test_ethereum_xfer_account_path_error_1)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_xfer_account_path_error_2(self):
        self.setup_mnemonic_nopin_nopassphrase()
	self.client.apply_policy('ShapeShift', 1)

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                response=proto_exchange.ExchangeResponse(
                                         withdrawal_amount=struct.pack('<Q', 98765),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,
  
                                         deposit_amount=int_to_big_endian(1234567890123456789),
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
	    to_n=[0x8000002c, 0x8000003c, 1, 1, 0],  
                           #error here      -^- 
            value=12345678901234567890,
            address_type=1,
            exchange_type=exchange_type_out1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Failed to compile output')
            print "Negative Test Passed (test_ethereum_xfer_account_path_error_2)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ethereum_xfer_account_path_error_3(self):
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
	    to_n=[0x8000002c, 0x8000003c, 1, 0, 1],  
                                #error here    -^-
            value=12345678901234567890,
            address_type=1,
            exchange_type=exchange_type_out1,
            )
        except CallException as e:
            self.assertEqual(e.args[1], 'Failed to compile output')
            print "Negative Test Passed (test_ethereum_xfer_account_path_error_2)!" 
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

if __name__ == '__main__':
    unittest.main()
