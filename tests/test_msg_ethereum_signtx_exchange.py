import unittest
import common
import binascii
import struct

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange

from rlp.utils import int_to_big_endian

class TestMsgEthereumSigntx(common.KeepKeyTest):

    def test_ethereum_signtx_nodata(self):
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
        sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify('1d1c328764a41bda0492b66baa30c4a339ff85ef'),
            value=12345678901234567890,
            address_type=3,
            exchange_type=exchange_type_out1,
            )

        self.assertEqual(sig_v, 28)
        self.assertEqual(binascii.hexlify(sig_r), 'a703218bb98bb28d584b0b2c66a42f810446a7862bf8c4f733d559a2d3323221')
        self.assertEqual(binascii.hexlify(sig_s), '41e92ce8e5a6d9c83ccd93fe57ec592c344ff4fc01d2e9e2c70cbd01b1a3640c')
        self.assertEqual(binascii.hexlify(hash), '6e7bec5ab02b87fb32b08a1a304a4bf7a8da105b57203870989b6617affdf6f7')
        self.assertEqual(binascii.hexlify(signature_der), '3045022100a703218bb98bb28d584b0b2c66a42f810446a7862bf8c4f733d559a2d3323221022041e92ce8e5a6d9c83ccd93fe57ec592c344ff4fc01d2e9e2c70cbd01b1a3640c')

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)
if __name__ == '__main__':
    unittest.main()
