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
import struct

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.client import CallException
from keepkeylib import tx_api

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
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('03cfd863'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,

                                         deposit_amount=binascii.unhexlify('0493e0'), #300000
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1EtCKS5SxoPeNnzrAjFpuNruBmq8EHvqdt') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='15jYdch7oghoPFDBQz8XDerbL382aT4U9e') ,

                                         expiration=1480964590181,
                                         quoted_rate=binascii.unhexlify('04f89e60b8'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('0186a0'),   #100000
                                         order_id=binascii.unhexlify('b026bddb3e74470bbab9146c4db58019'),
                                         ),
                                signature=binascii.unhexlify('1fd1f3bdb3ebd7b82956d5422352fa1a10d27b361f65b2293436a5c5059c3c9f1e4eb30632cce2511d0c892cdbe0cb28347a5d8d800eba1248fc71aa5b6379da5a')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692, 2147483650, 2147483649, 0, 1],
                              return_address_n=[2147483692,2147483648,2147483648,0,4]
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=300000,
                              address='1EtCKS5SxoPeNnzrAjFpuNruBmq8EHvqdt',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )
        with self.client:
            self.client.set_tx_api(tx_api.TxApiBitcoin)
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

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_ltc_to_eth_exchange(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)
        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC
        inp1 = proto_types.TxInputType(address_n=[0],  # 175AmUerJ2wxKmyMTWdTbeoFh3o4a5dmDJ  
                             # amount=2276970000000, ($22769.70)
                             prev_hash=binascii.unhexlify('4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c'),
                             prev_index=0,
                             )

        signed_exchange_out1=proto_exchange.SignedExchangeResponse(
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('01d23650d8380800'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='eth',
                                                address='0x3f2329c9adfbccd9a84f52c906e936a42da18cb8') ,
  
                                         deposit_amount=binascii.unhexlify('01ccec55'),
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LfbEZX7Q88zDxXJ8meuc8YKJTDCFeW51F3') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LQgMuyB7VMKB4NrEv5YwcBfbbwXgwH2uFD') ,

                                         expiration=1481074750525,
                                         quoted_rate=binascii.unhexlify('067d0007d7b2f400'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('2386f26fc10000'),
                                         order_id=binascii.unhexlify('b168e4ff7d634e35b2bba38ed2ba3098'),
                                         ),
                                signature=binascii.unhexlify('20b6a7c44f261906eba11ffae4a160f8ff98a8806ff9b2e233734aaa8f673ca0e401103c60660a57cf778a9078fa8b8cd586af5a94cd8284ffd9e285507b8e6bb9')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Ethereum',
                              withdrawal_address_n=[2147483692,2147483708,2147483648,0,0],
                              return_address_n=[2147483692,2147483650,2147483649,0,2]
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=30207061,
                              address='LfbEZX7Q88zDxXJ8meuc8YKJTDCFeW51F3',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )
        with self.client:
            self.client.set_tx_api(tx_api.TxApiBitcoin)
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify("4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify("4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify("4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify("4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=2, tx_hash=binascii.unhexlify("4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=3, tx_hash=binascii.unhexlify("4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=4, tx_hash=binascii.unhexlify("4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=5, tx_hash=binascii.unhexlify("4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=6, tx_hash=binascii.unhexlify("4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=7, tx_hash=binascii.unhexlify("4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=8, tx_hash=binascii.unhexlify("4a405a771b1c16af9059e01aa1de19ae1e143da6a5a8d130d1591875a93f9e0c"))),
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

    def test_signature_error0(self):
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
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('03cfd863'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,
  
                                         deposit_amount=binascii.unhexlify('0493e0'), #300000
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1EtCKS5SxoPeNnzrAjFpuNruBmq8EHvqdt') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='15jYdch7oghoPFDBQz8XDerbL382aT4U9e') ,

                                         expiration=1480964590181,
                                         quoted_rate=binascii.unhexlify('04f89e60b8'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('0186a0'),   #100000
                                         order_id=binascii.unhexlify('b026bddb3e74470bbab9146c4db58019'),
                                         ),
                                signature=binascii.unhexlify('0fd1f3bdb3ebd7b82956d5422352fa1a10d27b361f65b2293436a5c5059c3c9f1e4eb30632cce2511d0c892cdbe0cb28347a5d8d800eba1248fc71aa5b6379da5a')
                                                      #error -^-
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692, 2147483650, 2147483649, 0, 1],
                              return_address_n=[2147483692,2147483648,2147483648,0,4]
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=300000,
                              address='1EtCKS5SxoPeNnzrAjFpuNruBmq8EHvqdt',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )
        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEndsWith(e.args[1], 'Exchange signature error')
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)

    def test_signature_error1(self):
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
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('03cfd863'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,

                                         deposit_amount=binascii.unhexlify('0493e0'), #300000
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1EtCKS5SxoPeNnzrAjFpuNruBmq8EHvqdt') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='15jYdch7oghoPFDBQz8XDerbL382aT4U9e') ,

                                         expiration=1480964590181,
                                         quoted_rate=binascii.unhexlify('04f89e60b8'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('0186a0'),   #100000
                                         order_id=binascii.unhexlify('b026bddb3e74470bbab9146c4db58019'),
                                         ),
                                signature=binascii.unhexlify('1fd1f3bdb3ebd7b82956d5422352fa1a10d27b361f65b2293436a5c5059c3c9f1e4eb30632cce2511d0c892cdbe0cb28347a5d8d800eba1248fc71aa5b6379da5b')
                                                                                                                                                                                       #error -^-
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692, 2147483650, 2147483649, 0, 1],
                              return_address_n=[2147483692,2147483648,2147483648,0,4]
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=300000,
                              address='1EtCKS5SxoPeNnzrAjFpuNruBmq8EHvqdt',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )
        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEndsWith(e.args[1], 'Exchange signature error')
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
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('03cfd863'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,
  
                                         deposit_amount=binascii.unhexlify('0493e0'), #300000
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1EtCKS5SxoPeNnzrAjFpuNruBmq8EHvqdt') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='15jYdch7oghoPFDBQz8XDerbL382aT4U9e') ,

                                         expiration=1480964590181,
                                         quoted_rate=binascii.unhexlify('04f89e60b8'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('0186a0'),   #100000
                                         order_id=binascii.unhexlify('b026bddb3e74470bbab9146c4db58019'),
                                         ),
                                signature=binascii.unhexlify('1fd1f3bdb3ebd7b82956d5422352fa1a10d27b361f65b2293436a5c5059c3c9f1e4eb30632cce2511d0c892cdbe0cb28347a5d8d800eba1248fc71aa5b6379da5a')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Dogecoin',
                                            #error -^-
                              withdrawal_address_n=[2147483692, 2147483650, 2147483649, 0, 1],
                              return_address_n=[2147483692,2147483648,2147483648,0,4]
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=300000,
                              address='1EtCKS5SxoPeNnzrAjFpuNruBmq8EHvqdt',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )
        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEndsWith(e.args[1], 'Exchange withdrawal coin type error')
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
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('03cfd863'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,

                                         deposit_amount=binascii.unhexlify('0493e0'), #300000
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1EtCKS5SxoPeNnzrAjFpuNruBmq8EHvqdt') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='15jYdch7oghoPFDBQz8XDerbL382aT4U9e') ,

                                         expiration=1480964590181,
                                         quoted_rate=binascii.unhexlify('04f89e60b8'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('0186a0'),   #100000
                                         order_id=binascii.unhexlify('b026bddb3e74470bbab9146c4db58019'),
                                         ),
                                signature=binascii.unhexlify('1fd1f3bdb3ebd7b82956d5422352fa1a10d27b361f65b2293436a5c5059c3c9f1e4eb30632cce2511d0c892cdbe0cb28347a5d8d800eba1248fc71aa5b6379da5a')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692, 2147483650, 2147483649, 0, 0],
                                                                                   #error -^-
                              return_address_n=[2147483692,2147483648,2147483648,0,4]
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=300000,
                              address='1EtCKS5SxoPeNnzrAjFpuNruBmq8EHvqdt',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )
        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEndsWith(e.args[1], 'Exchange withdrawal address error')
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
                                responseV2=proto_exchange.ExchangeResponseV2(
                                         withdrawal_amount=binascii.unhexlify('03cfd863'),
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V') ,

                                         deposit_amount=binascii.unhexlify('0493e0'), #300000
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1EtCKS5SxoPeNnzrAjFpuNruBmq8EHvqdt') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='15jYdch7oghoPFDBQz8XDerbL382aT4U9e') ,

                                         expiration=1480964590181,
                                         quoted_rate=binascii.unhexlify('04f89e60b8'),

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=binascii.unhexlify('0186a0'),   #100000
                                         order_id=binascii.unhexlify('b026bddb3e74470bbab9146c4db58019'),
                                         ),
                                signature=binascii.unhexlify('1fd1f3bdb3ebd7b82956d5422352fa1a10d27b361f65b2293436a5c5059c3c9f1e4eb30632cce2511d0c892cdbe0cb28347a5d8d800eba1248fc71aa5b6379da5a')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692, 2147483650, 2147483649, 0, 1],
                              return_address_n=[2147483692,2147483648,2147483648,0,5]
                                                                           #error -^-
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=300000,
                              address='1EtCKS5SxoPeNnzrAjFpuNruBmq8EHvqdt',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )
        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEndsWith(e.args[1], 'Exchange return address error')
        else:
            self.assert_(False, "Failed to detect error condition")


        #reset policy ("ShapeShift")
        self.client.apply_policy('ShapeShift', 0)
if __name__ == '__main__':
    unittest.main()

