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
                                         withdrawal_amount=43704551,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LYXTv5RdsPYKC4qGmb6x6SuKoFMxUdSjLQ') ,
  
                                         deposit_amount=280700, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1MjjF2aaRe5Hii8x3jzWKjeoUXrNRiWNzd') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='14qUcU3sWMC8Ui4fS4e7yDy3iziCUvvZPd') ,

                                         expiration=1470782688764,
                                         quoted_rate=15605468750,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=100000,
                                         order_id=binascii.unhexlify('df138bd6ebc648f78338993ff1f66d26'),
                                         ),
                                signature=binascii.unhexlify('20b422966b75a5bd0fece6568298024b3261c33d72948b53e342f9c257f5d8e0624bf8a9cde8fcfbbc421181c9639c8c5cc19300fd0b3635880377887c61beaa09')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483648,0,0],
                              return_address_n=[2147483692,2147483648,2147483650,0,2],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=280700, 
                              address='1MjjF2aaRe5Hii8x3jzWKjeoUXrNRiWNzd',
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
                                         withdrawal_amount=43704551,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LYXTv5RdsPYKC4qGmb6x6SuKoFMxUdSjLQ') ,
  
#                                         deposit_amount=280700,   << error added here!!!
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1MjjF2aaRe5Hii8x3jzWKjeoUXrNRiWNzd') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='14qUcU3sWMC8Ui4fS4e7yDy3iziCUvvZPd') ,

                                         expiration=1470782688764,
                                         quoted_rate=15605468750,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=100000,
                                         order_id=binascii.unhexlify('df138bd6ebc648f78338993ff1f66d26'),
                                         ),
                                signature=binascii.unhexlify('20b422966b75a5bd0fece6568298024b3261c33d72948b53e342f9c257f5d8e0624bf8a9cde8fcfbbc421181c9639c8c5cc19300fd0b3635880377887c61beaa09')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483648,0,0],
                              return_address_n=[2147483692,2147483648,2147483650,0,2],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=280700, 
                              address='1MjjF2aaRe5Hii8x3jzWKjeoUXrNRiWNzd',
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
                                         withdrawal_amount=43704551,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LYXTv5RdsPYKC4qGmb6x6SuKoFMxUdSjLQ') ,
  
                                         deposit_amount=280700, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1MjjF2aaRe5Hii8x3jzWKjeoUXrNRiWNzd') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='14qUcU3sWMC8Ui4fS4e7yDy3iziCUvvZPd') ,

                                         expiration=1470782688764,
                                         quoted_rate=15605468750,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=100000,
                                         order_id=binascii.unhexlify('df138bd6ebc648f78338993ff1f66d26'),
                                         ),
                                signature=binascii.unhexlify('20b422966b75a5bd0fece6568298024b3261c33d72948b53e342f9c257f5d8e0624bf8a9cde8fcfbbc421181c9639c8c5cc19300fd0b3635880377887c61beaa09')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Bitcoin', # <<< error added here!!!
                              withdrawal_address_n=[2147483692,2147483650,2147483648,0,0],
                              return_address_n=[2147483692,2147483648,2147483650,0,2],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=280700, 
                              address='1MjjF2aaRe5Hii8x3jzWKjeoUXrNRiWNzd',
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
                                         withdrawal_amount=43704551,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LYXTv5RdsPYKC4qGmb6x6SuKoFMxUdSjLQ') ,
  
                                         deposit_amount=280700, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1MjjF2aaRe5Hii8x3jzWKjeoUXrNRiWNzd') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='14qUcU3sWMC8Ui4fS4e7yDy3iziCUvvZPd') ,

                                         expiration=1470782688764,
                                         quoted_rate=15605468750,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=100000,
                                         order_id=binascii.unhexlify('df138bd6ebc648f78338993ff1f66d26'),
                                         ),
                                signature=binascii.unhexlify('20b422966b75a5bd0fece6568298024b3261c33d72948b53e342f9c257f5d8e0624bf8a9cde8fcfbbc421181c9639c8c5cc19300fd0b3635880377887c61beaa09')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483648,0,1],  # <<< error added here!!!
                              return_address_n=[2147483692,2147483648,2147483650,0,2],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=280700, 
                              address='1MjjF2aaRe5Hii8x3jzWKjeoUXrNRiWNzd',
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
                                         withdrawal_amount=43704551,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LYXTv5RdsPYKC4qGmb6x6SuKoFMxUdSjLQ') ,
  
                                         deposit_amount=280700, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1MjjF2aaRe5Hii8x3jzWKjeoUXrNRiWNzd') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='14qUcU3sWMC8Ui4fS4e7yDy3iziCUvvZPd') ,

                                         expiration=1470782688764,
                                         quoted_rate=15605468750,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=100000,
                                         order_id=binascii.unhexlify('df138bd6ebc648f78338993ff1f66d26'),
                                         ),
                                signature=binascii.unhexlify('20b422966b75a5bd0fece6568298024b3261c33d72948b53e342f9c257f5d8e0624bf8a9cde8fcfbbc421181c9639c8c5cc19300fd0b3635880377887c61beaa09')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483648,0,0],
                              return_address_n=[2147483692,2147483648,2147483650,0,3],  # <<< error added here!
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=280700, 
                              address='1MjjF2aaRe5Hii8x3jzWKjeoUXrNRiWNzd',
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
                                         withdrawal_amount=43704551,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LYXTv5RdsPYKC4qGmb6x6SuKoFMxUdSjLQ') ,
  
                                         deposit_amount=280700, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='1MjjF2aaRe5Hii8x3jzWKjeoUXrNRiWNzd') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='14qUcU3sWMC8Ui4fS4e7yDy3iziCUvvZPd') ,

                                         expiration=1470782688764,
                                         quoted_rate=15605468750,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=100000,
                                         order_id=binascii.unhexlify('df138bd6ebc648f78338993ff1f66d26'),
                                         ),
                                signature=binascii.unhexlify('20b422966b75a5bd0fece6568298024b3261c33d72948b53e342f9c257f5d8e0624bf8a9cde8fcfbbc421181c9639c8c5cc19300fd0b3635880377887c61beaa09')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Litecoin',
                              withdrawal_address_n=[2147483692,2147483650,2147483648,0,0],
                              return_address_n=[2147483692,2147483648,2147483650,0,2],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=280700, 
                              address='1MjjF2aaRe5Hii8x3jzWKjeoUXrNRiWNzd',
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
                                         withdrawal_amount=605567,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='15jYdch7oghoPFDBQz8XDerbL382aT4U9e') ,
  
                                         deposit_amount=99900000, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LRdksqHsy16F2JXHjprmfRXpC7GK7wkCKz') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,

                                         expiration=1470785739719,
                                         quoted_rate=636203,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=30000,
                                         order_id=binascii.unhexlify('4a7dd90f344e4cf5914fc86c0de4009c'),
                                         ),
                                signature=binascii.unhexlify('1f47ea5abd1ea71c2b77288eeccc8340fcc4a8f453d3751a7d91c4b8f5d0ae99cb7499b763aaf89d49a8576c789b6acd858a9e3cbaee4579613a47a1a69b5ba637')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Bitcoin',
                              withdrawal_address_n=[2147483692,2147483648,2147483648,0,4],
                              return_address_n=[2147483692,2147483650,2147483648,0,1],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=99900000, 
                              address='LRdksqHsy16F2JXHjprmfRXpC7GK7wkCKz',
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

    def test_ltc_to_btc_withdrawal_address_error(self):
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
                                         withdrawal_amount=605567,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='15jYdch7oghoPFDBQz8XDerbL382aT4U9e') ,
  
                                         deposit_amount=99900000, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LRdksqHsy16F2JXHjprmfRXpC7GK7wkCKz') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,

                                         expiration=1470785739719,
                                         quoted_rate=636203,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=30000,
                                         order_id=binascii.unhexlify('4a7dd90f344e4cf5914fc86c0de4009c'),
                                         ),
                                signature=binascii.unhexlify('1f47ea5abd1ea71c2b77288eeccc8340fcc4a8f453d3751a7d91c4b8f5d0ae99cb7499b763aaf89d49a8576c789b6acd858a9e3cbaee4579613a47a1a69b5ba637')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Bitcoin',
                              withdrawal_address_n=[2147483692,2147483648,2147483648,0,5], #<<< Added error here
                              return_address_n=[2147483692,2147483650,2147483648,0,1],
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=99900000, 
                              address='LRdksqHsy16F2JXHjprmfRXpC7GK7wkCKz',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )

        try:
            self.client.sign_tx('Litecoin', [inp1, ], [out1, ]) # 
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_ltc_to_btc_withdrawal_address_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("Exchange1")
        self.client.apply_policy('Exchange1', 0)

    def test_ltc_to_btc_return_address_error(self):
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
                                         withdrawal_amount=605567,
                                         withdrawal_address=proto_exchange.ExchangeAddress(
                                                coin_type='btc',
                                                address='15jYdch7oghoPFDBQz8XDerbL382aT4U9e') ,
  
                                         deposit_amount=99900000, 
                                         deposit_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LRdksqHsy16F2JXHjprmfRXpC7GK7wkCKz') ,

                                         return_address=proto_exchange.ExchangeAddress(
                                                coin_type='ltc',
                                                address='LgCD3vmz2TkYGbaDDy1YRyT4JwL95XpYPw') ,

                                         expiration=1470785739719,
                                         quoted_rate=636203,

                                         api_key=binascii.unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                                         miner_fee=30000,
                                         order_id=binascii.unhexlify('4a7dd90f344e4cf5914fc86c0de4009c'),
                                         ),
                                signature=binascii.unhexlify('1f47ea5abd1ea71c2b77288eeccc8340fcc4a8f453d3751a7d91c4b8f5d0ae99cb7499b763aaf89d49a8576c789b6acd858a9e3cbaee4579613a47a1a69b5ba637')
                             )

        exchange_type_out1=proto_types.ExchangeType(
                              signed_exchange_response=signed_exchange_out1,
                              withdrawal_coin_name='Bitcoin',
                              withdrawal_address_n=[2147483692,2147483648,2147483648,0,4], 
                              return_address_n=[2147483692,2147483650,2147483648,0,2], #<<< Added error here
                            )
        # Exhange Output address
        out1 = proto_types.TxOutputType(
                              amount=99900000, 
                              address='LRdksqHsy16F2JXHjprmfRXpC7GK7wkCKz',
                              script_type=proto_types.PAYTOADDRESS,
                              address_type=3,
                              exchange_type=exchange_type_out1,
                              )
        try:
            self.client.sign_tx('Litecoin', [inp1, ], [out1, ]) # << error added here!!!
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_ltc_to_btc_return_address_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

        #reset policy ("Exchange1")
        self.client.apply_policy('Exchange1', 0)

if __name__ == '__main__':
    unittest.main()

