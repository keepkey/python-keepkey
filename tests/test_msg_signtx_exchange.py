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

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        exchange_response_out1=proto_exchange.ExchangeResponse(
                          request= proto_exchange.ExchangeRequest(
                                         withdrawal_amount=390000 - 10000, 
                                         withdrawal_address=proto_exchange.ExchangeAddress(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1'),
                                         withdrawal_coin_type='Bitcoin',
                                         deposit_coin_type='Litecoin',
                                         #Respect to Bitcoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                         return_address=proto_exchange.ExchangeAddress(address='1EWYfS5mkQTEssfTunjW6kmxyefhb4Z68D'), 
                                         api_key='2'),
                          #Respect to Litecoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                          deposit_address=proto_exchange.ExchangeAddress(address='LYjVvePbq4hJ8gMd5vioNmqjBs2yinWjWc'),  
                          deposit_amount=22,
                          expiration=5,
                          quoted_rate=2,
                          signature=binascii.unhexlify('1faf216844149abe1056dbf2fb47cf2c7144d44035be14ee0d7936eb386363cba5288d561cafc0c3012ae91af2c468edaec0faffc43fc96a3c0b827ffc88a72b1a'),
                          )

        exchange_type_out1=proto_types.ExchangeType(
                              response=exchange_response_out1,
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

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        exchange_response_out1=proto_exchange.ExchangeResponse(
                          request= proto_exchange.ExchangeRequest(
                                         withdrawal_amount=390000 - 10000, 
                                         withdrawal_address=proto_exchange.ExchangeAddress(address='LYtGrdDeqYUQnTkr5sHT2DKZLG7Hqg7HTK'),
                                         withdrawal_coin_type='Litecoin',
                                         deposit_coin_type='Bitcoin',
                                         #Respect to Bitcoin node "44'/44'/41/0/1([0x8000002c, 0x8000002c, 0x29, 0, 1 ]) "
                                         return_address=proto_exchange.ExchangeAddress(address='Le24wtC8xPgRKcViUQbsLB46uzixfiuPGy'),
                                         api_key='2'),
                          #Respect to Bitcoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                          deposit_address=proto_exchange.ExchangeAddress(address='1EWYfS5mkQTEssfTunjW6kmxyefhb4Z68D'), 
                          deposit_amount=22,
                          expiration=5,
                          quoted_rate=2,
                          signature=binascii.unhexlify('1f78f90f98a4428076a19e592b23d65186eace9b6833365b8e60aad0ca2b052154746679032f89f7761268f937461d871e10946de57a03fb95d777d8ca7cff73b4'),
                          )

        exchange_type_out1=proto_types.ExchangeType(
                              response=exchange_response_out1,
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

    def test_deposit_address_error(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        exchange_response_out1=proto_exchange.ExchangeResponse(
                          request= proto_exchange.ExchangeRequest(
                                         withdrawal_amount=390000 - 10000, 
                                         withdrawal_address=proto_exchange.ExchangeAddress(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1'),
                                         withdrawal_coin_type='Bitcoin',
                                         deposit_coin_type='Litecoin',
                                         #Respect to Bitcoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                         return_address=proto_exchange.ExchangeAddress(address='1EWYfS5mkQTEssfTunjW6kmxyefhb4Z68D'), 
                                         api_key='2'),
                          # error injected in deposit address. (Correct deposit address is  'LYjVvePbq4hJ8gMd5vioNmqjBs2yinWjWc'
                          deposit_address=proto_exchange.ExchangeAddress(address='LYjVvePbq4hJ8gMd5vioNmqjBeerrroooo'),  
                          deposit_amount=22,
                          expiration=5,
                          quoted_rate=2,
                          signature=binascii.unhexlify('1faf216844149abe1056dbf2fb47cf2c7144d44035be14ee0d7936eb386363cba5288d561cafc0c3012ae91af2c468edaec0faffc43fc96a3c0b827ffc88a72b1a'),
                          )

        exchange_type_out1=proto_types.ExchangeType(
                              response=exchange_response_out1,
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
                
            ])

            try:
               self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
            except CallException as e:
               self.assertEqual(e.args[0], proto_types.Failure_Other)
               print "TEST PASSED!"
            else:
               self.assert_(False, "Faile to detect error condition")

    def test_return_address_error(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        exchange_response_out1=proto_exchange.ExchangeResponse(
                          request= proto_exchange.ExchangeRequest(
                                         withdrawal_amount=390000 - 10000, 
                                         withdrawal_address=proto_exchange.ExchangeAddress(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1'),
                                         withdrawal_coin_type='Bitcoin',
                                         deposit_coin_type='Litecoin',
                                         #error injected in return address. (Correct return address is 1EWYfS5mkQTEssfTunjW6kmxyefhb4Z68D)
                                         return_address=proto_exchange.ExchangeAddress(address='1EWYfS5mkQTEssfTunjW6kmxyefhb4ZEEE'), 
                                         api_key='2'),
                          #Respect to Litecoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                          deposit_address=proto_exchange.ExchangeAddress(address='LYjVvePbq4hJ8gMd5vioNmqjBs2yinWjWc'),  
                          deposit_amount=22,
                          expiration=5,
                          quoted_rate=2,
                          signature=binascii.unhexlify('1faf216844149abe1056dbf2fb47cf2c7144d44035be14ee0d7936eb386363cba5288d561cafc0c3012ae91af2c468edaec0faffc43fc96a3c0b827ffc88a72b1a'),
                          )

        exchange_type_out1=proto_types.ExchangeType(
                              response=exchange_response_out1,
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
            ])

            try:
               self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
            except CallException as e:
               self.assertEqual(e.args[0], proto_types.Failure_Other)
               print "TEST PASSED!"
            else:
               self.assert_(False, "Faile to detect error condition")

    def test_signature_error(self):
        self.setup_mnemonic_nopin_nopassphrase()

        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        exchange_response_out1=proto_exchange.ExchangeResponse(
                          request= proto_exchange.ExchangeRequest(
                                         withdrawal_amount=390000 - 10000, 
                                         withdrawal_address=proto_exchange.ExchangeAddress(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1'),
                                         withdrawal_coin_type='Bitcoin',
                                         deposit_coin_type='Litecoin',
                                         #Respect to Bitcoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                                         return_address=proto_exchange.ExchangeAddress(address='1EWYfS5mkQTEssfTunjW6kmxyefhb4Z68D'), 
                                         api_key='2'),
                          #Respect to Litecoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                          deposit_address=proto_exchange.ExchangeAddress(address='LYjVvePbq4hJ8gMd5vioNmqjBs2yinWjWc'),  
                          deposit_amount=22,
                          expiration=5,
                          quoted_rate=2,
                          # error injected in signature (Correct signature is '1faf216844149abe1056dbf2fb47cf2c7144d44035be14ee0d7936eb386363cba5288d561cafc0c3012ae91af2c468edaec0faffc43fc96a3c0b827ffc88a72b1a')
                          signature=binascii.unhexlify('1faf216844149abe1056dbf2fb47cf2c7144d44035be14ee0d7936eb386363cba5288d561cafc0c3012ae91af2c468edaec0faffc43fc96a3c0b827ffc88a72b1E'),
                          )

        exchange_type_out1=proto_types.ExchangeType(
                              response=exchange_response_out1,
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
            ])

            try:
               self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
            except CallException as e:
               self.assertEqual(e.args[0], proto_types.Failure_Other)
               print "TEST PASSED!"
               
            else:
               self.assert_(False, "Faile to detect error condition")
               
if __name__ == '__main__':
    unittest.main()

