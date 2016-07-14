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
        self.client.apply_policy('ShapeShift', 1)
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
                                         return_address=proto_exchange.ExchangeAddress(address='1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCG'), 
                                         api_key='2'),
                          #Respect to Litecoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                          deposit_address=proto_exchange.ExchangeAddress(address='Li9Hjd2NFuEz8c1ffd9C1huEED6qvDuJSh'),  
                          deposit_amount=22,
                          expiration=5,
                          quoted_rate=2,
                          signature=binascii.unhexlify('c209541ec5d02677da407caca63c2e5e0a7ebfdb4bfaac82539b139f9e1e9d7c391c304a3341988e5eaba849e0e9cb291d73b2c25eb8b82a360dae8200e2c098'),
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
        self.client.apply_policy('ShapeShift', 1)

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
                                         return_address=proto_exchange.ExchangeAddress(address='LZPNdpJWH6ffEzNCxUSp1eCanazMBBu6xQ'),
                                         api_key='2'),
                          #Respect to Bitcoin node "44'/44'/44'/0/0([0x8000002c, 0x8000002c, 0x8000002c, 0, 0 ]) "
                          deposit_address=proto_exchange.ExchangeAddress(address='1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCG'), 
                          deposit_amount=22,
                          expiration=5,
                          quoted_rate=2,
                          signature=binascii.unhexlify('a7c5eef214de06fa13b402c8435ff004afc33f601b5322a2950f8351752f5cf7413645241e76454bbb587fb139cf443f1b027d70da1b12aee2114506fa7d6c14cc'),
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


    def test_incorrect_withdrawal_amount(self):           
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)
        # tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
        # input 0: 0.0039 BTC

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        exchange_response_out1=proto_exchange.ExchangeResponse(
                          request= proto_exchange.ExchangeRequest(
                                         # <<< Error injected (Correct value is 390000 - 10000) >>>
                                         withdrawal_amount=390000 - 1000,     
                                         withdrawal_address=proto_exchange.ExchangeAddress(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1'),
                                         withdrawal_coin_type='Bitcoin',
                                         deposit_coin_type='Litecoin',
                                         return_address=proto_exchange.ExchangeAddress(address='1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCG'), 
                                         api_key='2'),
                          deposit_address=proto_exchange.ExchangeAddress(address='Li9Hjd2NFuEz8c1ffd9C1huEED6qvDuJSh'),  
                          deposit_amount=22,
                          expiration=5,
                          quoted_rate=2,
                          signature=binascii.unhexlify('c209541ec5d02677da407caca63c2e5e0a7ebfdb4bfaac82539b139f9e1e9d7c391c304a3341988e5eaba849e0e9cb291d73b2c25eb8b82a360dae8200e2c098'),
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

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_incorrect_withdrawal_amount)!"
        else:
            self.assert_(False, "Failed to detect error condition")

    def test_deposit_address_error(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('ShapeShift', 1)
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
                                         return_address=proto_exchange.ExchangeAddress(address='1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCG'), 
                                         api_key='2'),
                          # <<< Error injected (Correct value is Li9Hjd2NFuEz8c1ffd9C1huEED6qvDuJSh) >>>
                          deposit_address=proto_exchange.ExchangeAddress(address='Li9Hjd2NFuEz8c1ffd9C1huEED6qvDuJSi'),  
                          deposit_amount=22,
                          expiration=5,
                          quoted_rate=2,
                          signature=binascii.unhexlify('c209541ec5d02677da407caca63c2e5e0a7ebfdb4bfaac82539b139f9e1e9d7c391c304a3341988e5eaba849e0e9cb291d73b2c25eb8b82a360dae8200e2c098'),
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

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_deposit_address_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

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

        exchange_response_out1=proto_exchange.ExchangeResponse(
                          request= proto_exchange.ExchangeRequest(
                                         withdrawal_amount=390000 - 10000, 
                                         withdrawal_address=proto_exchange.ExchangeAddress(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1'),
                                         withdrawal_coin_type='Bitcoin',
                                         deposit_coin_type='Litecoin',
                                         # <<< Error injected (Correct value is 1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCG) >>>
                                         return_address=proto_exchange.ExchangeAddress(address='1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCH'), 
                                         api_key='2'),
                          deposit_address=proto_exchange.ExchangeAddress(address='Li9Hjd2NFuEz8c1ffd9C1huEED6qvDuJSh'),  
                          deposit_amount=22,
                          expiration=5,
                          quoted_rate=2,
                          signature=binascii.unhexlify('c209541ec5d02677da407caca63c2e5e0a7ebfdb4bfaac82539b139f9e1e9d7c391c304a3341988e5eaba849e0e9cb291d73b2c25eb8b82a360dae8200e2c098'),
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


        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_return_address_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

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

        exchange_response_out1=proto_exchange.ExchangeResponse(
                          request= proto_exchange.ExchangeRequest(
                                         withdrawal_amount=390000 - 10000, 
                                         withdrawal_address=proto_exchange.ExchangeAddress(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1'),
                                         withdrawal_coin_type='Bitcoin',
                                         deposit_coin_type='Litecoin',
                                         return_address=proto_exchange.ExchangeAddress(address='1PvLUQiYBEzvsoKWVV9tjgqU1zjZnH7LCG'), 
                                         api_key='2'),
                          deposit_address=proto_exchange.ExchangeAddress(address='Li9Hjd2NFuEz8c1ffd9C1huEED6qvDuJSh'),  
                          deposit_amount=22,
                          expiration=5,
                          quoted_rate=2,
                          # <<< Error injected (Correct value is 'c209541ec5d02677da407caca63c2e5e0a7ebfdb4bfaac82539b139f9e1e9d7c391c304a3341988e5eaba849e0e9cb291d73b2c25eb8b82a360dae8200e2c098') >>>
                          signature=binascii.unhexlify('c209541ec5d02677da407caca63c2e5e0a7ebfdb4bfaac82539b139f9e1e9d7c391c304a3341988e5eaba849e0e9cb291d73b2c25eb8b82a360dae8200e2c099'), 
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

        try:
            self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        except CallException as e:
            self.assertEqual(e.args[0], proto_types.Failure_Other)
            print "Negative Test Passed (test_signature_error)!"
        else:
            self.assert_(False, "Failed to detect error condition")

if __name__ == '__main__':
    unittest.main()

