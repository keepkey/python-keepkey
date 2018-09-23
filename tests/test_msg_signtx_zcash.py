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

import unittest
import common
import binascii

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tx_api import TxApiZcashTestnet

class TestMsgSigntx(common.KeepKeyTest):

    def test_transparent_one_one(self):
        self.setup_mnemonic_allallall()

        # tx: 08a18fc5a768f8b08c4f5b53a502e2b182107b90b5b4e5f23294074670e57357
        # input 0: 9.99884999 TAZ
        inp1 = proto_types.TxInputType(address_n=[2147483692, 2147483649, 2147483648, 0, 0],  # t1YxYiYy8Hjq5HBN7sioDtTs98SX2SzW5q8
                             #amount=999884999,
                             prev_hash=binascii.unhexlify(b'08a18fc5a768f8b08c4f5b53a502e2b182107b90b5b4e5f23294074670e57357'),
                             prev_index=0,
                             )

        out1 = proto_types.TxOutputType(address='tmJ1xYxP8XNTtCoDgvdmQPSrxh5qZJgy65Z',
                              amount=999884999 - 1940,
                              script_type=proto_types.PAYTOADDRESS,
                              )

        with self.client:
            self.client.set_tx_api(TxApiZcashTestnet)
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"08a18fc5a768f8b08c4f5b53a502e2b182107b90b5b4e5f23294074670e57357"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify(b"08a18fc5a768f8b08c4f5b53a502e2b182107b90b5b4e5f23294074670e57357"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify(b"08a18fc5a768f8b08c4f5b53a502e2b182107b90b5b4e5f23294074670e57357"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify(b"08a18fc5a768f8b08c4f5b53a502e2b182107b90b5b4e5f23294074670e57357"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=2, tx_hash=binascii.unhexlify(b"08a18fc5a768f8b08c4f5b53a502e2b182107b90b5b4e5f23294074670e57357"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),

                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),

            ])

            (signatures, serialized_tx) = self.client.sign_tx('Zcash Testnet', [inp1, ], [out1, ])

        self.assertEqual(binascii.hexlify(serialized_tx), b'01000000015773e57046079432f2e5b4b5907b1082b1e202a5535b4f8cb0f868a7c58fa108000000006b483045022100cb92f4253705272142f8684489249cfdbb66d84a47872fca66597eb835474484022049916cb566bd431372be959e4239c80f72181922b0c5443c89d21aec27342c4a0121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff013301993b000000001976a9145b157a678a10021243307e4bb58f36375aa80e1088ac00000000')

    def test_transparent_one_one_fee_too_high(self):
        self.setup_mnemonic_allallall()

        # tx:  c8ff96d72e80c01792146d8f0970cbc970882fb315ab1ae043342b4d455e6b56
        # input 0: 10.0 TAZ

        inp1 = proto_types.TxInputType(address_n=[2147483692, 2147483649, 2147483648, 0, 0],  # t1YxYiYy8Hjq5HBN7sioDtTs98SX2SzW5q8
                             # amount=1000000000,
                             prev_hash=binascii.unhexlify(b'c8ff96d72e80c01792146d8f0970cbc970882fb315ab1ae043342b4d455e6b56'),
                             prev_index=0,
                             )

        out1 = proto_types.TxOutputType(address='tmJ1xYxP8XNTtCoDgvdmQPSrxh5qZJgy65Z',
                              amount=100000000- 1940,
                              script_type=proto_types.PAYTOADDRESS,
                              )

        with self.client:
            self.client.set_tx_api(TxApiZcashTestnet)
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"c8ff96d72e80c01792146d8f0970cbc970882fb315ab1ae043342b4d455e6b56"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify(b"c8ff96d72e80c01792146d8f0970cbc970882fb315ab1ae043342b4d455e6b56"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify(b"c8ff96d72e80c01792146d8f0970cbc970882fb315ab1ae043342b4d455e6b56"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify(b"c8ff96d72e80c01792146d8f0970cbc970882fb315ab1ae043342b4d455e6b56"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_FeeOverThreshold),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),

                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),

            ])

            (signatures, serialized_tx) = self.client.sign_tx('Zcash Testnet', [inp1, ], [out1, ])

        self.assertEqual(binascii.hexlify(serialized_tx), b'0100000001566b5e454d2b3443e01aab15b32f8870c9cb70098f6d149217c0802ed796ffc8000000006a4730440220226750799c61f8914df7cf8a7623bbcde3197e0eb83dac9905c2ff5f4a29c41a02203215a36c14ddbf82d57dc69476f7a08b6a4f2349960ae01a5a489b974f262a110121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff016cd9f505000000001976a9145b157a678a10021243307e4bb58f36375aa80e1088ac00000000')

    def test_shieldedIn_one_one_fee_1(self):
        self.setup_mnemonic_allallall()

        # tx:  43d133a5bb5d1764368726707584c4eb1faf2a696a832325a7608d6b5e72aeca
        # input 0: 19.99740373 TAZ

        inp1 = proto_types.TxInputType(address_n=[2147483692, 2147483649, 2147483648, 0, 0],  # tmJ1xYxP8XNTtCoDgvdmQPSrxh5qZJgy65Z
                             # amount=1999740373,
                             prev_hash=binascii.unhexlify(b'43d133a5bb5d1764368726707584c4eb1faf2a696a832325a7608d6b5e72aeca'),
                             prev_index=0,
                             )

        out1 = proto_types.TxOutputType(address='tmJ1xYxP8XNTtCoDgvdmQPSrxh5qZJgy65Z',
                              amount=1999740373 - 1940,
                              script_type=proto_types.PAYTOADDRESS,
                              )

        with self.client:
            self.client.set_tx_api(TxApiZcashTestnet)
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"43d133a5bb5d1764368726707584c4eb1faf2a696a832325a7608d6b5e72aeca"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify(b"43d133a5bb5d1764368726707584c4eb1faf2a696a832325a7608d6b5e72aeca"))),
                proto.TxRequest(request_type=proto_types.TXEXTRADATA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"43d133a5bb5d1764368726707584c4eb1faf2a696a832325a7608d6b5e72aeca"),extra_data_offset=0, extra_data_len=1024)),
                proto.TxRequest(request_type=proto_types.TXEXTRADATA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"43d133a5bb5d1764368726707584c4eb1faf2a696a832325a7608d6b5e72aeca"),extra_data_offset=1024, extra_data_len=875)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),

                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),

            ])

            (signatures, serialized_tx) = self.client.sign_tx('Zcash Testnet', [inp1, ], [out1, ])

        self.assertEqual(binascii.hexlify(serialized_tx), b'0100000001caae725e6b8d60a72523836a692aaf1febc484757026873664175dbba533d143000000006b483045022100e3118845371537bcdcbe9071327769aea86704b0574adcd808673d53bdd1a18f022070903ffa067b3ae02613f4652d2a8101a946c2c87157ff08272ae50e25d91cbe0121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff0141963177000000001976a9145b157a678a10021243307e4bb58f36375aa80e1088ac00000000')

    @unittest.expectedFailure # ZCash not yet supported
    def test_shieldedIn_one_one_fee_2(self):
        self.setup_mnemonic_allallall()

        # tx: c6eddfbedd5821baea352b79fbd0d793a55257111c46a79002844b86a1c872e1
        # input 0: 19.9973 TAZ

        inp1 = proto_types.TxInputType(address_n=[2147483692, 2147483649, 2147483648, 0, 0],  # t1YxYiYy8Hjq5HBN7sioDtTs98SX2SzW5q8
                             #amount=1999730000 TAZ
                             prev_hash=binascii.unhexlify(b'c6eddfbedd5821baea352b79fbd0d793a55257111c46a79002844b86a1c872e1'),
                             prev_index=0,
                             )

        out1 = proto_types.TxOutputType(address='tmJ1xYxP8XNTtCoDgvdmQPSrxh5qZJgy65Z',
                              amount=1997300000 - 1940,
                              script_type=proto_types.PAYTOADDRESS,
                              )

        with self.client:
            self.client.set_tx_api(TxApiZcashTestnet)
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"c6eddfbedd5821baea352b79fbd0d793a55257111c46a79002844b86a1c872e1"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify(b"c6eddfbedd5821baea352b79fbd0d793a55257111c46a79002844b86a1c872e1"))),
                proto.TxRequest(request_type=proto_types.TXEXTRADATA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"c6eddfbedd5821baea352b79fbd0d793a55257111c46a79002844b86a1c872e1"),extra_data_offset=0, extra_data_len=1024)),
                proto.TxRequest(request_type=proto_types.TXEXTRADATA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"c6eddfbedd5821baea352b79fbd0d793a55257111c46a79002844b86a1c872e1"),extra_data_offset=1024, extra_data_len=875)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures, serialized_tx) = self.client.sign_tx('Zcash Testnet', [inp1, ], [out1, ])

        self.assertEqual(binascii.hexlify(serialized_tx), b'0100000001e172c8a1864b840290a7461c115752a593d7d0fb792b35eaba2158ddbedfedc6000000006a473044022077f249005ac0d72936bf927d8b6b2a78b83749c31f35b7f86b6cd95852065a0c022027613dc308bc6230730f0f786071f93ab3080f10041f191f379baa47b14e42bf0121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff018c590c77000000001976a9145b157a678a10021243307e4bb58f36375aa80e1088ac00000000')

if __name__ == '__main__':
    unittest.main()

