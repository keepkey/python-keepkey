# This file is part of the KeepKey project.
#
# Copyright (C) 2018 KeepKey
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
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from keepkeylib import messages_nano_pb2 as proto
from keepkeylib import types_pb2 as types
from keepkeylib import nano

NANO_ACCOUNT_0_PATH = parse_path("m/44'/165'/0'")
NANO_ACCOUNT_0_ADDRESS = 'xrb_1bhbsc9yuh15anq3owu1izw1nk7bhhqefrkhfo954fyt8dk1q911buk1kk4c'
NANO_ACCOUNT_1_PATH = parse_path("m/44'/165'/1'")
NANO_ACCOUNT_1_ADDRESS = 'xrb_3p9ws1t6nx7r5xunf7khtbzqwa9ncjte9fmiy59eiyjkkfds6z5zgpom1cxs'
NANO_ACCOUNT_1_PUBLICKEY = 'd8fcc8344a74b81f7746964fd27f7e20f45474c3b670f0cec87a329357927c7f'
OTHER_ACCOUNT_3_PATH = parse_path("m/44'/100'/3'")
OTHER_ACCOUNT_3_ADDRESS = 'xrb_1x9k73o5icut7pr8khu9xcgtbaau6z6fh5fxxb5m9s3fpzuoe6aio9xjz4et'
OTHER_ACCOUNT_3_PUBLICKEY = '74f2286a382b7a2db0693f67ea9da4a11b27c8d78dbdea4733e42db7f7561110'
REP_OFFICIAL_1 = 'xrb_3arg3asgtigae3xckabaaewkx3bzsh7nwz7jkmjos79ihyaxwphhm6qgjps4'
REP_NANODE = 'xrb_1nanode8ngaakzbck8smq6ru9bethqwyehomf79sae1k7xd47dkidjqzffeg'
RECIPIENT_DONATIONS = 'xrb_3wm37qz19zhei7nzscjcopbrbnnachs4p1gnwo5oroi3qonw6inwgoeuufdp'
RECIPIENT_DONATIONS_PUBLICKEY = 'f2612dfe03fdec8169fcaa2aad9384d28853f22b01d4e5475c5601bd69c2429c'

class TestMsgNanoSignTx(common.KeepKeyTest):

    def test_encode_balance(self):
        self.assertEqual(nano.encode_balance(0), '00000000000000000000000000000000'.decode('hex'))
        self.assertEqual(nano.encode_balance(4440329590121742105910495447534801366), '03572d26b8163ca8016a76280cb011d6'.decode('hex'))
        self.assertEqual(nano.encode_balance(340282366920938463463374607431768211455), 'ffffffffffffffffffffffffffffffff'.decode('hex'))

    def test_block_1(self):
        self.setup_mnemonic_nopin_nopassphrase()
        res = self.client.nano_sign_tx(
            'Nano', NANO_ACCOUNT_0_PATH,
            link_hash='2e3249f1ffc09608d369e01a701bf03bd05509fab262086a59d09994d315e840'.decode('hex'),
            representative=REP_OFFICIAL_1,
            balance=9624176000000000000000000000000,
        )
        self.assertIsInstance(res, proto.NanoSignedTx)
        self.assertEqual(res.block_hash, '517565abb71bdccf03754421b1bcaee8327cfce7a571a844ae5392e851531ece'.decode('hex'))
        self.assertEqual(res.signature, 'e5449bd97ffcd555b435f1289ebf28be4ec4bc58915f7fbdda7283f6727b134b8fb1cdde4eafcb166f2a8a6642000ef3a088661d4100cd819d8bdddb64dd3a00'.decode('hex'))

    def test_block_2(self):
        self.setup_mnemonic_nopin_nopassphrase()
        res = self.client.nano_sign_tx(
            'Nano', NANO_ACCOUNT_0_PATH,
            parent_link='2e3249f1ffc09608d369e01a701bf03bd05509fab262086a59d09994d315e840'.decode('hex'),
            parent_representative=REP_OFFICIAL_1,
            parent_balance=9624176000000000000000000000000,
            representative=REP_NANODE,
            balance=9624176000000000000000000000000,
        )
        self.assertIsInstance(res, proto.NanoSignedTx)
        self.assertEqual(res.block_hash, '1a3ec7d5d246aa987d99fde40ff3cadb8833941391611ec9125014d7458ac406'.decode('hex'))
        self.assertEqual(res.signature, '992619296a0ffe80bfbf4f48739894c8288dde4dbb7f39225a644b4352acdec58e19e0899a18ffc68d89973438d5e6dd6a77e5ae707f03bc0c6544085175e30e'.decode('hex'))

    def test_block_3(self):
        self.setup_mnemonic_nopin_nopassphrase()
        res = self.client.nano_sign_tx(
            'Nano', NANO_ACCOUNT_0_PATH,
            grandparent_hash='517565abb71bdccf03754421b1bcaee8327cfce7a571a844ae5392e851531ece'.decode('hex'),
            parent_link='0000000000000000000000000000000000000000000000000000000000000000'.decode('hex'),
            parent_representative=REP_NANODE,
            parent_balance=9624176000000000000000000000000,
            link_hash='4f3d6ce7553bd16d0c03314efeb696dde1b2ae92a28e6346b5ed2cf6a8ff0d8b'.decode('hex'),
            representative=REP_NANODE,
            balance=19624176000000000000000000000000,
        )
        self.assertIsInstance(res, proto.NanoSignedTx)
        self.assertEqual(res.block_hash, '2df9eb25f4b7dd2e9174b47c45ab3987db23c38881fd70473ba1c7aff2519d32'.decode('hex'))
        self.assertEqual(res.signature, 'f0496f49b59a401322334dd7a7676ae4e894efea09be383bf55362e61eef8f526a247a6feefc3bbfa460abfdc6a21b59781fe6c97c4ee91b323868cdf0a4ed0f'.decode('hex'))

    def test_block_4(self):
        self.setup_mnemonic_nopin_nopassphrase()
        res = self.client.nano_sign_tx(
            'Nano', NANO_ACCOUNT_0_PATH,
            grandparent_hash='1a3ec7d5d246aa987d99fde40ff3cadb8833941391611ec9125014d7458ac406'.decode('hex'),
            parent_link='4f3d6ce7553bd16d0c03314efeb696dde1b2ae92a28e6346b5ed2cf6a8ff0d8b'.decode('hex'),
            parent_representative=REP_NANODE,
            parent_balance=19624176000000000000000000000000,
            link_recipient=RECIPIENT_DONATIONS,
            representative=REP_NANODE,
            balance=12624176000000000000000000000000,
        )
        self.assertIsInstance(res, proto.NanoSignedTx)
        self.assertEqual(res.block_hash, '30c1221a6985710a4d9d57f708cb1cf43a7ef51f933f49f7ae68550989c770f3'.decode('hex'))
        self.assertEqual(res.signature, 'd3da7079459fa3d16ceeaebc0905ac956d2b8dbaae21910ad2215fe8dc018f48c74c0bb06a68d9b78194395e3e33ed4c2a54c56a978e4245e761368fd6155a00'.decode('hex'))

    def test_block_5(self):
        self.setup_mnemonic_nopin_nopassphrase()
        res = self.client.nano_sign_tx(
            'Nano', NANO_ACCOUNT_0_PATH,
            grandparent_hash='2df9eb25f4b7dd2e9174b47c45ab3987db23c38881fd70473ba1c7aff2519d32'.decode('hex'),
            parent_link=RECIPIENT_DONATIONS_PUBLICKEY.decode('hex'),
            parent_representative=REP_NANODE,
            parent_balance=12624176000000000000000000000000,
            link_recipient_n=NANO_ACCOUNT_1_PATH,
            representative=REP_NANODE,
            balance=8624176000000000000000000000000,
        )
        self.assertIsInstance(res, proto.NanoSignedTx)
        self.assertEqual(res.block_hash, '09f4627f61ec90b66b9c87da06dca0090bbbd8644e3289dc95baa018d104a8d1'.decode('hex'))
        self.assertEqual(res.signature, 'a195b448b03afb3dc8e9f523cd74e065bddac1b9acef989504b59aca73ca6612aa06983fd3efa782d5230e2e17433d9a14ecffbc76d84d85d8099fb81cbf9a01'.decode('hex'))

    def test_block_6(self):
        self.setup_mnemonic_nopin_nopassphrase()
        res = self.client.nano_sign_tx(
            'Nano', NANO_ACCOUNT_0_PATH,
            tx_type=types.OutputAddressType.Value('TRANSFER'),
            grandparent_hash='30c1221a6985710a4d9d57f708cb1cf43a7ef51f933f49f7ae68550989c770f3'.decode('hex'),
            parent_link=NANO_ACCOUNT_1_PUBLICKEY.decode('hex'),
            parent_representative=REP_NANODE,
            parent_balance=8624176000000000000000000000000,
            link_recipient_n=NANO_ACCOUNT_1_PATH,
            representative=REP_NANODE,
            balance=4624176000000000000000000000000,
        )
        self.assertIsInstance(res, proto.NanoSignedTx)
        self.assertEqual(res.block_hash, '6ee110237ddfd250bb3d7962c058e4474eb83c244ecd6f1e924103a6a6467ab4'.decode('hex'))
        self.assertEqual(res.signature, '2dced1aedc3b1763d8875f1390726e4170936dc2fa5a57f739db08b810f3c2eb63d1f15661a7ad3b25e0f6a47552819cea53d458d3a009839f1839e3bc016301'.decode('hex'))

    def test_block_7(self):
        self.setup_mnemonic_nopin_nopassphrase()
        res = self.client.nano_sign_tx(
            'Nano', NANO_ACCOUNT_0_PATH,
            tx_type=types.OutputAddressType.Value('TRANSFER'),
            grandparent_hash='09f4627f61ec90b66b9c87da06dca0090bbbd8644e3289dc95baa018d104a8d1'.decode('hex'),
            parent_link=NANO_ACCOUNT_1_PUBLICKEY.decode('hex'),
            parent_representative=REP_NANODE,
            parent_balance=4624176000000000000000000000000,
            link_recipient_n=OTHER_ACCOUNT_3_PATH,
            representative=REP_NANODE,
            balance=4000076000000000000000000000000,
        )
        self.assertIsInstance(res, proto.NanoSignedTx)
        self.assertEqual(res.block_hash, 'bf190cba5a7491a3721811dda8f7aa9ec84a74c55d10a4c8c1f980bf931ef2ec'.decode('hex'))
        self.assertEqual(res.signature, 'b017e422fa2dd5853d85584e68a1fa967d38614737f32c434e7433bf7567fd47615d79a646c1e4de83e1e01ad34940a59451660e6e2eedb86d07cf1341853004'.decode('hex'))

    def test_invalid_block_1(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # Missing link_hash
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                representative=REP_OFFICIAL_1,
                balance=9624176000000000000000000000000,
            )

    def test_invalid_block_2(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # Missing representative
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                link_hash='2e3249f1ffc09608d369e01a701bf03bd05509fab262086a59d09994d315e840'.decode('hex'),
                balance=9624176000000000000000000000000,
            )

    def test_invalid_block_3(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # Missing balance
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                link_hash='2e3249f1ffc09608d369e01a701bf03bd05509fab262086a59d09994d315e840'.decode('hex'),
                representative=REP_OFFICIAL_1,
            )

    def test_invalid_block_4(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # Account first block cannot be 0 balance
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                link_hash='2e3249f1ffc09608d369e01a701bf03bd05509fab262086a59d09994d315e840'.decode('hex'),
                representative=REP_OFFICIAL_1,
                balance=0,
            )

    def test_invalid_block_5(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # First block must use link_hash, not other link_* fields
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                link_recipient=RECIPIENT_DONATIONS,
                representative=REP_OFFICIAL_1,
                balance=9624176000000000000000000000000,
            )

    def test_invalid_block_6(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # First block must use link_hash, not other link_* fields
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                link_recipient_n=NANO_ACCOUNT_1_PATH,
                representative=REP_OFFICIAL_1,
                balance=9624176000000000000000000000000,
            )

    def test_invalid_block_7(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # Only one of link_* fields can be specified
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                link_hash='2e3249f1ffc09608d369e01a701bf03bd05509fab262086a59d09994d315e840'.decode('hex'),
                link_recipient_n=NANO_ACCOUNT_1_PATH,
                representative=REP_OFFICIAL_1,
                balance=9624176000000000000000000000000,
            )

    def test_invalid_block_8(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # Only one of link_* fields can be specified
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                link_hash='2e3249f1ffc09608d369e01a701bf03bd05509fab262086a59d09994d315e840'.decode('hex'),
                link_recipient=RECIPIENT_DONATIONS,
                representative=REP_OFFICIAL_1,
                balance=9624176000000000000000000000000,
            )

    def test_invalid_block_9(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # Only one of link_* fields can be specified
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                link_recipient=RECIPIENT_DONATIONS,
                link_recipient_n=NANO_ACCOUNT_1_PATH,
                representative=REP_OFFICIAL_1,
                balance=9624176000000000000000000000000,
            )

    def test_invalid_block_10(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # Missing parent_representative
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                grandparent_hash='517565abb71bdccf03754421b1bcaee8327cfce7a571a844ae5392e851531ece'.decode('hex'),
                parent_link='0000000000000000000000000000000000000000000000000000000000000000'.decode('hex'),
                parent_balance=9624176000000000000000000000000,
                link_hash='4f3d6ce7553bd16d0c03314efeb696dde1b2ae92a28e6346b5ed2cf6a8ff0d8b'.decode('hex'),
                representative=REP_NANODE,
                balance=19624176000000000000000000000000,
            )

    def test_invalid_block_11(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # Missing parent_balance
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                grandparent_hash='517565abb71bdccf03754421b1bcaee8327cfce7a571a844ae5392e851531ece'.decode('hex'),
                parent_link='0000000000000000000000000000000000000000000000000000000000000000'.decode('hex'),
                parent_representative=REP_NANODE,
                link_hash='4f3d6ce7553bd16d0c03314efeb696dde1b2ae92a28e6346b5ed2cf6a8ff0d8b'.decode('hex'),
                representative=REP_NANODE,
                balance=19624176000000000000000000000000,
            )

    def test_invalid_block_12(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # Invalid parent_representative value
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                grandparent_hash='517565abb71bdccf03754421b1bcaee8327cfce7a571a844ae5392e851531ece'.decode('hex'),
                parent_link='0000000000000000000000000000000000000000000000000000000000000000'.decode('hex'),
                parent_representative=REP_NANODE[:-2],
                parent_balance=9624176000000000000000000000000,
                link_hash='4f3d6ce7553bd16d0c03314efeb696dde1b2ae92a28e6346b5ed2cf6a8ff0d8b'.decode('hex'),
                representative=REP_NANODE,
                balance=19624176000000000000000000000000,
            )

    def test_invalid_block_13(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # Invalid representative value
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                grandparent_hash='517565abb71bdccf03754421b1bcaee8327cfce7a571a844ae5392e851531ece'.decode('hex'),
                parent_link='0000000000000000000000000000000000000000000000000000000000000000'.decode('hex'),
                parent_representative=REP_NANODE,
                parent_balance=9624176000000000000000000000000,
                link_hash='4f3d6ce7553bd16d0c03314efeb696dde1b2ae92a28e6346b5ed2cf6a8ff0d8b'.decode('hex'),
                representative=REP_NANODE[:-2],
                balance=19624176000000000000000000000000,
            )

    def test_invalid_block_14(self):
        self.setup_mnemonic_nopin_nopassphrase()
        with self.assertRaises(CallException):
            # Invalid link_recipient value
            self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                grandparent_hash='1a3ec7d5d246aa987d99fde40ff3cadb8833941391611ec9125014d7458ac406'.decode('hex'),
                parent_link='4f3d6ce7553bd16d0c03314efeb696dde1b2ae92a28e6346b5ed2cf6a8ff0d8b'.decode('hex'),
                parent_representative=REP_NANODE,
                parent_balance=19624176000000000000000000000000,
                link_recipient=RECIPIENT_DONATIONS[:-2],
                representative=REP_NANODE,
                balance=12624176000000000000000000000000,
            )

if __name__ == '__main__':
    unittest.main()
