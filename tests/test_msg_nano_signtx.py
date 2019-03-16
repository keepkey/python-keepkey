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
from binascii import hexlify
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_nano_pb2 as proto_nano
from keepkeylib import types_pb2 as proto_types
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
        self.assertEqual(hexlify(nano.encode_balance(0)), '00000000000000000000000000000000')
        self.assertEqual(hexlify(nano.encode_balance(4440329590121742105910495447534801366)), '03572d26b8163ca8016a76280cb011d6')
        self.assertEqual(hexlify(nano.encode_balance(340282366920938463463374607431768211455)), 'ffffffffffffffffffffffffffffffff')

    def test_block_1(self):
        # https://www.nanode.co/block/f9a323153daefe041efb94d69b9669c882c935530ed953bbe8a665dfedda9696
        self.setup_mnemonic_nopin_nopassphrase()
        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto_nano.NanoSignedTx(),
            ])
            res = self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                link_hash='491fca2c69a84607d374aaf1f6acd3ce70744c5be0721b5ed394653e85233507'.decode('hex'),
                representative=REP_OFFICIAL_1,
                balance=96242336390000000000000000000,
            )
            self.assertIsInstance(res, proto_nano.NanoSignedTx)
            self.assertEqual(hexlify(res.block_hash), 'f9a323153daefe041efb94d69b9669c882c935530ed953bbe8a665dfedda9696')
            self.assertEqual(hexlify(res.signature), 'd247f6b90383b24e612569c75a12f11242f6e03b4914eadc7d941577dcf54a3a7cb7f0a4aba4246a40d9ebb5ee1e00b4a0a834ad5a1e7bef24e11f62b95a9e09')

    def test_block_2(self):
        # https://www.nanode.co/block/2568bf76336f7a415ca236dab97c1df9de951ca057a2e79df1322e647a259e7b
        self.setup_mnemonic_nopin_nopassphrase()
        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto_nano.NanoSignedTx(),
            ])
            res = self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                parent_link='491fca2c69a84607d374aaf1f6acd3ce70744c5be0721b5ed394653e85233507'.decode('hex'),
                parent_representative=REP_OFFICIAL_1,
                parent_balance=96242336390000000000000000000,
                representative=REP_NANODE,
                balance=96242336390000000000000000000,
            )
            self.assertIsInstance(res, proto_nano.NanoSignedTx)
            self.assertEqual(hexlify(res.block_hash), '2568bf76336f7a415ca236dab97c1df9de951ca057a2e79df1322e647a259e7b')
            self.assertEqual(hexlify(res.signature), '3a0687542405163d5623808052042b3482360a82cc003d178a0c0d8bfbca86450975d0faec60ae5ac37feba9a8e2205c8540317b26f2c589c2a6578b03870403')

    def test_block_3(self):
        # https://www.nanode.co/block/1ca240212838d053ecaa9dceee598c52a6080067edecaeede3319eb0b7db6525
        self.setup_mnemonic_nopin_nopassphrase()
        with self.client:
            self.client.set_expected_responses([
                # Receive doesn't produce a proto.ButtonRequest
                proto_nano.NanoSignedTx(),
            ])
            res = self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                grandparent_hash='f9a323153daefe041efb94d69b9669c882c935530ed953bbe8a665dfedda9696'.decode('hex'),
                parent_link='0000000000000000000000000000000000000000000000000000000000000000'.decode('hex'),
                parent_representative=REP_NANODE,
                parent_balance=96242336390000000000000000000,
                link_hash='d7384845d2ae530b45a5dd50ee50757f988329f652781767af3f1bc2322f52b9'.decode('hex'),
                representative=REP_NANODE,
                balance=196242336390000000000000000000,
            )
            self.assertIsInstance(res, proto_nano.NanoSignedTx)
            self.assertEqual(hexlify(res.block_hash), '1ca240212838d053ecaa9dceee598c52a6080067edecaeede3319eb0b7db6525')
            self.assertEqual(hexlify(res.signature), 'e980d45365ae2fb291950019f7c19a3d5fa5df2736ca7e7ca1984338b4686976cb7efdda2894ddcea480f82645b50f2340c9d0fc69a05621bdc355783a21820d')

    def test_block_4(self):
        # https://www.nanode.co/block/32ac7d8f5a16a498abf203b8dfee623c9e111ff25e7339f8cd69ec7492b23edd
        self.setup_mnemonic_nopin_nopassphrase()
        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto_nano.NanoSignedTx(),
            ])
            res = self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                grandparent_hash='2568bf76336f7a415ca236dab97c1df9de951ca057a2e79df1322e647a259e7b'.decode('hex'),
                parent_link='d7384845d2ae530b45a5dd50ee50757f988329f652781767af3f1bc2322f52b9'.decode('hex'),
                parent_representative=REP_NANODE,
                parent_balance=196242336390000000000000000000,
                link_recipient=RECIPIENT_DONATIONS,
                representative=REP_NANODE,
                balance=126242336390000000000000000000,
            )
            self.assertIsInstance(res, proto_nano.NanoSignedTx)
            self.assertEqual(hexlify(res.block_hash), '32ac7d8f5a16a498abf203b8dfee623c9e111ff25e7339f8cd69ec7492b23edd')
            self.assertEqual(hexlify(res.signature), 'bcb806e140c9e2bc71c51ebbd941b4d99cee3d97fd50e3006eabc5e325c712662e2dc163ee32660875d67815ce4721e122389d2e64f1c9ad4555a9d3d8c33802')

    def test_block_5(self):
        # https://www.nanode.co/block/5d732d843c22f806011127655790484dbabd38dda20b24900c053c3dfc12523f
        self.setup_mnemonic_nopin_nopassphrase()
        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto_nano.NanoSignedTx(),
            ])
            res = self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                grandparent_hash='1ca240212838d053ecaa9dceee598c52a6080067edecaeede3319eb0b7db6525'.decode('hex'),
                parent_link=RECIPIENT_DONATIONS_PUBLICKEY.decode('hex'),
                parent_representative=REP_NANODE,
                parent_balance=126242336390000000000000000000,
                link_recipient_n=NANO_ACCOUNT_1_PATH,
                representative=REP_NANODE,
                balance=86242336390000000000000000000,
            )
            self.assertIsInstance(res, proto_nano.NanoSignedTx)
            self.assertEqual(hexlify(res.block_hash), '5d732d843c22f806011127655790484dbabd38dda20b24900c053c3dfc12523f')
            self.assertEqual(hexlify(res.signature), '3fb596c34db1241201983cbf613fe9b68a6eae2420c7f294c7e883574fda10d5cc19c9e516b57ed0cbc5e7d3438f70f2ddd7a45bf3e693ff800b97e187de5701')

    def test_block_6(self):
        # https://www.nanode.co/block/a7e59d38b001d9348dbe16fa866d0b435259d381af1db019f3ff83fd7590e226
        self.setup_mnemonic_nopin_nopassphrase()
        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto_nano.NanoSignedTx(),
            ])
            res = self.client.nano_sign_tx(
                'Nano', NANO_ACCOUNT_0_PATH,
                grandparent_hash='32ac7d8f5a16a498abf203b8dfee623c9e111ff25e7339f8cd69ec7492b23edd'.decode('hex'),
                parent_link=NANO_ACCOUNT_1_PUBLICKEY.decode('hex'),
                parent_representative=REP_NANODE,
                parent_balance=86242336390000000000000000000,
                link_recipient_n=OTHER_ACCOUNT_3_PATH,
                representative=REP_NANODE,
                balance=40000760000000000000000000000,
            )
            self.assertIsInstance(res, proto_nano.NanoSignedTx)
            self.assertEqual(hexlify(res.block_hash), 'a7e59d38b001d9348dbe16fa866d0b435259d381af1db019f3ff83fd7590e226')
            self.assertEqual(hexlify(res.signature), '1dcd8a27aeac1cab9a2054d5cc6df1b80be46290596dcf6d195c2c286b1615d4139276f9be9c6f202ee1ee8a5569b4a4fc838b1d7306aa71c8e431a6b8075707')

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
