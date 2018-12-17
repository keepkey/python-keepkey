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
import binascii
import keepkeylib.ckd_public as bip32
import keepkeylib.types_pb2 as proto_types
import keepkeylib.messages_eos_pb2 as eos_proto
from keepkeylib.tools import parse_path
import keepkeylib.eos as eos

EOS_ACCOUNT_0_PATH   = parse_path("m/44'/194'/0'/0/0")
EOS_ACCOUNT_0_PUBKEY = '4u6Sfnzj4Sh2pEQnkXyZQJqH3PkKjGByDCbsqqmyq6PttM9KyB'
EOS_ACCOUNT_1_PATH   = parse_path("m/44'/194'/1'/0/0")
EOS_ACCOUNT_1_PUBKEY = '7UuNeTf13nfcG85rDB7AHGugZi4C4wJ4ft12QRotqNfxdV2NvP'
ACCOUNT_NONE_PATH    = []
ACCOUNT_NONE_PUBKEY  = '8hhFGcdMry96GpvyxnAGFsnyaNHzXu3Hw61Fy1CnmJUQDQBhqk'

class TestMsgEosGetPublicKey(common.KeepKeyTest):

    def test(self):
        self.setup_mnemonic_nopin_nopassphrase()
        vec = [
            (EOS_ACCOUNT_0_PATH, False, True,  'EOS' + EOS_ACCOUNT_0_PUBKEY),
            (EOS_ACCOUNT_1_PATH, False, True,  'EOS' + EOS_ACCOUNT_1_PUBKEY),
            (ACCOUNT_NONE_PATH,  False, True,  'EOS' + ACCOUNT_NONE_PUBKEY),
            (EOS_ACCOUNT_0_PATH, False, False, 'EOS_K1_' + EOS_ACCOUNT_0_PUBKEY),
            (EOS_ACCOUNT_1_PATH, False, False, 'EOS_K1_' + EOS_ACCOUNT_1_PUBKEY),
            (ACCOUNT_NONE_PATH,  False, False,  'EOS_K1_' + ACCOUNT_NONE_PUBKEY),
        ]

        for path, show, legacy, wif in vec:
            res = self.client.eos_get_public_key(path, show, legacy)
            self.assertEqual(res.wif_public_key, wif)

    def test_trezor(self):
        self.setup_mnemonic_abandon()

        derivation_paths = [
            [0x80000000 | 44, 0x80000000 | 194, 0x80000000, 0, 0],
            [0x80000000 | 44, 0x80000000 | 194, 0x80000000, 0, 1],
            [0x80000000 | 44, 0x80000000 | 194],
            [0x80000000 | 44, 0x80000000 | 194, 0x80000000, 0, 0x80000000],
        ]
        public_keys = [
            b'0315c358024ce46767102578947584c4342a6982b922d454f63588effa34597197',
            b'029622eff7248c4d298fe28f2df19ee0d5f7674f678844e05c31d1a5632412869e',
            b'02625f33c10399703e95e41bd5054beef3ab893dcc7df2bb9bdcee48359b29069d',
            b'037c9b7d24d42589941cca3f4debc75b37c0e7b881e6eb00d2e674958debe3bbc3',
        ]
        wif_keys = [
            'EOS6zpSNY1YoLxNt2VsvJjoDfBueU6xC1M1ERJw1UoekL1NHn8KNA',
            'EOS62cPUiWnLqbUjiBMxbEU4pm4Hp5X3RGk4KMTadvZNygjX72yHW',
            'EOS5dp8aCFoFwrKo6KuUfos1hwMfZGkiZUbaF2CyuD4chyBEN2wQK',
            'EOS7n7TXwR4Y3DtPt2ji6akhQi5uw4SruuPArvoNJso84vhwPQt1G',
        ]

        for index, path in enumerate(derivation_paths):
            res = self.client.eos_get_public_key(path, False, True)
            self.assertEqual(res.wif_public_key, wif_keys[index])
            self.assertEqual(binascii.hexlify(res.raw_public_key), public_keys[index])
            self.assertEqual(eos.public_key_to_wif(res.raw_public_key, 'EOS'), wif_keys[index])

if __name__ == '__main__':
    unittest.main()
