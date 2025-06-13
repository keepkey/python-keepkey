# This file is part of the Trezor project.
#
# Copyright (C) 2012-2018 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import unittest

from binascii import hexlify
import base64

from common import KeepKeyTest
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.tools import parse_path


class TestMsgSignmessageSegwit(KeepKeyTest):

    def test_sign(self):
        self.setup_mnemonic_nopin_nopassphrase()
        sig = self.client.sign_message('Bitcoin', [0], "This is an example of a signed message.", script_type=proto_types.SPENDP2SHWITNESS)
        self.assertEqual(sig.address, '3CwYaeWxhpXXiHue3ciQez1DLaTEAXcKa1')
        self.assertEqual(hexlify(sig.signature), b'249e23edf0e4e47ff1dec27f32cd78c50e74ef018ee8a6adf35ae17c7a9b0dd96f48b493fd7dbab03efb6f439c6383c9523b3bbc5f1a7d158a6af90ab154e9be80')

    def test_sign_testnet(self):
        self.setup_mnemonic_nopin_nopassphrase()
        sig = self.client.sign_message('Testnet', [0], "This is an example of a signed message.", script_type=proto_types.SPENDP2SHWITNESS)
        self.assertEqual(sig.address, '2N4VkePSzKH2sv5YBikLHGvzUYvfPxV6zS9')
        self.assertEqual(hexlify(sig.signature), b'249e23edf0e4e47ff1dec27f32cd78c50e74ef018ee8a6adf35ae17c7a9b0dd96f48b493fd7dbab03efb6f439c6383c9523b3bbc5f1a7d158a6af90ab154e9be80')

    def test_sign_long(self):
        self.setup_mnemonic_nopin_nopassphrase()
        sig = self.client.sign_message('Bitcoin', [0], "VeryLongMessage!" * 64, script_type=proto_types.SPENDP2SHWITNESS)
        self.assertEqual(sig.address, '3CwYaeWxhpXXiHue3ciQez1DLaTEAXcKa1')
        self.assertEqual(hexlify(sig.signature), b'245ff795c29aef7538f8b3bdb2e8add0d0722ad630a140b6aefd504a5a895cbd867cbb00981afc50edd0398211e8d7c304bb8efa461181bc0afa67ea4a720a89ed')

    def test_sign_grs(self):
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        sig = self.client.sign_message('Groestlcoin', parse_path("49'/17'/0'/0/0"), "test", script_type=proto_types.SPENDP2SHWITNESS)
        self.assertEqual(sig.address, '31inaRqambLsd9D7Ke4USZmGEVd3PHkh7P')
        self.assertEqual(base64.b64encode(sig.signature), 'I/NA/J+epkaeE9vHQ7cDE+TQdrzYzoZ+3dcexBFg0CpKRiIF0h7G5JUCvz4qhGPUjolcpW9rOFsV7CzHVWKS7K4=')

    def test_sign_utf(self):
        self.setup_mnemonic_nopin_nopassphrase()

        words_nfkd = u'Pr\u030ci\u0301s\u030cerne\u030c z\u030clut\u030couc\u030cky\u0301 ku\u030an\u030c u\u0301pe\u030cl d\u030ca\u0301belske\u0301 o\u0301dy za\u0301ker\u030cny\u0301 uc\u030cen\u030c be\u030cz\u030ci\u0301 pode\u0301l zo\u0301ny u\u0301lu\u030a'
        words_nfc = u'P\u0159\xed\u0161ern\u011b \u017elu\u0165ou\u010dk\xfd k\u016f\u0148 \xfap\u011bl \u010f\xe1belsk\xe9 \xf3dy z\xe1ke\u0159n\xfd u\u010de\u0148 b\u011b\u017e\xed pod\xe9l z\xf3ny \xfal\u016f'

        sig_nfkd = self.client.sign_message('Bitcoin', [0], words_nfkd, script_type=proto_types.SPENDP2SHWITNESS)
        self.assertEqual(sig_nfkd.address, '3CwYaeWxhpXXiHue3ciQez1DLaTEAXcKa1')
        self.assertEqual(hexlify(sig_nfkd.signature), b'24d0ec02ed8da8df23e7fe9e680e7867cc290312fe1c970749d8306ddad1a1eda41c6a771b13d495dd225b13b0a9d0f915a984ee3d0703f92287bf8009fbb9f7d6')

        sig_nfc = self.client.sign_message('Bitcoin', [0], words_nfc, script_type=proto_types.SPENDP2SHWITNESS)
        self.assertEqual(sig_nfc.address, '3CwYaeWxhpXXiHue3ciQez1DLaTEAXcKa1')
        self.assertEqual(hexlify(sig_nfc.signature), b'24d0ec02ed8da8df23e7fe9e680e7867cc290312fe1c970749d8306ddad1a1eda41c6a771b13d495dd225b13b0a9d0f915a984ee3d0703f92287bf8009fbb9f7d6')

if __name__ == '__main__':
    unittest.main()
