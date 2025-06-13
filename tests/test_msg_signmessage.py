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
import base64

from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

class TestMsgSignmessage(common.KeepKeyTest):

    def test_sign(self):
        self.setup_mnemonic_nopin_nopassphrase()
        sig = self.client.sign_message('Bitcoin', [0], "This is an example of a signed message.")
        self.assertEqual(sig.address, '14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e')
        self.assertEqual(binascii.hexlify(sig.signature), '209e23edf0e4e47ff1dec27f32cd78c50e74ef018ee8a6adf35ae17c7a9b0dd96f48b493fd7dbab03efb6f439c6383c9523b3bbc5f1a7d158a6af90ab154e9be80')

    def test_sign_testnet(self):
        self.setup_mnemonic_nopin_nopassphrase()
        sig = self.client.sign_message('Testnet', [0], "This is an example of a signed message.")

        self.assertEqual(sig.address, 'mirio8q3gtv7fhdnmb3TpZ4EuafdzSs7zL')
        self.assertEqual(binascii.hexlify(sig.signature), '209e23edf0e4e47ff1dec27f32cd78c50e74ef018ee8a6adf35ae17c7a9b0dd96f48b493fd7dbab03efb6f439c6383c9523b3bbc5f1a7d158a6af90ab154e9be80')

    def test_sign_long(self):
        self.setup_mnemonic_nopin_nopassphrase()
        sig = self.client.sign_message('Bitcoin', [0], "VeryLongMessage!" * 64)
        self.assertEqual(sig.address, '14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e')
        self.assertEqual(binascii.hexlify(sig.signature), '205ff795c29aef7538f8b3bdb2e8add0d0722ad630a140b6aefd504a5a895cbd867cbb00981afc50edd0398211e8d7c304bb8efa461181bc0afa67ea4a720a89ed')

    def test_sign_grs(self):
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        sig = self.client.sign_message('Groestlcoin', parse_path("44'/17'/0'/0/0"), "test")
        self.assertEqual(sig.address, 'Fj62rBJi8LvbmWu2jzkaUX1NFXLEqDLoZM')
        self.assertEqual(base64.b64encode(sig.signature), 'INOYaa/jj8Yxz3mD5k+bZfUmjkjB9VzoV4dNG7+RsBUyK30xL7I9yMgWWVvsL46C5yQtxtZY0cRRk7q9N6b+YTM=')

    """
    def test_sign_utf(self):
        self.setup_mnemonic_nopin_nopassphrase()

        words_nfkd = u'Pr\u030ci\u0301s\u030cerne\u030c z\u030clut\u030couc\u030cky\u0301 ku\u030an\u030c u\u0301pe\u030cl d\u030ca\u0301belske\u0301 o\u0301dy za\u0301ker\u030cny\u0301 uc\u030cen\u030c be\u030cz\u030ci\u0301 pode\u0301l zo\u0301ny u\u0301lu\u030a'
        words_nfc = u'P\u0159\xed\u0161ern\u011b \u017elu\u0165ou\u010dk\xfd k\u016f\u0148 \xfap\u011bl \u010f\xe1belsk\xe9 \xf3dy z\xe1ke\u0159n\xfd u\u010de\u0148 b\u011b\u017e\xed pod\xe9l z\xf3ny \xfal\u016f'

        sig_nfkd = self.client.sign_message('Bitcoin', [0], words_nfkd)
        self.assertEqual(sig_nfkd.address, '14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e')
        self.assertEqual(binascii.hexlify(sig_nfkd.signature), '1fd0ec02ed8da8df23e7fe9e680e7867cc290312fe1c970749d8306ddad1a1eda4e39588e4ec2b6a22dda4ec4f562f06e91129eea9a844a7193812de82d47c496b')

        sig_nfc = self.client.sign_message('Bitcoin', [0], words_nfc)
        self.assertEqual(sig_nfc.address, '14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e')
        self.assertEqual(binascii.hexlify(sig_nfc.signature), '1fd0ec02ed8da8df23e7fe9e680e7867cc290312fe1c970749d8306ddad1a1eda4e39588e4ec2b6a22dda4ec4f562f06e91129eea9a844a7193812de82d47c496b')
    """

if __name__ == '__main__':
    unittest.main()
