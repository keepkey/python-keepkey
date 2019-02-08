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
from keepkeylib.tools import parse_path

NANO_ACCOUNT_0_PATH = parse_path("m/44'/165'/0'")
NANO_ACCOUNT_0_ADDRESS = 'xrb_1bhbsc9yuh15anq3owu1izw1nk7bhhqefrkhfo954fyt8dk1q911buk1kk4c'
NANO_ACCOUNT_1_PATH = parse_path("m/44'/165'/1'")
NANO_ACCOUNT_1_ADDRESS = 'xrb_3p9ws1t6nx7r5xunf7khtbzqwa9ncjte9fmiy59eiyjkkfds6z5zgpom1cxs'
OTHER_ACCOUNT_3_PATH = parse_path("m/44'/100'/3'")
OTHER_ACCOUNT_3_ADDRESS = 'xrb_1x9k73o5icut7pr8khu9xcgtbaau6z6fh5fxxb5m9s3fpzuoe6aio9xjz4et'
ACCOUNT_NONE_PATH = []
ACCOUNT_NONE_ADDRESS = 'xrb_1b9dutog4daytip1meckewxqq9fmir49amq451pmef4bm7rihcjckfazajjt'

class TestMsgNanoGetAddress(common.KeepKeyTest):

    def test(self):
        self.setup_mnemonic_nopin_nopassphrase()
        vec = [
            (NANO_ACCOUNT_0_PATH,  False, NANO_ACCOUNT_0_ADDRESS),
            (NANO_ACCOUNT_1_PATH,  False, NANO_ACCOUNT_1_ADDRESS),
            (OTHER_ACCOUNT_3_PATH, False, OTHER_ACCOUNT_3_ADDRESS),
            (ACCOUNT_NONE_PATH,    False, ACCOUNT_NONE_ADDRESS),
            (NANO_ACCOUNT_0_PATH,  True,  NANO_ACCOUNT_0_ADDRESS),
            (NANO_ACCOUNT_1_PATH,  True,  NANO_ACCOUNT_1_ADDRESS),
            (OTHER_ACCOUNT_3_PATH, True,  OTHER_ACCOUNT_3_ADDRESS),
            (ACCOUNT_NONE_PATH,    True,  ACCOUNT_NONE_ADDRESS),
        ]

        for path, show, address in vec:
            res = self.client.nano_get_address('Nano', path, show)
            self.assertEqual(res.address, address)

if __name__ == '__main__':
    unittest.main()
