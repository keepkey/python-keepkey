#
# Copyright (C) 2022 markrypto <cryptoakorn@gmail.com>
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


from doctest import testfile
import unittest
import common
import binascii
import json

from keepkeylib import tools
from addSignedData import addSignedIcon


class TestMsgEthvm(common.KeepKeyTest): 
    def test_ethereum_verify_message_icon(self):       
        self.requires_firmware("7.6.0")
        f = open('evptests.json')
        test = json.load(f)
        f.close()
        
        self.client.load_device_by_mnemonic(mnemonic=test['mnemonic'], pin='', passphrase_protection=False, label='test', language='english')
        
        retval = addSignedIcon(self, 'iconEthereum')
        print(retval.message)

if __name__ == "__main__":
    unittest.main()
