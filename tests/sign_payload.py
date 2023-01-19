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


import unittest
import common
import binascii
import json

from keepkeylib import tools


class SignEvpPayload(common.KeepKeyTest): 
    def test_ethereum_verify_message(self):
        # self.setup_mnemonic_nopin_nopassphrase()

        self.requires_firmware("7.8.0")
        f = open('evptests.json')
        test = json.load(f)
        f.close()
        
        self.client.load_device_by_mnemonic(mnemonic=test['mnemonic'], pin='', passphrase_protection=False, label='test', language='english')
        
        # debug firmware knows this is the test key path
        testPath = "m/44'/60'/1'/0/0"
        n = tools.parse_path(testPath)
        sigAddress = self.client.ethereum_get_address(n, show_display=False, multisig=None)

        print("Verify address %s" % binascii.hexlify(sigAddress))

        for payload in test['payloads']:
            retval = self.client.ethereum_sign_message(
                n = n,
                message = bytes(json.dumps(payload['payload']), 'utf8')
            )
            print(bytes(json.dumps(payload['payload']['name']), 'utf8'))
            print(binascii.hexlify(retval.signature))
            print(" ")

if __name__ == "__main__":
    unittest.main()