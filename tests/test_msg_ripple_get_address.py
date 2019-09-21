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

from keepkeylib.tools import parse_path

from common import KeepKeyTest

class TestMsgRippleGetAddress(KeepKeyTest):
    def test_ripple_get_address(self):
        # data from https://iancoleman.io/bip39/#english
        self.setup_mnemonic_allallall()

        address = self.client.ripple_get_address(parse_path("m/44'/144'/0'/0/0"))
        self.assertEquals(address, "rNaqKtKrMSwpwZSzRckPf7S96DkimjkF4H")
        address = self.client.ripple_get_address(parse_path("m/44'/144'/0'/0/1"))
        self.assertEquals(address, "rBKz5MC2iXdoS3XgnNSYmF69K1Yo4NS3Ws")
        address = self.client.ripple_get_address(parse_path("m/44'/144'/1'/0/0"))
        self.assertEquals(address, "rJX2KwzaLJDyFhhtXKi3htaLfaUH2tptEX")

    def test_ripple_get_address_other(self):
        # data from https://github.com/you21979/node-ripple-bip32/blob/master/test/test.js
        self.client.load_device_by_mnemonic(
            mnemonic="armed bundle pudding lazy strategy impulse where identify submit weekend physical antenna flight social acoustic absurd whip snack decide blur unfold fiction pumpkin athlete",
            pin="",
            passphrase_protection=False,
            label="test",
            language="english",
        )
        address = self.client.ripple_get_address(parse_path("m/44'/144'/0'/0/0"))
        self.assertEquals(address, "r4ocGE47gm4G4LkA9mriVHQqzpMLBTgnTY")
        address = self.client.ripple_get_address(parse_path("m/44'/144'/0'/0/1"))
        self.assertEquals(address, "rUt9ULSrUvfCmke8HTFU1szbmFpWzVbBXW")

if __name__ == '__main__':
    unittest.main()

