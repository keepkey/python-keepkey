# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
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
import common

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.messages_stellar_pb2 as stellar_proto
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH = "m/44h/148h/0h"

class TestMsgStellarGetAddress(common.KeepKeyTest):
    def test_stellar_get_address(self):
        self.setup_mnemonic_nopin_nopassphrase()
        print self.mnemonic12
        address = self.client.stellar_get_address(parse_path(DEFAULT_BIP32_PATH))
        assert address.address == "GAK5MSF74TJW6GLM7NLTL76YZJKM2S4CGP3UH4REJHPHZ4YBZW2GSBPW"

    def test_stellar_get_address_sep(self):
        self.mnemonic12 = 'illness spike retreat truth genius clock brain pass fit cave bargain toe'
        self.setup_mnemonic_nopin_nopassphrase()
        # data from https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md
        address = self.client.stellar_get_address(parse_path(DEFAULT_BIP32_PATH))
        assert address.address == "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6"

        address = self.client.stellar_get_address(
            parse_path("m/44h/148h/1h"), show_display=True
        )
        assert address.address == "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX"

    def test_stellar_get_address_fail(self):
        self.setup_mnemonic_nopin_nopassphrase()
        try:
            self.client.stellar_get_address(parse_path("m/0/1"))
        except CallException as exc:
            assert exc.args[0] == proto_types.FailureType.Failure_FirmwareError
            assert exc.args[1].endswith("Failed to derive private key")

if __name__ == '__main__':
    unittest.main()