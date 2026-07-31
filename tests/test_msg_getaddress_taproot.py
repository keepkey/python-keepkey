# This file is part of the KeepKey project.
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

import common
import unittest

from keepkeylib import types_pb2 as proto
from keepkeylib.tools import parse_path


# Version in which SPENDTAPROOT support lands.  Keep this in step with
# CMakeLists.txt: if the firmware version is below it these tests SKIP, so a
# value that is never reached makes them silently green forever.
TAPROOT_FIRMWARE_VERSION = "7.16.0"


class TestMsgGetaddressTaproot(common.KeepKeyTest):

    def test_taproot_bip86_vectors(self):
        """Official BIP-86 test vectors.

        https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki

        BIP-86 publishes these against the "abandon abandon ... about"
        mnemonic, which is exactly what setup_mnemonic_abandon loads.  The
        expected addresses are therefore the spec's own constants, not values
        this implementation produced -- the comparison is against independent
        ground truth.
        """
        self.requires_firmware(TAPROOT_FIRMWARE_VERSION)
        self.setup_mnemonic_abandon()
        self.client.clear_session()

        # Account 0, first receiving address
        self.assertEqual(
            self.client.get_address(
                "Bitcoin", parse_path("86'/0'/0'/0/0"), False, None,
                script_type=proto.SPENDTAPROOT),
            'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr')

        # Account 0, second receiving address
        self.assertEqual(
            self.client.get_address(
                "Bitcoin", parse_path("86'/0'/0'/0/1"), False, None,
                script_type=proto.SPENDTAPROOT),
            'bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh')

        # Account 0, first change address
        self.assertEqual(
            self.client.get_address(
                "Bitcoin", parse_path("86'/0'/0'/1/0"), False, None,
                script_type=proto.SPENDTAPROOT),
            'bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7')


if __name__ == '__main__':
    unittest.main()
