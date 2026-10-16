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
import keepkeylib.ckd_public as bip32
import keepkeylib.types_pb2 as proto_types
import binascii

class TestMsgGetaddress(common.KeepKeyTest):

    def test_show(self):
        self.setup_mnemonic_nopin_nopassphrase()
        for n, address in ((1, '1CK7SJdcb8z9HuvVft3D91HLpLC6KSsGb'),
                           (2, '15AeAhtNJNKyowK8qPHwgpXkhsokzLtUpG'),
                           (3, '1CmzyJp9w3NafXMSEFH4SLYUPAVCSUrrJ5')):
            self.assertEqual(self.assert_shows_address(
                lambda: self.client.get_address('Bitcoin', [n], show_display=True),
                address), address)

    def test_show_multisig_3(self):
        self.setup_mnemonic_nopin_nopassphrase()

        node = bip32.deserialize('xpub661MyMwAqRbcF1zGijBb2K6x9YiJPh58xpcCeLvTxMX6spkY3PcpJ4ABcCyWfskq5DDxM3e6Ez5ePCqG5bnPUXR4wL8TZWyoDaUdiWW7bKy')
        multisig = proto_types.MultisigRedeemScriptType(
                            pubkeys=[proto_types.HDNodePathType(node=node, address_n=[1]),
                                     proto_types.HDNodePathType(node=node, address_n=[2]),
                                     proto_types.HDNodePathType(node=node, address_n=[3])],
                            signatures=[b'', b'', b''],
                            m=2,
                            )

        for i in [1, 2, 3]:
            address = '3E7GDtuHqnqPmDgwH59pVC7AvySiSkbibz'
            self.assertEqual(self.assert_shows_address(
                lambda: self.client.get_address('Bitcoin', [i], show_display=True, multisig=multisig),
                address), address)

    def test_show_multisig_15(self):
        self.setup_mnemonic_nopin_nopassphrase()

        node = bip32.deserialize('xpub661MyMwAqRbcF1zGijBb2K6x9YiJPh58xpcCeLvTxMX6spkY3PcpJ4ABcCyWfskq5DDxM3e6Ez5ePCqG5bnPUXR4wL8TZWyoDaUdiWW7bKy')

        pubs = []
        for x in range(15):
            pubs.append(proto_types.HDNodePathType(node=node, address_n=[x]))

        multisig = proto_types.MultisigRedeemScriptType(
                        pubkeys=pubs,
                        signatures=[b''] * 15,
                        m=15,
                        )

        for i in range(15):
            address = '3QaKF8zobqcqY8aS6nxCD5ZYdiRfL3RCmU'
            self.assertEqual(self.assert_shows_address(
                lambda: self.client.get_address('Bitcoin', [i], show_display=True, multisig=multisig),
                address), address)

if __name__ == '__main__':
    unittest.main()
