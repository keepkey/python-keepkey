# Copyright (C) 2023 markrypto <cryptoakorn@gmail.com>
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
import binascii

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import PinException, CallException


class TestAuthFeature(common.KeepKeyTest):
    def sendMsg(self, client, msg):
        err = ''
        retval = None
        try:
            retval = client.ping(msg=msg)
        except CallException as E:
            err = E.args[1]
        return retval, err

    def clearAuthData(self, client):
        retval, err = self.sendMsg(client, b'\x19' + bytes("wipeAuthdata:", 'utf8'))
        return err
        
    def test_InitGetOTPClear(self):
        if self.client.features.firmware_variant == "Emulator":
            self.skipTest("Skip test in emulator, test on physical KeepKey")
            return

        self.requires_firmware("7.6.0")
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()
        self.clearAuthData(self.client)
        
        for msg in (
            b'\x15' + bytes("initializeAuth:"+"KeepKey"+":"+"markrypto"+":"+"ZKLHM3W3XAHG4CBN", 'utf8'),
            b'\x15' + bytes("initializeAuth:"+"Shapeshift"+":"+"markrypto"+":"+"BASE32SECRET2345AB", 'utf8'),
            b'\x15' + bytes("initializeAuth:"+"KeepKey"+":"+"markrypto2"+":"+"JBSWY3DPEHPK3PXP", 'utf8')
            ):
            retval, err = self.sendMsg(self.client, msg)
            self.assertEqual(err, '')

        T0 = 1535317397
        interval = 30
        Tslice = int(T0/interval)
        Tremain = 7
        for vector in (
            (b'\x16' + bytes("generateOTPFrom:KeepKey:markrypto:", 'utf8') + bytes(str(Tslice), 'utf8') + bytes(":" + str(Tremain), 'utf8'), '910862'),
            (b'\x16' + bytes("generateOTPFrom:Shapeshift:markrypto:", 'utf8') + bytes(str(Tslice), 'utf8') + bytes(":" + str(Tremain), 'utf8'), '280672'),
            (b'\x16' + bytes("generateOTPFrom:KeepKey:markrypto2:", 'utf8') + bytes(str(Tslice), 'utf8') + bytes(":" + str(Tremain), 'utf8'), '660041')
            ):
            retval, err = self.sendMsg(self.client, vector[0])
            self.assertEqual(err, '')
            self.assertEqual(retval[:6], vector[1])

        err = self.clearAuthData(self.client)
        self.assertEqual(err, '')

if __name__ == '__main__':
    unittest.main()
