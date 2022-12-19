# Copyright (C) 2022 markrypto <cryptoakorn@gmail.com>
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
import usb1 as libusb

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import PinException, CallException


class TestAuthFeature(common.KeepKeyTest):
    def sendMsg(self, client, msg):
        err = ''
        retval = None
        try:
            retval = client.ping(msg)
        except CallException as E:
            err = E.args[1]
            
        except libusb.USBErrorNoDevice:
            err = "No KeepKey found"
        except libusb.USBErrorTimeout:
            err = "USB error timeout"
        except libusb.USBError as error:
            err = "USB error %r" % error
        
        return retval, err

    def clearAuthData(self, client):
        ctr=0
        while True:
            retval, err = self.sendMsg(client, msg = b'\x17' + bytes("getAccount:"+str(ctr), 'utf8'))
            if err == '':
                retval, err = self.sendMsg(client, msg = b'\x18' + bytes("removeAccount:"+retval, 'utf8'))
            else: 
                break
            ctr+=1
        if err == 'Account not found':
            return ''
        return err
        
    def test_InitGetOTPClear(self):
        self.requires_firmware("7.7.0")
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()
        self.clearAuthData(self.client)
        for msg in (
            b'\x15' + bytes("initializeAuth:"+"KeepKey"+":"+"markrypto"+":"+"ZKLHM3W3XAHG4CBN", 'utf8'),
            b'\x15' + bytes("initializeAuth:"+"Shapeshift"+":"+"markrypto"+":"+"BASE32SECRET2345AB", 'utf8'),
            b'\x15' + bytes("initializeAuth:"+"KeepKey"+":"+"markrypto2"+":"+"BACE32SECRET2345AB", 'utf8')
            ):
            retval, err = self.sendMsg(self.client, msg)
            self.assertEqual(err, '')

        T0 = 1535317397
        interval = 30
        Tslice = int(T0/interval)
        Tremain = 3
        T = Tslice.to_bytes(8, byteorder='big')
        for vector in (
            (b'\x16' + bytes("generateOTPFrom:KeepKey:markrypto:", 'utf8') + binascii.hexlify(bytearray(T)) + bytes(":" + str(Tremain), 'utf8'), '910862'),
            (b'\x16' + bytes("generateOTPFrom:Shapeshift:markrypto:", 'utf8') + binascii.hexlify(bytearray(T)) + bytes(":" + str(Tremain), 'utf8'), '280672'),
            (b'\x16' + bytes("generateOTPFrom:KeepKey:markrypto2:", 'utf8') + binascii.hexlify(bytearray(T)) + bytes(":" + str(Tremain), 'utf8'), '020352')
            ):
            retval, err = self.sendMsg(self.client, vector[0])
            self.assertEqual(err, '')
            self.assertEqual(retval, vector[1])

        err = self.clearAuthData(self.client)
        self.assertEqual(err, '')


if __name__ == '__main__':
    unittest.main()
