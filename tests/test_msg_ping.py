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

import time
import unittest
import common
from datetime import datetime
import binascii

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types

### Dynamic Truncation
def dynamic_truncate(b_hash):
    hash_len=len(b_hash)
    int_hash = int.from_bytes(b_hash, byteorder='big')
    offset = int_hash & 0xF
    # Geterate a mask to get bytes from left to right of the hash
    n_shift = 8*(hash_len-offset)-32
    MASK = 0xFFFFFFFF << n_shift
    hex_mask = "0x"+("{:0"+str(2*hash_len)+"x}").format(MASK)
    P = (int_hash & MASK)>>n_shift   # Get rid of left zeros
    LSB_31 = P & 0x7FFFFFFF          # Return only the lower 31 bits
    return LSB_31

class TestPing(common.KeepKeyTest):
    def test_auth_init(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.ping(
            #msg = b'\x15' + bytes("initializeAuth:" + "CGPZQ62R37AHNYKJES3JQL5E", 'utf8')
            msg = b'\x15' + bytes("initializeAuth:" + "BASE32SECRET2345AB==", 'utf8')
        )
 
        interval = 30       # 30 second interval
        #T0 = int(time.time())       
        T0 = 1535317397
        # T1 = T0 + interval
        
        #T = bytes(str(int(T0/interval).to_bytes(8, byteorder='big')), 'utf8')
        T = int(T0/interval).to_bytes(8, byteorder='big')
        # print(T)
        # print(T.hex())
        # print([T[i:i+1] for i in range(len(T))])
        # print(''.join('{:02x}'.format(x) for x in T))
        # print(b'\x16' + bytes("generateOTPFrom:", 'utf8') + ''.join('{:02x}'.format(x) for x in T))
        # print(T1)
        # print(T)
        # print((b'\x16' + bytes("generateOTPFrom:", 'utf8') + T).hex())
        retval = self.client.ping(
            #msg = b'\x16' + bytes("generateOTPFrom:", 'utf8') + bytes(''.join('{:02x}'.format(x) for x in T), 'utf8')
            msg = b'\x16' + bytes("generateOTPFrom:", 'utf8') + binascii.hexlify(bytearray(T))
        )
        print(retval)
        print(binascii.unhexlify(retval))
        Digits = 6
        trc_hash = dynamic_truncate(binascii.unhexlify(retval))
        print(("{:0"+str(Digits)+"}").format(trc_hash % (10**Digits)))
        print("should be 280672")


    # def test_ping(self):
    #     self.setup_mnemonic_pin_passphrase()
    #     self.client.clear_session()

    #     with self.client:
    #         self.client.set_expected_responses([proto.Success()])
    #         res = self.client.ping('random data')
    #         self.assertEqual(res, 'random data')

    #     with self.client:
    #         self.client.set_expected_responses([proto.ButtonRequest(code=proto_types.ButtonRequest_Ping), proto.Success()])
    #         res = self.client.ping('random data', button_protection=True)
    #         self.assertEqual(res, 'random data')

    #     with self.client:
    #         self.client.set_expected_responses([proto.PinMatrixRequest(), proto.Success()])
    #         res = self.client.ping('random data', pin_protection=True)
    #         self.assertEqual(res, 'random data')

    #     with self.client:
    #         self.client.set_expected_responses([
    #             proto.PassphraseRequest(), 
    #             proto.ButtonRequest(code=proto_types.ButtonRequest_Other), 
    #             proto.Success()
    #             ])
    #         res = self.client.ping('random data', passphrase_protection=True)
    #         self.assertEqual(res, 'random data')

    # def test_ping_format_specifier_sanitize(self):
    #     self.setup_mnemonic_pin_passphrase()
    #     self.client.clear_session()
    #     with self.client:
    #         self.client.set_expected_responses([
    #             proto.ButtonRequest(code=proto_types.ButtonRequest_Ping), 
    #             proto.PinMatrixRequest(), 
    #             proto.PassphraseRequest(), 
    #             proto.ButtonRequest(code=proto_types.ButtonRequest_Other), 
    #             proto.Success()
    #             ])
    #         res = self.client.ping('%s%x%n%p', button_protection=True, pin_protection=True, passphrase_protection=True)
    #         self.assertEqual(res, '%s%x%n%p')

    # def test_ping_caching(self):
    #     self.setup_mnemonic_pin_passphrase()
    #     self.client.clear_session()

    #     with self.client:
    #         self.client.set_expected_responses([
    #             proto.ButtonRequest(code=proto_types.ButtonRequest_Ping), 
    #             proto.PinMatrixRequest(), 
    #             proto.PassphraseRequest(), 
    #             proto.ButtonRequest(code=proto_types.ButtonRequest_Other), 
    #             proto.Success()
    #             ])
    #         res = self.client.ping('random data', button_protection=True, pin_protection=True, passphrase_protection=True)
    #         self.assertEqual(res, 'random data')

    #     with self.client:
    #         # pin and passphrase are cached
    #         self.client.set_expected_responses([
    #             proto.ButtonRequest(code=proto_types.ButtonRequest_Ping), 
    #             proto.Success()])
    #         res = self.client.ping('random data', button_protection=True, pin_protection=True, passphrase_protection=True)
    #         self.assertEqual(res, 'random data')

if __name__ == '__main__':
    unittest.main()
