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

class TestPing(common.KeepKeyTest):
    def test_ping(self):
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()

        with self.client:
            self.client.set_expected_responses([proto.Success()])
            res = self.client.ping('random data')
            self.assertEqual(res, 'random data')

        with self.client:
            self.client.set_expected_responses([proto.ButtonRequest(code=proto_types.ButtonRequest_Ping), proto.Success()])
            res = self.client.ping('random data', button_protection=True)
            self.assertEqual(res, 'random data')

        with self.client:
            self.client.set_expected_responses([proto.PinMatrixRequest(), proto.Success()])
            res = self.client.ping('random data', pin_protection=True)
            self.assertEqual(res, 'random data')

        with self.client:
            self.client.set_expected_responses([
                proto.PassphraseRequest(), 
                proto.ButtonRequest(code=proto_types.ButtonRequest_Other), 
                proto.Success()
                ])
            res = self.client.ping('random data', passphrase_protection=True)
            self.assertEqual(res, 'random data')

    def test_ping_format_specifier_sanitize(self):
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()
        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_Ping), 
                proto.PinMatrixRequest(), 
                proto.PassphraseRequest(), 
                proto.ButtonRequest(code=proto_types.ButtonRequest_Other), 
                proto.Success()
                ])
            res = self.client.ping('%s%x%n%p', button_protection=True, pin_protection=True, passphrase_protection=True)
            self.assertEqual(res, '%s%x%n%p')

    def test_ping_caching(self):
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()

        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_Ping), 
                proto.PinMatrixRequest(), 
                proto.PassphraseRequest(), 
                proto.ButtonRequest(code=proto_types.ButtonRequest_Other), 
                proto.Success()
                ])
            res = self.client.ping('random data', button_protection=True, pin_protection=True, passphrase_protection=True)
            self.assertEqual(res, 'random data')

        with self.client:
            # pin and passphrase are cached
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_Ping), 
                proto.Success()])
            res = self.client.ping('random data', button_protection=True, pin_protection=True, passphrase_protection=True)
            self.assertEqual(res, 'random data')

if __name__ == '__main__':
    unittest.main()
