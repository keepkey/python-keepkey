# This file is part of the KeepKey project.
#
# Copyright (C) 2019 ShapeShift
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

import time
import unittest
import common

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types

class TestVULN1969(common.KeepKeyTest):

    def test(self):
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()

        ret = self.client.call_raw(proto.Ping(
            message="VULN-1969",
            button_protection=True,
            pin_protection=False,
            passphrase_protection=False))

        assert isinstance(ret, proto.ButtonRequest)

        ret = self.client.call_raw(proto.Ping(
            message="very long",
            button_protection=False,
            pin_protection=False,
            passphrase_protection=False))

        self.assertIsInstance(ret, proto.Failure)
        self.assertEndsWith(ret.message, "Unknown message")

if __name__ == '__main__':
    unittest.main()
