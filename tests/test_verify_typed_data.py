# This file is part of the keepkey project.
#
# Copyright (C) 2022 markrypto
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
import json
import sys

import keepkeylib.messages_pb2 as proto
import keepkeylib.messages_ethereum_pb2 as eth_proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian
from keepkeylib import tools

class TestMsgE712Verify(common.KeepKeyTest):
  
    def test_verify(self):
        self.requires_firmware("7.5.0")
        self.setup_mnemonic_allallall()
        f = open('eip712tests.json')
        txtests = json.load(f)
        f.close()

        for test in txtests['tests']:
            print("test: ", json.dumps(test['results']['test_data']))
            retval = self.client.e712_types_values(
                n = tools.parse_path(test['path']),
                types_prop = "{\"types\": " + json.dumps(test['types']) + "}",
                ptype_prop = "{\"primaryType\": " + json.dumps(test['primaryType']) + "}",
                value_prop = "{\"domain\": " + json.dumps(test['domain']) + "}",
                typevals = 1
            )

            retval = self.client.e712_types_values(
                n = tools.parse_path(test['path']),
                types_prop = "{\"types\": " + json.dumps(test['types']) + "}",
                ptype_prop = "{\"primaryType\": " + json.dumps(test['primaryType']) + "}",
                value_prop = "{\"message\": " + json.dumps(test['message']) + "}",
                typevals = 2
            )
            self.assertEqual(retval.address, test['results']['address'])
            self.assertEqual(binascii.hexlify(retval.domain_separator_hash), test['results']['domain_separator_hash'][2:])
            if (retval.has_msg_hash):
                self.assertEqual(binascii.hexlify(retval.message_hash), test['results']['message_hash'][2:])
            self.assertEqual(binascii.hexlify(retval.signature), test['results']['sig'][2:])

if __name__ == '__main__':
    unittest.main()
