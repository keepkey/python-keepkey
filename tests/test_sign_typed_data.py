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

import keepkeylib.messages_pb2 as proto
import keepkeylib.messages_ethereum_pb2 as eth_proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian
from keepkeylib import tools

class TestMsgEthereumSignTypedDataHash(common.KeepKeyTest):
  
    def test_ethereum_sign_typed_data_hash(self):
        self.requires_firmware("7.4.0")
        self.setup_mnemonic_allallall()
        f = open('sign_typed_data.json')
        txtests = json.load(f)
        f.close()

        for test in txtests['tests']:
            print("test: ", json.dumps(test['name']))
            if test['parameters']['message_hash'] != None:
                retval = self.client.ethereum_sign_typed_data_hash(
                    n = tools.parse_path(test['parameters']['path']),
                    ds_hash = binascii.unhexlify(test['parameters']['domain_separator_hash'][2:]),
                    m_hash = binascii.unhexlify(test['parameters']['message_hash'][2:])
                    )
            else:
                retval = self.client.ethereum_sign_typed_data_hash(
                    n = tools.parse_path(test['parameters']['path']),
                    ds_hash = binascii.unhexlify(test['parameters']['domain_separator_hash'][2:]),
                    )

            self.assertEqual(retval.address, test['result']['address'])
            self.assertEqual(binascii.hexlify(retval.signature), test['result']['sig'][2:])

if __name__ == '__main__':
    unittest.main()
