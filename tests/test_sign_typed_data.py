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
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_allallall()
        with open('sign_typed_data.json') as f:
            txtests = json.load(f)

        def sign(test):
            parameters = test['parameters']
            kwargs = {
                'n': tools.parse_path(parameters['path']),
                'ds_hash': binascii.unhexlify(
                    parameters['domain_separator_hash'][2:]),
            }
            if parameters['message_hash'] is not None:
                kwargs['m_hash'] = binascii.unhexlify(
                    parameters['message_hash'][2:])
            return self.client.ethereum_sign_typed_data_hash(**kwargs)

        # This endpoint receives only precomputed hashes. It must fail closed
        # unless the user explicitly opts in to blind signing.
        self.client.apply_policy('AdvancedMode', False)
        with self.assertRaises(CallException) as ctx:
            sign(txtests['tests'][0])
        self.assertIn('disabled by policy', str(ctx.exception))

        self.client.apply_policy('AdvancedMode', True)
        try:
            for test in txtests['tests']:
                print("test: ", json.dumps(test['name']))
                retval = sign(test)
                self.assertEqual(retval.address, test['result']['address'])
                self.assertEqual(
                    binascii.hexlify(retval.signature),
                    test['result']['sig'][2:])
        finally:
            self.client.apply_policy('AdvancedMode', False)

if __name__ == '__main__':
    unittest.main()
