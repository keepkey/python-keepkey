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
  
    def test_structured_eip712_is_refused(self):
        """Post-RC18 firmware disables legacy structured EIP-712 outright.

        ethereum_structured_eip712_enabled() returns false
        (lib/firmware/ethereum.c), so fsm_msgEthereum712TypesValues fails closed
        before parsing anything. The legacy JSON parser could not guarantee that
        every displayed value was the canonical value being hashed, and the
        release withdrew the feature rather than ship a screen it could not
        vouch for.

        This is NOT an AdvancedMode gate and there is no opt-in: assert the
        refusal. When a canonical implementation lands, this test should be
        replaced by test_verify below, not simply deleted.
        """
        self.requires_fullFeature()
        self.requires_firmware("7.16.0")
        self.setup_mnemonic_allallall()

        try:
            self.client.e712_types_values(
                n=tools.parse_path("m/44'/60'/0'/0/0"),
                types_prop='{"types": {"EIP712Domain": []}}',
                ptype_prop='{"primaryType": "EIP712Domain"}',
                value_prop='{"domain": {}}',
                typevals=1,
            )
            self.fail("Expected Failure -- legacy structured EIP-712 is disabled")
        except CallException as e:
            self.assertIn("Structured EIP-712 disabled", str(e))

    @unittest.skip("structured EIP-712 is disabled in 7.14.2; see "
                   "test_structured_eip712_is_refused. Re-enable together with "
                   "a canonical display implementation.")
    def test_verify(self):
        self.requires_fullFeature()
        self.requires_firmware("7.5.1")
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
