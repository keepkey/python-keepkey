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

    def test_ethereum_sign_x402_eip3009(self):
        """x402 EVM exact payments clear-sign the EIP-3009 authorization.

        This fixture follows the official v2 EVM shape: Base Sepolia USDC,
        ``TransferWithAuthorization``, facilitator-paid gas, and the exact
        recipient and value embedded in the signed EIP-712 message.
        """
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.requires_message("Ethereum712TypesValues")
        self.setup_mnemonic_allallall()

        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "TransferWithAuthorization": [
                    {"name": "from", "type": "address"},
                    {"name": "to", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "validAfter", "type": "uint256"},
                    {"name": "validBefore", "type": "uint256"},
                    {"name": "nonce", "type": "bytes32"},
                ],
            },
            "primaryType": "TransferWithAuthorization",
            "domain": {
                "name": "USDC",
                "version": "2",
                "chainId": 84532,
                "verifyingContract":
                    "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            },
            "message": {
                "from": "0x73d0385F4d8E00C5e6504C6030F47BF6212736A8",
                "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                "value": "2000",
                "validAfter": "0",
                "validBefore": "2000000000",
                "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480",
            },
        }

        # Structured EIP-712 is clear-signable with blind signing disabled.
        self.client.apply_policy('AdvancedMode', False)
        response = self.client.ethereum_sign_typed_data(
            tools.parse_path("m/44'/60'/0'/0/0"), typed_data)

        # Hashes are independent reference values from the EIP-712 V4 encoder.
        self.assertEqual(
            binascii.hexlify(response.domain_separator_hash),
            b"71f17a3b2ff373b803d70a5a07c046c1a2bc8e89c09ef722fcb047abe94c9818")
        self.assertEqual(
            binascii.hexlify(response.message_hash),
            b"ccb8d59d2e8a63beafb02887b4c9dd2f79d3527df4167f8c6b36e3e43cf373be")
        self.assertEqual(response.address,
                         "0x73d0385F4d8E00C5e6504C6030F47BF6212736A8")
        self.assertEqual(len(response.signature), 65)

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
