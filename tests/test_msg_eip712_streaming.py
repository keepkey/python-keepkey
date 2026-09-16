# Structured EIP-712 over the device-driven streaming protocol.
#
# The expected hashes here come from OUTSIDE this repository -- the reference
# implementation EIP-712 itself links to, and a constant published by Circle in
# the deployed USDC contract. That matters more than it looks: the firmware,
# hdwallet and the python client were all written by the same hand against the
# same reading of the spec, so three of them agreeing proves only that the
# reading is self-consistent. Only an outside number can catch a shared
# misreading.

import unittest

import common
from keepkeylib import eip712_stream as es
from keepkeylib import messages_ethereum_pb2 as eth
from keepkeylib import messages_pb2 as proto
from keepkeylib.client import CallException

PATH = [0x8000002C, 0x8000003C, 0x80000000, 0, 0]

# assets/eip-712/Example.js in ethereum/EIPs publishes every intermediate.
SPEC_MAIL = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"},
        ],
        "Mail": [
            {"name": "from", "type": "Person"},
            {"name": "to", "type": "Person"},
            {"name": "contents", "type": "string"},
        ],
    },
    "primaryType": "Mail",
    "domain": {"name": "Ether Mail", "version": "1", "chainId": 1,
               "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
    "message": {
        "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
        "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
        "contents": "Hello, Bob!",
    },
}
SPEC_DOMAIN_SEPARATOR = "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
SPEC_MESSAGE_HASH = "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"


class TestEip712StreamHelpers(unittest.TestCase):

    def test_multidimensional_arrays_are_walked_outermost_first(self):
        doc = {
            'types': {
                'EIP712Domain': [],
                'Matrix': [{'name': 'values', 'type': 'int16[2][][4]'}],
            },
            'primaryType': 'Matrix',
            'domain': {},
            'message': {
                'values': [
                    [[1, 2]],
                    [[3, 4], [5, 6]],
                    [[7, 8], [9, 10], [11, 12]],
                    [[13, 14]],
                ],
            },
        }

        self.assertEqual(es.resolve_member_path(doc, [1, 0]), ('length', 4))
        self.assertEqual(es.resolve_member_path(doc, [1, 0, 2]), ('length', 3))
        self.assertEqual(es.resolve_member_path(doc, [1, 0, 2, 1]), ('length', 2))
        result = es.resolve_member_path(doc, [1, 0, 2, 1, 0])
        self.assertEqual(result[0], 'value')
        self.assertEqual(result[2], 9)

    def test_innermost_fixed_array_length_is_checked(self):
        doc = {
            'types': {
                'EIP712Domain': [],
                'Matrix': [{'name': 'values', 'type': 'int16[2][][4]'}],
            },
            'primaryType': 'Matrix',
            'domain': {},
            'message': {
                'values': [
                    [[1, 2]],
                    [[3, 4]],
                    [[5]],
                    [[6, 7]],
                ],
            },
        }

        with self.assertRaises(es.Eip712Error) as ctx:
            es.resolve_member_path(doc, [1, 0, 2, 0])
        self.assertIn('declares 2 elements', str(ctx.exception))


class TestMsgEip712Streaming(common.KeepKeyTest):

    def _walk(self, doc, max_steps=400):
        """Answer whatever the device asks until it returns a signature.

        The DEVICE leads. Nothing here chooses the order, which is the property
        under test: a host that answered a different question than the one asked
        would produce a digest that does not verify.
        """
        msg = eth.EthereumSignTypedData()
        for n in PATH:
            msg.address_n.append(n)
        msg.primary_type = doc['primaryType']
        msg.metamask_v4_compat = True

        resp = self.client.call_raw(msg)
        for _ in range(max_steps):
            if isinstance(resp, proto.ButtonRequest):
                self.client.debug.press_yes()
                resp = self.client.call_raw(proto.ButtonAck())
            elif isinstance(resp, eth.EthereumTypedDataStructRequest):
                resp = self.client.call_raw(
                    es.build_struct_ack(es.struct_members(doc, resp.name)))
            elif isinstance(resp, eth.EthereumTypedDataValueRequest):
                r = es.resolve_member_path(doc, list(resp.member_path))
                ack = eth.EthereumTypedDataValueAck()
                ack.value = (es.encode_array_length(r[1]) if r[0] == 'length'
                             else es.encode_value(r[1], r[2]))
                resp = self.client.call_raw(ack)
            else:
                return resp
        raise AssertionError('walk did not terminate')

    def setUp(self):
        super(TestMsgEip712Streaming, self).setUp()
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.requires_structured_eip712()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('AdvancedMode', 1)

    def test_spec_example_matches_the_published_hashes(self):
        """The device's own hashes equal the EIP-712 reference implementation's.

        This is the one assertion that three agreeing implementations cannot
        substitute for. Both numbers are published by Example.js in
        ethereum/EIPs and are reproduced independently by Example.sol, by
        eth-sig-util's V3 and V4 snapshots, and by Mrtenz/eip-712.

        It also exercises the nested-struct path: Mail references Person twice,
        so the walk pushes a child frame, derives Person's typeHash through its
        own closure, folds it to 32 bytes and hands it back to the parent.
        """
        resp = self._walk(SPEC_MAIL)
        self.assertIsInstance(resp, eth.EthereumTypedDataSignature)
        self.assertEqual(resp.domain_separator_hash.hex(), SPEC_DOMAIN_SEPARATOR)
        self.assertEqual(resp.message_hash.hex(), SPEC_MESSAGE_HASH)
        self.assertEqual(len(resp.signature), 65)

    def test_array_of_structs_walks(self):
        """Arrays, which the walk refused until the decode buffer was reclaimed.

        An array hashes WITHOUT a typeHash prefix -- enc(array) is the keccak of
        the concatenated element encodings and nothing else -- so getting this
        wrong produces a digest no verifier reproduces rather than an error.
        """
        doc = {
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}],
                "Item": [{"name": "id", "type": "uint256"}],
                "Basket": [{"name": "items", "type": "Item[]"}],
            },
            "primaryType": "Basket",
            "domain": {"name": "Basket"},
            "message": {"items": [{"id": 1}, {"id": 2}]},
        }
        resp = self._walk(doc)
        self.assertIsInstance(resp, eth.EthereumTypedDataSignature)
        self.assertEqual(len(resp.signature), 65)

    def test_fixed_array_length_must_match_the_declared_size(self):
        """A declared dimension is part of the type string and so of typeHash.

        The device only ever learns the count from us, so if it accepted a
        different one it would sign a document whose type declares another and
        nothing downstream could notice.
        """
        doc = {
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}],
                "Pair": [{"name": "who", "type": "address[2]"}],
            },
            "primaryType": "Pair",
            "domain": {"name": "Pair"},
            "message": {"who": ["0x" + "aa" * 20, "0x" + "bb" * 20, "0x" + "cc" * 20]},
        }
        # The host refuses before the device is ever asked to hash it.
        with self.assertRaises(es.Eip712Error) as ctx:
            self._walk(doc)
        self.assertIn('declares 2 elements', str(ctx.exception))

    def test_advanced_mode_gates_the_endpoint(self):
        """New parser surface reachable from a website stays behind the gate
        until there is hardware evidence for it."""
        self.client.apply_policy('AdvancedMode', 0)
        msg = eth.EthereumSignTypedData()
        for n in PATH:
            msg.address_n.append(n)
        msg.primary_type = 'Mail'
        resp = self.client.call_raw(msg)
        self.assertIsInstance(resp, proto.Failure)
        self.assertIn('AdvancedMode', resp.message)


if __name__ == '__main__':
    unittest.main()
