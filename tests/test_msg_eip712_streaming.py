# Structured EIP-712 over the device-driven streaming protocol.
#
# The expected hashes here come from OUTSIDE this repository -- the reference
# implementation EIP-712 itself links to, and a constant published by Circle in
# the deployed USDC contract. That matters more than it looks: the firmware,
# hdwallet and the python client were all written by the same hand against the
# same reading of the spec, so three of them agreeing proves only that the
# reading is self-consistent. Only an outside number can catch a shared
# misreading.

import copy
import time
import unittest

import common
import oled_text
from keepkeylib import eip712_stream as es
from keepkeylib import messages_ethereum_pb2 as eth
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types
from keepkeylib.client import CallException

PATH = [0x8000002C, 0x8000003C, 0x80000000, 0, 0]
SETTLE = 0.3  # seconds for a confirm screen to finish drawing

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


# --- Independent EIP-712 reference encoder ----------------------------------
# Written from the EIP-712 specification text and deliberately NOT built on
# keepkeylib.eip712_stream (the host half of the protocol under test), so a
# shared misreading of arrays or nested dimensions cannot make both sides
# agree. keccak comes from pycryptodome directly.
def _keccak(data):
    from Crypto.Hash import keccak
    return keccak.new(digest_bits=256, data=data).digest()


def _ref_base_struct(type_name):
    return type_name.split('[', 1)[0]


def _ref_encode_type(primary, types):
    deps = set()

    def collect(name):
        if name in deps or name not in types:
            return
        deps.add(name)
        for field in types[name]:
            collect(_ref_base_struct(field['type']))

    collect(primary)
    deps.discard(primary)
    return ''.join(
        '%s(%s)' % (name, ','.join('%s %s' % (f['type'], f['name'])
                                   for f in types[name]))
        for name in [primary] + sorted(deps))


def _ref_int(value):
    if isinstance(value, str):
        return int(value, 16) if value.startswith('0x') else int(value)
    return int(value)


def _ref_encode_value(type_name, value, types):
    if type_name.endswith(']'):
        # Arrays: keccak of the concatenated encodings of the elements, where
        # each element of T[n][m] is itself an encoded T[n] array.
        inner = type_name[:type_name.rindex('[')]
        return _keccak(b''.join(
            _ref_encode_value(inner, item, types) for item in value))
    if type_name in types:
        return _ref_hash_struct(type_name, value, types)
    if type_name == 'string':
        return _keccak(value.encode('utf-8'))
    if type_name == 'bytes':
        return _keccak(bytes.fromhex(value[2:]))
    if type_name == 'address':
        return bytes(12) + bytes.fromhex(value[2:])
    if type_name == 'bool':
        return (1 if value else 0).to_bytes(32, 'big')
    if type_name.startswith('bytes'):
        return bytes.fromhex(value[2:]).ljust(32, b'\0')
    if type_name.startswith('uint'):
        return _ref_int(value).to_bytes(32, 'big')
    if type_name.startswith('int'):
        return (_ref_int(value) % (1 << 256)).to_bytes(32, 'big')
    raise ValueError('reference encoder: unsupported type ' + type_name)


def _ref_hash_struct(name, data, types):
    encoded = _keccak(_ref_encode_type(name, types).encode('ascii'))
    for field in types[name]:
        encoded += _ref_encode_value(field['type'], data[field['name']], types)
    return _keccak(encoded)


def reference_eip712_hashes(doc):
    """Return (domain_separator, message_hash, signing_digest).

    primaryType EIP712Domain signs keccak(0x1901 || domainSeparator) with no
    message hash (eth-sig-util v4); message_hash is None then."""
    types = doc['types']
    domain = _ref_hash_struct('EIP712Domain', doc['domain'], types)
    if doc['primaryType'] == 'EIP712Domain':
        return domain, None, _keccak(b'\x19\x01' + domain)
    message = _ref_hash_struct(doc['primaryType'], doc['message'], types)
    return domain, message, _keccak(b'\x19\x01' + domain + message)


def recover_signer(signature, digest):
    from ecdsa import VerifyingKey, SECP256k1, util
    rec = signature[64] - 27
    if rec not in (0, 1):
        raise AssertionError('unexpected recovery byte %d' % signature[64])
    keys = VerifyingKey.from_public_key_recovery_with_digest(
        signature[:64], digest, SECP256k1, hashfunc=None,
        sigdecode=util.sigdecode_string)
    return _keccak(keys[rec].to_string())[-20:]


class TestEip712StreamHelpers(unittest.TestCase):

    def test_reference_encoder_reproduces_the_published_spec_hashes(self):
        """The independent encoder is itself checked against Example.js."""
        domain, message, _ = reference_eip712_hashes(SPEC_MAIL)
        self.assertEqual(domain.hex(), SPEC_DOMAIN_SEPARATOR)
        self.assertEqual(message.hex(), SPEC_MESSAGE_HASH)

    def test_review_identifiers_are_exact_and_unambiguous(self):
        doc = {
            'types': {
                'Permit': [
                    {'name': 'value', 'type': 'uint256'},
                    {'name': 'value', 'type': 'uint256'},
                ],
            },
        }
        with self.assertRaises(es.Eip712Error) as duplicate:
            es.struct_members(doc, 'Permit')
        self.assertIn('Duplicate', str(duplicate.exception))

        doc['types']['Permit'][1]['name'] = 'identifier_that_would_be_truncated'
        with self.assertRaises(es.Eip712Error) as overlong:
            es.struct_members(doc, 'Permit')
        self.assertIn('canonical EIP-712 identifier', str(overlong.exception))

        doc['types']['Permit'][1]['name'] = 'amount%08x'
        with self.assertRaises(es.Eip712Error) as malformed:
            es.struct_members(doc, 'Permit')
        self.assertIn('canonical EIP-712 identifier', str(malformed.exception))

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

    def _walk(self, doc, max_steps=400, decline_final=False):
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

        # (ButtonRequest code, framebuffer) for every screen, in order.
        self.frames = []
        resp = self.client.call_raw(msg)
        for _ in range(max_steps):
            if isinstance(resp, proto.ButtonRequest):
                # This is a manual, device-driven call_raw() loop, so no
                # callback_ButtonRequest() will capture the field being
                # approved. Retain it while that exact field is still active.
                self.client.capture_oled()
                # capture_oled() only settles when screenshots are enabled;
                # the text assertions need the finished frame either way.
                time.sleep(SETTLE)
                self.frames.append(
                    (resp.code, bytes(self.client.debug.read_layout())))
                if decline_final and resp.code == types.ButtonRequest_SignTx:
                    self.client.debug.press_no()
                else:
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

    def _assert_final_sign_screen(self, first_line):
        """Every typed-data signature ends with ONE "Sign Typed Data" screen
        (ButtonRequest_SignTx); only its own continuation pages follow it."""
        codes = [code for code, _ in self.frames]
        self.assertEqual(codes.count(types.ButtonRequest_SignTx), 1)
        final = codes.index(types.ButtonRequest_SignTx)
        self.assertTrue(all(code == types.ButtonRequest_Other
                            for code in codes[final + 1:]))
        layout = self.frames[final][1]
        self.assertIsNotNone(oled_text.find_line(
            layout, 'SIGN TYPED DATA', oled_text.TITLE_FONT))
        self.assertIsNotNone(oled_text.find_line(layout, first_line))
        return final

    def _leaf_index(self, path):
        """Index of the first screen whose body starts with `path`."""
        for index, (_, layout) in enumerate(self.frames):
            if oled_text.find_line(layout, path) is not None:
                return index
        self.fail('no screen shows the %r leaf' % path)

    def _assert_reference_signature(self, doc, resp):
        """The device's hashes AND signature match an independent encoder."""
        self.assertIsInstance(resp, eth.EthereumTypedDataSignature)
        domain, message, digest = reference_eip712_hashes(doc)
        self.assertEqual(resp.domain_separator_hash.hex(), domain.hex())
        if doc['primaryType'] == 'EIP712Domain':
            self.assertFalse(resp.has_msg_hash)
            self.assertEqual(resp.message_hash, b'')
        else:
            self.assertEqual(resp.message_hash.hex(), message.hex())
        self._assert_final_sign_screen('Sign ' + doc['primaryType'])
        self.assertEqual(len(resp.signature), 65)
        address = self.client.ethereum_get_address(PATH)
        self.assertEqual(recover_signer(resp.signature, digest).hex(),
                         address.hex())

    def setUp(self):
        super(TestMsgEip712Streaming, self).setUp()
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.requires_structured_eip712()
        self.setup_mnemonic_nopin_nopassphrase()
        # The device-driven stream validates, displays and hashes the same
        # bytes. It is not the blind precomputed-hash endpoint and must work
        # with Advanced Mode disabled.
        self.client.apply_policy('AdvancedMode', 0)
        # The report entries describe typed-data fields, not the policy prompt.
        self.client.reset_screenshots()

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
        self._assert_reference_signature(SPEC_MAIL, resp)

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
        self._assert_reference_signature(doc, resp)

    def test_multidimensional_arrays_walk_outermost_first_on_device(self):
        """Host and device must traverse asymmetric Solidity dimensions alike."""
        doc = {
            'types': {
                'EIP712Domain': [],
                'Matrix': [{'name': 'values', 'type': 'int16[2][4]'}],
            },
            'primaryType': 'Matrix',
            'domain': {},
            'message': {
                'values': [
                    [1, 2],
                    [3, 4],
                    [5, 6],
                    [7, 8],
                ],
            },
        }

        resp = self._walk(doc)
        self._assert_reference_signature(doc, resp)

    def test_permit2_batch_walks_realistic_nested_array(self):
        """The production Permit2 Batch shape, including trailing root fields.

        The smaller Basket fixture proves the array primitive, but does not
        exercise a multi-field child struct followed by more members on the
        parent.  That is the shape Uniswap and swap providers actually send.
        """
        doc = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "PermitDetails": [
                    {"name": "token", "type": "address"},
                    {"name": "amount", "type": "uint160"},
                    {"name": "expiration", "type": "uint48"},
                    {"name": "nonce", "type": "uint48"},
                ],
                "PermitBatch": [
                    {"name": "details", "type": "PermitDetails[]"},
                    {"name": "spender", "type": "address"},
                    {"name": "sigDeadline", "type": "uint256"},
                ],
            },
            "primaryType": "PermitBatch",
            "domain": {
                "name": "Permit2",
                "chainId": 1,
                "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
            },
            "message": {
                "details": [
                    {
                        "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                        "amount": "250000000",
                        "expiration": "1893456000",
                        "nonce": "1",
                    },
                    {
                        "token": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
                        "amount": "500000000000000000000",
                        "expiration": "1893456000",
                        "nonce": "2",
                    },
                ],
                "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                "sigDeadline": "1893456000",
            },
        }
        resp = self._walk(doc)
        self._assert_reference_signature(doc, resp)

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

    def test_advanced_mode_is_not_required_for_structured_review(self):
        """Exact device-driven review is available with blind signing off."""
        self.client.apply_policy('AdvancedMode', 0)
        resp = self._walk(SPEC_MAIL)
        self.assertIsInstance(resp, eth.EthereumTypedDataSignature)
        self.assertEqual(resp.domain_separator_hash.hex(), SPEC_DOMAIN_SEPARATOR)
        self.assertEqual(resp.message_hash.hex(), SPEC_MESSAGE_HASH)

    def test_declining_the_final_sign_screen_returns_no_signature(self):
        """The final "Sign Typed Data" screen is a real consent: declining it
        after every leaf was approved signs nothing."""
        resp = self._walk(SPEC_MAIL, decline_final=True)
        self.assertIsInstance(resp, proto.Failure)
        self.assertEqual((resp.code, resp.message),
                         (types.Failure_ActionCancelled,
                          'Signing cancelled by user'))
        codes = [code for code, _ in self.frames]
        self.assertEqual(codes.count(types.ButtonRequest_SignTx), 1)
        self.assertEqual(codes[-1], types.ButtonRequest_SignTx)

    def test_domain_only_signature_matches_an_independent_digest(self):
        """primaryType EIP712Domain signs keccak(0x1901 || domainSeparator)."""
        doc = dict(SPEC_MAIL, primaryType='EIP712Domain', message={})
        resp = self._walk(doc)
        self.assertIsInstance(resp, eth.EthereumTypedDataSignature)
        self.assertEqual(resp.domain_separator_hash.hex(), SPEC_DOMAIN_SEPARATOR)
        self._assert_reference_signature(doc, resp)

    def test_unlimited_permits_are_refused_before_the_amount_screen(self):
        """EIP-2612 Permit.value and Permit2 PermitDetails.amount at their
        all-ones maximum are refused before that leaf is ever displayed."""
        permit = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "Permit": [
                    {"name": "owner", "type": "address"},
                    {"name": "spender", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"},
                ],
            },
            "primaryType": "Permit",
            "domain": {"name": "USD Coin", "version": "2", "chainId": 1,
                       "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
            "message": {
                "owner": "0x73d0385F4d8E00C5e6504C6030F47BF6212736A8",
                "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                "value": "1000000", "nonce": "0", "deadline": "1893456000"},
        }
        permit2 = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "PermitDetails": [
                    {"name": "token", "type": "address"},
                    {"name": "amount", "type": "uint160"},
                    {"name": "expiration", "type": "uint48"},
                    {"name": "nonce", "type": "uint48"},
                ],
                "PermitSingle": [
                    {"name": "details", "type": "PermitDetails"},
                    {"name": "spender", "type": "address"},
                    {"name": "sigDeadline", "type": "uint256"},
                ],
            },
            "primaryType": "PermitSingle",
            "domain": {"name": "Permit2", "chainId": 1,
                       "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"},
            "message": {
                "details": {
                    "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount": "250000000", "expiration": "1893456000",
                    "nonce": "1"},
                "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                "sigDeadline": "1893456000"},
        }
        for doc, path, leaf, bits in ((permit, ("value",), "value", 256),
                                      (permit2, ("details", "amount"),
                                       "details.amount", 160)):
            # A finite amount signs and shows the leaf; its position is where
            # the unlimited amount must stop.
            self._assert_reference_signature(doc, self._walk(doc))
            before_leaf = self._leaf_index(leaf)
            unlimited = copy.deepcopy(doc)
            target = unlimited["message"]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = str((1 << bits) - 1)
            resp = self._walk(unlimited)
            self.assertIsInstance(resp, proto.Failure)
            self.assertEqual((resp.code, resp.message),
                             (types.Failure_SyntaxError,
                              'Unlimited ERC20 approval is disabled'))
            self.assertEqual(len(self.frames), before_leaf)

    def test_1024_byte_dynamic_bytes_leaf_signs(self):
        """A 1024-byte `bytes` leaf is reviewed in parts and signs; the digest
        and signer are checked independently."""
        doc = {
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}],
                "Blob": [{"name": "data", "type": "bytes"}],
            },
            "primaryType": "Blob",
            "domain": {"name": "Blob"},
            "message": {"data": "0x" + bytes(range(256)).hex() * 4},
        }
        resp = self._walk(doc)
        self._assert_reference_signature(doc, resp)


if __name__ == '__main__':
    unittest.main()
