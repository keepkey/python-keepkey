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

    def test_long_values_are_chunked_only_for_capable_firmware(self):
        """Over 1 KB, a value goes in 1 KB chunks: the first names the total,
        each later one echoes the offset asked for. Without the capability,
        or in the domain, the host refuses rather than send a value an older
        device would truncate."""
        doc = {
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}],
                "Msg": [{"name": "data", "type": "bytes"},
                        {"name": "note", "type": "string"},
                        {"name": "list", "type": "uint8[]"}],
            },
            "primaryType": "Msg",
            "domain": {"name": "x" * 1025},
            "message": {"data": "0x" + "ab" * 1025, "note": "y" * 1024,
                        "list": [1]},
        }

        def request(path, offset=None):
            req = eth.EthereumTypedDataValueRequest(member_path=path)
            if offset is not None:
                req.value_offset = offset
            return req

        with self.assertRaisesRegex(es.Eip712Error, 'chunked values'):
            es.value_ack(doc, request([1, 0]))
        first = es.value_ack(doc, request([1, 0]), chunked=True)
        self.assertEqual(first.value, b'\xab' * 1024)
        self.assertEqual(first.value_total_length, 1025)
        self.assertFalse(first.HasField('value_offset'))
        last = es.value_ack(doc, request([1, 0], 1024), chunked=True)
        self.assertEqual((last.value, last.value_offset), (b'\xab', 1024))
        self.assertFalse(last.HasField('value_total_length'))
        # A string is read a second time from 0.
        again = es.value_ack(doc, request([1, 0], 0), chunked=True)
        self.assertEqual((len(again.value), again.value_offset), (1024, 0))
        with self.assertRaises(es.Eip712Error):
            es.value_ack(doc, request([1, 0], 1025), chunked=True)
        # 1024 bytes still go whole, with or without the capability.
        for chunked in (False, True):
            whole = es.value_ack(doc, request([1, 1]), chunked)
            self.assertEqual(whole.value, b'y' * 1024)
            self.assertFalse(whole.HasField('value_total_length'))
            with self.assertRaises(es.Eip712Error):
                es.value_ack(doc, request([1, 1], 1024), chunked)
        with self.assertRaisesRegex(es.Eip712Error, 'domain'):
            es.value_ack(doc, request([0, 0]), chunked=True)
        with self.assertRaises(es.Eip712Error):
            es.value_ack(doc, request([1, 2], 0), chunked=True)
        doc["message"]["data"] = "0x" + "00" * (es.MAX_VALUE_BYTES + 1)
        with self.assertRaises(es.Eip712Error):
            es.value_ack(doc, request([1, 0]), chunked=True)

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
        # Read before the walk: reading Features mid-walk would end it.
        chunked = self._chunked_values()

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
                resp = self.client.call_raw(es.value_ack(doc, resp, chunked))
            else:
                return resp
        raise AssertionError('walk did not terminate')

    def _chunked_values(self):
        """Whether the firmware takes values over 1 KB in chunks."""
        return es.CHUNKED_VALUES in (self.firmware_capabilities() or ())

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
        # The reported signer must be intact too: the response is built after
        # the final screen, so a DebugLink read during it cannot erase it.
        self.assertEqual(resp.address.lower(), '0x' + address.hex())

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

    # Uniswap's request from the owner's Vault log (2026-04-10): mainnet USDC,
    # spender 0x66a9...A8Af, an UNLIMITED allowance expiring in 30 days.
    UNISWAP_PERMIT2 = {
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
        "domain": {"name": "Permit2", "chainId": "1",
                   "verifyingContract":
                       "0x000000000022d473030f116ddee9f6b43ac78ba3"},
        "message": {
            "details": {
                "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                "amount": "1461501637330902918203684832716283019655932542975",
                "expiration": "1778393946", "nonce": "0"},
            "spender": "0x66a9893cc07d91d95644aedd05d03f95e1dba8af",
            "sigDeadline": "1775803746"},
    }

    def _screens(self):
        """(title, layout) of every screen before the final sign screen."""
        final = self._assert_final_sign_screen('Sign PermitSingle')
        return [layout for _, layout in self.frames[:final]]

    def test_permit2_reads_as_who_what_until_when(self):
        """SRS-7.16 §3.7: a canonical Permit2 PermitSingle is described in
        words. No raw domain or leaf screens; an unlimited allowance is
        allowed and stated, with exact dates from the signed timestamps."""
        self.requires_firmware("7.16.0")
        self.requires_release_capability("permit2-review")
        doc = self.UNISWAP_PERMIT2
        resp = self._walk(doc)
        self._assert_reference_signature(doc, resp)
        want = [
            ("PERMIT2", "Allow 0x66a9...A8Af to spend UNLIMITED USDC from "
                        "this wallet until 2026-05-10 06:19 UTC"),
            ("LIMITS", "Spender may take\nUNLIMITED USDC"),
            ("LIMITS", "Allowance expires\n2026-05-10 06:19 UTC"),
            ("LIMITS", "Signature valid until\n2026-04-10 06:49 UTC"),
            ("TOKEN", "USDC\n0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            ("SPENDER", "Not identified\n"
                        "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"),
            ("DETAILS", "Nonce 0"),
            ("DETAILS", "Permit2 contract on chain 1"),
        ]
        screens = self._screens()
        self.assertEqual(len(screens), len(want))
        for i, (layout, (title, body)) in enumerate(zip(screens, want)):
            self.assertIsNotNone(
                oled_text.find_line(layout, title, oled_text.TITLE_FONT),
                "screen %d is not titled %r" % (i, title))
            self.assertTrue(oled_text.shows(layout, body),
                            "screen %d does not show %r" % (i, body))

    # signedPayload from the deployed ClearSign Worker (source d2849aaf8),
    # POST /v1/evm/name {chainId 1, address 0x66a9...a8af}; deterministic.
    UR_V2_NAME = bytes.fromhex(
        "030101000000016b359b004b6565704b657920416c7068612037313600000000"
        "00000000000000000000000342f5f9704494b3f9bd72295eecaf29d783d23ea0"
        "2b2dc9f48abcd2e46d4850cffc4364672f0172aa70ed21eacc2ea8bd0d333119"
        "ddf048b096686e1a8e56bda438f9e70b9cfc229a1e93e2d91846c31c4083d8b1"
        "76e225d76341069dd22826cf060000000166a9893cc07d91d95644aedd05d03f"
        "95e1dba8af18556e697377617020556e6976657273616c20526f757465720100"
        "000000806d645ca60ffadfd620a8abda7a77f84dbbf4770644e51c234937f715"
        "12d2019b30068dfd95e88e2ebbdd2186db629012a9d861b55b14d3ef9000c99f"
        "ef5de4811b")

    def test_permit2_names_a_vouched_spender_beside_its_address(self):
        """A KeepKey-certified name record names the spender; the full address
        is still shown, and the voucher is identified."""
        self.requires_firmware("7.16.0")
        self.requires_message("EthereumTxMetadata")
        self.requires_release_capability("permit2-review")
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=self.UR_V2_NAME, metadata_version=3, key_id=0x80)
        self.assertEqual(resp.classification, 1)  # VERIFIED
        doc = self.UNISWAP_PERMIT2
        self._assert_reference_signature(doc, self._walk(doc))
        screens = self._screens()
        self.assertEqual(len(screens), 9)
        self.assertTrue(oled_text.shows(
            screens[0], "Allow Uniswap Universal Router to spend UNLIMITED "
                        "USDC from this wallet until 2026-05-10 06:19 UTC"))
        self.assertTrue(oled_text.shows(
            screens[5], "Uniswap Universal Router\n"
                        "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"))
        self.assertTrue(oled_text.shows(
            screens[8], "Spender named by KeepKey Alpha 716 A9531B9D\n"
                        "certified by KeepKey"))
        # One review per record: the next request is not named.
        self._walk(doc)
        self.assertTrue(oled_text.shows(
            self._screens()[5], "Not identified\n"
                                "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"))

    def test_permit2_name_never_outlives_a_failed_request(self):
        """A record sent ahead of a request that FAILS is gone with it: the
        next Permit2 says "Not identified" (Copilot r1 on #919)."""
        self.requires_firmware("7.16.0")
        self.requires_message("EthereumTxMetadata")
        self.requires_release_capability("permit2-review")
        self.client.ethereum_send_tx_metadata(
            signed_payload=self.UR_V2_NAME, metadata_version=3, key_id=0x80)
        # An unlimited EIP-2612 permit whose domain names no token
        # (no verifyingContract): ambiguous, so the device still refuses it.
        refused = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
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
            "domain": {"name": "USD Coin", "chainId": 1},
            "message": {
                "owner": "0x73d0385F4d8E00C5e6504C6030F47BF6212736A8",
                "spender": "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af",
                "value": str((1 << 256) - 1), "nonce": "0",
                "deadline": "1893456000"},
        }
        failure = self._walk(refused)
        self.assertIsInstance(failure, proto.Failure)
        self.assertEqual(failure.message,
                         'Unlimited ERC20 approval is disabled')
        doc = self.UNISWAP_PERMIT2
        self._assert_reference_signature(doc, self._walk(doc))
        self.assertTrue(oled_text.shows(
            self._screens()[5], "Not identified\n"
                                "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"))

    def test_permit2_exact_amount_and_lookalikes(self):
        """An exact amount is shown exactly. A PermitSingle outside the Permit2
        contract keeps the raw review, and its domain screens still appear in
        order, so nothing is hidden by the attempt to recognise it."""
        self.requires_firmware("7.16.0")
        self.requires_release_capability("permit2-review")
        exact = copy.deepcopy(self.UNISWAP_PERMIT2)
        exact["message"]["details"]["amount"] = "250000000"
        self._assert_reference_signature(exact, self._walk(exact))
        self.assertTrue(oled_text.shows(self._screens()[1],
                                        "Spender may take\n250 USDC"))
        other = copy.deepcopy(exact)
        other["domain"]["verifyingContract"] = (
            "0x1111111111111111111111111111111111111111")
        self._assert_reference_signature(other, self._walk(other))
        self.assertIsNotNone(oled_text.find_line(
            self.frames[0][1], 'EIP-712 DOMAIN', oled_text.TITLE_FONT))
        self.assertIsNotNone(self._leaf_index("details.amount"))

    USDC_PERMIT = {
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
                   "verifyingContract":
                       "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
        "message": {
            "owner": "0x73d0385F4d8E00C5e6504C6030F47BF6212736A8",
            "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
            "value": "1000000", "nonce": "0", "deadline": "1893456000"},
    }

    # The canonical DAI permit (all-or-nothing `allowed`, `expiry` 0 = never).
    DAI_PERMIT = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Permit": [
                {"name": "holder", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "nonce", "type": "uint256"},
                {"name": "expiry", "type": "uint256"},
                {"name": "allowed", "type": "bool"},
            ],
        },
        "primaryType": "Permit",
        "domain": {"name": "Dai Stablecoin", "version": "1", "chainId": 1,
                   "verifyingContract":
                       "0x6B175474E89094C44Da98b954EedeAC495271d0F"},
        "message": {
            "holder": "0x73d0385F4d8E00C5e6504C6030F47BF6212736A8",
            "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
            "nonce": "0", "expiry": "0", "allowed": True},
    }

    def _warnings(self):
        """Indexes of the "UNLIMITED allowance" screens (F-D, D-010)."""
        return [i for i, (_, layout) in enumerate(self.frames)
                if oled_text.find_line(layout, 'UNLIMITED ALLOWANCE',
                                       oled_text.TITLE_FONT) is not None]

    def _assert_unlimited_warning(self, ticker, token, deadline):
        """Every leaf was shown; then the two warning screens, then the sign
        screen. Screen 1: "Allow <spender> to spend an UNLIMITED amount of
        <ticker>. It does not expire."; screen 2: ticker, token address,
        "Signature valid until", deadline, one per line. The device pages a
        long body by characters, so each drawn line is checked on the warning
        pages."""
        warnings = self._warnings()
        self.assertGreaterEqual(len(warnings), 2)
        final = self._assert_final_sign_screen('Sign Permit')
        self.assertEqual(warnings[-1], final - 1)
        pages = [self.frames[i][1] for i in warnings]
        spender = self.USDC_PERMIT["message"]["spender"]
        first = oled_text.wrap("Allow %s to spend an UNLIMITED amount of %s. "
                               "It does not expire." % (spender, ticker))
        second = oled_text.wrap("%s\n%s\nSignature valid until\n%s" %
                                (ticker, token, deadline))
        for line in first[:3] + ["It does not expire."] + second:
            self.assertTrue(any(oled_text.find_line(page, line) is not None
                                for page in pages), line)

    def test_unlimited_permits_are_refused_before_the_amount_screen(self):
        """7.15: EIP-2612 Permit.value at its all-ones maximum is refused
        before that leaf is ever displayed. 7.16 reviews a canonical one
        instead (F-D, D-010): test_canonical_unlimited_permits_sign_after_a_
        warning."""
        self.requires_firmware_below("7.16.0")
        self.requires_capability_absent("erc20-unlimited-permit-review")
        permit = copy.deepcopy(self.USDC_PERMIT)
        for doc, path, leaf, bits in ((permit, ("value",), "value", 256),):
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

    def test_unlimited_permits_sign_with_unlimited_on_the_value_screen(self):
        """7.15 (owner decision 2026-10-07): an unlimited EIP-2612 value, a
        DAI allowed=true and a Permit2 amount at its uint160 maximum are
        signed. The value's own screen is titled UNLIMITED APPROVAL and reads
        UNLIMITED; a finite value keeps the ordinary screen."""
        self.requires_firmware("7.15.0")
        self.requires_firmware_below("7.16.0")
        self.requires_release_capability("erc20-unlimited-permit-review")
        usdc = copy.deepcopy(self.USDC_PERMIT)
        usdc["message"]["value"] = str((1 << 256) - 1)
        permit2 = copy.deepcopy(self.UNISWAP_PERMIT2)
        cases = ((usdc, "value", "value\nuint256: UNLIMITED"),
                 (self.DAI_PERMIT, "allowed",
                  "allowed\nbool: UNLIMITED (allowed)"),
                 (permit2, "details.amount",
                  "details.amount\nuint160: UNLIMITED"))
        for doc, leaf, body in cases:
            self._assert_reference_signature(doc, self._walk(doc))
            warnings = [i for i, (_, layout) in enumerate(self.frames)
                        if oled_text.find_line(layout, 'UNLIMITED APPROVAL',
                                               oled_text.TITLE_FONT)
                        is not None]
            with self.subTest(leaf):
                self.assertEqual(warnings, [self._leaf_index(leaf)])
                self.assertTrue(oled_text.shows(self.frames[warnings[0]][1],
                                                body), body)
        self._assert_reference_signature(self.USDC_PERMIT,
                                         self._walk(self.USDC_PERMIT))
        self.assertIsNone(oled_text.find_text(
            [layout for _, layout in self.frames], "value\nuint256: UNLIMITED"))
        self.assertTrue(all(
            oled_text.find_line(layout, 'UNLIMITED APPROVAL',
                                oled_text.TITLE_FONT) is None
            for _, layout in self.frames))

    def test_canonical_unlimited_permits_sign_after_a_warning(self):
        """D-010 for permits (F-D): a canonical EIP-2612 permit of 2^255 or
        more, or a canonical DAI permit with allowed=true, is signed after
        two "UNLIMITED allowance" screens naming spender, token and deadline.
        2^255 - 1 is an exact amount: no warning."""
        self.requires_firmware("7.16.0")
        self.requires_release_capability("erc20-unlimited-permit-review")
        usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        for value in ((1 << 256) - 1, 1 << 255):
            doc = copy.deepcopy(self.USDC_PERMIT)
            doc["message"]["value"] = str(value)
            self._assert_reference_signature(doc, self._walk(doc))
            self._assert_unlimited_warning("USDC", usdc,
                                           "2030-01-01 00:00 UTC")
            # The amount leaf itself was still disclosed.
            self.assertIsNotNone(self._leaf_index("value"))

        exact = copy.deepcopy(self.USDC_PERMIT)
        exact["message"]["value"] = str((1 << 255) - 1)
        self._assert_reference_signature(exact, self._walk(exact))
        self.assertEqual(self._warnings(), [])

        dai = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
        doc = copy.deepcopy(self.DAI_PERMIT)
        self._assert_reference_signature(doc, self._walk(doc))
        self._assert_unlimited_warning("DAI", dai, "no deadline")
        doc["message"]["expiry"] = "1893456000"
        self._assert_reference_signature(doc, self._walk(doc))
        self._assert_unlimited_warning("DAI", dai, "2030-01-01 00:00 UTC")
        # allowed=false revokes: nothing to warn about.
        doc["message"]["allowed"] = False
        self._assert_reference_signature(doc, self._walk(doc))
        self.assertEqual(self._warnings(), [])

    def test_declining_the_unlimited_warning_signs_nothing(self):
        self.requires_firmware("7.16.0")
        self.requires_release_capability("erc20-unlimited-permit-review")
        doc = copy.deepcopy(self.USDC_PERMIT)
        doc["message"]["value"] = str((1 << 256) - 1)
        msg = eth.EthereumSignTypedData()
        for n in PATH:
            msg.address_n.append(n)
        msg.primary_type = doc['primaryType']
        msg.metamask_v4_compat = True
        resp = self.client.call_raw(msg)
        for _ in range(400):
            if isinstance(resp, proto.ButtonRequest):
                time.sleep(SETTLE)
                layout = bytes(self.client.debug.read_layout())
                if oled_text.find_line(layout, 'UNLIMITED ALLOWANCE',
                                       oled_text.TITLE_FONT) is not None:
                    self.client.debug.press_no()
                else:
                    self.client.debug.press_yes()
                resp = self.client.call_raw(proto.ButtonAck())
            elif isinstance(resp, eth.EthereumTypedDataStructRequest):
                resp = self.client.call_raw(
                    es.build_struct_ack(es.struct_members(doc, resp.name)))
            elif isinstance(resp, eth.EthereumTypedDataValueRequest):
                resp = self.client.call_raw(es.value_ack(doc, resp))
            else:
                break
        self.assertIsInstance(resp, proto.Failure)
        self.assertEqual(resp.code, types.Failure_ActionCancelled)

    def test_ambiguous_unlimited_permits_are_refused_before_the_amount_screen(
            self):
        """An unlimited permit the device cannot attribute is refused before
        that leaf is ever displayed: a Permit whose type hash is not
        EIP-2612's or DAI's, an EIP-2612 permit whose domain names no token,
        and an unlimited Permit2-shaped amount outside canonical
        PermitSingle."""
        self.requires_firmware("7.16.0")
        self.requires_release_capability("erc20-unlimited-permit-review")
        no_nonce = copy.deepcopy(self.USDC_PERMIT)  # another type hash
        no_nonce["types"]["Permit"] = [
            m for m in no_nonce["types"]["Permit"] if m["name"] != "nonce"]
        del no_nonce["message"]["nonce"]
        no_token = copy.deepcopy(self.USDC_PERMIT)
        no_token["types"]["EIP712Domain"] = [
            m for m in no_token["types"]["EIP712Domain"]
            if m["name"] != "verifyingContract"]
        del no_token["domain"]["verifyingContract"]
        no_token_dai = copy.deepcopy(self.DAI_PERMIT)
        no_token_dai["types"]["EIP712Domain"] = [
            m for m in no_token_dai["types"]["EIP712Domain"]
            if m["name"] != "verifyingContract"]
        del no_token_dai["domain"]["verifyingContract"]
        transfer = {  # Permit2 SignatureTransfer: not reviewed in words
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "TokenPermissions": [
                    {"name": "token", "type": "address"},
                    {"name": "amount", "type": "uint256"},
                ],
                "PermitTransferFrom": [
                    {"name": "permitted", "type": "TokenPermissions"},
                    {"name": "spender", "type": "address"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"},
                ],
            },
            "primaryType": "PermitTransferFrom",
            "domain": {"name": "Permit2", "chainId": 1, "verifyingContract":
                       "0x000000000022D473030F116dDEE9F6B43aC78BA3"},
            "message": {
                "permitted": {
                    "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount": "1000000"},
                "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                "nonce": "0", "deadline": "1893456000"},
        }
        cases = (
            (no_nonce, ("value",), "value", str((1 << 256) - 1)),
            (no_token, ("value",), "value", str(1 << 255)),
            (no_token_dai, ("allowed",), "allowed", True),
            (transfer, ("permitted", "amount"), "permitted.amount",
             str((1 << 256) - 1)),
        )
        for doc, path, leaf, unlimited_value in cases:
            finite = copy.deepcopy(doc)
            if leaf == "allowed":
                finite["message"]["allowed"] = False
            # A finite amount signs and shows the leaf; its position is where
            # the unlimited amount must stop.
            self._assert_reference_signature(finite, self._walk(finite))
            before_leaf = self._leaf_index(leaf)
            unlimited = copy.deepcopy(doc)
            target = unlimited["message"]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = unlimited_value
            resp = self._walk(unlimited)
            self.assertIsInstance(resp, proto.Failure, leaf)
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


    # -- Values over one ValueAck ------------------------------------------
    # Safe MultiSend data and Snapshot proposal bodies run past 1 KB. Firmware
    # with CAPABILITY_EIP712_CHUNKED_VALUES takes them in 1 KB chunks and
    # shows every byte, numbered over the whole value.

    def _walk_text(self, doc, tamper=None, decline=None, max_steps=600):
        """The walk, recording each confirmation's (title, body) exactly as
        formatted (once per confirmation, however it is paged). `tamper`
        may rewrite a value answer; `decline` names a body prefix to reject."""
        msg = eth.EthereumSignTypedData(address_n=PATH,
                                        primary_type=doc['primaryType'],
                                        metamask_v4_compat=True)
        screens = []
        resp = self.client.call_raw(msg)
        for _ in range(max_steps):
            if isinstance(resp, proto.ButtonRequest):
                text = self.client.debug.read_confirm_text()
                if not screens or screens[-1] != text:
                    screens.append(text)
                if decline and text[1].startswith(decline):
                    self.client.debug.press_no()
                else:
                    self.client.debug.press_yes()
                resp = self.client.call_raw(proto.ButtonAck())
            elif isinstance(resp, eth.EthereumTypedDataStructRequest):
                resp = self.client.call_raw(
                    es.build_struct_ack(es.struct_members(doc, resp.name)))
            elif isinstance(resp, eth.EthereumTypedDataValueRequest):
                ack = es.value_ack(doc, resp, chunked=True)
                if tamper:
                    tamper(ack)
                resp = self.client.call_raw(ack)
            else:
                return resp, screens
        raise AssertionError('walk did not terminate')

    @staticmethod
    def _escaped(data):
        """A string as the review draws it: 0x21-0x7e as itself but a
        backslash doubled, any other byte (a space too) as \\xNN."""
        return ''.join('\\\\' if b == 0x5c else chr(b) if 0x21 <= b <= 0x7e
                       else '\\x%02x' % b for b in data)

    def _parts(self, screens, path, type_name):
        """The parts of `path`, checked to count 1..N in order, joined."""
        joined, total = '', None
        for number, (_, body) in enumerate(
                b for b in screens if b[1].startswith(path + ' (')):
            head, _, rest = body.partition('\n')
            index, of = head[len(path) + 2:-1].split('/')
            self.assertEqual(int(index), number + 1)
            self.assertIn(total, (None, int(of)))
            total = int(of)
            self.assertTrue(rest.startswith(type_name + ': '), body[:60])
            joined += rest[len(type_name) + 2:]
        self.assertIsNotNone(total, 'no part of ' + path)
        self.assertEqual(number + 1, total)
        return joined, total

    def _assert_signed(self, doc, resp):
        self.assertIsInstance(resp, eth.EthereumTypedDataSignature,
                              getattr(resp, 'message', resp))
        domain, message, digest = reference_eip712_hashes(doc)
        self.assertEqual(resp.domain_separator_hash.hex(), domain.hex())
        self.assertEqual(resp.message_hash.hex(), message.hex())
        address = self.client.ethereum_get_address(PATH)
        self.assertEqual(recover_signer(resp.signature, digest).hex(),
                         address.hex())

    @staticmethod
    def _blob(data_type, value):
        return {
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}],
                "Blob": [{"name": "data", "type": data_type},
                         {"name": "n", "type": "uint256"}],
            },
            "primaryType": "Blob",
            "domain": {"name": "Blob"},
            "message": {"data": value, "n": 7},
        }

    def test_values_over_1kb_sign_in_chunks(self):
        """1024, 1025 and 2048 bytes, and a string with a three-byte
        character split across the first chunk boundary: each signs with the
        independent digest, every byte is shown once and in order, and the
        part counter covers the whole value from its first screen."""
        self.requires_release_capability(es.CHUNKED_VALUES)
        euro = 'a' * 1023 + '\u20ac' + 'b' * 500
        cases = [('bytes', bytes(range(256)) * 4),
                 ('bytes', bytes(range(256)) * 4 + b'\xfe'),
                 ('bytes', bytes(range(256)) * 8),
                 ('string', ('x' * 1025).encode()),
                 ('string', euro.encode('utf-8'))]
        for data_type, data in cases:
            with self.subTest(type=data_type, length=len(data)):
                value = ('0x' + data.hex() if data_type == 'bytes'
                         else data.decode('utf-8'))
                doc = self._blob(data_type, value)
                resp, screens = self._walk_text(doc)
                self._assert_signed(doc, resp)
                shown, parts = self._parts(screens, 'data', data_type)
                self.assertEqual(shown, '0x' + data.hex()
                                 if data_type == 'bytes'
                                 else self._escaped(data))
                self.assertGreater(parts, 1)

    def test_misframed_chunks_are_refused(self):
        """A chunk at another offset than the one asked for, or one running
        past the total, is refused, and the session is gone."""
        self.requires_release_capability(es.CHUNKED_VALUES)
        doc = self._blob('bytes', '0x' + 'ab' * 1500)

        def wrong_offset(ack):
            if ack.HasField('value_offset'):
                ack.value_offset += 1

        def past_total(ack):
            if ack.HasField('value_offset'):
                ack.value = ack.value + b'\xab' * 100

        for tamper, error in ((wrong_offset, 'EIP-712 value chunk out of order'),
                              (past_total,
                               'EIP-712 value chunk has the wrong length')):
            with self.subTest(error=error):
                resp, _ = self._walk_text(doc, tamper)
                self.assertIsInstance(resp, proto.Failure)
                self.assertEqual((resp.code, resp.message),
                                 (types.Failure_SyntaxError, error))
                stale = self.client.call_raw(eth.EthereumTypedDataValueAck(
                    value=b'\xab' * 476, value_offset=1024))
                self.assertIsInstance(stale, proto.Failure)
        self._assert_signed(doc, self._walk_text(doc)[0])

    def test_declining_a_part_mid_value_signs_nothing(self):
        """Rejecting a part of the second chunk cancels; the next document
        signs with its own digest."""
        self.requires_release_capability(es.CHUNKED_VALUES)
        doc = self._blob('bytes', '0x' + 'cd' * 3000)
        resp, screens = self._walk_text(doc, decline='data (8/')
        self.assertIsInstance(resp, proto.Failure)
        self.assertEqual(resp.code, types.Failure_ActionCancelled)
        self.assertTrue(screens[-1][1].startswith('data (8/'))
        self._assert_signed(doc, self._walk_text(doc)[0])

    def test_unlimited_approve_in_chunked_safe_data_warns_first(self):
        """approve(spender, 2^256-1) heading a 3 KB SafeTx.data: the
        UNLIMITED warning is read from the first chunk and shown before any
        screen of the bytes."""
        self.requires_release_capability(es.CHUNKED_VALUES)
        self.requires_release_capability("erc20-unlimited-approve-review")
        spender = '68b3465833fb72a70ecdf485e0e4c7bd8665fc45'
        data = ('095ea7b3' + '00' * 12 + spender + 'ff' * 32).ljust(6000, '0')
        doc = {
            "types": {
                "EIP712Domain": [{"name": "chainId", "type": "uint256"}],
                "SafeTx": [{"name": "to", "type": "address"},
                           {"name": "data", "type": "bytes"}],
            },
            "primaryType": "SafeTx",
            "domain": {"chainId": 1},
            "message": {"to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                        "data": "0x" + data},
        }
        resp, screens = self._walk_text(doc)
        self._assert_signed(doc, resp)
        titles = [title for title, _ in screens]
        self.assertEqual(titles.count('UNLIMITED approval'), 1)
        warning = titles.index('UNLIMITED approval')
        first = next(i for i, (_, body) in enumerate(screens)
                     if body.startswith('data ('))
        self.assertLess(warning, first)
        self.assertIn('to spend ALL your USDC', screens[warning][1])
        self.assertEqual(self._parts(screens, 'data', 'bytes')[0],
                         '0x' + data)

if __name__ == '__main__':
    unittest.main()
