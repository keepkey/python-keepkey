"""Typed-data ERC-7730 shows each field once (7.17).

A certified typed-data definition walks the message once per field value it
needs. Through 7.16 every one of those walks showed every leaf again, so the
CoW order below took several times the screens of plain streaming. From 7.17
every message value is shown once: a value a definition field shows, in that
field's format; the device's own warnings and any value too long for a field
to hold, in the first walk; every other value, raw, in one last walk after
the fields, in message order.

The order is a real request: swaps.pro, CoW route, 25,000 USDC to ETH,
captured 2026-10-29 (keepkey-vault docs/clearsign-case-studies/
swapspro-20261029/requests/order-cow-usdc.json). Its receiver is the signing
account of the "all all all" test mnemonic.

The definition is signed by the throwaway runtime key (AdvancedMode, "NOT
verified by KeepKey"); the stream behaves the same for every tier.
"""

import copy
import hashlib

import common
from keepkeylib import eip712_stream, erc7730_compiler
from keepkeylib import messages_ethereum_pb2 as eth
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types
from test_msg_ethereum_erc7730_runtime import (
    ADDRESS, Erc7730Harness, assert_failure)

PATH = [0x8000002C, 0x8000003C, 0x80000000, 0, 0]

COW_ORDER = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"}],
        "Order": [
            {"name": "sellToken", "type": "address"},
            {"name": "buyToken", "type": "address"},
            {"name": "receiver", "type": "address"},
            {"name": "sellAmount", "type": "uint256"},
            {"name": "buyAmount", "type": "uint256"},
            {"name": "validTo", "type": "uint32"},
            {"name": "appData", "type": "bytes32"},
            {"name": "feeAmount", "type": "uint256"},
            {"name": "kind", "type": "string"},
            {"name": "partiallyFillable", "type": "bool"},
            {"name": "sellTokenBalance", "type": "string"},
            {"name": "buyTokenBalance", "type": "string"}]},
    "primaryType": "Order",
    "domain": {
        "name": "Gnosis Protocol",
        "version": "v2",
        "chainId": 1,
        "verifyingContract": "0x9008D19f58AAbD9eD0D60971565AA8510560ab41"},
    "message": {
        "sellToken": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "buyToken": "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
        "receiver": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        "sellAmount": "25000000000",
        "buyAmount": "9487278979799916817",
        "validTo": 1793308500,
        "appData": "0x048680e79dfa12d06c2362b19faa34b7c754a3ed153d204656c48f82e84d4e60",
        "feeAmount": "0",
        "kind": "sell",
        "partiallyFillable": False,
        "sellTokenBalance": "erc20",
        "buyTokenBalance": "erc20"}}

ORDER_FORMAT = ("Order(address sellToken,address buyToken,address receiver,"
                "uint256 sellAmount,uint256 buyAmount,uint32 validTo,"
                "bytes32 appData,uint256 feeAmount,string kind,"
                "bool partiallyFillable,string sellTokenBalance,"
                "string buyTokenBalance)")

# A GPv2 Order definition in ERC-7730 terms: what is sold, the least that
# comes back, to whom, until when, and the fee.
COW_DESCRIPTOR = {"display": {"formats": {ORDER_FORMAT: {
    "intent": "Swap order",
    "fields": [
        {"path": "sellAmount", "label": "Sell", "format": "tokenAmount",
         "params": {"tokenPath": "sellToken"}},
        {"path": "buyAmount", "label": "Receive at least",
         "format": "tokenAmount",
         "params": {"tokenPath": "buyToken", "nativeCurrencyAddress":
                    ["0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"]}},
        {"path": "receiver", "label": "Recipient", "format": "addressName"},
        {"path": "validTo", "label": "Expires", "format": "date",
         "params": {"encoding": "timestamp"}},
        {"path": "feeAmount", "label": "Fee", "format": "tokenAmount",
         "params": {"tokenPath": "sellToken"}}]}}}}

# The five Order values the definition does not show: raw, once, in order,
# after its fields.
COW_REST = ["appData", "kind", "partiallyFillable", "sellTokenBalance",
            "buyTokenBalance"]

# What the definition shows, each once, in order.
COW_FIELDS = [
    ("Signer field", "Sell:\n25000 USDC"),
    ("Signer field", "Receive at least:\n9.487278979799916817  ETH"),
    ("Signer field", "Recipient:\n0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n"
                     "(this wallet)"),
    ("Signer field", "Expires:\n2026-10-29 21:15:00 UTC\n(1793308500)"),
    ("Signer field", "Fee:\n0 USDC"),
]


# Permit2 PermitBatch granting the maximum uint160 allowance: the shape
# Uniswap sends, one token. With a definition required there is no native
# Permit2 review, so the device's UNLIMITED leaf screen is its only warning.
PERMIT_BATCH = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"}],
        "PermitDetails": [
            {"name": "token", "type": "address"},
            {"name": "amount", "type": "uint160"},
            {"name": "expiration", "type": "uint48"},
            {"name": "nonce", "type": "uint48"}],
        "PermitBatch": [
            {"name": "details", "type": "PermitDetails[]"},
            {"name": "spender", "type": "address"},
            {"name": "sigDeadline", "type": "uint256"}]},
    "primaryType": "PermitBatch",
    "domain": {
        "name": "Permit2",
        "chainId": 1,
        "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"},
    "message": {
        "details": [{
            "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "amount": str(2 ** 160 - 1),
            "expiration": "1893456000",
            "nonce": "1"}],
        "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
        "sigDeadline": "1893456000"}}

# Names the spender and the deadline; never mentions the amount.
PERMIT_BATCH_DESCRIPTOR = {"display": {"formats": {"PermitBatch(": {
    "intent": "Permit",
    "fields": [
        {"path": "spender", "label": "Spender", "format": "addressName"},
        {"path": "sigDeadline", "label": "Deadline", "format": "date",
         "params": {"encoding": "timestamp"}}]}}}}

# Two values; the definition shows only the first.
MAIL = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"}],
        "Mail": [{"name": "first", "type": "uint256"},
                 {"name": "second", "type": "uint256"}]},
    "primaryType": "Mail",
    "domain": {"name": "Audit app", "chainId": 1,
               "verifyingContract": "0x" + ADDRESS.hex()},
    "message": {"first": 42, "second": 7}}

MAIL_FIRST_ONLY = {"display": {"formats": {
    "Mail(uint256 first,uint256 second)": {
        "intent": "Audit action",
        "fields": [{"path": "first", "label": "First value",
                    "format": "raw"}]}}}}


class TestMsgEthereumErc7730TypedShowOnce(Erc7730Harness, common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.requires_fullFeature()
        self.requires_firmware("7.17.0")
        self.requires_release_capability("erc7730-runtime-review")
        self.requires_structured_eip712()
        self.setup_mnemonic_abandon()
        self.client.apply_policy("AdvancedMode", 1)

    def _start(self, doc):
        return eth.EthereumSignTypedData(
            address_n=PATH, primary_type=doc["primaryType"],
            metamask_v4_compat=True)

    def _sign(self, doc, descriptor):
        """Sign `doc` streamed, then with its certified definition. Returns
        (streamed screens, certified screens, certified field walks)."""
        baseline, streamed, _, _ = self._walk(self._start(doc), doc=doc)
        self.assertIsInstance(baseline, eth.EthereumTypedDataSignature)
        envelope = self._preload(erc7730_compiler.compile_eip712(descriptor, doc))
        result, certified, _, walks = self._walk(self._start(doc), envelope, doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        # The definition changes what is shown, never what is signed.
        self.assertEqual(result.signature, baseline.signature)
        return streamed, certified, walks

    def test_cow_order_shows_each_field_once(self):
        streamed, certified, walks = self._sign(COW_ORDER, COW_DESCRIPTOR)
        print("CoW order screens: streamed %d, certified %d (%d field walks)"
              % (streamed, certified, walks))
        pages = self._first_pages()
        titles = [title for title, _ in pages]
        # Every leaf was walked and hashed once per field value (amounts and
        # their tokens, the receiver, the date), then once more for the
        # values no field shows.
        self.assertEqual(walks, 9)
        # The four domain leaves, the definition, each field once, the five
        # other values once, then the signature.
        self.assertEqual(
            [p for p in pages if p[0] == "Signer field"], COW_FIELDS)
        self.assertEqual(
            [t for t in titles if t not in ("Signer field",)],
            ["EIP-712 Domain"] * 4 + ["Runtime signer", "Unverified data",
                                      "Contract action"] +
            ["EIP-712 Message"] * 5 + ["Sign Typed Data"])
        self.assertEqual(
            [body.split("\n")[0] for title, body in pages
             if title == "EIP-712 Message"], COW_REST)
        # The owner's ship rule: better than streaming.
        self.assertLess(certified, streamed)

    def test_a_leaf_changed_in_a_silent_walk_is_refused(self):
        # The later walks show nothing, so each must hash the message the
        # first one did. Walk 7 is the Fee field's first; a host that
        # answers it with another fee is refused before Fee is shown.
        envelope = self._preload(erc7730_compiler.compile_eip712(
            COW_DESCRIPTOR, COW_ORDER))
        tampered = copy.deepcopy(COW_ORDER)
        tampered["message"]["feeAmount"] = "1"
        definition_id = hashlib.sha256(envelope).digest()
        shown = []
        walks = 0
        response = self.client.call_raw(self._start(COW_ORDER))
        for _ in range(1000):
            if isinstance(response, proto.ButtonRequest):
                shown.append(self.client.debug.read_confirm_text())
                self.client.debug.press_yes()
                response = self.client.call_raw(proto.ButtonAck())
            elif isinstance(response, eth.EthereumClearSignDefinitionRequest):
                offset = response.offset
                response = self.client.call_raw(
                    eth.EthereumClearSignDefinitionChunk(
                        definition_id=definition_id, offset=offset,
                        total_length=len(envelope),
                        data=envelope[offset:offset + response.length]))
            elif isinstance(response, eth.EthereumTypedDataStructRequest):
                response = self.client.call_raw(eip712_stream.build_struct_ack(
                    eip712_stream.struct_members(COW_ORDER, response.name)))
            elif isinstance(response, eth.EthereumTypedDataValueRequest):
                path = list(response.member_path)
                if path == [1, 0]:
                    walks += 1
                doc = tampered if walks == 7 else COW_ORDER
                kind, field, value = eip712_stream.resolve_member_path(doc, path)
                response = self.client.call_raw(eth.EthereumTypedDataValueAck(
                    value=eip712_stream.encode_value(field, value)))
            else:
                break
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.message,
                         "Certified EIP-712 value was not found")
        self.assertEqual(walks, 7)
        self.assertNotIn("Fee:", "".join(body for _, body in shown))
        self.assertIn("Expires:", "".join(body for _, body in shown))

    def test_an_unlimited_permit_is_warned_once_whatever_the_definition(self):
        _, _, walks = self._sign(PERMIT_BATCH, PERMIT_BATCH_DESCRIPTOR)
        # Two field walks, then the values the definition never shows.
        self.assertEqual(walks, 3)
        pages = self._first_pages()
        self.assertEqual(
            [p for p in pages if p[0] == "UNLIMITED approval"],
            [("UNLIMITED approval", "details[0].amount\nuint160: UNLIMITED")])
        # The amount was shown as its warning; it is not shown again.
        self.assertEqual(
            [body.split("\n")[0] for title, body in pages
             if title == "EIP-712 Message"],
            ["details", "details[0].token", "details[0].expiration",
             "details[0].nonce"])

    def test_a_value_no_field_shows_is_shown_raw_once(self):
        _, _, walks = self._sign(MAIL, MAIL_FIRST_ONLY)
        self.assertEqual(walks, 2)  # the field's walk, then the rest
        self.assertEqual(
            [p for p in self._first_pages()
             if p[0] in ("Signer field", "EIP-712 Message")],
            [("Signer field", "First value:\n42"),
             ("EIP-712 Message", "second\nuint256: 7")])

    def test_declining_a_value_no_field_shows_aborts(self):
        envelope = self._preload(
            erc7730_compiler.compile_eip712(MAIL_FIRST_ONLY, MAIL))
        result, _, _, _ = self._walk(
            self._start(MAIL), envelope, MAIL, cancel_title="EIP-712 Message")
        assert_failure(self, result, types.Failure_ActionCancelled,
                       "EIP-712 cancelled")
        self.assertEqual(self.screens[-1],
                         ("EIP-712 Message", "second\nuint256: 7"))
