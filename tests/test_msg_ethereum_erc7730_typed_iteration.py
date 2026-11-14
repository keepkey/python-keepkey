"""Typed-data ERC-7730 iteration: Seaport's offer[] and consideration[] (7.17).

Through 7.17's first cut a typed-data definition could not walk an array, so
no Seaport definition could show what an OpenSea listing sells and what it is
paid: every item was shown raw. A typed-data definition may now iterate one
array at a time, as calldata definitions do. The device counts the array from
the length the stream sends at the array's path, then shows the iteration's
fields once per element ("Signer field i of n"), each from its own walk of
the message. Every value is still shown exactly once: an item value no field
reads, and the count of an empty array, are shown raw in the last walk.

Both orders are real OpenSea listings on Seaport 1.6 (Ethereum mainnet),
rebuilt from the fulfillBasicOrder calldata that filled them; the order hash
matches the OrderFulfilled event and the signature recovers the offerer
(keepkey-vault __tests__/fixtures/typed-data/seaport-opensea-listing-*.json):
  LISTING     tx 0x24550d5012c90f1b478d243aca85563f57b196f6a492aeb21b96c0709da2a5e8
  CREATOR_FEE tx 0x1dfb30c93389a69c8c97dfb08ffc0e546a36f62ea141592a7c43eec5a509e3bb
The device signs with the "abandon" test mnemonic, so the offerer is not this
wallet; the signature is compared with plain streaming, not with the chain.

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
from test_msg_ethereum_erc7730_runtime import Erc7730Harness, assert_failure

PATH = [0x8000002C, 0x8000003C, 0x80000000, 0, 0]

SEAPORT_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"}],
    "OrderComponents": [
        {"name": "offerer", "type": "address"},
        {"name": "zone", "type": "address"},
        {"name": "offer", "type": "OfferItem[]"},
        {"name": "consideration", "type": "ConsiderationItem[]"},
        {"name": "orderType", "type": "uint8"},
        {"name": "startTime", "type": "uint256"},
        {"name": "endTime", "type": "uint256"},
        {"name": "zoneHash", "type": "bytes32"},
        {"name": "salt", "type": "uint256"},
        {"name": "conduitKey", "type": "bytes32"},
        {"name": "counter", "type": "uint256"}],
    "OfferItem": [
        {"name": "itemType", "type": "uint8"},
        {"name": "token", "type": "address"},
        {"name": "identifierOrCriteria", "type": "uint256"},
        {"name": "startAmount", "type": "uint256"},
        {"name": "endAmount", "type": "uint256"}],
    "ConsiderationItem": [
        {"name": "itemType", "type": "uint8"},
        {"name": "token", "type": "address"},
        {"name": "identifierOrCriteria", "type": "uint256"},
        {"name": "startAmount", "type": "uint256"},
        {"name": "endAmount", "type": "uint256"},
        {"name": "recipient", "type": "address"}]}

SEAPORT_DOMAIN = {
    "name": "Seaport",
    "version": "1.6",
    "chainId": 1,
    "verifyingContract": "0x0000000000000068F116a894984e2DB1123eB395"}

ZERO = "0x0000000000000000000000000000000000000000"
ZERO32 = "0x" + "00" * 32
OPENSEA_FEE = "0x0000a26b00c1F0DF003000390027140000fAa719"
OPENSEA_CONDUIT = (
    "0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000")


def _eth_item(amount, recipient):
    return {"itemType": 0, "token": ZERO, "identifierOrCriteria": "0",
            "startAmount": amount, "endAmount": amount,
            "recipient": recipient}


def _order(offerer, nft, token_id, payments, start, end, salt):
    return {
        "types": SEAPORT_TYPES,
        "primaryType": "OrderComponents",
        "domain": SEAPORT_DOMAIN,
        "message": {
            "offerer": offerer,
            "zone": ZERO,
            "offer": [{"itemType": 2, "token": nft,
                       "identifierOrCriteria": token_id,
                       "startAmount": "1", "endAmount": "1"}],
            "consideration": [_eth_item(a, r) for a, r in payments],
            "orderType": 0,
            "startTime": start,
            "endTime": end,
            "zoneHash": ZERO32,
            "salt": salt,
            "conduitKey": OPENSEA_CONDUIT,
            "counter": "0"}}


SELLER = "0x3A3B180A7eb906D808A999148A81128543EfC5Bc"
LISTING = _order(
    SELLER, "0x387C41B0B2F1128dE44dB1Bcf8baad085f26392C", "5318",
    [("553407831900000000", SELLER), ("5589978100000000", OPENSEA_FEE)],
    "1793312324", "1793333924",
    "27855337018906766782546881864045825683096516384821792734238808442380"
    "141071021")

CREATOR_SELLER = "0xFff2A8b6E03B0B68ecFf845cAEDD190a13fA6C87"
CREATOR = "0x2C4fF0ce082D8BA63f6d1B8B5Cf1995a42dE3296"
CREATOR_FEE = _order(
    CREATOR_SELLER, "0xe00d3Dabe9FD2C0D4d8D7ce96A9fAf9A07dBe529", "64",
    [("19740000000000000", CREATOR_SELLER), ("210000000000000", OPENSEA_FEE),
     ("1050000000000000", CREATOR)],
    "1793305723", "1793392183",
    "90759400893519003444481949768152775275288223950272168603741534947820"
    "144683383")

ORDER_FORMAT = (
    "OrderComponents(address offerer,address zone,OfferItem[] offer,"
    "ConsiderationItem[] consideration,uint8 orderType,uint256 startTime,"
    "uint256 endTime,bytes32 zoneHash,uint256 salt,bytes32 conduitKey,"
    "uint256 counter)ConsiderationItem(uint8 itemType,address token,"
    "uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount,"
    "address recipient)OfferItem(uint8 itemType,address token,"
    "uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount)")


def _amount(path, label):
    # 0x0 is Seaport's native coin (itemType 0); any other token is named by
    # the device's table or shown by address.
    return {"path": path, "label": label, "format": "tokenAmount",
            "params": {"tokenPath": "token", "nativeCurrencyAddress": [ZERO]}}


ITEM_FIELDS = [
    {"path": "itemType", "label": "Item type", "format": "enum",
     "params": {"$ref": "$.metadata.enums.itemType"}},
    {"path": "identifierOrCriteria", "label": "Token ID", "format": "raw"},
    _amount("startAmount", "Amount"),
    _amount("endAmount", "End amount")]


def _descriptor(item_fields=ITEM_FIELDS):
    """Every OrderComponents value, each item's in its iteration."""
    return {
        "metadata": {"owner": "OpenSea", "enums": {
            "itemType": {"0": "Native coin", "1": "ERC-20",
                         "2": "NFT (ERC-721)", "3": "ERC-1155",
                         "4": "ERC-721 by criteria",
                         "5": "ERC-1155 by criteria"},
            "orderType": {"0": "Full, open", "1": "Partial, open",
                          "2": "Full, restricted", "3": "Partial, restricted",
                          "4": "Contract"}}},
        "display": {"formats": {ORDER_FORMAT: {
            "intent": "Seaport order",
            "fields": [
                {"path": "offerer", "label": "Offerer",
                 "format": "addressName"},
                {"path": "offer.[]", "label": "You give",
                 "fields": item_fields},
                {"path": "consideration.[]", "label": "You get",
                 "fields": item_fields + [
                     {"path": "recipient", "label": "Paid to",
                      "format": "addressName"}]},
                {"path": "startTime", "label": "Starts", "format": "date",
                 "params": {"encoding": "timestamp"}},
                {"path": "endTime", "label": "Expires", "format": "date",
                 "params": {"encoding": "timestamp"}},
                {"path": "orderType", "label": "Order type", "format": "enum",
                 "params": {"$ref": "$.metadata.enums.orderType"}},
                {"path": "zone", "label": "Zone", "format": "addressName"},
                {"path": "zoneHash", "label": "Zone hash", "format": "raw"},
                {"path": "conduitKey", "label": "Conduit key",
                 "format": "raw"},
                {"path": "salt", "label": "Salt", "format": "raw"},
                {"path": "counter", "label": "Counter", "format": "raw"}]}}}}


SEAPORT_DESCRIPTOR = _descriptor()

NFT_TYPE = "Item type:\nlabel set by signer\nNFT (ERC-721) (2)"
ETH_TYPE = "Item type:\nlabel set by signer\nNative coin (0)"


def _eth_screens(amount, recipient, this_wallet=False):
    return [ETH_TYPE, "Token ID:\n0", "Amount:\n%s" % amount,
            "End amount:\n%s" % amount,
            "Paid to:\n%s%s" % (recipient,
                                "\n(this wallet)" if this_wallet else "")]


class TestMsgEthereumErc7730TypedIteration(Erc7730Harness,
                                           common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.requires_fullFeature()
        self.requires_firmware("7.17.0")
        self.requires_release_capability("erc7730-runtime-review")
        # Alpha builds of 7.17 before typed iteration report the same version
        # and runtime capability; only this one tells them apart.
        self.requires_release_capability("erc7730-typed-iteration")
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
        envelope = self._preload(
            erc7730_compiler.compile_eip712(descriptor, doc))
        result, certified, _, walks = self._walk(
            self._start(doc), envelope, doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        # The definition changes what is shown, never what is signed.
        self.assertEqual(result.signature, baseline.signature)
        return streamed, certified, walks

    def _fields(self):
        return [(title, body) for title, body in self._first_pages()
                if title.startswith("Signer field")]

    def _top_level(self, start, end, salt):
        return [
            ("Signer field", "Starts:\n%s" % start),
            ("Signer field", "Expires:\n%s" % end),
            ("Signer field",
             "Order type:\nlabel set by signer\nFull, open (0)"),
            ("Signer field", "Zone:\n" + ZERO),
            ("Signer field", "Zone hash:\n" + ZERO32),
            ("Signer field", "Conduit key:\n" + OPENSEA_CONDUIT),
            ("Signer field", "Salt:\n" + salt),
            ("Signer field", "Counter:\n0")]

    def test_listing_shows_each_offer_and_consideration_item_once(self):
        streamed, certified, walks = self._sign(LISTING, SEAPORT_DESCRIPTOR)
        print("Seaport listing screens: streamed %d, certified %d "
              "(%d field walks)" % (streamed, certified, walks))
        fields = self._fields()
        offer = [("Signer field 1 of 1", body) for body in (
            NFT_TYPE, "Token ID:\n5318",
            "Amount:\n1\nunknown token\n"
            "0x387C41B0B2F1128dE44dB1Bcf8baad085f26392C",
            "End amount:\n1\nunknown token\n"
            "0x387C41B0B2F1128dE44dB1Bcf8baad085f26392C")]
        paid = ([("Signer field 1 of 2", body) for body in _eth_screens(
            "0.5534078319 ETH", SELLER)] +
            [("Signer field 2 of 2", body) for body in _eth_screens(
                "0.0055899781 ETH", OPENSEA_FEE)])
        self.assertEqual(
            fields,
            [("Signer field", "Offerer:\n" + SELLER)] + offer + paid +
            self._top_level("2026-10-29 22:18:44 UTC\n(1793312324)",
                            "2026-10-30 04:18:44 UTC\n(1793333924)",
                            LISTING["message"]["salt"]))
        # Every value was shown by a field: nothing is left for the last walk.
        self.assertEqual(
            [t for t, _ in self._first_pages() if t == "EIP-712 Message"], [])
        # One walk per item field value (a tokenAmount reads its amount and
        # its token), one per array count, one per top-level field.
        self.assertEqual(walks, 9 + 1 + 6 + 1 + 2 * 7)
        # The owner's ship rule: better than streaming.
        self.assertLess(certified, streamed)

    def test_creator_fee_listing_numbers_three_payments(self):
        streamed, certified, walks = self._sign(CREATOR_FEE, SEAPORT_DESCRIPTOR)
        print("Seaport creator-fee listing screens: streamed %d, certified %d "
              "(%d field walks)" % (streamed, certified, walks))
        fields = self._fields()
        paid = [(title, body) for title, body in fields
                if title.endswith(" of 3")]
        self.assertEqual(
            paid,
            [("Signer field 1 of 3", body) for body in _eth_screens(
                "0.01974 ETH", CREATOR_SELLER)] +
            [("Signer field 2 of 3", body) for body in _eth_screens(
                "0.00021 ETH", OPENSEA_FEE)] +
            [("Signer field 3 of 3", body) for body in _eth_screens(
                "0.00105 ETH", CREATOR)])
        self.assertEqual(
            [t for t, _ in self._first_pages() if t == "EIP-712 Message"], [])
        self.assertLess(certified, streamed)

    def test_an_item_value_no_field_shows_is_shown_raw_once(self):
        # Without "End amount" every item's endAmount is shown raw, once, in
        # the last walk, in message order.
        self._sign(LISTING, _descriptor(ITEM_FIELDS[:3]))
        pages = self._first_pages()
        self.assertEqual(
            [body for title, body in pages if title == "EIP-712 Message"],
            ["offer[0].endAmount\nuint256: 1",
             "consideration[0].endAmount\nuint256: 553407831900000000",
             "consideration[1].endAmount\nuint256: 5589978100000000"])
        self.assertNotIn("End amount:", "".join(body for _, body in pages))

    def test_an_empty_array_is_shown_raw_once(self):
        # No item shows the count of an empty array, so the last walk does.
        doc = copy.deepcopy(LISTING)
        doc["message"]["consideration"] = []
        self._sign(doc, SEAPORT_DESCRIPTOR)
        pages = self._first_pages()
        self.assertEqual(
            [body for title, body in pages if title == "EIP-712 Message"],
            ["consideration\nConsiderationItem[]: 0 items"])
        self.assertEqual(
            [t for t, _ in pages if t.endswith(" of 1")], ["Signer field 1 of 1"] * 4)

    def test_declining_a_payment_aborts(self):
        envelope = self._preload(
            erc7730_compiler.compile_eip712(SEAPORT_DESCRIPTOR, LISTING))
        result, _, _, _ = self._walk(
            self._start(LISTING), envelope, LISTING,
            cancel_title="Signer field 2 of 2")
        assert_failure(self, result, types.Failure_ActionCancelled,
                       "Signing cancelled by user")
        self.assertEqual(self.screens[-1],
                         ("Signer field 2 of 2", ETH_TYPE))

    def _walk_tampered(self, tampered, at_walk):
        """Sign LISTING with its definition, answering walk `at_walk` from
        `tampered`. Returns (response, screens shown, walks)."""
        envelope = self._preload(erc7730_compiler.compile_eip712(
            SEAPORT_DESCRIPTOR, LISTING))
        definition_id = hashlib.sha256(envelope).digest()
        shown = []
        walks = 0
        response = self.client.call_raw(self._start(LISTING))
        for _ in range(20000):
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
                    eip712_stream.struct_members(LISTING, response.name)))
            elif isinstance(response, eth.EthereumTypedDataValueRequest):
                path = list(response.member_path)
                if path == [1, 0]:
                    walks += 1
                doc = tampered if walks == at_walk else LISTING
                resolved = eip712_stream.resolve_member_path(doc, path)
                response = self.client.call_raw(eth.EthereumTypedDataValueAck(
                    value=eip712_stream.encode_array_length(resolved[1])
                    if resolved[0] == "length" else
                    eip712_stream.encode_value(resolved[1], resolved[2])))
            else:
                break
        return response, shown, walks

    def test_an_item_changed_in_a_later_walk_is_refused(self):
        # Each item field is its own walk; every walk must hash the message
        # the first one did. A host that pays the fee to itself only in the
        # walk that shows it is refused before the fee recipient is shown.
        tampered = copy.deepcopy(LISTING)
        tampered["message"]["consideration"][1]["recipient"] = SELLER
        # Walk 1 is the offerer's; 2 counts the offer, 3-8 read its item;
        # 9 counts the consideration, 10-16 read the first payment, 17-22
        # the second's type, id, amounts and tokens, and 23 its recipient.
        response, shown, walks = self._walk_tampered(tampered, 23)
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.message,
                         "Certified EIP-712 value was not found")
        self.assertEqual(walks, 23)
        bodies = "".join(text[1] for text in shown)
        self.assertNotIn("Paid to:\n" + OPENSEA_FEE, bodies)
        self.assertIn("Paid to:\n" + SELLER, bodies)

    def test_a_count_changed_in_its_walk_is_refused(self):
        # The count is not shown on a screen of its own: the "i of n" titles
        # carry it. So the count must be the signed message's. A host that
        # drops the fee from the walk that counts the consideration (9) would
        # have the device show "1 of 1" and never the fee; that walk hashes
        # another message, so it is refused before any payment is shown.
        tampered = copy.deepcopy(LISTING)
        del tampered["message"]["consideration"][1]
        response, shown, walks = self._walk_tampered(tampered, 9)
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.message,
                         "Certified EIP-712 value was not found")
        self.assertEqual(walks, 9)
        # No payment screen at all: neither a recipient nor an item type.
        bodies = "".join(text[1] for text in shown)
        self.assertNotIn("Paid to:", bodies)
        self.assertNotIn("Native coin", bodies)

    def test_a_payment_more_is_counted_on_every_payment_screen(self):
        # Same listing, one more payment: every payment's title says "of 3",
        # and the extra payment is shown like the others.
        doc = copy.deepcopy(LISTING)
        doc["message"]["consideration"].append(
            _eth_item("1000000000000000", CREATOR))
        self._sign(doc, SEAPORT_DESCRIPTOR)
        self.assertEqual(
            [(t, body) for t, body in self._fields() if t.endswith(" of 3")],
            [("Signer field 1 of 3", body) for body in _eth_screens(
                "0.5534078319 ETH", SELLER)] +
            [("Signer field 2 of 3", body) for body in _eth_screens(
                "0.0055899781 ETH", OPENSEA_FEE)] +
            [("Signer field 3 of 3", body) for body in _eth_screens(
                "0.001 ETH", CREATOR)])
        self.assertEqual(
            [t for t, _ in self._fields() if t.endswith(" of 2")], [])
