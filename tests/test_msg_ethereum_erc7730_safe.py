"""Safe owner approvals: signed inner definitions on the actual EIP-712 bytes.

Only throwaway runtime metadata is signed here. Production metadata is prepared
separately for the operator's ClearSign signer.
"""
import json
import os
import copy
import hashlib
import unittest

import common
from keepkeylib import erc7730, erc7730_compiler
from keepkeylib import messages_ethereum_pb2 as eth
from keepkeylib import messages_pb2 as proto
from keepkeylib.signed_metadata import keccak256
from test_msg_ethereum_erc7730_runtime import ADDRESS, Erc7730Harness

PATH = [0x8000002C, 0x8000003C, 0x80000000, 0, 0]
CHAIN = int(os.getenv("KK_SAFE_TEST_CHAIN", "1"))
AMOUNT_FIELD = "Amount:\n" + ("unit set by signer\n1.5 USDC\nraw 1500000" if CHAIN == 8453 else "1.5 USDC")
USDC = bytes.fromhex("833589fcd6edb6e08f4c7c32d4f71b54bda02913" if CHAIN == 8453
                     else "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
RECIPIENT = "0x2222222222222222222222222222222222222222"
SAFE_FORMAT = ("SafeTx(address to,uint256 value,bytes data,uint8 operation,"
               "uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,"
               "address gasToken,address refundReceiver,uint256 nonce)")
SAFE_DESCRIPTOR = {"display": {"formats": {SAFE_FORMAT: {
    "intent": "Approve Safe transaction", "fields": [
        {"path": "data", "label": "Safe call", "format": "calldata",
         "params": {"calleePath": "to", "amountPath": "value",
                    "spenderPath": "@.to"}},
        {"path": "nonce", "label": "Safe nonce", "format": "raw"}]}}}}
TRANSFER_FORMAT = "transfer(address to,uint256 amount)"
TRANSFER_DESCRIPTOR = {"display": {"formats": {TRANSFER_FORMAT: {
    "intent": "Transfer", "fields": [
        {"path": "to", "label": "Recipient", "format": "addressName"},
        {"path": "amount", "label": "Amount", "format": "tokenAmount",
         "params": {"tokenPath": "@.to"}}]}}}}
OWNER_FORMAT = "addOwnerWithThreshold(address owner,uint256 threshold)"
OWNER_DESCRIPTOR = {"display": {"formats": {OWNER_FORMAT: {
    "intent": "Add Safe owner", "fields": [
        {"path": "owner", "label": "New owner", "format": "addressName"},
        {"path": "threshold", "label": "Required signatures", "format": "raw"}]}}}}
FORWARDER = bytes.fromhex("33" * 20)
FORWARD_FORMAT = "forward(address target,bytes data)"
FORWARD_DESCRIPTOR = {"display": {"formats": {FORWARD_FORMAT: {
    "intent": "TEST nested call", "fields": [
        {"path": "data", "label": "Forwarded call", "format": "calldata",
         "params": {"calleePath": "target"}}]}}}}


def safe_doc(data=None, **overrides):
    fields = [("to", "address"), ("value", "uint256"), ("data", "bytes"),
              ("operation", "uint8"), ("safeTxGas", "uint256"),
              ("baseGas", "uint256"), ("gasPrice", "uint256"),
              ("gasToken", "address"), ("refundReceiver", "address"),
              ("nonce", "uint256")]
    zero = "0x" + "00" * 20
    call = (bytes.fromhex("a9059cbb") + bytes(12) + bytes.fromhex(RECIPIENT[2:])
            + (1500000).to_bytes(32, "big"))
    msg = dict(to="0x" + USDC.hex(), value="0", data="0x" + (call if data is None else data).hex(),
               operation=0, safeTxGas="0", baseGas="0", gasPrice="0",
               gasToken=zero, refundReceiver=zero, nonce="12")
    msg.update(overrides)
    return {"primaryType": "SafeTx", "types": {
        "EIP712Domain": [{"name": "chainId", "type": "uint256"},
                         {"name": "verifyingContract", "type": "address"}],
        "SafeTx": [{"name": n, "type": t} for n, t in fields]},
        "domain": {"chainId": CHAIN, "verifyingContract": "0x" + ADDRESS.hex()},
        "message": msg}


def batch_doc(calls=2, inner_operation=0):
    transfer = bytes.fromhex(safe_doc()["message"]["data"][2:])
    packed = b"".join(bytes([inner_operation]) + USDC + bytes(32)
                      + len(transfer).to_bytes(32, "big") + transfer
                      for _ in range(calls))
    data = (bytes.fromhex("8d80ff0a") + (32).to_bytes(32, "big")
            + len(packed).to_bytes(32, "big") + packed
            + bytes(-len(packed) % 32))
    return safe_doc(data, operation=1,
                    to="0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761")


class TestMsgEthereumErc7730Safe(Erc7730Harness, common.KeepKeyTest):
    def _walk(self, *args, **kwargs):
        return super()._walk(*args, max_steps=20000, **kwargs)

    def setUp(self):
        super().setUp()
        self.requires_fullFeature()
        self.requires_structured_eip712()
        if proto.Features.CAPABILITY_SAFE_TYPED_CALLS not in self.client.features.capabilities:
            raise unittest.SkipTest("requires authenticated Safe typed calls")
        self.setup_mnemonic_abandon()
        self.client.apply_policy("AdvancedMode", 1)

    def _start(self):
        return eth.EthereumSignTypedData(address_n=PATH, primary_type="SafeTx",
                                         metamask_v4_compat=True)

    def _catalog(self, doc, missing=False):
        certified = os.getenv("KK_SAFE_CERTIFIED_FIXTURE")
        if certified:
            self.client.apply_policy("AdvancedMode", 0)
            with open(certified) as stream:
                fixture = json.load(stream)
            entries = [erc7730.Definition(
                bytes.fromhex(d["envelope"][2:]), d["kind"], d["chainId"],
                bytes.fromhex(d["contractAddress"][2:]),
                bytes.fromhex(d["selectorOrTypeHash"][2:]))
                for d in fixture["definitions"] if not (missing and d["kind"] == 1)]
            erc7730.preload(self.client, entries[0])
            self._drop_setup_screenshots()
            return erc7730.Catalog(entries)
        outer = erc7730_compiler.compile_eip712(SAFE_DESCRIPTOR, doc)
        envelope = self._preload(outer)
        entries = [self._definition(outer, envelope)]
        if not missing:
            inner = erc7730_compiler.compile_calldata(
                TRANSFER_DESCRIPTOR, TRANSFER_FORMAT, 1, USDC)
            entries.append(erc7730.Definition(self._envelope(inner), 1, 1,
                                               USDC, inner[38:42]))
            owner_program = erc7730_compiler.compile_calldata(
                OWNER_DESCRIPTOR, OWNER_FORMAT, 1, ADDRESS)
            entries.append(self._definition(owner_program, self._envelope(owner_program)))
            forward = erc7730_compiler.compile_calldata(
                FORWARD_DESCRIPTOR, FORWARD_FORMAT, 1, FORWARDER)
            entries.append(erc7730.Definition(self._envelope(forward), 1, 1,
                                               FORWARDER, forward[38:42]))
        return erc7730.Catalog(entries)

    def test_transfer_uses_signed_inner_metadata_and_signs_the_same_digest(self):
        doc = safe_doc()
        baseline = self._walk(self._start(), doc=doc)[0]
        self.assertIsInstance(baseline, eth.EthereumTypedDataSignature)
        result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc))[0]
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(result.signature, baseline.signature)
        pages = self._first_pages()
        self.assertIn(("Inner field", AMOUNT_FIELD), pages)
        self.assertTrue(any(RECIPIENT in body for _, body in pages))
        if os.getenv("KK_SAFE_CERTIFIED_FIXTURE"):
            self.assertIn("Verified by KeepKey", [title for title, _ in pages])
            self.assertNotIn("Unverified data", [title for title, _ in pages])

    def test_missing_inner_metadata_refuses_before_signing(self):
        doc = safe_doc()
        result = self._walk(self._start(), doc=doc,
                            catalog=self._catalog(doc, missing=True))[0]
        self.assertIsInstance(result, proto.Failure)
        self.assertEqual(result.message, "Inner call cannot be clear-signed")

    def test_delegatecall_cannot_claim_the_callees_normal_action(self):
        doc = safe_doc(operation=1)
        result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc))[0]
        self.assertIsInstance(result, proto.Failure)
        self.assertEqual(result.message, "DELEGATECALL cannot be clear-signed")

    def test_change_in_a_silent_inner_replay_is_refused(self):
        doc = safe_doc()
        def change(current, walk, path):
            if walk >= 5:
                current["message"]["nonce"] = "13"
        result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc),
                            typed_altered=change)[0]
        self.assertIsInstance(result, proto.Failure)
        self.assertEqual(result.message, "Certified EIP-712 value was not found")

    def test_multisend_reviews_every_call_and_signs_the_same_digest(self):
        doc = batch_doc()
        baseline = self._walk(self._start(), doc=doc)[0]
        self.assertIsInstance(baseline, eth.EthereumTypedDataSignature)
        result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc))[0]
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(result.signature, baseline.signature)
        self.assertEqual(self._first_pages().count(
            ("Inner field", AMOUNT_FIELD)), 2)

    def test_multisend_inner_delegatecall_is_refused(self):
        doc = batch_doc(inner_operation=1)
        result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc))[0]
        self.assertIsInstance(result, proto.Failure)
        self.assertEqual(result.message, "DELEGATECALL cannot be clear-signed")

    def test_multisend_over_chunk_boundary_reviews_all_calls(self):
        doc = batch_doc(8)
        result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc))[0]
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(self._first_pages().count(
            ("Inner field", AMOUNT_FIELD)), 8)

    def test_owner_change_is_reviewed_from_its_own_signed_definition(self):
        call = bytes.fromhex("0d582f13") + bytes(12) + bytes.fromhex(RECIPIENT[2:]) + (2).to_bytes(32, "big")
        doc = safe_doc(call, to="0x" + ADDRESS.hex())
        result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc))[0]
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertIn(("Inner field", "Required signatures:\n2"), self._first_pages())

    def test_native_transfer_shows_its_entire_context_without_an_inner_definition(self):
        doc = safe_doc(b"", to=RECIPIENT, value="1000000000000000000")
        result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc, missing=True))[0]
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertTrue(any("Value 1 ETH" in body and RECIPIENT in body for _, body in self._first_pages()))

    def test_declining_an_inner_field_signs_nothing(self):
        doc = safe_doc()
        result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc), cancel_title="Inner field")[0]
        self.assertIsInstance(result, proto.Failure)

    def test_nested_call_returns_to_the_batch_and_reviews_the_next_entry(self):
        transfer = bytes.fromhex(safe_doc()["message"]["data"][2:])
        forward = (keccak256(b"forward(address,bytes)")[:4] + bytes(12) + USDC
                   + (64).to_bytes(32, "big") + len(transfer).to_bytes(32, "big")
                   + transfer + bytes(-len(transfer) % 32))
        packed = b"".join(b"\0" + to + bytes(32) + len(data).to_bytes(32, "big") + data
                          for to, data in [(FORWARDER, forward), (USDC, transfer)])
        data = (bytes.fromhex("8d80ff0a") + (32).to_bytes(32, "big")
                + len(packed).to_bytes(32, "big") + packed + bytes(-len(packed) % 32))
        doc = safe_doc(data, operation=1, to="0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761")
        result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc))[0]
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(self._first_pages().count(("Inner field", AMOUNT_FIELD)), 2)


class TestBaseSafeIncident(Erc7730Harness, common.KeepKeyTest):
    """Public incident bytes; signatures use only the emulator's test seed.

    Requires the emulator-only KK_CLEARSIGN_TEST_ROOT override. These public,
    deterministic keys must never certify a production catalog.
    """
    _start = TestMsgEthereumErc7730Safe._start
    ROOT_KEY = hashlib.sha256(b"Safe ClearSign TEST ROOT ONLY").digest()
    DELEGATE_KEY = hashlib.sha256(b"Safe ClearSign TEST DELEGATE ONLY").digest()

    def setUp(self):
        super().setUp()
        self.requires_fullFeature()
        self.requires_structured_eip712()
        if os.getenv("KK_CLEARSIGN_TEST_ROOT") != (
                "0288bbff17897c34aa5c0e92c2068f3396e3786fb0356f589417111db59016d147"):
            raise unittest.SkipTest("requires emulator-only test root")
        self.assertEqual(os.getenv("KK_FORCE_UDP"), "1")
        self.setup_mnemonic_abandon()
        self.client.apply_policy("AdvancedMode", 0)

    def _incident(self):
        doc = safe_doc(nonce=0, to="0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")
        doc["domain"] = {"chainId": "8453", "verifyingContract":
                         "0x6717d97655d8fc9d05c2dd3f28b54f574309b473"}
        doc["message"]["data"] = ("0xa9059cbb" + "00" * 12 +
            "4efb11f884a2ead4c1f4e4f4d2841f207dba14dd" + (8000000).to_bytes(32, "big").hex())
        return doc

    def _catalog(self, doc, missing=False):
        from ecdsa import SigningKey, SECP256k1
        from ecdsa.util import sigencode_string_canonize
        root = SigningKey.from_string(self.ROOT_KEY, curve=SECP256k1)
        delegate = SigningKey.from_string(self.DELEGATE_KEY, curve=SECP256k1)
        self.assertEqual(root.verifying_key.to_string("compressed").hex(),
                         os.getenv("KK_CLEARSIGN_TEST_ROOT"))
        body = (bytes([1, 1]) + (8453).to_bytes(4, "big") +
                (1893456000).to_bytes(4, "big") + b"Safe TEST ONLY".ljust(32, b"\0") +
                delegate.verifying_key.to_string("compressed"))
        domain = bytes.fromhex("8839401f8d0112b4348770ddace152e96fc5e5081aefeed6b5d8bef0d6ecdf66")
        digest = keccak256(b"\x19\x01" + domain + keccak256(body))
        certificate = body + root.sign_digest_deterministic(
            digest, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize)
        descriptor = copy.deepcopy(TRANSFER_DESCRIPTOR)
        descriptor["display"]["formats"][TRANSFER_FORMAT]["fields"][1].update(
            format="unit", params={"decimals": 6, "base": "USDC"})
        programs = [erc7730_compiler.compile_eip712(SAFE_DESCRIPTOR, doc)]
        if not missing:
            programs.append(erc7730_compiler.compile_calldata(
                descriptor, TRANSFER_FORMAT, 8453, bytes.fromhex(doc["message"]["to"][2:])))
        definitions = [erc7730.Definition(
            erc7730.sign_envelope(p, certificate, self.DELEGATE_KEY), p[7], 8453,
            p[18:38], p[38:70 if p[7] == 2 else 42]) for p in programs]
        erc7730.preload(self.client, definitions[0])
        self._drop_setup_screenshots()
        return erc7730.Catalog(definitions)

    def test_actual_base_8_usdc_intent_and_digest(self):
        from test_msg_ethereum_signing_guards import recover_eth_signer
        doc = self._incident()
        result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc))[0]
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        sig = bytes(result.signature)
        digest = bytes.fromhex("def9a33d36e2dca79d9e67460e4c5e038b73b868b5fec35888774294010a096d")
        self.assertEqual(recover_eth_signer(sig[:32], sig[32:64], sig[64] - 27, digest),
                         self.client.ethereum_get_address(PATH))
        pages = self._first_pages()
        self.assertIn(("Inner field", "Amount:\nunit set by signer\n8 USDC\nraw 8000000"), pages)
        rendered = "\n".join(body.lower() for _, body in pages)
        self.assertIn("0x4efb11f884a2ead4c1f4e4f4d2841f207dba14dd", rendered)
        self.assertIn(doc["domain"]["verifyingContract"], rendered)
        self.assertIn("8453", rendered)
        self.assertNotIn(doc["message"]["data"][2:], rendered)
        self.assertIn("Verified by KeepKey", [title for title, _ in pages])
        self.assertNotIn("Unverified data", [title for title, _ in pages])

    def test_actual_base_missing_token_definition_refuses(self):
        doc = self._incident()
        result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc, missing=True))[0]
        self.assertIsInstance(result, proto.Failure)

    def test_changed_signed_bytes_during_inner_replay_refuse(self):
        # Domain facts are collected once and retained by the device. Replays
        # request message values only, so mutate the bytes actually requested.
        for field in ("to", "amount", "recipient", "nonce"):
            with self.subTest(field=field):
                doc = self._incident()
                def change(current, walk, path):
                    if walk >= 5:
                        if field == "amount":
                            current["message"]["data"] = current["message"]["data"][:-2] + "01"
                        elif field == "recipient":
                            data = current["message"]["data"]
                            current["message"]["data"] = data[:34] + RECIPIENT[2:] + data[74:]
                        elif field == "to":
                            current["message"][field] = RECIPIENT
                        else:
                            current["message"][field] = "1"
                result = self._walk(self._start(), doc=doc, catalog=self._catalog(doc),
                                    typed_altered=change)[0]
                self.assertIsInstance(result, proto.Failure)

    def test_metadata_cannot_move_to_another_chain_or_safe(self):
        for field, value in (("chainId", "1"), ("verifyingContract", RECIPIENT)):
            with self.subTest(field=field):
                doc = self._incident()
                catalog = self._catalog(doc)
                doc["domain"][field] = value
                result = self._walk(self._start(), doc=doc, catalog=catalog)[0]
                self.assertIsInstance(result, proto.Failure)
