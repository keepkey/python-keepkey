# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Certified address-book contacts.

The user approves a list of contacts on the device, which signs a commitment
to it with a key derived from the seed. A later send to one of them carries a
proof, and the device names the contact, then shows the full address.

The request, commitment and proof are built here from the format alone, not
with the firmware's or KeepKey Desktop's code, and the device's signature is
checked with python-ecdsa.
"""

import hashlib
import unittest

import common
import oled_text

from ecdsa import SECP256k1, VerifyingKey, util

from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_ethereum_pb2 as eth_proto
from keepkeylib import types_pb2 as types
from keepkeylib.tools import int_to_big_endian, parse_path

ALICE = "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
BOB = "52908400098527886E0F7030069857D2E4169EE7"
CAROL = "8617E340B3D01FA5F11F306F4090FD50E238070D"
USDC = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

BOOK = (("eip155:1", ALICE, "Alice"),
        ("eip155:8453", BOB, "Bob at the bank"),
        ("eip155:1", CAROL, "Carol"))
REVISION = 7


def _entry(network, address, label):
    net, dest, name = network.encode(), bytes.fromhex(address), label.encode()
    return (bytes([len(net)]) + net + bytes([1, len(dest)]) + dest
            + bytes([len(name)]) + name)


def _sha(data):
    return hashlib.sha256(data).digest()


def _levels(book):
    """Merkle levels, leaves first; a short level repeats its last leaf."""
    level = [_sha(b"KKABLEAF" + _entry(*c)) for c in book]
    width = 1
    while width < len(level):
        width *= 2
    level += [level[-1]] * (width - len(level))
    levels = [level]
    while len(level) > 1:
        level = [_sha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def _header(book, revision):
    return b"\x01" + revision.to_bytes(4, "big") + bytes([len(book)])


def request(book, revision=REVISION):
    return (b"KKABREQ1" + _header(book, revision)
            + b"".join(_entry(*c) for c in book))


def manifest(book, revision=REVISION):
    return b"KKABRT01" + _header(book, revision) + _levels(book)[-1][0]


def proof(book, index, public_key, signature, revision=REVISION):
    levels = _levels(book)
    siblings, cursor = [], index
    for level in levels[:-1]:
        siblings.append(level[cursor ^ 1])
        cursor >>= 1
    return (b"KKABPRF1" + _header(book, revision) + levels[-1][0] + public_key
            + signature + _entry(*book[index])
            + bytes([index, len(siblings)]) + b"".join(siblings))


class TestMsgEthereumCertifiedContacts(common.KeepKeyTest):

    def _ready(self):
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.requires_message("ClearsignAttestorSign")
        self.requires_release_capability("certified-contacts")
        self.setup_mnemonic_allallall()

    def _screens(self, msg):
        """Send `msg`, approving every screen; return (screens, response)."""
        screens = []
        press = self.client.callback_ButtonRequest

        def capture(req):
            screens.append(self.client._read_oled_after_settle())
            return press(req)

        self.client.callback_ButtonRequest = capture
        try:
            resp = self.client.call(msg)
        finally:
            del self.client.callback_ButtonRequest
        return screens, resp

    def _certify(self, book=BOOK):
        screens, resp = self._screens(
            proto.ClearsignAttestorSign(payload=request(book)))
        self.assertIsInstance(resp, proto.ClearsignAttestorSignature)
        return screens, resp.public_key, resp.signature

    def _send(self, to=ALICE, **kw):
        fields = dict(
            address_n=parse_path("m/44'/60'/0'/0/0"),
            nonce=int_to_big_endian(1),
            gas_price=int_to_big_endian(20000000000),
            gas_limit=int_to_big_endian(21000),
            value=int_to_big_endian(10**18),
            to=bytes.fromhex(to),
            chain_id=1)
        fields.update(kw)
        screens, resp = self._screens(eth_proto.EthereumSignTx(**fields))
        self.assertIsInstance(resp, eth_proto.EthereumTxRequest)
        self.assertEqual(len(resp.signature_r), 32)
        return screens

    def _load(self, payload):
        ack = self.client.call_raw(
            eth_proto.EthereumTxMetadata(signed_payload=payload))
        self.assertIsInstance(ack, eth_proto.EthereumMetadataAck)
        return ack

    def _shown(self, screens, text):
        return [i for i, s in enumerate(screens) if oled_text.shows(s, text)]

    def test_certifying_shows_every_contact_and_signs_only_the_commitment(self):
        self._ready()
        # No AdvancedMode: the user reviews their own contacts.
        screens, public_key, signature = self._certify()

        # One summary, then a name screen and an address screen per contact.
        self.assertEqual(len(screens), 1 + 2 * len(BOOK))
        self.assertTrue(oled_text.shows(
            screens[0], "Approve 3 contacts?\nRevision 7"))
        for i, (network, address, label) in enumerate(BOOK):
            self.assertTrue(oled_text.shows(
                screens[1 + 2 * i], "%s\n%s" % (label, network)))
            self.assertTrue(oled_text.shows(
                screens[2 + 2 * i], "0x" + address))

        self.assertEqual(len(public_key), 33)
        self.assertEqual(len(signature), 64)
        key = VerifyingKey.from_string(public_key, curve=SECP256k1)
        self.assertTrue(key.verify_digest(
            signature, _sha(manifest(BOOK)), sigdecode=util.sigdecode_string))

    def test_a_send_to_a_contact_names_it_and_still_shows_the_address(self):
        self._ready()
        baseline = self._send()
        self.assertEqual(
            len(self._shown(baseline, "Send 1 ETH to 0x" + ALICE)), 1)

        _, public_key, signature = self._certify()
        ack = self._load(proof(BOOK, 0, public_key, signature))
        self.assertEqual(ack.display_summary, "Contact verified")
        named = self._send()

        # The same review plus one screen: the name, then the full address.
        self.assertEqual(len(named), len(baseline) + 1)
        at = self._shown(named, "Send 1 ETH to Alice")
        self.assertEqual(len(at), 1)
        self.assertTrue(oled_text.shows(named[at[0] + 1], "0x" + ALICE))
        self.assertEqual(self._shown(named, "Send 1 ETH to 0x" + ALICE), [])

        # One proof names one send: the next one is the baseline again.
        again = self._send()
        self.assertEqual(len(again), len(baseline))
        self.assertEqual(self._shown(again, "Send 1 ETH to Alice"), [])

    def test_a_known_token_transfer_names_the_recipient(self):
        self._ready()
        _, public_key, signature = self._certify()
        self._load(proof(BOOK, 0, public_key, signature))
        data = (bytes.fromhex("a9059cbb") + bytes(12) + bytes.fromhex(ALICE)
                + (1).to_bytes(32, "big"))
        screens = self._send(to=USDC, value=b"", data_length=len(data),
                             data_initial_chunk=data)
        at = self._shown(screens, "Send 0.000001 USDC to Alice")
        self.assertEqual(len(at), 1)
        self.assertTrue(oled_text.shows(screens[at[0] + 1], "0x" + ALICE))

    def test_a_proof_names_only_its_own_address_and_network(self):
        self._ready()
        baseline = self._send()
        _, public_key, signature = self._certify()

        # Carol's proof, a send to Alice.
        self._load(proof(BOOK, 2, public_key, signature))
        self.assertEqual(len(self._send()), len(baseline))

        # Bob is a contact on Base only: on Ethereum he is an address.
        self._load(proof(BOOK, 1, public_key, signature))
        screens = self._send(to=BOB)
        self.assertEqual(self._shown(screens, "Send 1 ETH to Bob at the bank"),
                         [])
        self.assertEqual(len(self._shown(screens, "Send 1 ETH to 0x" + BOB)), 1)

    def test_an_altered_proof_is_refused_and_the_send_is_unchanged(self):
        self._ready()
        baseline = self._send()
        _, public_key, signature = self._certify()
        good = proof(BOOK, 0, public_key, signature)
        label_at = good.index(b"Alice")
        cases = {
            "label": good[:label_at] + b"Alicf" + good[label_at + 5:],
            "address": good.replace(bytes.fromhex(ALICE), bytes.fromhex(BOB)),
            "signature": good.replace(
                signature, signature[:-1] + bytes([signature[-1] ^ 1])),
            "another book": proof(BOOK[:2], 0, public_key, signature),
        }
        for name, bad in cases.items():
            with self.subTest(name):
                ack = self._load(bad)
                self.assertEqual(ack.display_summary, "Invalid contact")
                screens = self._send()
                self.assertEqual(len(screens), len(baseline))
                self.assertEqual(self._shown(screens, "Send 1 ETH to Alice"),
                                 [])

    def test_a_book_the_device_cannot_vouch_for_is_refused_unreviewed(self):
        self._ready()
        bad_books = {
            "one address, two names": (("eip155:1", ALICE, "Alice"),
                                       ("eip155:1", ALICE, "Mallory")),
            "one name, two addresses": (("eip155:1", ALICE, "Alice"),
                                        ("eip155:1", BOB, "Alice")),
            "label ends in a space": (("eip155:1", ALICE, "Alice "),),
            "label is padded": (("eip155:1", ALICE, "Bob  eip155:1"),),
            "not an EVM network": (("cosmos:cosmoshub-4", ALICE, "Alice"),),
        }
        for name, book in bad_books.items():
            with self.subTest(name):
                # call_raw answers nothing: a ButtonRequest here would mean
                # the device started a review.
                resp = self.client.call_raw(
                    proto.ClearsignAttestorSign(payload=request(book)))
                self.assertIsInstance(resp, proto.Failure)
                self.assertEqual(resp.code, types.Failure_SyntaxError)
                self.assertEqual(resp.message, "Invalid address book")


if __name__ == '__main__':
    unittest.main()
