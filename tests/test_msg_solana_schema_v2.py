# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.

"""KKSOLSC1 schema v2 reviews, asserted by what the screen says.

Certified tier: the public Vault 501-scope certificate and its delegate's real
signature over the version 1 relayDepositNative schema (the fixture of
test_relay_certified_v0_no_lookup_proof_reaches_signer_check), applied to
messages built around this device's own key so the whole review runs; and the
delegate's signatures, from the deployed ClearSign Worker, over the SoltoshiDICE
join's version 2 schema and the SDICE token definition, applied to the real
join re-keyed to this device. It needs
the alpha ClearSign root compiled in (KK_CLEARSIGN_ALPHA_ROOT); an emulator
without it refuses the certificate first, and those tests skip.

Runtime tier: the CI signer, loaded into slots 2 and 3, signs the schema and
the token definitions.

ClearsignAttestor: the extra screen a version 2 TOKEN_AMOUNT costs the
operator before anything is attested.

Screens are read through oled_text: DebugLink returns pixels, not text, so the
expected text is rendered with the firmware's glyphs and found in the frame.
"""

import hashlib
import struct
import unittest

import common
from Crypto.Signature import eddsa
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_solana_pb2 as solana
from keepkeylib.client import CallException
from keepkeylib import signed_metadata
from keepkeylib.tools import b58decode, b58encode, parse_path
from oled_text import TITLE_FONT, find_line, find_text, shows
from test_msg_display_disclosure import ScreenRecorder

PATH = parse_path("m/44'/501'/0'/0'")
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

RELAY_PROGRAM = bytes.fromhex(
    "792689378ecd51d80406eb0caa3b62795beb10b6c5dc96bc2e0df03cbfee1abf")
RELAY_DISC = bytes.fromhex("0d9e0ddf5fd51c06")
RELAY_SCHEMA = bytes.fromhex(
    "4b4b534f4c53433101792689378ecd51d80406eb0caa3b62795beb10b6c5dc96"
    "bc2e0df03cbfee1abf080d9e0ddf5fd51c060c52656c6179204272696467650d"
    "6465706f7369744e6174697665020506416d6f756e7404054f72646572010305"
    "5661756c74")
RELAY_SCHEMA_SIG = bytes.fromhex(
    "801b309d284ae89287a21a6acbd5c63f999515f3ff6bf71d72a256485321b892"
    "7b7ebc3a26ace3df5551b85a68df8e9f1ef8eac220d85f4bfaa33d43b5349061")
CERT_501 = bytes.fromhex(
    "0101000001f56c68c8804b6565704b6579205661756c74000000000000000000"
    "000000000000000000000342f5f9704494b3f9bd72295eecaf29d783d23ea02"
    "b2dc9f48abcd2e46d4850cfa2753fac6068a45747a32a4a39f249af72b55370f"
    "3491913b7fb9a80207d619b3b4fca6750fc1fdc790da5562b42a351e12cde3c"
    "0f084056a24ca8d1bf2c36b5")
SYSTEM = b"\0" * 32
COMPUTE_BUDGET = bytes.fromhex(
    "0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000")
DESTINATION = b"\x22" * 32

# SoltoshiDICE "Blackjack join", the real message and its version 2 schema
# (keepkey-firmware unittests/firmware/solana.cpp kSoltoshiJoinMessageHex and
# kSoltoshiJoinSchemaHex). Instructions: SetComputeUnitLimit, a System
# Transfer to the session key, the 82-byte join. Its three TOKEN_AMOUNTs read
# their mint from join account 3, message key 8: the SDICE mint.
SOLTOSHI_JOIN = bytes.fromhex(
    "0100060dec3979a4dc6b401bd045171a189f26856fab9eab75560214f972b2ed"
    "c164300f209892e406a5c1bf530d7721f4634090040c3fbe35df3834a2e80d97"
    "bee0620e635230d0ec6d2689ed9f0bf1da57e147ac13babc4430c5af1ade2e40"
    "c9cf3ee577e4b4511f351e94a764bde876019ec3523510049d3b50b3a8c70fd3"
    "8b6007f9847d3c28e2cbbff9e7c4f7cb6d6d71e5bc16d50aa6ed4ffe3aeae6a0"
    "d6c6eaa4a11b0a513ec5310074c9de56117aad169ab339ec9a544b3c4cf33a74"
    "d0cc37c6fc4da258d76a62aa6a0c641d34cefc33c97f0b9424c1678e26ee25b4"
    "c49b7bda00000000000000000000000000000000000000000000000000000000"
    "0000000038278241da03c70dd0fc885f7ad2123bad32b33a5402340739af8ae5"
    "d84cacef8b673cda2e293e0220ab3e01d2b58ed055c9c1b2762dd515612b10ca"
    "cd6e34360306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a"
    "40000000b0e08af4a4fcfad13ef8fcfd9dc70975eb6fc2e04a7c76611540a51c"
    "d5db9ed006ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928"
    "d8a18bfcf9adfb23cba734d5c630dc94ffe9bc6964e347bd3af8c3afb795b849"
    "cab5d927030a000502400d0300070200050c0200000080841e00000000000b09"
    "0002040803010c060952515600000000000000d4030000000000000100ca9a3b"
    "00000000a11b0a513ec5310074c9de56117aad169ab339ec9a544b3c4cf33a74"
    "d0cc37c6100e00000000000000ca9a3b0000000000ca9a3b00000000")
SOLTOSHI_SCHEMA = bytes.fromhex(
    "4b4b534f4c53433102b0e08af4a4fcfad13ef8fcfd9dc70975eb6fc2e04a7c7661"
    "1540a51cd5db9ed001510c536f6c746f736869444943450e426c61636b6a61636b"
    "206a6f696e080105526f756e6401085265766973696f6e02045365617406064275"
    "792d696e03030b53657373696f6e206b6579070a4578706972657320696e060941"
    "6c6c6f77616e63650306094d61782077616765720300")
SDICE_MINT = "4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump"
TOKEN_AMOUNT_LABELS = ("BUY-IN", "ALLOWANCE", "MAX WAGER")

# The deployed ClearSign Worker's certify response for that join (Worker
# source ee1488807): the Vault delegate's signature over SOLTOSHI_SCHEMA, and its
# KeepKeySolanaTokenDef/2 signature over the SDICE mint, Token-2022, 6 and
# "SDICE". Neither covers a transaction, so both apply to the join re-keyed
# to this device. The delegate is certified by CERT_501.
SOLTOSHI_SCHEMA_SIG = bytes.fromhex(
    "7302c703ce5fee498427bf87801384c21660f4d3451aef18549f2a31d8cd2561"
    "1d99c94afcaeafcbd6a8d04c3c1b49232a77a2b949451ba84ff217c590c14700")
SDICE_DEFINITION_SIG = bytes.fromhex(
    "36ed412ef38eb9ade9a7ac3e5b60841f9d032ea870c7886b87155c202f2ecfa1"
    "1fc87848280fea855881f9e34127fbd2dfb91c4ed556dbd54cd1fb18e279d41a")
# The join's decoded values (Vault __tests__/fixtures/solana/
# soltoshidice-blackjack-join.json).
SESSION_KEY = "BqtZ8PRQywD9Z5xXeB5112wtPG3xtj7TqF56hroicGjX"
SDICE_TRUSTED = "1000.000000 SDICE\n" + SDICE_MINT
SDICE_UNTRUSTED = "1000000000 base units of mint\n" + SDICE_MINT
# 1,000,000 micro-lamports x the join's 200,000-unit limit = 200,000 lamports.
JOIN_PRICE = 1000000
JOIN_MAX_FEE = "Max priority fee\n0.000200000 SOL"


def sign(preimage):
    """The CI signer (slot 3's key) over sha256(preimage)."""
    key = SigningKey.from_string(signed_metadata.TEST_PRIVATE_KEY,
                                 curve=SECP256k1)
    return key.sign_digest_deterministic(hashlib.sha256(preimage).digest(),
                                         hashfunc=hashlib.sha256,
                                         sigencode=sigencode_string)


def price(micro_lamports):
    return (4, [], bytes([3]) + struct.pack("<Q", micro_lamports))


def limit(units):
    return (4, [], bytes([2]) + struct.pack("<I", units))


RELAY_IX = (5, [0, 1, 1, 1],
            RELAY_DISC + struct.pack("<Q", 996374000) + b"\xAB" * 32)
TRANSFER_IX = (3, [0, 2], struct.pack("<I", 2) + struct.pack("<Q", 2000000))


def relay_message(signer, ixs):
    """Legacy message. Keys: signer, vault, transfer destination, System,
    ComputeBudget, Relay; the last three are readonly programs."""
    keys = [signer, b"\x66" * 32, DESTINATION, SYSTEM, COMPUTE_BUDGET,
            RELAY_PROGRAM]
    out = bytearray([1, 0, 3, len(keys)]) + b"".join(keys) + b"\xBB" * 32
    out.append(len(ixs))
    for program, accounts, data in ixs:
        out += bytes([program, len(accounts)]) + bytes(accounts)
        out += bytes([len(data)]) + data
    return bytes(out)


def soltoshi_join(signer, priced=False):
    """The join with account 0, its fee payer and only signer, set to
    `signer`. `priced` adds a SetComputeUnitPrice of JOIN_PRICE after the
    SetComputeUnitLimit; the real join sets none."""
    msg = bytearray(SOLTOSHI_JOIN)
    msg[4:36] = signer
    if priced:
        count_at = 4 + 32 * msg[3] + 32
        msg[count_at] += 1
        after_limit = count_at + 1 + 3 + 5  # program 10, no accounts, 5 bytes
        msg[after_limit:after_limit] = (bytes([10, 0, 9, 3]) +
                                        struct.pack("<Q", JOIN_PRICE))
    return bytes(msg)


def sdice_definition(signature=SDICE_DEFINITION_SIG):
    return solana.SolanaTokenInfo(
        mint=b58decode(SDICE_MINT, 32), symbol="SDICE", decimals=6,
        signature=signature, signer_key_id=128)


def schema_v2(args):
    """A version 2 KKSOLSC1 payload for the Relay program, no accounts."""
    out = bytearray(b"KKSOLSC1\x02") + RELAY_PROGRAM + b"\x01\x0d"
    for text in (b"Attest Probe", b"join"):
        out += bytes([len(text)]) + text
    out.append(len(args))
    for arg_type, label, mint_account in args:
        out += bytes([arg_type, len(label)]) + label
        if mint_account is not None:
            out.append(mint_account)
    out.append(0)
    return bytes(out)


class SchemaReview(common.KeepKeyTest):

    def setUp(self):
        super(SchemaReview, self).setUp()
        self.requires_firmware("7.16.0")
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

    def _signer(self):
        address = self.client.call(solana.SolanaGetAddress(
            address_n=PATH, show_display=False)).address
        number = 0
        for char in address:
            number = number * 58 + ALPHABET.index(char)
        return number.to_bytes(32, "big")

    def _review(self, request, group):
        """Sign, returning (response, one settled frame per ButtonRequest)."""
        recorder = ScreenRecorder(self.client, answer=True,
                                  screenshot_group=group)
        with recorder:
            response = self.client.call(request)
        return response, recorder.screens

    def assertShows(self, screens, title, body):
        """Index of the first screen titled `title` (as the device uppercases
        it) whose body shows `body`."""
        for i, screen in enumerate(screens):
            if (find_line(screen, title, TITLE_FONT) is not None and
                    shows(screen, body)):
                return i
        self.fail("no screen titled %r shows %r" % (title, body))

    def assertNotShown(self, screens, body):
        self.assertIsNone(find_text(screens, body),
                          "unexpectedly shown: %r" % body)


class TestSolanaSchemaCertified(SchemaReview):

    def setUp(self):
        super(TestSolanaSchemaCertified, self).setUp()
        self.client.apply_policy("AdvancedMode", False)
        self._require_alpha_root()
        self.signer = self._signer()

    def _certified(self, raw):
        return solana.SolanaSignTx(
            address_n=PATH, raw_tx=raw, schema_payload=RELAY_SCHEMA,
            schema_signature=RELAY_SCHEMA_SIG, schema_signer_key_id=128,
            clearsign_certificate=CERT_501)

    def _require_alpha_root(self):
        """A build without the root refuses the certificate before anything
        else. With it, a proof for a message this device does not sign passes
        every certified check and fails at the signer check; any other outcome
        is a failure, not a skip."""
        with self.assertRaises(CallException) as refused:
            self.client.call(self._certified(
                relay_message(b"\x11" * 32, [RELAY_IX])))
        if "Invalid certified Solana certificate" in str(refused.exception):
            self.skipTest("emulator built without the alpha ClearSign root "
                          "(KK_CLEARSIGN_ALPHA_ROOT=OFF)")
        self.assertIn("Derived key is not a signer for this tx",
                      str(refused.exception))

    def test_certified_v1_schema_reviews_static_transfer_companion(self):
        send = "Send 0.002000000 SOL to %s?" % b58encode(DESTINATION)
        base, base_screens = self._review(
            self._certified(relay_message(self.signer, [RELAY_IX])),
            "relay")
        self.assertEqual(len(base.signature), 64)
        self.assertNotShown(base_screens, send)

        response, screens = self._review(
            self._certified(relay_message(self.signer,
                                          [RELAY_IX, TRANSFER_IX])),
            "relay_transfer")
        self.assertEqual(len(response.signature), 64)
        funding = self.assertShows(
            screens, "INSTR 2/2",
            "Funding account\n%s" % b58encode(self.signer))
        self.assertGreater(self.assertShows(screens, "INSTR 2/2", send),
                           funding)

    def test_certified_review_shows_priority_fee(self):
        fee_payer = "Fee payer\n%s" % b58encode(self.signer)
        # 1,000,000 micro-lamports x 200,000 units = 200,000 lamports.
        max_fee = "Max priority fee\n0.000200000 SOL"
        _, plain = self._review(
            self._certified(relay_message(self.signer,
                                          [limit(200000), RELAY_IX])),
            "relay_no_price")
        self.assertNotShown(plain, fee_payer)
        self.assertNotShown(plain, max_fee)

        response, priced = self._review(
            self._certified(relay_message(
                self.signer, [limit(200000), price(1000000), RELAY_IX])),
            "relay_price")
        self.assertEqual(len(response.signature), 64)
        payer_at = self.assertShows(priced, "FEE", fee_payer)
        self.assertEqual(self.assertShows(priced, "FEE", max_fee),
                         payer_at + 1)

    def test_certified_duplicate_compute_budget_refused(self):
        for ixs in ([price(1), price(2), RELAY_IX],
                    [limit(1000), limit(2000), RELAY_IX]):
            with self.assertRaises(CallException) as refused:
                self.client.call(
                    self._certified(relay_message(self.signer, ixs)))
            self.assertIn("Invalid priority fee", str(refused.exception))

    # The real SoltoshiDICE join, certified by the deployed ClearSign Worker.

    def _join_request(self, raw, token_info=()):
        return solana.SolanaSignTx(
            address_n=PATH, raw_tx=raw, schema_payload=SOLTOSHI_SCHEMA,
            schema_signature=SOLTOSHI_SCHEMA_SIG, schema_signer_key_id=128,
            clearsign_certificate=CERT_501, token_info=list(token_info))

    def _join_review(self, amount, priced=False):
        """Every screen of the join's certified review, in order, as (title,
        body). The real join sets no compute-unit price, so it has no Fee
        screens; its fee payer is the Transfer's funding account."""
        payer = b58encode(self.signer)
        total = 4 if priced else 3
        instr = lambda i: "INSTR %d/%d" % (i, total)
        screens = [(instr(1), "Set compute unit limit to 200000?")]
        if priced:
            screens.append((instr(2), "Set compute unit price to %d?" %
                            JOIN_PRICE))
        screens += [
            (instr(total - 1), "Funding account\n" + payer),
            (instr(total - 1), "Send 0.002000000 SOL to %s?" % SESSION_KEY),
            ("KEEPKEY CLEARSIGN", "KeepKey Vault\nSigner A9531B9D"),
            ("SOLTOSHIDICE", "Blackjack join"),
            ("ROUND", "86"),
            ("REVISION", "980"),
            ("SEAT", "1"),
            ("BUY-IN", amount),
            ("SESSION KEY", SESSION_KEY),
            ("EXPIRES IN", "1 h"),
            ("ALLOWANCE", amount),
            ("MAX WAGER", amount),
        ]
        if priced:
            screens += [("FEE", "Fee payer\n" + payer), ("FEE", JOIN_MAX_FEE)]
        return screens + [("SOLANA", "Sign this Solana transaction?")]

    def assertScreens(self, screens, expected):
        self.assertEqual(len(screens), len(expected))
        for i, (screen, (title, body)) in enumerate(zip(screens, expected)):
            self.assertIsNotNone(find_line(screen, title, TITLE_FONT),
                                 "screen %d is not titled %r" % (i, title))
            self.assertTrue(shows(screen, body),
                            "screen %d does not show %r" % (i, body))

    def assertSignedBy(self, response, message):
        """A 64-byte ed25519 signature by this device's key over `message`."""
        self.assertEqual(len(response.signature), 64)
        eddsa.new(eddsa.import_public_key(self.signer), "rfc8032").verify(
            message, bytes(response.signature))

    def test_certified_soltoshi_join_reviews_every_screen(self):
        """The Worker's schema and SDICE definition name every value of the
        join, AdvancedMode off. These frames are the report's evidence, so
        the setUp policy screen is dropped first."""
        raw = soltoshi_join(self.signer)
        self.client.reset_screenshots()
        response, screens = self._review(
            self._join_request(raw, [sdice_definition()]), None)
        self.assertScreens(screens, self._join_review(SDICE_TRUSTED))
        self.assertSignedBy(response, raw)

    def test_certified_soltoshi_join_priority_fee_names_fee_payer(self):
        """With a compute-unit price added, the fee payer and the maximum
        priority fee follow the join's values, before the final screen."""
        raw = soltoshi_join(self.signer, priced=True)
        response, screens = self._review(
            self._join_request(raw, [sdice_definition()]), "join_priced")
        self.assertScreens(screens,
                           self._join_review(SDICE_TRUSTED, priced=True))
        self.assertSignedBy(response, raw)

    def test_certified_soltoshi_join_untrusted_definition_shows_base_units(
            self):
        """No definition, or one with one byte of its signature changed: the
        three amounts are raw base units beside the mint, nothing else
        changes, and the join still signs."""
        raw = soltoshi_join(self.signer)
        response, missing = self._review(self._join_request(raw),
                                         "join_no_definition")
        self.assertScreens(missing, self._join_review(SDICE_UNTRUSTED))
        self.assertSignedBy(response, raw)

        signature = bytearray(SDICE_DEFINITION_SIG)
        signature[0] ^= 0x01
        response, flipped = self._review(
            self._join_request(raw, [sdice_definition(bytes(signature))]),
            "join_bad_definition")
        self.assertEqual(flipped, missing)
        self.assertSignedBy(response, raw)

    def test_certified_soltoshi_join_ignores_blind_sign_policy(self):
        """AdvancedMode on changes nothing: the same certified review, frame
        for frame, and never the Blind Sign screen."""
        raw = soltoshi_join(self.signer)
        request = self._join_request(raw, [sdice_definition()])
        _, off = self._review(request, "join_policy_off")
        self.client.apply_policy("AdvancedMode", True)
        response, on = self._review(request, "join_policy_on")
        self.assertEqual(on, off)
        self.assertScreens(on, self._join_review(SDICE_TRUSTED))
        self.assertFalse(any(find_line(screen, "BLIND SIGN", TITLE_FONT)
                             for screen in on))
        self.assertSignedBy(response, raw)


class TestSolanaSchemaRuntime(SchemaReview):

    def setUp(self):
        super(TestSolanaSchemaRuntime, self).setUp()
        self.requires_message("LoadClearsignSigner")
        signed_metadata.assert_test_key_matches_slot3()
        self.client.apply_policy("AdvancedMode", True)
        self.signer = self._signer()

    def _load_signers(self):
        """Slots 2 and 3 hold the same CI key under different aliases."""
        for key_id, alias in ((3, "CI Test"), (2, "CI Two")):
            self.client.load_clearsign_signer(
                key_id=key_id,
                pubkey=signed_metadata.test_signer_compressed_pubkey(),
                alias=alias)

    def test_runtime_schema_refuses_transfer_companion(self):
        self._load_signers()
        request = solana.SolanaSignTx(
            address_n=PATH,
            raw_tx=relay_message(self.signer, [RELAY_IX, TRANSFER_IX]),
            schema_payload=RELAY_SCHEMA, schema_signature=sign(RELAY_SCHEMA),
            schema_signer_key_id=3)
        with self.assertRaises(CallException) as refused:
            self.client.call(request)
        self.assertIn("Invalid Solana instruction schema",
                      str(refused.exception))

        # Control: the same request without the Transfer is reviewed.
        request.raw_tx = relay_message(self.signer, [RELAY_IX])
        response, screens = self._review(request, "runtime_relay")
        self.assertEqual(len(response.signature), 64)
        self.assertShows(screens, "AMOUNT", "0.996374000 SOL")

    def _join(self):
        """The join with account 0 set to this device's key and the Transfer
        dropped: the runtime path refuses any Transfer companion."""
        msg = bytearray(SOLTOSHI_JOIN)
        msg[4:36] = self.signer
        at = 4 + 32 * msg[3] + 32
        self.assertEqual(msg[at], 3)
        ixs, q = [], at + 1
        for _ in range(3):
            start = q
            q += 2 + msg[q + 1]
            q += 1 + msg[q]
            ixs.append(bytes(msg[start:q]))
        self.assertEqual(q, len(msg))
        return bytes(msg[:at]) + b"\x02" + ixs[0] + ixs[2]

    def test_runtime_token_amount_trust_comes_from_the_schema_signer(self):
        """The schema is signed by slot 2. Slot 2's definition names and
        scales the three TOKEN_AMOUNTs and the mint stays on screen; the same
        definition from slot 3 verifies but is ignored, and the review is the
        one with no definition at all: raw base units and the mint."""
        raw = self._join()
        mint = raw[4 + 8 * 32:4 + 9 * 32]
        self.assertEqual(b58encode(mint), SDICE_MINT)
        definition = (b"KeepKeySolanaTokenDef/1" + mint +
                      struct.pack("<I", 6) + b"SDICE")

        def review(definition_slot, group):
            infos = []
            if definition_slot is not None:
                infos = [solana.SolanaTokenInfo(
                    mint=mint, symbol="SDICE", decimals=6,
                    signature=sign(definition),
                    signer_key_id=definition_slot)]
            self._load_signers()
            response, screens = self._review(solana.SolanaSignTx(
                address_n=PATH, raw_tx=raw, schema_payload=SOLTOSHI_SCHEMA,
                schema_signature=sign(SOLTOSHI_SCHEMA),
                schema_signer_key_id=2, token_info=infos), group)
            self.assertEqual(len(response.signature), 64)
            return screens

        trusted = "1000.000000 SDICE\n" + SDICE_MINT
        untrusted = "1000000000 base units of mint\n" + SDICE_MINT

        same = review(2, "join_schema_signer_definition")
        for label in TOKEN_AMOUNT_LABELS:
            self.assertShows(same, label, trusted)
        self.assertNotShown(same, untrusted)

        none = review(None, "join_no_definition")
        for label in TOKEN_AMOUNT_LABELS:
            self.assertShows(none, label, untrusted)
        self.assertNotShown(none, trusted)

        other = review(3, "join_other_slot_definition")
        self.assertEqual(other, none)


class TestClearsignAttestorTokenAmount(SchemaReview):

    def setUp(self):
        super(TestClearsignAttestorTokenAmount, self).setUp()
        self.requires_message("ClearsignAttestorSign")
        self.client.apply_policy("AdvancedMode", True)

    def _attest(self, payload, group):
        recorder = ScreenRecorder(self.client, answer=True,
                                  screenshot_group=group)
        with recorder:
            response = self.client.call(
                proto.ClearsignAttestorSign(payload=payload))
        return response, recorder.screens

    def test_token_amount_mint_account_is_attested_before_signing(self):
        """A TOKEN_AMOUNT's mint account decides which token definition may
        name its amount, so the operator confirms it on its own screen right
        after the argument, before the attestation is signed. The same schema
        with a u64 there is the control: one screen fewer, nothing else
        different before or after."""
        token_payload = schema_v2([(6, b"Buy-in", 3)])
        u64_payload = schema_v2([(1, b"Buy-in", None)])

        response, token = self._attest(token_payload, "token_amount")
        _, u64 = self._attest(u64_payload, "u64")
        self.assertEqual(len(token), len(u64) + 1)

        arg = self.assertShows(token, "ATTEST SCHEMA",
                               "Arg 1: token amount (u64 LE)\nBuy-in")
        self.assertEqual(self.assertShows(token, "ATTEST SCHEMA",
                                          "Arg 1 token mint is\naccount #3"),
                         arg + 1)
        self.assertEqual(token[:arg], u64[:arg])
        self.assertEqual(token[arg + 2:], u64[arg + 1:])
        self.assertShows(u64, "ATTEST SCHEMA", "Arg 1: u64 LE\nBuy-in")
        self.assertNotShown(u64, "Arg 1 token mint is\naccount #3")

        # What was signed after those screens is this exact payload.
        key = VerifyingKey.from_string(bytes(response.public_key),
                                       curve=SECP256k1)
        self.assertTrue(key.verify_digest(
            bytes(response.signature),
            hashlib.sha256(token_payload).digest(),
            sigdecode=sigdecode_string))


if __name__ == "__main__":
    unittest.main()
