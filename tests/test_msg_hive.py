# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.

"""Hive (SLIP-0048) device tests — multi-role keys + account operations.

Uses the standard 12-word test seed (mnemonic12, "alcohol ... aisle") via
setup_mnemonic_nopin_nopassphrase().

The account_create / account_update / transfer tests are self-validating: they
recover the signer from the 65-byte device signature over
SHA256(chain_id || serialized_tx) and assert it equals the device-derived
signing key. This exercises the device AND validates the attestation-digest
contract documented in keepkey-vault docs/HIVE-ATTESTATION-DIGEST-SPEC.md —
no precomputed golden vector required, and not circular (recovery is an
independent cryptographic check).
"""

import hashlib
import struct
import unittest

import common

from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_string

from keepkeylib import hive
from keepkeylib.tools import parse_path

# Hive mainnet chain id: beeab0de followed by 28 zero bytes (32 bytes).
HIVE_CHAIN_ID = bytes.fromhex("beeab0de" + "00" * 28)

# SLIP-0048 roles (hardened offsets within the role component).
ROLE_OWNER, ROLE_ACTIVE, ROLE_MEMO, ROLE_POSTING = 0, 1, 3, 4

HIVE_OP_VOTE = 0
HIVE_OP_COMMENT = 1
HIVE_OP_TRANSFER = 2
HIVE_OP_ACCOUNT_CREATE = 9
HIVE_OP_ACCOUNT_UPDATE = 10
HIVE_OP_CUSTOM_JSON = 18


def hive_path(role, account_index=0):
    """m/48'/13'/role'/account'/0' — all five components hardened."""
    h = 0x80000000
    return [h + 48, h + 13, h + role, h + account_index, h]


def recover_compressed(serialized_tx, sig65):
    """Recover the 33-byte compressed signer pubkey from a Hive device signature.

    Mirrors HIVE-ATTESTATION-DIGEST-SPEC.md §1-2:
      digest = SHA256(chain_id || serialized_tx)
      sig[0] = 27 + recovery_id + 4   -> recovery_id = sig[0] - 31
      sig[1:65] = r || s
    """
    assert len(sig65) == 65, "Hive signature must be 65 bytes"
    recid = sig65[0] - 31
    assert 0 <= recid <= 3, "unexpected recovery header byte %d" % sig65[0]
    digest = hashlib.sha256(HIVE_CHAIN_ID + serialized_tx).digest()
    candidates = VerifyingKey.from_public_key_recovery_with_digest(
        sig65[1:], digest, SECP256k1, hashfunc=hashlib.sha256, sigdecode=sigdecode_string
    )
    return candidates[recid].to_string("compressed")


# ── Independent Graphene serializer for HiveSignOperations tests ──────────
# dhive-equivalent byte building, written here so firmware parser bugs can't
# cancel out against firmware serializer bugs.

def _varint(n):
    out = b""
    while True:
        b_ = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b_ | 0x80])
        else:
            return out + bytes([b_])


def _string(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return _varint(len(s)) + s


def _ops_tx(op_blobs, ref_num=12345, ref_prefix=67890, expiration=1700000000,
            ext=b"\x00", opcount=None):
    """header + varint op count + ops + extensions (default: empty)."""
    head = struct.pack("<HII", ref_num, ref_prefix, expiration)
    n = opcount if opcount is not None else len(op_blobs)
    return head + _varint(n) + b"".join(op_blobs) + ext


def _op_vote(voter, author, permlink, weight):
    return (_varint(HIVE_OP_VOTE) + _string(voter) + _string(author) +
            _string(permlink) + struct.pack("<h", weight))


def _op_comment(parent_author, parent_permlink, author, permlink, title,
                body, json_metadata):
    return (_varint(HIVE_OP_COMMENT) + _string(parent_author) +
            _string(parent_permlink) + _string(author) + _string(permlink) +
            _string(title) + _string(body) + _string(json_metadata))


def _op_custom_json(required_auths, required_posting_auths, id_, json_):
    out = _varint(18)  # custom_json
    out += _varint(len(required_auths)) + b"".join(_string(a) for a in required_auths)
    out += _varint(len(required_posting_auths)) + b"".join(_string(a) for a in required_posting_auths)
    return out + _string(id_) + _string(json_)


# The 2020 rebrand renamed the tokens but not their on-chain serialization:
# hived still writes "STEEM" and "SBD" (confirmed against
# condenser_api.get_transaction_hex). Call sites below pass the display names
# because that is what a reader expects; this is the one place that knows the
# wire spelling.
_WIRE_SYMBOL = {"HIVE": "STEEM", "HBD": "SBD"}


def _asset(amount, symbol):
    """int64 LE amount + uint8 precision + 7-byte NUL-padded WIRE symbol.

    Precision is pinned per symbol exactly as firmware's cur_asset requires;
    passing the wrong one is what the negative tests below exercise.
    """
    precision = 6 if symbol == "VESTS" else 3
    wire = _WIRE_SYMBOL.get(symbol, symbol)
    return (struct.pack("<q", amount) + bytes([precision]) +
            wire.encode("ascii").ljust(7, b"\x00"))


def _asset_raw(amount, precision, symbol):
    """Asset with a caller-chosen precision, for malformed-input tests.

    Still maps to the wire symbol: these tests target the precision and amount
    checks, and leaving the display spelling here would trip the symbol check
    first, so they would pass while testing nothing.
    """
    wire = _WIRE_SYMBOL.get(symbol, symbol)
    return (struct.pack("<q", amount) + bytes([precision]) +
            wire.encode("ascii").ljust(7, b"\x00"))


def _op_transfer_to_vesting(from_, to, amount):
    return (_varint(3) + _string(from_) + _string(to) + _asset(amount, "HIVE"))


def _op_withdraw_vesting(account, vesting_shares):
    return _varint(4) + _string(account) + _asset(vesting_shares, "VESTS")


def _op_limit_order_create(owner, orderid, sell, sell_sym, recv, recv_sym,
                           fill_or_kill, expiration):
    return (_varint(5) + _string(owner) + struct.pack("<I", orderid) +
            _asset(sell, sell_sym) + _asset(recv, recv_sym) +
            bytes([1 if fill_or_kill else 0]) + struct.pack("<I", expiration))


def _op_limit_order_cancel(owner, orderid):
    return _varint(6) + _string(owner) + struct.pack("<I", orderid)


def _op_convert(owner, requestid, amount):
    return (_varint(8) + _string(owner) + struct.pack("<I", requestid) +
            _asset(amount, "HBD"))


def _op_comment_options(author, permlink, max_payout, percent_hbd,
                        allow_votes=True, allow_curation=True,
                        beneficiaries=None):
    out = (_varint(19) + _string(author) + _string(permlink) +
           _asset(max_payout, "HBD") + struct.pack("<H", percent_hbd) +
           bytes([1 if allow_votes else 0, 1 if allow_curation else 0]))
    if not beneficiaries:
        return out + _varint(0)
    out += _varint(1) + _varint(0) + _varint(len(beneficiaries))
    for account, weight in beneficiaries:
        out += _string(account) + struct.pack("<H", weight)
    return out


def _op_transfer_to_savings(from_, to, amount, symbol, memo=""):
    return (_varint(32) + _string(from_) + _string(to) +
            _asset(amount, symbol) + _string(memo))


def _op_transfer_from_savings(from_, request_id, to, amount, symbol, memo=""):
    return (_varint(33) + _string(from_) + struct.pack("<I", request_id) +
            _string(to) + _asset(amount, symbol) + _string(memo))


def _op_claim_reward_balance(account, hive_amt, hbd_amt, vests_amt):
    return (_varint(39) + _string(account) + _asset(hive_amt, "HIVE") +
            _asset(hbd_amt, "HBD") + _asset(vests_amt, "VESTS"))


def _op_delegate_vesting_shares(delegator, delegatee, vesting_shares):
    return (_varint(40) + _string(delegator) + _string(delegatee) +
            _asset(vesting_shares, "VESTS"))


def _op_account_update2(account, json_metadata, posting_json_metadata,
                        authority_present=False):
    return (_varint(43) + _string(account) +
            bytes([1 if authority_present else 0, 0, 0, 0]) +
            _string(json_metadata) + _string(posting_json_metadata) +
            _varint(0))


class _Reader:
    """Cursor over the device-emitted Graphene bytes. Matches firmware
    serialization exactly (see hive.c append_* helpers)."""

    def __init__(self, data):
        self.d = data
        self.i = 0

    def take(self, n):
        v = self.d[self.i:self.i + n]
        assert len(v) == n, "truncated serialized_tx"
        self.i += n
        return v

    def u8(self):
        return self.take(1)[0]

    def u16le(self):
        return int.from_bytes(self.take(2), "little")

    def u32le(self):
        return int.from_bytes(self.take(4), "little")

    def u64le(self):
        return int.from_bytes(self.take(8), "little")

    def varint(self):
        shift = result = 0
        while True:
            b = self.u8()
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result
            shift += 7

    def string(self):
        return self.take(self.varint())

    def asset(self):
        amount = self.u64le()
        precision = self.u8()
        symbol = self.take(7).rstrip(b"\x00").decode()
        return amount, precision, symbol

    def authority(self):
        # weight_threshold=1, 0 account auths, 1 key auth, key(33), weight=1
        assert self.u32le() == 1, "weight_threshold must be 1"
        assert self.varint() == 0, "expected 0 account_auths"
        assert self.varint() == 1, "expected 1 key_auth"
        key = self.take(33)
        assert self.u16le() == 1, "key weight must be 1"
        return key

    def assert_end(self):
        assert self.i == len(self.d), "trailing bytes after operation (offset %d/%d)" % (self.i, len(self.d))


def _parse_header(r, expected_op):
    ref_block_num = r.u16le()
    ref_block_prefix = r.u32le()
    expiration = r.u32le()
    assert r.varint() == 1, "expected exactly one operation"
    op_type = r.varint()
    assert op_type == expected_op, "op_type %d != expected %d" % (op_type, expected_op)
    return ref_block_num, ref_block_prefix, expiration


class TestMsgHive(common.KeepKeyTest):

    def test_hive_get_public_key_active(self):
        """Active-role key derives and returns an STM-prefixed key + 33-byte raw."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveGetPublicKey")
        self.setup_mnemonic_nopin_nopassphrase()

        resp = hive.get_public_key(self.client, hive_path(ROLE_ACTIVE), show_display=False)
        self.assertTrue(resp.public_key.startswith("STM"), "expected STM-prefixed key")
        self.assertEqual(len(resp.raw_public_key), 33)
        self.assertIn(resp.raw_public_key[0], (2, 3), "compressed pubkey prefix")

    def test_hive_get_public_keys_all_roles(self):
        """All four role keys derive, are distinct, and STM-formatted."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveGetPublicKeys")
        self.setup_mnemonic_nopin_nopassphrase()

        resp = hive.get_public_keys(self.client, account_index=0, show_display=False)
        keys = [resp.owner_key, resp.active_key, resp.memo_key, resp.posting_key]
        for k in keys:
            self.assertTrue(k.startswith("STM"), "expected STM-prefixed key, got %r" % k)
        self.assertEqual(len(set(keys)), 4)

        # The single-key path must agree with the bulk path for the active role.
        single = hive.get_public_key(self.client, hive_path(ROLE_ACTIVE), show_display=False)
        self.assertEqual(single.public_key, resp.active_key)

    def test_hive_sign_transfer(self):
        """Transfer (op 2) signs and the signature recovers to the active key."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignTx")
        self.setup_mnemonic_nopin_nopassphrase()

        active = hive.get_public_key(self.client, hive_path(ROLE_ACTIVE), show_display=False)
        resp = hive.sign_tx(
            self.client,
            address_n=hive_path(ROLE_ACTIVE),
            chain_id=HIVE_CHAIN_ID,
            ref_block_num=12345,
            ref_block_prefix=67890,
            expiration=1700000000,
            sender="kktester",
            recipient="kkrecipient",
            amount=1000,  # 1.000 HIVE
            decimals=3,
            asset_symbol="HIVE",
            memo="kktest",
        )
        self.assertEqual(len(resp.signature), 65)
        self.assertIn(resp.signature[0], (31, 32))
        self.assertEqual(recover_compressed(resp.serialized_tx, resp.signature), active.raw_public_key)

        # Parse the transfer op and bind EVERY field — a rewritten recipient,
        # amount, or asset must fail, not just a missing substring.
        r = _Reader(resp.serialized_tx)
        ref_num, ref_prefix, expiration = _parse_header(r, HIVE_OP_TRANSFER)
        self.assertEqual((ref_num, ref_prefix, expiration), (12345, 67890, 1700000000))
        self.assertEqual(r.string(), b"kktester")     # from
        self.assertEqual(r.string(), b"kkrecipient")  # to
        self.assertEqual(r.asset(), (1000, 3, "HIVE"))
        self.assertEqual(r.string(), b"kktest")        # memo
        self.assertEqual(r.varint(), 0)                # extensions
        r.assert_end()

    def test_hive_sign_account_create(self):
        """account_create (op 9): signs, recovers to owner key, binds the 4 keys + name.

        This is the attestation a Pioneer sponsor verifies before spending an ACT.
        """
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignAccountCreate")
        self.requires_message("HiveGetPublicKeys")
        self.setup_mnemonic_nopin_nopassphrase()

        # Device-derived raw keys per role, for slot-exact comparison.
        raw = {role: hive.get_public_key(self.client, hive_path(role), show_display=False).raw_public_key
               for role in (ROLE_OWNER, ROLE_ACTIVE, ROLE_POSTING, ROLE_MEMO)}
        keys = hive.get_public_keys(self.client, account_index=0, show_display=False)

        resp = hive.sign_account_create(
            self.client,
            address_n=hive_path(ROLE_OWNER),
            chain_id=HIVE_CHAIN_ID,
            ref_block_num=12345,
            ref_block_prefix=67890,
            expiration=1700000000,
            creator="kksponsor",
            new_account_name="kktestacct",
            fee_amount=3000,
            owner_key=keys.owner_key,
            active_key=keys.active_key,
            posting_key=keys.posting_key,
            memo_key=keys.memo_key,
        )
        self.assertEqual(len(resp.signature), 65)
        self.assertIn(resp.signature[0], (31, 32))

        # Attestation: signature recovers to the device owner key.
        self.assertEqual(recover_compressed(resp.serialized_tx, resp.signature), raw[ROLE_OWNER])

        # Parse op 9 and bind EVERY field at its position. A firmware bug that
        # swaps roles, rewrites the creator, or alters the fee must fail here.
        r = _Reader(resp.serialized_tx)
        ref_num, ref_prefix, expiration = _parse_header(r, HIVE_OP_ACCOUNT_CREATE)
        self.assertEqual((ref_num, ref_prefix, expiration), (12345, 67890, 1700000000))
        self.assertEqual(r.asset(), (3000, 3, "HIVE"))     # fee
        self.assertEqual(r.string(), b"kksponsor")          # creator
        self.assertEqual(r.string(), b"kktestacct")         # new_account_name
        self.assertEqual(r.authority(), raw[ROLE_OWNER])
        self.assertEqual(r.authority(), raw[ROLE_ACTIVE])
        self.assertEqual(r.authority(), raw[ROLE_POSTING])
        self.assertEqual(r.take(33), raw[ROLE_MEMO])
        self.assertEqual(r.string(), b"")                   # json_metadata
        self.assertEqual(r.varint(), 0)                     # extensions
        r.assert_end()

    def test_hive_sign_account_update(self):
        """account_update (op 10): signs and recovers to the owner key."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignAccountUpdate")
        self.requires_message("HiveGetPublicKeys")
        self.setup_mnemonic_nopin_nopassphrase()

        raw = {role: hive.get_public_key(self.client, hive_path(role), show_display=False).raw_public_key
               for role in (ROLE_OWNER, ROLE_ACTIVE, ROLE_POSTING, ROLE_MEMO)}
        keys = hive.get_public_keys(self.client, account_index=0, show_display=False)

        resp = hive.sign_account_update(
            self.client,
            address_n=hive_path(ROLE_OWNER),
            chain_id=HIVE_CHAIN_ID,
            ref_block_num=12345,
            ref_block_prefix=67890,
            expiration=1700000000,
            account="kktestacct",
            new_owner_key=keys.owner_key,
            new_active_key=keys.active_key,
            new_posting_key=keys.posting_key,
            new_memo_key=keys.memo_key,
        )
        self.assertEqual(len(resp.signature), 65)
        self.assertIn(resp.signature[0], (31, 32))
        self.assertEqual(recover_compressed(resp.serialized_tx, resp.signature), raw[ROLE_OWNER])

        # Parse op 10 and bind the replacement keys to their slots. A bad impl
        # that updates the wrong authorities must fail even if op/name are right.
        r = _Reader(resp.serialized_tx)
        ref_num, ref_prefix, expiration = _parse_header(r, HIVE_OP_ACCOUNT_UPDATE)
        self.assertEqual((ref_num, ref_prefix, expiration), (12345, 67890, 1700000000))
        self.assertEqual(r.string(), b"kktestacct")          # account
        for role, label in ((ROLE_OWNER, "owner"), (ROLE_ACTIVE, "active"), (ROLE_POSTING, "posting")):
            self.assertEqual(r.u8(), 0x01)
            self.assertEqual(r.authority(), raw[role])
        self.assertEqual(r.take(33), raw[ROLE_MEMO])
        self.assertEqual(r.string(), b"")                    # json_metadata
        self.assertEqual(r.varint(), 0)                      # extensions
        r.assert_end()


    def _transfer_kwargs(self, **overrides):
        """Baseline valid HiveSignTx args; override per negative case."""
        kw = dict(
            address_n=hive_path(ROLE_ACTIVE),
            chain_id=HIVE_CHAIN_ID,
            ref_block_num=12345,
            ref_block_prefix=67890,
            expiration=1700000000,
            sender="kktester",
            recipient="kkrecipient",
            amount=1000,
            decimals=3,
            asset_symbol="HIVE",
            memo="kktest",
        )
        kw.update(overrides)
        return kw

    def _assert_sign_tx_fails(self, message_fragment, **overrides):
        from keepkeylib.client import CallException
        with self.assertRaises(CallException) as ctx:
            hive.sign_tx(self.client, **self._transfer_kwargs(**overrides))
        self.assertIn(message_fragment, str(ctx.exception))

    def test_hive_sign_transfer_rejects_foreign_path(self):
        """A path outside SLIP-0048 (e.g. BIP-44 BTC) must be rejected before
        signing — a compromised host cannot obtain a Hive signature with a
        key from another coin's derivation tree."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignTx")
        self.setup_mnemonic_nopin_nopassphrase()
        self._assert_sign_tx_fails(
            "Invalid Hive SLIP-0048 path",
            address_n=parse_path("m/44'/0'/0'/0/0"),
        )

    def test_hive_sign_transfer_rejects_wrong_network(self):
        """Wrong SLIP-0048 network index (registry 3054' instead of the
        de-facto 13') must be rejected — keys must be Ledger-compatible."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignTx")
        self.setup_mnemonic_nopin_nopassphrase()
        h = 0x80000000
        self._assert_sign_tx_fails(
            "Invalid Hive SLIP-0048 path",
            address_n=[h + 48, h + 3054, h + ROLE_ACTIVE, h, h],
        )

    def test_hive_sign_transfer_rejects_non_active_roles(self):
        """Transfers must sign with the active key ONLY. Post-HF28 hived no
        longer accepts higher-role substitution, so an owner/memo/posting
        signature would be rejected at broadcast — and the cold owner key
        must never be spent on a transfer. Unassigned roles reject too."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignTx")
        self.setup_mnemonic_nopin_nopassphrase()
        for role in (ROLE_OWNER, ROLE_MEMO, ROLE_POSTING, 2):  # 2' unassigned
            self._assert_sign_tx_fails(
                "Invalid Hive SLIP-0048 path",
                address_n=hive_path(role),
            )

    def test_hive_sign_account_ops_reject_non_owner_roles(self):
        """account_create/account_update must sign with the owner key ONLY —
        the sponsor's attestation check recovers to the device OWNER key, and
        account_update replaces the owner authority itself."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignAccountCreate")
        self.requires_message("HiveSignAccountUpdate")
        self.requires_message("HiveGetPublicKeys")
        self.setup_mnemonic_nopin_nopassphrase()
        from keepkeylib.client import CallException
        keys = hive.get_public_keys(self.client, account_index=0, show_display=False)
        tx_kw = dict(
            chain_id=HIVE_CHAIN_ID,
            ref_block_num=12345,
            ref_block_prefix=67890,
            expiration=1700000000,
        )
        with self.assertRaises(CallException) as ctx:
            hive.sign_account_create(
                self.client, address_n=hive_path(ROLE_ACTIVE),
                creator="kksponsor", new_account_name="kktestacct",
                fee_amount=3000, owner_key=keys.owner_key,
                active_key=keys.active_key, posting_key=keys.posting_key,
                memo_key=keys.memo_key, **tx_kw)
        self.assertIn("Invalid Hive SLIP-0048 path", str(ctx.exception))
        with self.assertRaises(CallException) as ctx:
            hive.sign_account_update(
                self.client, address_n=hive_path(ROLE_ACTIVE),
                account="kktestacct", new_owner_key=keys.owner_key,
                new_active_key=keys.active_key,
                new_posting_key=keys.posting_key,
                new_memo_key=keys.memo_key, **tx_kw)
        self.assertIn("Invalid Hive SLIP-0048 path", str(ctx.exception))

    def test_hive_sign_transfer_rejects_long_memo(self):
        """Memo over the 440-byte serialization limit must fail with a
        specific error, not a generic signing failure."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignTx")
        self.setup_mnemonic_nopin_nopassphrase()
        self._assert_sign_tx_fails("memo too long", memo="x" * 441)

    def test_hive_sign_transfer_max_memo_ok(self):
        """A memo of exactly 440 bytes still signs (boundary check)."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignTx")
        self.setup_mnemonic_nopin_nopassphrase()
        active = hive.get_public_key(self.client, hive_path(ROLE_ACTIVE), show_display=False)
        resp = hive.sign_tx(self.client, **self._transfer_kwargs(memo="x" * 440))
        self.assertEqual(len(resp.signature), 65)
        self.assertEqual(recover_compressed(resp.serialized_tx, resp.signature), active.raw_public_key)


    # ── Message signing (Keychain signBuffer contract) ────────────────────

    def _recover_message_signer(self, message, sig65):
        """Recover the compressed signer pubkey from a HiveSignedMessage.

        The signBuffer contract: digest = SHA256(message bytes) ONLY — no
        chain_id prepend (unlike transactions), no message prefix. This
        recovery is exactly what a Hive dApp does to verify a login.
        """
        # NB: common.KeepKeyTest overrides assertEqual without the msg param.
        self.assertEqual(len(sig65), 65)
        recid = sig65[0] - 31
        self.assertTrue(0 <= recid <= 3, "unexpected recovery header byte %d" % sig65[0])
        digest = hashlib.sha256(message).digest()
        candidates = VerifyingKey.from_public_key_recovery_with_digest(
            sig65[1:], digest, SECP256k1, hashfunc=hashlib.sha256,
            sigdecode=sigdecode_string
        )
        return candidates[recid].to_string("compressed")

    def test_hive_sign_message_posting(self):
        """dApp login: a posting-key signBuffer signature recovers to the
        posting key — both against the response public_key and against an
        independently derived HiveGetPublicKey for the same path."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignMessage")
        self.setup_mnemonic_nopin_nopassphrase()

        challenge = b'{"login":"skatehive","ts":1700000000,"nonce":"abc123"}'
        posting = hive.get_public_key(self.client, hive_path(ROLE_POSTING), show_display=False)
        resp = hive.sign_message(self.client, hive_path(ROLE_POSTING), challenge)

        self.assertEqual(len(resp.signature), 65)
        self.assertEqual(len(resp.public_key), 33)
        self.assertEqual(resp.public_key, posting.raw_public_key)
        self.assertEqual(self._recover_message_signer(challenge, resp.signature),
                         posting.raw_public_key)

    def test_hive_sign_message_all_roles(self):
        """The three Keychain-exposed roles (Posting/Active/Memo) may sign;
        each signature recovers to that role's key and to no other's.
        owner' is rejected — see test_hive_sign_message_rejects_bad_paths."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignMessage")
        self.setup_mnemonic_nopin_nopassphrase()

        message = b"kk role check"
        seen = set()
        for role in (ROLE_ACTIVE, ROLE_MEMO, ROLE_POSTING):
            expected = hive.get_public_key(self.client, hive_path(role), show_display=False)
            resp = hive.sign_message(self.client, hive_path(role), message)
            self.assertEqual(resp.public_key, expected.raw_public_key)
            self.assertEqual(self._recover_message_signer(message, resp.signature),
                             expected.raw_public_key)
            seen.add(resp.public_key)
        self.assertEqual(len(seen), 3)  # role keys must be distinct

    def test_hive_sign_message_nonprintable_bytes(self):
        """Non-printable buffers are REFUSED. A Hive transaction digest is
        SHA256(chain_id || serialized_tx) over binary bytes, so a binary
        "message" equal to C || tx would hash to a valid transaction signature
        on any fork chain C. Restricting signable messages to printable ASCII
        keeps them in a domain disjoint from every transaction preimage, closing
        that cross-chain message->transaction signature oracle."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignMessage")
        self.setup_mnemonic_nopin_nopassphrase()

        from keepkeylib.client import CallException
        message = bytes(range(0, 48))  # non-printable bytes
        with self.assertRaises(CallException) as ctx:
            hive.sign_message(self.client, hive_path(ROLE_POSTING), message)
        self.assertIn("printable", str(ctx.exception))

    def test_hive_sign_message_long_printable_ok(self):
        """Printable text over the 128-byte display budget still signs — it
        routes through the hex-preview confirm (never silently truncated
        text), and the signature covers every byte."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignMessage")
        self.setup_mnemonic_nopin_nopassphrase()

        message = (b"benign preamble. " * 20)[:300]  # printable, > 128 bytes
        posting = hive.get_public_key(self.client, hive_path(ROLE_POSTING), show_display=False)
        resp = hive.sign_message(self.client, hive_path(ROLE_POSTING), message)
        self.assertEqual(self._recover_message_signer(message, resp.signature),
                         posting.raw_public_key)

    def test_hive_sign_message_max_length_ok(self):
        """A message of exactly 1024 bytes (the proto cap) still signs."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignMessage")
        self.setup_mnemonic_nopin_nopassphrase()

        message = b"x" * 1024
        posting = hive.get_public_key(self.client, hive_path(ROLE_POSTING), show_display=False)
        resp = hive.sign_message(self.client, hive_path(ROLE_POSTING), message)
        self.assertEqual(self._recover_message_signer(message, resp.signature),
                         posting.raw_public_key)

    def test_hive_sign_message_rejects_oversize(self):
        """1025 bytes must fail (nanopb max_size cap — the proto and handler
        agree on 1024)."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignMessage")
        self.setup_mnemonic_nopin_nopassphrase()
        from keepkeylib.client import CallException
        with self.assertRaises(CallException):
            hive.sign_message(self.client, hive_path(ROLE_POSTING), b"x" * 1025)

    def test_hive_sign_message_rejects_bad_paths(self):
        """Foreign trees, wrong network index, and unassigned roles must all
        be rejected — same fence as the transaction handlers."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignMessage")
        self.setup_mnemonic_nopin_nopassphrase()
        from keepkeylib.client import CallException
        h = 0x80000000
        bad_paths = [
            parse_path("m/44'/0'/0'/0/0"),          # BIP-44 BTC
            [h + 48, h + 3054, h + ROLE_POSTING, h, h],  # registry 3054', not 13'
            hive_path(2),                             # unassigned role 2'
            hive_path(ROLE_OWNER),                    # owner' not a Keychain signBuffer role
            [h + 48, h + 13, h + ROLE_POSTING, h],    # short path
        ]
        for path in bad_paths:
            with self.assertRaises(CallException) as ctx:
                hive.sign_message(self.client, path, b"login challenge")
            self.assertIn("Invalid Hive SLIP-0048 path", str(ctx.exception))

    # ── Operations signing (HiveSignOperations — parsed generic ops) ──────
    # The test builds transactions byte-exactly with its OWN serializer
    # (below, module level) — never firmware-emitted bytes — so a parser bug
    # and a serializer bug cannot cancel out.

    def _recover_ops_signer(self, tx, sig65):
        """digest = SHA256(chain_id || serialized_tx), same as transfers."""
        self.assertEqual(len(sig65), 65)
        recid = sig65[0] - 31
        self.assertTrue(0 <= recid <= 3, "unexpected recovery header byte %d" % sig65[0])
        digest = hashlib.sha256(HIVE_CHAIN_ID + tx).digest()
        candidates = VerifyingKey.from_public_key_recovery_with_digest(
            sig65[1:], digest, SECP256k1, hashfunc=hashlib.sha256,
            sigdecode=sigdecode_string
        )
        return candidates[recid].to_string("compressed")

    def test_hive_sign_ops_vote(self):
        """A vote tx signs with the posting key and recovers to it."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        tx = _ops_tx([_op_vote("kkvoter", "someauthor", "cool-post-permlink", 10000)])
        posting = hive.get_public_key(self.client, hive_path(ROLE_POSTING), show_display=False)
        resp = hive.sign_operations(self.client, hive_path(ROLE_POSTING), tx, chain_id=HIVE_CHAIN_ID)
        self.assertEqual(self._recover_ops_signer(tx, resp.signature), posting.raw_public_key)

    def test_hive_sign_ops_downvote_and_default_chain_id(self):
        """Negative weight (downvote) signs; omitted chain_id defaults to
        mainnet in firmware — recovery against the mainnet id proves it."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        tx = _ops_tx([_op_vote("kkvoter", "spammer", "bad-post", -10000)])
        posting = hive.get_public_key(self.client, hive_path(ROLE_POSTING), show_display=False)
        resp = hive.sign_operations(self.client, hive_path(ROLE_POSTING), tx)  # no chain_id
        self.assertEqual(self._recover_ops_signer(tx, resp.signature), posting.raw_public_key)

    def test_hive_sign_ops_comment(self):
        """A top-level post (empty parent_author) with a unicode body signs —
        the body routes through the non-ASCII display fallback."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        body = "skate clip of the day — hardflip".encode("utf-8")
        tx = _ops_tx([_op_comment("", "hive-173115", "kkauthor",
                                  "my-first-post", "My first post", body, "{}")])
        posting = hive.get_public_key(self.client, hive_path(ROLE_POSTING), show_display=False)
        resp = hive.sign_operations(self.client, hive_path(ROLE_POSTING), tx, chain_id=HIVE_CHAIN_ID)
        self.assertEqual(self._recover_ops_signer(tx, resp.signature), posting.raw_public_key)

    def test_hive_sign_ops_custom_json_posting(self):
        """custom_json with posting auths (Hive Engine style) signs with the
        posting key."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        tx = _ops_tx([_op_custom_json([], ["kkplayer"], "ssc-mainnet-hive",
                                      '{"contractName":"tokens","contractAction":"transfer"}')])
        posting = hive.get_public_key(self.client, hive_path(ROLE_POSTING), show_display=False)
        resp = hive.sign_operations(self.client, hive_path(ROLE_POSTING), tx, chain_id=HIVE_CHAIN_ID)
        self.assertEqual(self._recover_ops_signer(tx, resp.signature), posting.raw_public_key)

    def test_hive_sign_ops_custom_json_active(self):
        """custom_json with required_auths (active tier) must sign with the
        ACTIVE key — and does."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        tx = _ops_tx([_op_custom_json(["kkadmin"], [], "witness-ops", '{"op":"x"}')])
        active = hive.get_public_key(self.client, hive_path(ROLE_ACTIVE), show_display=False)
        resp = hive.sign_operations(self.client, hive_path(ROLE_ACTIVE), tx, chain_id=HIVE_CHAIN_ID)
        self.assertEqual(self._recover_ops_signer(tx, resp.signature), active.raw_public_key)

    def _assert_ops_fails(self, fragment, tx, path=None):
        from keepkeylib.client import CallException
        with self.assertRaises(CallException) as ctx:
            hive.sign_operations(self.client, path or hive_path(ROLE_POSTING),
                                 tx, chain_id=HIVE_CHAIN_ID)
        if fragment:
            self.assertIn(fragment, str(ctx.exception))

    def test_hive_sign_ops_rejects_excluded_and_unknown_ops(self):
        """Op types 2/9/10 are PERMANENTLY excluded (dedicated messages keep
        their stronger invariants); unknown types reject too. The parser
        refuses on the op-type byte, so the bodies never matter."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()
        for op_type in (2, 9, 10):
            self._assert_ops_fails("dedicated message",
                                   _ops_tx([_varint(op_type)]))
        # 49 = recurrent_transfer: a real Hive op deliberately kept out of the
        # table. (This previously used op 3, mislabelled "comment_options";
        # op 3 is transfer_to_vesting and is now clear-signed, so it no longer
        # exercises the unknown-op path.)
        self._assert_ops_fails("unsupported operation",
                               _ops_tx([_varint(49)]))

    def test_hive_sign_ops_rejects_malformed_structure(self):
        """Zero ops, >4 ops, nonzero extensions, trailing bytes, overlong
        varint, out-of-range weight — each refused with a specific error."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        vote = _op_vote("kkvoter", "author", "permlink", 100)
        self._assert_ops_fails("op count", _ops_tx([], opcount=0))
        self._assert_ops_fails("op count", _ops_tx([vote] * 5))
        self._assert_ops_fails("extensions must be empty",
                               _ops_tx([vote], ext=b"\x01"))
        self._assert_ops_fails("trailing bytes", _ops_tx([vote]) + b"\x00")
        # op_count as an overlong 6-byte varint encoding of 1
        head = struct.pack("<HII", 12345, 67890, 1700000000)
        self._assert_ops_fails("malformed operation",
                               head + b"\x81\x80\x80\x80\x80\x00" + vote + b"\x00")
        self._assert_ops_fails("value out of range",
                               _ops_tx([_op_vote("kkvoter", "author", "permlink", 10001)]))

    def test_hive_sign_ops_role_fences(self):
        """Posting-tier tx on the active/memo/owner path rejects; active-tier
        custom_json on the posting path rejects; mixed-tier tx and
        both-auths custom_json reject as malformed."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        vote_tx = _ops_tx([_op_vote("kkvoter", "author", "permlink", 100)])
        for role in (ROLE_ACTIVE, ROLE_MEMO, ROLE_OWNER):
            self._assert_ops_fails("needs posting", vote_tx, path=hive_path(role))

        active_cj = _ops_tx([_op_custom_json(["kkadmin"], [], "witness-ops", '{"a":1}')])
        self._assert_ops_fails("needs active", active_cj, path=hive_path(ROLE_POSTING))

        mixed = _ops_tx([
            _op_vote("kkvoter", "author", "permlink", 100),
            _op_custom_json(["kkadmin"], [], "witness-ops", '{"a":1}'),
        ])
        self._assert_ops_fails("mixed posting/active", mixed, path=hive_path(ROLE_ACTIVE))

        both_auths = _ops_tx([_op_custom_json(["kkadmin"], ["kkplayer"], "x-id", '{"a":1}')])
        self._assert_ops_fails("mixed posting/active", both_auths,
                               path=hive_path(ROLE_ACTIVE))

    def test_hive_sign_ops_rejects_oversize(self):
        """A tx over the 2048-byte proto cap fails at decode."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()
        big_body = b"x" * 2100
        tx = _ops_tx([_op_comment("", "cat", "kkauthor", "perm", "", big_body, "")])
        self.assertTrue(len(tx) > 2048)
        from keepkeylib.client import CallException
        with self.assertRaises(CallException):
            hive.sign_operations(self.client, hive_path(ROLE_POSTING), tx,
                                 chain_id=HIVE_CHAIN_ID)

    # ── Phase-3 op table ─────────────────────────────────────────────────
    # Every tx below is built by THIS file's serializer, never by firmware, so
    # a parser bug and a serializer bug cannot cancel out.

    def _ops_signs_with(self, tx, role):
        """Sign tx with `role` and assert the signature recovers to that key."""
        key = hive.get_public_key(self.client, hive_path(role), show_display=False)
        resp = hive.sign_operations(self.client, hive_path(role), tx,
                                    chain_id=HIVE_CHAIN_ID)
        self.assertEqual(self._recover_ops_signer(tx, resp.signature),
                         key.raw_public_key)

    def test_hive_sign_ops_limit_order_create(self):
        """The op that motivated phase 3: a HIVE->HBD internal-market swap.
        Active tier, since it moves funds."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        tx = _ops_tx([_op_limit_order_create("kktrader", 42, 1500, "HIVE",
                                             400, "HBD", True, 1700003600)])
        self._ops_signs_with(tx, ROLE_ACTIVE)

    def test_hive_sign_ops_limit_order_cancel(self):
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        self._ops_signs_with(_ops_tx([_op_limit_order_cancel("kktrader", 42)]),
                             ROLE_ACTIVE)

    def test_hive_sign_ops_active_tier_value_ops(self):
        """The active-tier ops that move or lock value all sign with active."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        for op in (
            _op_transfer_to_vesting("kkuser", "kkuser", 1000),
            _op_convert("kkuser", 7, 2500),
            _op_transfer_to_savings("kkuser", "kkfriend", 1500, "HBD", "rent"),
            _op_transfer_from_savings("kkuser", 7, "kkfriend", 1500, "HIVE"),
            _op_delegate_vesting_shares("kkuser", "kkfriend", 1000000),
            _op_withdraw_vesting("kkuser", 5000000),
        ):
            self._ops_signs_with(_ops_tx([op]), ROLE_ACTIVE)

    def test_hive_sign_ops_posting_tier_ops(self):
        """claim_reward_balance is posting tier — claiming is not spending."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        tx = _ops_tx([_op_claim_reward_balance("kkuser", 1234, 5678, 90123456)])
        self._ops_signs_with(tx, ROLE_POSTING)

    def test_hive_sign_ops_zero_amount_semantics(self):
        """Zero means something for these two and nothing for the rest, so the
        parser must not apply one blanket rule."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        # 0 VESTS withdraw_vesting cancels an in-progress power-down.
        self._ops_signs_with(_ops_tx([_op_withdraw_vesting("kkuser", 0)]),
                             ROLE_ACTIVE)
        # 0 VESTS delegation removes an existing delegation.
        self._ops_signs_with(
            _ops_tx([_op_delegate_vesting_shares("kkuser", "kkfriend", 0)]),
            ROLE_ACTIVE)
        # A zero power-up, by contrast, does nothing and is refused.
        self._assert_ops_fails("amount must be greater than zero",
                               _ops_tx([_op_transfer_to_vesting("kkuser", "kkuser", 0)]),
                               path=hive_path(ROLE_ACTIVE))
        # Nothing to claim.
        self._assert_ops_fails("no effect",
                               _ops_tx([_op_claim_reward_balance("kkuser", 0, 0, 0)]))

    def test_hive_sign_ops_asset_symbol_and_precision_pinned(self):
        """A swapped symbol hides a ~2000x value difference behind an
        identical-looking number; a wrong precision moves the decimal point
        relative to what the chain applies. Both must be refused."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()
        active = hive_path(ROLE_ACTIVE)

        # transfer_to_vesting is HIVE-only.
        wrong_symbol = (_varint(3) + _string("kkuser") + _string("kkuser") +
                        _asset(1000, "HBD"))
        self._assert_ops_fails("malformed operation", _ops_tx([wrong_symbol]),
                               path=active)
        # Right symbol, wrong precision.
        wrong_precision = (_varint(3) + _string("kkuser") + _string("kkuser") +
                           _asset_raw(1000, 6, "HIVE"))
        self._assert_ops_fails("malformed operation", _ops_tx([wrong_precision]),
                               path=active)
        # Negative int64 would render as an enormous positive amount.
        negative = (_varint(3) + _string("kkuser") + _string("kkuser") +
                    _asset_raw(-1000, 3, "HIVE"))
        self._assert_ops_fails("malformed operation", _ops_tx([negative]),
                               path=active)
        # An order priced VESTS-for-HBD is not a market that exists.
        vests_order = (_varint(5) + _string("kktrader") + struct.pack("<I", 1) +
                       _asset(100, "VESTS") + _asset(100, "HBD") +
                       bytes([0]) + struct.pack("<I", 1))
        self._assert_ops_fails("malformed operation", _ops_tx([vests_order]),
                               path=active)
        # Same symbol on both sides of an order is a no-op trade that still fills.
        same_symbol = _op_limit_order_create("kktrader", 1, 100, "HIVE",
                                             100, "HIVE", False, 1)
        self._assert_ops_fails("symbols must differ", _ops_tx([same_symbol]),
                               path=active)

    def test_hive_sign_ops_comment_options_binds_to_its_comment(self):
        """comment_options redirects a post's payout. Detached from its
        comment it could retarget a post published earlier that the user is
        not reviewing on screen, so firmware requires it to follow one with a
        matching author and permlink."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        comment = _op_comment("", "hive-100", "kkauthor", "my-post",
                              "Title", b"Body", "{}")
        options = _op_comment_options("kkauthor", "my-post", 1000000, 10000)

        # Standing alone: refused.
        self._assert_ops_fails("must follow its comment", _ops_tx([options]))
        # Following a comment for a DIFFERENT post: refused.
        other = _op_comment_options("kkauthor", "other-post", 1000000, 10000)
        self._assert_ops_fails("must follow its comment",
                               _ops_tx([comment, other]))
        # Correctly paired, with beneficiaries: signs on the posting key.
        paired = _ops_tx([comment, _op_comment_options(
            "kkauthor", "my-post", 1000000, 10000,
            beneficiaries=[("aaron", 1000), ("zoe", 500)])])
        self._ops_signs_with(paired, ROLE_POSTING)

    def test_hive_sign_ops_comment_options_beneficiary_rules(self):
        """hived requires strictly ascending, unique beneficiaries summing to
        <= 100%; signing anything else only wastes a device confirmation."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        comment = _op_comment("", "hive-100", "kkauthor", "my-post",
                              "Title", b"Body", "{}")
        for bens in ([("zoe", 500), ("aaron", 1000)],      # unsorted
                     [("aaron", 500), ("aaron", 500)],     # duplicate
                     [("aaron", 6000), ("zoe", 5000)]):    # > 100%
            tx = _ops_tx([comment, _op_comment_options(
                "kkauthor", "my-post", 1000000, 10000, beneficiaries=bens)])
            self._assert_ops_fails("beneficiaries", tx)

    def test_hive_sign_ops_account_update2_rejects_authority_change(self):
        """account_update2 can rotate account keys. Only the profile-metadata
        form is in the table — the same device-derived-keys invariant that
        keeps ops 9/10 out, applied field-level."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        self._assert_ops_fails(
            "authority changes",
            _ops_tx([_op_account_update2("kkuser", '{"profile":{}}', "",
                                         authority_present=True)]),
            path=hive_path(ROLE_ACTIVE))

        # json_metadata is an active-key field...
        self._ops_signs_with(
            _ops_tx([_op_account_update2("kkuser", '{"profile":{}}', "")]),
            ROLE_ACTIVE)
        # ...while a posting-metadata-only profile edit stays posting tier.
        self._ops_signs_with(
            _ops_tx([_op_account_update2("kkuser", "", '{"profile":{}}')]),
            ROLE_POSTING)

    def test_hive_sign_ops_truncated_bodies_rejected(self):
        """The signature covers the whole buffer, so a short read would mean
        signing bytes the device never displayed. Every truncation must be
        refused rather than partially parsed."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignOperations")
        self.setup_mnemonic_nopin_nopassphrase()

        for op in (_op_limit_order_create("kktrader", 1, 100, "HIVE", 50,
                                          "HBD", False, 9),
                   _op_claim_reward_balance("kkuser", 1, 1, 1),
                   _op_transfer_from_savings("kkuser", 7, "kkfriend", 1500,
                                             "HBD", "memo")):
            # One byte short is the boundary case; a deeper cut exercises the
            # length-prefixed string readers.
            for cut in (1, 5):
                if cut >= len(op):
                    continue
                self._assert_ops_fails(None, _ops_tx([op[:-cut]]),
                                       path=hive_path(ROLE_ACTIVE))

    def test_hive_sign_message_rejects_chain_id_prefix(self):
        """A 'message' that begins with the mainnet chain id would hash to a
        broadcastable TRANSACTION digest (tx digest = SHA256(chain_id || tx)).
        The firmware must refuse the collision."""
        self.requires_firmware("7.15.0")
        self.requires_message("HiveSignMessage")
        self.setup_mnemonic_nopin_nopassphrase()
        from keepkeylib.client import CallException
        disguised_tx = HIVE_CHAIN_ID + b"\x39\x30" + b"\x00" * 40
        with self.assertRaises(CallException) as ctx:
            hive.sign_message(self.client, hive_path(ROLE_ACTIVE), disguised_tx)
        self.assertIn("chain ID", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
