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

HIVE_OP_TRANSFER = 2
HIVE_OP_ACCOUNT_CREATE = 9
HIVE_OP_ACCOUNT_UPDATE = 10


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


if __name__ == "__main__":
    unittest.main()
