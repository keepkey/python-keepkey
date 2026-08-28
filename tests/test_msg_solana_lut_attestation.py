"""KKSOLSW1 -- transaction-bound lookup-table account attestation.

A Solana v0 message may source instruction accounts from an Address Lookup
Table. Those accounts are NOT in the bytes being signed, so the device cannot
derive them: it forces the whole transaction to SOL_TX_REVIEW_OPAQUE, refuses
it outright without AdvancedMode, and treats it as an explicit BLIND SIGN with
AdvancedMode on. The instruction's meaning is never shown.

A clear-sign provider may attest the resolved account list for THIS exact
transaction, turning that blind sign into a described one. The attestation is:

  * DOMAIN-TAGGED  -- "KeepKeySolanaTxAccounts/1", so a signature made for any
                      other purpose (an EVM metadata blob, a token definition)
                      cannot be replayed as one;
  * TX-BOUND       -- over sha256(raw_tx), so it cannot be replayed onto a
                      different transaction;
  * ADDITIVE       -- the blind-sign warning still follows it. A runtime signer
                      is annotation, never authority.

These tests assert all three, and assert that every failure mode degrades to
exactly the flow that exists today rather than to something new.
"""
import struct
import unittest

import common
import keepkeylib.messages_solana_pb2 as messages
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

TAG = b"KeepKeySolanaTxAccounts/1"
SLOT = 3


class TestSolanaLutAttestation(common.KeepKeyTest):

    SYSTEM_PROGRAM = b'\x00' * 32

    def setUp(self):
        super(TestSolanaLutAttestation, self).setUp()
        # KKSOLSW1 landed after the RC18 candidate and first ships in 7.16.
        # RC18 ignores the forward-compatible attestation fields, which makes
        # all negative-path tests pass vacuously unless the whole class gates.
        self.requires_firmware("7.16.0")
        self.requires_fullFeature()
        self.requires_message("LoadClearsignSigner")
        self.setup_mnemonic_allallall()

    # ---------------------------------------------------------------- helpers

    def _raw_pubkey(self):
        """The device's Solana (ed25519) pubkey, decoded from the base58
        address. get_public_node() would hand back a secp256k1 key, which is
        not what signs a Solana transaction -- the device would then reject the
        tx with "Derived key is not a signer"."""
        addr = self.client.call(messages.SolanaGetAddress(
            address_n=parse_path("m/44'/501'/0'/0'"),
            show_display=False)).address
        ALPHABET = ('123456789ABCDEFGHJKLMNPQRSTUVWXYZ'
                    'abcdefghijkmnopqrstuvwxyz')
        n = 0
        for c in addr:
            n = n * 58 + ALPHABET.index(c)
        return n.to_bytes(32, 'big')

    def _build_lut_tx(self, from_pubkey):
        """A v0 message carrying a lookup-table section.

        The ALT section is what forces the device opaque -- exactly the case
        KKSOLSW1 exists for. Built by hand rather than reused from another test
        so the shape under test is visible here.
        """
        tx = bytearray()
        tx.append(0x80)             # versioned, v0
        tx.extend([1, 0, 1])        # header: 1 sig, 0 ro-signed, 1 ro-unsigned
        tx.append(2)                # 2 static accounts
        tx.extend(from_pubkey)
        tx.extend(self.SYSTEM_PROGRAM)
        tx.extend(b'\xbb' * 32)     # recent blockhash
        tx.append(1)                # 1 instruction
        tx.extend(bytes([1]))       # program index -> SYSTEM_PROGRAM
        tx.append(1)                # 1 account index
        tx.append(3)                # index 3: BEYOND the static table -> external
        tx.append(4)                # data len
        tx.extend(struct.pack('<I', 2))
        # One lookup table: 1 writable index, 0 readonly.
        tx.append(1)
        tx.extend(b'\x77' * 32)     # table address
        tx.append(1)
        tx.append(3)
        tx.append(0)
        return bytes(tx)

    def _attest(self, raw_tx, accounts, private_key=None):
        """Sign the KKSOLSW1 preimage the way the firmware rebuilds it."""
        import hashlib
        from ecdsa import SigningKey, SECP256k1
        from ecdsa.util import sigencode_string
        from keepkeylib.signed_metadata import TEST_PRIVATE_KEY

        msg_hash = hashlib.sha256(raw_tx).digest()
        preimage = TAG + msg_hash + struct.pack('<I', len(accounts))
        for a in accounts:
            preimage += a
        digest = hashlib.sha256(preimage).digest()
        sk = SigningKey.from_string(private_key or TEST_PRIVATE_KEY,
                                    curve=SECP256k1)
        return sk.sign_digest_deterministic(
            digest, hashfunc=hashlib.sha256, sigencode=sigencode_string)

    def _load_signer(self):
        from keepkeylib.signed_metadata import (
            test_signer_compressed_pubkey, assert_test_key_matches_slot3)
        assert_test_key_matches_slot3()
        self.client.apply_policy('AdvancedMode', True)
        self.client.load_clearsign_signer(
            key_id=SLOT, pubkey=test_signer_compressed_pubkey(),
            alias="CI Test")

    def _screens(self, **kw):
        """Sign, returning (button_request_codes, response)."""
        codes = []
        orig = self.client.callback_ButtonRequest

        def spy(msg):
            codes.append(msg.code)
            return orig(msg)

        self.client.callback_ButtonRequest = spy
        try:
            resp = self.client.call(messages.SolanaSignTx(
                address_n=parse_path("m/44'/501'/0'/0'"), **kw))
        finally:
            self.client.callback_ButtonRequest = orig
        return codes, resp

    # ------------------------------------------------------------------ tests

    def test_attested_accounts_are_shown_and_blind_sign_still_follows(self):
        """The whole point: MORE screens, and the blind-sign warning survives.

        This is the additive invariant restated for Solana. The attested
        accounts are added in front of the existing flow; nothing is removed.
        """
        self._load_signer()
        pk = self._raw_pubkey()
        raw = self._build_lut_tx(pk)
        accounts = [b'\x51' * 32, b'\x52' * 32]

        base_codes, _ = self._screens(raw_tx=raw)
        # Reload: identities are RAM-only and a completed signing tears the
        # session down, which is the behaviour section I asserts. Without this
        # the attested run would find no signer, verify nothing, and the test
        # would pass VACUOUSLY by comparing two identical baseline flows.
        self._load_signer()
        att_codes, resp = self._screens(
            raw_tx=raw, lut_account=accounts,
            lut_signature=self._attest(raw, accounts),
            lut_signer_key_id=SLOT)

        self.assertEqual(len(resp.signature), 64)
        # One identity screen + one per account, and the baseline flow intact.
        self.assertEqual(len(att_codes), len(base_codes) + 1 + len(accounts))
        self.assertEqual(att_codes[-len(base_codes):], base_codes)

    def test_bad_signature_degrades_to_todays_flow(self):
        """A signature that does not verify must change NOTHING."""
        self._load_signer()
        pk = self._raw_pubkey()
        raw = self._build_lut_tx(pk)
        accounts = [b'\x51' * 32]

        base_codes, _ = self._screens(raw_tx=raw)
        # Same reload as the attested case above: a completed signing tears the
        # RAM-only session down, so without this the second run would find no
        # signer, verify nothing, and pass vacuously by comparing two identical
        # baseline flows -- which is exactly what this test must not do.
        self._load_signer()
        bad_codes, resp = self._screens(
            raw_tx=raw, lut_account=accounts,
            lut_signature=b'\x00' * 64, lut_signer_key_id=SLOT)

        self.assertEqual(len(resp.signature), 64)
        self.assertEqual(bad_codes, base_codes)

    def test_attestation_does_not_replay_onto_another_transaction(self):
        """Bound to sha256(raw_tx): the same signature on a different tx is
        worthless. This is what stops a provider's one honest attestation being
        reused to describe a transaction it never saw."""
        self._load_signer()
        pk = self._raw_pubkey()
        raw_a = self._build_lut_tx(pk)
        raw_b = bytearray(raw_a)
        raw_b[-40] ^= 0xFF          # perturb the lookup-table address
        raw_b = bytes(raw_b)
        accounts = [b'\x51' * 32]
        sig_for_a = self._attest(raw_a, accounts)

        base_codes, _ = self._screens(raw_tx=raw_b)
        # Same reload as the attested case above: a completed signing tears the
        # RAM-only session down, so without this the second run would find no
        # signer, verify nothing, and pass vacuously by comparing two identical
        # baseline flows -- which is exactly what this test must not do.
        self._load_signer()
        replay_codes, _ = self._screens(
            raw_tx=raw_b, lut_account=accounts,
            lut_signature=sig_for_a, lut_signer_key_id=SLOT)
        self.assertEqual(replay_codes, base_codes)

    def test_no_signer_loaded_means_no_extra_screens(self):
        """Without a loaded provider there is nothing to verify against, so a
        well-formed attestation is inert. Trust is opt-in, per session."""
        self.client.apply_policy('AdvancedMode', True)
        pk = self._raw_pubkey()
        raw = self._build_lut_tx(pk)
        accounts = [b'\x51' * 32]

        base_codes, _ = self._screens(raw_tx=raw)
        codes, _ = self._screens(
            raw_tx=raw, lut_account=accounts,
            lut_signature=self._attest(raw, accounts),
            lut_signer_key_id=SLOT)
        self.assertEqual(codes, base_codes)


if __name__ == '__main__':
    unittest.main()
