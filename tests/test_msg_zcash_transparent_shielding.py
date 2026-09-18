"""Device tests for Zcash transparent-to-Orchard shielding.

The original alpha tests exercised the first draft of this protocol. That
draft accepted a host-provided transparent sighash and returned one signature
immediately after each input. The shipping protocol is intentionally stricter:
the device reconstructs ZIP-244/229 digests from streamed transaction data and
withholds every transparent signature until the Orchard digest and fee pass.

These tests preserve the original security assertions against that final wire
contract. The digest implementation below is independent of the client and
matches ZIP-244 section 4.10b, so a host/client regression cannot make an
incorrect device signature appear valid.
"""

import hashlib
import unittest

import ecdsa
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der

import common
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_zcash_pb2 as zcash_proto

from test_msg_zcash_sign_pczt_device import (
    CMX_ORCHARD,
    VALUE,
    bundle_digest,
    note_action,
    sign_kwargs,
)


H = 0x80000000
ZEC_PATH = [H + 44, H + 133, H, 0, 0]
P2PKH_SCRIPT = b'\x76\xa9\x14' + b'\x23' * 20 + b'\x88\xac'
EMPTY_SAPLING_DIGEST = hashlib.blake2b(
    b'', digest_size=32, person=b'ZTxIdSaplingHash').digest()


def _b2b(person, data):
    return hashlib.blake2b(data, digest_size=32, person=person).digest()


def _compact_size(value):
    if value < 253:
        return bytes([value])
    if value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    if value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    return b'\xff' + value.to_bytes(8, 'little')


def _prevouts_digest(inputs):
    data = b''.join(
        item['prevout_txid'] + item['prevout_index'].to_bytes(4, 'little')
        for item in inputs)
    return _b2b(b'ZTxIdPrevoutHash', data)


def _amounts_digest(inputs):
    data = b''.join(item['amount'].to_bytes(8, 'little') for item in inputs)
    return _b2b(b'ZTxTrAmountsHash', data)


def _scripts_digest(inputs):
    data = b''.join(
        _compact_size(len(item['script_pubkey'])) + item['script_pubkey']
        for item in inputs)
    return _b2b(b'ZTxTrScriptsHash', data)


def _sequences_digest(inputs):
    data = b''.join(item['sequence'].to_bytes(4, 'little') for item in inputs)
    return _b2b(b'ZTxIdSequencHash', data)


def _outputs_digest(outputs):
    data = b''.join(
        item['amount'].to_bytes(8, 'little') +
        _compact_size(len(item['script_pubkey'])) + item['script_pubkey']
        for item in outputs)
    return _b2b(b'ZTxIdOutputsHash', data)


def _txin_digest(item):
    data = (
        item['prevout_txid'] +
        item['prevout_index'].to_bytes(4, 'little') +
        item['amount'].to_bytes(8, 'little') +
        _compact_size(len(item['script_pubkey'])) +
        item['script_pubkey'] +
        item['sequence'].to_bytes(4, 'little'))
    return _b2b(b'Zcash___TxInHash', data)


def _transparent_sig_digest(inputs, outputs, input_index=None):
    """Return ZIP-244 S.2 transparent_sig_digest.

    Orchard authorization uses an empty txin digest. A transparent ECDSA
    signature replaces it with the digest for the specific signed input.
    """
    txin = (_b2b(b'Zcash___TxInHash', b'') if input_index is None
            else _txin_digest(inputs[input_index]))
    data = (
        b'\x01' +
        _prevouts_digest(inputs) +
        _amounts_digest(inputs) +
        _scripts_digest(inputs) +
        _sequences_digest(inputs) +
        _outputs_digest(outputs) +
        txin)
    return _b2b(b'ZTxIdTranspaHash', data)


class TestZcashTransparentShielding(common.KeepKeyTest):
    """Transparent signing must stay bound to reviewed transaction data."""

    def setUp(self):
        super().setUp()
        # Bitcoin-only builds have no Zcash (KK_ZCASH_PRIVACY OFF); the device
        # correctly answers "Unknown message". skipTest in setUp bypasses
        # tearDown, so close the transport via a cleanup instead.
        if self.client.features.firmware_variant in ("KeepKeyBTC", "EmulatorBTC"):
            self.addCleanup(self.client.close)
            self.skipTest("Zcash is not in the bitcoin-only firmware")

    def _make_transparent_input(self, index=0, address_n=None, amount=VALUE):
        return {
            'index': index,
            'address_n': address_n or ZEC_PATH,
            'amount': amount,
            'prevout_txid': hashlib.sha256(
                b'python-keepkey transparent input ' + bytes([index])).digest(),
            'prevout_index': index,
            'sequence': 0xffffffff,
            'script_pubkey': P2PKH_SCRIPT,
        }

    def _get_pubkey_for_path(self, path):
        response = self.client.get_public_node(path, coin_name='Zcash')
        return bytes(response.node.public_key)

    def _verify_der_signature(self, pubkey, digest, signature):
        key = VerifyingKey.from_string(pubkey, curve=SECP256k1)
        try:
            return key.verify_digest(signature, digest,
                                     sigdecode=sigdecode_der)
        except ecdsa.BadSignatureError:
            return False

    def _sign(self, transparent_inputs):
        action = note_action(CMX_ORCHARD)
        kwargs = sign_kwargs([action])
        value_balance = -VALUE
        kwargs.update({
            'total_amount': VALUE,
            'fee': 0,
            'orchard_value_balance': value_balance,
            'orchard_digest': bundle_digest(
                [action], False, kwargs['tx_version'],
                value_balance=value_balance),
            'transparent_digest': _transparent_sig_digest(
                transparent_inputs, [], input_index=None),
            'transparent_inputs': transparent_inputs,
            'return_transparent_signatures': True,
        })
        response, signatures = self.client.zcash_sign_pczt(**kwargs)
        return response, signatures, kwargs

    def _assert_signature(self, signature, pubkey, kwargs, inputs, index):
        transparent_digest = _transparent_sig_digest(inputs, [], index)
        person = b'ZcashTxHash_' + kwargs['branch_id'].to_bytes(4, 'little')
        digest = _b2b(
            person,
            kwargs['header_digest'] + transparent_digest +
            EMPTY_SAPLING_DIGEST + kwargs['orchard_digest'])
        self.assertTrue(
            self._verify_der_signature(pubkey, digest, signature),
            "transparent DER signature must verify against the locally "
            "reconstructed ZIP-244 sighash")

    def _start_raw_session(self, n_inputs):
        action = note_action(CMX_ORCHARD)
        kwargs = sign_kwargs([action])
        del kwargs['actions']
        kwargs.update({
            'n_actions': 1,
            'n_transparent_inputs': n_inputs,
            # Invalid-path and ordering tests fail before digest finalization.
            'transparent_digest': b'\x00' * 32,
        })
        request = zcash_proto.ZcashSignPCZT(**kwargs)
        # Valid sessions display their summary before asking for input zero;
        # use call() so the debug client acknowledges that ButtonRequest. The
        # over-limit case fails before any prompt, so call_raw() preserves the
        # Failure message for the bounds assertion.
        if n_inputs > 8:
            response = self.client.call_raw(request)
        else:
            response = self.client.call(request)
        return response, action

    def _assert_first_input_requested(self, response):
        self.assertIsInstance(response, zcash_proto.ZcashTransparentAck)
        self.assertTrue(response.HasField('next_input_index'))
        self.assertEqual(response.next_input_index, 0)

    def _assert_path_rejected(self, bad_path, message):
        self.setup_mnemonic_allallall()
        response, _ = self._start_raw_session(1)
        self._assert_first_input_requested(response)
        item = self._make_transparent_input(address_n=bad_path)
        response = self.client.call_raw(
            zcash_proto.ZcashTransparentInput(**item))
        self.assertIsInstance(response, proto.Failure)
        self.assertIn(message.lower(), response.message.lower())

    def test_hybrid_signature_verifies(self):
        self.setup_mnemonic_allallall()
        inputs = [self._make_transparent_input()]
        pubkey = self._get_pubkey_for_path(ZEC_PATH)

        response, signatures, kwargs = self._sign(inputs)

        self.assertIsInstance(response, zcash_proto.ZcashSignedPCZT)
        self.assertEqual(len(response.signatures), 0)
        self.assertEqual(len(signatures), 1)
        self._assert_signature(signatures[0], pubkey, kwargs, inputs, 0)

    def test_hybrid_multi_input_signatures_verify(self):
        self.setup_mnemonic_allallall()
        amounts = [VALUE // 2, VALUE - (VALUE // 2)]
        inputs = [
            self._make_transparent_input(index=i, amount=amount)
            for i, amount in enumerate(amounts)
        ]
        pubkey = self._get_pubkey_for_path(ZEC_PATH)

        response, signatures, kwargs = self._sign(inputs)

        self.assertIsInstance(response, zcash_proto.ZcashSignedPCZT)
        self.assertEqual(len(signatures), 2)
        self._assert_signature(signatures[0], pubkey, kwargs, inputs, 0)
        self._assert_signature(signatures[1], pubkey, kwargs, inputs, 1)

        digest_1 = _transparent_sig_digest(inputs, [], 1)
        person = b'ZcashTxHash_' + kwargs['branch_id'].to_bytes(4, 'little')
        wrong_digest = _b2b(
            person,
            kwargs['header_digest'] + digest_1 + EMPTY_SAPLING_DIGEST +
            kwargs['orchard_digest'])
        self.assertFalse(
            self._verify_der_signature(pubkey, wrong_digest, signatures[0]),
            "input 0 signature must not verify for input 1")

    def test_wrong_key_does_not_verify(self):
        self.setup_mnemonic_allallall()
        path_0 = list(ZEC_PATH)
        path_1 = list(ZEC_PATH[:-1]) + [1]
        inputs = [self._make_transparent_input(address_n=path_0)]
        pubkey_0 = self._get_pubkey_for_path(path_0)
        pubkey_1 = self._get_pubkey_for_path(path_1)
        self.assertNotEqual(pubkey_0, pubkey_1)

        _, signatures, kwargs = self._sign(inputs)

        self._assert_signature(signatures[0], pubkey_0, kwargs, inputs, 0)
        transparent_digest = _transparent_sig_digest(inputs, [], 0)
        person = b'ZcashTxHash_' + kwargs['branch_id'].to_bytes(4, 'little')
        digest = _b2b(
            person,
            kwargs['header_digest'] + transparent_digest +
            EMPTY_SAPLING_DIGEST + kwargs['orchard_digest'])
        self.assertFalse(
            self._verify_der_signature(pubkey_1, digest, signatures[0]),
            "signature for account 0 path must not verify under another key")

    def test_rejects_wrong_purpose(self):
        self._assert_path_rejected(
            [H + 49, H + 133, H, 0, 0], "m/44'/133'")

    def test_rejects_wrong_coin_type(self):
        self._assert_path_rejected(
            [H + 44, H + 60, H, 0, 0], "m/44'/133'")

    def test_rejects_unhardened_account(self):
        self._assert_path_rejected(
            [H + 44, H + 133, 0, 0, 0], "account must be hardened")

    def test_rejects_wrong_account(self):
        self._assert_path_rejected(
            [H + 44, H + 133, H + 1, 0, 0],
            "account does not match approved session")

    def test_rejects_short_path(self):
        self._assert_path_rejected(
            [H + 44, H + 133, H],
            "m/44'/133'/account'/change/index")

    def test_rejects_bad_change(self):
        self._assert_path_rejected(
            [H + 44, H + 133, H, 7, 0], "change must be 0 or 1")

    def test_rejects_hardened_index(self):
        self._assert_path_rejected(
            [H + 44, H + 133, H, 0, H], "index must not be hardened")

    def test_orchard_before_transparent_rejected(self):
        self.setup_mnemonic_allallall()
        response, action = self._start_raw_session(1)
        self._assert_first_input_requested(response)

        response = self.client.call_raw(zcash_proto.ZcashPCZTAction(
            index=0, **action))

        self.assertIsInstance(response, proto.Failure)
        self.assertIn("transparent data not yet complete",
                      response.message.lower())

    def test_rejects_out_of_order_transparent_index(self):
        self.setup_mnemonic_allallall()
        response, _ = self._start_raw_session(2)
        self._assert_first_input_requested(response)
        item = self._make_transparent_input(index=1)

        response = self.client.call_raw(
            zcash_proto.ZcashTransparentInput(**item))

        self.assertIsInstance(response, proto.Failure)
        self.assertIn("index", response.message.lower())

    def test_rejects_too_many_transparent_inputs(self):
        self.setup_mnemonic_allallall()
        response, _ = self._start_raw_session(100)

        self.assertIsInstance(response, proto.Failure)
        self.assertIn("too many transparent inputs", response.message.lower())


if __name__ == '__main__':
    unittest.main()
