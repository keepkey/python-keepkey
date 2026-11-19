"""The reference host signer, using an in-memory device transcript only."""
import json
from pathlib import Path
import random
import unittest
from unittest.mock import Mock

from Crypto.Cipher import ChaCha20_Poly1305
import monero_fixtures as xmr
from keepkeylib import messages_monero_pb2 as proto
from keepkeylib import monero_stream as stream


class TestMoneroStreamUnit(unittest.TestCase):
    def test_sign_returns_final_payment_proof_keys(self):
        for additional in ([], [(7).to_bytes(32, 'little'),
                                (11).to_bytes(32, 'little')]):
            with self.subTest(additional=bool(additional)):
                plan = json.loads(Path(__file__).with_name(
                    'monero_plans.json').read_text())[0]['plan']
                key = (123).to_bytes(32, 'little')
                public = xmr._encode(xmr._mul(xmr.G, 123))
                opening = bytes(range(32))
                ins = [proto.MoneroTxSetInputAck(
                    vini=b'\x02\x00\x01\x01' + bytes([i + 1]) * 32,
                    vini_hmac=bytes(32), pseudo_out=bytes(32),
                    pseudo_out_hmac=bytes(32)) for i in range(len(plan['inputs']))]
                vinis = sorted((a.vini for a in ins), reverse=True)
                proof = bytes(192) + b'\x07' + bytes(224) + b'\x07' + bytes(224)
                outs = [proto.MoneroTxSetOutputAck(
                    tx_out=b'\x00\x03' + bytes(33), out_pk=bytes(64),
                    ecdh_info=bytes(8), bp_plus=proof if j == 1 else b'')
                    for j in range(2)]
                all_out = proto.MoneroTxAllOutSetAck(
                    extra=b'\x01' + public, fee=plan['fee'], rct_type=6)
                clsags = [bytes(576) for _ in ins]
                prefix, base, prunable = stream.assemble(
                    0, vinis, outs, all_out, clsags, [bytes(32)] * len(ins))
                all_out.tx_prefix_hash = stream.keccak256(prefix)
                all_out.full_message_hash = stream.clsag_message(
                    all_out.tx_prefix_hash, base, proof)
                signed = []
                for position, plain in enumerate(clsags):
                    cipher = ChaCha20_Poly1305.new(
                        key=opening, nonce=position.to_bytes(4, 'little') + bytes(8))
                    sealed, tag = cipher.encrypt_and_digest(plain)
                    signed.append(proto.MoneroTxSignInputAck(
                        clsag_enc=sealed + tag, pseudo_out=bytes(32)))
                client = Mock()
                client.monero_tx_init.return_value = proto.MoneroTxInitAck(
                    dst_hmacs=[bytes(32)] * 2)
                client.monero_tx_set_input.side_effect = ins
                client.monero_tx_set_output.side_effect = outs
                client.monero_tx_all_out_set.return_value = all_out
                client.monero_tx_sign_input.side_effect = signed
                client.monero_tx_final.return_value = proto.MoneroTxFinalAck(
                    opening_key=opening, tx_key=key, additional_tx_keys=additional)
                result = stream.sign(client, xmr.path(0), plan, rng=random.Random(1))
                self.assertEqual(result.blob, prefix + base + prunable)
                self.assertEqual(result.tx_key, key)
                self.assertEqual(result.additional_tx_keys, additional)
                self.assertEqual(xmr._encode(xmr._mul(
                    xmr.G, int.from_bytes(result.tx_key, 'little'))), public)
                client.monero_tx_final.assert_called_once_with()
