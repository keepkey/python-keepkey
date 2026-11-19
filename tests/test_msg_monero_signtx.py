"""Monero streamed signing (wire 1810-1825) on the emulator.

The device builds the whole transaction; this test plays the host and then
checks what came back without using the firmware's crypto: Ed25519 and Keccak
from monero_fixtures, the AEAD from pycryptodome. It checks the key images
against the Monero Core fixtures, the prefix hash and the CLSAG message
against a host-side serialization, the RingCT balance, and it scans every
output as its recipient would.

The ring signatures and the range proof themselves are verified by Monero
Core in the firmware unit tests (unittests/firmware/monero_tx.cpp). Set
KK_MONERO_TX_CORE_VERIFY to the monero_tx_core_verify binary that
monero_tx_vectors_gen.sh builds and this test also hands each transaction the
emulator signed, with its real random draws, to Monero Core.
"""

import os
import struct
import subprocess
import tempfile
import unittest

import common
import monero_fixtures as xmr
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_monero_pb2 as monero_proto
from keepkeylib import types_pb2 as proto_types

# Monero's second generator: amounts are committed as mask*G + amount*H.
H = xmr._decode(bytes.fromhex(
    '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94'))
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BLOCK_BYTES = {11: 8, 7: 5}


def address_keys(address):
    """(spend public, view public) of a 95-character address."""
    data = b''
    for i in range(0, len(address), 11):
        block = address[i:i + 11]
        value = 0
        for ch in block:
            value = value * 58 + ALPHABET.index(ch)
        data += value.to_bytes(BLOCK_BYTES[len(block)], 'big')
    assert xmr.keccak256(data[:-4])[:4] == data[-4:]
    return data[1:33], data[33:65]


def hs(data):
    return int.from_bytes(xmr.keccak256(data), 'little') % xmr.L


def scalar(label, index):
    return hs(b'pyk-monero-sign' + label + struct.pack('<I', index))


def point(label, index):
    return xmr._encode(xmr._mul(xmr.G, scalar(label, index)))


def commit(mask, amount):
    return xmr._encode(xmr._add(xmr._mul(xmr.G, mask), xmr._mul(H, amount)))


def source(output, amount, real, tag):
    """A source entry spending a Core fixture output of the abandon wallet,
    hidden at `real` in a ring of 15 decoys."""
    mask = scalar(b'mask', tag)
    src = monero_proto.MoneroTxSourceEntry(
        real_index=real,
        real_out_tx_key=bytes.fromhex(output['tx_public']),
        real_output_in_tx_index=output['index'],
        amount=amount, mask=mask.to_bytes(32, 'little'),
        sub_major=output['major'], sub_minor=output['minor'])
    for i in range(16):
        member = src.ring.add()
        member.global_index = 5000000 + tag * 1000 + i * 37
        member.dest = point(b'dest', tag * 16 + i)
        member.commitment = point(b'commit', tag * 16 + i)
    src.ring[real].dest = bytes.fromhex(output['output_public'])
    src.ring[real].commitment = commit(mask, amount)
    return src


def destination(address, amount, subaddress=False):
    spend, view = address_keys(address)
    return monero_proto.MoneroTxDestination(
        amount=amount, spend_public_key=spend, view_public_key=view,
        is_subaddress=subaddress, is_integrated=False)


OWN = xmr.ADDRESSES[('abandon', 0)][(0, 0)]
OWN_VIEW = bytes.fromhex(xmr.VIEW_KEYS[('abandon', 0)])
PAYEE = xmr.ADDRESSES[('alcohol', 0)][(0, 0)]
PAYEE_SUB = xmr.ADDRESSES[('alcohol', 0)][(0, 1)]
PAYEE_VIEW = bytes.fromhex(xmr.VIEW_KEYS[('alcohol', 0)])
FEE = 31000000


def plan(payee, subaddress, inputs, change_first=False):
    """One recipient and change back to the wallet's primary address."""
    total = sum(amount for _, amount in inputs)
    send = total // 3
    change = total - send - FEE
    outputs = [destination(payee, send, subaddress), destination(OWN, change)]
    views = [PAYEE_VIEW, OWN_VIEW]
    if change_first:
        outputs.reverse()
        views.reverse()
    spend, view = address_keys(OWN)
    data = monero_proto.MoneroTxData(
        outputs=outputs,
        change_dts=monero_proto.MoneroTxChange(
            amount=change, spend_public_key=spend, view_public_key=view,
            major=0, minor=0),
        num_inputs=len(inputs), ring_size=16, fee=FEE, account=0,
        unlock_time=0, hard_fork=16, bp_version=4)
    sources = [source(output, amount, (3 + 5 * i) % 16, i + 1)
               for i, (output, amount) in enumerate(inputs)]
    return {'data': data, 'sources': sources, 'views': views,
            'outputs': [output for output, _ in inputs],
            'send': send, 'change': change}


class TestMsgMoneroSignTx(common.KeepKeyTest):

    def setUp(self):
        super(TestMsgMoneroSignTx, self).setUp()
        self.requires_firmware(common.CAPABILITIES_SINCE)
        self.requires_fullFeature()
        self.requires_release_capability('monero-signing')
        self.setup_mnemonic_abandon()

    # ---- the host's side of the protocol ----

    def init(self, p, answers=(True,)):
        with xmr.Screens(self.client, answers) as screens:
            ack = self.client.call_raw(monero_proto.MoneroTxInitRequest(
                address_n=xmr.path(0), tsx_data=p['data']))
            while isinstance(ack, proto.ButtonRequest):
                ack = self.client.call_raw(
                    self.client.callback_ButtonRequest(ack))
        return ack, screens

    def inputs(self, p):
        acks = [self.client.monero_tx_set_input(src) for src in p['sources']]
        # Core's input order: key images descending.
        order = sorted(range(len(acks)), key=lambda i: acks[i].vini[-32:],
                       reverse=True)
        return acks, order

    def sign(self, p):
        init, screens = self.init(p)
        self.assertIsInstance(init, monero_proto.MoneroTxInitAck)
        self.assertEqual(len(init.dst_hmacs), 2)
        self.assertEqual(init.rsig_mode, 0)
        ins, order = self.inputs(p)
        for i in order:
            self.assertIsInstance(
                self.client.monero_tx_input_vini(ins[i].vini,
                                                 ins[i].vini_hmac, i),
                monero_proto.MoneroTxInputViniAck)
        self.client.monero_tx_all_inputs_set()
        outs = [self.client.monero_tx_set_output(dst, init.dst_hmacs[j])
                for j, dst in enumerate(p['data'].outputs)]
        all_out = self.client.monero_tx_all_out_set()
        signed = [self.client.monero_tx_sign_input(
            p['sources'][i], ins[i].vini, ins[i].vini_hmac,
            ins[i].pseudo_out, ins[i].pseudo_out_hmac, i) for i in order]
        final = self.client.monero_tx_final()
        clsags = [xmr.decrypt(final.opening_key,
                              struct.pack('<I', k) + bytes(8), s.clsag_enc)
                  for k, s in enumerate(signed)]
        return {'init': init, 'screens': screens, 'ins': ins, 'order': order,
                'outs': outs, 'all_out': all_out, 'signed': signed,
                'clsags': clsags}

    # ---- host-side checks, independent of the firmware ----

    def prefix(self, p, r):
        tx = xmr.varint(2) + xmr.varint(0) + xmr.varint(len(r['order']))
        tx += b''.join(r['ins'][i].vini for i in r['order'])
        tx += xmr.varint(2) + b''.join(o.tx_out for o in r['outs'])
        return tx + xmr.varint(len(r['all_out'].extra)) + r['all_out'].extra

    def transaction(self, p, r):
        base = bytes([r['all_out'].rct_type]) + xmr.varint(r['all_out'].fee)
        base += b''.join(o.ecdh_info for o in r['outs'])
        base += b''.join(o.out_pk[32:] for o in r['outs'])
        prunable = xmr.varint(1) + r['outs'][1].bp_plus
        prunable += b''.join(r['clsags'])
        prunable += b''.join(s.pseudo_out for s in r['signed'])
        return self.prefix(p, r), base, prunable

    def check(self, p, r):
        prefix, base, prunable = self.transaction(p, r)
        all_out = r['all_out']
        # Key images are Monero Core's for these outputs, largest first.
        images = [r['ins'][i].vini[-32:] for i in r['order']]
        self.assertEqual(sorted(images, reverse=True), images)
        for i, output in enumerate(p['outputs']):
            self.assertEqual(r['ins'][i].vini[-32:].hex(), output['key_image'])
            self.assertEqual(r['ins'][i].vini[:3], b'\x02\x00\x10')
        # The device hashed exactly the prefix the host assembles.
        self.assertEqual(xmr.keccak256(prefix), all_out.tx_prefix_hash)
        self.assertEqual(all_out.rct_type, 6)
        self.assertEqual(all_out.fee, FEE)
        # CLSAG message: prefix hash | rctSigBase hash | range proof keys.
        proof = r['outs'][1].bp_plus
        self.assertEqual(len(proof), 642)
        self.assertEqual((proof[192], proof[417]), (7, 7))
        keys = proof[:192] + proof[193:417] + proof[418:]
        self.assertEqual(
            xmr.keccak256(all_out.tx_prefix_hash + xmr.keccak256(base) +
                          xmr.keccak256(keys)),
            all_out.full_message_hash)
        self.assertFalse(r['outs'][0].bp_plus)

        # extra: the tx key, then the encrypted (dummy) payment ID.
        extra = all_out.extra
        self.assertEqual(len(extra), 44)
        self.assertEqual((extra[0], extra[33:36]), (1, b'\x02\x09\x01'))
        R = xmr._decode(extra[1:33])

        # Every output scans for its recipient with only its view key.
        commitments = []
        for j, (dst, view) in enumerate(zip(p['data'].outputs, p['views'])):
            out = r['outs'][j]
            a = int.from_bytes(view, 'little')
            derivation = xmr._encode(xmr._mul(R, 8 * a))
            shared = hs(derivation + xmr.varint(j))
            key = xmr._add(xmr._mul(xmr.G, shared),
                           xmr._decode(dst.spend_public_key))
            self.assertEqual(out.tx_out[:2], b'\x00\x03')
            self.assertEqual(out.tx_out[2:34], xmr._encode(key))
            self.assertEqual(
                out.tx_out[34],
                xmr.keccak256(b'view_tag' + derivation + xmr.varint(j))[0])
            self.assertEqual(out.out_pk[:32], out.tx_out[2:34])
            amount_key = shared.to_bytes(32, 'little')
            pad = xmr.keccak256(b'amount' + amount_key)[:8]
            amount = int.from_bytes(
                bytes(x ^ y for x, y in zip(out.ecdh_info, pad)), 'little')
            self.assertEqual(amount, dst.amount)
            mask = hs(b'commitment_mask' + amount_key)
            self.assertEqual(out.out_pk[32:], commit(mask, amount))
            commitments.append(xmr._decode(out.out_pk[32:]))
        # The payment ID a wallet would decrypt is the all-zero dummy.
        payee = [v for d, v in zip(p['data'].outputs, p['views'])
                 if d.spend_public_key != address_keys(OWN)[0]][0]
        pad = xmr.keccak256(xmr._encode(
            xmr._mul(R, 8 * int.from_bytes(payee, 'little'))) + b'\x8d')[:8]
        self.assertEqual(extra[36:], pad)

        # RingCT balance: pseudo-outputs = output commitments + fee*H.
        left = right = (0, 1, 1, 0)
        for s in r['signed']:
            left = xmr._add(left, xmr._decode(s.pseudo_out))
        for c in commitments + [xmr._mul(H, FEE)]:
            right = xmr._add(right, c)
        self.assertEqual(xmr._encode(left), xmr._encode(right))
        # Only the last-signed pseudo-output moved.
        for k, i in enumerate(r['order']):
            same = r['signed'][k].pseudo_out == r['ins'][i].pseudo_out
            self.assertEqual(same, k + 1 < len(r['order']))
        # Each CLSAG: 16 responses, c1 and D; canonical scalars.
        for clsag in r['clsags']:
            self.assertEqual(len(clsag), 18 * 32)
            for k in range(17):
                self.assertLess(
                    int.from_bytes(clsag[32 * k:32 * k + 32], 'little'), xmr.L)
            xmr._decode(clsag[544:])
        self.core_verify(p, r, prefix + base + prunable)

    def core_verify(self, p, r, tx):
        verifier = os.environ.get('KK_MONERO_TX_CORE_VERIFY')
        if not verifier:
            return
        record = b'T\x01' + bytes([len(self.id()[-28:])]) + \
            self.id()[-28:].encode()
        record += struct.pack('<I', len(tx)) + tx
        record += r['all_out'].tx_prefix_hash + r['all_out'].full_message_hash
        record += struct.pack('<Q', FEE) + bytes([len(r['order'])])
        for i in r['order']:
            for member in p['sources'][i].ring:
                record += struct.pack('<Q', member.global_index)
                record += member.dest + member.commitment
            record += bytes.fromhex(p['outputs'][i]['output_secret'])
        for dst, view in zip(p['data'].outputs, p['views']):
            record += struct.pack('<Q', dst.amount) + view
            record += dst.spend_public_key
        payee = [v for d, v in zip(p['data'].outputs, p['views'])
                 if d.spend_public_key != address_keys(OWN)[0]][0]
        record += bytes(8) + payee
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'records.bin')
            with open(path, 'wb') as f:
                f.write(record)
            done = subprocess.run(
                [verifier, path, os.path.join(tmp, 'vectors.h')],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if done.returncode != 0 or b'core=accept' not in done.stdout:
            self.fail('Monero Core: ' + done.stdout.decode())
        print(done.stdout.decode().strip())

    # ---- tests ----

    def test_one_input_to_a_standard_address(self):
        p = plan(PAYEE, False, [(xmr.OWNED_OUTPUTS[0], 2000000000000)])
        r = self.sign(p)
        self.check(p, r)
        # The review: complete addresses, exact amounts, change as change,
        # fee and total.
        shown = [(title, ''.join(body.split()))
                 for title, body in r['screens'].confirmations()]
        send = [body for title, body in shown if title.startswith('Monero send')]
        change = [body for title, body in shown
                  if title.startswith('Monero change')]
        self.assertEqual(len(send), 1)
        self.assertEqual(len(change), 1)
        self.assertIn(PAYEE, send[0])
        self.assertIn('Send0.666666666666XMRtostandardaddress', send[0])
        self.assertIn(OWN, change[0])
        self.assertIn('Change1.333302333334XMRreturnstothiswallet', change[0])
        self.assertNotIn(OWN, send[0])
        title, last = shown[-1]
        self.assertEqual(title, 'Sign Monero')
        self.assertIn('Fee0.000031000000XMR', last)
        self.assertIn('Total0.666697666666XMR', last)
        for _, body in shown:
            self.assertNotIn('...', body)

    def test_two_inputs_to_a_subaddress(self):
        # The second input was received on subaddress (0, 1); the recipient
        # is a subaddress, so the tx key is r*D; change comes first.
        p = plan(PAYEE_SUB, True, [(xmr.OWNED_OUTPUTS[0], 1500000000000),
                                   (xmr.OWNED_OUTPUTS[1], 700000000000)],
                 change_first=True)
        r = self.sign(p)
        self.check(p, r)
        shown = ''.join(''.join(body.split())
                        for _, body in r['screens'].confirmations())
        self.assertIn(PAYEE_SUB, shown)
        self.assertIn('tosubaddress', shown)

    def test_a_session_signs_once(self):
        p = plan(PAYEE, False, [(xmr.OWNED_OUTPUTS[0], 2000000000000)])
        self.sign(p)
        # The session ended with TxFinal: nothing can be signed again.
        for message in (monero_proto.MoneroTxFinalRequest(),
                        monero_proto.MoneroTxAllOutSetRequest(),
                        monero_proto.MoneroTxSetInputRequest(
                            src=p['sources'][0])):
            response = self.client.call_raw(message)
            self.assertIsInstance(response, proto.Failure)
            self.assertEqual(response.code,
                             proto_types.Failure_UnexpectedMessage)

    def test_declined_review_opens_no_session(self):
        p = plan(PAYEE, False, [(xmr.OWNED_OUTPUTS[0], 2000000000000)])
        for answers in ((False,), (True, True, False)):
            ack, _ = self.init(p, answers)
            self.assertIsInstance(ack, proto.Failure)
            self.assertEqual(ack.code, proto_types.Failure_ActionCancelled)
            response = self.client.call_raw(
                monero_proto.MoneroTxSetInputRequest(src=p['sources'][0]))
            self.assertIsInstance(response, proto.Failure)
            self.assertEqual(response.code,
                             proto_types.Failure_UnexpectedMessage)

    def test_unsupported_plans_are_refused_before_any_screen(self):
        def refused(change, text):
            p = plan(PAYEE, False, [(xmr.OWNED_OUTPUTS[0], 2000000000000)])
            change(p['data'])
            ack, screens = self.init(p)
            self.assertIsInstance(ack, proto.Failure)
            self.assertIn(text, ack.message)
            self.assertEqual(screens.confirmations(), [])

        def third_output(data):
            data.outputs.add().CopyFrom(destination(PAYEE_SUB, 1, True))
        refused(third_output, 'exactly 2 outputs')

        def one_output(data):
            del data.outputs[-1]
        refused(one_output, 'exactly 2 outputs')
        refused(lambda d: setattr(d, 'ring_size', 11), 'ring size must be 16')
        refused(lambda d: setattr(d, 'hard_fork', 15), 'hard fork')
        refused(lambda d: setattr(d, 'bp_version', 3), 'Bulletproofs+')
        refused(lambda d: setattr(d, 'payment_id', b'\x01' * 7), 'payment ID')

        def foreign_change(data):
            spend, view = address_keys(PAYEE)
            data.change_dts.spend_public_key = spend
            data.change_dts.view_public_key = view
        refused(foreign_change, 'change must return to this wallet')

        def no_change_output(data):
            data.outputs[1].CopyFrom(destination(PAYEE_SUB,
                                                 data.outputs[1].amount, True))
        refused(no_change_output, 'change must return to this wallet')

    def test_other_requests_end_the_session(self):
        p = plan(PAYEE, False, [(xmr.OWNED_OUTPUTS[0], 2000000000000)])
        ack, _ = self.init(p)
        self.assertIsInstance(ack, monero_proto.MoneroTxInitAck)
        # Reading the features does not disturb it.
        self.assertIsInstance(self.client.call_raw(proto.GetFeatures()),
                              proto.Features)
        self.assertIsInstance(self.client.monero_tx_set_input(p['sources'][0]),
                              monero_proto.MoneroTxSetInputAck)
        # Anything else does, Ping included.
        self.client.call_raw(proto.Ping(message='x'))
        response = self.client.call_raw(monero_proto.MoneroTxInputViniRequest())
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.code, proto_types.Failure_UnexpectedMessage)

    def test_changed_host_state_ends_the_session(self):
        p = plan(PAYEE, False, [(xmr.OWNED_OUTPUTS[0], 2000000000000)])

        def started():
            ack, _ = self.init(p)
            ins, order = self.inputs(p)
            return ack, ins

        def ended(response, text):
            self.assertIsInstance(response, proto.Failure)
            self.assertIn(text, response.message)
            stale = self.client.call_raw(monero_proto.MoneroTxFinalRequest())
            self.assertEqual(stale.code, proto_types.Failure_UnexpectedMessage)

        # A changed key image.
        ack, ins = started()
        vini = bytearray(ins[0].vini)
        vini[-1] ^= 1
        ended(self.client.call_raw(monero_proto.MoneroTxInputViniRequest(
            vini=bytes(vini), vini_hmac=ins[0].vini_hmac, orig_idx=0)),
            'changed or replayed')
        # A changed amount for an output.
        ack, ins = started()
        self.client.monero_tx_input_vini(ins[0].vini, ins[0].vini_hmac, 0)
        self.client.monero_tx_all_inputs_set()
        dst = monero_proto.MoneroTxDestination()
        dst.CopyFrom(p['data'].outputs[0])
        dst.amount += 1
        ended(self.client.call_raw(monero_proto.MoneroTxSetOutputRequest(
            dst=dst, dst_hmac=ack.dst_hmacs[0])), 'changed or replayed')
        # State from the session before: its MACs no longer verify.
        old_ack, old_ins = started()
        ack, ins = started()
        ended(self.client.call_raw(monero_proto.MoneroTxInputViniRequest(
            vini=old_ins[0].vini, vini_hmac=old_ins[0].vini_hmac, orig_idx=0)),
            'changed or replayed')
        # An input that is not this wallet's.
        ack, _ = self.init(p)
        foreign = monero_proto.MoneroTxSourceEntry()
        foreign.CopyFrom(p['sources'][0])
        foreign.real_out_tx_key = point(b'foreign', 1)
        ended(self.client.call_raw(
            monero_proto.MoneroTxSetInputRequest(src=foreign)),
            'does not belong to this wallet')


if __name__ == '__main__':
    unittest.main()
