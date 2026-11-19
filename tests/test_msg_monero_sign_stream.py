"""Monero signing through keepkeylib.monero_stream, the reference host signer.

The plans in monero_plans.json are unsigned transfers that a stock Monero
v0.18.5.4 watch-only wallet built on a private regtest chain for the
"abandon ... about" wallet, paying the "alcohol woman ..." wallet: real
rings, commitments and additional transaction keys. The transactions the
emulator signed from these plans were accepted and mined by that chain's
daemon (keepkey-firmware tools/monero-e2e/regtest_e2e.py); their key images
are recorded with each plan.

Signing a plan again draws new randomness, so the bytes differ from the
mined ones. These tests sign each plan on the emulator, parse the blob the
host signer assembled and check it without the firmware's crypto: the key
images are the mined ones, the rings are the plan's, every output scans for
its recipient with only its view key, the payment ID decrypts, and the
RingCT amounts balance. Set KK_MONERO_TX_CORE_VERIFY to the
monero_tx_core_verify binary (keepkey-firmware
unittests/firmware/monero_tx_vectors_gen.sh) and each transaction is also
verified by Monero Core.
"""

import json
import os
import struct
import subprocess
import tempfile
import unittest

import common
import monero_fixtures as xmr
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_monero_pb2 as monero_proto
from keepkeylib import monero_stream
from keepkeylib import types_pb2 as proto_types

# Monero's second generator: amounts are committed as mask*G + amount*H.
H = xmr._decode(bytes.fromhex(
    '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94'))
OWN_VIEW = bytes.fromhex(xmr.VIEW_KEYS[('abandon', 0)])
PAYEE_VIEW = bytes.fromhex(xmr.VIEW_KEYS[('alcohol', 0)])

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       'monero_plans.json')) as f:
    CASES = {case['name']: case for case in json.load(f)}


def hs(data):
    return int.from_bytes(xmr.keccak256(data), 'little') % xmr.L


def xmr_amount(atomic):
    return '%d.%012d' % divmod(atomic, 10 ** 12)


class ChangeFirst(object):
    def shuffle(self, outputs):
        outputs.sort(key=lambda o: not o['is_change'])


class Reader(object):
    def __init__(self, data):
        self.data, self.at = data, 0

    def take(self, size):
        self.at += size
        assert self.at <= len(self.data)
        return self.data[self.at - size:self.at]

    def varint(self):
        value = shift = 0
        while True:
            byte = self.take(1)[0]
            value |= (byte & 0x7f) << shift
            shift += 7
            if not byte & 0x80:
                return value


def parse(blob):
    """A two-output RingCT type 6 transaction, every byte accounted for."""
    r = Reader(blob)
    tx = {'version': r.varint(), 'unlock_time': r.varint(), 'inputs': []}
    for _ in range(r.varint()):
        assert r.take(1) == b'\x02' and r.varint() == 0   # txin_to_key
        index, ring = 0, []
        for _ in range(r.varint()):
            index += r.varint()
            ring.append(index)
        tx['inputs'].append({'ring': ring, 'key_image': r.take(32)})
    tx['outputs'] = []
    for _ in range(r.varint()):
        assert r.varint() == 0 and r.take(1) == b'\x03'   # tagged key
        tx['outputs'].append({'key': r.take(32), 'view_tag': r.take(1)[0]})
    tx['extra'] = r.take(r.varint())
    prefix_end = r.at
    tx['rct_type'], tx['fee'] = r.take(1)[0], r.varint()
    for out in tx['outputs']:
        out['ecdh'] = r.take(8)
    for out in tx['outputs']:
        out['commitment'] = r.take(32)
    base_end = r.at
    assert r.varint() == 1                                # one BP+ proof
    proof_start = r.at
    r.take(6 * 32)
    for _ in range(2):
        r.take(32 * r.varint())
    tx['bp_plus'] = blob[proof_start:r.at]
    tx['clsags'] = [r.take(18 * 32) for _ in tx['inputs']]
    tx['pseudo_outs'] = [r.take(32) for _ in tx['inputs']]
    assert r.at == len(blob)
    tx['prefix'], tx['base'] = blob[:prefix_end], blob[prefix_end:base_end]
    tx['prunable'] = blob[base_end:]
    return tx


class TestMsgMoneroSignStream(common.KeepKeyTest):

    def setUp(self):
        super(TestMsgMoneroSignStream, self).setUp()
        self.requires_firmware(common.CAPABILITIES_SINCE)
        self.requires_fullFeature()
        self.requires_release_capability('monero-signing')
        self.setup_mnemonic_abandon()

    def sign(self, name, rng=None):
        case = CASES[name]
        plan = json.loads(json.dumps(case['plan']))
        change = plan['change']
        for output in plan['outputs']:
            output['is_change'] = all(
                output[k] == change[k] for k in
                ('amount', 'spend_public_key', 'view_public_key'))
        with xmr.Screens(self.client) as screens:
            signed = monero_stream.sign(self.client, xmr.path(0), plan,
                                        rng=rng)
        self.check(case, plan, signed)
        return case, plan, signed, [
            (title, ''.join(body.split()))
            for title, body in screens.confirmations()]

    def check(self, case, plan, signed):
        tx = parse(signed.blob)
        self.assertEqual((tx['version'], tx['unlock_time'], tx['rct_type']),
                         (2, 0, 6))
        self.assertEqual(tx['fee'], plan['fee'])
        self.assertEqual(signed.tx_hash, xmr.keccak256(
            xmr.keccak256(tx['prefix']) + xmr.keccak256(tx['base']) +
            xmr.keccak256(tx['prunable'])))

        # Inputs: the key images the private chain's daemon accepted for
        # these outputs, largest first, each over the plan's ring.
        images = [i['key_image'] for i in tx['inputs']]
        self.assertEqual(images, signed.key_images)
        self.assertEqual(sorted(images, reverse=True), images)
        self.assertEqual(sorted(k.hex() for k in images), case['key_images'])
        rings = [[m['global_index'] for m in i['ring']]
                 for i in plan['inputs']]
        order = [rings.index(i['ring']) for i in tx['inputs']]
        self.assertEqual(sorted(order), list(range(len(rings))))

        # extra: the tx key, then the encrypted payment ID.
        extra = tx['extra']
        self.assertEqual(len(extra), 44)
        self.assertEqual((extra[0], extra[33:36]), (1, b'\x02\x09\x01'))
        R = xmr._decode(extra[1:33])
        # Final's payment-proof secret opens the public key in the signed extra.
        self.assertEqual(len(signed.tx_key), 32)
        # R = r*G, or r*D when the one recipient is a subaddress with
        # spend key D (Core's construct_tx_with_tx_key).
        paid = [o for o in signed.outputs if not o['is_change']]
        base = xmr._decode(bytes.fromhex(paid[0]['spend_public_key'])) \
            if len(paid) == 1 and paid[0]['is_subaddress'] else xmr.G
        self.assertEqual(xmr._encode(xmr._mul(
            base, int.from_bytes(signed.tx_key, 'little'))), extra[1:33])
        self.assertEqual(signed.additional_tx_keys, [])

        # Every output scans for its recipient with only its view key.
        self.assertEqual(len(tx['outputs']), 2)
        self.assertEqual(sorted(o['is_change'] for o in signed.outputs),
                         [False, True])
        commitments = []
        for j, (dst, out) in enumerate(zip(signed.outputs, tx['outputs'])):
            view = OWN_VIEW if dst['is_change'] else PAYEE_VIEW
            derivation = xmr._encode(
                xmr._mul(R, 8 * int.from_bytes(view, 'little')))
            shared = hs(derivation + xmr.varint(j))
            key = xmr._add(xmr._mul(xmr.G, shared), xmr._decode(
                bytes.fromhex(dst['spend_public_key'])))
            self.assertEqual(out['key'], xmr._encode(key))
            self.assertEqual(out['view_tag'], xmr.keccak256(
                b'view_tag' + derivation + xmr.varint(j))[0])
            amount_key = shared.to_bytes(32, 'little')
            pad = xmr.keccak256(b'amount' + amount_key)[:8]
            amount = int.from_bytes(
                bytes(x ^ y for x, y in zip(out['ecdh'], pad)), 'little')
            self.assertEqual(amount, dst['amount'])
            mask = hs(b'commitment_mask' + amount_key)
            self.assertEqual(out['commitment'], xmr._encode(xmr._add(
                xmr._mul(xmr.G, mask), xmr._mul(H, amount))))
            commitments.append(xmr._decode(out['commitment']))
        # The recipient decrypts the plan's payment ID, or the zero dummy.
        pad = xmr.keccak256(xmr._encode(xmr._mul(
            R, 8 * int.from_bytes(PAYEE_VIEW, 'little'))) + b'\x8d')[:8]
        payment_id = bytes(x ^ y for x, y in zip(extra[36:], pad))
        self.assertEqual(payment_id.hex(),
                         plan.get('payment_id', '00' * 8))

        # RingCT balance: pseudo-outputs = output commitments + fee*H.
        left = right = (0, 1, 1, 0)
        for pseudo_out in tx['pseudo_outs']:
            left = xmr._add(left, xmr._decode(pseudo_out))
        for c in commitments + [xmr._mul(H, plan['fee'])]:
            right = xmr._add(right, c)
        self.assertEqual(xmr._encode(left), xmr._encode(right))
        self.core_verify(case, plan, signed, tx, order, payment_id)

    def core_verify(self, case, plan, signed, tx, order, payment_id):
        verifier = os.environ.get('KK_MONERO_TX_CORE_VERIFY')
        if not verifier:
            return
        name = ('stream-' + case['name']).encode()
        prefix_hash = xmr.keccak256(tx['prefix'])
        record = b'T\x01' + bytes([len(name)]) + name
        record += struct.pack('<I', len(signed.blob)) + signed.blob
        record += prefix_hash + monero_stream.clsag_message(
            prefix_hash, tx['base'], tx['bp_plus'])
        record += struct.pack('<Q', plan['fee']) + bytes([len(order)])
        for i in order:
            for member in plan['inputs'][i]['ring']:
                record += struct.pack('<Q', member['global_index'])
                record += bytes.fromhex(member['public_key'] +
                                        member['commitment'])
            record += bytes.fromhex(case['input_secrets'][i])
        for dst in signed.outputs:
            record += struct.pack('<Q', dst['amount'])
            record += OWN_VIEW if dst['is_change'] else PAYEE_VIEW
            record += bytes.fromhex(dst['spend_public_key'])
        record += payment_id + PAYEE_VIEW
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

    def review(self, case, plan, shown, kind):
        """The complete addresses, exact amounts, the fee and the total."""
        send = [body for title, body in shown if title == 'Monero send']
        change = [body for title, body in shown if title == 'Monero change']
        self.assertEqual((len(send), len(change)), (1, 1))
        self.assertIn('Send%sXMRto%s%s' % (
            xmr_amount(case['amount']), kind, case['recipient']), send[0])
        own = xmr.ADDRESSES[('abandon', 0)][(plan['account'], 0)]
        self.assertIn(
            'Change%sXMRreturnstothiswallet(account%d),toyouraddress%s' % (
                xmr_amount(plan['change']['amount']), plan['account'], own),
            change[0])
        title, last = shown[-1]
        self.assertEqual(title, 'Sign Monero')
        self.assertIn('Fee%sXMRTotal%sXMR%dinput(s)' % (
            xmr_amount(plan['fee']),
            xmr_amount(case['amount'] + plan['fee']),
            len(plan['inputs'])), last)
        for _, body in shown:
            self.assertNotIn('...', body)

    # ---- tests ----

    def test_standard_address(self):
        # One input, received on subaddress (0, 1) through an additional
        # transaction key. Output order as the host signer shuffles it.
        case, plan, signed, shown = self.sign('standard')
        self.assertEqual(len(plan['inputs']), 1)
        self.review(case, plan, shown, 'standardaddress')

    def test_subaddress_spending_change(self):
        # Three inputs: the change of the transaction above, an output on
        # the primary address and one on subaddress (0, 2) that was paid
        # alone (its transaction key is r*D). The recipient is a subaddress
        # too. Change first.
        case, plan, signed, shown = self.sign('subaddress', ChangeFirst())
        self.assertEqual(len(plan['inputs']), 3)
        self.assertTrue(signed.outputs[0]['is_change'])
        self.review(case, plan, shown, 'subaddress')

    def test_integrated_address(self):
        case, plan, signed, shown = self.sign('integrated')
        self.review(case, plan, shown, 'integratedaddress')
        self.assertIn(('Monero payment ID', 'PaymentID%sissentwiththis'
                       'payment.' % plan['payment_id']), shown)

    def test_block_reward_input(self):
        # A coinbase output: its commitment is to the plain amount, with
        # mask 1.
        case, plan, signed, shown = self.sign('coinbase')
        self.assertIn('01' + '00' * 31, [i['mask'] for i in plan['inputs']])
        self.review(case, plan, shown, 'standardaddress')

    def test_account_1_three_inputs(self):
        # Inputs on subaddresses (1, 0), (1, 1) and (1, 2); the change
        # returns to subaddress (1, 0).
        case, plan, signed, shown = self.sign('account1')
        self.assertEqual(plan['account'], 1)
        self.assertEqual(len(plan['inputs']), 3)
        self.review(case, plan, shown, 'standardaddress')

    def test_cancel_during_the_range_proof(self):
        # A host's way out while the device proves: Cancel. The session
        # ends with nothing half-signed, and the plan signs from the start.
        plan = CASES['standard']['plan']
        outputs = plan['outputs']
        init = self.client.monero_tx_init(
            xmr.path(0), monero_stream.tx_data(plan, outputs))
        ack = self.client.monero_tx_set_input(
            monero_stream.source_entry(plan['inputs'][0]))
        self.client.monero_tx_input_vini(ack.vini, ack.vini_hmac, 0)
        self.client.monero_tx_all_inputs_set()
        self.client.monero_tx_set_output(
            monero_stream.destination(outputs[0]), init.dst_hmacs[0])
        transport = self.client.transport
        transport.write(monero_proto.MoneroTxSetOutputRequest(
            dst=monero_stream.destination(outputs[1]),
            dst_hmac=init.dst_hmacs[1]))
        transport.write(proto.Cancel())
        cancelled = transport.read_blocking()
        self.assertIsInstance(cancelled, proto.Failure)
        self.assertEqual(cancelled.code, proto_types.Failure_ActionCancelled)
        stale = self.client.call_raw(monero_proto.MoneroTxAllOutSetRequest())
        self.assertIsInstance(stale, proto.Failure)
        self.assertEqual(stale.code, proto_types.Failure_UnexpectedMessage)
        self.sign('standard')


if __name__ == '__main__':
    unittest.main()
