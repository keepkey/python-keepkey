"""Device-level Zcash shielded signing.

Every other PCZT test in this suite is an offline contract test: they drive a
ScriptedTransport with canned responses and never reach a device. That left the
on-device shielded path with no automated coverage at all -- and it is not a
quiet corner of the firmware. fsm_msg_zcash.h calls total_amount "a summary
prompt" and delegates verification of Orchard output *values* to the per-output
confirm screen, so that screen is the whole trust story for a shielded send.

Nothing had ever rendered it. The RC run captured 1037 OLED frames and not one
came from a shielded flow, which is how a confirm that could not physically fit
its amount line shipped unnoticed.

The note fixtures are the known-answer vectors from
unittests/firmware/zcash.cpp (OrchardNoteCommitment_KnownVectorAndProgress,
IronwoodNoteCommitment_V3KnownVector, OrchardReceiverToUnifiedAddress_KnownVector),
so the device's own cmx recomputation accepts them. Same note under both pools,
with a different commitment each -- which is what lets us prove the device
actually honours shielded_pool instead of ignoring it.
"""

import hashlib
import struct
import unittest

import common

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib import messages_zcash_pb2 as zcash_proto


H = 0x80000000
ADDRESS_N = [H + 32, H + 133, H]

# --- known-answer note, from unittests/firmware/zcash.cpp -------------------
RECIPIENT = bytes.fromhex(
    '3c150e6098b861716cc7f62835f69feb302193c92660444f26624fd13e00ea7a'
    'c774cd55074d6367efef37')                                    # 43 bytes
RHO = bytes.fromhex(
    '112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00')
RSEED = bytes.fromhex(
    'cafebabedeadbeef0102030405060708090a0b0c0d0e0f101112131415161718')
VALUE = 12345678

CMX_ORCHARD = bytes.fromhex(
    '02defb39c8f2e1ecc945189373cf2a8e21d4e154398efa1621d5fb989e1deb36')
CMX_IRONWOOD = bytes.fromhex(
    '896ee345d8b0409872172537666a482409661a22ad77c09896a3e71765f18633')

# OrchardReceiverToUnifiedAddress_KnownVector. 106 characters -- three full
# body rows on their own, which is the entire reason the confirm needs two
# screens instead of one.
EXPECTED_UA = ('u1ut4h93zg5670tyqss7tneru3t7h6dk62r9hhyxyrpv3nwwe9dnyj5l0ruwygf'
               '74gp5f3zklj5xly4h8h54un3asugt9mn6gwfqsq3wq7')

ORCHARD_TX = dict(tx_version=5, version_group_id=0x26A7270A, branch_id=0x5437F330)
IRONWOOD_TX = dict(tx_version=6, version_group_id=0xD884B698, branch_id=0x37A5165B)

ANCHOR = b'\x13' * 32
FLAGS = 3


def _b2b(person, data):
    return hashlib.blake2b(data, digest_size=32, person=person).digest()


def header_digest(tx_version, version_group_id, branch_id, lock_time, expiry):
    """BLAKE2b-256('ZTxIdHeadersHash', 20-byte LE header). zcash.c:840-857."""
    header = struct.pack('<IIIII', tx_version | 0x80000000, version_group_id,
                         branch_id, lock_time, expiry)
    return _b2b(b'ZTxIdHeadersHash', header)


def bundle_digest(actions, ironwood, tx_version,
                  flags=FLAGS, value_balance=0, anchor=ANCHOR):
    """The shielded bundle digest the device recomputes. fsm_msg_zcash.h:1116-1189.

    The anchor is folded in only for pre-v6 transactions, and that is keyed on
    tx_version rather than on the pool.
    """
    if ironwood:
        pc, pm, pn, pb = (b'ZTxIdIrnActCH_v6', b'ZTxIdIrnActMH_v6',
                          b'ZTxIdIrnActNH_v6', b'ZTxIdIronwd_H_v6')
    else:
        pc, pm, pn, pb = (b'ZTxIdOrcActCHash', b'ZTxIdOrcActMHash',
                          b'ZTxIdOrcActNHash', b'ZTxIdOrchardHash')

    compact = _b2b(pc, b''.join(
        a['nullifier'] + a['cmx'] + a['epk'] + a['enc_compact'] for a in actions))
    memos = _b2b(pm, b''.join(a['enc_memo'] for a in actions))
    noncompact = _b2b(pn, b''.join(
        a['cv_net'] + a['rk'] + a['enc_noncompact'] + a['out_ciphertext']
        for a in actions))

    body = compact + memos + noncompact + bytes([flags]) + struct.pack('<q', value_balance)
    if tx_version != 6:
        body += anchor
    return _b2b(pb, body)


def note_action(cmx, recipient=RECIPIENT, value=VALUE, rseed=RSEED):
    """One action carrying real output metadata.

    Every field is size-checked by the firmware (fsm_msg_zcash.h:1068-1088) and
    is_spend must be present even when false. is_spend=False keeps this focused
    on the confirm screens: no RedPallas signature is emitted, so the test does
    not need an rk consistent with the device's spend authorizing key.
    """
    return {
        'alpha': b'\x01' * 32,
        'nullifier': RHO,          # the firmware feeds this in as rho
        'cmx': cmx,
        'epk': b'\x02' * 32,
        'enc_compact': b'\x03' * 52,
        'enc_memo': b'\x04' * 512,
        'enc_noncompact': b'\x05' * 16,
        'cv_net': b'\x06' * 32,
        'rk': b'\x07' * 32,
        'out_ciphertext': b'\x08' * 80,
        'is_spend': False,
        'value': value,
        'recipient': recipient,
        'rseed': rseed,
    }


def sign_kwargs(actions, ironwood=False, **overrides):
    """A shielded-only request the firmware will actually accept.

    Two gates the offline fixtures do not satisfy: the header digest is
    recomputed and compared (fsm_msg_zcash.h:677-685), and for a shielded-only
    transaction the verified fee reduces to orchard_value_balance, which must
    equal the declared fee (fsm_msg_zcash.h:281-326). Both are zero here.
    """
    tx = dict(IRONWOOD_TX if ironwood else ORCHARD_TX)
    tx.update({k: overrides.pop(k) for k in list(overrides)
               if k in ('tx_version', 'version_group_id', 'branch_id')})
    lock_time, expiry = 0, 0

    digest = bundle_digest(actions, ironwood, tx['tx_version'])
    kwargs = {
        'address_n': ADDRESS_N,
        'actions': actions,
        'account': 0,
        'total_amount': VALUE,
        'fee': 0,
        'lock_time': lock_time,
        'expiry_height': expiry,
        'orchard_flags': FLAGS,
        'orchard_value_balance': 0,
        'orchard_anchor': ANCHOR,
        'header_digest': header_digest(tx['tx_version'], tx['version_group_id'],
                                       tx['branch_id'], lock_time, expiry),
        'orchard_digest': digest,
    }
    kwargs.update(tx)
    if ironwood:
        kwargs['shielded_pool'] = zcash_proto.ZCASH_SHIELDED_POOL_IRONWOOD
        kwargs['ironwood_digest'] = digest
        # orchard_digest is still required to be present and 32 bytes, but for
        # Ironwood it is the ironwood_digest that is verified against the
        # actions; this one only feeds the locally derived sighash.
        kwargs['orchard_digest'] = b'\x00' * 32
    kwargs.update(overrides)
    return kwargs


def _lit_pixels(layout):
    """Count set pixels in a raw 2048-byte OLED framebuffer.

    read_layout returns the framebuffer, not text -- there is no glyph decoder
    anywhere in this repo -- so screen assertions here are structural: a screen
    that renders nothing, or two screens that render identically, are both
    detectable without OCR.
    """
    total = 0
    for b in layout:
        if isinstance(b, str):
            b = ord(b)
        total += bin(b).count('1')
    return total


class TestZcashShieldedSigningDevice(common.KeepKeyTest):

    def setUp(self):
        super(TestZcashShieldedSigningDevice, self).setUp()
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.requires_message("ZcashSignPCZT")
        self.setup_mnemonic_allallall()

    def _capture_button_screens(self):
        """Record the framebuffer at each ButtonRequest, before it is acked."""
        screens = []
        original = self.client.callback_ButtonRequest

        def capture(msg):
            screens.append((msg.code, self.client.debug.read_layout()))
            return original(msg)

        self.client.callback_ButtonRequest = capture
        return screens

    def test_shielded_output_review_is_two_screens(self):
        """The amount and the full address must each get a screen of their own.

        A unified address is 106 characters, which is three full body rows. The
        standard notification body is three rows and draw_string simply stops
        emitting once a character will not fit -- no scroll, no pagination, no
        indication. So a single confirm holding the question, the address and
        the amount rendered the question plus the first 76 address characters
        and silently dropped the rest along with the entire amount line.

        Two ConfirmOutput requests per action is therefore the assertion that
        matters: one screen cannot hold both, and collapsing them back into one
        reintroduces exactly the defect.
        """
        actions = [note_action(CMX_ORCHARD)]
        screens = self._capture_button_screens()

        result = self.client.zcash_sign_pczt(**sign_kwargs(actions))

        self.assertIsInstance(result, zcash_proto.ZcashSignedPCZT)
        self.assertEqual(len(result.signatures), 0)  # no is_spend action

        outputs = [(code, layout) for code, layout in screens
                   if code == proto_types.ButtonRequest_ConfirmOutput]
        # KeepKeyTest.assertEqual takes no message argument (common.py:114).
        self.assertTrue(
            len(outputs) == 2,
            "expected an amount screen and an address screen per shielded "
            "output; got %d ConfirmOutput screen(s). One screen cannot fit a "
            "106-character unified address plus an amount line."
            % len(outputs))

        amount_screen, address_screen = outputs[0][1], outputs[1][1]
        self.assertNotEqual(bytes(amount_screen), bytes(address_screen),
                            "the two review screens rendered identically")
        for name, layout in (('amount', amount_screen), ('address', address_screen)):
            self.assertEqual(len(layout), 2048)
            self.assertGreater(_lit_pixels(layout), 200,
                               "%s screen rendered (near-)blank" % name)

        # The address occupies three dense rows; the amount line is one short
        # row. If the address screen were truncated to the amount screen's
        # content this ordering would not hold.
        self.assertGreater(_lit_pixels(address_screen), _lit_pixels(amount_screen))

    def test_note_commitment_binds_the_recipient(self):
        """Flipping one recipient bit must break the commitment check.

        This is what stops a host from showing one recipient and committing to
        another: the device recomputes cmx from recipient, value, rho and rseed
        and compares it to the supplied commitment.
        """
        tampered = bytearray(RECIPIENT)
        tampered[0] ^= 0x01
        actions = [note_action(CMX_ORCHARD, recipient=bytes(tampered))]

        with self.assertRaises(Exception) as caught:
            self.client.zcash_sign_pczt(**sign_kwargs(actions))
        self.assertIn('commitment mismatch', str(caught.exception))

    def test_pool_selection_is_honoured(self):
        """The same note commits differently in each pool.

        Orchard and Ironwood derive a different cmx from identical inputs, so
        offering the Orchard commitment while declaring the Ironwood pool must
        be rejected. If the device ignored shielded_pool this would pass.
        """
        actions = [note_action(CMX_ORCHARD)]

        with self.assertRaises(Exception) as caught:
            self.client.zcash_sign_pczt(**sign_kwargs(actions, ironwood=True))
        self.assertIn('commitment mismatch', str(caught.exception))

    def test_ironwood_note_is_accepted(self):
        """The Ironwood commitment for that same note is accepted.

        The positive half of the pool test -- together they prove the branch is
        selected by shielded_pool rather than one path serving both.
        """
        actions = [note_action(CMX_IRONWOOD)]
        screens = self._capture_button_screens()

        result = self.client.zcash_sign_pczt(**sign_kwargs(actions, ironwood=True))

        self.assertIsInstance(result, zcash_proto.ZcashSignedPCZT)
        outputs = [c for c, _ in screens
                   if c == proto_types.ButtonRequest_ConfirmOutput]
        self.assertTrue(len(outputs) == 2,
                        "expected 2 ConfirmOutput screens, got %d" % len(outputs))


if __name__ == '__main__':
    unittest.main()
