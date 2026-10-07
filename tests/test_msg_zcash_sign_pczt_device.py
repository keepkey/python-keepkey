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

The note fixture is note 0 of the zcash-test-vectors Orchard note-encryption
vectors, with a real ciphertext, so the device's cmx recomputation and its
note-ciphertext check both accept it. Same note under both pools, with a
different commitment and ciphertext each -- which is what lets us prove the
device actually honours shielded_pool instead of ignoring it.
"""

import hashlib
import struct
import time
import unittest

import common

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib import messages_zcash_pb2 as zcash_proto


H = 0x80000000
ADDRESS_N = [H + 32, H + 133, H]

# --- note 0 of zcash-test-vectors orchard_note_encryption.py ---------------
# As carried by the orchard 0.15.4 crate (src/test_vectors/note_encryption.rs).
# The device recomputes cmx AND decrypts the note ciphertext, so every field
# below must be a real encryption of this note; rho is the vector's nf_old.
# The Ironwood (V3, lead byte 0x03) cmx and ciphertext re-encrypt the same note
# with orchard 0.15.4's IronwoodNoteEncryption; epk is unchanged.
RECIPIENT = bytes.fromhex(
    '56e84b1adc9423c3676c0463f7125df4836fd2816b024ee70efe09fb9a7b3863'
    'c6eacdf95e03894950692c')  # d || pk_d, 43 bytes
RHO = bytes.fromhex('c596fbd32ebbcbadae60d285c7d75fa836f9d2fa86100ab858ea2de1f11c8306')
RSEED = bytes.fromhex('bf69b8250c18ef41294ca97993db546c1fe01f7e9c8e36d6a5e29d4e30a73594')
VALUE = 8567075990963576717

CMX_ORCHARD = bytes.fromhex('a5706f3d1b688e9dc634eee4e65b028a43eeaed2435bea2ae3d5160575c11a3b')
CMX_IRONWOOD = bytes.fromhex('07a8d0edab5130bcdb265d8efed333514c2c9b180df70ba3963ca8fc1166bd14')
EPK = bytes.fromhex('addb47b6ac5dfc16558923d3a8f376095c695c047c4e3266ae676987f7e31381')
# enc_ciphertext = compact (52) || memo (512) || AEAD tag (16).
C_ENC_ORCHARD = bytes.fromhex(
    '1a9adb142498e3dcc76fed778614dd316c02fbb8ba9244ae4c2e32a07daeeca4'
    '1226b98bfe74f9fcb228cfc100f3180f5775ece38be7ed45d94021f4401b2a4d'
    '7582b428d49ec7f5b5a498973e60e38e74f5c3e577827c382857d8166b54e64f'
    '66ef5c7e8c9baa2a3fa9e37d087717d5e96bc2f73d031450dc2432ba49d8b74d'
    'b213099ea9ba04eb63b6574d46c03ce7900d4ac4bb188ee9030d7f69c895a94f'
    'c182f225a94f0cde1b49886871a376341ea94171befd95a830fa18407097dca5'
    '11025463d437e9695caa079a2f68cdc7f2c13267bff4195137fa8953252a81b2'
    'afa1582b9bfb4ac96037ed2991d3cbc7d54aff6e621b06a7b2b9caf2955efaf4'
    'ea8efcfd023a3c1748df3cbd43e0b9a8b0945688d52056c1d16eea37e798ba31'
    'dc3e5d4952bd51ec769d5788b6e35fe9042b95d4d21781400eaff58616ad5627'
    '96636a50b8ed6c7f981dc7ba814eff152cb228a2ead2f832662fa4a4a50797b0'
    'f85b62d08b1dd2d8e43b4a5bfbb159ed578ef7475de0ada13e17ad87cc230567'
    '2bcc55a8881317fdc1bfc459b68b2df70cad3770ed0fd02d64b96f2bbf6f8f63'
    '2e866ca5d196d248ad05c3de644148a80b51ada95bd08d73cdbb45264f3bd113'
    '835b46f9be7b6d23a43bddfe1e7408c97031e1a8214bab46391044b700d38f51'
    '92c57fe6f87159b55512094e29d2cebab868c8f1adbad57077cbeb5e69658582'
    'bf98d19d64f44b0d50c7e2209ab3fc56b4f409123aaeb0263a22451bc14ed756'
    'd048385aedbb86a84677bb2d21c52cc9494147bf0fb102745282990909726228'
    '186e02c8')
C_ENC_IRONWOOD = bytes.fromhex(
    '1b9adb142498e3dcc76fed778614dd316c02fbb8ba9244ae4c2e32a07daeeca4'
    '1226b98bfe74f9fcb228cfc100f3180f5775ece38be7ed45d94021f4401b2a4d'
    '7582b428d49ec7f5b5a498973e60e38e74f5c3e577827c382857d8166b54e64f'
    '66ef5c7e8c9baa2a3fa9e37d087717d5e96bc2f73d031450dc2432ba49d8b74d'
    'b213099ea9ba04eb63b6574d46c03ce7900d4ac4bb188ee9030d7f69c895a94f'
    'c182f225a94f0cde1b49886871a376341ea94171befd95a830fa18407097dca5'
    '11025463d437e9695caa079a2f68cdc7f2c13267bff4195137fa8953252a81b2'
    'afa1582b9bfb4ac96037ed2991d3cbc7d54aff6e621b06a7b2b9caf2955efaf4'
    'ea8efcfd023a3c1748df3cbd43e0b9a8b0945688d52056c1d16eea37e798ba31'
    'dc3e5d4952bd51ec769d5788b6e35fe9042b95d4d21781400eaff58616ad5627'
    '96636a50b8ed6c7f981dc7ba814eff152cb228a2ead2f832662fa4a4a50797b0'
    'f85b62d08b1dd2d8e43b4a5bfbb159ed578ef7475de0ada13e17ad87cc230567'
    '2bcc55a8881317fdc1bfc459b68b2df70cad3770ed0fd02d64b96f2bbf6f8f63'
    '2e866ca5d196d248ad05c3de644148a80b51ada95bd08d73cdbb45264f3bd113'
    '835b46f9be7b6d23a43bddfe1e7408c97031e1a8214bab46391044b700d38f51'
    '92c57fe6f87159b55512094e29d2cebab868c8f1adbad57077cbeb5e69658582'
    'bf98d19d64f44b0d50c7e2209ab3fc56b4f409123aaeb0263a22451bc14ed756'
    'd048385aedbb86a84677bb2d21c52cc9494147bfa197dd4326a43baa347044f2'
    'bdb49861')

# RECIPIENT as an Orchard-only mainnet unified address, encoded with
# librustzcash's zcash_address 0.13.0. 106 characters -- three full body rows
# on their own, which is the entire reason the confirm needs two screens
# instead of one.
EXPECTED_UA = ('u17j4lvw84jd238ev9ukr0lvqhv4z32v98pxcglctaj3aqfqj7rr2wwvh73247ek'
               'czw4smyrvm2wf2v5nfxvn3sl0ycc6w4455yg49yf2m')

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


def note_action(cmx, recipient=RECIPIENT, value=VALUE, rseed=RSEED,
                c_enc=C_ENC_ORCHARD):
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
        'epk': EPK,
        'enc_compact': c_enc[:52],
        'enc_memo': c_enc[52:564],
        'enc_noncompact': c_enc[564:],
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
        # A v6 transaction streams and verifies only its Ironwood actions, so
        # its Orchard bundle must be EMPTY -- and provably so. This used to be
        # b'\x00' * 32, arbitrary filler, with a comment noting that the field
        # "only feeds the locally derived sighash". That was the bug: the
        # device signed a sighash committing to an Orchard bundle it never
        # inspected, and a host could point it at a real bundle spending the
        # victim's note, reusing an approved action's alpha so the one emitted
        # RedPallas signature verified in both bundles.
        #
        # ZIP-229 v6 empty-bundle digest: BLAKE2b-256 of the empty string
        # personalized "ZTxIdOrchardH_v6". The v5/ZIP-244
        # "ZTxIdOrchardHash" value is a different digest.
        kwargs['orchard_digest'] = bytes.fromhex(
            'a3367d2fdea2910159fc5026e9bf1fccd3e28ce5e6de46bfb71587230eea9515')
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


# Matches client.SCREENSHOT_SETTLE_SECONDS; the emulator needs a moment to
# finish drawing after ButtonRequest before read_layout() is meaningful.
BUTTON_RENDER_SETTLE_SECONDS = 0.5


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
            # The firmware emits ButtonRequest immediately BEFORE drawing the
            # confirmation, so the framebuffer must be allowed to settle first.
            # original(msg) does contain that delay, but it runs after this read
            # and then presses the button -- so reading before it captures a
            # partially drawn (or previous) screen, and reading after it captures
            # the NEXT one. Settle here instead.
            #
            # Unconditional, unlike client.callback_ButtonRequest's SCREENSHOT-only
            # sleep: these are structural assertions, not screenshot evidence, so
            # they need a settled layout on every run.
            time.sleep(BUTTON_RENDER_SETTLE_SECONDS)
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
        # The canonical 7.15 product includes the separated amount/address
        # confirmation. Exercise it instead of inheriting RC18's old skip.
        self.requires_firmware("7.15.0")
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

    def test_corrupted_note_ciphertext_is_refused(self):
        """A note the recipient cannot decrypt must not be signed.

        The commitment alone does not reach the recipient: a host could keep a
        valid cmx and corrupt the ciphertext, recomputing the bundle digest to
        match, and the payment would be invisible to normal wallet scanning.
        The device decrypts with the key derived from rseed and rho and must
        refuse before the output screens.
        """
        c_enc = bytearray(C_ENC_ORCHARD)
        c_enc[52 + 100] ^= 0x01                                  # one memo bit
        actions = [note_action(CMX_ORCHARD, c_enc=bytes(c_enc))]

        with self.assertRaises(Exception) as caught:
            self.client.zcash_sign_pczt(**sign_kwargs(actions))
        self.assertIn('ciphertext mismatch', str(caught.exception))

    # Canonical release/7.15 includes Ironwood handlers and the corresponding
    # native commitment vectors. These regressions apply to that product.
    IRONWOOD_FIRMWARE = "7.15.0"

    def test_pool_selection_is_honoured(self):
        """The same note commits differently in each pool.

        Orchard and Ironwood derive a different cmx from identical inputs, so
        offering the Orchard commitment while declaring the Ironwood pool must
        be rejected. If the device ignored shielded_pool this would pass.
        """
        self.requires_firmware(self.IRONWOOD_FIRMWARE)
        actions = [note_action(CMX_ORCHARD)]

        with self.assertRaises(Exception) as caught:
            self.client.zcash_sign_pczt(**sign_kwargs(actions, ironwood=True))
        self.assertIn('commitment mismatch', str(caught.exception))

    def test_ironwood_rejects_a_non_empty_orchard_bundle(self):
        """A v6 transaction may not carry an unverified Orchard bundle.

        The device streams and verifies only the ACTIVE pool's actions. On the
        Ironwood path that is the Ironwood bundle, so an orchard_digest other
        than the empty-bundle value describes a bundle the device never
        inspected yet still commits to in the sighash it signs.

        That was exploitable, not merely untidy: point orchard_digest at a real
        Orchard bundle spending one of this seed's notes, reuse the alpha of an
        approved Ironwood action so rk is byte-identical, and the single
        RedPallas signature the device emits verifies in BOTH bundles, because
        verification is [s]G = R + [H(R||rk||M)]rk and rk and M are shared. The
        Orchard bundle's valueBalance never enters the device's fee check.
        """
        self.requires_firmware(self.IRONWOOD_FIRMWARE)
        actions = [note_action(CMX_IRONWOOD, c_enc=C_ENC_IRONWOOD)]
        kwargs = sign_kwargs(actions, ironwood=True)
        # Anything but the ZIP-229 v6 empty-bundle digest must be refused.
        kwargs['orchard_digest'] = bytes([0x11]) * 32

        with self.assertRaises(Exception) as caught:
            self.client.zcash_sign_pczt(**kwargs)
        self.assertIn('empty Orchard bundle', str(caught.exception))

    def test_ironwood_note_is_accepted(self):
        """The Ironwood commitment for that same note is accepted.

        The positive half of the pool test -- together they prove the branch is
        selected by shielded_pool rather than one path serving both.
        """
        self.requires_firmware(self.IRONWOOD_FIRMWARE)
        actions = [note_action(CMX_IRONWOOD, c_enc=C_ENC_IRONWOOD)]
        screens = self._capture_button_screens()

        result = self.client.zcash_sign_pczt(**sign_kwargs(actions, ironwood=True))

        self.assertIsInstance(result, zcash_proto.ZcashSignedPCZT)
        outputs = [c for c, _ in screens
                   if c == proto_types.ButtonRequest_ConfirmOutput]
        self.assertTrue(len(outputs) == 2,
                        "expected 2 ConfirmOutput screens, got %d" % len(outputs))


if __name__ == '__main__':
    unittest.main()
