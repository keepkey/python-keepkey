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


# --- a real NU6.3 Orchard bundle -------------------------------------------
# Built by the orchard 0.16.0 crate (Builder with BundleVersion::orchard_v3()
# and Flags::CROSS_ADDRESS_DISABLED, then build_for_pczt) for the "all" seed,
# account 0: a 100000-zat spend and a 90000-zat change output, fee 10000.
# With cross-address transfers disabled the builder pairs the spend with a
# fabricated zero-valued output to the spent note's own receiver whose
# enc_ciphertext is random bytes (ZIP 326), and the change with a fabricated
# zero-valued wallet spend. Both spends are the wallet's, so rk is this seed's
# ak re-randomized by alpha and the device signs both actions.
FABRICATED_BUNDLE = [
    {
        'nullifier': bytes.fromhex('aed05ebddc392dda842311207fbc3fa84fb454f43fcfac292d87a3e8300ee112'),
        'rk': bytes.fromhex('2c1b8779ac1aca3abec73dfe9b8635be2fae970dfe76237495042fed96c3849f'),
        'alpha': bytes.fromhex('f081a5920a807a9189bc48f6ef5916b48effd77745c905def34316c2af87290c'),
        'cv_net': bytes.fromhex('e80cb524dfe437bebaaeffec6c4543a7f64f48fa4bfa03e1847641b184c3da1d'),
        'cmx': bytes.fromhex('6685ca96b57a11cae02c5c562b3f999713d06fadc697444e4c34f022a1df752a'),
        'epk': bytes.fromhex('e56229ea7072ff2dac9e9d0d3545bc13511e55b849089d3244e3d6667466872c'),
        'enc': bytes.fromhex(
            '8807db653fc5d70f3382f580c2283ed388a87134aec35d3f1108efea6df55ef0'
            'b61eaa33b79f8d53b6a3fb791c83b75876186f6e404ca22e3246bd3d6ee956f6'
            '983d2f7efb6cbb27571832127afd4f48136bdab4ebc68bc2a7c667a4ab231030'
            '19ecd43212a1b6e47307949de23f82998fb33d3f3d15abefaa8052026b17d172'
            '1a508d8af11baa74df8f2f67c3be1a92bea530039b4920a0efedc8ee934485b2'
            'aecd88b5af781c8614d968236504d40d58d64875a808aae0995bb14577c89a26'
            '564f7be2d8a8e871ca8caaeb04c7af0023b25d6930745b0fce3d1b01575d68b9'
            '8965500c6de13f84b14052e24cca3bbe8aa0570ca4196b18a4b2cada1ddd039c'
            '4d6038c809426d1eed7674efb6990b040035cc1b92952dae4d642f9c4c613572'
            '59dc961c5f208a14387b7d8f9b4f5e502a09aa1d292d33e72b489bb5e5cf4ede'
            '7e239d96d07139f9270ec5a3305da1013f0a5b6de6860af11a212c77fe5c1cb9'
            '73888cbc1100e0e07423e879e40365844c2ca9a75b16ed4d032127470ca0e0bd'
            '5de907a32b3aea36512929f5b83863bc1d63b40fce26dc4d58472ec15f2fadd2'
            '24c16985bd5ab01e388502dd22596fe85012a9f74e2ea6c9b9aca2b7bc2298ed'
            '779c61285753e6ba92f0a1a963f33750c105122c7e5ec92d95e2f454e0556682'
            '25ebf956231f22a139c3c31fdb7e4a4a214d296765353e0e45269cef2eebdbf7'
            'e53e3743c4266eb705d30ea2cb567e370eda979b44f33ee2f6233dc8e1f5e844'
            'ff66891d37165675e63b2a10722381a55a92b006dd793ca832010a002d3021ab'
            '5e526af9'),
        'out': bytes.fromhex(
            'a5fe4a96ac820c57db11db73741c6fee879c90635e16c5fd60967be70c58f27d'
            '85e4a135ac87ecc858d88b34df846b2af6035683c138b97876c373328076e8ce'
            'f61c5989e4fee41ed2334b932f947f82'),
        'recipient': bytes.fromhex(
            'da973031634a8938ad1c480f978780693ec7709ba5caf58d8a7eb945586cbed6'
            '45520f17387437bcfdc216'),
        'rseed': bytes.fromhex('c29d5ab216448f6ebf6388a6251160e7c9fe2413c85ac1cd2340363807ba8840'),
        'value': 0,
    },
    {
        'nullifier': bytes.fromhex('31aafc80063db2af87ffdee21267ccd1f8a6eda982f7c5816b8f1d99ee580217'),
        'rk': bytes.fromhex('defbdcf42d021aa013d14a391b3cefa8ce94ac9cac96481bfddecab3f2065e06'),
        'alpha': bytes.fromhex('a16c066adf9a10e1696c4fa884a67f93b24d858e8cf06743304ad6cae69a1b06'),
        'cv_net': bytes.fromhex('fd260057cb02e71c9d37554c7fb496b48d5412c1c2707fcf0c8601946dd04c12'),
        'cmx': bytes.fromhex('e35568cf21a2befafa3d8bbd2bf6a19bcdbfe6b6234c303004ba38ba76afed3f'),
        'epk': bytes.fromhex('9b9efea983df2470cfc8d28bcf8c5bfd4f714e6bc08b0a15ab3611b0c7b56101'),
        'enc': bytes.fromhex(
            'b82f1b13e501868055a3f88433481172ee1173402227637b46be3e63cd3fa939'
            '93af3074450b558a4d6ff8ee65bdb04962077060b5c258b3d0f7bc21ec7df69a'
            'a0898c47b6d913186a13fa21c420f0da48e72d167bc3e08bffa1f16d99a11aad'
            '65cf98cc0a0ce37ec679c03dc7c6f1fe9feb619b4eca0c5823f6d413c7a5be12'
            '2aee48f070770d163fde8ad4862df692d4433afe053e6b9e1a50e6cc8cbd37aa'
            '54ce3e014e3dd342496855226cd65896442300161e242a8c4d7b2c19c83df04f'
            'f3ab7c7afcb9fb486d28bda503260b758ac473b618cce25b9d0daf8bafbe64ee'
            '3d52f804c33ee78e25fe5bd6a105d4a1cde143e2d047f0fee8e9cb3645964688'
            '2eb5ade60a1ff79284b81ee817d638ad5e1da8052266171b320a8bf4ec337df3'
            'ebcf087de768b46404f45a23208c8358c644e626152d67cf4e2efa94ff9ac2dd'
            'b8e3c670360523c238f1cc3b961dedade8e90de90927841745c5398f140ac053'
            '8d48561bb372a367933147d239c500c238cf294d05e93c473378f59708f5aefb'
            '375d23df2d0fc1a8f0de90c8fdb6cbb0036eef778c1bdca2731c7fe23a0331ee'
            '4ceb357a52ce552ca0626891f5362c1983fb2656f91b372f0559de8943a9e555'
            '30bc009ede7c222f8748ade9762270f937725a25401ad5a4fdc01a3f1f100289'
            'c5a291b9bfc3bc696e0af71e7199f6555b53ed875aa7ebdfeba1cd3f8c711190'
            'c6d5c64059483983834faf47283ca15682c4966070425d0f305cad882901d70f'
            'd222a8bfeb2077541449b73ce56a8d08aa623c06aa8b38e675eb17fd162b862d'
            '5f777396'),
        'out': bytes.fromhex(
            '28c960f201269936a006ae1cc2cd358b29f981dc52d10448a3c02479855bf89c'
            'ff2a654493f29035ff20daf3ce97d13d514bca41d0d298d0c40834248d1f617f'
            '3db9516428eeca01be53af1da897071e'),
        'recipient': bytes.fromhex(
            'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
            'f0bb27c032b2e7718c962e'),
        'rseed': bytes.fromhex('c53e0dc6ce5562fbf35fd57698514207df3cb42161093b070ba16bffcb93fdd9'),
        'value': 90000,
    },
]


def fabricated_action(v):
    return {
        'alpha': v['alpha'],
        'nullifier': v['nullifier'],
        'cmx': v['cmx'],
        'epk': v['epk'],
        'enc_compact': v['enc'][:52],
        'enc_memo': v['enc'][52:564],
        'enc_noncompact': v['enc'][564:],
        'cv_net': v['cv_net'],
        'rk': v['rk'],
        'out_ciphertext': v['out'],
        'is_spend': True,
        'value': v['value'],
        'recipient': v['recipient'],
        'rseed': v['rseed'],
    }


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

    # ZIP 374 user_address. Both addresses are real librustzcash output:
    # MULTI_RECEIVER_UA is RECIPIENT plus a Sapling and a P2PKH receiver
    # (zcash_address 0.13.0); OTHER_ORCHARD_UA is the "all" seed's account-0
    # address at diversifier index 1 (zcash_keys 0.16.1), a valid mainnet UA
    # whose Orchard receiver is not RECIPIENT.
    USER_ADDRESS_FIRMWARE = "7.15.0"
    MULTI_RECEIVER_UA = (
        'u16065qzvddm89jcmzufxjs5pe6dr006tezvd7pap2nc58cctca8tt373s2he7xx76cn'
        'lyfatutph9kfl5g35cnuw6szxlf0qhpqajh0xrujjny6rxh6wej6mx6x5zuz4auaffd5'
        'hd56t8kwxnnquasruhg8qv3344cn6dauw00waq8ak2lmlyn8r84jumahr2nrd246gdxw'
        '932t8uvgs')
    OTHER_ORCHARD_UA = (
        'u1elnjt36zcqfelwj62v8lujthlqefztqcy02jfm2p5vs9phrzr8fj68j3mpzmvlktay'
        'k9fdz4zd4k3x6f7z3n62dw09w8sr9a8a0ka5m6xktd8hl6x5ekd0qky8h8t0an6p8eqk'
        '3ggwnl30dkv7txlw5r2qef330j94r0lftqktn0ev70kc78h8ev43ja5x7de27rvvhf0h'
        '4ku663uw6')

    def _capture_confirm_text(self):
        """(code, title, body) of each confirmation, as the firmware formatted it."""
        screens = []
        original = self.client.callback_ButtonRequest

        def capture(msg):
            title, body = self.client.debug.read_confirm_text()
            screens.append((msg.code, title, body))
            return original(msg)

        self.client.callback_ButtonRequest = capture
        return screens

    def test_user_address_is_checked_then_shown(self):
        """The address the user pasted is shown once it holds the recipient.

        The device decodes the Unified Address, finds its single Orchard
        receiver equal to the output's recipient, and shows the user's own
        string -- not the Orchard-only address it would otherwise rebuild.
        Ironwood outputs use the same Orchard receiver type.
        """
        self.requires_firmware(self.USER_ADDRESS_FIRMWARE)
        for ironwood in (False, True):
            action = (note_action(CMX_IRONWOOD, c_enc=C_ENC_IRONWOOD)
                      if ironwood else note_action(CMX_ORCHARD))
            action['user_address'] = self.MULTI_RECEIVER_UA
            screens = self._capture_confirm_text()

            result = self.client.zcash_sign_pczt(
                **sign_kwargs([action], ironwood=ironwood))

            self.assertIsInstance(result, zcash_proto.ZcashSignedPCZT)
            shown = [(title, body) for code, title, body in screens
                     if code == proto_types.ButtonRequest_ConfirmOutput
                     and title == 'Shielded recipient']
            self.assertEqual(shown,
                             [('Shielded recipient', self.MULTI_RECEIVER_UA)])

    def test_mismatched_user_address_is_refused(self):
        """A valid address that does not hold the recipient refuses signing.

        Nothing about the output is shown: the refusal comes before the output
        screens, so the user is never asked to approve the wrong address.
        """
        self.requires_firmware(self.USER_ADDRESS_FIRMWARE)
        action = note_action(CMX_ORCHARD)
        action['user_address'] = self.OTHER_ORCHARD_UA
        screens = self._capture_confirm_text()

        with self.assertRaises(Exception) as caught:
            self.client.zcash_sign_pczt(**sign_kwargs([action]))
        self.assertIn('does not match output', str(caught.exception))
        self.assertEqual([c for c, _, _ in screens
                          if c == proto_types.ButtonRequest_ConfirmOutput], [])

    def test_absent_user_address_shows_the_orchard_address(self):
        """Without user_address the device rebuilds an Orchard-only address.

        It is labelled as exactly that, since it is not what the user pasted.
        """
        self.requires_firmware(self.USER_ADDRESS_FIRMWARE)
        screens = self._capture_confirm_text()

        self.client.zcash_sign_pczt(**sign_kwargs([note_action(CMX_ORCHARD)]))

        shown = [(title, body) for code, title, body in screens
                 if code == proto_types.ButtonRequest_ConfirmOutput
                 and title == 'Orchard address']
        self.assertEqual(shown, [('Orchard address', EXPECTED_UA)])


    FABRICATED_OUTPUT_FIRMWARE = "7.15.0"

    def test_fabricated_zero_value_output_signs(self):
        """A real NU6.3 wallet transaction is not refused.

        From NU6.3 every Orchard spend is paired with a fabricated zero-valued
        output whose ciphertext is random bytes (ZIP 326), so it cannot decrypt
        to its note. Its cmx still binds value 0, so it pays no one: the device
        accepts it without a screen, shows only the change output and the fee,
        and signs both wallet spends.
        """
        self.requires_firmware(self.FABRICATED_OUTPUT_FIRMWARE)
        actions = [fabricated_action(v) for v in FABRICATED_BUNDLE]
        kwargs = sign_kwargs(actions, fee=10000, orchard_value_balance=10000,
                             total_amount=90000)
        kwargs['orchard_digest'] = bundle_digest(actions, False, 5,
                                                 value_balance=10000)
        screens = self._capture_confirm_text()

        result = self.client.zcash_sign_pczt(**kwargs)

        self.assertIsInstance(result, zcash_proto.ZcashSignedPCZT)
        self.assertEqual(len(result.signatures), 2)
        outputs = [body for code, _, body in screens
                   if code == proto_types.ButtonRequest_ConfirmOutput]
        self.assertEqual(len(outputs), 2)  # the change's amount and address
        self.assertIn('0.00090000 ZEC', outputs[0])
        for _, _, body in screens:
            self.assertNotIn('0.00000000 ZEC', body)

if __name__ == '__main__':
    unittest.main()
