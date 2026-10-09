"""ZIP 320 TEX payments.

A TEX address (tex1..., bech32m) wraps a P2PKH key hash and takes only
transparent funds, so a wallet pays it from shielded funds in two
transactions: one to its own one-time address m/44'/133'/account'/2/index,
then a transparent-only one from that address to the TEX recipient.

Both transactions are built by librustzcash (zcash_primitives
Builder::build_for_pczt, pczt Creator + IoFinalizer; orchard 0.16.0) for the
"all" seed, account 0, on regtest, and the sighashes are librustzcash's pczt
Signer sighashes:

  step 1 (v6, NU6.3): one 1,025,000-zat Orchard note to the one-time address,
    1,010,000 zat, fee 15,000, a 2-action Orchard bundle;
  step 2 (v6 NU6.3 and v5 NU6.2): that output to the ZIP 320 example address
    tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte, 1,000,000 zat, fee 10,000,
    with no shielded bundle at all.
"""

import hashlib

import ecdsa
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der

import common
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib import messages_zcash_pb2 as zcash_proto
from keepkeylib.client import CallException

from test_msg_zcash_sign_pczt_device import (
    ADDRESS_N,
    ANCHOR,
    IRONWOOD_TX,
    ORCHARD_TX,
    bundle_digest,
    header_digest,
    migration_action,
)
from test_msg_zcash_transparent_shielding import (
    _b2b,
    _outputs_digest,
    _prevouts_digest,
    _sequences_digest,
    _transparent_sig_digest,
)

H = 0x80000000
ONE_TIME_PATH = [H + 44, H + 133, H, 2, 0]
TEX_FIRMWARE = "7.15.0"

ONE_TIME_SCRIPT = bytes.fromhex(
    '76a9142875b160968fae11ca7fdd0174825c812f24f05688ac')
ONE_TIME_T1 = 't1MZY2TFhahiyGL9fscjCAjhppXGn48oHMM'
TEX_SCRIPT = bytes.fromhex('76a9148286bf790866805397e3a947640b77a43f0b43a588ac')
TEX_ADDRESS = 'tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte'
TEX_T1 = 't1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC'  # the same key hash (ZIP 320)
EMPTY_SAPLING = hashlib.blake2b(b'', digest_size=32,
                                person=b'ZTxIdSaplingHash').digest()

STEP1 = {
    'sighash': bytes.fromhex('981da2d23dcdd6c04e5d36aa00cca4eb6d21cd4aa1af6547bacc5ab8d9764e7d'),
    'actions': [
        {
            'is_spend': False,
            'nullifier': bytes.fromhex('a593b9cd40c49a4f447d87ed1f01b5896b1135ee7739d7fdb04ad1a6eeda232f'),
            'rk': bytes.fromhex('6742b6a24175e6157151140a7ed464e4236a78785183c58a0eadc9a00e22dea4'),
            'alpha': bytes.fromhex('0b9ad8d7306dba1cb592962db3ffec30ca18fe3cdcef51c199eaad4615b57d3e'),
            'cv_net': bytes.fromhex('a41f06ec4122d79c0442c06a04c8d9a623c87d94a1e994787ec2acfb13288587'),
            'cmx': bytes.fromhex('ff61e8171bc34a00c43a2824b016c089b467313e51e02d776dcbc13c4dc7d10f'),
            'epk': bytes.fromhex('676ed987d25b96b7ff4ef38bf414f74e884e79012ba1db7d6090e37d7e9cb126'),
            'enc': bytes.fromhex(
                'ffd7c80499607ed7ff8ccf36ea23890a40dbfbe7e1e2f4c4ecc9c719ec38bfd3'
                '7022afc69a91121396c96183645bc6f2cf4a8b2c1455fb81ce815ed964e2788e'
                '7db82875c8d9a6ac4235b5d1ac954b906c7181b97ed1aae6641b2d2ed4a41d20'
                '5b61d2bf0faabfa6512ffdaff000525efb96acf524120155847b45e3938e30c8'
                '310202deb697351458742efe591c95865f2348c220d17318dcacf183e4ae6e15'
                '302a4bcea524810ae1c70d50ee0aa9dd90546e7a6345922297220454c6a97b44'
                '4a926be368679a31535c95932daeb1aed9fcda3000cf0963c4105fd9bc6fd24b'
                '84062be96d06debd41f20332dc4d4291ec2b2f9364ba0f6cbc6f90da6729d0ee'
                'c6417a722c38c893f7e9113698f4ecde3ec560c37d88a8bd6bd04f2b1d86a06e'
                '84695c69b0333913ae81492981b4bff367998995ea689a705113346cb81ccdad'
                '6cbc5fc0733b97cefb92ce0b335bab1f492ac38da4c2384c005d7e2a352467d2'
                'e8544f9664df46950a3207edcfefd983e8495f53c214f19a9024c0c54a15fa75'
                'b80166313f550dbe42fa71704620bb78ed7273d5e5af8760b330278306da8098'
                'da3cbf3a640dc60aea3642e2b59a7902e61f89d3396c25d4692881f7de250e51'
                'e72300866c789036f550c3008b3865c89101b8925fee8abcddbd08b72ae9933f'
                '812f52f5d7705a105f66d0b4dfd16bde4211a08c6740c3887b1356a1744ddd81'
                '6f7c6e9dd2d682df1d14603ad69aa684587ea09c2fd25f746798c604fa3d7b07'
                'cb1ab7170a18b380cdd2fd3d539039d21a1e264d4cc9803170c3931408d2fd2c'
                '16310cf7'),
            'out': bytes.fromhex(
                '8e54a7b6418db19c27eb768c3c754113eaa575de83023862634fb40ccb87c17c'
                '043be6f0d883754e2fd337dae19d79fe27c4904ab28ffc360681ffb6f8e871ed'
                'fd6684d6b5e23c4e0ec28d3a951f5d3f'),
            'recipient': bytes.fromhex(
                '66faa653531d4a8acdf5096f756577b19962df6615641e5fe2db3a324970a7ff'
                'e546a1f97b073e94f7b238'),
            'rseed': bytes.fromhex('716070a992fff0e13dd67cc3ddaef4ada426aa5f4ec0f13668a6f4f537ad545e'),
            'value': 0,
        },
        {
            'is_spend': True,
            'nullifier': bytes.fromhex('0440da65e51ce699977111262432473c28e06b12c3e5e38fc742f35b0fd02429'),
            'rk': bytes.fromhex('fec66ad4c564961f7af701ffbc1f1e2eb3abf8b4bbf1404d60aa9efc0881e585'),
            'alpha': bytes.fromhex('83969789048b1dc71a91d523c61624cc84894ddd64c4b8dc4380e08a327f4820'),
            'cv_net': bytes.fromhex('c7343ce3e707ccdbfac1e3cae1acbef5701e793e107efe264d027af10ab73e31'),
            'cmx': bytes.fromhex('a34f6a687d5ad6aae53f0225144324a070a7de1066a9c592af9d51ea0da78b1b'),
            'epk': bytes.fromhex('0e4237147546d913c2273bb3a70f6e3cbbd8b9f839c89cc1f8a26ecaa2aba986'),
            'enc': bytes.fromhex(
                'd878f9142e82cfdcc5abb5f3d6b4b32978a6b8f3163cf48cd167abfb8512e352'
                '04e7edd316c39e5c9a01be0efab1707355bb93d9b968c50820f27b6bb20415a6'
                '0213dbf69f95554b56bac05cceae2f2f227b7c03925e87374fb1f9c3c0d723e8'
                '9fc80fa61c863fc04aa061c91cc81c484d086d2ab66125532d89a530ee6f07e6'
                '7941805f62784c8a8dec22a230506f9cb74e4c7dcaff00c4224543b052aa9f6b'
                '6db1837090f7fd87536d326866a8694dbe41b3b388cca38e6e546af80af68e9f'
                '8b24abb381fe57b6731dd686c179bea116a8e3be9fe041488d46634bda302abd'
                '027249fb2508bfc5260b286f0ab66a9c32c07fe1796c767b266d30d752e77840'
                '320ba9d7669c0ed9fe5b3c488856e84ab3674e4deed92225c4be2f31f56d4963'
                'b4bfc5f0fe686fc01950a9c5b6a95024086c566bfa7f1ce88fd6785660e60cbc'
                '0b2e881a4dacfdea6b9158717dd5d0aba72b30dd067f7c32b1e08f9a714a5965'
                '6567ea0fa3dbc31c12cdacbcefb9c42d832ae8cfea003fea36a32327f44ce8ac'
                '0d9aff4bccf03539cf037d5c2dfb114c2b027328660b0abbab07554015b9ab8d'
                '284db47c04b117e2a4365cd14f10c0416082d8615e36fa1bc5243c9d76902b99'
                'c87fb5d635b94157915fd979747247b5294006d2a74dce6c7c666e3d9c1bea5f'
                'b0124b846b22e217c6732817a13b72111395f496220af07bc8732e7d4a0f353c'
                'ff5b4c453915b5bee84ec00f817f51ff05d09138e7460727637641b178982a53'
                '3ca4618a251b2f92d7b73e5d31f3d56693964a014418d767dc23c6b522d2a695'
                '2a3d3200'),
            'out': bytes.fromhex(
                '93148f0d468fa8c829f1499a4fa7acb16a99a2cd42b958397dffb46b2e34370e'
                'a2168063cfe245932eb4d828a461ad6a1f9951f2752b2ff9333893aa9045008a'
                '1b0bf265077c00d84d6617524e341439'),
            'recipient': bytes.fromhex(
                'da973031634a8938ad1c480f978780693ec7709ba5caf58d8a7eb945586cbed6'
                '45520f17387437bcfdc216'),
            'rseed': bytes.fromhex('ab6fed1774ced71e695168fc591b9cfc196b7297ac0486db880fb455b1a0f3ee'),
            'value': 0,
        },
    ],
}

STEP2 = {
    6: dict(IRONWOOD_TX,
            prevout_txid=bytes.fromhex(
                '981da2d23dcdd6c04e5d36aa00cca4eb6d21cd4aa1af6547bacc5ab8d9764e7d'),
            sighash=bytes.fromhex(
                '03e328bb6a70c20bd803375f2da51bcd56d1e46fba7f6408752de160fc7234a5')),
    5: dict(ORCHARD_TX,
            prevout_txid=bytes.fromhex(
                '7d2c9e83172282b3d4521c9c16632bae0ef19dbaaa8188cb46761f510574b621'),
            sighash=bytes.fromhex(
                '89c5074214b150ff73a3d80fa893e1b66c41e96be1f67b504740a27b16a4f6e6')),
}


def transparent_digest_no_inputs(outputs):
    """ZIP-244 T.2: with no transparent input the shielded sighash commits to
    the transparent txid digest, not the S.2 signature digest."""
    return _b2b(b'ZTxIdTranspaHash', _prevouts_digest([]) +
                _sequences_digest([]) + _outputs_digest(outputs))


def step1_kwargs(output):
    actions = [migration_action(v) for v in STEP1['actions']]
    tx = IRONWOOD_TX
    kwargs = dict(tx)
    kwargs.update({
        'address_n': ADDRESS_N,
        'actions': actions,
        'account': 0,
        'fee': 15000,
        'lock_time': 0,
        'expiry_height': 69120,
        'orchard_flags': 0x03,
        'orchard_value_balance': 1025000,
        'orchard_anchor': ANCHOR,
        'header_digest': header_digest(tx['tx_version'], tx['version_group_id'],
                                       tx['branch_id'], 0, 69120),
        'orchard_digest': bundle_digest(actions, False, 6, flags=0x03,
                                        value_balance=1025000),
        'transparent_outputs': [output],
        'transparent_digest': transparent_digest_no_inputs([output]),
    })
    return kwargs


def step2_parts(version):
    tx = STEP2[version]
    output = {'amount': 1000000, 'script_pubkey': TEX_SCRIPT, 'is_tex': True}
    inp = {
        'address_n': ONE_TIME_PATH,
        'amount': 1010000,
        'prevout_txid': tx['prevout_txid'],
        'prevout_index': 0,
        'sequence': 0xffffffff,
        'script_pubkey': ONE_TIME_SCRIPT,
    }
    return tx, output, inp


def step2_kwargs(version, output, inp):
    tx = STEP2[version]
    kwargs = {k: tx[k] for k in ('tx_version', 'version_group_id', 'branch_id')}
    kwargs.update({
        'address_n': ADDRESS_N,
        'actions': [],
        'account': 0,
        'fee': 10000,
        'lock_time': 0,
        'expiry_height': 69121,
        'orchard_flags': 0,
        'orchard_value_balance': 0,
        'orchard_anchor': ANCHOR,
        'header_digest': header_digest(tx['tx_version'], tx['version_group_id'],
                                       tx['branch_id'], 0, 69121),
        # The empty bundle digest: ZIP 229 for v6, ZIP 244 for v5.
        'orchard_digest': hashlib.blake2b(
            b'', digest_size=32,
            person=b'ZTxIdOrchardH_v6' if version == 6
            else b'ZTxIdOrchardHash').digest(),
        'sapling_digest': EMPTY_SAPLING,
        'transparent_outputs': [output],
        'transparent_inputs': [inp],
        'transparent_digest': _transparent_sig_digest([inp], [output]),
        'return_transparent_signatures': True,
    })
    return kwargs


class TestZcashTex(common.KeepKeyTest):

    def setUp(self):
        super(TestZcashTex, self).setUp()
        self.requires_firmware(TEX_FIRMWARE)
        self.requires_fullFeature()
        self.requires_message("ZcashSignPCZT")
        self.setup_mnemonic_allallall()

    def _capture_confirm_text(self):
        screens = []
        original = self.client.callback_ButtonRequest

        def capture(msg):
            # A paged confirmation asks once per page; keep each one once.
            title, body = self.client.debug.read_confirm_text()
            if not screens or screens[-1][1:] != (title, body):
                screens.append((msg.code, title, body))
            return original(msg)

        self.client.callback_ButtonRequest = capture
        return screens

    def _one_time_pubkey(self):
        node = self.client.get_public_node(ONE_TIME_PATH, coin_name='Zcash').node
        return bytes(node.public_key)

    def _refused(self, kwargs, message):
        with self.assertRaises(CallException) as ctx:
            self.client.zcash_sign_pczt(**kwargs)
        self.assertEqual(ctx.exception.args[1], message)

    def test_one_time_address_matches_librustzcash(self):
        """The fixture's one-time address is the device's own key at
        m/44'/133'/0'/2/0 (TransparentKeyScope::EPHEMERAL)."""
        pubkey = self._one_time_pubkey()
        self.assertEqual(
            ONE_TIME_SCRIPT,
            b'\x76\xa9\x14' + hashlib.new(
                'ripemd160', hashlib.sha256(pubkey).digest()).digest() +
            b'\x88\xac')

    def test_step1_pays_the_own_one_time_address(self):
        """With its path, the output is proven to pay the account's one-time
        address and is shown as a transfer to yourself; the one wallet spend
        is signed."""
        self.requires_firmware(TEX_FIRMWARE)
        screens = self._capture_confirm_text()
        output = {'amount': 1010000, 'script_pubkey': ONE_TIME_SCRIPT,
                  'address_n': ONE_TIME_PATH}

        result = self.client.zcash_sign_pczt(**step1_kwargs(output))

        self.assertIsInstance(result, zcash_proto.ZcashSignedPCZT)
        self.assertEqual(len(result.signatures), 1)
        self.assertEqual(
            [(title, body) for code, title, body in screens
             if code == proto_types.ButtonRequest_ConfirmOutput],
            [('Zcash Output', 'To your one-time address:\n%s\n'
              'Amount: 0.01010000 ZEC' % ONE_TIME_T1)])
        self.assertEqual(screens[-1][1:],
                         ('Zcash Fee',
                          'Confirm transaction fee?\n0.00015000 ZEC'))

    def test_step1_without_a_path_is_a_plain_send(self):
        """Without a path the device cannot know the address is the user's own,
        so it is shown as a payment to that t1 address."""
        self.requires_firmware(TEX_FIRMWARE)
        screens = self._capture_confirm_text()
        output = {'amount': 1010000, 'script_pubkey': ONE_TIME_SCRIPT}

        result = self.client.zcash_sign_pczt(**step1_kwargs(output))

        self.assertEqual(len(result.signatures), 1)
        self.assertEqual(
            [body for code, _, body in screens
             if code == proto_types.ButtonRequest_ConfirmOutput],
            ['Send transparent ZEC?\n%s\nAmount: 0.01010000 ZEC' % ONE_TIME_T1])

    def test_step1_refuses_a_path_that_does_not_pay_the_script(self):
        self.requires_firmware(TEX_FIRMWARE)
        for path, message in (
                (ONE_TIME_PATH[:4] + [1],
                 'Transparent output script does not match path'),
                (ONE_TIME_PATH[:3] + [0, 0],
                 'Output path must be a one-time address'),
                ([H + 44, H + 133, H + 1, 2, 0],
                 'Account does not match approved session')):
            output = {'amount': 1010000, 'script_pubkey': ONE_TIME_SCRIPT,
                      'address_n': path}
            self._refused(step1_kwargs(output), message)

    def test_step2_signs_a_transparent_only_transaction(self):
        """No shielded action: the TEX recipient is shown as tex1..., then the
        fee and the input, and the one ECDSA signature verifies under
        librustzcash's sighash, in v6 and v5."""
        self.requires_firmware(TEX_FIRMWARE)
        pubkey = self._one_time_pubkey()
        key = VerifyingKey.from_string(pubkey, curve=SECP256k1)
        for version in (6, 5):
            tx, output, inp = step2_parts(version)
            screens = self._capture_confirm_text()

            result, signatures = self.client.zcash_sign_pczt(
                **step2_kwargs(version, output, inp))

            self.assertIsInstance(result, zcash_proto.ZcashSignedPCZT)
            self.assertEqual(len(result.signatures), 0)
            self.assertEqual(len(signatures), 1)
            self.assertTrue(key.verify_digest(signatures[0], tx['sighash'],
                                              sigdecode=sigdecode_der))
            self.assertEqual(
                [(title, body) for _, title, body in screens],
                [('Zcash Transparent', 'Send transparent ZEC?\n'
                  'Fee: 0.00010000 ZEC\nInputs: 1\nOutputs: 1'),
                 ('Zcash Output', 'Send to TEX address?\n%s\n'
                  'Amount: 0.01000000 ZEC' % TEX_ADDRESS),
                 ('Zcash Fee', 'Confirm transaction fee?\n0.00010000 ZEC'),
                 ('Sign Input',
                  'Sign transparent input?\nInput 1: 0.01010000 ZEC')])

    def test_step2_without_the_hint_shows_the_t1_address(self):
        """is_tex is only a display hint: without it the same key hash is shown
        in its t1 form, and the transaction signs the same."""
        self.requires_firmware(TEX_FIRMWARE)
        tx, output, inp = step2_parts(6)
        del output['is_tex']
        screens = self._capture_confirm_text()

        _, signatures = self.client.zcash_sign_pczt(
            **step2_kwargs(6, output, inp))

        self.assertEqual(len(signatures), 1)
        self.assertEqual(
            [body for code, _, body in screens
             if code == proto_types.ButtonRequest_ConfirmOutput],
            ['Send transparent ZEC?\n%s\nAmount: 0.01000000 ZEC' % TEX_T1])

    def test_transparent_only_refusals(self):
        """A transparent-only request is refused with no signature when it
        claims a shielded bundle, a non-empty Sapling digest, or an input path
        outside the session account or past the one-time scope."""
        self.requires_firmware(TEX_FIRMWARE)
        tx, output, inp = step2_parts(6)
        other_account = dict(inp, address_n=[H + 44, H + 133, H + 1, 2, 0])
        change_3 = dict(inp, address_n=ONE_TIME_PATH[:3] + [3, 0])
        cases = (
            ({'orchard_digest': b'\x01' * 32},
             'Transparent transaction must have empty shielded bundles'),
            ({'orchard_value_balance': 5000},
             'Transparent transaction must have empty shielded bundles'),
            ({'sapling_digest': b'\x11' * 32}, 'Sapling not supported'),
            ({'transparent_inputs': [other_account],
              'transparent_digest': _transparent_sig_digest(
                  [other_account], [output])},
             'Account does not match approved session'),
            ({'transparent_inputs': [change_3],
              'transparent_digest': _transparent_sig_digest(
                  [change_3], [output])},
             'Change must be 0, 1 or 2'),
        )
        for overrides, message in cases:
            kwargs = step2_kwargs(6, output, inp)
            kwargs.update(overrides)
            self._refused(kwargs, message)

    def test_no_action_needs_a_transparent_input(self):
        """n_actions 0 with nothing to sign is refused before any screen."""
        self.requires_firmware(TEX_FIRMWARE)
        tx, output, inp = step2_parts(6)
        kwargs = step2_kwargs(6, output, inp)
        for key in ('actions', 'transparent_outputs', 'transparent_inputs',
                    'return_transparent_signatures'):
            del kwargs[key]
        kwargs.update(n_actions=0, n_transparent_outputs=1)
        response = self.client.call_raw(zcash_proto.ZcashSignPCZT(**kwargs))
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.message, 'No actions specified')
