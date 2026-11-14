"""7.17: Solana v0 lookup tables resolved by the host, and Token-2022 PYUSD.

Real mainnet messages (fetched 2026-10-29 with getTransaction, signatures
stripped), the same bytes as the firmware unit tests
(unittests/firmware/solana_real_vectors.h). Only the fee payer is swapped for
this seed's key so the device is a signer.

A v0 message names lookup-table accounts by index; the keys are not in the
signed bytes. With no proof (D-018: no online signer), firmware 7.17 takes the
host's resolution only to DECODE the review: every host-resolved key is shown
marked "from lookup table, not verified by KeepKey", the message stays a blind
sign under AdvancedMode, and a list that does not match the signed indexes is
refused.
"""
import unittest

import common
import keepkeylib.messages_solana_pb2 as messages
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

PATH = "m/44'/501'/0'/0'"

# Jupiter v6 swap, 0.039272743 SOL -> USDC; 17 static keys, 41 loaded.
# Signature 4BwHtwFcDw3UDfUMj4nZknJ4ybbn4yxvyCFGGKiMiuHPZz6sFMayF42aqkt3q9uCqrch9vhQiTCJkbTyNbmEC8qe
JUPITER = bytes.fromhex(
    '800100091143af0006aca4533038866a1015ba1c38f9a6996ae5796bc2478828250b8f2f'
    '60769ff54c7cef10de6fd781aa4736efb4b6e601c877076c21ecc587f8fed340adb608a3'
    'd6dad60a1ee96ff7053e5162ef24c18aefdd4d0247112743147048b684edf1b6fa21f7b7'
    '98161adaafbf691201ebaf1313f6e8a5de33a784529ff9af3e04783126072f42a9cd66ad'
    'd18d1b87bb310bf5830bccf55f6a2df17c011cd40cd0999af5ac90ed72537aeaea4ef504'
    '8c1c8e2f7fb2d34ec5a5e748f5bbf3b78bf18eae3ec0417c9354d858b918719637454f19'
    '1dc66b43bff93023c9a87097cceb20f3bc396099067401ccbe4cb7a40b618749c2142713'
    'e97482f17daf8f0cb00306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b'
    '3a400000008c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f8'
    '59000000000000000000000000000000000000000000000000000000000000000006ddf6'
    'e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90479d55bf231c0'
    '6eee74c56ece681507fdb1b2dea3f48e5102b1cda256bc138f140c09c3886c1c6a844f32'
    '931bcf04aac3178519b1c0fe53d4ff2a710eb4de3cb43ffa27f5d7f64a74c09b1f295879'
    'de4b09ab36dfc9dd514b321aa7b38ce5e8be939a8309f56407187fff30ac54b169498be9'
    '9f6d8e1bfd4244680cd4f7d1e20436b7dea1e6d6556d85e7981663cccef16234d6354136'
    '9a0bceaddb5a60e74874bc266537f1e93b95c448913c4cee4b21d7d07c9899a7d87f2500'
    'c72d23c7c3080800050289d4040008000903561e00000000000009060001002b0a0b0101'
    '0a0200010c0200000027415702000000000b0101011109060002002c0a0b01010c4c0d00'
    '010304022b2c0b0b0e0c331603051718191a1b1c1d1e1f0d340b0c0c350b36370d032021'
    '052223380d392403052526270b0628292a0c2d0d2e1105041213140b2f30312c3215070f'
    '100c37d19853937cfed8e901274157020000000035a63900000000006400000000000400'
    '0000134709000303730c00031a561100039c102703040b03010000010904a472ae1832a0'
    'b033bdefb1103ce96a03b57105247f946b7aeededcd4b7d71a16059195999a9b082a0696'
    '8f4a049293ba20c9530cf10afc52919675223a154adac9743de281c6d6e1198f90170633'
    'bd0aefebf3edf5f1eaecf4e802f2e95abd217dfcec25e8ce49d27509041243202cbccb67'
    '6544b18e9b68b38a572e63040903040603050802e2aef692e0c70672d4ac7172118ac916'
    '7fbbc09c992e9d9051b49a4e778bf0de07292e2d262f3023022724')
# meta.loadedAddresses: writable, then readonly.
JUPITER_LOADED = [bytes.fromhex(k) for k in (
    '1eb0abeabfb89ad1256ced27068d2e4545e7dbcf226fd80a7f870c0bb8b5d7cd',  # 34oUrDd3BMGf2nQTSDhqSioiD6t3VMAajQnvAu8eNn9r
    '5aff7fc8994b58cb8105eb36536155f4d0e91bdb1530316bfa95350644cba1a2',  # 78Df8z8qfrdvWioxrsQvw4NcgSZkqKkCPE1XJr6gkdGd
    'bcfe4125ead99d4a79e72b7c6286329a1331aa57e160b3552cf3dea6d0668427',  # DikWeTTT5sR2QMFDHR9AeH1eM6qHb91ELRFQJm3ABMVY
    '80e73b3c53b0a7d0309a507c72896dc89d7ef59e2771bf5c61964a4211b66883',  # 9gBgsqdhAtLDmZFS4GgNVjGQZ8TucRxgzYpskqSUGrGJ
    'f2a12b638c77ceb06d14a788612e8d6aa3037fab0e293c686212b8063ea090a5',  # HL8CiRp5xAHBQdnFymGRPsZVe5noRGkk9U14CTsViPEt
    'e411a1588cd135b1a497df220ce858a41ef176ba5e2619e47912e0ed7b32db25',  # GMHYkP8imvLHb4BmH68rpoj8stbpJ7JXPEUaBeaAUUHJ
    '432b0a1f9d68038a747e26a6a83a5348e799b2e14b811c8cee0bdb00e9012097',  # 5XCP3oD3JAuQyDpfBFFVUxsBxNjPQojpKuL4aVhHsDok
    'd3742176b89c5e14c96b748998421f38101e09e5c59331b168b625cd2715bb26',  # FERjPVNEa7Udq8CEv68h6tPL46Tq7ieE49HrE2wea3XT
    'b86064bf2acb185dc9ba1d4e8f7a406a22ff7ca8e77286d34d509c37aa5016c5',  # DQjGWHN9ERn1zSMpWLNvSpTFUSfnxbanBt9A7xyU2bVE
    'f617cd4510af70c761920499f8fe97d5b2311a69e19a17683ca2aaa48bec9a7d',  # HZeLxbZ9uHtSpwZC3LBr4Nubd14iHwz7bRSghRZf5VCG
    'c9963109f8909b3ca35001534d3fa75c8ae4942255b9c164aa220cfc7c4b4a2a',  # EZun6G5514FeqYtUv26cBHWLqXjAEdjGuoX6ThBpBtKj
    'd84e1290c198e788ba0e114f038214679608da28fcd20a1631efc393fbbf692a',  # FZN7QZ8ZUUAxMPfxYEYkH3cXUASzH8EqA6B4tyCL8f1j
    'a7ac089fcc3ab665b6de796501d0fd765e6305000e3f582fd71cc4f12d7d4fa6',  # CHXEWna7LYKQajNDJfUrGaufLZ8NeUyg6Sg6X2DA6qND
    '91b84c2a6718fe4a69ff094f4ff3860e792410d9c9a9dff4bb43b0f8a669e61c',  # Aoq7NVjhRYtfj8D66SJSfitPLpufguchoQem4yYpwUEX
    '6b0649d79d21917f4ee787e9c82e98899919cf37a65bc97c761b1d3d0c71837b',  # 8CnBjzcRoCgxVuoB9FMczs8iLirod2xqErQSdAscVfJz
    '9732b58eea2d0ba668201806c93246f21b9bb0545e1854dfa5e8b8e8bf9c97f7',  # BBDQmitNga99M9QsBRnyos9uWPumNbWLC1mfbReJi45C
    '7643839382c237735d9f9528526dfda2a8b5baccb92d81ff3951ee2bcb39a25c',  # 8xepSs1iXsSw8QrCS1rpZk8KY3fMwUZqDT4dmzDa2trX
    '9fff06fbfdb6ab2cb60268f20879b8f91d5d362fc2fbe573a02a3e90a50899ea',  # BmZNYGt7aApGTUUxAQUYsW64cMbb6P7uniokCWaptj4D
    'f3e306b30db5909a245dbad6d87e024d4372d97ae204e35c3375d3eea87ea8b9',  # HR2rWgcU6SNCWxJDozDu6qCgSSvUoKCynbhQPGRNqpCG
    'a44453ddaf32dffb9d2f7caaabf9c5ee516685c07b82aab95c24dda47e238205',  # C4EHvK6nREQw7GfhmZeZDy5fcGCVX3NsD7D8U4imHWbW
    '8acd69526dced710c82fcdc6cabc9f07a3a7b61bf86bddd805cb28927dc74578',  # ALpvtnX2F9uM1avdyTh3tQFu1AS9WDJ5NWZndKgZA5MR
    'aed64ebf7e6ac64332bc2dbaf3312fee875730eb3a0a8d9c167170292f3c02f8',  # CmVUW2hwFrwoS6DKpQFwQRa7fGTVwA7vfs6GaaibDaE3
    '6bea2c4b6e1b96d9b5800ff1cc85d04f5d55aa2090b29bc2a2c657ae58c11dfd',  # 8GFjCDTz1WM3jGNomN7sJoatnrMveq21JoJBvRhCbrjN
    '7d943440875680181c3bbcd7a8e90eecac21c92fbf0fbb35af977899578781ab',  # 9TD31gf9koVjGCEvZW25bWeEzyfVXY63pKJK6w78KkWE
    '417af33083193edbfdc26455b43b98598b38c4c511a73eeaaea154bf44fb2d06',  # 5QcEoNLa9GMF4aRegMRtcD8pnVRSh6aCziBiQVUiPr4M
    'aebde27f8bfcc552f7dcfc7447d4f5335c2a3fdb25c31ecd43394aebd750fba5',  # Cm7sifQKz9QWQeRznXrungc3DB3ABMWS4J4gLDGffXYx
    '069b8857feab8184fb687f634618c035dac439dc1aeb3b5598a0f00000000001',  # So11111111111111111111111111111111111111112
    'c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61',  # EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
    '0634d20f1bf56dd164e3c13c7836a4229ec5ab21ff54528390a51789f3cdbbdb',  # REALQqNEomY6cQGZJUGwywTBD2UmDT32rZcNnfxQ5N2
    'a917a0b2c2935b6dca9716068446f3e68f8de7a82118855143740a4537004dbc',  # CP4oFU3cNfTSUpkNDL9xotELPGUbv2U8Sgd8HmEyfd1V
    '06ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfc',  # TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
    '054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448d',  # MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr
    'ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264',  # Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB
    'da22e0dddd9c4aeea852d747a4eb4c3ea3b7c52ac18134d5e3b9c183ba6f9b44',  # FgWj314yjje5yRgvHC4iPY1D19xrYkM2dUEzphpPbsp7
    'ccf802d4cccc84d7fb21b5f73b49d81a16c5b4c88ee32394e1c91d3588cc4080',  # Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB
    '0fbfe8846d685cbdc62cca7e04c7e8f68dcc313ab31277e2e0112a2ec0e052e5',  # 24Uqj9JCLxUeoC3hGfh5W3s9FM9uCHDS2SG3LYwBpyTi
    'bd2e8d50bc09278e5e14bf65629a4896f5819ecac40f50c84b757847ba9464dc',  # DjVE6JNiYqPL2QXyCUUh8rNjHrbz9hXHNYt99MQ59qw1
    '35652f5e281fd835c626fe16b58d36b02bac86f0cfec523819f929fc90295e8c',  # 4bS6bkBdJ4B1Bt4ft3oGF8La7eKpCqz8xnu1AMpMxWSP
    'c3b2781a6174429d87168ee842f0799280e37e3a5af55400ce8bb491f4245607',  # EAvLj3zW236pUSSSzwjL18QuPpkTxkWaVSR5GdX7yiNa
    'a5d5ca9e04cf5db590b714ba2fe32cb159133fc1c192b72257fd07d39cb0401e',  # CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK
    'bf03242a15ce182d3ec4b69d9663b011886609d4d10a4cbfed8c9d1b272b0769',  # DrdecJVzkaRsf1TQu1g7iFncaokikVTHqpzPjenjRySY
)]
JUPITER_PAYER_OFFSET = 5  # v0 prefix, header, key count

# 605,446.589474 PYUSD with the recipient's Token-2022 account created first.
# Signature 2eU6Vrfdu9QyCsQtbYHmr81zUr9ySyVKtUw2bps5HJrbqGr7zhic36eqRLwDgRh14sA66rUgSfJem3yWFH3ins1e
PYUSD = bytes.fromhex(
    '0100070a5edce8e3e3b386395df7fafc626181f2ce13f762a5e440917fe0e00b7e87cf94'
    'b2fb90a373040bb87baf4c6537562a2653ce838d05d4edb67b148544bd9f330770ba1e5f'
    '97c97556dd6d6417beaadd9f22aa5b947dc327489ec087ce1d5dc288b290434f8ce00659'
    'd9e1394fa0653b2f89f21965ac2570330bcd98368ba9a00d1792483b6c8a2a87b7471d81'
    '4f9591f9395c840a9ce3d9f4d5ba7d3a4b8a749e00000000000000000000000000000000'
    '0000000000000000000000000000000006ddf6e1ee758fde18425dbce46ccddab61afc4d'
    '83b90d27febdf928d8a18bfc06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44'
    'e3dbd98a000000000306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a'
    '400000008c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f859'
    'e9d56d35f9cf25d975ecca8e750bc5fa6a060137b6295e3dda33e023c0a5f34404080009'
    '036b4d01000000000008000502797e0000090700010304050607000604020401000a0c22'
    'cc6df78c00000006')
PYUSD_PAYER_OFFSET = 4  # header, key count


class TestSolanaHostLookupAccounts(common.KeepKeyTest):

    def setUp(self):
        super(TestSolanaHostLookupAccounts, self).setUp()
        self.requires_fullFeature()
        self.requires_firmware("7.17.0")
        self.setup_mnemonic_allallall()

    def _pubkey(self):
        addr = self.client.call(messages.SolanaGetAddress(
            address_n=parse_path(PATH), show_display=False)).address
        alphabet = ('123456789ABCDEFGHJKLMNPQRSTUVWXYZ'
                    'abcdefghijkmnopqrstuvwxyz')
        n = 0
        for c in addr:
            n = n * 58 + alphabet.index(c)
        return n.to_bytes(32, 'big')

    def _with_payer(self, raw, offset):
        raw = bytearray(raw)
        raw[offset:offset + 32] = self._pubkey()
        return bytes(raw)

    def _sign(self, **kw):
        """Sign, returning (button_request_codes, response)."""
        codes = []
        orig = self.client.callback_ButtonRequest

        def spy(msg):
            codes.append(msg.code)
            return orig(msg)

        self.client.callback_ButtonRequest = spy
        try:
            resp = self.client.call(messages.SolanaSignTx(
                address_n=parse_path(PATH), **kw))
        finally:
            self.client.callback_ButtonRequest = orig
        return codes, resp

    def test_jupiter_swap_decodes_host_lookup_accounts_then_blind_signs(self):
        self.client.apply_policy('AdvancedMode', True)
        raw = self._with_payer(JUPITER, JUPITER_PAYER_OFFSET)
        base_codes, base = self._sign(raw_tx=raw)
        self.assertEqual(len(base.signature), 64)
        self.assertEqual(len(base_codes), 2)  # blind sign, final

        codes, resp = self._sign(raw_tx=raw, lut_account=JUPITER_LOADED)
        self.assertEqual(len(resp.signature), 64)
        # Heading, 15 instruction screens (one mint pages its mark), fee
        # payer, max fee, then the unchanged blind-sign flow.
        self.assertEqual(len(codes), 20)
        self.assertEqual(codes[-2:], base_codes)
        # Ed25519 is deterministic: the same message, the same signature.
        self.assertEqual(resp.signature, base.signature)

    def test_host_lookup_accounts_never_lift_advanced_mode(self):
        self.client.apply_policy('AdvancedMode', False)
        raw = self._with_payer(JUPITER, JUPITER_PAYER_OFFSET)
        with self.assertRaises(CallException) as e:
            self._sign(raw_tx=raw, lut_account=JUPITER_LOADED)
        self.assertIn('Enable AdvancedMode', e.exception.args[1])

    def test_mismatched_host_lookup_accounts_are_refused(self):
        self.client.apply_policy('AdvancedMode', True)
        raw = self._with_payer(JUPITER, JUPITER_PAYER_OFFSET)
        for keys in (JUPITER_LOADED[:-1],
                     JUPITER_LOADED[:-1] + [JUPITER_LOADED[0]]):
            with self.assertRaises(CallException) as e:
                self._sign(raw_tx=raw, lut_account=keys)
            self.assertIn('Lookup accounts do not match transaction',
                          e.exception.args[1])

    def test_pyusd_token2022_transfer_clear_signs(self):
        self.client.apply_policy('AdvancedMode', False)
        raw = self._with_payer(PYUSD, PYUSD_PAYER_OFFSET)
        codes, resp = self._sign(raw_tx=raw)
        self.assertEqual(len(resp.signature), 64)
        # 2 compute budget, 3 account create, 3 transfer, 2 fee, final.
        self.assertEqual(len(codes), 11)


if __name__ == '__main__':
    unittest.main()
