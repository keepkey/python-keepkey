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


# The same spend and change as an NU6.2 bundle (orchard 0.16.0,
# BundleVersion::orchard_v2(), Flags::ENABLED), as wallets build today. The
# builder pads it with a dummy spend (dummy_sk, host-signed) and a dummy
# zero-valued output to a random address whose ciphertext really decrypts.
PADDING_BUNDLE = [
    {
        'nullifier': bytes.fromhex('aed05ebddc392dda842311207fbc3fa84fb454f43fcfac292d87a3e8300ee112'),
        'rk': bytes.fromhex('2c1b8779ac1aca3abec73dfe9b8635be2fae970dfe76237495042fed96c3849f'),
        'alpha': bytes.fromhex('f081a5920a807a9189bc48f6ef5916b48effd77745c905def34316c2af87290c'),
        'cv_net': bytes.fromhex('ba35dd670b2f19d39a44f2fb871e35ec8b9a444d49bf84a8e9bf6c5556e69d0c'),
        'cmx': bytes.fromhex('087796ff6b2f7943ea69464410a8b2710c2b90316fd5c748f41e3a4793b59d0a'),
        'epk': bytes.fromhex('81f9bbeaf78f326630fd4526ab67289a44d0d09972ef30682d4f5ffeb9417798'),
        'enc': bytes.fromhex(
            '7635af9d8406383ee8dd92f37ef87a8216b57a8004ea779251263d8665916e2c'
            'ad6139ad2266484d70f79806e431c7531de4c5d620b14b585070871e1c50aeca'
            'dda4ae9a45216132c33e3ec304c1edaa29d1a18687e546b95139bce8f57de0f1'
            '1e200bad146f9580434d6471084df7b0cb8b54f09098923e821939c6769f33f4'
            '1add1d82c3660dcf065c8bf43e3f69925270ef175fa2f595166dbeeb00d2eed8'
            'd19280580081a541ff0db45894f0af53c82f85c4d83e139a98dd99b5544ab23a'
            '0ee74c33a416bc4ab28d28d5717463f9e100f7cbe2f7334d93a6f8715e49791f'
            '3e1efb1a6c285b9e9aaca988ea3d4dd90ec5307a7e8067d7926bbc664c049968'
            'aac677fd0497c68555809c7f34888b5aae50ba8c4bc509a1a5773eecfaf57e32'
            '7bbcc042059d61e60c37bbe6b9981f8c862c08714ced7143e480d33373bc2871'
            '0a6cc670f85d68400fc49e5581b2a918bdac988ec720a9fc2196a0833db5026e'
            '753924001effd0ca209bdf8fab61c4cbb8e666d408979ad351f9de8e3551a032'
            'a471b1842cb2534c8f98996d964b67344a96f5baa24db77ebc581a252d242933'
            'd413c4cfe3dc9b60b7821d4f02d95a09321cbd677e9311f0acfb6e2e97d54ca7'
            '3280e64c2d216e3b190a44b5b6c26da1a9f8ec1dac3d5d494e4c650562ad5594'
            '6736bb8ea447b4905a1602a67c988c5aba1fa81c03e33b1af82f60de2c23d1ac'
            'afcd6dcfb1dddbe12b695295a694e893f2279a271039ba3eb1ab48446047bef2'
            '9efa519bb08cb6f0c0a753f9a70c2b683e55b783a8a79310e990cb9fbef3d1fa'
            '255602bc'),
        'out': bytes.fromhex(
            '72d9526061fc8f2088c225996dde720ab8f19502950b052f9c8d9e8e00f06532'
            'ba4ffff2ecd176e5836af72a44a1d58cefd03dd089b66b4dc0d92d3860e1d437'
            '5595655e7abbb43afcea3a8b570f1987'),
        'recipient': bytes.fromhex(
            'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
            'f0bb27c032b2e7718c962e'),
        'rseed': bytes.fromhex('c29d5ab216448f6ebf6388a6251160e7c9fe2413c85ac1cd2340363807ba8840'),
        'value': 90000,
    },
    {
        'nullifier': bytes.fromhex('82b4ace6f48bca884543cca25633e137f3791e3ed655c775f8b6f84187c8082d'),
        'rk': bytes.fromhex('ffc4c2218a0382a530909566f44a7ab4421df95cd12e0590a19c01eb6e06b83e'),
        'alpha': bytes.fromhex('14de74940160f3450f3f8fad83c3d50dc9fc766bcdd4d5968a13ad8245613138'),
        'cv_net': bytes.fromhex('21f87ec22c92674f97585415535b5cdade848408fb729765bdcf2c36118e463f'),
        'cmx': bytes.fromhex('b46b4f684d39569dcd24db0db912406dff3fbc78466e590260d729313499230d'),
        'epk': bytes.fromhex('a7d08787142ac449a74203ccf11ad1e927b8fb4356f33ae8f81b1c9e7b3c01a6'),
        'enc': bytes.fromhex(
            '43fed1e4afbd93923651a18623245c91b2717cbbf89ef9a4905bd0da58f3a578'
            'bd2330a347bc32526261273feeb11120746ce964aac12d82209183195eeafa8d'
            '54ac7b02e4c107aee4ec1db2452a50bcf53ebb7902827bfef0ba144ca16c0f9a'
            '1ef79116b5f86a740a68c46b28f5b1235235ed347244ff7beb65898e74f139d5'
            '975965a2f786e60a9b081f96f576a087070bb7a8e1a182fbf7366467005a051e'
            '28ed1509aa2177a684417e618e0a07a4f157f1152308ef7f6757533f5f45cd67'
            'a21cb1b26944fb266fd2bd6e892bc9bc672d2eed09afcd7119074b0c8639b13c'
            '548df077595390a7aa4b4181341804c793644d9bd19b92e0e322d87b64075eac'
            '7e6a908c9fee485175ec7c85ffd3e010a85fb67adf6435bd66f45464f7ace727'
            '7471eed60135e19d420fb5b9af89957b23f33e458e09c393a02d9403eabef6c8'
            'f11f4002cd2c877197f573bc0146bd6eef0bc00283f29ad0ae500ea80c84e221'
            '81f9470a4d1e8c60b4680efbd5dd47fa73cf82de930b304afe0686d11b963c8b'
            'e5a3731e7f74b245958c46c3e0b591278ec8e4206f291a80193ec325f06742ee'
            '3de56bd11121df9432eb2456ae090f64e840d2ea17365abb6c6ec9fd51f94036'
            'c0ace903ae39ef5a0824799b1b4ba529c3403d240d7f18cb90559af4252f1fd2'
            '27eefabfcb830b94c3c3e5114e41265cef100aad103bd25505279a39cb294db4'
            '0ccfe4d4b8c13539b975564008c113da36d67d50568769751fb9c775f363c969'
            '4d834ba1ea03e956a6036dc2a676918044a1fc76c777caad479de213ef856055'
            '5407b7ca'),
        'out': bytes.fromhex(
            'e41a17506e1af63acd8edc563c195819e26e740b5f3fb4830242d804bcee8a56'
            '2572f52e73d190ef270ecf7aaf309e93b2ab9eb6200b8466cd1aa7889b42cfcc'
            '2fa9b853f9e136be5e04f9020ac82d4f'),
        'recipient': bytes.fromhex(
            'df8789f215ca59a4fc59ce4e9b694f87b354d01cc397c47b594db69dc0fd4ad0'
            '0e11a41d7751189db93210'),
        'rseed': bytes.fromhex('983d2f7efb6cbb27571832127afd4f48136bdab4ebc68bc2a7c667a4ab231030'),
        'value': 0,
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


# ZIP 318 migration transactions built by librustzcash's zcash_pool_migration
# (build_transfer_pczt, build_prep_tx; orchard 0.16.0) for the "all" seed,
# account 0: v6, NU6.3 branch, lock time 0, expiry 69120. The transfer moves a
# 1,015,000-zat Orchard note into 1,000,000 zat at the account's internal
# Ironwood address (fee 15,000): a 2-action Orchard bundle and a 1-action
# Ironwood bundle in one transaction. The preparation transaction splits one
# note into fifteen 1,015,000-zat notes (fee 80,000) in exactly 16 Orchard
# actions. is_spend is False for a protocol dummy, which the host signs; the
# sighash is librustzcash's (also checked by the firmware unit tests).
MIGRATION_TRANSFER = {
    'expiry': 69120,
    'sighash': bytes.fromhex('37d64f27ae739dcb68087da7d8a2d61abdb2fb1fb89e3d4f0e029d80965f4edf'),
    'orchard': {
        'flags': 0x03, 'value_balance': 1015000,
        'actions': [
            {
                'is_spend': False,
                'nullifier': bytes.fromhex('1864599aa7e56f8c0399922334bc322b1e5c0e9614056e705f5dca13652e3e30'),
                'rk': bytes.fromhex('8e0da71eb98174f038bcce8dd232ccf690e8fcdc68e2c571310626f44d897307'),
                'alpha': bytes.fromhex('d60207f13eebd372f8f9e79b966230dac87839f33a68c21b1a7adf5602b1c024'),
                'cv_net': bytes.fromhex('ccb4e6427d30b8b910fc733ba30a1a4a6f43bc339ba4e7d38e731aa8c79553ab'),
                'cmx': bytes.fromhex('e8a96150abbdd4a657639d23e8202c621eb422a46f115a4f9b329203783daa27'),
                'epk': bytes.fromhex('76b0f4ff80bf7a981e2f127086358c3eb65cf4ecf855dc7153f50d41421648b7'),
                'enc': bytes.fromhex(
                    '8087f8103c81159a18755a0dc6506283ee6872d2ec050051f9c52403b831aa74'
                    '2965708f3c466aedd08dd8db5d2df018ef5ba744a23ea84822b715e4b1c89524'
                    '49264e6d548e4cfabc9dee6d5ded01f80c137f5b08282ab151356382e8fa7c70'
                    '722d6d4f8de0503eca664b27bfe415a0f9413898b39215669179f4f2ec0a80d9'
                    '4c624179133386574e2aa4a4c9702c697493c95ae442996cbcae044eea1b1d0d'
                    'df037aa81b779f894dc86c17965ce4362b60cb2e314634a49398e1f43ad80c94'
                    'e64573bfb2bbc5d5f398c5c9dc57133a9b6d3ce5a7392ff9d0e716f8b6f0f3c2'
                    '5732e8c108f4bdfc316eccb9202d1455316b32d4a5bb5f427d2ad69a8f1d1a0c'
                    'b87ae8ddd870ba00d37e246b758845e147ce19ebad1485617bf0e51d92f9f9fe'
                    '0aa9804091e0ae89dcb815f3238df56accf9b3a25703f481462d8ca43d3a1673'
                    'a1e9053fed093ef5bc3c74e31c99cc0343d8aa6fb8ca56f63676b07e4ec898ae'
                    'c8b82eb90194d47b914669435a4b3161e76724774cdf3bab2390a3d31fe18a16'
                    '06fb060728b6db876472f7d75cbfb6e2f75065ef7b8507a54a5fb219e01e2bf5'
                    '81af63ba475347a0a75bb8b6cc16652188fd315b73e8155492e6b1bf78ad79da'
                    '6ddb9b19599d9e2ed73b17ca2f5281c78bedcd215918290c3c3ee7bb44ab3ae3'
                    'a88f5065a7585905bacf2c1af0ed7a98aac974b992945faddf8e07f11aa259ee'
                    'c891e55cfc9924d44da5fef14b823e7c2c246c4daf1ac01e4e1ecfd00d1efdda'
                    'bb181a2b9598ebb42edb69d116a77820b46482034ee7f54bf0f556bc9cccf2db'
                    '3d16f60a'),
                'out': bytes.fromhex(
                    '608c408a0545c24615106484531cfaea8fdd107f2ccd5007cc3a74640c1a058b'
                    'b3e8e52a668aca85c8be3780496ef53bcc0a768496ef089c3db2382f75904882'
                    '9e1447576fc7df7626a1e76db2a620af'),
                'recipient': bytes.fromhex(
                    '937bcbdf0e9bbc3a056d4b840825fa3adf31c338eef5d0a57d56e432455cbdc5'
                    'daa4f738338166c7b9ed07'),
                'rseed': bytes.fromhex('809144435bbd53c9d16a3944e5355a512a875cd5177d6f97ce291debc4684229'),
                'value': 0,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('489a7ca2cfced841420598f2dc0236f637652fc3fa410fbe448e28aadb5b9c0f'),
                'rk': bytes.fromhex('a618a687af32bb8d148bd5745c8b6f8b8f40d18d5b2bbe733d10e3b024966b01'),
                'alpha': bytes.fromhex('b3abb9d87a35fe5d9697cf96d9eca2e802988bd6bc2de2ebba30eda0eb10a31e'),
                'cv_net': bytes.fromhex('a122f0fc50ec9b8653a3ddcd4e12bd9d9910f879f6a4881f958852b0797f7e2d'),
                'cmx': bytes.fromhex('eb709cbf300754e5f17f1d6947d0854575305e487d96344b55ff2de9821b5f36'),
                'epk': bytes.fromhex('1374c5379cc8daa943f521558d7a4c0a7ac8ae21ab311f275b051a8631f799a4'),
                'enc': bytes.fromhex(
                    'f714bbc0dc6f64674d579ff6a85de299a4a98788b2cf473d687b142e2501ae94'
                    '9309bd2295c8b93afa7d0607e8663f516e855c9104341f09dd649e406bf8f21c'
                    '687c5706b1d5afd74fd8e063921a05ebaa89cee7f7251d518aa271533c5ce752'
                    '4074b7f32dcabfb6fb4309bf86e9cc00b3cb2424b7a2ae6ecb83e14b4c4fc4bf'
                    '86d494b2d528d7d9281a8f7af1e78fb674327782b178d1469119199b3d9de1d9'
                    'd381a4600b85323cdc93f43f89ffa9cdc94e0095eaed60ee68047b015b57c362'
                    '159f43a0bbfa21c4be1856dc1256a04b27d3ae52962bd9a8661b74f0bd7a4a9b'
                    'f7e53fd02b7b33038f824e20a3d21f3d6b152df460bbb720f7597d267707cd00'
                    '14d4099952ad1195076d521da378de8b14261efac4e1bd2b3deae15c899de20f'
                    '090210d3ab853d7f25dc01522b725574282f45bbc78c0213fbe6f040f2b3355a'
                    'ff909180bfdc21dd8c1cbcb7ace23d4a5575633bfe561ca018f23beba644761e'
                    '70e87d03280b6677d1e7af24783d23476a6e5958789eca3f738cdd6683a2b762'
                    '3606de12b9a75ce127169c02fb37e22549451ce3d1912d0f6d546b541c2a5e93'
                    '5e18d924d43629c5a0ae13b20498592cbf6daf2f180acb7c7cfe401b37e808dc'
                    'e2fc54227a523fd8b973a4f261ee6dc3c48ea4ad10d2d4a07807723b6a8ade44'
                    'fa3a236fbba8a0f7f8b7b62e82985b6a6e63ca95f01cf597eba7c839571d5d77'
                    '31eeeb9a90961537bb0301497c20ae735f21715bc37ca3ca1626aec076ec3b73'
                    'a8001204d3d59ba1a078c996bcc97ad89f7ac7890b89145e4527bcd76355bef7'
                    '43eae3ac'),
                'out': bytes.fromhex(
                    'fa9051ee2d97442f3618721452e5433399d53c5f3b42ecbbb6e5ab0cd4ca6457'
                    'e7444ccece08e96d282fc184fe08e23d3b8084bf63a5061e21f7fae609987704'
                    'd50c3954228af752f5e00abb61b65f3c'),
                'recipient': bytes.fromhex(
                    'da973031634a8938ad1c480f978780693ec7709ba5caf58d8a7eb945586cbed6'
                    '45520f17387437bcfdc216'),
                'rseed': bytes.fromhex('259c76a04a44a10defc8b3de279aaa2f57f453c4843932e07ab89e8d08a7045d'),
                'value': 0,
            },
        ],
    },
    'ironwood': {
        'flags': 0x07, 'value_balance': -1000000,
        'actions': [
            {
                'is_spend': False,
                'nullifier': bytes.fromhex('436effc6778e973a5cc77c202d0a396e5b932905346443ddaaadc8253ab4db27'),
                'rk': bytes.fromhex('6c05eb42cca028e4ed2740bb176d1bc6ea64a72d8012437d3ee4e488c0116e06'),
                'alpha': bytes.fromhex('ca3ea1b2ed99993558b786870350dd0b3a6bb2c096e9f3d9e6d744743ad7563f'),
                'cv_net': bytes.fromhex('8ea1ceccc9a86e011ecfabe68f68b6aaeff93e57d7fd16fef5befd15edc5a382'),
                'cmx': bytes.fromhex('a8cb867f1ae569fef09e6b6642f4795e37992ece4e4fbdc33f1354b379c97c20'),
                'epk': bytes.fromhex('ae9f613cf5a2bc3c5e480a4af39b36e6d40c8bf7a664edb0548c4fd2a5bf8414'),
                'enc': bytes.fromhex(
                    '75022c701b77054ebe6886efba031ceb9d0a48c46f34a58b9a9f4b4dbaaa63ef'
                    'e9445158db413bf37b22901cf4334f1bdc8acf15626e8f442998fbd1ac7e42d5'
                    '6639800df728a431f3496d1235dc1888ef296d4f8b63db81721a8e4895b43886'
                    'ed342c7226c0265281a7e5701d1946ce25e06f521ded2a9be3db6b926ec554f6'
                    '83821c46fd19a342d7b883c1bf7e385643e947ec0dc4d7f41de7f54131ea60f5'
                    'fbc1c9f9e454dc1a5434bea7956f7a6e404aaaef73b481ce8184c44cb0fe9bd3'
                    '2ee18a8d7da8e2493fc88c9e6c6dcd601073f7ba8b0fc77cc6f6fb9ce74962ae'
                    '6dfd10fba03197e2a488633e479cebace7d99a5fb55c73114db764bc9ac54264'
                    '0e4747fc2d81ed02f8297cc4fe52fc1fa9e5402fbe9ba2f6ec74c59f1102d082'
                    '2d4d3c0a0a371dfacd541477f8c920e36cfe8f9e7d712b6bb2230963e07b16a6'
                    '439b116b6d510e5e4f3ca5af8da8597fde93dfe2bad94570786367da4de38937'
                    '797ade29d01a762edd85e01fae2cd8d8ce3161ae9dafa80121579e20076e6293'
                    'c25de93a3b7ba07f3be7a305c6193ee53668d6039d4aebc56207ea22582f3d68'
                    '4c7df5fd48c726d9fe0179015cdf7f88572adfd1897150c38d059a02204b2b72'
                    'ad982e83400f75a397eb2ba67a793a8d1a179c3355b2a9f4ce2bdc0124ceffe2'
                    '93fe0d00f9fcc072be2fb0b279b6bc6c67e03ca396dcd0827dd9485d1a518399'
                    '2ae4425ac5cf3f7629c6cd0cfdda397b1098a1a41e386c223182af6823e847fb'
                    '753a18610d24ffd130cc015d569cae682273e20498f7240972a9c26f26981159'
                    'edf6104c'),
                'out': bytes.fromhex(
                    '86d9ffaf8df7203a5db69ec59ebeb544b34a5863dc7f4db848c70bb8678b959f'
                    'f86c5224265c690e5ec56910c66dd513fba56a4c946f63d7009a0f86f9537b54'
                    '8bb3e19cb69d2ce349246b2c352adf88'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('7ecfb512ece0d14ff72733c55f85dcb3717ec0196cb6248fee63c590ebc6e8ba'),
                'value': 1000000,
            },
        ],
    },
}

MIGRATION_PREP = {
    'expiry': 69120,
    'sighash': bytes.fromhex('9ef92705d1598a058ba70b3254653e7c0c2efa108cf8cf611b0a71266d7d12de'),
    'orchard': {
        'flags': 0x03, 'value_balance': 80000,
        'actions': [
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('054ec0e73431e55a5c9282a41ebd2af81a3dc0515c849dadb4817c7c397a9b24'),
                'rk': bytes.fromhex('49f1ba4aa6ac6a111632ec4c1a799988cd0f595d10379a2980f45b0ebad74f32'),
                'alpha': bytes.fromhex('e2b209a4c7ece0b87a6d0149b919dc636e89accc183c03489a75781e7abcac30'),
                'cv_net': bytes.fromhex('026b83c63c03b0eafa8bb82f70e2f557136ca082d35563bdf1e044d667c805b7'),
                'cmx': bytes.fromhex('5e2d87ac1d8a59bed84174c856e713acf1bcf806aefdff44725c88bc517d4025'),
                'epk': bytes.fromhex('9639beb15a85b79ae394cd9b394ed82364908b33a54908ede023f88aa1822280'),
                'enc': bytes.fromhex(
                    '405978bbdac91023104dd3885b96a8355108413bc16e82db5fb5c2728b941a5b'
                    '07447a4b52c1e3bde81eb3ebf44f2481598779059dec907d310a633703181059'
                    'b52a010b2a0b4f8ecbdd1a04108bfd4971fbc326209229219bd951a8806428e8'
                    'af01859da5a5941a5183b292cc03a7ba7f69bc4359e33bb4cb6d843e261ffb07'
                    '77bf92f6841e4fb646cd9e65d1443cf582138a2c8472dd4701a0a5ebe1396c42'
                    '3315b630ef409388a3db83ba35ff52ab7ecd3155048f05411c06d73aafc6d747'
                    'f94e6806faec548fcab05a630217f520a2cdada7906d14406fa93211529c3edd'
                    'd5f3803aca5fa86527668a5a19d01fa5f7b9091d09048b9292ea195fc001a002'
                    'd709a57c94b7ff4e043337f392b59831a8467c61a9b358528f4427a1d78e0556'
                    '4e5a570d6afcc995ec737a62de866d8989c3fd652d7174444319dfa8e5493250'
                    'c6018149fb15507f2a35f13d58bd8a695fabcc8a07174b3f6e675ab0ee95480d'
                    '2308aaa7a3c5e3a5affecece3375ce4fc2d0a6c6e156fa7764fa6a68fbf89c84'
                    '640daba42cf345408d18bb88eff1a13f3567688a46fba77720047f255a792af2'
                    'c4046a50bb904b4e2bd885f82bb7085979d11b8502dc09ada9291ca9bcd1017f'
                    '0a5e6a09344bf783976d69ef787ba6b394a6ee2c6563fba02bc0ff7ae7d6f499'
                    'da6ba692cc5eca6fb2a1eb6c1e9e2c9f05209675278d3e0d51302927dd6eca2e'
                    'c10918646f9ffd5b1e57640464fb75d33034132933fd1526d8c28ce6d6e70667'
                    '8d044a52659bc654559e90d440b546f317b295b1183fdeb26dba6bd7ae7ed937'
                    '9fddd84a'),
                'out': bytes.fromhex(
                    '1e2d399e94df4bc9369536a5640049af19013052ca97c9c3446ab25da81cf049'
                    '8a0b71bb55c66ba5f435c190a3ea047f49e617dff4a6ee3e765bc9c696cf1361'
                    '23bc52f37fb084443d8c2ca5e52d7e73'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('4472e5d068978450f247eba631f080a34ca5265be231e1ea01d76b1fa0ad022f'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('1e9167c36ccddea1bfeae395089b3c9c084ec497f1cc1a6064163eca850c920c'),
                'rk': bytes.fromhex('0ba435bf58e44f0fc5df77904f7500ae6173bd5b115ec49a17b2948ba9c362a0'),
                'alpha': bytes.fromhex('99188cc6049c504b58fb3107a5095270083002032d24923353ea1b5ac238e721'),
                'cv_net': bytes.fromhex('ac8bc004cff0fa6ada12acd1c2b67629dccd83305f6292c1d46306d614b03b23'),
                'cmx': bytes.fromhex('6c8b9235b5ab488414e47cbb78a1471d5523b62228bc469980e8288d3e0bea34'),
                'epk': bytes.fromhex('6adcdd0c83ea1841e96ee48c1c820f4366e5672646742999810783c9da6d7b92'),
                'enc': bytes.fromhex(
                    '5b19ca83d72fe4914b5a0eb56508f186cfd3417d72764b09b2923da9554b4f44'
                    '8f76bcfcb2bbb1df591b1cc83d8d92a748cef4d8e401fd9ad62e824768bba2a1'
                    'f72c54553365dcc119863ddb43b262948cfa19ede52c0159a3f7f5b6f8bd265d'
                    'dd642fd50dffc2ab8e1767c6e94f278c2ad09583825388239f0230d0cbb50e83'
                    'fe19c0da47b450a94ab7b3cc8ad03ba14ed6144249d61660e2ef177e1f2d1ffc'
                    'bef9142ff2cd192ee059363bf67bf1d267b3db1616b238399c7829c95c914780'
                    '0fb6946a3d3560c85f4acee07b3dde868bc5068ee169a30bd9a1cb8be4e1451a'
                    '123036f6644fe5cf372ef9f14a5fdb5b7a22bc44b2bcd1fef077960b367247de'
                    'd0f3e6f7b0a2bd59418059c03713d9458f9b2bbb1c01d13948c0ae2824017710'
                    'ded86dea4f2e2bbb28ffcbee53b2cb2d9348998d62a99d7094e85b49ca5ba583'
                    'f5394c7407bc8d8a356334993b13bf490c2fcb554dea2120e1724deb3fa2ecf4'
                    'bfd120e6557f0ba0d3f5d0c8e6934357751b13dc3c2d301297d02f336eae4534'
                    '06bfae54262ad3e4abad97b00c0da2048acdb7686c4d3cd9057e9744e108b4dc'
                    'c394579b602735ee1b4d3692057fff978e274f2ba9cd73b096999cc9336ac263'
                    '7c88542d087b3990881e3a92cd823fbaa497bd9af6017f0f32c82fea44c2c167'
                    'af21df07910c2fc92c6fc6509695bc7b6f6b36e760c7b8f890f68f2143577bea'
                    '2b52b4e79e4e1a46ce46a7aebfc9e0694b4b27fde0ce0e369f8e072644ab1042'
                    'dca5c6cd3c9a6d3e0e2c7f75f5d395bc5344dd11ae36da88e854c8d87d1faa30'
                    '9e1f4942'),
                'out': bytes.fromhex(
                    'bffa9f4a10c74c0921509df29e7d2d48d33eb0bb9a4bccc39025fa02bc59d9fc'
                    '8ef211d81dea3a431c81d5f4d300144853e480ae179562bb3562ffad91ed1139'
                    'ab45b62e3895ce45599de0ce4ed53c8e'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('df5ffe7fb55357586aff35971495391edc50b0f3aa13b2e86301e7e51a72b62f'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('bd279975aa116b7a6ab041d9b7025d5d7d711510657413469c4fec8482469d0c'),
                'rk': bytes.fromhex('3a3bbaf10cba4710f6b6aa292570b8618fc918a1bd6acce6a76cbb3fdf3fa1af'),
                'alpha': bytes.fromhex('aac41becf3358cd8f0c1e9833ba9303398436077ed870e471598e6f0a9af8325'),
                'cv_net': bytes.fromhex('7e741c1968cfe1a44879f786827d09bc8d4c1784090dbf15ca7dcc87f151babe'),
                'cmx': bytes.fromhex('10fd8bebba556d433f407718ac2753c2be129c8d76da8c56a484bb14503a7117'),
                'epk': bytes.fromhex('4ffdf1afd2e75c0e2104e18061f338a3d3071fd5af823c9b634264dde4a2b31d'),
                'enc': bytes.fromhex(
                    'de190d24706ff2cbae88088d97490349ab087c40fc5a0785dea63b5cb5749f14'
                    'a2fb2bdf3538c17d198d4486e7c0c2eb8cd4f39cbcb7aaa721c7608abcb6120e'
                    'd9bceb204f0c5c67c25cc3caf0b77f099e95a9644adf9adae0ae7ceef8f5e343'
                    '1aa83a705bbfd751901e8ce9adb9c080130021caeab3150de2b10716791219a4'
                    '44dbe13e861d0c1c0eba7dc52b16d59ca84b7044e88917a7e0a5bd5c21ae814a'
                    '7b61754662bccc774ece3e83ae3dc40bbde4044601291fa4611be64122ba75c5'
                    '7c396b13745a097a5b0622423d35a53d81606a0e4e0d8a5508baeebade8e2a84'
                    '7a1292f18b7c8f763fa39ae54a725707efb1282fe2fc380550c8e201b304c2a4'
                    '28631f04602249f35cb04b92d89d3f5ee0687f15f581fd1421e5aa3504f4fa6c'
                    '560253bac75b3951df2b871090e077835dbbba5c083ad8fa6e16529d6cd764f0'
                    'e970ab155e61789a3c95a9889639a3479766f5cb75c03133636cb915a5fa86be'
                    '71bcc1a4fa561074fd5b2f9a48a9654733a9d472901197c96b8a54e40cdd9f9e'
                    '4ae9a1c82af52b45f0b02c82956c250546f732cf1ed22abf01523714b21f3c1a'
                    'f3868a236343cca4ad81d227f46eae69e95f966cbed0331bd195ff23451896bf'
                    '95405921fe1e0ba8cdf010807cb6c10d1ab22d0e2a0e6368af8c77dc266319e7'
                    '13b552df2c0f6912915e6cfacee9eef6c752897de533419ff0c1b6b2be63322a'
                    'eaa6c246989916123d45aa7669487bc30576a9c2727c6bb6c07daa58d07a0931'
                    '3b5858d75b2d48b94fcab0a8d4fd2fb7ee6af73ca8d116f3353455f9600b70e8'
                    'e36b3361'),
                'out': bytes.fromhex(
                    '465b8b2660a00bc32d67f26c501fa6ddc2457664c49e1f6e7fc09e8e371cc7b3'
                    '807a800fceb01c6afc79b0d153b23d6b85276c703b41e371d2f3f741964d5843'
                    'e2f4cb7c403d75664c536acb6dfaff08'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('f3cc731a88be61db608e0e647d65669174778a9c7523d86e9ce96960af2404d1'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('46ec8306c0fe282e2ffebe4a7dfb99bb5d66594376402310e6d329ad1fa72039'),
                'rk': bytes.fromhex('9a7515f062b707fb218b763b2af09fcb696af3ee5e72acbfa569130c5e8bab8e'),
                'alpha': bytes.fromhex('134a9c395fb85dacaf5394c35be9df6f4ff69d5e967ac21b22fc1e2a1b06681b'),
                'cv_net': bytes.fromhex('32671fedf628dee6bdbcc4c861949b9dfb7aca84d2cb09f3b7276facd33166ae'),
                'cmx': bytes.fromhex('a6bf790e0eff686ef6561743880e609aa2ac9ac2fafb809cb536428387155034'),
                'epk': bytes.fromhex('38a2115c524ac490a5c656742e85ec3f4870a6c6207576b35ce35f5e9a304c00'),
                'enc': bytes.fromhex(
                    '4d653b68299ecaedc541dfe5e48498a7d8d363d56554e851030ac55781178d0e'
                    'cbe7ba151f99195e49ea6898676ac4eda0e12f55e56bd6909fff7bd4c4a3de8f'
                    'c34fa83472065f620db37d16f7efa36e024366062b11ef9e7cd33da638e906bf'
                    'ea92031869fcbd8d4e37f3094484993e67574116033c1a80ee1212fd01cb938a'
                    '0e671134e42ef954a4568e23f672f58ef64d937273e7a6a0b8d0673c2fa9eba1'
                    'f060db60cc7344cd81778e04a2049fbaf3dc160acd039c5c4fa1d2b93eb851e1'
                    'ab34f64e9a562a72a5dcd7c8f2ae9b991760a26cf9f966fafb272a82e7da0c9e'
                    'bfddba790abc62691bc6c9739224764911d941f68c5f9209f0047356f2c7d042'
                    '06156872a3ef82394739d5a7921ce81de2d2b4a5bacc84a864bf75d0dcdc8b1a'
                    'ab6eb5eeccbaee53518c491dc88672ed1774b950e39cd26590d8bf7894ad5790'
                    '2cf4ffb611650fbda399dfca0049829a278a5de46921f6e8bf9c358be2d1dbfd'
                    '806e89bc619c2492ef13fd09ee925fdb0bfc54581bda16828415e3ce4873c05f'
                    '7f555382ea943125b673b233b9612a9b63e6e78ddb27c180f69fcbe60e2d9d64'
                    '29cf273c1245c2b4cc56c9daed238a962e283eb1bcb5b31a81b7e42d4da91f02'
                    '0e4b51f20232d77ffae9e387515e99daf456a61cfc141bf0390257380797b154'
                    '567d335ef6376101b2d9feff939768f81ffd3f97f34bb92f8d6439a51801af33'
                    '8dfabf9c9779de2cd587381f58835ce491704359e15e668a3606f80c51fb95fa'
                    '45524400320920ce3c32668bc9bea9000053e2de0607e37608d649630af0991d'
                    '2b26a11a'),
                'out': bytes.fromhex(
                    '17527eab850e901d0fca69dfd95d0bdabeeae5a05f20a8ba8ad6bce615f8a1f1'
                    '0166a0777aed3bb3536eaa639e9b9cac6056508a5fb8f585182b48b9c166beeb'
                    'b0f30af96885078502cdc000181a698f'),
                'recipient': bytes.fromhex(
                    'da973031634a8938ad1c480f978780693ec7709ba5caf58d8a7eb945586cbed6'
                    '45520f17387437bcfdc216'),
                'rseed': bytes.fromhex('b28fb566a83a3e62b49a4577d3a299d1c5e9692649917f4a495da4f590e45069'),
                'value': 0,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('84b1e3f25066dc3531ec282f8ea0a1fd2f8cbec31e0a5c60ce1b5eaeb820521d'),
                'rk': bytes.fromhex('88a5cc84f7483c9f775bb0d5c70409d05a44db5e6262f4a687468d4349a7d58c'),
                'alpha': bytes.fromhex('3527420fcbab8f9580730144813546c1cb50f608d06aab0c145f59634f7bdd2f'),
                'cv_net': bytes.fromhex('85c7f1af6a5226cf953e4dcc5ce531205fdc1594f8aab38ff62b497e80413f17'),
                'cmx': bytes.fromhex('94988df15b79910e7c217b069e8175588b3844c839b1cd07b4bb238552acc22b'),
                'epk': bytes.fromhex('6fff64e1409564630a7efddbe75f4f7f6a5411126cee98a6a184187b218a7793'),
                'enc': bytes.fromhex(
                    '9523ee3dfd23d9d418333d4d4f541d6e1ffb6708a57847858944ef9c043da78e'
                    'b2a834dda0dd3c26704566cd823928438af12b279851a73204795d370efb3928'
                    '2e41ecec65eace5b96f7e79cf0bbf763bde3aa2672976899e487fea37fbcf250'
                    '179f895ba59ca2cb33699cabd073b05af5585e2f34c88d5432dd39c9e28622a3'
                    '12f2fb32fc7dcc3445b9f8044ceaac5e3828a36339576c502004e1b619cfa2b2'
                    '148f8b4d04c8f8df85b9e32496b15f2ba6c398b502f9bc1394fe99a4d3538b2e'
                    '5a22d86afc32d6704820a80495be317dcc97ac9a8932f8e2e5a1c7bbef99a613'
                    'f51374ba41d6fa0d7a45f2a4cf9450a888e6b586c7371c91afae1c30067b6019'
                    '74ca0494458efd07b26fe402fa5e9fb2e9ed45072f0de676329d0acd34de67f0'
                    '0e5cb863798568991cfeb3a3647b516cbf80442ed830966035ced2e8153ef7bc'
                    '9e7c848c08f5106e507c198f4c463cf5cf33147d2eb0285ea23d978bbbb2f2e4'
                    '653c75c3a67f31048d2ad7458ec3bcfe65ccf33e08d7f869d4c10b5e8dc51797'
                    'b4b4aba646ae031ce13503d37c23202322f68a1de641539ab8906ca1cc2116bb'
                    '02f3e23b2484a50ad557ca59beb12210ad6af7c3361a915baf8da33021893eb7'
                    '3ecfbaa020a5800332ce1ebdb3678d25dea61f32f04596ca6e672023288c59e5'
                    '61e451ba05cc7b382c25248d5ade7af1c7304f26b230f60fc73cb1655175a8af'
                    'db4d0734f001ee35661433b2928526482079d11d485be8c8fa3a066f12e4b213'
                    '5d738667bdf461d78466d0f88f72d10163ca7e7f53f0e36ff4061e6a15824144'
                    'ca80aee2'),
                'out': bytes.fromhex(
                    'dc650d9efce2e1fdccce0e0631c7513ac9cdc3967d66b91de7899ef244f76c9d'
                    '211b2a01d51da32fd1cde8ad79e93b7f95e74125443a30c07e2a51f7c7f0c596'
                    'd13b074003319a0d4d73869c06e6de24'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('fe195185577caffc9b3214d0e82bef90ff91a1e2164ffec23bfca96b4e2da6b7'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('2eecf6557ebe7d63d7e8c8e2d8c63e73a4a626a4ed7be4dcda98a5ecd3de0a08'),
                'rk': bytes.fromhex('c3bec9b4b5453deda20a3b8c88a4b1f99047b74ba2004aab2c93c243088da713'),
                'alpha': bytes.fromhex('5a02fc4ecc2201be9955971281892dfc183eeab06488d07fcdcbfd5afa8a462e'),
                'cv_net': bytes.fromhex('fafb1a6b93bb4868690dede7f7d76e3639ee37e9ed020e166c2eb20cdf3feebe'),
                'cmx': bytes.fromhex('982d0cec5df92480e143a33b672a5fcc9860ab0589919beb24072b102e01802e'),
                'epk': bytes.fromhex('d5d01af305d54fd71f9b0eb44f44b00b61bcbd8cb0811d70f97af5a9e9a09225'),
                'enc': bytes.fromhex(
                    '67884b80a71f55d3160a7e8026497c433aebd9f73b9499e3eebc19b48268c32f'
                    '3d2303bd2d47c298a29b0ca51678b7f416ae1527c9e297beb539333cbcbade4b'
                    '0358c9da9be0c8d23bebf6b01cfb292d9071307e41c07cc27027807dadd1b729'
                    '144ec0033a6d31a7a3969e5ce0b0217768a3a8a746df3c87967a378b98ae200b'
                    'c398c17681916fb41c702966e51d61c09711405f2056053d98bbf97641b232e0'
                    'bf789215e0f95d11e10fdb1a4c1893d370eaf1784750132d2a0206cf30f98d66'
                    'e832fa03305f6f06dcd4f084dd5a70d62f5e9170062882ae165bfc8878842c03'
                    '64b97575e72df61bbcccefad9b85a68df47a984761e6a0f0c792ff89208bfd45'
                    '1ae6ca32eea30eef4f8e23e08246cd848d335d2d86cf44e6e3348e3cfb8d35f8'
                    '609609ff5fd4469d2dbb38a5e204f4065b3dbcb1e1835dafc9314a56aee71278'
                    '319ad917fe547eaf4b6105d8d3b9c7680e3a1ae426d952ea90fb8cc013d7ec47'
                    'fad46d554c105726d27496d1af967675ef665922c2fb647b29bba606da802cd6'
                    '36a54b3dd42a19be2e6801003a7765b9a9b466ac85040fe1479b1fac30e47f7f'
                    '349dc867f0eecbd693128975dc1fd4015a4c253ddb5164fffb0556ffc77db5a2'
                    '5fbfc692ac6d710c4b96050bcf56a4a03ca881c2f7901cec7b878ea8c056e3eb'
                    'bb8d40b9ad16ef66fb8a48793f27d54847b020a2922a41297475d2d48656ba2e'
                    'dccad8140c68014eafc307bc1446ffc8549b03067cdfb52ea7763f4eb0e337eb'
                    'd22093c41aea70fd5b5d8b35eeca6d15b876b8abf01c4a8192ef3961a01eefcb'
                    '70acfd14'),
                'out': bytes.fromhex(
                    'c10219cf368ddfb680e526e11a1b5e7359215b84e4a64d57ba00b04512a717ae'
                    '4daba78f715883e538483a46907e77bbb113308e6d26bd69ce6ce069e055b685'
                    'f3e36f9e0c14a5d7d1abb77b23a7f5e0'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('01dba523114310d50eb4e53c91820c72a69eb9152c87d5f109993481ba973971'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('93230114c4c52e75ec9dc038aaca803fb603e93a97d93fccee4828efb45a153e'),
                'rk': bytes.fromhex('9d66f8dc6fd1a77a333218e706d32bc39cec8762d1d03d1d1875618c654d0e80'),
                'alpha': bytes.fromhex('7cb83df4bace45f805b2b3fd11cc619e4fa3680bf02b1ffab81b9597307ba50d'),
                'cv_net': bytes.fromhex('e096705eb994c3a642b5ad9cf6101f97ae21f598f6df2dd92b4065e0aa410f8a'),
                'cmx': bytes.fromhex('1fcc601ca83b576c969a946cc0fc839fa5f4a5c79028e401e57ae28a876f0421'),
                'epk': bytes.fromhex('98e9e62857ecbf63fa5ac554771da098fbbc0916b229581454bf2ed4110e9812'),
                'enc': bytes.fromhex(
                    '3250ad1c60f1431694c2cf131eb22762386d0caaaeab3e8e3d204098f2ee9a7a'
                    '71b1c0c442b32812f09715fe328fa2be96a049d0551cecaab3f53fbf1e06c67f'
                    '506b68987986448df8fc52738722d4c6974b9ded1980488e7afe0ada81ff9ea7'
                    'c9b1a487735c5c793b6942e61ccb4c60a32dc3c481112d781948db61130f4af8'
                    '21eb5cf087f18eb64899026a14d5841db228ce27c9496db2272c06b2d9f97fcf'
                    '9070358c7627a5711e34870510c92895761f7520a3d8e465e8536694f54a5352'
                    '73390a4aa53aa861edadeb6bd2cb490615c0c9a162ddd981f96d968ef7957e31'
                    '2c7da312c3038944aeeda1f111345f57557e103f8503d5d6144a0ebdd873115a'
                    '1bff4fcb83791d5c4f1c5d21c71b316f2daa868fd2bd100b82c3ed86505db9c3'
                    '9a2f2aa618eb77791b4a10a7e5a8e59c63aa5cfa211591651af39a2208fffb87'
                    '2b4d42e0183fd8a4a7c00575cbd5f3d6ef4e0ed10505d8af5eecc75bb8b576b7'
                    '7c8ea652f6454151666438bea8c325ef65a8c8d2bcf262be8d11e6e2aae117e2'
                    '8020b31faca1ea6b56ee0ed0eaa0d55e10242a77a3b95be92597ef8b2584d9a8'
                    '5f8f9f0df5c142ae50b106913c0a64fa2ff5eec1d2c475fd2e82f57fd4512160'
                    '60cb7030e4e5696d1bb5e33c5b2065474b596e55ab818cd7a5426493618f0775'
                    '7c13382f6c50931230a0e9fe5f1bbadc8713c057db04b7c8e3139a0eed550bfd'
                    '634533e279b9fe9dc3ecd6489119db4e3181dc912c567a29cb237f940ccefa77'
                    'f01c3c5e835a1bdef8596348fd6070eadfc9773d875292a5adf3baacbe1321d6'
                    'ab6c75e9'),
                'out': bytes.fromhex(
                    '9e205080da9edb1fd3b6e085573af34227aec4ecad864410de66490b60c8a62c'
                    'd4a47033b4e4cd8588ab3179001ff4c2d740e0a6d3bf07e6876385a46a5ef69b'
                    '65d5a6779a8f93ade6be5d06e1b562e9'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('f6acf873f135d7e04bf21774693489e45932921041c3199618800927f88314a3'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('a8f517b0c5ad9c9661b5cbb54575e35debebf8494330d3de71b21d35f8f18735'),
                'rk': bytes.fromhex('d9580d672676562530ffb3c2af3c930d51486210c17ecbb0d2719f37fbac06a5'),
                'alpha': bytes.fromhex('b9400ad4f74f9b3bab7dba7490fe19e1658f376c4d05176f1f55a46c98ee6d17'),
                'cv_net': bytes.fromhex('434b0e3c18eccc0c9537b2182cdc06f37f567ca8ce83546bd00c5d2d0ad8f098'),
                'cmx': bytes.fromhex('7b45c8f7a62254eb30e6d0d650314276487a57d596e9fc2876f3768bc6cfea17'),
                'epk': bytes.fromhex('9dfbabd58f6d0efe50d452a99ef1e4641013f9e06927354f00de88939ce87486'),
                'enc': bytes.fromhex(
                    '432df485cecaeb63e5951044143da40415e2312a340e4d907b3466f7393f22c2'
                    '9aa7cc39d3f39fb0e33dd6ca0a888565f112c3bdcec136d585e399637384cc4b'
                    '3f98e55d2eedc76b13bf7b8eed1cdcbe06032a1be7a6c0fdff3d53b745a93e74'
                    '79aaf87585d9a7c05d8243be062d5a067e179fd1b1ca433317ac6152bc45b72a'
                    'edb5cfed7cabbecdbf67f51636de3763d597b11c6c2ebfe15ab0879293e96320'
                    '652732a93fe627df9760c095bd72cec8e11c3a007148e4d6b787a1c4ebb990b8'
                    'f5c2ee794b3feabdc443b21e50262798dfd4bc2e7e20be77daf4ac1a250c38ef'
                    '3fbf43514c62bfe2c58e17cdf3f6a3209ece9b38052a9bd5b396a2e817b80bb2'
                    '70646ff00cac2d6e03ce396809dd8f71d4f943f2d6c11cd9265c3a8d3f51503c'
                    '91d5f028b5cf68fec248621f38a17a71dfee52e25ad6660b8a1825ffb9f8fbbf'
                    '391e4038d4ba51e06e38972ef597ecfd62bba8a43fd92847b9bd56dc6a1370d0'
                    '463e1a70642098d68b673d530f8400ae5b083506db5b6b613740c371bb1e6180'
                    '9398b72e1859b3d723ca8bfd3ecfffa22f14838a0d9047be360aa795f0f60a9d'
                    '368ced599ca8e899e3c2313c08a2162a5e748168b44f5014564e34b4679db0d2'
                    '9f9ed884b31884ad561c137feab5e94f2abead3a4f7845293ecc8cb55c33e995'
                    '4b82fd4e5db3f3ae072e542049249aa55b6f9d4b779e22d305b6d722f11ea90f'
                    '47931532e763aac84f8475e3f16fd761c51a1c1c6c2f8d5607a9b8e878451825'
                    '5f1f492083ecfdb8ee096407cb960f85594908801d0e158bc1706fbce13d4435'
                    'ad4b716e'),
                'out': bytes.fromhex(
                    'b9e292eb7b5a72ef9ff2eb20781bea6cade7b2e08a48c76b16428ff68cd5958f'
                    'a2fc90eaab442d6ca2308c79b4f6c06084fdfd95feeb6368eeb8104fde692e7c'
                    'f4fc22fff2a6169052589a0e90717198'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('ea010bd93d0fc3dab9df9dda4c97d5eb97239ef14125990db577b7d2e6255a48'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('8be3f4d69956566229a1c9eb93706d6cfacea806d84c10917f74e188a9cc943c'),
                'rk': bytes.fromhex('80c9e3061bf4459060267edf1dae4c65ffef5d195877f0db23731543663f2f82'),
                'alpha': bytes.fromhex('f082eabd7c9c5f61b451344c08464e50b80b5e37aed95f2f91c4b72452e5f114'),
                'cv_net': bytes.fromhex('8921d8eb9dadbf0305ef3fc6181aab0eb5279349e6230a72fbdd3527c1a7e088'),
                'cmx': bytes.fromhex('366eba72bbf033716b9c8bddfcd0d1e1579beb762c75c20ebaa1889de454a307'),
                'epk': bytes.fromhex('4d70467ce11de44d408fa3d70615365116075dad52a88ced8b626652d10f692d'),
                'enc': bytes.fromhex(
                    'd1c554ff7a8a890588b74863ced1524c9c8c70f7b40596869c694df71970ff09'
                    '5bf8033f956c3f89ca53ddc6fcd8b55335483a4a7c93431b739d66ed1531a792'
                    '0ba2a7067d21ebd12119560fe7de48aa729e96daec16e4b7873528252e2f14f9'
                    '06851bd05df7a80745fc83ba8658434054063536c93c9947cfdd143c9f44d02d'
                    'ca9fd3cdc8379ba1fcbc985220ee2c91210f33f6a6f7190b4a48f9084a54ec55'
                    '0e6359acd7ec940d1434ed6c6b56d5e297592f4b03925e0e5fdd646052ab458b'
                    '85cad33b27ab5f5bfb719b92010f58b136e14672bf4e5ba5d864979fbb50fa60'
                    '965de41f9d605f20a42f23274dab99002bb469a72f6a89e77417abdaa1a59b7f'
                    '7ceb374d3876496359672a55ba8fb366273041d48713a06177eec5c9f5780184'
                    'e4ce2ac57a6d54a4e2092ff8216786536d2e142bd67433d35278b459cbe40f58'
                    'd4260691e19b5233f9ebac6f4f834c58fbccc3a6f2396f0644979a9b9098cacf'
                    '06b96fcf275df4b4e9dd927a8be3fbcd24c1e16e0fc8df973034691989d10057'
                    '99e2242496d3e1654015479eaa948dc5bae0c71f8b7f3105ce3c77020b7da5be'
                    '55e55d5ed3fcf764f0f5a405fe89f3470ad8b2d912efe99c8923a208fe6ab155'
                    '60a246bb18b01b1afe31d3902f2ccfae9c2fddd346058ba94b82f5baff187576'
                    '3b3befca7fead99325f80cf6dfcc23723356b855106fdf259bf7fb8504826ea4'
                    'cd29ec1e695f3049c24f42cd919ac3553acfe75004febac20c35d92d1a21c12f'
                    'b6d906e18741fb8bbfbd3dbd1293fbff197385f55adf1e6b3ef3af80edc63110'
                    'caabf9c3'),
                'out': bytes.fromhex(
                    'c17ba0c208ed0dd0411da64971b00cf404eb980599c45faebc6b3f1cbae311b7'
                    'c262a8a222b20d386e990c657dcca6471e79fa5b36edd7acc40a6d5294ef7aa2'
                    'f8b18f3f7566218067227cb7574ef6c0'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('f1d5593b77bb5d5918c0bdecc5651d301e6a7b435461809626a741d119bb0b35'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('1b54c34cc8292f6b79f51d2f91b5c9bda3627beb0e675add3fb37b3ab939c516'),
                'rk': bytes.fromhex('4e3b84aa7957fa0a0ba3c22782067599a2b70003878393f914f07f19eeadc832'),
                'alpha': bytes.fromhex('98e18b95741626e10f4872c434db7ec7390750689b51803adcf291d1318d4f0b'),
                'cv_net': bytes.fromhex('22ce1208b3d6638d0cecce265a815cdb57d5bfaec4bac5a14a2ef992417c303f'),
                'cmx': bytes.fromhex('9f65f0016b01015217c5abb05fcae0b1a1d2822057add19b35076b2e05f0192c'),
                'epk': bytes.fromhex('7ab81a60e6d8c6a2490f8ecd724c46711c542375dadfbcd1e5c70019420c2282'),
                'enc': bytes.fromhex(
                    '6c802a261b0941f99873b3e209466b249a272a139963bafadd71cc5b64afc98d'
                    'b6f2706189467a74c05ae8a02ad328de8aa12d4e5dee060135e3b94e1cc0efbc'
                    '5866c91b3301724f7131ead81efd7a0c520cd1474028e3407488893b6b45b9de'
                    'f8f753122f7ec2cd0c49a3eb06b64d4d2835e94c380051af5486012f401b8c81'
                    '4c6331b976b0b65527d56e136655766cd08084f4fd7399a17171c1879330bb98'
                    'afbb5cc756168c44e4b0df9b52ab7fa35bc193c99f5ce6df6313e5da0b445d94'
                    'fc12f631a3bd231fdf0c0be8fd2cc98df50b4fc5c4853177f4f22e270c59c6d0'
                    '7556ec5f5e82244bd5ee9bc148ca02daa3ae2bc460c65ac73b0d5a803878ec6e'
                    'ba1e91ce0574b386d28a1738d004ac2bd93f4c9c1d5f90fa1e6ade99a87635c0'
                    '711a7f740dcc0c45210f06adb4ca90f54e8668fcd1a45260de2f3fd967ca4986'
                    'ee9c90767f9734e448061d72886f800b20a783989a33b46c960078fd5beb0638'
                    'db8d24907b5d8c15ee8eda056fc187d8eceb2d1245c5f7cba5b98b9bd1b56c2d'
                    'f35757f87ed07dc5e6214ea25f1d8384afc00b60894fae3e17ee619975794cdd'
                    '6de4eb21c3d92d57d019b2bc3c98f08d35c1cd12382cab10f9f7532736767bb2'
                    'a2e8cf5c6d51c8526652c00598e97695d8ba522dda0c50e8eb1b446e6d00c2ca'
                    '820fddde2c4c5b4902cb9aff51d7d102cfa7bcee0202fe0d958e88a00373d5b4'
                    '69af521e264d6b6a201c0f6559d89884acb4a481d9b56fabafb4e59c70d846c2'
                    '815a090dcc98cbe5a7d0cfa5287d9315056581cd89667a9c085c6e77ab7577af'
                    '30ed55b8'),
                'out': bytes.fromhex(
                    '9644bb917c9eebd52f057e1a863889f4992574bf57b5166073b245f2aa6bbcc8'
                    '4dca318ea3d0b80e193e382938c8b41fcec4757929dac9d443c67000b29f7eec'
                    '6c7ce44a19afab60dbed39300731fecd'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('b7de09450e2fed78853c39a0fc18af601066bccb870003c4db47aed37040bb00'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('762eba63803d81c90d7d38e08f9c62ae3de0ea98495cebfbc212fcb0b625f231'),
                'rk': bytes.fromhex('de1c617b2474661d10fa5e472538f2c289ca63a39c637f8988c3532172364816'),
                'alpha': bytes.fromhex('526f668e2286b53400e4f4bc12fa99559319be6d14f15ffc00086c7215b9a314'),
                'cv_net': bytes.fromhex('a062251a60672e947dcdb248efe064196c2f1ed962708672f67a28c0ea541d1a'),
                'cmx': bytes.fromhex('e0e01ee861405e4f11b27828183084a1a76006719679e8dfe05c06b2d9b9c81d'),
                'epk': bytes.fromhex('8f9acad54e4c4ceb63626ce76d7dccb975480934ae7348137d01f98636c4bdae'),
                'enc': bytes.fromhex(
                    '378ac9089167edecc577b1b28c02580ca55f8c64acd6a747eb21a9fb59375b70'
                    '7ab5ad0cd0a7b5c59fae6fd0b8047206d97c59fca7ec148cf31907bad0080204'
                    '72ea9a00c2df60df5ca53402671edd36902573d6a91d81b10486dcbfb5f49736'
                    '858f913f65233143b58bf06aea901994440b94d6b1dba85be0c453c45bd8a88b'
                    '4378559d4f68cd5e65ed2a57182adb0ae93728c912cb3ab513f037f7c5216095'
                    '4db465d49eaa6c6f3025fbe703c37b4c9bd0d354bf0016527a69c64c2adf4e43'
                    '0a4ceabd84b0f021df50cd5f40d197d07e414e9e9743ae9350f17d37abd688b6'
                    'a2316a63d6863972f07b2a400969f3e558c9ebe375e31096fecc3c05c8e55f83'
                    '5d7d40a7e1f9b26d4f8a0669a5eda32e7c7317c5fc9799986acd96c52b565094'
                    '9d44932609978ef3ff85fb9f62072213d493b5a6e8343132aac03396c706de43'
                    '11ebece4ac91e1b6c361a1cc244e8af083657bf84bc9ebb09dc617c339c23e1d'
                    '7e763fd1413f0e5182ee523b6fc3438eaef2ba931574bd72dbd45ac6eba2d161'
                    '43ed70093c7e2fd7e1db14054c9cfb7ec6bc89f3bb7e99ab9aff08467c624072'
                    '5ed0bf560bc30687921500b4b4b030984a2d3b186517e7d19493d2ef6a566711'
                    '153c020b3b3859a4eef0929348016997139608167db4c84b5854869454548357'
                    'f324dfd8ee8c4b19b0ce6dab70954c87160c0f9828abea8eb05841c08646d725'
                    '32ce65bae94ecd1a48f3a0114b65eeee4aec7003687ca8dd28800cb1ce80c759'
                    '0b1b62becf1be211375b4fe438710d38fbd7889096995e35347f91eca6b5e8e5'
                    'fec6ba19'),
                'out': bytes.fromhex(
                    '88e413bcd8f75391cf3df89bd64ce8dc7a0d741679223f02c8546d50856a3cf4'
                    '48365f976b567eea5aa1219a66b30eb04ee2e3c472a6e45aff2ea22b0eb1d14b'
                    '9e6fbb2a1b5e699d05e3036b28d832a3'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('211558a82b0684b453222b1171beef68aeda93b143b9368b5a0c40b1df7322cb'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('05aa1878dfd335dbce602e1a8cd23986ee6a85c83e77e886c6acc5f2330f682c'),
                'rk': bytes.fromhex('4e54d29b80fa7f535d2a8c5a2784f7ad152c44a2a87b2d817ae3361fccb0d4a1'),
                'alpha': bytes.fromhex('f133a7eb65d87ff41ba8f909d0fac69cebf863f40d3225c559a823def2772b04'),
                'cv_net': bytes.fromhex('c3c2670c08676d45b580a8ccfa206e3683feb88a5f9406e20ed30eb355190409'),
                'cmx': bytes.fromhex('057543e8f38759e6cf094ccae696826f4eac83e64779ecf3f74ffba3b6a41c16'),
                'epk': bytes.fromhex('7aceaf5b50896ae5c8e5856313b0313b9257e89c4140feab46cfffd2261b2a81'),
                'enc': bytes.fromhex(
                    'd0295cdb43aead4bafd89cd3e796ed7d205576af427f1665fcf890fddac1d94a'
                    '1b422fee2b1a39631fcc49056bf3fb333c2dd9aa7096bd8382c48a614be6b35a'
                    '5f236a6b3a7148d2c2259be05db67fbf008106e4277f39b8ccf479e4c132e4cb'
                    '6d38b956eedbf98b1f33ca2da57949dcc305460b7e279cba6ad6b189e0a74dbe'
                    '52ce18f32fc9096b3eb58a71637b472b1da4d0359a654101fa0ab40412212134'
                    '903ee4a996d877b43f292381c01919484a54d927dbb6bfab98fbaf4a5d655241'
                    '4ee223155459322855ba6b4dc8d28336ecc9b4ba66580bfd93541f0d2100ce6e'
                    '272ba130a05d73c7190f11148f4443181e6ef2214e96af0a4a79c5c61e84c946'
                    '2aa6a4b552f6364051a87c674e9306bd06256c2f3cfb382980b57cc9f542cf24'
                    'b122763931c17ec1083b2056a55f50383421e56d9c293a919c40684cc9d2c60e'
                    '4d0b83a1b80abbd373e35028cb01e11bb2eb6a6dc1f4210090e1edb8ba318b12'
                    '56081c5f861ca3d005b72fb3fef89032703c12a4e0f4c314c214e77b87a12af4'
                    '2b72289d61334aac4e6abf13ee47ebe459ec2a5a14253a58687c7b52fe67d919'
                    'c2484f933374e09d746da0d16929151a5fd22dd39955fd1feebc7d648f3924ef'
                    '93b309990d9ce740d388caef3e0f5935e34c17670241393702f1b8d9fc7efa38'
                    '83d67eed63b477887c3dc8356fdeabd11574b108a06695801457bd53eb9fcf2b'
                    '1360423b82eab0401b89fb956f8fd2615d037d2380b2c6e1cdbc33c3fe376601'
                    'be0eefdc6e98e5ce2929cd7e7c70ee4ff8ef7988b57e4da5b5b17b5da29fd03a'
                    'f6d75d99'),
                'out': bytes.fromhex(
                    '61a814cb4fbe7c77bc339a4f3bff21ce26a9dee3c8ea1ad8b886ee424601f976'
                    'a956e84c22097081763ed29f3a8b11a8a88824015424c29958c5d8b7cacd0962'
                    'd1e9310d25cf0a2694f883eb0007cb78'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('c857fac23f3c2410be8c8a1000915edd2e1b781493e0b4e4a07f539da5f9355f'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('80bd69243039fd9f893a1db9bfa2a90bb42b0435c68a4de69c44ee96397e7217'),
                'rk': bytes.fromhex('b75f29780411e873a54f66e2196e6dfbb2692b74f880a0c16622211ef2cf690c'),
                'alpha': bytes.fromhex('06509facde7313b6f42003afc3ada326f487c1bb51daede42037fd2a1c313106'),
                'cv_net': bytes.fromhex('84f5d51ecc7d7f6861c295d83b4cfd5a12cd25c97be1d194cbe4eb048d0764a7'),
                'cmx': bytes.fromhex('b3fd458b9111b4944613a695c8396c19be004562e41aeb9e2d091e1457d3f83f'),
                'epk': bytes.fromhex('be4d055f42218ccbe8be8bf130b950fe6672243d49d2ca91a9056e08e5554f2e'),
                'enc': bytes.fromhex(
                    '88b493cbe854943130f7d811e2003fd70fb606e12ebcd3fa5e920d949743dffd'
                    'a421643863cf8e51c71c894173b213e8d59479674fc1a4493397b14bc81467c6'
                    'ee4f97f29a938bae7646b89e8900f0d9ee043b1e19bd0aa56c14496ce88794a0'
                    '59723ef024431c0279b49fceaf6bb81370998520a5c710f1349e53dbc567463c'
                    '339553e375c575eea58dac685350c389b3b1658d0221432ed3722c94ccf5d6df'
                    '0fa7fe60a1b4615ef9b7667cbb9bb012f1a4fbdc54e47ade84393514fc4ac359'
                    '2159af250081a3a8317b9904928959553224017b709f7819e1bc676baf44dc51'
                    '1710988d90c2dd14f8fa30e81efea9ef7ff3d748ae2de43f0ff8726d88f140ef'
                    'd178611768224388f62ad1cd4893650d352d1fdab6c7825e1e6fa08125f9cc98'
                    '862eb48fc4e5de2dfe7e5297a7ba2cf2ccc94b37d06fac064c4a4a20d4c61352'
                    '2ee7251fd22e8a3cf6ac9cbfdb631cca65ca201615d10637fc5326ebd1732e44'
                    '1f342bfc5fd510e99a83ecb10a1e5e1f4cb75e2062f851de7828f317af783321'
                    '0459a8784a52d01a5405ad28ae93b509d672d3376c7cf1386426992e32fe1191'
                    '69eb5ceab02f44d1bf2fb7c1d8f7d9cb5edf47fe68cd91091e34879a00a834e8'
                    '77d8ed8841ae776259ae2225f4d93614896630e74635655fff3eafaf3317039f'
                    '53afae9aed77b71cc33098ca84bf8df70d7e10133ac5b40f05fd1b5a81eb3772'
                    '1e3448d624ff301c69f69cdacbca8ec077033939af9fadb05b601514b024f476'
                    '373afe9dc31334eb2afffeb47bc1b79245d064324ef1e6185bdf865ea71e43a3'
                    'f4d5a341'),
                'out': bytes.fromhex(
                    'c5153d598e573e369a83048eeb7f7a33fbcae9fc38c01cc86450cbbb79ddc15a'
                    '38768fe782efbdc2d595c7ac047669c5da4f12ad60f8e83ac679c6931089304e'
                    '7e00ed59ef7aa2943ed9b57e6b5e6c48'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('fccf09a55f9a8bcd8cef78fda81e7327042fc4b5cb89f98d082e1536bdb134b8'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('9626584a16d66fe07ebf4f3c882686e408209f3b0466dc1acff98bdb5083881a'),
                'rk': bytes.fromhex('3d193701dd72c6e5b91c5ce173283391a9b838db3e322f8726e7b9f70f8f0830'),
                'alpha': bytes.fromhex('ff5e8f768ac3da0c5fe125323d57b107348dfae35f7814038c57bf9b72a50229'),
                'cv_net': bytes.fromhex('46877a8ce2afb3ded4da748f3165368d1e6161ac95fc40c3841a093107a3970f'),
                'cmx': bytes.fromhex('959c475be8bf479932a20fc31ea661c23c47d5f4ca6a9634e9efad8da528c70e'),
                'epk': bytes.fromhex('c5aa46b209c2bb664a085844288d2712b1358c0e134cd6de9e8341bbbbf3bd33'),
                'enc': bytes.fromhex(
                    'f3cee24d5ea281f27a88653b3d81079e339e6c54427c88444b9843a4818a6dd4'
                    'e2f0de12b80e02fe95801d3cc2032c68395625a84763daca66f4803405ac2633'
                    'abd46fe0b5b2d1f1ddffe1b9e459e5ec55562ace3d4a1d282ffe55bdbe5edab1'
                    'a09efb2556d3642922c25dc9827601a6257ee34d07f03ed5495e8f7a5e808e4d'
                    'c63b8cae4755079f99775e7ac7242cd3793352a813c13381fb5758d798be1899'
                    'ef901d6c715303e66ee7506ca15d84a78461518aec81cfcb820c998e73838213'
                    '5c99d9daac438d71d24f732a92d2e139c824650cc73a8cb0e3c0430cfe46d375'
                    '3ee7b8ba452fa54dafe52d84946b9bec8c42d2d9e434c2ca62fd6fba7f1decb5'
                    'c14de077b2aabc1a83e80eb78c300fef35e0e781cb0d7727bcebe09efe1f0985'
                    'ef9cf15ea4814d3a7836207ee6769ba72b5ca957100739587c1b9fe9473b0f74'
                    '05eb94e2c5d4b3f4ae886815da966ad7338529e05cb1a1733e6266a530c4302b'
                    '8a9c3601f7ba26ee9756938983b7bd41b3405794c2768c6c9dded0500f4dbdd4'
                    'f0eaa9161e553674c0791c13ed7f8b233778b3a93ab366166bb0fb2ab3a03e47'
                    'a5decfef4c224640458d5b4d85cc91edcb799e445b1331e49e0e8325c41103fb'
                    'd54e4dd45a9f71c445323e99a65db21e9aace73e1cf8d9b91dcd481714bd8c3f'
                    '133132c30a3f3613eb6b08d905f104244c3952b953439c237c59dec6596164da'
                    '45d3d456d8c283b8759f7367ed232c7b3e7ea23c5d401dc09f3a8717b8e3a621'
                    '489c2095c1198268237b589ac9831f43dc082f14aea899d807ba60ffeb56e7d5'
                    '6256542e'),
                'out': bytes.fromhex(
                    '662b7206d372e142414db811f3bf16a63147976e8ebba60a006676c92639634d'
                    '65581d26fdeada20db03b26b6ad1dc617daf3c4b26b177eff9193ba6c8aa8304'
                    '3680feb5f3e25273658ccb5ec54207d6'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('6701cfd14370c25c7bf281f3ac777386621102d8ea16e0e124ca72c49a08943f'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('b717ab43b4030e502789837104b0f1d17c52fc85e9feb67597cc37ea6fefdb06'),
                'rk': bytes.fromhex('4b383511daa4696049c4a62841907f4b2a9f73391f399fb5028d8c4f3bea7117'),
                'alpha': bytes.fromhex('e621c7864db5823238401a62fcaa693cba9b0a8d207b0e43a34e9e9ec4d1b536'),
                'cv_net': bytes.fromhex('b7458fa5c8f2a3e9ca396d936220f7dedb5a8461d5964525179ccef4e39a6f09'),
                'cmx': bytes.fromhex('de7008c29a058bd3ca41759f3d3d45da1b7aff891e79abcd592004437a7a0617'),
                'epk': bytes.fromhex('d1136d16826a6ea26d99f2a54ff4b8f1c3c6c615d8bb325ca798eda9de93113b'),
                'enc': bytes.fromhex(
                    '39d375985cad35237c13c10db3d8b11f8670b49a9de9dcde98ce544129cb83da'
                    '345b5393e2949ac27d6efbb02b37e23a1db879fb4678f38e46c2e6b9925c4c04'
                    '8fd9193b4a46cfe0d6fb5d211e9f18955aa8c66ea362508abf10aa77b019da10'
                    '435c8a68dafab7a9647af4773a3dd01e36587d184c32efb6f4dc93a9f1ccec76'
                    '9c6307f1280ccca365cd736b298ece2212193de887ca3a79a064931ff0bf65f4'
                    'dab1876205388fd4238f9a47f431d1534ba716de658671368260a1eec4606589'
                    'c6a0727ab692d0cfddc5c4ca317d3e5e19109c2952629282d53f1b6fc6afd2bc'
                    'f09e2d18a2510689dc087564813a8e27161a49569f311ae8672f648229cea4f3'
                    'f8fe6f1e4b7f6b00c67c8ba9b392b66a3f275c6488c048e5cc50900551090a06'
                    'b2432b717cf09a7b23dd9d872af1bc967dcaf03e50032ec55938aebe011fe6b0'
                    '27497fd69caeeffdd0b1dab2eadc28b362bc845a9a409b94ed428bd7601b6520'
                    'e5992534ecbbff182de27914255658ac9f7cc6d30d5ec413c44a4f24f2d51425'
                    '47e0e27fda435b89008160eab76874016396c996a3a16d78a8903e1195bb8045'
                    '01a2053556cda4ae5ecfae92a02939f06b028727c09d874b5b403a17fe04880c'
                    'e579b628e619af2f506e12207dd3a9cc5f0e08839945c42d912db74d325a1dc7'
                    '161e978b9ddb39fa6944f1776c946f2c7ac450e6e533cd8535a0150547746257'
                    'dae1bae72232adf3eeab141f99d40aaacfd30f26714a1ac0f78d4793de75fff5'
                    '848b71d81440eb9e772dbde5cb3ca5d7c7b10fb39420b443a210abfe29d0ed77'
                    '1e44a561'),
                'out': bytes.fromhex(
                    'aae26bb3b088a37a3442125fe2bc61d0699a77bc86b82a224096c82c60296711'
                    '12b3e888482afdd1085e11bfc08ac01fbf1cc359420bc7f99f9b47d1237e12f0'
                    '3757fa7bf2ffd0967c6e23b60009f9aa'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('e4ee1456a223dfa31cb714824dfeb95a2234ce811ea308b63a4fe4786407a33b'),
                'value': 1015000,
            },
            {
                'is_spend': True,
                'nullifier': bytes.fromhex('e1e8dabd82a6bcba2107fc4a8be64f0ede30355e5eed5bd365db848908fda23b'),
                'rk': bytes.fromhex('64b31d813e4fa32ad2413109882805a1b6d825eed19dc58a86b4486a4671e39e'),
                'alpha': bytes.fromhex('f08196949dd1c2293d8f45a1919ba6d3d51e03e4a79ffce03df30a9aa6c6a527'),
                'cv_net': bytes.fromhex('0cb9920d9da9d1ab56dc2fe03fe7ba0e99d6680319dab7e79480b38ab781751c'),
                'cmx': bytes.fromhex('df52e0d1e9ef1a81c53c00dfdd98ec1063caeb40f796607dacc0a940ce3c2a0b'),
                'epk': bytes.fromhex('a9d9c634dea3e7077601a14ec78ed750260202728d517eae494670da0cbda6a8'),
                'enc': bytes.fromhex(
                    'b01527e05660d0d77f0f23cd2192bf470ea7104ac9219ea44c9992ec5090cce3'
                    '0b930b56cf37e77c034b6ff110f09b8894796e5840309b92071896d5b44674ec'
                    '8af09965c555fe34eb6df782a992c3b1bcccbd6bafefda52095061d3f26ca90b'
                    '000e8096a350a00422d1f85b39c73ddb22b8138bb88ea1b5a69c71c51d487a7e'
                    '1c3b7be3e11c18341483e2df8151505c05eb3315d717b973874a22e2f9164d7b'
                    'cca4cd6465845075084bc4647065df093ba4f521332196fc22488b53f22ce39e'
                    '8088cbff2b5a320c44191472c72d07d343e057c37ccfc2c30e44759ee53fab33'
                    'c3c1a69a63567a862415b0116a6199b0d0a3155a72e9d67295955d835201b65d'
                    '3d5267bcafaaef444f4c7cabc2dfa444ca4589eb0b7a595370a8ffb172c47f7e'
                    '1a87745b78badc91840ec56ae11463b12b10450573891b2edbbec61c5e8b5443'
                    'bf23feb0649c434860d01d2bc3d07a6879ef38a01d09de4b3a1b9ec173accb3b'
                    '682c6476e24c9accbd71d9aad42a1a52871d906b7878cd72d1e90b38665f1900'
                    '258d12da147e1ac2156af74bc8823b9fadb47ba20d369c5c54f575640abb383d'
                    '5723378a9357086241f43c01133081f7d6fdc3aeaaf4f763478c0f6ef20030a2'
                    'a128bfef33b05ea8e3b9565c2b35b49745aeeb9ab43f543469c79ffb28f63673'
                    '645ff957db246104df1984b26de1ef5de5eb0e98562822c21750ff97efa716e4'
                    'a050d027244fc2d76fb1e521547caf6f19f05ae5d6cbdbaef872a2cee284859a'
                    'd173fe53d282c4598725a069c7490963b1524e1ca01bc9890fe42e58fcbdc80b'
                    '8d3af351'),
                'out': bytes.fromhex(
                    '892b762b0d42e42da9a64a52c82c1e609cb94efe8089c75c8b93cf85464748af'
                    '812446c0d38a737e2450d1ac9560b2a7bfca9835a3aad344c04ee19f3ab3e491'
                    '44af0486105188941f2e2294a05f915d'),
                'recipient': bytes.fromhex(
                    'ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0'
                    'f0bb27c032b2e7718c962e'),
                'rseed': bytes.fromhex('bdd6672d18bc9ddbe590b177c010c17470a5263b05c9b770448173b7a336debe'),
                'value': 1015000,
            },
        ],
    },
}


def migration_action(v):
    action = fabricated_action(v)
    action['is_spend'] = v['is_spend']
    return action


def migration_kwargs(tx, fee):
    lock_time, expiry = 0, tx['expiry']
    orchard = [migration_action(v) for v in tx['orchard']['actions']]
    kwargs = {
        'address_n': ADDRESS_N,
        'actions': orchard,
        'account': 0,
        'fee': fee,
        'lock_time': lock_time,
        'expiry_height': expiry,
        'orchard_flags': tx['orchard']['flags'],
        'orchard_value_balance': tx['orchard']['value_balance'],
        'orchard_anchor': ANCHOR,
        'header_digest': header_digest(IRONWOOD_TX['tx_version'],
                                       IRONWOOD_TX['version_group_id'],
                                       IRONWOOD_TX['branch_id'], lock_time, expiry),
        'orchard_digest': bundle_digest(
            orchard, False, 6, flags=tx['orchard']['flags'],
            value_balance=tx['orchard']['value_balance']),
    }
    kwargs.update(IRONWOOD_TX)
    if 'ironwood' in tx:
        ironwood = [migration_action(v) for v in tx['ironwood']['actions']]
        kwargs.update(
            ironwood_actions=ironwood,
            ironwood_flags=tx['ironwood']['flags'],
            ironwood_value_balance=tx['ironwood']['value_balance'],
            ironwood_digest=bundle_digest(
                ironwood, True, 6, flags=tx['ironwood']['flags'],
                value_balance=tx['ironwood']['value_balance']))
    return kwargs


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
                          b'ZTxIdOrcActNHash',
                          b'ZTxIdOrchardH_v6' if tx_version == 6
                          else b'ZTxIdOrchardHash')

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

    def test_zero_value_padding_output_is_not_shown(self):
        """A padding dummy output is not shown, even though it decrypts.

        Wallets pad an Orchard bundle with a dummy zero-valued output to a
        random address (protocol spec 4.8.3). Its cmx binds value 0, so like
        Keystone and Ledger the device shows only the change and the fee, and
        signs only the wallet spend.
        """
        self.requires_firmware(self.FABRICATED_OUTPUT_FIRMWARE)
        actions = [fabricated_action(v) for v in PADDING_BUNDLE]
        actions[1]['is_spend'] = False  # the dummy spend carries dummy_sk
        kwargs = sign_kwargs(actions, fee=10000, orchard_value_balance=10000,
                             total_amount=90000)
        kwargs['orchard_digest'] = bundle_digest(actions, False, 5,
                                                 value_balance=10000)
        screens = self._capture_confirm_text()

        result = self.client.zcash_sign_pczt(**kwargs)

        self.assertIsInstance(result, zcash_proto.ZcashSignedPCZT)
        self.assertEqual(len(result.signatures), 1)
        outputs = [body for code, _, body in screens
                   if code == proto_types.ButtonRequest_ConfirmOutput]
        self.assertEqual(len(outputs), 2)  # the change's amount and address
        self.assertIn('0.00090000 ZEC', outputs[0])
        for _, _, body in screens:
            self.assertNotIn('0.00000000 ZEC', body)

    MIGRATION_FIRMWARE = "7.15.0"

    def test_migration_transfer_signs_both_pools(self):
        """A ZIP 318 Orchard to Ironwood transfer signs.

        From NU6.3 Orchard funds can only leave the Orchard pool. The transfer
        spends an Orchard note and creates an Ironwood note in one v6
        transaction; the device verifies both bundles, shows the Ironwood
        output and the fee, and signs the one wallet spend.
        """
        self.requires_firmware(self.MIGRATION_FIRMWARE)
        screens = self._capture_confirm_text()

        result = self.client.zcash_sign_pczt(
            **migration_kwargs(MIGRATION_TRANSFER, fee=15000))

        self.assertIsInstance(result, zcash_proto.ZcashSignedPCZT)
        self.assertEqual(len(result.signatures), 1)
        outputs = [body for code, _, body in screens
                   if code == proto_types.ButtonRequest_ConfirmOutput]
        self.assertEqual(len(outputs), 2)  # the Ironwood amount and address
        self.assertIn('0.01000000 ZEC', outputs[0])
        for _, _, body in screens:
            self.assertNotIn('0.00000000 ZEC', body)

    def test_migration_preparation_signs_sixteen_actions(self):
        """A ZIP 318 note-preparation transaction of 16 actions signs.

        Every action carries a wallet spend (one real, fifteen fabricated), so
        the device returns sixteen signatures.
        """
        self.requires_firmware(self.MIGRATION_FIRMWARE)
        screens = self._capture_confirm_text()

        result = self.client.zcash_sign_pczt(
            **migration_kwargs(MIGRATION_PREP, fee=80000))

        self.assertIsInstance(result, zcash_proto.ZcashSignedPCZT)
        self.assertEqual(len(result.signatures), 16)
        outputs = [body for code, _, body in screens
                   if code == proto_types.ButtonRequest_ConfirmOutput]
        self.assertEqual(len(outputs), 30)  # fifteen notes, two screens each


if __name__ == '__main__':
    unittest.main()
