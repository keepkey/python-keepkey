import unittest
import common

from base64 import b64encode
from binascii import hexlify, unhexlify

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH = "m/44h/934h/0h/0/0"

def make_send(from_address, to_address, amount):
    return {
        'type': 'thorchain/MsgSend',
        'value': {
            'amount': [{
                'denom': 'rune',
                'amount': str(amount)
            }]
            'from_address': from_address,
            'to_address': to_address,
        }
    }

class TestMsgThorChainSignTx(common.KeepKeyTest):
    def test_thorchain_sign_tx(self):
        self.requires_firmware("7.0.0")
        self.setup_mnemonic_nopin_nopassphrase()
        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=16354,
            chain_id="thorchain",
            fee=1000,
            gas=28000,
            msgs=[make_send(
                "tthor1jvt443rvhq5h8yrna55yjysvhtju0el7ldnwwy",
                "tthor1dheycdevq39qlkxs2a6wuuzyn4aqxhve3hhmlw",
                47000
            )],
            memo="KeepKey",
            sequence=5
        )
        print((signature.signature))
        print((signature.public_key))
        return
        self.assertEqual(hexlify(signature.signature), "4a200cc240df784ac19d1c51ee1ea47c8e257327dd3a3c4ff89d90cbba861b711d3a61929ce3c41e68c4722e63e6a60d553c46b82e9dac3b1f6ad9382b508ccf")
        self.assertEqual(hexlify(signature.public_key), "03bee3af30e53a73f38abc5a2fcdac426d7b04eb72a8ebd3b01992e2d206e24ad8")


    def test_thorchain_sign_tx_memo(self):
        self.skipTest("skip for now")
        return

        self.requires_firmware("7.0.0")
        self.setup_mnemonic_nopin_nopassphrase()
        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=19637,
            chain_id="thorchain",
            fee=5000,
            gas=200000,
            msgs=[make_send(
                "thor15cenya0tr7nm3tz2wn3h3zwkht2rxrq7q7h3dj",
                "thor18vhdczjut44gpsy804crfhnd5nq003nz0nf20v",
                8675309
            )],
            memo="Epstein didn't kill himself.",
            sequence=3
        )
        self.assertEqual(hexlify(signature.signature), "9f2434543bc4afd2fc7bb43db05facdd6d529aa7c467ef0d41e1c2954f68db9942b8eb431cf27b52d1b3d914bbde076960179b7f426bd1a182448bb9c245009c")
        self.assertEqual(hexlify(signature.public_key), "03bee3af30e53a73f38abc5a2fcdac426d7b04eb72a8ebd3b01992e2d206e24ad8")


    def test_onchain1(self):
        self.skipTest("skip for now")
        return

        self.requires_firmware("7.0.0")
        self.client.load_device_by_mnemonic(
          mnemonic='hybrid anger habit story vibrant grit ill sense duck butter heavy frame',
          pin='',
          passphrase_protection=False,
          label='test',
          language='english'
        )

        # https://www.mintscan.io/txs/93c7f98bf0ab2f727832f08344d8bd8d0c14021c160a904c512b93082d2fb694
        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=24250,
            chain_id="thorchain",
            fee=1000,
            gas=28000,
            msgs=[make_send(
                "thor1934nqs0ke73lm5ej8hs9uuawkl3ztesg9jp5c5",
                "thor14um3sf75lc0kpvgrpj9hspqtv0375epn05cpfa",
                1000
            )],
            memo="KeepKey",
            sequence=2
        )

        self.assertEqual(hexlify(signature.signature), "ff04dbada6d95d2639d1a6a62b23f93e958d22423156f771248520b495c58a7a0aa1a877ce3819544d203e400c9f256b9fe49e1fcc1f723964c73e1df0a5e3c2")


    def test_onchain2(self):
        self.skipTest("skip for now")
        return

        self.requires_firmware("7.0.0")
        self.client.load_device_by_mnemonic(
          mnemonic='hybrid anger habit story vibrant grit ill sense duck butter heavy frame',
          pin='',
          passphrase_protection=False,
          label='test',
          language='english'
        )

        # https://www.mintscan.io/txs/93c7f98bf0ab2f727832f08344d8bd8d0c14021c160a904c512b93082d2fb694
        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=24250,
            chain_id="thorchain",
            fee=1000,
            gas=28000,
            msgs=[make_send(
                "thor1934nqs0ke73lm5ej8hs9uuawkl3ztesg9jp5c5",
                "thor14um3sf75lc0kpvgrpj9hspqtv0375epn05cpfa",
                47000
            )],
            memo="KeepKey",
            sequence=3
        )

        self.assertEqual(hexlify(signature.signature), "71295606d64f1fa987fea1af2292d0b735a5c2d5104b7cc3f818a7208ea9b1a504a386c40011242c115f77268c67af841d29137af5d608d21361ebc7e0513a11")


    def test_exchange_src(self):
        self.skipTest("skip for now")
        return

        self.requires_firmware("7.0.0")
        self.setup_mnemonic_nopin_nopassphrase()

        signed_exchange_out=proto_exchange.SignedExchangeResponse(
            responseV2=proto_exchange.ExchangeResponseV2(
                withdrawal_amount=unhexlify('03cfd863'),
                withdrawal_address=proto_exchange.ExchangeAddress(
                    coin_type='ltc',
                    address='LhvxkkwMCjDAwyprNHhYW8PE9oNf6wSd2V'),

                deposit_amount=unhexlify('0186a0'), # 100000 RUNE
                deposit_address=proto_exchange.ExchangeAddress(
                    coin_type='rune',
                    address='thor18vhdczjut44gpsy804crfhnd5nq003nz0nf20v'),

                return_address=proto_exchange.ExchangeAddress(
                    coin_type='rune',
                    address='thor15cenya0tr7nm3tz2wn3h3zwkht2rxrq7q7h3dj'),

                expiration=1480964590181,
                quoted_rate=unhexlify('04f89e60b8'),

                api_key=unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                miner_fee=unhexlify('0186a0'),   #100000
                order_id=unhexlify('b026bddb3e74470bbab9146c4db58019'),
            ),
            signature=b'FAKE_SIG'
        )

        exchange_type_out=proto_types.ExchangeType(
            signed_exchange_response=signed_exchange_out,
            withdrawal_coin_name='Litecoin',
            withdrawal_address_n=parse_path("m/44'/2'/1'/0/1"),
            return_address_n=parse_path("m/44'/934'/0'/0/0")
        )

        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=19637,
            chain_id="thorchain",
            fee=5000,
            gas=200000,
            msgs=[make_send(
                "thor15cenya0tr7nm3tz2wn3h3zwkht2rxrq7q7h3dj",
                "thor18vhdczjut44gpsy804crfhnd5nq003nz0nf20v",
                100000
            )],
            memo=None,
            sequence=3,
            exchange_types=[exchange_type_out]
        )

        self.assertEqual(hexlify(signature.signature), "4a200cc240df784ac19d1c51ee1ea47c8e257327dd3a3c4ff89d90cbba861b711d3a61929ce3c41e68c4722e63e6a60d553c46b82e9dac3b1f6ad9382b508ccf")
        self.assertEqual(hexlify(signature.public_key), "03bee3af30e53a73f38abc5a2fcdac426d7b04eb72a8ebd3b01992e2d206e24ad8")

    def test_exchange_dst(self):
        self.skipTest("skip for now")
        return

        self.requires_firmware("7.0.0")
        self.setup_mnemonic_nopin_nopassphrase()

        signed_exchange_out=proto_exchange.SignedExchangeResponse(
            responseV2=proto_exchange.ExchangeResponseV2(
                withdrawal_amount=unhexlify('03cfd863'),
                withdrawal_address=proto_exchange.ExchangeAddress(
                    coin_type='rune',
                    address='thor15cenya0tr7nm3tz2wn3h3zwkht2rxrq7q7h3dj'),

                deposit_amount=unhexlify('00000000000000000000000000000000000000000000000000000002540be400'),
                deposit_address=proto_exchange.ExchangeAddress(
                    coin_type='cvc',
                    address='0x1d8ce9022f6284c3a5c317f8f34620107214e545'),

                return_address=proto_exchange.ExchangeAddress(
                    coin_type='cvc',
                    address='0x3f2329C9ADFbcCd9A84f52c906E936A42dA18CB8'),

                expiration=1480964590181,
                quoted_rate=unhexlify('04f89e60b8'),

                api_key=unhexlify('6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b'),
                miner_fee=unhexlify('0186a0'),   #100000
                order_id=unhexlify('b026bddb3e74470bbab9146c4db58019'),
            ),
            signature=b'FAKE_SIG'
        )

        exchange_type_out=proto_types.ExchangeType(
            signed_exchange_response=signed_exchange_out,
            withdrawal_coin_name='THORChain',
            withdrawal_address_n=parse_path("m/44'/934'/0'/0/0"),
            return_address_n=parse_path("m/44'/60'/0'/0/0")
        )

        sig_v, sig_r, sig_s, hash, signature_der = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=1,
            gas_price=20,
            gas_limit=20,
            value=0,
            to=unhexlify('41e5560054824ea6b0732e656e3ad64e20e94e45'),
            address_type=3,
            exchange_type=exchange_type_out,
            chain_id=1,
            data=unhexlify('a9059cbb000000000000000000000000' + '1d8ce9022f6284c3a5c317f8f34620107214e545' + '00000000000000000000000000000000000000000000000000000002540be400')
            )

        self.assertEqual(sig_v, 37)
        self.assertEqual(hexlify(sig_r), '1238fd332545415f09a01470350a5a20abc784dbf875cf58f7460560e66c597f')
        self.assertEqual(hexlify(sig_s), '10efa4dd6fdb381c317db8f815252c2ac0d2a883bd364901dee3dec5b7d3660a')
        self.assertEqual(hexlify(hash), '3878462365df8bd2253c72dfe6e5cb744c64915e23fd5556f7077e43950a1afd')
        self.assertEqual(hexlify(signature_der), '304402201238fd332545415f09a01470350a5a20abc784dbf875cf58f7460560e66c597f022010efa4dd6fdb381c317db8f815252c2ac0d2a883bd364901dee3dec5b7d3660a')


if __name__ == '__main__':
    unittest.main()
