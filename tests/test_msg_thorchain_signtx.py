import unittest
import common

from base64 import b64encode
from binascii import hexlify, unhexlify

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH = "m/44h/931h/0h/0/0"

def make_send(from_address, to_address, amount):
    return {
        'type': 'thorchain/MsgSend',
        'value': {
            'amount': [{
                'denom': 'rune',
                'amount': str(amount),
            }],
            'from_address': from_address,
            'to_address': to_address,
        }
    }

class TestMsgThorChainSignTx(common.KeepKeyTest):

    def test_thorchain_sign_tx(self):
        self.requires_firmware("7.0.2")
        self.setup_mnemonic_nopin_nopassphrase()
        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=92,
            chain_id="thorchain",
            fee=3000,
            gas=200000,
            msgs=[make_send(
                "tthor1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8",
                "tthor1jvt443rvhq5h8yrna55yjysvhtju0el7ldnwwy",
                10000
            )],
            memo="foobar",
            sequence=3,
            testnet = True
        )
        self.assertEqual(hexlify(signature.signature), "164ea435b39444fa780e453ffe0d0ca07fa74a44272713a283f6297b951e06dc71575e83a6a5405b324c8bc187c50951f1d46fd58acadf060fdf23980d61488a")
        self.assertEqual(hexlify(signature.public_key), "031519713b8b42bdc367112d33132cf14cedf928ac5771d444ba459b9497117ba3")
        return

    def test_sign_btc_eth_swap(self):
        self.requires_firmware("7.0.2")
        self.setup_mnemonic_nopin_nopassphrase()

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        out1 = proto_types.TxOutputType(op_return_data=b'SWAP:ETH.ETH:0x41e5560054824ea6b0732e656e3ad64e20e94e45:420',
                              amount=0,
                              script_type=proto_types.PAYTOOPRETURN,
                              )


        (signatures, serialized_tx) = self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        self.assertEqual(hexlify(serialized_tx), '010000000182488650ef25a58fef6788bd71b8212038d7f2bbe4750bc7bcb44701e85ef6d5000000006b483045022100c1cf12191f0a50398dae21553d14d5c796ff3e2e1c378bce3d0a7d43fa9bdf4402201245f76291db518dd8b496b4406128ca0e07165c64d2fe927161eee17402f9c40121023230848585885f63803a0a8aecdd6538792d5c539215c91698e315bf0253b43dffffffff0100000000000000003d6a3b535741503a4554482e4554483a3078343165353536303035343832346561366230373332653635366533616436346532306539346534353a34323000000000')
  
    def test_sign_eth_btc_swap(self):
        self.requires_firmware("7.1.0")
        self.setup_mnemonic_nopin_nopassphrase()
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692,2147483708,2147483648,0,0],
            nonce=0x0,
            gas_price=0x5FB9ACA00,
            gas_limit=0x186A0,
            value=0x00,
            to=unhexlify('42a5ed456650a09dc10ebc6361a7480fdd61f27b'),
            address_type=0,
            chain_id=1,
            data=unhexlify('1fece7b4' +
            '000000000000000000000000345b297ec83add7ff74d2f7933651bffa037d956' +    # asgard vault address 
            '0000000000000000000000000000000000000000000000000000000000000000' +    # asset ETH
            '000000000000000000000000000000000000000000000065945acd2b867ef000' +    # amount
            '0000000000000000000000000000000000000000000000000000000000000080' +    # offset of memo string from after func sig
            '000000000000000000000000000000000000000000000000000000000000003b' +    # length of memo string in bytes
            # SWAP:BTC.BTC:0x41e5560054824ea6b0732e656e3ad64e20e94e45:420
            '535741503a4254432e4254433a30783431653535363030353438323465613662' +    # thorchain transaction memo
            '30373332653635366533616436346532306539346534353a3432300000000000')
        )   
        self.assertEqual(sig_v, 37)
        self.assertEqual(hexlify(sig_r), 'da472e9d40fb3c981cebbc6dec70d9d756e5f03aca1ca4259f26dd4c257f8a68')
        self.assertEqual(hexlify(sig_s), '025af171f9bd0af71266417f82a72214f349d96ed6505288c1a4032463ef920a')


    def test_sign_btc_add_liquidity(self):
        self.requires_firmware("7.0.2")
        self.setup_mnemonic_nopin_nopassphrase()

        inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
                             # amount=390000,
                             prev_hash=unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
                             prev_index=0,
                             )

        out1 = proto_types.TxOutputType(op_return_data=b'ADD:BTC.BTC:thorpub1addwnpepq2ynqt500fag3wyxsjuv7570qxr8rqtpx93hw3cpqaqxtwxesy76utgtemp:420',
                              amount=0,
                              script_type=proto_types.PAYTOOPRETURN,
                              )


        (signatures, serialized_tx) = self.client.sign_tx('Bitcoin', [inp1, ], [out1, ])
        self.assertEqual(hexlify(serialized_tx), '010000000182488650ef25a58fef6788bd71b8212038d7f2bbe4750bc7bcb44701e85ef6d5000000006b483045022100ed9206af5ba7fe82dda17cf20574197924a120be5b415f875f7d9880f4591e4202201081cb688cceadad65dc20e9843d910d895342ce9316f792b748b0e4a0f757870121023230848585885f63803a0a8aecdd6538792d5c539215c91698e315bf0253b43dffffffff0100000000000000005e6a4c5b4144443a4254432e4254433a74686f7270756231616464776e7065707132796e717435303066616733777978736a7576373537307178723872717470783933687733637071617178747778657379373675746774656d703a34323000000000')
  
    def test_sign_eth_add_liquidity(self):
        self.requires_firmware("7.0.2")
        self.setup_mnemonic_nopin_nopassphrase()
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
                        n=[2147483692,2147483708,2147483648,0,0],
            nonce=0x0,
            gas_price=0x5FB9ACA00,
            gas_limit=0x186A0,
            value=0x00,
            to=unhexlify('41e5560054824ea6b0732e656e3ad64e20e94e45'),
            address_type=0,
            chain_id=1,
            data=unhexlify('1fece7b4' +
            '0000000000000000000000000000000000000000000000000000000000000000' + 
            '0000000000000000000000000000000000000000000000000000000000000000' +
            '0000000000000000000000000000000000000000000000000000000000000000' +
            '0000000000000000000000000000000000000000000000000000000000000080' +  # offset of memo string from 4
            '000000000000000000000000000000000000000000000000000000000000003b' +  # length of memo string in bytes
            # ADD:ETH.ETH:0xc5b2608927ea95ed43f842f553e3a27b09c050e8:420
            '4144443a4554482e4554483a3078633562323630383932376561393565643433' +
            '663834326635353365336132376230396330353065383a343230000000000000')

        )
        self.assertEqual(sig_v, 37)
        self.assertEqual(hexlify(sig_r), '638f9f42c099d0d47f7fc70d248249d2db24ecabc2fdee5bf2f5ad73b5bbfd30')
        self.assertEqual(hexlify(sig_s), '3dae036aabbe0ec55f7b9e4eef54e2b5335f62544d8c2ed041797a9397f185c7')

    def test_thorchain_remove_liquidity(self):
        self.requires_firmware("7.1.1")
        self.setup_mnemonic_nopin_nopassphrase()
        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=92,
            chain_id="thorchain",
            fee=3000,
            gas=200000,
            msgs=[make_send(
                "thor1x00pfwyx8xld45sdlmyn29vjf7ev0mv3rcn9al",
                "thor1zfjv26zx08s6skjwq20clxs076hptp45aktjm0",
                10000
            )],
            memo="WITHDRAW:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:10000",
            sequence=3,
            testnet = False
        )
        self.assertEqual(b64encode(signature.signature), "vGgRuLYO9auhdphbqJVarVbVoKzuaP4eyjvzofoiegluiBQLq8gXY7eWUosA6+trvPYnHOUxzF00Rk+xXdwIMg==")
        self.assertEqual(b64encode(signature.public_key), "AxUZcTuLQr3DZxEtMxMs8Uzt+SisV3HURLpFm5SXEXuj")
        return


    def test_thorchain_sign_tx(self):
        self.requires_firmware("7.0.2")
        self.setup_mnemonic_nopin_nopassphrase()

        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=92,
            chain_id="thorchain",
            fee=3000,
            gas=200000,
            msgs=[make_send(
                "tthor1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8",
                "tthor1jvt443rvhq5h8yrna55yjysvhtju0el7ldnwwy",
                10000
            )],
            # full memo
            memo="SWAP:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45:420",
            sequence=3,
            testnet = True
        )
        self.assertEqual(b64encode(signature.signature), "DPVRuKqAx9OL5cBMB3pF799zPzGlNXdosRY+ecAmPN4LnoRUKpPOGtI2kKtM8Q/YvR6KKASmGw19UbM8IVEWJg==")
        self.assertEqual(b64encode(signature.public_key), "AxUZcTuLQr3DZxEtMxMs8Uzt+SisV3HURLpFm5SXEXuj")

        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=92,
            chain_id="thorchain",
            fee=3000,
            gas=200000,
            msgs=[make_send(
                "tthor1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8",
                "tthor1jvt443rvhq5h8yrna55yjysvhtju0el7ldnwwy",
                10000
            )],
            # no limit, 's' for swap token
            memo="s:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45:",
            sequence=3,
            testnet = True
        )
        self.assertEqual(b64encode(signature.signature), "dm/zzIlTOMd09tsuZA2zwBwK5MZrEsNbGnv27RikcZdzhsucot83vQlNopotDb6p+e48QVw3DxerB0rMixyN8g==")
        self.assertEqual(b64encode(signature.public_key), "AxUZcTuLQr3DZxEtMxMs8Uzt+SisV3HURLpFm5SXEXuj")

        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=92,
            chain_id="thorchain",
            fee=3000,
            gas=200000,
            msgs=[make_send(
                "tthor1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8",
                "tthor1jvt443rvhq5h8yrna55yjysvhtju0el7ldnwwy",
                10000
            )],
            # swap to self, "=" for swap token
            memo="=:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7::420",
            sequence=3,
            testnet = True
        )
        self.assertEqual(b64encode(signature.signature), "WLGLhMzNksxcBy5UlfKNdIXiH/9V0lEF3wcVv59Jzg00knCJ0/ndMmY3McmgyTdFgX/MJ1ox9RFGXGozuYXqYA==")
        self.assertEqual(b64encode(signature.public_key), "AxUZcTuLQr3DZxEtMxMs8Uzt+SisV3HURLpFm5SXEXuj")
        
        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=92,
            chain_id="thorchain",
            fee=3000,
            gas=200000,
            msgs=[make_send(
                "tthor1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8",
                "tthor1jvt443rvhq5h8yrna55yjysvhtju0el7ldnwwy",
                10000
            )],
            # swap to self, no limit
            memo="SWAP:BTC.BTC",
            sequence=3,
            testnet = True
        )
        self.assertEqual(b64encode(signature.signature), "41X+5ZrYWuWRfJA0kBMx1LwJ9BGCvKTvgeCGJtiiH8JStXyX1RQqlTVbuuIrVG3q5jHkXgzgfLXyCYoRsS4UJw==")
        self.assertEqual(b64encode(signature.public_key), "AxUZcTuLQr3DZxEtMxMs8Uzt+SisV3HURLpFm5SXEXuj")

        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=92,
            chain_id="thorchain",
            fee=3000,
            gas=200000,
            msgs=[make_send(
                "tthor1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8",
                "tthor1jvt443rvhq5h8yrna55yjysvhtju0el7ldnwwy",
                10000
            )],
            # full memo
            memo="ADD:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45",
            sequence=3,
            testnet = True
        )
        self.assertEqual(b64encode(signature.signature), "mv8z8mOMuF70hbOwMVabwN3SJwErnRZ7P6grFn56b7UCf2OiZlv1eICLkSlcn9rl5uubHm45ytRPnHkjQwYF2g==")
        self.assertEqual(b64encode(signature.public_key), "AxUZcTuLQr3DZxEtMxMs8Uzt+SisV3HURLpFm5SXEXuj")

        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=92,
            chain_id="thorchain",
            fee=3000,
            gas=200000,
            msgs=[make_send(
                "tthor1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8",
                "tthor1jvt443rvhq5h8yrna55yjysvhtju0el7ldnwwy",
                10000
            )],
            #'a' for add liquidity
            memo="a:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45",
            #memo="a:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7",
            sequence=3,
            testnet = True
        )
        self.assertEqual(b64encode(signature.signature), "2zEP/SgcL6yWHBtcb+q+xWJ15FOKIe2Kueaa5f1b9TIlXdxMceHaauDyMzoD7sxwW/6jQ9WvmnzWZGfAuMK1dw==")
        self.assertEqual(b64encode(signature.public_key), "AxUZcTuLQr3DZxEtMxMs8Uzt+SisV3HURLpFm5SXEXuj")

        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=92,
            chain_id="thorchain",
            fee=3000,
            gas=200000,
            msgs=[make_send(
                "tthor1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8",
                "tthor1jvt443rvhq5h8yrna55yjysvhtju0el7ldnwwy",
                10000
            )],
            #"+" for add liquidity
            memo="+:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45",
            sequence=3,
            testnet = True
        )
        self.assertEqual(b64encode(signature.signature), "f0p5jp/8UinilCOD6YDw58oFi1AQJEOIeY0MmD903igeIP3OW2/6ktg03rPXkJfXmIzia5jOinaR8sytthXHpQ==")
        self.assertEqual(b64encode(signature.public_key), "AxUZcTuLQr3DZxEtMxMs8Uzt+SisV3HURLpFm5SXEXuj")

        return

if __name__ == '__main__':
    unittest.main()
