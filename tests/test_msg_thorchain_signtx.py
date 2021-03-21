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
            '0000000000000000000000000000000000000000000000000000000000000080' +
            '000000000000000000000000000000000000000000000000000000000000003b' +
            '535741503a4254432e4254433a30783431653535363030353438323465613662' +
            '30373332653635366533616436346532306539346534353a3432300000000000')

        )
        self.assertEqual(sig_v, 38)
        self.assertEqual(hexlify(sig_r), '30c4d80ebf1c9e214370bae286a9cee9384788080bcfb773afb75cb2573ef433')
        self.assertEqual(hexlify(sig_s), '104f5b60cf6f8ab3a511fb98ddbbfdc9b8837a7b6d8d8627ca65510ca3733b08')

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
        self.assertEqual(hexlify(signature.signature), "a1b9082c6817d4c80b82a2d955f2be26a39b8a5e6909c5fcc52114a5c5e5476e68df191c2be5c88e35ef3090c3bafbd44083e32fbf4d26a809218aeec42ec8a9")
        self.assertEqual(hexlify(signature.public_key), "031519713b8b42bdc367112d33132cf14cedf928ac5771d444ba459b9497117ba3")

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
            # no limit
            memo="SWAP:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45:",
            sequence=3,
            testnet = True
        )
        self.assertEqual(hexlify(signature.signature), "1f01d0b31acf0201f6c388f7b9d96b0fb40429e75b9f1192bacd54fe4d69573158fc6d392f9115c42a3e0c8178ebcdf9edb616a5897670504e7801a3b06d1ad1")
        self.assertEqual(hexlify(signature.public_key), "031519713b8b42bdc367112d33132cf14cedf928ac5771d444ba459b9497117ba3")

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
            # swap to self
            memo="SWAP:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7::420",
            sequence=3,
            testnet = True
        )
        self.assertEqual(hexlify(signature.signature), "20f78a381454f04dc9bfa1f55a46b228527f4a41a2e892e43c43761d8ea31e22294b076c7e8a9512fe11c598bf8b6cc8e6cfb668e78d21802e377f5a15a8897e")
        self.assertEqual(hexlify(signature.public_key), "031519713b8b42bdc367112d33132cf14cedf928ac5771d444ba459b9497117ba3")
        
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
        self.assertEqual(hexlify(signature.signature), "6e6908262ae5f268e104a567f64b4be18297cc68577962925a1dcbcc2333f7ba5a5446f623a774359d68335804e88448bf432c95dc9777b26effecb339a790a9")
        self.assertEqual(hexlify(signature.public_key), "031519713b8b42bdc367112d33132cf14cedf928ac5771d444ba459b9497117ba3")

        return

if __name__ == '__main__':
    unittest.main()
