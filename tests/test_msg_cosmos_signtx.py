import unittest
import common

from base64 import b64encode
from binascii import hexlify, unhexlify

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH = "m/44h/118h/0h/0/0"

def make_send(from_address, to_address, amount):
    return {
        'type': 'cosmos-sdk/MsgSend',
        'value': {
            'from_address': from_address,
            'to_address': to_address,
            'amount': [{
                'denom': 'uatom',
                'amount': str(amount)
            }]
        }
    }

class TestMsgCosmosSignTx(common.KeepKeyTest):
    def test_cosmos_sign_tx(self):
        self.requires_fullFeature()
        self.requires_firmware("6.3.0")
        self.setup_mnemonic_nopin_nopassphrase()
        signature = self.client.cosmos_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=19637,
            chain_id="cosmoshub-2",
            fee=5000,
            gas=200000,
            msgs=[make_send(
                "cosmos15cenya0tr7nm3tz2wn3h3zwkht2rxrq7q7h3dj",
                "cosmos18vhdczjut44gpsy804crfhnd5nq003nz0nf20v",
                100000
            )],
            memo="",
            sequence=3
        )
        self.assertEqual(hexlify(signature.signature), "4a200cc240df784ac19d1c51ee1ea47c8e257327dd3a3c4ff89d90cbba861b711d3a61929ce3c41e68c4722e63e6a60d553c46b82e9dac3b1f6ad9382b508ccf")
        self.assertEqual(hexlify(signature.public_key), "03bee3af30e53a73f38abc5a2fcdac426d7b04eb72a8ebd3b01992e2d206e24ad8")


    def test_cosmos_sign_tx_memo(self):
        self.requires_fullFeature()
        self.requires_firmware("6.3.0")
        self.setup_mnemonic_nopin_nopassphrase()
        signature = self.client.cosmos_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=19637,
            chain_id="cosmoshub-2",
            fee=5000,
            gas=200000,
            msgs=[make_send(
                "cosmos15cenya0tr7nm3tz2wn3h3zwkht2rxrq7q7h3dj",
                "cosmos18vhdczjut44gpsy804crfhnd5nq003nz0nf20v",
                8675309
            )],
            memo="Epstein didn't kill himself.",
            sequence=3
        )
        self.assertEqual(hexlify(signature.signature), "9f2434543bc4afd2fc7bb43db05facdd6d529aa7c467ef0d41e1c2954f68db9942b8eb431cf27b52d1b3d914bbde076960179b7f426bd1a182448bb9c245009c")
        self.assertEqual(hexlify(signature.public_key), "03bee3af30e53a73f38abc5a2fcdac426d7b04eb72a8ebd3b01992e2d206e24ad8")


    def test_onchain1(self):
        self.requires_fullFeature()
        self.requires_firmware("6.3.0")
        self.client.load_device_by_mnemonic(
          mnemonic='hybrid anger habit story vibrant grit ill sense duck butter heavy frame',
          pin='',
          passphrase_protection=False,
          label='test',
          language='english'
        )

        # https://www.mintscan.io/txs/93c7f98bf0ab2f727832f08344d8bd8d0c14021c160a904c512b93082d2fb694
        signature = self.client.cosmos_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=24250,
            chain_id="cosmoshub-2",
            fee=1000,
            gas=28000,
            msgs=[make_send(
                "cosmos1934nqs0ke73lm5ej8hs9uuawkl3ztesg9jp5c5",
                "cosmos14um3sf75lc0kpvgrpj9hspqtv0375epn05cpfa",
                1000
            )],
            memo="KeepKey",
            sequence=2
        )

        self.assertEqual(hexlify(signature.signature), "ff04dbada6d95d2639d1a6a62b23f93e958d22423156f771248520b495c58a7a0aa1a877ce3819544d203e400c9f256b9fe49e1fcc1f723964c73e1df0a5e3c2")


    def test_onchain2(self):
        self.requires_fullFeature()
        self.requires_firmware("6.3.0")
        self.client.load_device_by_mnemonic(
          mnemonic='hybrid anger habit story vibrant grit ill sense duck butter heavy frame',
          pin='',
          passphrase_protection=False,
          label='test',
          language='english'
        )

        # https://www.mintscan.io/txs/93c7f98bf0ab2f727832f08344d8bd8d0c14021c160a904c512b93082d2fb694
        signature = self.client.cosmos_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=24250,
            chain_id="cosmoshub-2",
            fee=1000,
            gas=28000,
            msgs=[make_send(
                "cosmos1934nqs0ke73lm5ej8hs9uuawkl3ztesg9jp5c5",
                "cosmos14um3sf75lc0kpvgrpj9hspqtv0375epn05cpfa",
                47000
            )],
            memo="KeepKey",
            sequence=3
        )

        self.assertEqual(hexlify(signature.signature), "71295606d64f1fa987fea1af2292d0b735a5c2d5104b7cc3f818a7208ea9b1a504a386c40011242c115f77268c67af841d29137af5d608d21361ebc7e0513a11")

if __name__ == '__main__':
    unittest.main()
