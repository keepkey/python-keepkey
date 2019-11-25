import unittest
import common

from base64 import b64encode
from binascii import hexlify

import keepkeylib.messages_pb2 as proto
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH = "m/44h/118h/0h/0/0"

class TestMsgCosmosGetAddress(common.KeepKeyTest):
    def test_cosmos_sign_tx(self):
        self.setup_mnemonic_nopin_nopassphrase()
        signature = self.client.cosmos_sign_tx(parse_path(DEFAULT_BIP32_PATH), 19637, "cosmoshub-2", 5000, 200000, "cosmos15cenya0tr7nm3tz2wn3h3zwkht2rxrq7q7h3dj", "cosmos18vhdczjut44gpsy804crfhnd5nq003nz0nf20v", 100000, "", 3)
        self.assertEqual(hexlify(signature.signature), "4a200cc240df784ac19d1c51ee1ea47c8e257327dd3a3c4ff89d90cbba861b711d3a61929ce3c41e68c4722e63e6a60d553c46b82e9dac3b1f6ad9382b508ccf")
        self.assertEqual(hexlify(signature.public_key), "03bee3af30e53a73f38abc5a2fcdac426d7b04eb72a8ebd3b01992e2d206e24ad8")

    def test_cosmos_sign_tx_memo(self):
        self.setup_mnemonic_nopin_nopassphrase()
        signature = self.client.cosmos_sign_tx(parse_path(DEFAULT_BIP32_PATH), 19637, "cosmoshub-2", 5000, 200000, "cosmos15cenya0tr7nm3tz2wn3h3zwkht2rxrq7q7h3dj", "cosmos18vhdczjut44gpsy804crfhnd5nq003nz0nf20v", 8675309, "Epstein didn't kill himself.", 3)
        self.assertEqual(hexlify(signature.signature), "9f2434543bc4afd2fc7bb43db05facdd6d529aa7c467ef0d41e1c2954f68db9942b8eb431cf27b52d1b3d914bbde076960179b7f426bd1a182448bb9c245009c")
        self.assertEqual(hexlify(signature.public_key), "03bee3af30e53a73f38abc5a2fcdac426d7b04eb72a8ebd3b01992e2d206e24ad8")

if __name__ == '__main__':
    unittest.main()
