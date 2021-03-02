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
        self.requires_firmware("7.0.1")
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

    
if __name__ == '__main__':
    unittest.main()
