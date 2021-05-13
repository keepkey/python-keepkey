import unittest
import common

from base64 import b64encode
from binascii import hexlify, unhexlify

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH_TERRA = "m/44h/330h/0h/0/0"
DEFAULT_BIP32_PATH_KAVA = "m/44h/459h/0h/0/0"
DEFAULT_BIP32_PATH_SECRET = "m/44h/529h/0h/0/0"


def make_send_secret(from_address, to_address, amount):
    return {
        'type': 'cosmos-sdk/MsgSend',
        'value': {
            'amount': [{
                'denom': 'uscrt',
                'amount': str(amount),
            }],
            'from_address': from_address,
            'to_address': to_address,
        }
    }

class TestMsgTendermintSignTx(common.KeepKeyTest):

    def test_secret_sign_tx(self):
        self.requires_firmware("7.2.0")
        self.setup_mnemonic_nopin_nopassphrase()
        signature = self.client.tendermint_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH_SECRET),
            account_number=92,
            chain_id="secret",
            fee=20000,
            gas=80000,
            msgs=[make_send_secret(
                "secret1rgrn5gqy6g8vuz5d88e3nm0p9nhvqtert2cyl2",
                "secret1667etn8jhulzkd3q6vhrsjargev2spzgsrw4wt",
                3000000
            )],
            memo="KeepKey",
            sequence=3,
            testnet = False,
            denom = "secret,uscrt",
            decimals = 6,
            chain_name = "Secret",
            message_type_prefix = "cosmos-sdk"
        )
        print(hexlify(signature.signature))
        print(hexlify(signature.public_key))
        #self.assertEqual(hexlify(signature.signature), "164ea435b39444fa780e453ffe0d0ca07fa74a44272713a283f6297b951e06dc71575e83a6a5405b324c8bc187c50951f1d46fd58acadf060fdf23980d61488a")
        #self.assertEqual(hexlify(signature.public_key), "031519713b8b42bdc367112d33132cf14cedf928ac5771d444ba459b9497117ba3")
        return


if __name__ == '__main__':
    unittest.main()
