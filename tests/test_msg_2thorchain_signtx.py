import unittest
import common

from base64 import b64encode
from binascii import hexlify, unhexlify

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.exchange_pb2 as proto_exchange
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH = "m/44h/931h/0h/0/0"

def make_deposit(asset, amount, memo, signer):
    return {
        'type': 'thorchain/MsgDeposit',
        'value': {
            'coins': [{
                'asset': str(asset),
                'amount': str(amount),
            }],
            'memo': memo,
            'signer': signer,
        }
    }

class TestMsg2ThorChainSignTx(common.KeepKeyTest):

    def test_thorchain_sign_tx_deposit(self):
        self.requires_firmware("7.1.3")
        self.setup_mnemonic_nopin_nopassphrase()
        signature = self.client.thorchain_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=2722,
            chain_id="thorchain",
            fee=0,
            gas=350000,
            msgs=[make_deposit(
                "THOR.RUNE",
                50994000,
                "SWAP:BNB.BNB:bnb12splwpg8jenr9pjw3dwc5rr35t8792y8pc4mtf:348953501",
                "thor1ls33ayg26kmltw7jjy55p32ghjna09zp74t4az"
            )],
            memo="",
            sequence=4,
            testnet = False
        )
        self.assertEqual(b64encode(signature.signature), "/1Gv4PzMoe7bHjpp/WKMDOb7AMFJKRMwa3VRb88Osgd32WOvRbxlqd/1HTW/89FE/IFEzAa92aElxJNwKp9caA==")
        self.assertEqual(b64encode(signature.public_key), "AxUZcTuLQr3DZxEtMxMs8Uzt+SisV3HURLpFm5SXEXuj")
        return

if __name__ == '__main__':
    unittest.main()
