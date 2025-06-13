import unittest
import common

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.messages_thorchain_pb2 as thorchain_proto
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH = "m/44h/931h/0h/0/0"

class TestMsgMayaChainGetAddress(common.KeepKeyTest):

    def test_mayachain_get_address(self):
        self.requires_firmware("7.9.1")
        self.setup_mnemonic_nopin_nopassphrase()
        address = self.client.mayachain_get_address(parse_path(DEFAULT_BIP32_PATH), testnet=True)
        self.assertEqual(address, "tthor1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8")

if __name__ == '__main__':
    unittest.main()
