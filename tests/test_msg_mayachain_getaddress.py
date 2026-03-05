import unittest
import common

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH = "m/44h/931h/0h/0/0"

class TestMsgMayaChainGetAddress(common.KeepKeyTest):

    @unittest.skip("Expected values need to be captured from emulator - mayachain uses smaya prefix, not tthor")
    def test_mayachain_get_address(self):
        self.requires_firmware("7.9.1")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        address = self.client.mayachain_get_address(parse_path(DEFAULT_BIP32_PATH), testnet=True)
        self.assertEqual(address, "smaya1ls33ayg26kmltw7jjy55p32ghjna09zp74kufc")

if __name__ == '__main__':
    unittest.main()
