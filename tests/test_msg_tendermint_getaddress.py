import unittest
import common

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.messages_tendermint_pb2 as tendermint_proto
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH_TERRA = "m/44h/330h/0h/0/0"
DEFAULT_BIP32_PATH_KAVA = "m/44h/459h/0h/0/0"
DEFAULT_BIP32_PATH_SECRET = "m/44h/529h/0h/0/0"

class TestMsgTerraGetAddress(common.KeepKeyTest):
    def test_tendermint_get_address(self):
        self.requires_firmware("7.2.0")
        self.setup_mnemonic_nopin_nopassphrase()
        address = self.client.tendermint_get_address(parse_path(DEFAULT_BIP32_PATH_TERRA), address_prefix="terra", chain_name="Terra")
        print(address)
        #self.assertEqual(address, "tthor1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8")
        address = self.client.tendermint_get_address(parse_path(DEFAULT_BIP32_PATH_KAVA), address_prefix="kava", chain_name="Kava")
        print(address)
        #self.assertEqual(address, "tthor1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8")
        address = self.client.tendermint_get_address(parse_path(DEFAULT_BIP32_PATH_SECRET), address_prefix="secret", chain_name="Secret")
        print(address)
        #self.assertEqual(address, "tthor1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8")

if __name__ == '__main__':
    unittest.main()
