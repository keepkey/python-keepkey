import unittest
import common

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.messages_cosmos_pb2 as cosmos_proto
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH = "m/44h/118h/0h/0/0"

class TestMsgCosmosGetAddress(common.KeepKeyTest):
    def test_cosmos_get_address(self):
        self.setup_mnemonic_nopin_nopassphrase()
        address = self.client.cosmos_get_address(parse_path(DEFAULT_BIP32_PATH))
        assert address.address == "cosmos15cenya0tr7nm3tz2wn3h3zwkht2rxrq7q7h3dj"

    def test_cosmos_get_address_sep(self):
        self.mnemonic12 = 'illness spike retreat truth genius clock brain pass fit cave bargain toe'
        self.setup_mnemonic_nopin_nopassphrase()
        address = self.client.cosmos_get_address(parse_path(DEFAULT_BIP32_PATH))
        assert address.address == "cosmos1jcwdsdelc4cwvall0twl974sfkpqmzrgkszu9l"

        address = self.client.cosmos_get_address(
            parse_path("m/44h/118h/1h/0/0"), show_display=True
        )
        assert address.address == "cosmos1280uphuty5rxr2m05t6xujvylkkftlrvdnw0pp"

    def test_cosmos_get_address_fail(self):
        self.setup_mnemonic_nopin_nopassphrase()
        try:
            self.client.cosmos_get_address(parse_path("m/0/1"))
        except CallException as exc:
            assert exc.args[0] == proto_types.FailureType.Failure_FirmwareError
            assert exc.args[1].endswith("Failed to derive private key")

if __name__ == '__main__':
    unittest.main()