import unittest
import common


import keepkeylib.messages_binance_pb2 as binance_proto
from keepkeylib.tools import parse_path

class TestMsgBinanceGetAddress(common.KeepKeyTest):
    def test_standard(self):
        self.requires_firmware("6.4.0")

        self.client.load_device_by_mnemonic(
            mnemonic='offer caution gift cross surge pretty orange during eye soldier popular holiday mention east eight office fashion ill parrot vault rent devote earth cousin',
            pin='',
            passphrase_protection=False,
            label='test',
            language='english'
        )

        BINANCE_ADDRESS_TEST_VECTORS = [
            ("bnb1hgm0p7khfk85zpz5v0j8wnej3a90w709vhkdfu", parse_path("m/44h/714h/0h/0/0")),
            ("bnb1egswqkszzfc2uq78zjslc6u2uky4pw46x4rstd", parse_path("m/44h/714h/0h/0/1")),
        ]

        for (expected, path) in BINANCE_ADDRESS_TEST_VECTORS:
            with self.client:
                self.client.set_expected_responses([
                    binance_proto.BinanceAddress(address=expected)
                ])

                self.assertEqual(expected, self.client.binance_get_address(path, show_display=False))


if __name__ == '__main__':
    unittest.main()
