import unittest
import common

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
import keepkeylib.messages_thorchain_pb2 as thorchain_proto
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH = "m/44h/934h/0h/0/0"

class TestMsgThorChainGetAddress(common.KeepKeyTest):
    def test_standard(self):
        self.requires_firmware("6.7.0")
        self.setup_mnemonic_nopin_nopassphrase()

        vec = [
            ("thor15cenya0tr7nm3tz2wn3h3zwkht2rxrq7q7h3dj", parse_path(DEFAULT_BIP32_PATH)),
            ("thor1kae7mmy87v7qudnz2tk3ctn0c4ut5vccqg63tw", parse_path("m/44h/934h/1h/0/0")),
            ("thor1qpjr794gfnsp4c8uu84xl9xudea7h2tzns7ct8", parse_path("m/44h/934h/12345678h/0/0")),
        ]

        for (expected, path) in vec:
            with self.client:
                self.client.set_expected_responses([
                    proto.ButtonRequest(code=proto_types.ButtonRequest_Address),
                    thorchain_proto.ThorChainAddress(address=expected)
                ])

                self.assertEqual(expected, self.client.thorchain_get_address(path, show_display=True))

            with self.client:
                self.client.set_expected_responses([
                    thorchain_proto.ThorChainAddress(address=expected)
                ])

                self.assertEqual(expected, self.client.thorchain_get_address(path, show_display=False))


    def test_nonstandard(self):
        self.requires_firmware("6.7.0")
        self.setup_mnemonic_nopin_nopassphrase()

        vec = [
            ("thor1njwjrarnsfmzmuadsyu3acykfv5dm9ghe8f3z2", parse_path("m/44h/0h/0h/0/0")),
            ("thor17543w8x4dywq0k4nymd4x96ur27um8cn932832", parse_path("m/49h/934h/0h/0/0")),
            ("thor19g5s8msys3j3xj64yywwqcamlswrl23yj7jmmh", parse_path("m/44h/934h/0h/0/1")),
            ("thor1w6h0mg4nwku4hynv046rat6vy7wt7y6ltu6d8p", parse_path("m/44h/934h/1h/0/1")),
            ("thor1w6h0mg4nwku4hynv046rat6vy7wt7y6ltu6d8p", parse_path("m/44h/934h/1h/0/1")),
            ("thor1yjjkmdpu7metqt5r36jf872a34syws33xa5twl", parse_path("m/0")),
            ("thor1jhv0vuygfazfvfu5ws6m80puw0f80kk6ugf74d", []),
        ]

        for (expected, path) in vec:
            with self.client:
                self.client.set_expected_responses([
                    proto.ButtonRequest(code=proto_types.ButtonRequest_Other),
                    proto.ButtonRequest(code=proto_types.ButtonRequest_Address),
                    thorchain_proto.ThorChainAddress(address=expected)
                ])

                self.assertEqual(expected, self.client.thorchain_get_address(path, show_display=True))

            with self.client:
                self.client.set_expected_responses([
                    thorchain_proto.ThorChainAddress(address=expected)
                ])

                self.assertEqual(expected, self.client.thorchain_get_address(path, show_display=False))


    def test_thorchain_get_address_sep(self):
        self.requires_firmware("6.7.0")
        self.client.load_device_by_mnemonic(
          mnemonic='illness spike retreat truth genius clock brain pass fit cave bargain toe',
          pin='',
          passphrase_protection=False,
          label='test',
          language='english'
        )

        address = self.client.thorchain_get_address(parse_path(DEFAULT_BIP32_PATH))
        assert address == "thor1jcwdsdelc4cwvall0twl974sfkpqmzrgkszu9l"

        address = self.client.thorchain_get_address(
            parse_path("m/44h/934h/1h/0/0"), show_display=True
        )
        assert address == "thor1280uphuty5rxr2m05t6xujvylkkftlrvdnw0pp"

    def test_onchain(self):
        self.requires_firmware("6.7.0")
        self.client.load_device_by_mnemonic(
          mnemonic='hybrid anger habit story vibrant grit ill sense duck butter heavy frame',
          pin='',
          passphrase_protection=False,
          label='test',
          language='english'
        )

        self.assertEqual(
          "thor1934nqs0ke73lm5ej8hs9uuawkl3ztesg9jp5c5",
          self.client.thorchain_get_address(parse_path(DEFAULT_BIP32_PATH)))


if __name__ == '__main__':
    unittest.main()
