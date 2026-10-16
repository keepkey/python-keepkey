import unittest
import common

from keepkeylib.tools import parse_path


class TestMsgOsmosisGetAddress(common.KeepKeyTest):

    def test_osmosis_show_address(self):
        self.requires_fullFeature()
        self.requires_firmware("7.7.0")
        self.requires_message("OsmosisGetAddress")
        self.setup_mnemonic_nopin_nopassphrase()
        path = parse_path("m/44h/118h/0h/0/0")
        expected = self.client.osmosis_get_address(path)
        address = self.assert_shows_address(
            lambda: self.client.osmosis_get_address(path, show_display=True),
            expected)
        self.assertEqual(address, expected)


if __name__ == '__main__':
    unittest.main()
