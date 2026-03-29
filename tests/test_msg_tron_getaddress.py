# This file is part of the KeepKey project.
#
# Copyright (C) 2024 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.

import unittest
import common

from keepkeylib.tools import parse_path
from keepkeylib import messages_tron_pb2 as tron_proto

# TRON default BIP44 path: m/44'/195'/0'/0/0
TRON_DEFAULT_PATH = "m/44'/195'/0'/0/0"

class TestMsgTronGetAddress(common.KeepKeyTest):

    def test_tron_get_address(self):
        """Derive Tron address at the default path and verify format."""
        self.requires_firmware("7.14.0")
        self.requires_message("TronGetAddress")
        self.setup_mnemonic_allallall()

        resp = self.client.tron_get_address(
            parse_path(TRON_DEFAULT_PATH),
            show_display=False
        )
        address = resp.address

        # TRON addresses are 34-character Base58Check strings starting with 'T'
        self.assertTrue(len(address) == 34, "Tron address must be 34 characters, got %d" % len(address))
        self.assertTrue(address.startswith('T'), "Tron address must start with 'T', got '%s'" % address)

    def test_tron_show_address(self):
        """Display TRON address on OLED with QR code (show_display=True)."""
        self.requires_firmware("7.14.0")
        self.requires_message("TronGetAddress")
        self.setup_mnemonic_allallall()

        resp = self.client.tron_get_address(
            parse_path(TRON_DEFAULT_PATH),
            show_display=True
        )
        self.assertTrue(len(resp.address) == 34)

    def test_tron_different_accounts(self):
        """Different derivation paths must produce different addresses."""
        self.requires_firmware("7.14.0")
        self.requires_message("TronGetAddress")
        self.setup_mnemonic_allallall()

        resp_0 = self.client.tron_get_address(
            parse_path("m/44'/195'/0'/0/0"),
            show_display=False
        )
        resp_1 = self.client.tron_get_address(
            parse_path("m/44'/195'/1'/0/0"),
            show_display=False
        )
        resp_2 = self.client.tron_get_address(
            parse_path("m/44'/195'/0'/0/1"),
            show_display=False
        )

        addr_0 = resp_0.address
        addr_1 = resp_1.address
        addr_2 = resp_2.address

        # All should be valid Tron addresses
        for addr in [addr_0, addr_1, addr_2]:
            self.assertTrue(len(addr) == 34, "Tron address must be 34 characters, got %d" % len(addr))
            self.assertTrue(addr.startswith('T'), "Tron address must start with 'T', got '%s'" % addr)

        # All must be distinct
        self.assertTrue(addr_0 != addr_1, "Account 0 and account 1 addresses must differ")
        self.assertTrue(addr_0 != addr_2, "Account 0 index 0 and index 1 addresses must differ")
        self.assertTrue(addr_1 != addr_2, "Account 1 and index 1 addresses must differ")

    def test_tron_deterministic(self):
        """Calling get_address twice with the same path returns the same address."""
        self.requires_firmware("7.14.0")
        self.requires_message("TronGetAddress")
        self.setup_mnemonic_allallall()

        resp_1 = self.client.tron_get_address(
            parse_path(TRON_DEFAULT_PATH),
            show_display=False
        )
        resp_2 = self.client.tron_get_address(
            parse_path(TRON_DEFAULT_PATH),
            show_display=False
        )

        self.assertTrue(
            resp_1.address == resp_2.address,
            "Same path must produce identical addresses: '%s' vs '%s'" % (resp_1.address, resp_2.address)
        )

    def test_tron_show_address(self):
        """Display TRON address on OLED (triggers ButtonRequest for screenshot capture).

        Address correctness verified by test_tron_get_address (show_display=False).
        This test only triggers the OLED display flow for screenshot capture.
        """
        self.requires_firmware("7.14.0")
        self.requires_message("TronGetAddress")
        self.setup_mnemonic_allallall()

        resp = self.client.tron_get_address(
            parse_path(TRON_DEFAULT_PATH),
            show_display=True
        )
        self.assertIsNotNone(resp)


if __name__ == '__main__':
    unittest.main()
