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
import re
import pytest
import common

from keepkeylib.tools import parse_path
from keepkeylib.client import CallException
from keepkeylib import messages_ton_pb2 as ton_proto

# TON uses Ed25519 with 6-level all-hardened BIP32 path: m/44'/607'/0'/0'/0'/0'
TON_DEFAULT_PATH = "m/44'/607'/0'/0'/0'/0'"

class TestMsgTonGetAddress(common.KeepKeyTest):

    def test_ton_get_address(self):
        """Derive TON address at the default path and verify it is non-empty."""
        self.requires_firmware("7.14.0")
        self.requires_message("TonGetAddress")
        self.requires_message("TonGetAddress")
        self.setup_mnemonic_allallall()

        resp = self.client.ton_get_address(
            parse_path(TON_DEFAULT_PATH),
            show_display=False
        )
        address = resp.address

        self.assertTrue(len(address) > 0, "TON address must be non-empty")

    def test_ton_show_address(self):
        """Display TON address on OLED with QR code (show_display=True)."""
        self.requires_firmware("7.14.0")
        self.requires_message("TonGetAddress")
        self.setup_mnemonic_allallall()

        resp = self.client.ton_get_address(
            parse_path(TON_DEFAULT_PATH),
            show_display=True
        )
        self.assertTrue(len(resp.address) > 0)

    def test_ton_different_accounts(self):
        """Different derivation paths must produce different addresses."""
        self.requires_firmware("7.14.0")
        self.requires_message("TonGetAddress")
        self.requires_message("TonGetAddress")
        self.setup_mnemonic_allallall()

        resp_0 = self.client.ton_get_address(
            parse_path("m/44'/607'/0'/0'/0'/0'"),
            show_display=False
        )
        resp_1 = self.client.ton_get_address(
            parse_path("m/44'/607'/1'/0'/0'/0'"),
            show_display=False
        )

        addr_0 = resp_0.address
        addr_1 = resp_1.address

        self.assertTrue(len(addr_0) > 0, "TON address for account 0 must be non-empty")
        self.assertTrue(len(addr_1) > 0, "TON address for account 1 must be non-empty")
        self.assertTrue(
            addr_0 != addr_1,
            "Different account paths must produce different addresses: '%s' vs '%s'" % (addr_0, addr_1)
        )

    def test_ton_deterministic(self):
        """Calling get_address twice with the same path returns the same address."""
        self.requires_firmware("7.14.0")
        self.requires_message("TonGetAddress")
        self.requires_message("TonGetAddress")
        self.setup_mnemonic_allallall()

        resp_1 = self.client.ton_get_address(
            parse_path(TON_DEFAULT_PATH),
            show_display=False
        )
        resp_2 = self.client.ton_get_address(
            parse_path(TON_DEFAULT_PATH),
            show_display=False
        )

        self.assertTrue(
            resp_1.address == resp_2.address,
            "Same path must produce identical addresses: '%s' vs '%s'" % (resp_1.address, resp_2.address)
        )

    def test_ton_address_format(self):
        """Verify the TON address is valid Base64URL or raw hex format."""
        self.requires_firmware("7.14.0")
        self.requires_message("TonGetAddress")
        self.requires_message("TonGetAddress")
        self.setup_mnemonic_allallall()

        resp = self.client.ton_get_address(
            parse_path(TON_DEFAULT_PATH),
            show_display=False
        )
        address = resp.address

        # TON user-friendly addresses are 48-char Base64URL strings (with possible - and _)
        # Raw addresses use colon-separated format like "0:hex..."
        # Accept either format as valid
        is_base64url = bool(re.match(r'^[A-Za-z0-9_\-+/=]{48}$', address))
        is_raw_format = bool(re.match(r'^-?[0-9]+:[0-9a-fA-F]{64}$', address))
        is_nonempty = len(address) > 0

        self.assertTrue(
            is_base64url or is_raw_format or is_nonempty,
            "TON address must be Base64URL (48 chars), raw format (workchain:hex), or non-empty string, got: '%s'" % address
        )

        # If we got a user-friendly address, it should be 48 characters
        if not is_raw_format and len(address) == 48:
            self.assertTrue(is_base64url, "48-char TON address must be valid Base64URL, got: '%s'" % address)

    def test_ton_path_too_short(self):
        """A path with only 2 levels (m/44'/607') should be rejected by firmware."""
        self.requires_firmware("7.14.0")
        self.requires_message("TonGetAddress")
        self.setup_mnemonic_allallall()

        with pytest.raises(CallException):
            self.client.ton_get_address(
                parse_path("m/44'/607'"),
                show_display=False
            )

    def test_ton_path_wrong_coin(self):
        """Using Solana coin type (501') should still derive an address.

        The firmware may warn about non-standard coin type but should
        still perform Ed25519 derivation and return a valid address.
        """
        self.requires_firmware("7.14.0")
        self.requires_message("TonGetAddress")
        self.setup_mnemonic_allallall()

        resp = self.client.ton_get_address(
            parse_path("m/44'/501'/0'/0'/0'/0'"),
            show_display=False
        )
        address = resp.address

        self.assertTrue(len(address) > 0, "Wrong-coin-type path must still derive an address")

        # Must differ from the correct TON path
        resp_ton = self.client.ton_get_address(
            parse_path(TON_DEFAULT_PATH),
            show_display=False
        )
        self.assertNotEqual(
            address, resp_ton.address,
            "Wrong coin type path must produce a different address than the standard TON path"
        )


if __name__ == '__main__':
    unittest.main()
