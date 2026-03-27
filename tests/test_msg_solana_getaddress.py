# Solana address derivation tests.
#
# Tests SolanaGetAddress message which derives Solana addresses
# (Ed25519 public keys encoded as Base58) from the device seed.
#
# Uses the "all" x12 mnemonic as the master seed.
# Solana BIP-44 path: m/44'/501'/account'/change'

import unittest
import common
import re

from keepkeylib import messages_solana_pb2 as solana_proto

# Base58 alphabet (Bitcoin variant, used by Solana)
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE58_RE = re.compile('^[' + BASE58_ALPHABET + ']+$')

# Hardened offset
H = 0x80000000


def _is_valid_solana_address(address):
    """Check that an address is a valid Solana Base58 string (32-44 chars)."""
    if not isinstance(address, str):
        # Handle bytes response from older protobuf
        try:
            address = address.decode('utf-8')
        except (AttributeError, UnicodeDecodeError):
            return False
    if len(address) < 32 or len(address) > 44:
        return False
    if not BASE58_RE.match(address):
        return False
    return True


class TestMsgSolanaGetAddress(common.KeepKeyTest):
    """Test Solana address derivation from the device."""

    def test_solana_get_address(self):
        """Derive Solana address at standard path m/44'/501'/0'/0'."""
        self.requires_firmware("7.14.0")
        self.requires_message("SolanaGetAddress")
        self.setup_mnemonic_allallall()

        resp = self.client.call(
            solana_proto.SolanaGetAddress(
                address_n=[H + 44, H + 501, H + 0, H + 0],
                show_display=False,
            )
        )

        self.assertTrue(
            isinstance(resp, solana_proto.SolanaAddress),
            "Expected SolanaAddress response, got %s" % type(resp).__name__
        )

        address = resp.address
        # Handle bytes vs str
        if isinstance(address, bytes):
            address = address.decode('utf-8')

        self.assertTrue(
            _is_valid_solana_address(address),
            "Invalid Solana address format: '%s' (len=%d)" % (address, len(address))
        )

    def test_solana_different_accounts(self):
        """Different account indices must produce different addresses."""
        self.requires_firmware("7.14.0")
        self.requires_message("SolanaGetAddress")
        self.setup_mnemonic_allallall()

        # Account 0: m/44'/501'/0'/0'
        resp0 = self.client.call(
            solana_proto.SolanaGetAddress(
                address_n=[H + 44, H + 501, H + 0, H + 0],
                show_display=False,
            )
        )
        # Account 1: m/44'/501'/1'/0'
        resp1 = self.client.call(
            solana_proto.SolanaGetAddress(
                address_n=[H + 44, H + 501, H + 1, H + 0],
                show_display=False,
            )
        )

        self.assertTrue(
            isinstance(resp0, solana_proto.SolanaAddress),
            "Expected SolanaAddress for account 0, got %s" % type(resp0).__name__
        )
        self.assertTrue(
            isinstance(resp1, solana_proto.SolanaAddress),
            "Expected SolanaAddress for account 1, got %s" % type(resp1).__name__
        )

        addr0 = resp0.address
        addr1 = resp1.address
        if isinstance(addr0, bytes):
            addr0 = addr0.decode('utf-8')
        if isinstance(addr1, bytes):
            addr1 = addr1.decode('utf-8')

        # Both must be valid
        self.assertTrue(
            _is_valid_solana_address(addr0),
            "Account 0 address invalid: '%s'" % addr0
        )
        self.assertTrue(
            _is_valid_solana_address(addr1),
            "Account 1 address invalid: '%s'" % addr1
        )

        # Must be different
        self.assertTrue(
            addr0 != addr1,
            "Account 0 and account 1 produced identical addresses: %s" % addr0
        )

    def test_solana_deterministic(self):
        """Same path must produce the same address every time."""
        self.requires_firmware("7.14.0")
        self.requires_message("SolanaGetAddress")
        self.setup_mnemonic_allallall()

        resp1 = self.client.call(
            solana_proto.SolanaGetAddress(
                address_n=[H + 44, H + 501, H + 0, H + 0],
                show_display=False,
            )
        )
        resp2 = self.client.call(
            solana_proto.SolanaGetAddress(
                address_n=[H + 44, H + 501, H + 0, H + 0],
                show_display=False,
            )
        )

        self.assertTrue(
            isinstance(resp1, solana_proto.SolanaAddress),
            "Expected SolanaAddress (call 1), got %s" % type(resp1).__name__
        )
        self.assertTrue(
            isinstance(resp2, solana_proto.SolanaAddress),
            "Expected SolanaAddress (call 2), got %s" % type(resp2).__name__
        )

        addr1 = resp1.address
        addr2 = resp2.address
        if isinstance(addr1, bytes):
            addr1 = addr1.decode('utf-8')
        if isinstance(addr2, bytes):
            addr2 = addr2.decode('utf-8')

        self.assertTrue(
            addr1 == addr2,
            "Determinism violated: '%s' != '%s'" % (addr1, addr2)
        )


    def test_solana_show_address(self):
        """Display Solana address on OLED (triggers ButtonRequest for screenshot capture).

        Note: When KEEPKEY_SCREENSHOT=1, the DebugLink read_layout() call can
        race with the show_display response, causing an empty address. This test
        only asserts we get a SolanaAddress response (not empty-check) so it
        works in both screenshot and non-screenshot modes. Address correctness
        is verified by test_solana_get_address (show_display=False).
        """
        self.requires_firmware("7.14.0")
        self.requires_message("SolanaGetAddress")
        self.setup_mnemonic_allallall()

        resp = self.client.call(
            solana_proto.SolanaGetAddress(
                address_n=[H + 44, H + 501, H + 0, H + 0],
                show_display=True,
            )
        )

        self.assertTrue(
            isinstance(resp, solana_proto.SolanaAddress),
            "Expected SolanaAddress response, got %s" % type(resp).__name__
        )


if __name__ == '__main__':
    unittest.main()
