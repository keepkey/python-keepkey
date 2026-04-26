"""Regression test for the dylib confirm-flow contract.

Exercises the exact sequence the keepkey-vault FFI path runs:

  1. Initialize       — Features round-trip (no confirm)
  2. WipeDevice       — needs one confirm (BA on iface 0 + DLD on iface 1)
  3. LoadDevice       — needs one confirm
  4. GetAddress       — Features cache + xpub derivation, no confirm

Each step calls into ``confirm_helper`` inside the firmware while the
caller (this test process) is the only thing driving ``kkemu_poll``. The
exact same firmware passes the UDP-transport tests because the standalone
``kkemu`` binary has its own poll thread; the dylib path doesn't, so any
busy-loop in confirm_helper that waits on a frame the dylib silently
dropped will hang here.

Skips automatically when ``KK_TRANSPORT != 'dylib'`` so the file is safe
to keep in the regular pytest run.
"""

import os
import unittest

import config


@unittest.skipUnless(
    os.environ.get("KK_TRANSPORT") == "dylib",
    "dylib confirm-flow regression — set KK_TRANSPORT=dylib KK_DYLIB=...",
)
class TestDylibConfirmFlow(unittest.TestCase):
    """Skipped under the default UDP transport; the UDP daemon hides the
    polling contract that this test specifically validates."""

    # We import lazily so the module loads even when KK_TRANSPORT != 'dylib'
    # (config.py only constructs the dylib state on demand in that branch).
    def setUp(self):
        # Late import — `common` is heavy (it eagerly wipes the device on
        # construction) and would defeat the skip above.
        import common  # noqa: WPS433

        self._common = common
        self.test = common.KeepKeyTest("setUp")
        self.test.setUp()
        self.client = self.test.client

    def tearDown(self):
        self.test.tearDown()

    def test_features_round_trip(self):
        """The connection itself works; Features should have firmware fields."""
        self.client.init_device()
        f = self.client.features
        self.assertGreaterEqual(f.major_version, 7)

    def test_load_device_with_auto_confirm(self):
        """The full LoadDevice flow — confirm_helper must exit cleanly.

        This is the exact path the vault hangs on. If the dylib's tiny-msg
        dispatch is broken, this test hangs (eventually pytest's timeout
        kills it) instead of returning.
        """
        # KeepKeyTest.setUp already wipes; load a known mnemonic on top.
        self.test.setup_mnemonic_nopin_nopassphrase()
        # Round-trip something that requires the seed — confirms LoadDevice
        # actually committed instead of bouncing off a confirm timeout.
        addr = self.client.get_address("Bitcoin", [])
        # Valid mainnet P2PKH addresses start with '1' and are 26-35 chars.
        self.assertTrue(addr.startswith("1"))
        self.assertGreaterEqual(len(addr), 26)


if __name__ == "__main__":
    unittest.main()
