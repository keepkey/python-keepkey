"""Regression test for the dylib confirm-flow contract.

Exercises the keepkey-vault FFI path:

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

Layout deliberately splits ``setUp`` (cheap: just open a client against
the dylib singleton) from the confirm-touching operations (in the test
methods themselves). Doing wipe/load inside ``setUp`` would defeat
``pytest.mark.xfail`` on the pending confirm-flow test, because the hang
would happen before the test method even runs — pytest can't classify a
setUp hang as expected-failure.

Skips automatically when ``KK_TRANSPORT != 'dylib'`` so the file is safe
to keep in the regular pytest run.
"""

import os
import unittest


@unittest.skipUnless(
    os.environ.get("KK_TRANSPORT") == "dylib",
    "dylib confirm-flow regression — set KK_TRANSPORT=dylib KK_DYLIB=...",
)
class TestDylibConfirmFlow(unittest.TestCase):
    """Skipped under the default UDP transport; the UDP daemon hides the
    polling contract that this test specifically validates."""

    def setUp(self):
        """Construct the client directly — NO wipe_device, NO load_device.

        Going through ``common.KeepKeyTest.setUp`` would call
        ``self.client.wipe_device()`` (common.py:62) which itself enters
        the confirm-flow path that this file's pending test is a
        regression for. A hang in setUp can't be classified by
        ``pytest.mark.xfail``; it would just appear to lock the runner.
        """
        # Late imports — `config` instantiates a transport on import and
        # would fail under non-dylib runs even though this class is
        # skip-decorated.
        import config  # noqa: WPS433
        from keepkeylib.client import KeepKeyDebuglinkClient  # noqa: WPS433

        transport = config.TRANSPORT(*config.TRANSPORT_ARGS, **config.TRANSPORT_KWARGS)
        debug_transport = config.DEBUG_TRANSPORT(
            *config.DEBUG_TRANSPORT_ARGS, **config.DEBUG_TRANSPORT_KWARGS
        )
        self.client = KeepKeyDebuglinkClient(transport)
        self.client.set_debuglink(debug_transport)

    def tearDown(self):
        try:
            self.client.close()
        except Exception:
            pass

    def test_features_round_trip(self):
        """The connection itself works; Features should have firmware fields.

        This is the pure no-confirm path: just Initialize → Features.
        Validates that the dylib's main-iface ringbuffer wiring delivers a
        single round-trip end-to-end. Should always pass.
        """
        self.client.init_device()
        f = self.client.features
        self.assertGreaterEqual(f.major_version, 7)

    @unittest.skip(
        "Pending firmware fix — confirm_helper busy-loops on a ButtonAck "
        "the dylib silently consumed but never delivered. The original "
        "intent here was @pytest.mark.xfail(strict=True) + "
        "@pytest.mark.timeout, but neither pytest-timeout method (signal "
        "or thread) can interrupt the C-level kkemu_poll() loop — the "
        "hang locks up the entire test runner instead of failing the test. "
        "Once the firmware fix lands, drop the @unittest.skip and run "
        "this directly; if a future change makes kkemu_poll() interruptible "
        "from Python (e.g. periodic GIL release with a deadline check), "
        "switch back to xfail(strict=True)+timeout so the test self-promotes."
    )
    def test_load_device_with_auto_confirm(self):
        """The full LoadDevice flow — confirm_helper must exit cleanly.

        This is the exact path the keepkey-vault wipe_device flow hangs on.
        With the firmware bug present, the test hangs at wipe_device (or
        load_device) and pytest-timeout cannot break out — so we skip
        rather than lock up the runner. Re-enable when firmware ships.
        """
        # Mnemonic taken from common.KeepKeyTest.mnemonic12 to keep
        # eyeball-comparison with that fixture trivial.
        mnemonic = "alcohol woman abuse must during monitor noble actual mixed trade anger aisle"

        self.client.wipe_device()
        self.client.load_device_by_mnemonic(
            mnemonic=mnemonic,
            pin="",
            passphrase_protection=False,
            label="test",
            language="english",
        )
        # Round-trip something that requires the seed — confirms LoadDevice
        # actually committed instead of bouncing off a confirm timeout.
        addr = self.client.get_address("Bitcoin", [])
        # Valid mainnet P2PKH addresses start with '1' and are 26-35 chars.
        self.assertTrue(addr.startswith("1"))
        self.assertGreaterEqual(len(addr), 26)


if __name__ == "__main__":
    unittest.main()
