"""Regression tests for libkkemu's screenshot / DebugLinkGetState path.

Two firmware-side changes need functional coverage that the existing dylib
confirm-flow test doesn't provide:

1. ``RINGBUF_CAPACITY`` in ``lib/emulator/ringbuf.h``. A 2048-byte
   ``DebugLinkState.layout`` field plus the rest of the message serializes
   to ~44 HID reports through the output ring; the previous capacity left
   effective room for 31 reports, so screenshot capture truncated silently
   (``msg_debug_write`` ignored ``emulatorSocketWrite``'s 0-on-full
   return). The host saw a short payload, not an error.

2. ``fsm_msgDebugLinkGetState`` in ``lib/firmware/fsm_msg_debug.h``: now
   does a single ``display_refresh()`` instead of
   ``force_animation_start() + animate()``. The old form overwrote static
   layouts (``layout_warning``, address displays, etc.) with stale
   animation frames or no-ops depending on queue state, so screenshots
   captured something different from what the user was seeing on screen.

Both fixes are functionally invisible to the existing
``test_dylib_confirm_flow`` suite — that test never asks for a layout. So
without these tests, regressing either change ships green.

Skipped unless ``KK_TRANSPORT=dylib``. Set ``KK_DYLIB=/path/to/libkkemu.dylib``
to run.
"""

import os
import unittest


@unittest.skipUnless(
    os.environ.get("KK_TRANSPORT") == "dylib",
    "dylib screenshot regression — set KK_TRANSPORT=dylib KK_DYLIB=...",
)
class TestDylibScreenshot(unittest.TestCase):
    """Constructs a fresh KeepKeyDebuglinkClient against the dylib singleton
    WITHOUT going through ``common.KeepKeyTest.setUp`` — the canonical
    fixture wipes the device on every test, and ``wipe_device`` exercises
    the confirm-flow path that ``test_dylib_confirm_flow`` is itself a
    pending regression for. Reading a layout doesn't require any of that;
    we just init and ask DebugLink for the home-screen capture.
    """

    def setUp(self):
        # Late imports — `config` and `common` construct transports on
        # import and would fail / hang under non-dylib runs even though
        # this class is skip-decorated.
        import config  # noqa: WPS433
        from keepkeylib.client import KeepKeyDebuglinkClient  # noqa: WPS433

        transport = config.TRANSPORT(*config.TRANSPORT_ARGS, **config.TRANSPORT_KWARGS)
        debug_transport = config.DEBUG_TRANSPORT(
            *config.DEBUG_TRANSPORT_ARGS, **config.DEBUG_TRANSPORT_KWARGS
        )
        self.client = KeepKeyDebuglinkClient(transport)
        self.client.set_debuglink(debug_transport)
        # No wipe_device — dylib boot already drew the home screen and
        # that's what we want to capture. Going through wipe would also
        # exercise confirm_helper, which is intentionally out of scope here.

    def tearDown(self):
        try:
            self.client.close()
        except Exception:
            pass

    # ── Ring capacity coverage ──────────────────────────────────────────

    def test_layout_round_trip_fits_through_ring(self):
        """The smoking-gun test for ``RINGBUF_CAPACITY``.

        ``messages.options`` declares ``DebugLinkState.layout max_size:2048``.
        If the output ring is too small, the response is truncated mid-
        layout-field and either fails to decode or returns a short value.
        Either way the canonical contract — 2048 bytes — is broken.
        """
        layout = self.client.debug.read_layout()

        # nanopb encodes the layout field as bytes; python-keepkey returns
        # whatever bytes the firmware put in. The contract is exactly 2048.
        self.assertEqual(
            len(layout), 2048,
            "DebugLinkState.layout returned %d bytes; firmware contract is 2048. "
            "Truncation here points at an undersized libkkemu output ring." % len(layout),
        )
        # Sanity: the home screen has *something* drawn on it; a fully-zero
        # layout would mean we read a frame before the firmware drew home.
        self.assertGreater(
            sum(layout), 0,
            "Layout came back all zeros — host raced firmware boot? "
            "DylibState.__init__ pumps 8 polls before returning; if that "
            "stops being enough to settle the home screen, this test will "
            "catch it.",
        )

    def test_layout_repeated_reads_no_truncation(self):
        """Ten back-to-back ``read_layout`` calls must each return 2048 bytes.

        A subtle ring-capacity bug could pass a single read (writer fills,
        reader drains, writer re-fills cleanly) but fail under repeated
        reads if writer/reader fall out of phase. Catches half-step
        truncation that the single-shot test above misses.
        """
        for i in range(10):
            layout = self.client.debug.read_layout()
            self.assertEqual(
                len(layout), 2048,
                "Read #%d returned %d bytes" % (i, len(layout)),
            )

    # ── Canvas semantics coverage ───────────────────────────────────────

    def test_layout_stable_across_idle_reads(self):
        """When the firmware is idle (sitting on the home screen) the
        captured layout must be byte-identical between reads.

        With the OLD ``fsm_msgDebugLinkGetState`` code, the
        ``force_animation_start() + animate()`` calls before the canvas
        capture would either:
          (a) re-run a queued animation → the bytes would change between
              reads as the animation advanced, OR
          (b) overwrite a static canvas with a no-op redraw → bytes match
              this read but the next layout-changing call sees stale state.

        With the new ``display_refresh()`` form, the canvas is whatever
        the firmware last drew — stable across reads of an idle UI.
        """
        first = self.client.debug.read_layout()
        for i in range(5):
            again = self.client.debug.read_layout()
            self.assertEqual(
                first, again,
                "Idle layout byte-changed between reads (iter %d). "
                "fsm_msgDebugLinkGetState may be running animations again." % i,
            )

    def test_layout_features_dont_corrupt_capture(self):
        """An interleaved Initialize call (which the canonical
        ``KeepKeyTest`` setUp ALSO does as part of ``KeepKeyClient``
        construction) must not desynchronize the next ``read_layout``.

        Catches a class of dylib-output-ring bugs where a non-debug
        response leaves bytes in the main ring that bleed into the next
        DebugLink read. Both rings are independent, but a serializer bug
        that writes to the wrong iface would surface as a misframed
        screenshot.
        """
        self.client.init_device()  # round-trips Features on iface 0
        layout = self.client.debug.read_layout()
        self.assertEqual(len(layout), 2048)


if __name__ == "__main__":
    unittest.main()
