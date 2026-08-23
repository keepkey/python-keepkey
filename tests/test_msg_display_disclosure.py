# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.

"""On-screen disclosure: what the device shows must distinguish what it signs.

These tests assert one property, stated as a property rather than as a list of
known payloads:

    Two requests whose SIGNED BYTES differ must not produce IDENTICAL screens.

If two different payloads render the same pixels, then whatever distinguishes
them is invisible to the user at the moment they approve, and their approval
does not mean what it appears to mean. That is the shape of every display /
sign divergence in the 7.14.2 audit, independent of which chain or which field
happened to carry it.

Why pixels and not text: DebugLinkState.layout is the framebuffer, 2048 bytes
of 1-bit 256x64. There is no text channel, so the assertions here are
differential. That is a feature for this property — it makes no assumption
about wording, spacing, fonts or truncation strategy, so it keeps holding when
the copy changes, and it cannot be satisfied by a screen that merely looks
plausible.

Each case below is a payload pair built so the difference lies exactly where a
naive implementation stops looking:

  - past a NUL, because a protobuf `bytes` field is not a C string and "%s"
    stops there while the signature covers the rest;
  - past the visible cut, with whitespace chosen so a length or line-count
    check measures the padded string as fitting;
  - past the end of one screen, where a truncating renderer silently drops the
    tail rather than paging it.

Refusal counts as a pass. A device that declines to sign something it cannot
display honestly has satisfied the property; the failure being tested for is
signing it while showing the user something indistinguishable from the benign
case.
"""

from __future__ import print_function

import unittest

import common

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types
from keepkeylib.client import CallException


class ScreenRecorder(object):
    """Records the framebuffer at every ButtonRequest of one flow.

    The client answers ButtonRequests through callback_ButtonRequest. Reading
    the layout inside that callback captures each screen while it is actually
    displayed; reading it afterwards would only ever see the home screen.
    """

    def __init__(self, client, answer=True):
        self.client = client
        self.answer = answer
        self.screens = []
        self._original = None

    def __enter__(self):
        client = self.client
        recorder = self

        self._original = client.callback_ButtonRequest

        def recording_callback(msg):
            try:
                layout = client.debug.read_layout()
                if layout:
                    recorder.screens.append(bytes(layout))
            except Exception:
                # A capture failure must not mask the behaviour under test;
                # the assertions below check what was captured.
                pass
            try:
                # Also emit the frame as a PNG through the normal capture path.
                # This class answers ButtonRequests itself, which bypasses the
                # client's own capture hook -- so under KEEPKEY_SCREENSHOT=1
                # these tests were selected by the screenshot filter, passed,
                # and produced NO images. The screens this suite exists to
                # police were the ones nobody could look at.
                if getattr(client, 'screenshot_dir', None):
                    client._capture_oled()
            except Exception:
                pass
            if recorder.answer:
                client.debug.press_yes()
            else:
                client.debug.press_no()
            return proto.ButtonAck()

        client.callback_ButtonRequest = recording_callback
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.client.callback_ButtonRequest = self._original
        return False

    @property
    def fingerprint(self):
        """The full ordered screen sequence, as a comparable value."""
        return tuple(self.screens)


class TestDisplayDisclosesSignedContent(common.KeepKeyTest):

    # The disclosure behaviour these assert landed in 7.14.2. On older
    # firmware the payloads below are signed with a truncated or NUL-stopped
    # display, which is the defect, so the tests would fail for the right
    # reason on the wrong target. Gate rather than assert against old builds.
    MIN_FIRMWARE = "7.14.2"

    def setUp(self):
        super(TestDisplayDisclosesSignedContent, self).setUp()
        self.requires_firmware(self.MIN_FIRMWARE)
        # The inherited setUp wipes the device. Without a seed every
        # SignMessage below is refused with Failure_NotInitialized before
        # confirm_bytes() is ever reached, _sign_message_screens() returns
        # None, and _assert_distinguishable() returns without asserting -- so
        # the whole suite passed while exercising zero display logic. Load a
        # seed so the device actually renders the screens under test.
        self.setup_mnemonic_nopin_nopassphrase()

    # ── helpers ─────────────────────────────────────────────────────────

    def _sign_message_screens(self, message):
        """Sign the exact bytes of `message`; return the screens, or None.

        Deliberately builds the protobuf rather than calling
        ``client.sign_message()``: that helper runs ``normalize_nfc()`` and
        re-encodes to UTF-8, which would rewrite the very payloads under test
        — a NUL-bearing or whitespace-padded body would not survive it intact.
        A hostile host has no such helper in the way, so the test should not
        either.

        None means the device declined to sign, which satisfies the property.
        """
        recorder = ScreenRecorder(self.client, answer=True)
        try:
            with recorder:
                self.client.call(proto.SignMessage(
                    coin_name='Bitcoin',
                    address_n=[0],
                    message=message,
                    script_type=types.SPENDADDRESS,
                ))
        except CallException:
            return None
        return recorder.fingerprint

    def _assert_distinguishable(self, a_label, a_msg, b_label, b_msg):
        """The two payloads must not present identically to the user."""
        a = self._sign_message_screens(a_msg)
        b = self._sign_message_screens(b_msg)

        if a is None or b is None:
            # A refusal is only meaningful from an initialized device that
            # could have signed and chose not to. On an uninitialized device
            # every call is refused for an unrelated reason, which is what let
            # this suite pass vacuously -- so assert the device can sign at
            # all before treating a refusal as the honest-refusal pass.
            self.assertTrue(
                self.client.features.initialized,
                "device is not initialized, so this refusal says nothing "
                "about display disclosure -- the assertion below never ran")
            refused = a_label if a is None else b_label
            raise AssertionError(
                "device refused to sign %s. Refusing to display what it "
                "cannot show honestly is defensible, but it must be an "
                "explicit, reviewed decision rather than a silent pass: if "
                "this is intended, assert the refusal here by name."
                % refused)

        self.assertNotEqual(
            a, b,
            "%s and %s produced identical screens, so the bytes that differ "
            "between them were never shown. The user approving %s cannot tell "
            "it apart from %s, and the signature covers the difference."
            % (a_label, b_label, b_label, a_label),
        )

    # ── the property, at each place an implementation stops looking ─────

    def test_bytes_past_an_embedded_nul_are_disclosed(self):
        """A protobuf `bytes` field is not a C string.

        Passing it to "%s" stops the display at the first NUL while
        cryptoMessageSign covers message.size bytes, so everything after the
        NUL is signed invisibly.
        """
        benign = b"benign login"
        hidden = b"benign login\x00 AND APPROVE TRANSFER OF ALL FUNDS"
        self._assert_distinguishable(
            "a plain message", benign,
            "the same message with a NUL-hidden suffix", hidden,
        )

    def test_bytes_past_whitespace_padding_are_disclosed(self):
        """Whitespace is the cheapest way to push content out of view.

        A leading space costs zero pixels once a line has wrapped, so padding
        can make an over-long body measure as fitting while the tail is
        neither shown nor dropped from the signature.
        """
        benign = b"Sign in to example.com"
        padded = b"Sign in to example.com" + b" " * 320 + \
                 b"AND APPROVE TRANSFER TO 0xATTACKER"
        self._assert_distinguishable(
            "a short login message", benign,
            "the same message padded so the suffix falls past the cut", padded,
        )

    def test_bytes_past_the_first_screen_are_disclosed(self):
        """Content beyond one screenful must not vanish silently.

        Whether the device pages it, states how much is hidden, or refuses is
        not asserted here — only that the two payloads do not look the same.
        """
        short = b"a" * 40
        long_with_tail = b"a" * 400 + b"THE PART YOU NEVER SAW"
        self._assert_distinguishable(
            "a message that fits", short,
            "a long message with a distinct tail", long_with_tail,
        )

    def test_newline_padding_does_not_collapse_the_screen(self):
        """Line counting is a security boundary, so it must not wrap.

        A body carrying many newlines exercises the row counter rather than
        the character count; if that counter overflows, an arbitrarily long
        body reports as fitting.
        """
        benign = b"Confirm login"
        newline_padded = b"Confirm login" + b"\n" * 300 + b"APPROVE EVERYTHING"
        self._assert_distinguishable(
            "a one-line message", benign,
            "the same message behind 300 newlines", newline_padded,
        )

    # ── the flow must actually reach the user ───────────────────────────

    def test_signing_shows_at_least_one_screen(self):
        """Guards the tests above.

        Every assertion here compares screen sequences. If a flow produced no
        ButtonRequest at all, two payloads would trivially compare equal as
        empty tuples and the suite would pass while showing the user nothing.
        """
        screens = self._sign_message_screens(b"hello")
        # Do NOT skip here. This test exists to prove the rest of the file is
        # not vacuous, so skipping itself when the device will not sign is the
        # one failure mode it cannot be allowed to have -- that is exactly how
        # the whole suite went green against an uninitialized device.
        self.assertIsNotNone(
            screens,
            "device refused to sign the control message, so every comparison "
            "in this file compared None against None and asserted nothing")
        self.assertGreater(
            len(screens), 0,
            "signing produced no ButtonRequest, so nothing was shown to the "
            "user and the comparisons in this file would be vacuous",
        )
        self.assertTrue(
            any(sum(bytearray(s)) > 0 for s in screens),
            "every captured screen was blank",
        )


if __name__ == '__main__':
    unittest.main()
