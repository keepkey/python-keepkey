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

import os
import hashlib
import json
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

    def __init__(self, client, answer=True, screenshot_group=None):
        self.client = client
        self.answer = answer
        self.screenshot_group = screenshot_group
        self.screens = []
        self._original = None
        self._original_screenshot_dir = None
        self._original_screenshot_id = None
        self._group_dir = None

    def __enter__(self):
        client = self.client
        recorder = self

        self._original = client.callback_ButtonRequest
        if self.screenshot_group and getattr(client, 'screenshot_dir', None):
            self._original_screenshot_dir = client.screenshot_dir
            self._original_screenshot_id = client.screenshot_id
            client.screenshot_dir = os.path.join(
                client.screenshot_dir, self.screenshot_group
            )
            os.makedirs(client.screenshot_dir, exist_ok=True)
            self._group_dir = client.screenshot_dir
            client.screenshot_id = 0

        def recording_callback(msg):
            # ButtonRequest is written immediately before the firmware draws
            # a paged confirmation's next OLED frame. Reading once here can
            # therefore retain the previous page twice and omit the new one.
            # Use the same settled framebuffer primitive as the production
            # screenshot callback, then bind assertions and PNG output to
            # that one byte sequence.
            layout = client._read_oled_after_settle()
            if not layout:
                raise AssertionError("ButtonRequest produced no OLED layout")
            recorder.screens.append(bytes(layout))
            # Use the same framebuffer for the assertion and PNG. A second
            # DebugLink read can race the button transition and make the PDF
            # evidence disagree with the bytes the test actually compared.
            if getattr(client, 'screenshot_dir', None):
                client._capture_oled(layout=layout)
            if recorder.answer:
                client.debug.press_yes()
            else:
                client.debug.press_no()
            return proto.ButtonAck()

        client.callback_ButtonRequest = recording_callback
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.client.callback_ButtonRequest = self._original
        try:
            if exc_type is None and self._group_dir is not None:
                expected = ["btn%05d.png" % i
                            for i in range(len(self.screens))]
                actual = sorted(
                    name for name in os.listdir(self._group_dir)
                    if name != "frames.json"
                )
                if actual != expected:
                    raise AssertionError(
                        "OLED group %s is incomplete: expected=%r actual=%r" %
                        (self.screenshot_group, expected, actual))
                frames = []
                for name in expected:
                    path = os.path.join(self._group_dir, name)
                    with open(path, "rb") as handle:
                        digest = hashlib.sha256(handle.read()).hexdigest()
                    frames.append({"file": name, "sha256": digest})
                manifest = {
                    "schema": 1,
                    "group": self.screenshot_group,
                    "frame_count": len(frames),
                    "frames": frames,
                }
                manifest_path = os.path.join(self._group_dir, "frames.json")
                with open(manifest_path, "w") as handle:
                    json.dump(manifest, handle, sort_keys=True, indent=2)
                    handle.write("\n")
        finally:
            if self._original_screenshot_dir is not None:
                self.client.screenshot_dir = self._original_screenshot_dir
                self.client.screenshot_id = self._original_screenshot_id
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
        # These are positive display-binding controls, not refusal tests. A
        # fresh emulator is uninitialized; without an explicit seed setup every
        # request is rejected before its first ButtonRequest, the differential
        # cases vacuously "pass", and the only non-vacuity control skips. Keep
        # the fixture capable of reaching the confirmation path.
        self.setup_mnemonic_allallall()

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
            # Refusing to display something it cannot show honestly is a pass.
            return

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
        self.assertIsNotNone(
            screens,
            "device refused the control request; the display-binding A/B "
            "tests did not prove they can reach a confirmation path",
        )
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
