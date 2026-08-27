# This file is part of the TREZOR project.
#
# Copyright (C) 2012-2016 Marek Palatinus <slush@satoshilabs.com>
# Copyright (C) 2012-2016 Pavol Rusnak <stick@satoshilabs.com>
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
#
# The script has been modified for KeepKey Device.

import unittest
import common
import hashlib
import os
import time

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from mnemonic import Mnemonic

def generate_entropy(strength, internal_entropy, external_entropy):
    '''
    strength - length of produced seed. One of 128, 192, 256
    random - binary stream of random data from external HRNG
    '''
    if strength not in (128, 192, 256):
        raise Exception("Invalid strength")

    if not internal_entropy:
        raise Exception("Internal entropy is not provided")

    if len(internal_entropy) < 32:
        raise Exception("Internal entropy too short")

    if not external_entropy:
        raise Exception("External entropy is not provided")

    if len(external_entropy) < 32:
        raise Exception("External entropy too short")

    entropy = hashlib.sha256(internal_entropy + external_entropy).digest()
    entropy_stripped = entropy[:int(strength / 8)]

    if len(entropy_stripped) * 8 != strength:
        raise Exception("Entropy length mismatch")

    return entropy_stripped

class TestDeviceReset(common.KeepKeyTest):
    def _current_layout_for_capture(self):
        if os.environ.get('KEEPKEY_SCREENSHOT') != '1':
            return None
        return self.client.debug.read_layout()

    def _capture_after_stable_transition(self, previous_layout):
        """Record the screen belonging to the response we just received.

        ButtonRequest can arrive before the emulator has repainted the OLED.
        Capturing immediately therefore retained the preceding screen and
        silently omitted the final seed page. Polling DebugLink also advances
        the emulator render loop, so require a changed layout to remain stable
        for three reads before accepting it as evidence.
        """
        if os.environ.get('KEEPKEY_SCREENSHOT') != '1':
            return None

        deadline = time.monotonic() + 2.0
        candidate = None
        stable_reads = 0
        while time.monotonic() < deadline:
            layout = self.client.debug.read_layout()
            if layout != previous_layout:
                if layout == candidate:
                    stable_reads += 1
                else:
                    candidate = layout
                    stable_reads = 1
                if stable_reads >= 3:
                    self.client._capture_oled(layout)
                    return layout
            else:
                candidate = None
                stable_reads = 0
            time.sleep(0.025)

        raise RuntimeError(
            'OLED did not reach a stable changed seed-ceremony screen')

    def _reset_without_pin_and_capture(self, strength):
        external_entropy = b'zlutoucky kun upel divoke ody' * 2
        ret = self.client.call_raw(proto.ResetDevice(display_random=False,
                                               strength=strength,
                                               passphrase_protection=False,
                                               pin_protection=False,
                                               language='english',
                                               label='test'))

        # Provide entropy
        self.assertIsInstance(ret, proto.EntropyRequest)
        internal_entropy = self.client.debug.read_reset_entropy()
        previous_layout = self._current_layout_for_capture()
        resp = self.client.call_raw(proto.EntropyAck(entropy=external_entropy))

        # Generate mnemonic locally
        entropy = generate_entropy(strength, internal_entropy, external_entropy)
        expected_mnemonic = Mnemonic('english').to_mnemonic(entropy)

        # Explainer Dialog
        self.assertIsInstance(resp, proto.ButtonRequest)
        previous_layout = self._capture_after_stable_transition(previous_layout)
        self.client.debug.press_yes()
        resp = self.client.call_raw(proto.ButtonAck())

        mnemonic = []
        while isinstance(resp, proto.ButtonRequest):
            previous_layout = self._capture_after_stable_transition(
                previous_layout)
            words = self.client.debug.read_reset_word()
            # 7.14.2's debug build exposes each physical subpage as a separate
            # ButtonRequest for evidence capture. All subpages in one legacy
            # word group intentionally report the same reset_word value.
            if not mnemonic or mnemonic[-1] != words:
                mnemonic.append(words)
            self.client.debug.press_yes()
            resp = self.client.call_raw(proto.ButtonAck())

        mnemonic = ' '.join(mnemonic)

        self.assertEqual(mnemonic, expected_mnemonic)
        self.assertIsInstance(resp, proto.Success)
        self.assertEqual(strength // 32 * 3, len(mnemonic.split()))
        return self.client.call_raw(proto.Initialize())

    def test_reset_device(self):
        # 128-bit entropy produces the 12-word ceremony.
        resp = self._reset_without_pin_and_capture(128)
        self.assertFalse(resp.pin_protection)
        self.assertFalse(resp.passphrase_protection)

        # Do passphrase-protected action, PassphraseRequest should NOT be raised
        resp = self.client.call_raw(proto.Ping(passphrase_protection=True))
        self.assertIsInstance(resp, proto.Success)

        # Do PIN-protected action, PinRequest should NOT be raised
        resp = self.client.call_raw(proto.Ping(pin_protection=True))
        self.assertIsInstance(resp, proto.Success)

    def test_reset_device_dice(self):
        # 7.14.3, not 7.15.0: the bitcoin-only 7.14.3 release line carries the
        # dice backport, and no firmware between 7.14.3 and 7.15.0 exists
        # without it, so the version gate is exact for the whole fleet.
        self.requires_firmware("7.14.3")

        external_entropy = b'zlutoucky kun upel divoke ody' * 2
        strength = 256  # 99 rolls

        previous_layout = self._current_layout_for_capture()
        ret = self.client.call_raw(proto.ResetDevice(display_random=False,
                                               strength=strength,
                                               passphrase_protection=False,
                                               pin_protection=False,
                                               language='english',
                                               label='dice',
                                               dice_entropy=True))

        # Device announces the on-device dice entry screen
        self.assertIsInstance(ret, proto.ButtonRequest)
        self.assertEqual(ret.code, proto_types.ButtonRequest_DiceRoll)
        dice_entry_layout = self._capture_after_stable_transition(previous_layout)

        # Ack without blocking on the reply: the device only leaves the dice
        # screen once the rolls are complete, and input is ignored until the
        # ButtonRequest is acked.
        self.client.transport.write(proto.ButtonAck())
        time.sleep(0.3)

        # Inject rolls in max_size-40 chunks, exercising undo ('u') along the
        # way. Simulate the same rules host-side to know the expected string.
        chunks = [
            "123456" * 6 + "1234",           # 40 digits
            "654321" * 6 + "43u2",           # 39 digits + undo
            "1234561234561234561u2u3",       # more undo churn
            "555555555555555555555555",      # top up past 99 (extras dropped)
        ]
        expected = []
        for chunk in chunks:
            for c in chunk:
                if c == 'u':
                    if expected:
                        expected.pop()
                elif len(expected) < 99:
                    expected.append(c)
            self.client.debug.press_input(chunk)
            time.sleep(0.2)
        expected = ''.join(expected)
        self.assertEqual(len(expected), 99)

        # Rolls complete -> digest confirmation screen
        resp = self.client.transport.read_blocking()
        self.assertIsInstance(resp, proto.ButtonRequest)
        self.assertEqual(resp.code, proto_types.ButtonRequest_DiceRoll)
        self._capture_after_stable_transition(dice_entry_layout)

        # The device-computed digest must cover exactly the injected rolls
        dice_digest = self.client.debug.read_dice_digest()
        self.assertEqual(dice_digest,
                         hashlib.sha256(expected.encode('ascii')).digest())

        self.client.debug.press_yes()
        ret = self.client.call_raw(proto.ButtonAck())

        # From here the flow is the standard one: the displayed internal
        # entropy is the post-dice-mix value and still binds the seed.
        self.assertIsInstance(ret, proto.EntropyRequest)
        internal_entropy = self.client.debug.read_reset_entropy()
        resp = self.client.call_raw(proto.EntropyAck(entropy=external_entropy))

        entropy = generate_entropy(strength, internal_entropy, external_entropy)
        expected_mnemonic = Mnemonic('english').to_mnemonic(entropy)

        # Explainer dialog, then the paginated backup
        self.assertIsInstance(resp, proto.ButtonRequest)
        self.client.debug.press_yes()
        resp = self.client.call_raw(proto.ButtonAck())

        mnemonic = []
        while isinstance(resp, proto.ButtonRequest):
            mnemonic.append(self.client.debug.read_reset_word())
            self.client.debug.press_yes()
            resp = self.client.call_raw(proto.ButtonAck())

        self.assertIsInstance(resp, proto.Success)
        self.assertEqual(' '.join(mnemonic), expected_mnemonic)

    def test_reset_reentry_disarms_entropy_ack(self):
        """An abandoned reset must never leave EntropyAck armed.

        Regression this guards: reset_init aborts (dice cancel, PIN mismatch,
        ...) left awaiting_entropy set from an earlier run while zeroing
        int_entropy, so a following EntropyAck derived the seed from
        sha256(0*32 || host_bytes) -- entirely host-chosen.

        7.15 closes it EARLIER and more strongly than the original fix did.
        #429 replaced the separate awaiting_entropy flag with a single armed
        (kind) ceremony, and setup_stage() now REFUSES to open a second
        ceremony on top of an armed one. So the re-entry this test used to
        perform is rejected outright rather than being allowed and then
        disarmed -- there is no second ceremony to leave armed. Both halves are
        asserted below: the refusal, and then the original property.
        """
        # 7.14.3: the bitcoin-only release line carries the same single-armed
        # ceremony and the dice backport; see test_reset_device_dice.
        self.requires_firmware("7.14.3")
        self.client.wipe_device()

        # Arm a reset and walk away without acking the entropy request.
        ret = self.client.call_raw(proto.ResetDevice(display_random=False,
                                               strength=256,
                                               passphrase_protection=False,
                                               pin_protection=False,
                                               language='english',
                                               label='first'))
        self.assertIsInstance(ret, proto.EntropyRequest)

        # Re-entry is REFUSED while a ceremony is armed. This is the #429
        # guard; before it, the second ResetDevice was accepted and the code
        # had to remember to disarm the first one.
        ret = self.client.call_raw(proto.ResetDevice(display_random=False,
                                               strength=256,
                                               passphrase_protection=False,
                                               pin_protection=False,
                                               language='english',
                                               label='second',
                                               dice_entropy=True))
        self.assertIsInstance(ret, proto.Failure)
        self.assertIn('middle of setup', ret.message)

        # Abandon the FIRST ceremony the way the host is told to.
        ret = self.client.call_raw(proto.Cancel())
        self.assertIsInstance(ret, proto.Failure)

        # The abandoned reset must be disarmed, so this cannot generate a seed.
        ret = self.client.call_raw(proto.EntropyAck(entropy=b'H' * 32))
        self.assertIsInstance(ret, proto.Failure)
        self.assertIn('Not in Reset mode', ret.message)

        # And the device must still be uninitialized.
        ret = self.client.call_raw(proto.Initialize())
        self.assertFalse(ret.initialized)

    def test_reset_device_18_words(self):
        resp = self._reset_without_pin_and_capture(192)
        self.assertFalse(resp.pin_protection)
        self.assertFalse(resp.passphrase_protection)

    def test_reset_device_24_words(self):
        resp = self._reset_without_pin_and_capture(256)
        self.assertFalse(resp.pin_protection)
        self.assertFalse(resp.passphrase_protection)

    def test_reset_device_pin(self):
        external_entropy = b'zlutoucky kun upel divoke ody' * 2
        strength = 128
        hides_internal_entropy = self.firmware_at_least("7.14.2")

        ret = self.client.call_raw(proto.ResetDevice(display_random=True,
                                               strength=strength,
                                               passphrase_protection=True,
                                               pin_protection=True,
                                               language='english',
                                               label='test'))

        # display_random=True above is deliberate: the field stays in the wire
        # schema for host compatibility. Firmware 7.15.0 (fw 320f0eb5, "no
        # entropy display") stopped honouring it -- internal entropy is seed
        # pre-image material, and a host that sets the flag and reads that
        # screen once can compute SHA256(shown || ext) and derive the seed.
        #
        # Branch on the version rather than skipping the test: everything below
        # (PIN entry, EntropyRequest/Ack, mnemonic derivation) is version-
        # independent and must keep running on older firmware.
        f = self.client.features
        if (f.major_version, f.minor_version, f.patch_version) < (7, 15, 0):
            # Pre-7.15: the Internal Entropy screen legitimately still exists.
            self.assertIsInstance(ret, proto.ButtonRequest)
            self.client.debug.press_yes()
            ret = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(ret, proto.PinMatrixRequest)
        self.client._capture_oled_after_animation(1.05, (192, 256, 0, 64))

        # Enter PIN for first time
        pin_encoded = self.client.debug.encode_pin('654')
        ret = self.client.call_raw(proto.PinMatrixAck(pin=pin_encoded))
        self.assertIsInstance(ret, proto.PinMatrixRequest)
        self.client._capture_oled_after_animation(1.05, (192, 256, 0, 64))

        # Enter PIN for second time
        pin_encoded = self.client.debug.encode_pin('654')
        ret = self.client.call_raw(proto.PinMatrixAck(pin=pin_encoded))

        # Provide entropy
        self.assertIsInstance(ret, proto.EntropyRequest)
        internal_entropy = self.client.debug.read_reset_entropy()
        previous_layout = self._current_layout_for_capture()
        resp = self.client.call_raw(proto.EntropyAck(entropy=external_entropy))

        # Generate mnemonic locally
        entropy = generate_entropy(strength, internal_entropy, external_entropy)
        expected_mnemonic = Mnemonic('english').to_mnemonic(entropy)

        # Explainer Dialog
        self.assertIsInstance(resp, proto.ButtonRequest)
        previous_layout = self._capture_after_stable_transition(previous_layout)
        self.client.debug.press_yes()
        resp = self.client.call_raw(proto.ButtonAck())

        mnemonic = []
        while isinstance(resp, proto.ButtonRequest):
            previous_layout = self._capture_after_stable_transition(
                previous_layout)
            words = self.client.debug.read_reset_word()
            if not mnemonic or mnemonic[-1] != words:
                mnemonic.append(words)
            self.client.debug.press_yes()
            resp = self.client.call_raw(proto.ButtonAck())

        mnemonic = ' '.join(mnemonic)

        # Compare that device generated proper mnemonic for given entropies
        self.assertEqual(mnemonic, expected_mnemonic)

        self.assertIsInstance(resp, proto.Success)

        # Compare that second pass printed out the same mnemonic once again
        self.assertEqual(mnemonic, expected_mnemonic)

        # Check if device is properly initialized
        resp = self.client.call_raw(proto.Initialize())
        self.assertTrue(resp.pin_protection)
        self.assertTrue(resp.passphrase_protection)

        self.client.clear_session()

        # Do passphrase-protected action, PassphraseRequest should be raised
        resp = self.client.call_raw(proto.Ping(passphrase_protection=True))
        self.assertIsInstance(resp, proto.PassphraseRequest)
        self.client.call_raw(proto.Cancel())

        # Do PIN-protected action, PinRequest should be raised
        resp = self.client.call_raw(proto.Ping(pin_protection=True))
        self.assertIsInstance(resp, proto.PinMatrixRequest)
        self.client.call_raw(proto.Cancel())

    def test_failed_pin(self):
        external_entropy = 'zlutoucky kun upel divoke ody' * 2
        strength = 128
        hides_internal_entropy = self.firmware_at_least("7.14.2")

        ret = self.client.call_raw(proto.ResetDevice(display_random=True,
                                               strength=strength,
                                               passphrase_protection=True,
                                               pin_protection=True,
                                               language='english',
                                               label='test'))

        # display_random=True above is deliberate: the field stays in the wire
        # schema for host compatibility. Firmware 7.15.0 (fw 320f0eb5, "no
        # entropy display") stopped honouring it -- internal entropy is seed
        # pre-image material, and a host that sets the flag and reads that
        # screen once can compute SHA256(shown || ext) and derive the seed.
        #
        # Branch on the version rather than skipping the test: everything below
        # (PIN entry, EntropyRequest/Ack, mnemonic derivation) is version-
        # independent and must keep running on older firmware.
        f = self.client.features
        if (f.major_version, f.minor_version, f.patch_version) < (7, 15, 0):
            # Pre-7.15: the Internal Entropy screen legitimately still exists.
            self.assertIsInstance(ret, proto.ButtonRequest)
            self.client.debug.press_yes()
            ret = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(ret, proto.PinMatrixRequest)
        self.client._capture_oled_after_animation(1.05, (192, 256, 0, 64))

        # Enter PIN for first time
        pin_encoded = self.client.debug.encode_pin(self.pin4)
        ret = self.client.call_raw(proto.PinMatrixAck(pin=pin_encoded))
        self.assertIsInstance(ret, proto.PinMatrixRequest)
        self.client._capture_oled_after_animation(1.05, (192, 256, 0, 64))

        # Enter PIN for second time
        pin_encoded = self.client.debug.encode_pin(self.pin6)
        ret = self.client.call_raw(proto.PinMatrixAck(pin=pin_encoded))

        self.assertIsInstance(ret, proto.Failure)

    def test_already_initialized(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.assertRaises(Exception, self.client.reset_device, False, 128, True, True, 'label', 'english')

if __name__ == '__main__':
    unittest.main()
