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

# Dice derivations, restated here independently of the firmware so the tests
# check the published formula rather than whatever the device happens to do.
# The byte tags match lib/firmware/dice_input.c; the shape mirrors Coldcard's
# so its published verifier applies to ONLY mode unchanged.
DICE_TAG_USER = b'KK\x01D'
DICE_TAG_MIX = b'KK\x01SM'


def dice_only_seed(rolls):
    """ONLY mode: seed = SHA256(rolls). Nothing else participates."""
    return hashlib.sha256(rolls.encode('ascii')).digest()


def dice_mixed_seed(device_entropy, rolls):
    """MIXED mode: user = SHA256(tag || rolls);
    seed = SHA256(SHA256(tag2 || device_entropy || user))."""
    user = hashlib.sha256(DICE_TAG_USER + rolls.encode('ascii')).digest()
    inner = hashlib.sha256(DICE_TAG_MIX + device_entropy + user).digest()
    return hashlib.sha256(inner).digest()


def bip39_words_to_entropy(words):
    """Decode a 24-word BIP-39 sentence to its 32 entropy bytes, checking
    the checksum. Written out rather than taken from the mnemonic library so
    the words the device showed are decoded by code the device did not
    write, and so it does not depend on the library version in the test
    image."""
    wordlist = Mnemonic('english').wordlist
    words = words.split()
    if len(words) != 24:
        raise ValueError('expected 24 words, got %d' % len(words))
    bits = ''.join('{:011b}'.format(wordlist.index(w)) for w in words)
    entropy = bytes(int(bits[i:i + 8], 2) for i in range(0, 256, 8))
    checksum = '{:08b}'.format(hashlib.sha256(entropy).digest()[0])
    if bits[256:] != checksum:
        raise ValueError('BIP-39 checksum mismatch')
    return entropy


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

    def _inject_rolls(self, target):
        """Inject rolls in max_size-40 chunks, exercising undo ('u') along
        the way, and simulate the same rules host-side to know the string
        the device saw. Extras past `target` are dropped, as on the device.
        The pattern stays close to uniform so it passes the 30%-per-face
        bias gate for both the 50- and 99-roll targets."""
        chunks = [
            "123456" * 6 + "1234",           # 40 digits
            "654321" * 6 + "43u2",           # 39 digits + undo
            "1234561234561234561u2u3",       # more undo churn
            "612345612345612345612345",      # top up past target
        ]
        expected = []
        for chunk in chunks:
            for c in chunk:
                if c == 'u':
                    if expected:
                        expected.pop()
                elif len(expected) < target:
                    expected.append(c)
            self.client.debug.press_input(chunk)
            time.sleep(0.2)
        expected = ''.join(expected)
        self.assertEqual(len(expected), target)
        return expected

    def _dice_reset(self, mode_char, strength, external_entropy):
        """Drive a dice ResetDevice through the on-device mode selector.

        mode_char is '1' (MIXED) or '2' (ONLY), injected as a committed
        selection exactly as a button hold would be. Returns
        (device_words, rolls, mnemonic, final_resp); device_words is the
        24-word device-entropy sentence MIXED shows before rolling, else ''.
        """
        rolls_needed = {128: 50, 192: 75, 256: 99}[strength]

        previous_layout = self._current_layout_for_capture()
        ret = self.client.call_raw(proto.ResetDevice(display_random=False,
                                               strength=strength,
                                               passphrase_protection=False,
                                               pin_protection=False,
                                               language='english',
                                               label='dice',
                                               dice_entropy=True))

        # The mode selector is the first dice screen. Every dice screen is
        # acked without blocking: the device stays on it until the choice is
        # committed, and input is ignored until the ack arrives.
        self.assertIsInstance(ret, proto.ButtonRequest)
        self.assertEqual(ret.code, proto_types.ButtonRequest_DiceRoll)
        selector_layout = self._capture_after_stable_transition(previous_layout)
        self.client.transport.write(proto.ButtonAck())
        time.sleep(0.3)
        self.client.debug.press_input(mode_char)

        # MIXED shows the device-entropy words BEFORE the rolls, one DiceRoll
        # request per page, readable over DebugLink. The roll screen reads
        # back empty, which is how this loop knows the pages are over.
        resp = self.client.transport.read_blocking()
        device_words = []
        while True:
            self.assertIsInstance(resp, proto.ButtonRequest)
            self.assertEqual(resp.code, proto_types.ButtonRequest_DiceRoll)
            words = self.client.debug.read_reset_word()
            if not words:
                break
            if not device_words or device_words[-1] != words:
                device_words.append(words)
            self.client.debug.press_yes()
            resp = self.client.call_raw(proto.ButtonAck())
        dice_entry_layout = self._capture_after_stable_transition(selector_layout)

        self.client.transport.write(proto.ButtonAck())
        time.sleep(0.3)
        rolls = self._inject_rolls(rolls_needed)

        # Rolls complete -> full-digest confirmation screen
        resp = self.client.transport.read_blocking()
        self.assertIsInstance(resp, proto.ButtonRequest)
        self.assertEqual(resp.code, proto_types.ButtonRequest_DiceRoll)
        self._capture_after_stable_transition(dice_entry_layout)

        # The device-computed digest must cover exactly the injected rolls
        self.assertEqual(self.client.debug.read_dice_digest(),
                         hashlib.sha256(rolls.encode('ascii')).digest())

        self.client.debug.press_yes()
        ret = self.client.call_raw(proto.ButtonAck())

        # The wire flow is unchanged: EntropyRequest is still sent and its ack
        # consumed. Its bytes must not reach the seed, which the callers prove
        # by computing the expected mnemonic without them.
        self.assertIsInstance(ret, proto.EntropyRequest)
        resp = self.client.call_raw(proto.EntropyAck(entropy=external_entropy))

        # Explainer dialog, then the paginated backup
        self.assertIsInstance(resp, proto.ButtonRequest)
        self.client.debug.press_yes()
        resp = self.client.call_raw(proto.ButtonAck())

        mnemonic = []
        while isinstance(resp, proto.ButtonRequest):
            words = self.client.debug.read_reset_word()
            # Debug subpages repeat their logical word group, as in the
            # normal reset collector above. Keep the final seed assertion.
            if not mnemonic or mnemonic[-1] != words:
                mnemonic.append(words)
            self.client.debug.press_yes()
            resp = self.client.call_raw(proto.ButtonAck())

        return ' '.join(device_words), rolls, ' '.join(mnemonic), resp

    def test_reset_device_dice_mixed_is_verifiable(self):
        # Dice exist from 7.14.3; the mode selector this drives ships with the
        # verifiable-dice unit on both 7.14.3 and 7.15.
        self.requires_firmware("7.14.3")

        external_entropy = b'zlutoucky kun upel divoke ody' * 2
        strength = 256  # 99 rolls, 24 words

        device_words, rolls, mnemonic, resp = self._dice_reset(
            '1', strength, external_entropy)
        self.assertIsInstance(resp, proto.Success)

        # The device committed its 32-byte draw as 24 valid BIP-39 words
        # before it had seen a single roll.
        self.assertEqual(24, len(device_words.split()))
        device_entropy = bip39_words_to_entropy(device_words)

        # Recompute the seed from exactly what a user holds -- the words they
        # copied and the rolls they made -- with the host's EntropyAck bytes
        # nowhere in it. A match proves the device used both and ignored the
        # host; the expected value comes from the formula, not the device.
        seed = dice_mixed_seed(device_entropy, rolls)
        self.assertEqual(
            mnemonic, Mnemonic('english').to_mnemonic(seed[:strength // 8]))
        self.assertEqual(24, len(mnemonic.split()))

    def test_reset_device_dice_only_is_verifiable(self):
        self.requires_firmware("7.14.3")

        # A nonzero, known host contribution, so a device that mixed it in
        # would produce a different sentence and fail below.
        external_entropy = b'host bytes that must be ignored' * 2
        strength = 128  # 50 rolls, 12 words: the shorter target too

        device_words, rolls, mnemonic, resp = self._dice_reset(
            '2', strength, external_entropy)
        self.assertIsInstance(resp, proto.Success)

        # Nothing to copy down: the rolls are the entire derivation.
        self.assertEqual('', device_words)
        seed = dice_only_seed(rolls)
        self.assertEqual(
            mnemonic, Mnemonic('english').to_mnemonic(seed[:strength // 8]))
        self.assertEqual(12, len(mnemonic.split()))

    def test_reset_device_dice_rejects_biased_rolls(self):
        self.requires_firmware("7.14.3")

        ret = self.client.call_raw(proto.ResetDevice(display_random=False,
                                               strength=128,
                                               passphrase_protection=False,
                                               pin_protection=False,
                                               language='english',
                                               label='dice',
                                               dice_entropy=True))
        self.assertIsInstance(ret, proto.ButtonRequest)
        self.client.transport.write(proto.ButtonAck())
        time.sleep(0.3)
        self.client.debug.press_input('2')

        resp = self.client.transport.read_blocking()
        self.assertIsInstance(resp, proto.ButtonRequest)
        self.assertEqual(resp.code, proto_types.ButtonRequest_DiceRoll)
        self.client.transport.write(proto.ButtonAck())
        time.sleep(0.3)

        # Fifty ones: one face on 100% of the rolls. Coldcard's rule refuses
        # anything over 30%, and so does the device -- before it shows a
        # digest, so a loaded die never becomes a wallet.
        self.client.debug.press_input('1' * 40)
        time.sleep(0.2)
        self.client.debug.press_input('1' * 10)
        time.sleep(0.2)

        resp = self.client.transport.read_blocking()
        self.assertIsInstance(resp, proto.Failure)
        self.assertEqual(resp.code, proto_types.Failure_SyntaxError)

    def test_reset_reentry_disarms_entropy_ack(self):
        """An abandoned reset must never leave EntropyAck armed.

        Regression this guards: reset_init aborts (dice cancel, PIN mismatch,
        ...) left awaiting_entropy set from an earlier run while zeroing
        int_entropy, so a following EntropyAck derived the seed from
        sha256(0*32 || host_bytes) -- entirely host-chosen.

        The post-RC18 setup hardening closes it EARLIER and more strongly than
        the original fix did.
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
        # display_random is ignored by every supported product. 7.14.2 always
        # did; 7.14.3 and 7.15 now do too. The request below deliberately sets
        # it to True so this test fails if any firmware starts honouring it
        # again: the device half it would render is the exact 32 bytes whose
        # complement this host supplies, so the screen plus our own
        # external_entropy is the seed pre-image.

        ret = self.client.call_raw(proto.ResetDevice(display_random=True,
                                               strength=strength,
                                               passphrase_protection=True,
                                               pin_protection=True,
                                               language='english',
                                               label='test'))

        self.assertNotIsInstance(
            ret, proto.ButtonRequest,
            'display_random must be ignored: firmware answered the reset with a '
            'ButtonRequest, which means an internal-entropy screen was drawn')
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
        # display_random is ignored by every supported product. 7.14.2 always
        # did; 7.14.3 and 7.15 now do too. The request below deliberately sets
        # it to True so this test fails if any firmware starts honouring it
        # again: the device half it would render is the exact 32 bytes whose
        # complement this host supplies, so the screen plus our own
        # external_entropy is the seed pre-image.

        ret = self.client.call_raw(proto.ResetDevice(display_random=True,
                                               strength=strength,
                                               passphrase_protection=True,
                                               pin_protection=True,
                                               language='english',
                                               label='test'))

        self.assertNotIsInstance(
            ret, proto.ButtonRequest,
            'display_random must be ignored: firmware answered the reset with a '
            'ButtonRequest, which means an internal-entropy screen was drawn')
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
