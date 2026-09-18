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

import time
import unittest
import common
import hashlib

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
    POST_RC18_SETUP_FIRMWARE = "7.16.0"

    def test_reset_device(self):
        # No PIN, no passphrase
        external_entropy = b'zlutoucky kun upel divoke ody' * 2
        strength = 128

        ret = self.client.call_raw(proto.ResetDevice(display_random=False,
                                               strength=strength,
                                               passphrase_protection=False,
                                               pin_protection=False,
                                               language='english',
                                               label='test'))

        # Provide entropy
        self.assertIsInstance(ret, proto.EntropyRequest)
        internal_entropy = self.client.debug.read_reset_entropy()
        resp = self.client.call_raw(proto.EntropyAck(entropy=external_entropy))

        # Generate mnemonic locally
        entropy = generate_entropy(strength, internal_entropy, external_entropy)
        expected_mnemonic = Mnemonic('english').to_mnemonic(entropy)

        # Explainer Dialog
        self.assertIsInstance(resp, proto.ButtonRequest)
        self.client.debug.press_yes()
        resp = self.client.call_raw(proto.ButtonAck())

        mnemonic = []
        while isinstance(resp, proto.ButtonRequest):
            mnemonic.append(self.client.debug.read_reset_word())
            if len(mnemonic) == 1:
                # Manual call_raw() flow: bind the report evidence to a word
                # the DebugLink confirms is currently on the device.
                self.client.capture_oled()
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
        self.assertFalse(resp.pin_protection)
        self.assertFalse(resp.passphrase_protection)

        # Do passphrase-protected action, PassphraseRequest should NOT be raised
        resp = self.client.call_raw(proto.Ping(passphrase_protection=True))
        self.assertIsInstance(resp, proto.Success)

        # Do PIN-protected action, PinRequest should NOT be raised
        resp = self.client.call_raw(proto.Ping(pin_protection=True))
        self.assertIsInstance(resp, proto.Success)

    def test_reset_device_dice(self):
        """MIXED dice reset through the host-selected, on-device-consented
        flow: consent, the device's 24 words BEFORE any roll, the rolls, the
        full-digest confirm. The seed is recomputed from the words and rolls
        alone -- the host's EntropyAck bytes must not reach it."""
        self.requires_firmware(self.POST_RC18_SETUP_FIRMWARE)
        self.requires_dice_modes()

        external_entropy = b'zlutoucky kun upel divoke ody' * 2
        strength = 256  # 99 rolls, 24 words

        resp = self.client.call_raw(proto.ResetDevice(display_random=False,
                                                strength=strength,
                                                passphrase_protection=False,
                                                pin_protection=False,
                                                language='english',
                                                label='dice',
                                                dice_entropy=True,
                                                dice_only=False))
        # Consent screen names the mode the host asked for.
        self.assertIsInstance(resp, proto.ButtonRequest)
        self.assertEqual(resp.code, proto_types.ButtonRequest_DiceRoll)
        self.client.capture_oled()
        self.client.debug.press_yes()
        resp = self.client.call_raw(proto.ButtonAck())

        # Device-entropy words, one DiceRoll request per page; the roll screen
        # reads back empty, which ends the pages.
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
        device_words = ' '.join(device_words)

        # Roll entry: ack without blocking, then inject rolls. The pattern is
        # close to uniform so it passes the 30%-per-face bias gate, and stops
        # at the target exactly as dice_input_collect() does.
        self.client.transport.write(proto.ButtonAck())
        time.sleep(0.3)
        chunks = [
            "123456" * 6 + "1234",
            "654321" * 6 + "43u2",
            "1234561234561234561u2u3",
            "612345612345612345612345",
        ]
        rolls = []
        for chunk in chunks:
            for c in chunk:
                if len(rolls) >= 99:
                    break
                if c == 'u':
                    if rolls:
                        rolls.pop()
                else:
                    rolls.append(c)
            self.client.debug.press_input(chunk)
            time.sleep(0.2)
            if len(rolls) >= 99:
                break
        rolls = ''.join(rolls)
        self.assertEqual(len(rolls), 99)

        # Full-digest confirm covers exactly the injected rolls.
        resp = self.client.transport.read_blocking()
        self.assertIsInstance(resp, proto.ButtonRequest)
        self.assertEqual(resp.code, proto_types.ButtonRequest_DiceRoll)
        self.assertEqual(self.client.debug.read_dice_digest(),
                         hashlib.sha256(rolls.encode('ascii')).digest())
        self.client.capture_oled()
        ret = resp
        while isinstance(ret, proto.ButtonRequest):
            self.assertEqual(ret.code, proto_types.ButtonRequest_DiceRoll)
            self.client.debug.press_yes()
            ret = self.client.call_raw(proto.ButtonAck())

        # EntropyRequest is still sent and consumed; its bytes are dropped.
        self.assertIsInstance(ret, proto.EntropyRequest)
        resp = self.client.call_raw(proto.EntropyAck(entropy=external_entropy))
        self.assertIsInstance(resp, proto.ButtonRequest)
        self.client.debug.press_yes()
        resp = self.client.call_raw(proto.ButtonAck())
        mnemonic = []
        while isinstance(resp, proto.ButtonRequest):
            words = self.client.debug.read_reset_word()
            if not mnemonic or mnemonic[-1] != words:
                mnemonic.append(words)
            self.client.debug.press_yes()
            resp = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(resp, proto.Success)

        seed = dice_mixed_seed(bip39_words_to_entropy(device_words), rolls)
        self.assertEqual(' '.join(mnemonic),
                         Mnemonic('english').to_mnemonic(seed[:strength // 8]))

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
        # The single armed-ceremony guard is the post-RC18 #429 behavior.
        self.requires_firmware(self.POST_RC18_SETUP_FIRMWARE)
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

    def test_reset_device_pin(self):
        external_entropy = b'zlutoucky kun upel divoke ody' * 2
        strength = 128

        ret = self.client.call_raw(proto.ResetDevice(display_random=True,
                                               strength=strength,
                                               passphrase_protection=True,
                                               pin_protection=True,
                                               language='english',
                                               label='test'))

        # display_random=True above is deliberate: the field stays in the wire
        # schema for host compatibility. The post-RC18 setup hardening (fw
        # 320f0eb5, "no entropy display"), first shipped on 7.16, stopped
        # honouring it -- internal entropy is seed
        # pre-image material, and a host that sets the flag and reads that
        # screen once can compute SHA256(shown || ext) and derive the seed.
        #
        # Branch on the version rather than skipping the test: everything below
        # (PIN entry, EntropyRequest/Ack, mnemonic derivation) is version-
        # independent and must keep running on older firmware.
        f = self.client.features
        if (f.major_version, f.minor_version, f.patch_version) < (7, 16, 0):
            # RC18 and older: the Internal Entropy screen still exists.
            self.assertIsInstance(ret, proto.ButtonRequest)
            self.client.debug.press_yes()
            ret = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(ret, proto.PinMatrixRequest)

        # Enter PIN for first time
        pin_encoded = self.client.debug.encode_pin('654')
        ret = self.client.call_raw(proto.PinMatrixAck(pin=pin_encoded))
        self.assertIsInstance(ret, proto.PinMatrixRequest)

        # Enter PIN for second time
        pin_encoded = self.client.debug.encode_pin('654')
        ret = self.client.call_raw(proto.PinMatrixAck(pin=pin_encoded))

        # Provide entropy
        self.assertIsInstance(ret, proto.EntropyRequest)
        internal_entropy = self.client.debug.read_reset_entropy()
        resp = self.client.call_raw(proto.EntropyAck(entropy=external_entropy))

        # Generate mnemonic locally
        entropy = generate_entropy(strength, internal_entropy, external_entropy)
        expected_mnemonic = Mnemonic('english').to_mnemonic(entropy)

        # Explainer Dialog
        self.assertIsInstance(resp, proto.ButtonRequest)
        self.client.debug.press_yes()
        resp = self.client.call_raw(proto.ButtonAck())

        mnemonic = []
        while isinstance(resp, proto.ButtonRequest):
            mnemonic.append(self.client.debug.read_reset_word())
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

        ret = self.client.call_raw(proto.ResetDevice(display_random=True,
                                               strength=strength,
                                               passphrase_protection=True,
                                               pin_protection=True,
                                               language='english',
                                               label='test'))

        # display_random=True above is deliberate: the field stays in the wire
        # schema for host compatibility. The post-RC18 setup hardening (fw
        # 320f0eb5, "no entropy display"), first shipped on 7.16, stopped
        # honouring it -- internal entropy is seed
        # pre-image material, and a host that sets the flag and reads that
        # screen once can compute SHA256(shown || ext) and derive the seed.
        #
        # Branch on the version rather than skipping the test: everything below
        # (PIN entry, EntropyRequest/Ack, mnemonic derivation) is version-
        # independent and must keep running on older firmware.
        f = self.client.features
        if (f.major_version, f.minor_version, f.patch_version) < (7, 16, 0):
            # RC18 and older: the Internal Entropy screen still exists.
            self.assertIsInstance(ret, proto.ButtonRequest)
            self.client.debug.press_yes()
            ret = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(ret, proto.PinMatrixRequest)

        # Enter PIN for first time
        pin_encoded = self.client.debug.encode_pin(self.pin4)
        ret = self.client.call_raw(proto.PinMatrixAck(pin=pin_encoded))
        self.assertIsInstance(ret, proto.PinMatrixRequest)

        # Enter PIN for second time
        pin_encoded = self.client.debug.encode_pin(self.pin6)
        ret = self.client.call_raw(proto.PinMatrixAck(pin=pin_encoded))

        self.assertIsInstance(ret, proto.Failure)

    def test_already_initialized(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.assertRaises(Exception, self.client.reset_device, False, 128, True, True, 'label', 'english')

if __name__ == '__main__':
    unittest.main()
