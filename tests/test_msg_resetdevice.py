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
        self.requires_firmware("7.15.0")

        external_entropy = b'zlutoucky kun upel divoke ody' * 2
        strength = 256  # 99 rolls

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
        """An aborted reset must not leave EntropyAck armed.

        Regression: reset_init aborts (dice cancel, PIN mismatch, ...) left
        awaiting_entropy set from an earlier run while zeroing int_entropy,
        so a following EntropyAck derived the seed from
        sha256(0*32 || host_bytes) -- entirely host-chosen.
        """
        self.requires_firmware("7.15.0")
        self.client.wipe_device()

        # Arm a reset and walk away without acking the entropy request.
        ret = self.client.call_raw(proto.ResetDevice(display_random=False,
                                               strength=256,
                                               passphrase_protection=False,
                                               pin_protection=False,
                                               language='english',
                                               label='first'))
        self.assertIsInstance(ret, proto.EntropyRequest)

        # Re-enter with dice, then abort from the host.
        ret = self.client.call_raw(proto.ResetDevice(display_random=False,
                                               strength=256,
                                               passphrase_protection=False,
                                               pin_protection=False,
                                               language='english',
                                               label='second',
                                               dice_entropy=True))
        self.assertIsInstance(ret, proto.ButtonRequest)
        self.assertEqual(ret.code, proto_types.ButtonRequest_DiceRoll)
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
