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

from keepkeylib import messages_pb2 as proto

class TestDeviceRecovery(common.KeepKeyTest):
    def test_pin_passphrase(self):
        mnemonic = self.mnemonic12
        ret = self.client.call_raw(proto.RecoveryDevice(word_count=12,
                                   passphrase_protection=True,
                                   pin_protection=True,
                                   label='label',
                                   language='english',
                                   enforce_wordlist=True,
                                   use_character_cipher=True))

        self.assertIsInstance(ret, proto.PinMatrixRequest)

        # Enter PIN for first time
        pin_encoded = self.client.debug.encode_pin(self.pin6)
        ret = self.client.call_raw(proto.PinMatrixAck(pin=pin_encoded))
        self.assertIsInstance(ret, proto.PinMatrixRequest)

        # Enter PIN for second time
        pin_encoded = self.client.debug.encode_pin(self.pin6)
        ret = self.client.call_raw(proto.PinMatrixAck(pin=pin_encoded))

        mnemonic_words = mnemonic.split(' ')

        for index, word in enumerate(mnemonic_words):
            for character in word:
                self.assertIsInstance(ret, proto.CharacterRequest)
                cipher = self.client.debug.read_recovery_cipher()

                encoded_character = cipher[ord(character) - 97]
                ret = self.client.call_raw(proto.CharacterAck(character=encoded_character))

                auto_completed = self.client.debug.read_recovery_auto_completed_word()

                if word == auto_completed:
                    if len(mnemonic_words) != index + 1:
                        ret = self.client.call_raw(proto.CharacterAck(character=' '))
                    break

        # Send final ack
        self.assertIsInstance(ret, proto.CharacterRequest)
        ret = self.client.call_raw(proto.CharacterAck(done=True))

        # Workflow succesfully ended
        self.assertIsInstance(ret, proto.Success)

        # Mnemonic is the same
        self.client.init_device()
        self.assertEqual(self.client.debug.read_mnemonic(), self.mnemonic12)

        self.assertTrue(self.client.features.pin_protection)
        self.assertTrue(self.client.features.passphrase_protection)

        # Do passphrase-protected action, PassphraseRequest should be raised
        resp = self.client.call_raw(proto.Ping(passphrase_protection=True))
        self.assertIsInstance(resp, proto.PassphraseRequest)
        self.client.call_raw(proto.Cancel())

        self.client.clear_session()

        # Do PIN-protected action, PinRequest should be raised
        resp = self.client.call_raw(proto.Ping(pin_protection=True))
        self.assertIsInstance(resp, proto.PinMatrixRequest)
        self.client.call_raw(proto.Cancel())

    def test_nopin_nopassphrase(self):
        mnemonic = self.mnemonic12
        ret = self.client.call_raw(proto.RecoveryDevice(word_count=12,
                                   passphrase_protection=False,
                                   pin_protection=False,
                                   label='label',
                                   language='english',
                                   enforce_wordlist=True,
                                   use_character_cipher=True))

        mnemonic_words = mnemonic.split(' ')

        for index, word in enumerate(mnemonic_words):
            for character in word:
                self.assertIsInstance(ret, proto.CharacterRequest)
                cipher = self.client.debug.read_recovery_cipher()

                encoded_character = cipher[ord(character) - 97]
                ret = self.client.call_raw(proto.CharacterAck(character=encoded_character))

                auto_completed = self.client.debug.read_recovery_auto_completed_word()

                if word == auto_completed:
                    if len(mnemonic_words) != index + 1:
                        ret = self.client.call_raw(proto.CharacterAck(character=' '))
                    break

        # Send final ack
        self.assertIsInstance(ret, proto.CharacterRequest)
        ret = self.client.call_raw(proto.CharacterAck(done=True))

        # Workflow succesfully ended
        self.assertIsInstance(ret, proto.Success)

        # Mnemonic is the same
        self.client.init_device()
        self.assertEqual(self.client.debug.read_mnemonic(), self.mnemonic12)

        self.assertFalse(self.client.features.pin_protection)
        self.assertFalse(self.client.features.passphrase_protection)

        # Do passphrase-protected action, PassphraseRequest should NOT be raised
        resp = self.client.call_raw(proto.Ping(passphrase_protection=True))
        self.assertIsInstance(resp, proto.Success)

        # Do PIN-protected action, PinRequest should NOT be raised
        resp = self.client.call_raw(proto.Ping(pin_protection=True))
        self.assertIsInstance(resp, proto.Success)

    def test_character_fail(self):
        ret = self.client.call_raw(proto.RecoveryDevice(word_count=12,
                                   passphrase_protection=False,
                                   pin_protection=False,
                                   label='label',
                                   language='english',
                                   enforce_wordlist=True,
                                   use_character_cipher=True))

        self.assertIsInstance(ret, proto.CharacterRequest)
        ret = self.client.call_raw(proto.CharacterAck(character='1'))
        self.assertIsInstance(ret, proto.Failure)

    def test_backspace(self):
        mnemonic = self.mnemonic12
        ret = self.client.call_raw(proto.RecoveryDevice(word_count=12,
                                   passphrase_protection=False,
                                   pin_protection=False,
                                   label='label',
                                   language='english',
                                   enforce_wordlist=True,
                                   use_character_cipher=True))

        mnemonic_words = mnemonic.split(' ')

        for index, word in enumerate(mnemonic_words):
            for character in word:
                self.assertIsInstance(ret, proto.CharacterRequest)
                cipher = self.client.debug.read_recovery_cipher()

                encoded_character = cipher[ord(character) - 97]
                ret = self.client.call_raw(proto.CharacterAck(character=encoded_character))

                auto_completed = self.client.debug.read_recovery_auto_completed_word()

                if word == auto_completed:
                    if len(mnemonic_words) != index + 1:
                        ret = self.client.call_raw(proto.CharacterAck(character=' '))
                    break


        for character in mnemonic:
            self.assertIsInstance(ret, proto.CharacterRequest)
            ret = self.client.call_raw(proto.CharacterAck(delete=True))

        for index, word in enumerate(mnemonic_words):
            for character in word:
                self.assertIsInstance(ret, proto.CharacterRequest)
                cipher = self.client.debug.read_recovery_cipher()

                encoded_character = cipher[ord(character) - 97]
                ret = self.client.call_raw(proto.CharacterAck(character=encoded_character))

                auto_completed = self.client.debug.read_recovery_auto_completed_word()

                if word == auto_completed:
                    if len(mnemonic_words) != index + 1:
                        ret = self.client.call_raw(proto.CharacterAck(character=' '))
                    break

        # Send final ack
        self.assertIsInstance(ret, proto.CharacterRequest)
        ret = self.client.call_raw(proto.CharacterAck(done=True))

        # Workflow succesfully ended
        self.assertIsInstance(ret, proto.Success)

        # Mnemonic is the same
        self.client.init_device()
        self.assertEqual(self.client.debug.read_mnemonic(), self.mnemonic12)

        self.assertFalse(self.client.features.pin_protection)
        self.assertFalse(self.client.features.passphrase_protection)

        # Do passphrase-protected action, PassphraseRequest should NOT be raised
        resp = self.client.call_raw(proto.Ping(passphrase_protection=True))
        self.assertIsInstance(resp, proto.Success)

        # Do PIN-protected action, PinRequest should NOT be raised
        resp = self.client.call_raw(proto.Ping(pin_protection=True))
        self.assertIsInstance(resp, proto.Success)

    def test_reset_and_recover(self):
        for strength in (128, 192, 256):
            external_entropy = self.client._get_local_entropy()

            ret = self.client.call_raw(proto.ResetDevice(display_random=False,
                                                strength=strength,
                                                passphrase_protection=False,
                                                pin_protection=False,
                                                language='english',
                                                label='test'))

            # Provide entropy
            self.assertIsInstance(ret, proto.EntropyRequest)
            resp = self.client.call_raw(proto.EntropyAck(entropy=external_entropy))

            mnemonic = []
            while isinstance(resp, proto.ButtonRequest):
                mnemonic.append(self.client.debug.read_reset_word())
                self.client.debug.press_yes()
                resp = self.client.call_raw(proto.ButtonAck())

            mnemonic = ' '.join(mnemonic)

            # wipe device
            ret = self.client.call_raw(proto.WipeDevice())
            self.client.debug.press_yes()
            ret = self.client.call_raw(proto.ButtonAck())

            # recover devce
            ret = self.client.call_raw(proto.RecoveryDevice(word_count=(strength/32*3),
                                   passphrase_protection=False,
                                   pin_protection=False,
                                   label='label',
                                   language='english',
                                   enforce_wordlist=True,
                                   use_character_cipher=True))

            mnemonic_words = mnemonic.split(' ')

            for index, word in enumerate(mnemonic_words):
                for character in word:
                    self.assertIsInstance(ret, proto.CharacterRequest)
                    cipher = self.client.debug.read_recovery_cipher()

                    encoded_character = cipher[ord(character) - 97]
                    ret = self.client.call_raw(proto.CharacterAck(character=encoded_character))

                    auto_completed = self.client.debug.read_recovery_auto_completed_word()

                    if word == auto_completed:
                        if len(mnemonic_words) != index + 1:
                            ret = self.client.call_raw(proto.CharacterAck(character=' '))
                        break

            # Send final ack
            self.assertIsInstance(ret, proto.CharacterRequest)
            ret = self.client.call_raw(proto.CharacterAck(done=True))

            # Workflow succesfully ended
            self.assertIsInstance(ret, proto.Success)

            self.client.init_device()
            self.assertEqual(self.client.debug.read_mnemonic(), mnemonic)

            # wipe device
            ret = self.client.call_raw(proto.WipeDevice())
            self.client.debug.press_yes()
            ret = self.client.call_raw(proto.ButtonAck())

if __name__ == '__main__':
    unittest.main()
