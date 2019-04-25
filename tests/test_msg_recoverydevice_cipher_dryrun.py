# This file is part of the Trezor project.
#
# Copyright (C) 2012-2018 SatoshiLabs and contributors
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
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from __future__ import print_function

import unittest
import common

from keepkeylib import messages_pb2 as proto

class TestDeviceRecoveryDryRun(common.KeepKeyTest):
    def recovery_loop(self, mnemonic, result):
        ret = self.client.call_raw(
            proto.RecoveryDevice(
                word_count=12,
                passphrase_protection=False,
                pin_protection=False,
                label="label",
                language="english",
                enforce_wordlist=True,
                dry_run=True,
                use_character_cipher=True,
            )
        )

        for index, word in enumerate(mnemonic):
            for character in word:
                self.assertIsInstance(ret, proto.CharacterRequest)
                cipher = self.client.debug.read_recovery_cipher()

                encoded_character = cipher[ord(character) - 97]
                ret = self.client.call_raw(proto.CharacterAck(character=encoded_character))

                auto_completed = self.client.debug.read_recovery_auto_completed_word()

                if word == auto_completed:
                    if len(mnemonic) != index + 1:
                        ret = self.client.call_raw(proto.CharacterAck(character=' '))
                    break

        self.assertIsInstance(ret, proto.CharacterRequest)
        ret = self.client.call_raw(proto.CharacterAck(done=True))

        assert isinstance(ret, proto.ButtonRequest)
        self.client.debug.press_yes()

        ret = self.client.call_raw(proto.ButtonAck())
        assert isinstance(ret, result)

    def test_correct_notsame(self):
        self.setup_mnemonic_nopin_nopassphrase()
        mnemonic = ["all"] * 12
        self.recovery_loop(mnemonic, proto.Failure)

    def test_correct_same(self):
        self.setup_mnemonic_nopin_nopassphrase()
        mnemonic = self.mnemonic12.split(" ")
        self.recovery_loop(mnemonic, proto.Success)

    def test_incorrect(self):
        self.setup_mnemonic_nopin_nopassphrase()
        mnemonic = ["stick"] * 12
        self.recovery_loop(mnemonic, proto.Failure)


if __name__ == '__main__':
    unittest.main()
