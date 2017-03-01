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

from keepkeylib import messages_pb2 as proto

class TestMsgApplysettings(common.KeepKeyTest):

    def test_apply_settings(self):
        self.setup_mnemonic_pin_passphrase()
        self.assertEqual(self.client.features.label, 'test')

        with self.client:
            self.client.set_expected_responses([proto.ButtonRequest(),
                                                proto.Success(),
                                                proto.Features()])
            self.client.apply_settings(label='new label')

        self.assertEqual(self.client.features.label, 'new label')

    def test_invalid_language(self):
        self.setup_mnemonic_pin_passphrase()
        self.assertEqual(self.client.features.language, 'english')

        with self.client:
            self.client.set_expected_responses([proto.ButtonRequest(),
                                                proto.Success(),
                                                proto.Features()])
            self.client.apply_settings(language='nonexistent')

        self.assertEqual(self.client.features.language, 'english')

    def test_apply_settings_passphrase(self):
        self.setup_mnemonic_pin_nopassphrase()

        self.assertEqual(self.client.features.passphrase_protection, False)

        with self.client:
            self.client.set_expected_responses([proto.ButtonRequest(),
                                                proto.Success(),
                                                proto.Features()])
            self.client.apply_settings(use_passphrase=True)

        self.assertEqual(self.client.features.passphrase_protection, True)

        with self.client:
            self.client.set_expected_responses([proto.ButtonRequest(),
                                                proto.Success(),
                                                proto.Features()])
            self.client.apply_settings(use_passphrase=False)

        self.assertEqual(self.client.features.passphrase_protection, False)

        with self.client:
            self.client.set_expected_responses([proto.ButtonRequest(),
                                                proto.Success(),
                                                proto.Features()])
            self.client.apply_settings(use_passphrase=True)

        self.assertEqual(self.client.features.passphrase_protection, True)

if __name__ == '__main__':
    unittest.main()
