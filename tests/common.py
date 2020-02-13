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

from __future__ import print_function

import unittest
import config
import time
import semver
import os

from keepkeylib.client import KeepKeyClient, KeepKeyDebuglinkClient, KeepKeyDebuglinkClientVerbose
from keepkeylib import tx_api

cur_dir = os.path.dirname(os.path.realpath(__file__))
tx_api.cache_dir = os.path.join(cur_dir, 'txcache')

VERBOSE = os.environ.get('VERBOSE', False)

class KeepKeyTest(unittest.TestCase):
    def setUp(self):
        transport = config.TRANSPORT(*config.TRANSPORT_ARGS, **config.TRANSPORT_KWARGS)
        if hasattr(config, 'DEBUG_TRANSPORT'):
            debug_transport = config.DEBUG_TRANSPORT(*config.DEBUG_TRANSPORT_ARGS, **config.DEBUG_TRANSPORT_KWARGS)
            if VERBOSE:
                self.client = KeepKeyDebuglinkClientVerbose(transport)
            else:
                self.client = KeepKeyDebuglinkClient(transport)
            self.client.set_debuglink(debug_transport)
        else:
            self.client = KeepKeyClient(transport)
        self.client.set_tx_api(tx_api.TxApiBitcoin)
        # self.client.set_buttonwait(3)

        #                     1      2     3    4      5      6      7     8      9    10    11    12
        self.mnemonic12 = 'alcohol woman abuse must during monitor noble actual mixed trade anger aisle'
        self.mnemonic18 = 'owner little vague addict embark decide pink prosper true fork panda embody mixture exchange choose canoe electric jewel'
        self.mnemonic24 = 'dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic'
        self.mnemonic_all = ' '.join(['all'] * 12)
        self.mnemonic_abandon = ' '.join(['abandon'] * 11) + ' about'

        self.pin4 = '1234'
        self.pin6 = '789456'
        self.pin8 = '45678978'

        self.client.wipe_device()

        if VERBOSE:
            print("Setup finished")
            print("--------------")

    def setup_mnemonic_allallall(self):
        self.client.load_device_by_mnemonic(mnemonic=self.mnemonic_all, pin='', passphrase_protection=False, label='test', language='english')

    def setup_mnemonic_abandon(self):
        self.client.load_device_by_mnemonic(mnemonic=self.mnemonic_abandon, pin='', passphrase_protection=False, label='test', language='english')

    def setup_mnemonic_nopin_nopassphrase(self):
        self.client.load_device_by_mnemonic(mnemonic=self.mnemonic12, pin='', passphrase_protection=False, label='test', language='english')

    def setup_mnemonic_pin_nopassphrase(self):
        self.client.load_device_by_mnemonic(mnemonic=self.mnemonic12, pin=self.pin4, passphrase_protection=False, label='test', language='english')

    def setup_mnemonic_pin_passphrase(self):
        self.client.load_device_by_mnemonic(mnemonic=self.mnemonic12, pin=self.pin4, passphrase_protection=True, label='test', language='english')

    def tearDown(self):
        self.client.close()

    def assertEqual(self, lhs, rhs):
        if type(lhs) == type(b'') and type(rhs) == type(''):
            super(KeepKeyTest, self).assertEqual(lhs, rhs.encode('utf-8'))
        else:
            super(KeepKeyTest, self).assertEqual(lhs, rhs)

    def assertEndsWith(self, s, suffix):
        self.assertTrue(s.endswith(suffix), "'{}'.endswith('{}')".format(s, suffix))

    def requires_firmware(self, ver_required):
        self.client.init_device()
        features = self.client.features
        version = "%s.%s.%s" % (features.major_version, features.minor_version, features.patch_version)
        if semver.compare(version, ver_required) < 0:
            self.skipTest("Firmware version " + ver_required + " or higher is required to run this test")

