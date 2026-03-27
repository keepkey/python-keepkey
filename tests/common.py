# This file is part of the TREZOR project.
#
# Copyright (C) 2022 markrypto
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
import os
import semver

from keepkeylib.client import KeepKeyClient, KeepKeyDebuglinkClient, KeepKeyDebuglinkClientVerbose
from keepkeylib import tx_api

tx_api.cache_dir = 'txcache'
VERBOSE = False

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

        # Per-test screenshot directory (unittest runner — conftest.py handles pytest)
        if os.environ.get('KEEPKEY_SCREENSHOT') == '1':
            test_id = self.id()
            parts = test_id.split('.')
            test_name = parts[-1] if parts else 'unknown'
            mod = 'unknown'
            for p in parts:
                if p.startswith('test_msg_') or p.startswith('test_sign_') or p.startswith('test_verify_'):
                    mod = p.replace('test_', '', 1)
                    break
            sdir = os.path.join(os.environ.get('SCREENSHOT_DIR', 'screenshots'), mod, test_name)
            os.makedirs(sdir, exist_ok=True)
            self.client.screenshot_dir = sdir
            self.client.screenshot_id = 0

        #                     1      2     3    4      5      6      7     8      9    10    11    12
        self.mnemonic12 = 'alcohol woman abuse must during monitor noble actual mixed trade anger aisle'
        self.mnemonic18 = 'owner little vague addict embark decide pink prosper true fork panda embody mixture exchange choose canoe electric jewel'
        self.mnemonic24 = 'dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic'
        self.mnemonic20007 = 'fix spot clown mobile oven eagle pond arrest opera buyer muffin myself'
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

    def setup_mnemonic_vuln20007(self):
        self.client.load_device_by_mnemonic(mnemonic=self.mnemonic20007, pin='', passphrase_protection=False, label='test', language='english')

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
        if semver.VersionInfo.parse(version) < semver.VersionInfo.parse(ver_required):
            self.skipTest("Firmware version " + ver_required + " or higher is required to run this test")

    def requires_message(self, msg_name):
        """Skip if firmware does not handle this message type.
        Use alongside requires_firmware for per-feature gating:
          self.requires_firmware("7.14.0")
          self.requires_message("ZcashGetOrchardFVK")
        """
        # Check all pb2 modules — message classes live in chain-specific pb2 files,
        # not just messages_pb2 (which only has the MessageType enum values).
        import keepkeylib
        proto = None
        for mod_name in dir(keepkeylib):
            if mod_name.endswith('_pb2'):
                mod = getattr(keepkeylib, mod_name, None)
                if mod and hasattr(mod, msg_name):
                    proto = mod
                    break
        if proto is None:
            # Fallback: try importing chain-specific modules directly
            for suffix in ['solana', 'tron', 'ton', 'zcash', 'ethereum', '']:
                try:
                    mod_path = 'messages_%s_pb2' % suffix if suffix else 'messages_pb2'
                    mod = __import__('keepkeylib.%s' % mod_path, fromlist=[msg_name])
                    if hasattr(mod, msg_name):
                        proto = mod
                        break
                except ImportError:
                    continue
        if proto is None or not hasattr(proto, msg_name):
            self.skipTest("%s proto message not available" % msg_name)
        # Send a minimal probe — if firmware returns Failure_UnexpectedMessage, skip
        from keepkeylib import messages_pb2 as base_proto
        msg = getattr(proto, msg_name)()
        try:
            resp = self.client.call_raw(msg)
            if hasattr(resp, 'code') and resp.code == 1:  # Failure_UnexpectedMessage
                self.skipTest("%s not supported by this firmware build" % msg_name)
            # Re-init device state after probe (some messages may have changed state)
            self.client.call_raw(base_proto.Initialize())
        except Exception:
            self.skipTest("%s not supported by this firmware build" % msg_name)

    def requires_fullFeature(self):
      if self.client.features.firmware_variant == "KeepKeyBTC" or \
            self.client.features.firmware_variant == "EmulatorBTC":
        self.skipTest("Full feature firmware required to run this test")

            

