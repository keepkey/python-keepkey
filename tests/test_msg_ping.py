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
from keepkeylib import types_pb2 as proto_types

class TestPing(common.KeepKeyTest):

    def test_ping(self):
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()

        with self.client:
            self.client.set_expected_responses([proto.Success()])
            res = self.client.ping('random data')
            self.assertEqual(res, 'random data')

        with self.client:
            self.client.set_expected_responses([proto.ButtonRequest(code=proto_types.ButtonRequest_Ping), proto.Success()])
            res = self.client.ping('random data', button_protection=True)
            self.assertEqual(res, 'random data')

        with self.client:
            self.client.set_expected_responses([proto.PinMatrixRequest(), proto.Success()])
            res = self.client.ping('random data', pin_protection=True)
            self.assertEqual(res, 'random data')

        with self.client:
            self.client.set_expected_responses([
                proto.PassphraseRequest(), 
                proto.ButtonRequest(code=proto_types.ButtonRequest_Other), 
                proto.Success()
                ])
            res = self.client.ping('random data', passphrase_protection=True)
            self.assertEqual(res, 'random data')

    def test_ping_long_body_is_paged(self):
        """A body that will not fit one screen must be shown across several.

        Before 7.14.2 the device drew what fitted and stopped: no ellipsis, no
        warning, nothing to tell the user the tail of an address or an amount
        had been dropped. A warning screen was then added that said "Hold to
        view it anyway" and re-drew the SAME clipped body, which is worse --
        it claims a disclosure it does not make.

        Now the body is paged, and the titles carry n/m. This test exists so
        those pages are CAPTURED: the screens are the evidence, and until this
        test existed no suite with an over-long body was in the screenshot set,
        so the pager's own rendering appeared nowhere in CI.

        The press DURATIONS -- click to page, hold to approve -- are not
        assertable here. The emulator has no physical button; that half needs
        hardware.
        """
        self.requires_firmware("7.14.2")
        self.setup_mnemonic_nopin_nopassphrase()

        # Digit ramp: the Nth character is str(N % 10), so a dropped or
        # repeated character at a page seam is visible by inspection.
        body = ''.join(str(i % 10) for i in range(255))
        res = self.client.ping(body, button_protection=True)
        self.assertEqual(res, body)

    def test_ping_short_body_is_not_paged(self):
        """The control for the test above.

        A body that fits must still take exactly one screen with an unnumbered
        title. Without this, a pager that numbered every confirmation -- making
        ordinary approvals cost two presses -- would pass unnoticed.
        """
        self.requires_firmware("7.14.2")
        self.setup_mnemonic_nopin_nopassphrase()

        body = ''.join(str(i % 10) for i in range(100))
        res = self.client.ping(body, button_protection=True)
        self.assertEqual(res, body)

    def test_ping_format_specifier_sanitize(self):
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()
        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_Ping), 
                proto.PinMatrixRequest(), 
                proto.PassphraseRequest(), 
                proto.ButtonRequest(code=proto_types.ButtonRequest_Other), 
                proto.Success()
                ])
            res = self.client.ping('%s%x%n%p', button_protection=True, pin_protection=True, passphrase_protection=True)
            self.assertEqual(res, '%s%x%n%p')

    def test_ping_caching(self):
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()

        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_Ping), 
                proto.PinMatrixRequest(), 
                proto.PassphraseRequest(), 
                proto.ButtonRequest(code=proto_types.ButtonRequest_Other), 
                proto.Success()
                ])
            res = self.client.ping('random data', button_protection=True, pin_protection=True, passphrase_protection=True)
            self.assertEqual(res, 'random data')

        with self.client:
            # pin and passphrase are cached
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_Ping), 
                proto.Success()])
            res = self.client.ping('random data', button_protection=True, pin_protection=True, passphrase_protection=True)
            self.assertEqual(res, 'random data')

    def test_authenticator_passphrase_cancel_is_terminal(self):
        """Cancelling auth unlock must not fall through to cached auth data."""
        self.requires_firmware("7.14.2")
        self.setup_mnemonic_pin_passphrase()

        # Populate both persistent auth storage and the firmware's decrypted
        # local cache. This is the precondition that made the stale-data path
        # reachable after ClearSession.
        self.client.ping('\x19wipeAuthdata:')
        init_auth = ('\x15initializeAuth:example.com:alice:'
                     'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')
        self.client.ping(init_auth)
        self.client.clear_session()
        # The wipe/add-account confirmations establish the stale-cache
        # precondition; they are not evidence for the cancellation boundary.
        # Retain only the randomized PIN grid reached by the operation under
        # test. Passphrase entry and terminal cancellation are host/wire state.
        common.reset_screenshot_capture(self.client)

        resp = self.client.call_raw(proto.Ping(message='\x17getAccount:0'))
        self.assertIsInstance(resp, proto.PinMatrixRequest)
        resp = self.client.call_raw(self.client.callback_PinMatrixRequest(resp))
        self.assertIsInstance(resp, proto.PassphraseRequest)
        resp = self.client.call_raw(proto.Cancel())
        self.assertIsInstance(resp, proto.Failure)
        self.assertEqual(resp.code, proto_types.Failure_ActionCancelled)

        # Before the fix fsm_msgPing continued after the Failure and queued a
        # Success carrying the cached account. The next request would receive
        # that stale Success instead of its own response.
        resp = self.client.call_raw(proto.Initialize())
        self.assertIsInstance(resp, proto.Features)

if __name__ == '__main__':
    unittest.main()
