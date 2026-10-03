# This file is part of the TREZOR project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from __future__ import print_function

import unittest

import common
import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types


class TestAuthenticatorBoundaries(common.KeepKeyTest):
    # 7.15 enforces the RFC-recommended 128-bit minimum for TOTP secrets.
    ADD_ACCOUNT = ('\x15initializeAuth:example:alice:'
                   'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')
    GET_ACCOUNT = '\x17getAccount:0'
    WIPE_ACCOUNTS = '\x19wipeAuthdata:'

    def _auth_ping(self, message):
        return self.client.call(proto.Ping(message=message))

    def _reject_passphrase_and_assert_no_account(self):
        response = self.client.call_raw(proto.Ping(message=self.GET_ACCOUNT))
        self.assertIsInstance(response, proto.PassphraseRequest)

        response = self.client.call_raw(proto.Cancel())
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.code, proto_types.Failure_ActionCancelled)
        self.assertNotIn('example:alice', response.message)

    def test_authorization_loss_drops_cache_and_requires_reauthorization(self):
        self.client.load_device_by_mnemonic(
            mnemonic=self.mnemonic12,
            pin='',
            passphrase_protection=True,
            label='test',
            language='english')
        self.client.set_passphrase('authenticator-wallet')

        # Authenticator storage is encrypted independently from the wallet.
        # Initialize its fingerprint for this passphrase before adding data.
        response = self._auth_ping(self.WIPE_ACCOUNTS)
        self.assertIsInstance(response, proto.Success)
        response = self._auth_ping(self.ADD_ACCOUNT)
        self.assertIsInstance(response, proto.Success)
        self.assertEqual(self._auth_ping(self.GET_ACCOUNT).message,
                         'example:alice')

        authorization_losses = (
            ('ClearSession/lock', lambda: self.client.call(proto.ClearSession())),
            ('Initialize', lambda: self.client.call(proto.Initialize())),
        )

        for name, revoke in authorization_losses:
            response = revoke()
            self.assertIsInstance(response, (proto.Success, proto.Features,
                                             proto.Failure), name)
            self._reject_passphrase_and_assert_no_account()

            # The rejected operation must not have consumed or changed the
            # persistent account. A fresh authorization reloads it from the
            # encrypted storage rather than a stale plaintext cache.
            response = self._auth_ping(self.GET_ACCOUNT)
            self.assertIsInstance(response, proto.Success, name)
            self.assertEqual(response.message, 'example:alice')

    def _reset_accounts(self):
        self.setup_mnemonic_nopin_nopassphrase()
        self.assertIsInstance(self._auth_ping(self.WIPE_ACCOUNTS), proto.Success)
        common.reset_screenshot_capture(self.client)

    def _walk_auth(self, message, reject=None):
        response = self.client.call_raw(proto.Ping(message=message))
        screens = []
        for _ in range(12):
            if not isinstance(response, proto.ButtonRequest):
                return response, screens
            screens.append(self.client.debug.read_confirm_text())
            self.client.capture_oled()
            if len(screens) == reject:
                self.client.debug.press_no()
            else:
                self.client.debug.press_yes()
            response = self.client.call_raw(proto.ButtonAck())
        self.fail('authenticator did not terminate within 12 screens')

    def test_block09_add_reviews_complete_identity_and_secret(self):
        self._reset_accounts()
        secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
        response, screens = self._walk_auth(
            '\x15initializeAuth:abcdefghijk:ABCDEFGHIJK:' + secret)
        self.assertIsInstance(response, proto.Success)
        self.assertFalse(response.HasField('message'))
        self.assertEqual(screens, [
            ('Add Auth Account', 'Domain: abcdefghijk\nAccount: ABCDEFGHIJK'),
            ('TOTP Secret', secret)])
        self.assertEqual(self._auth_ping(self.GET_ACCOUNT).message,
                         'abcdefghijk:ABCDEFGHIJK')

    def test_block09_duplicate_and_cancellation_have_exact_failures(self):
        self._reset_accounts()
        for reject in (1, 2):
            response, screens = self._walk_auth(self.ADD_ACCOUNT, reject=reject)
            self.assertIsInstance(response, proto.Failure)
            self.assertEqual(response.code, proto_types.Failure_ActionCancelled)
            self.assertEqual(response.message, 'Action cancelled')
            self.assertEqual(len(screens), reject)
            missing = self.client.call_raw(proto.Ping(message=self.GET_ACCOUNT))
            self.assertIsInstance(missing, proto.Failure)
            self.assertEqual(missing.message, 'Account not found')
        response, screens = self._walk_auth(self.ADD_ACCOUNT)
        self.assertIsInstance(response, proto.Success)
        self.assertEqual(len(screens), 2)
        # No Initialize or reload between refusal and retry or duplicate.
        duplicate = self.client.call_raw(proto.Ping(message=self.ADD_ACCOUNT))
        self.assertIsInstance(duplicate, proto.Failure)
        self.assertEqual(duplicate.message, 'Authenticator account already exists')
        self.assertEqual(self._auth_ping(self.GET_ACCOUNT).message, 'example:alice')

    def test_block09_invalid_identity_and_secret_fail_before_buttons(self):
        self._reset_accounts()
        secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
        credentials = [
            ':alice:' + secret, 'example::' + secret,
            '::example:alice:' + secret, 'exam\nple:alice:' + secret,
            'example:ali\tce:' + secret, 'example:\u00e9:' + secret,
            'abcdefghijkl:alice:' + secret, 'example:abcdefghijkl:' + secret,
            'example:alice:' + 'A' * 25, 'example:alice:' + 'A' * 34,
            'example:alice:' + '!' * 32,
        ]
        for credential in credentials:
            with self.subTest(credential=credential):
                response = self.client.call_raw(proto.Ping(
                    message='\x15initializeAuth:' + credential))
                self.assertIsInstance(response, proto.Failure)
                self.assertEqual(response.code, proto_types.Failure_ActionCancelled)
        response, _ = self._walk_auth(
            '\x15initializeAuth:abcdefghijk:ABCDEFGHIJK:' + 'A' * 26)
        self.assertIsInstance(response, proto.Success)
        for request in (
                '\x16generateOTPFrom:abcdefghijkX:ABCDEFGHIJK:1:30',
                '\x16generateOTPFrom:abcdefghijk:ABCDEFGHIJKX:1:30',
                '\x16generateOTPFrom::abcdefghijk:ABCDEFGHIJK:1:30',
                '\x18removeAccount::abcdefghijk:ABCDEFGHIJK',
                '\x18removeAccount:abcdefghijk:ABCDEFGHIJKX',
                '\x16generateOTPFrom:abcdefghijk:ABCDEFGHIJK:+1:30',
                '\x16generateOTPFrom:abcdefghijk:ABCDEFGHIJK:1:31',
                '\x16generateOTPFrom:abcdefghijk:ABCDEFGHIJK:1:30junk',
                '\x16generateOTPFrom:abcdefghijk:ABCDEFGHIJK:4294967296:30'):
            response = self.client.call_raw(proto.Ping(message=request))
            self.assertIsInstance(response, proto.Failure)
        self.assertEqual(self._auth_ping(self.GET_ACCOUNT).message,
                         'abcdefghijk:ABCDEFGHIJK')

    def test_block09_delete_decline_preserves_account_then_retry_removes(self):
        self._reset_accounts()
        response, _ = self._walk_auth(self.ADD_ACCOUNT)
        self.assertIsInstance(response, proto.Success)
        request = '\x18removeAccount:example:alice'
        response, screens = self._walk_auth(request, reject=1)
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.message, 'Action cancelled')
        self.assertEqual(len(screens), 1)
        self.assertEqual(self._auth_ping(self.GET_ACCOUNT).message, 'example:alice')
        response, screens = self._walk_auth(request)
        self.assertIsInstance(response, proto.Success)
        self.assertEqual(len(screens), 1)
        missing = self.client.call_raw(proto.Ping(message=self.GET_ACCOUNT))
        self.assertIsInstance(missing, proto.Failure)
        self.assertEqual(missing.message, 'Account not found')


if __name__ == '__main__':
    unittest.main()
