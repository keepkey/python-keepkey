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


if __name__ == '__main__':
    unittest.main()
