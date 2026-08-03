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

import os
import unittest
import common
from collections import Counter

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types

class TestMsgGetentropy(common.KeepKeyTest):

    @unittest.skipUnless(
        os.getenv('KK_EXPECT_ENTROPY_BUDGET') == '1',
        'requires the RC23 entropy audit budget policy')
    def test_entropy(self):
        chunk_size = 8192
        chunk_count = 8

        # A fresh budget must not make raw RNG output silently available from
        # an initialized, PIN-protected, locked device.  Confirm one request in
        # that state before spending any of the press-free budget.
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()
        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_GetEntropy),
                proto.Entropy(),
            ])
            locked_sample = self.client.get_entropy(chunk_size)
        self.assertEqual(len(locked_sample), chunk_size)

        # Wiping returns the device to the uninitialized audit state.  The
        # confirmed locked request above does not consume the fresh budget.
        self.client.wipe_device()

        samples = []
        for _ in range(chunk_count):
            with self.client:
                self.client.set_expected_responses([proto.Entropy()])
                sample = self.client.get_entropy(chunk_size)
            self.assertEqual(len(sample), chunk_size)
            samples.append(sample)

        self.assertEqual(sum(len(sample) for sample in samples), 64 * 1024)
        self.assertEqual(len(set(samples)), chunk_count)

        # Deliberately broad catastrophic-failure checks, not a statistical
        # certification of the hardware RNG.  They catch a stuck/constant or
        # grossly biased source without imposing a fragile quality threshold.
        combined = b''.join(samples)
        counts = Counter(combined)
        self.assertGreaterEqual(len(counts), 200)
        self.assertLess(max(counts.values()), len(combined) // 20)
        one_bits = sum(bin(value).count('1') for value in combined)
        one_ratio = float(one_bits) / (8 * len(combined))
        self.assertGreater(one_ratio, 0.40)
        self.assertLess(one_ratio, 0.60)

        # Exactly 64 KiB was press-free.  The next request must restore the
        # original confirmation flow and still return the requested length
        # after the debug-link approval.
        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_GetEntropy),
                proto.Entropy(),
            ])
            after_budget = self.client.get_entropy(chunk_size)
        self.assertEqual(len(after_budget), chunk_size)

if __name__ == '__main__':
    unittest.main()
