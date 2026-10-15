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

    def test_entropy(self):
        self.requires_release_capability("entropy-audit-budget")
        if os.getenv("KK_EXPECT_ENTROPY_BUDGET") != "1":
            self.requires_firmware("7.14.3")
        # Entropy is a bounded nanopb response (1024 bytes on every supported
        # release). Collect 64 KiB for the health sample, then consume the
        # complete consent-based 8 MiB grant in wire-valid chunks.
        chunk_size = 1024
        chunk_count = 64
        grant_bytes = 8 * 1024 * 1024
        # 7.15 advertises an initial 64 KiB press-free budget. 7.14.3 requires
        # approval immediately; both then use consent-based 8 MiB grants.
        initial_press_free = self.firmware_at_least("7.15.0")

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
        # confirmed locked request above does not acquire an audit grant.
        self.client.wipe_device()

        samples = []
        for i in range(chunk_count):
            with self.client:
                expected = [proto.Entropy()]
                if i == 0 and not initial_press_free:
                    expected.insert(0, proto.ButtonRequest(
                        code=proto_types.ButtonRequest_GetEntropy))
                self.client.set_expected_responses(expected)
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

        if initial_press_free:
            # The initial 64 KiB is exhausted. Approval now acquires the
            # separate 8 MiB grant, and this request consumes its first chunk.
            with self.client:
                self.client.set_expected_responses([
                    proto.ButtonRequest(code=proto_types.ButtonRequest_GetEntropy),
                    proto.Entropy(),
                ])
                acquired = self.client.get_entropy(chunk_size)
            self.assertEqual(len(acquired), chunk_size)
            grant_consumed = chunk_size
        else:
            # The health sample already consumed part of the first grant.
            grant_consumed = chunk_count * chunk_size

        for _ in range((grant_bytes - grant_consumed) // chunk_size):
            with self.client:
                self.client.set_expected_responses([proto.Entropy()])
                sample = self.client.get_entropy(chunk_size)
            self.assertEqual(len(sample), chunk_size)

        # Exhaustion requires a fresh approval and starts the next grant.
        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=proto_types.ButtonRequest_GetEntropy),
                proto.Entropy(),
            ])
            after_budget = self.client.get_entropy(chunk_size)
        self.assertEqual(len(after_budget), chunk_size)

if __name__ == '__main__':
    unittest.main()
