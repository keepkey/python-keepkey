# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""A segwit-v0 signature commits to one input's amount only, and the device
takes those amounts from the host. A host can therefore ask twice for the
same payment over the same two coins, tell the truth about a different coin
each time, and keep one valid signature from each: together they spend both
coins, and the difference from what the screens said goes to the fee.

The device remembers the last payment it approved. The same payment over the
same coins with different claimed amounts is refused.
"""

import unittest

import common

from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

COIN_A = bytes.fromhex(
    "20912f98ea3ed849042efed0fdac8cb4fc301961c5988cba56902d8ffb61c337")
COIN_B = bytes.fromhex(
    "e5040e1bc1ae7667ffb9e5248e90b2fb93cd9150234151ce90e14ab2f5933bcd")
PAYMENT = 2000000000


class TestMsgSigntxSegwitAmountSwap(common.KeepKeyTest):

    def _sign(self, amount_a, amount_b):
        inputs = [
            proto_types.TxInputType(
                address_n=parse_path("84'/1'/0'/0/0"), amount=amount_a,
                prev_hash=COIN_A, prev_index=0,
                script_type=proto_types.SPENDWITNESS),
            proto_types.TxInputType(
                address_n=parse_path("84'/1'/0'/0/1"), amount=amount_b,
                prev_hash=COIN_B, prev_index=1,
                script_type=proto_types.SPENDWITNESS),
        ]
        outputs = [proto_types.TxOutputType(
            address='mhRx1CeVfaayqRwq5zgRQmD7W5aWBfD5mC', amount=PAYMENT,
            script_type=proto_types.PAYTOADDRESS)]
        return self.client.sign_tx('Testnet', inputs, outputs)

    def test_same_payment_with_swapped_input_amounts_is_refused(self):
        self.requires_firmware("7.14.3")
        self.setup_mnemonic_allallall()

        # Coin A really holds 15 BTC and coin B 20. First the host is honest
        # about A and understates B so the fee reads as one satoshi.
        self._sign(1500000000, 500000001)

        # Asking again with the same claims is an ordinary retry.
        self._sign(1500000000, 500000001)

        # Now honest about B, understating A. The screens would be the same
        # payment with the same one-satoshi fee.
        with self.assertRaises(CallException):
            self._sign(1, 2000000000)


if __name__ == '__main__':
    unittest.main()
