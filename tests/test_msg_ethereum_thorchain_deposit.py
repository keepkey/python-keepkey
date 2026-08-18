# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Test coverage for THORChain EVM depositWithExpiry() selector recognition.
# The legacy deposit() selector (0x1fece7b4) was already handled; firmware
# 7.14.2 adds recognition of the modern depositWithExpiry() selector (0x44bc937b).

import unittest
import common
import binascii

import keepkeylib.messages_pb2 as proto
from keepkeylib.tools import parse_path


THOR_ROUTER = "d37bbe5744d730a1d98d8dc97c42f0ca46ad7146"  # ETH THORChain router
ETH_NATIVE  = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"  # sentinel for native ETH


def _build_deposit_calldata(memo):
    """Build deposit(address,address,uint256,string) calldata (legacy selector)."""
    selector    = bytes.fromhex("1fece7b4")
    vault       = bytes(12) + bytes.fromhex(THOR_ROUTER)
    asset       = bytes(12) + bytes.fromhex(ETH_NATIVE)
    amount      = (500000000000000000).to_bytes(32, "big")     # 0.5 ETH
    memo_offset = (4 * 32).to_bytes(32, "big")                 # offset = 128
    memo_bytes  = memo.encode("ascii")
    memo_len    = len(memo_bytes).to_bytes(32, "big")
    pad         = ((len(memo_bytes) + 31) // 32) * 32
    memo_data   = memo_bytes + bytes(pad - len(memo_bytes))
    return selector + vault + asset + amount + memo_offset + memo_len + memo_data


def _build_deposit_with_expiry_calldata(memo, expiry=9999999999):
    """Build depositWithExpiry(address,address,uint256,string,uint256) calldata."""
    selector    = bytes.fromhex("44bc937b")
    vault       = bytes(12) + bytes.fromhex(THOR_ROUTER)
    asset       = bytes(12) + bytes.fromhex(ETH_NATIVE)
    amount      = (500000000000000000).to_bytes(32, "big")     # 0.5 ETH
    memo_offset = (5 * 32).to_bytes(32, "big")                 # offset = 160 (after expiry)
    expiry_b    = expiry.to_bytes(32, "big")
    memo_bytes  = memo.encode("ascii")
    memo_len    = len(memo_bytes).to_bytes(32, "big")
    pad         = ((len(memo_bytes) + 31) // 32) * 32
    memo_data   = memo_bytes + bytes(pad - len(memo_bytes))
    return selector + vault + asset + amount + memo_offset + expiry_b + memo_len + memo_data


class TestMsgEthereumThorchainDeposit(common.KeepKeyTest):

    def test_deposit_legacy_selector(self):
        """Existing deposit() selector (0x1fece7b4) is recognized without AdvancedMode."""
        self.requires_fullFeature()
        self.requires_firmware("7.5.0")
        self.setup_mnemonic_allallall()

        memo = "=:ETH.ETH:0xabcdef1234567890abcdef1234567890abcdef12:0:t:0"
        data = _build_deposit_calldata(memo)

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=parse_path("m/44'/60'/0'/0/0"),
            nonce=1,
            gas_price=50000000000,
            gas_limit=300000,
            to=binascii.unhexlify(THOR_ROUTER),
            value=500000000000000000,
            chain_id=1,
            data=data,
        )
        self.assertIn(sig_v, [37, 38])  # EIP-155 with chain_id=1: v = 35 + chain_id*2 + recovery
        self.assertEqual(len(sig_r), 32)
        self.assertEqual(len(sig_s), 32)

    def test_deposit_with_expiry_selector(self):
        """Modern depositWithExpiry() selector (0x44bc937b) is recognized without AdvancedMode.

        Before 7.14.2 the firmware only matched the legacy 0x1fece7b4 selector.
        All modern THORChain routers use depositWithExpiry. Without this fix the
        device would fall through to the blind-sign gate and refuse to sign (or
        require AdvancedMode), breaking every EVM->THORChain swap.
        """
        self.requires_fullFeature()
        self.requires_firmware("7.14.2")
        self.setup_mnemonic_allallall()

        memo = "=:ETH.ETH:0xabcdef1234567890abcdef1234567890abcdef12:0:t:0"
        data = _build_deposit_with_expiry_calldata(memo)

        # AdvancedMode is intentionally OFF — THORChain txs must sign without it.
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=parse_path("m/44'/60'/0'/0/0"),
            nonce=2,
            gas_price=50000000000,
            gas_limit=300000,
            to=binascii.unhexlify(THOR_ROUTER),
            value=500000000000000000,
            chain_id=1,
            data=data,
        )
        self.assertIn(sig_v, [37, 38])  # EIP-155 with chain_id=1: v = 35 + chain_id*2 + recovery
        self.assertEqual(len(sig_r), 32)
        self.assertEqual(len(sig_s), 32)

    def test_deposit_with_expiry_non_thor_address_blind_sign_blocked(self):
        """depositWithExpiry to a non-THORChain address must not be auto-approved.

        The firmware only clears the blind-sign gate when msg->has_to && the
        deposit selector matches. Sending to an arbitrary address must still
        require AdvancedMode so unrelated contracts can't exploit the selector.
        """
        self.requires_fullFeature()
        self.requires_firmware("7.14.2")
        self.setup_mnemonic_allallall()

        memo = "malicious memo"
        data = _build_deposit_with_expiry_calldata(memo)

        from keepkeylib.client import CallException
        import keepkeylib.types_pb2 as types

        # No AdvancedMode, random contract address — should be rejected
        with self.assertRaises((CallException, Exception)):
            self.client.ethereum_sign_tx(
                n=parse_path("m/44'/60'/0'/0/0"),
                nonce=3,
                gas_price=50000000000,
                gas_limit=300000,
                to=binascii.unhexlify("1234567890123456789012345678901234567890"),
                value=0,
                chain_id=1,
                data=data,
            )


if __name__ == "__main__":
    unittest.main()
