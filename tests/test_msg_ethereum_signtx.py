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
# The script has been modified for KeepKey device.

import unittest
import common
import binascii
import hashlib

import keepkeylib.messages_pb2 as proto
import keepkeylib.messages_ethereum_pb2 as eth_proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian
from test_msg_display_disclosure import ScreenRecorder


class TestMsgEthereumSigntx(common.KeepKeyTest):
    def test_ethereum_native_pseudo_address_is_unknown_off_mainnet(self):
        """0xeeee..eeee must render as unknown for chain-257 token calls."""
        self.requires_firmware("7.14.2")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)
        common.reset_screenshot_capture(self.client)

        recipient = self.client.ethereum_get_address([0, 0])
        pseudo_address = b"\xee" * 20
        calls = (
            (
                "transfer",
                binascii.unhexlify("a9059cbb" + "00" * 12) +
                recipient + int_to_big_endian(1).rjust(32, b"\x00"),
                "7910ca5cdea6e4f6870dad52fde79fd55891fd38fe2ad5d3295502fdf578dfe7",
            ),
            (
                "approve",
                binascii.unhexlify("095ea7b3" + "00" * 12) +
                recipient + int_to_big_endian(1).rjust(32, b"\x00"),
                "e8e44436251ef16cb00192f23adcc86f843201d676d1a3d2377a1e8ae6330c01",
            ),
        )

        try:
            for label, data, expected_frame_sha256 in calls:
                with ScreenRecorder(
                        self.client,
                        screenshot_group="pseudo-%s" % label) as recorder:
                    self.client.ethereum_sign_tx(
                        n=[0, 0], nonce=0, gas_price=20, gas_limit=60000,
                        to=pseudo_address, value=0, chain_id=257, data=data,
                    )
                self.assertGreaterEqual(len(recorder.screens), 2)
                self.assertEqual(
                    hashlib.sha256(recorder.screens[0]).hexdigest(),
                    expected_frame_sha256,
                )
        finally:
            self.client.apply_policy("AdvancedMode", 0)
            common.reset_screenshot_capture(self.client)

    def test_ethereum_erc20_high_chain_id_does_not_alias_mainnet(self):
        """Chain 257 must not borrow chain-1 token labels or decimals."""
        self.requires_firmware("7.14.2")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

        recipient = self.client.ethereum_get_address([0, 0])
        erc20_data = (
            binascii.unhexlify("a9059cbb" + "00" * 12) +
            recipient + int_to_big_endian(1).rjust(32, b"\x00")
        )
        contract = binascii.unhexlify(
            "d0d6d6c5fe4a677d343cc433536bb717bae167dd"
        )

        first_screens = {}
        try:
            for chain_id in (1, 257):
                with ScreenRecorder(self.client) as recorder:
                    self.client.ethereum_sign_tx(
                        n=[0, 0], nonce=0, gas_price=20, gas_limit=60000,
                        to=contract, value=0, chain_id=chain_id,
                        data=erc20_data,
                    )
                self.assertGreaterEqual(len(recorder.screens), 2)
                first_screens[chain_id] = recorder.screens[0]
        finally:
            self.client.apply_policy("AdvancedMode", 0)

        self.assertNotEqual(first_screens[1], first_screens[257])

    def test_ethereum_unrenderable_amounts_are_rejected(self):
        """Neither a native nor ERC-20 amount may reach an approval blank."""
        self.requires_firmware("7.14.2")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        recipient = binascii.unhexlify(
            "1d1c328764a41bda0492b66baa30c4a339ff85ef"
        )
        max_uint256 = (1 << 256) - 1

        with self.client:
            self.client.set_expected_responses([
                proto.Failure(
                    code=proto_types.Failure_SyntaxError,
                    message="Ethereum amount too large"),
            ])
            with self.assertRaises(CallException):
                self.client.ethereum_sign_tx(
                    n=[0, 0], nonce=0, gas_price=20, gas_limit=21000,
                    to=recipient, value=max_uint256, chain_id=1,
                )

        # Known mainnet ERC-20 transfer with the same unrenderable amount.
        erc20_data = (
            binascii.unhexlify("a9059cbb" + "00" * 12) +
            recipient + int_to_big_endian(max_uint256).rjust(32, b"\x00")
        )
        with self.client:
            self.client.set_expected_responses([
                proto.Failure(
                    code=proto_types.Failure_SyntaxError,
                    message="Ethereum amount too large"),
            ])
            with self.assertRaises(CallException):
                self.client.ethereum_sign_tx(
                    n=[0, 0], nonce=0, gas_price=20, gas_limit=60000,
                    to=binascii.unhexlify(
                        "d0d6d6c5fe4a677d343cc433536bb717bae167dd"
                    ),
                    value=0, chain_id=1, data=erc20_data,
                )

    def test_ethereum_signtx_data(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=10,
            data=b"abcdefghijklmnop" * 16,
            chain_id=1,
        )
        self.assertEqual(sig_v, 37)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "8580110f4113ec0fc6549a7cfc23ce93efd5ae2bbb1a274f03a42374f5feb391",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "36fa05c132ee8db6eced6410b9ee9745e2b6bf3716316f3a792a887e852e90e2",
        )

        # Second sign — same params, verify deterministic signature
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=10,
            data=b"abcdefghijklmnop" * 16,
            chain_id=1,
        )
        self.assertEqual(sig_v, 37)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "8580110f4113ec0fc6549a7cfc23ce93efd5ae2bbb1a274f03a42374f5feb391",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "36fa05c132ee8db6eced6410b9ee9745e2b6bf3716316f3a792a887e852e90e2",
        )

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=123456,
            gas_price=20000,
            gas_limit=20000,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=12345678901234567890,
            data=b"ABCDEFGHIJKLMNOP" * 256 + b"!!!",
            chain_id=1,
        )
        self.assertEqual(sig_v, 38)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "2a72ecd90252eed066d113776f4c7573a468e2dbef5f503dbc1b7c616c1902a2",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "30e216f799ba0a16688e7e365ac3439b40d29405ef7bb7939aa5a407a05e5670",
        )

        self.client.apply_policy("AdvancedMode", 0)

    def test_ethereum_blind_sign_blocked(self):
        """AdvancedMode OFF + contract data = device refuses to sign (7.14.2+).

        OLED shows the blind-sign refusal, then Failure. The wire message is
        7.14.2's "Arbitrary contract data signing disabled by policy", which
        replaced alpha's shorter "Blind signing disabled" -- it names WHICH
        policy refused and what it refused.
        The device identifies the transaction destination, displays one
        non-approving Blocked notice, then returns the policy failure. The
        exact two-ButtonRequest -> Failure sequence proves the host cannot
        advance from that notice into a signing approval.
        """
        self.requires_firmware("7.14.2")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 0)
        common.reset_screenshot_capture(self.client)

        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(
                    code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(
                    code=proto_types.ButtonRequest_Other),
                proto.Failure(
                    code=proto_types.Failure_ActionCancelled,
                    message=(
                        "Arbitrary contract data signing disabled by policy")),
            ])
            try:
                self.client.ethereum_sign_tx(
                    n=[0, 0],
                    nonce=0,
                    gas_price=20,
                    gas_limit=20,
                    to=binascii.unhexlify(
                        "1d1c328764a41bda0492b66baa30c4a339ff85ef"),
                    value=0,
                    data=b"abcdefghijklmnop" * 16,
                    chain_id=1,
                )
                self.fail(
                    "Expected Failure -- blind signing should be blocked")
            except CallException as e:
                self.assertIn(
                    "Arbitrary contract data signing disabled by policy",
                    str(e))

    def test_ethereum_blind_sign_allowed(self):
        """AdvancedMode ON permits opaque contract-data signing (7.14.2+).

        OLED shows 'BLIND SIGNATURE' before signing.
        """
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)
        common.reset_screenshot_capture(self.client)

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=0,
            data=b"abcdefghijklmnop" * 16,
            chain_id=1,
        )
        self.assertIsNotNone(sig_v)
        self.client.apply_policy("AdvancedMode", 0)

    def test_ethereum_signtx_message(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20000,
            gas_limit=20000,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=0,
            data=b"ABCDEFGHIJKLMNOP" * 256 + b"!!!",
            chain_id=1,
        )
        self.assertEqual(sig_v, 38)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "1bc0410a7e3e035dcdd24a9473b9c9fb95287c23f4ac8ad4e53ad70956cf40bf",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "465f4aa446c65b72285c7ed67d13520ace6ba63f4a34aa5b995df92151358afa",
        )

    def test_ethereum_signtx_newcontract(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

        # contract creation without data should fail.
        self.assertRaises(
            Exception,
            self.client.ethereum_sign_tx,
            n=[0, 0],
            nonce=123456,
            gas_price=20000,
            gas_limit=20000,
            to="",
            value=12345678901234567890,
            chain_id=1,
        )

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20000,
            gas_limit=20000,
            to="",
            value=12345678901234567890,
            data=b"ABCDEFGHIJKLMNOP" * 256 + b"!!!",
            chain_id=1,
        )
        self.assertEqual(sig_v, 38)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "db5d0092d44df683b1ab955d6c170c3d612e78ea9baa33bc328602ce3970843e",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "2392007ebb23dfaef07c93d45fba2a6d286c005f8491d0a209769caa2ac5c0a0",
        )

    def test_ethereum_sanity_checks(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

        # gas overflow
        self.assertRaises(
            Exception,
            self.client.ethereum_sign_tx,
            n=[0, 0],
            nonce=123456,
            gas_price=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
            gas_limit=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=12345678901234567890,
            chain_id=1,
        )

        # no gas price and no max fee per gas
        self.assertRaises(
            Exception,
            self.client.ethereum_sign_tx,
            n=[0, 0],
            nonce=123456,
            gas_limit=10000,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=12345678901234567890,
            chain_id=1,
        )

        # no gas limit
        self.assertRaises(
            Exception,
            self.client.ethereum_sign_tx,
            n=[0, 0],
            nonce=123456,
            gas_price=10000,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=12345678901234567890,
            chain_id=1,
        )

        # no nonce
        self.assertRaises(
            Exception,
            self.client.ethereum_sign_tx,
            n=[0, 0],
            gas_price=10000,
            gas_limit=123456,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=12345678901234567890,
            chain_id=1,
        )

    def test_ethereum_signtx_omitted_chain_id_rejected(self):
        """An omitted chain_id must be refused, not silently signed pre-EIP-155.

        Before 7.14.2 the `chain_id < 1` bounds check lived inside
        `if (msg->has_chain_id)`, so a host that simply left the field out
        reached chain_id == 0 without tripping it. Two things followed:

          - send_signature() appends the EIP-155 fields only `if (chain_id)`,
            so the device emitted a pre-EIP-155 signature -- replayable on
            every EVM chain where this address is funded at this nonce.
          - ethereumFormatAmount() switches on the chain id for the ticker;
            cid 0 matches no case, so the confirm screen rendered a bare
            number. No screen named a network. The user could not see either
            problem before holding the button.

        This is the regression test for that. It asserts the refusal, and the
        sibling tests in this file all now pass chain_id explicitly so they
        keep exercising their own subject rather than this one.
        """
        self.requires_firmware("7.14.2")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

        try:
            self.client.ethereum_sign_tx(
                n=[0, 0],
                nonce=0,
                gas_price=20,
                gas_limit=20,
                to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
                value=10,
            )
            self.fail(
                "Expected Failure -- a transaction with no chain_id must be "
                "refused, not signed without replay protection"
            )
        except CallException as e:
            self.assertIn("Chain Id out of bounds", str(e))

        self.client.apply_policy("AdvancedMode", 0)

    def test_ethereum_signtx_explicit_zero_chain_id_rejected(self):
        """chain_id=0 sent explicitly is refused the same way as omitting it.

        Covers the other half of the same gate: 7.14.1 already rejected an
        explicit 0, and that must not regress while fixing the absent case.
        """
        self.requires_firmware("7.14.2")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        try:
            self.client.ethereum_sign_tx(
                n=[0, 0],
                nonce=0,
                gas_price=20,
                gas_limit=20,
                to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
                value=10,
                chain_id=0,
            )
            self.fail("Expected Failure -- chain_id=0 must be refused")
        except CallException as e:
            self.assertIn("Chain Id out of bounds", str(e))

    def test_ethereum_signtx_nodata_eip155(self):
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 0)

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0x80000000 | 44, 0x80000000 | 1, 0x80000000, 0, 0],
            nonce=0,
            gas_price=20000000000,
            gas_limit=21000,
            to=binascii.unhexlify("8ea7a3fccc211ed48b763b4164884ddbcf3b0a98"),
            value=100000000000000000,
            chain_id=3,
        )
        self.assertEqual(sig_v, 41)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "a90d0bc4f8d63be69453dd62f2bb5fff53c610000abf956672564d8a654d401a",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "544a2e57bc8b4da18660a1e6036967ea581cc635f5137e3ba97a750867c27cf2",
        )

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0x80000000 | 44, 0x80000000 | 1, 0x80000000, 0, 0],
            nonce=1,
            gas_price=20000000000,
            gas_limit=21000,
            to=binascii.unhexlify("8ea7a3fccc211ed48b763b4164884ddbcf3b0a98"),
            value=100000000000000000,
            chain_id=3,
        )
        self.assertEqual(sig_v, 42)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "699428a6950e23c6843f1bf3754f847e64e047e829978df80d55187d19a401ce",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "087343d0a3a2f10842218ffccb146b59a8431b6245ab389fde22dc833f171e6e",
        )

    def test_ethereum_signtx_data_eip155(self):
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 1)

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0x80000000 | 44, 0x80000000 | 1, 0x80000000, 0, 0],
            nonce=2,
            gas_price=20000000000,
            gas_limit=21004,
            to=binascii.unhexlify("8ea7a3fccc211ed48b763b4164884ddbcf3b0a98"),
            value=100000000000000000,
            data=b"\0",
            chain_id=3,
        )
        self.assertEqual(sig_v, 42)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "ba85b622a8bb82606ba96c132e81fa8058172192d15bc41d7e57c031bca17df4",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "6473b75997634b6f692f8d672193591d299d5bf1c2d6e51f1a14ed0530b91c7d",
        )

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0x80000000 | 44, 0x80000000 | 1, 0x80000000, 0, 0],
            nonce=3,
            gas_price=20000000000,
            gas_limit=299732,
            to=binascii.unhexlify("8ea7a3fccc211ed48b763b4164884ddbcf3b0a98"),
            value=100000000000000000,
            data=b"ABCDEFGHIJKLMNOP" * 256 + b"!!!",
            chain_id=3,
        )
        self.assertEqual(sig_v, 42)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "d021c98f92859c8db5e4de2f0e410a8deb0c977eb1a631e323ebf7484bd0d79a",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "2c0e9defc9b1e895dc9520ff25ba3c635b14ad70aa86a5ad6c0a3acb82b569b6",
        )

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0x80000000 | 44, 0x80000000 | 1, 0x80000000, 0, 0],
            nonce=4,
            gas_price=20000000000,
            gas_limit=21004,
            to=binascii.unhexlify("8ea7a3fccc211ed48b763b4164884ddbcf3b0a98"),
            value=0,
            data=b"\0",
            chain_id=3,
        )
        self.assertEqual(sig_v, 42)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "dd52f026972a83c56b7dea356836fcfc70a68e3b879cdc8ef2bb5fea23e0a7aa",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "079285fe579c9a2da25c811b1c5c0a74cd19b6301ee42cf20ef7b3b1353f7242",
        )

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0x80000000 | 44, 0x80000000 | 1, 0x80000000, 0, 0],
            nonce=5,
            gas_price=100000,
            gas_limit=21004,
            to=binascii.unhexlify("8ea7a3fccc211ed48b763b4164884ddbcf3b0a98"),
            value=0,
            data=b"\0",
            chain_id=3,
        )
        self.assertEqual(sig_v, 41)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "f402df670b79efba59fd8314ded5e0130263bdee0fe35da6ced4e03c85faf63d",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "0fb9e6bc9243daf5017fc26f8ee2747f0ffd76fb277d451d2dfd5ccfa1e8b438",
        )

    def test_ethereum_eip_1559(self):
        self.requires_fullFeature()
        self.requires_firmware("7.2.1")
        self.setup_mnemonic_nopin_nopassphrase()

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0x80000000 | 44, 0x80000000 | 60, 0x80000000, 0, 0],
            nonce=0,
            gas_limit=0x5ac3,
            max_fee_per_gas=0x16854be509,
            max_priority_fee_per_gas=0x540ae480,
            to=binascii.unhexlify("fc0cc6e85dff3d75e3985e0cb83b090cfd498dd1"),
            value=0x1550f7dca70000,
            chain_id=1
        )

        self.assertEqual(sig_v, 1)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "840314e4bec1fe3d4464ac918f9bab3e5af0b0994df225d2968962a4c8f8fec8",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "67297089e0ba53c29dda1aafc23fce64a772c5433e127e5885edc03ece4670c9",
        )

    def test_ethereum_eip_1559_multibyte_chain_id(self):
        """EIP-1559 must hash the WHOLE chain_id, not just its low byte.

        Regression for the multi-byte chain_id bug (firmware ed6db167). The
        EIP-1559 hash step used hash_rlp_field((uint8_t*)&chain_id, 1), which on
        little-endian ARM fed only the least-significant byte into keccak. For
        Base (8453 = 0x2105) that hashed 0x05, so the signature recovered to an
        unrelated address with no funds. The RLP *length* was computed correctly
        from the full value and the legacy EIP-155 path was always correct —
        only the EIP-1559 hash was wrong. Affected: Base (8453), Arbitrum
        (42161), Avalanche (43114). Unaffected: ETH (1), OP (10), BSC (56),
        Polygon (137) — all single-byte.

        Every other EIP-1559 case in this file uses chain_id 1 or 3, so the bug
        had no coverage in the file that tests the feature.

        A golden r/s would need a device run to produce, so this is a
        differential. Sign one identical transaction under two chain ids the
        BUGGY firmware cannot tell apart:

            8453 = 0x2105   low byte 0x05, two-byte value
            4357 = 0x1105   low byte 0x05, two-byte value

        Same low byte AND same RLP length header, so the broken code hashes a
        byte-identical pre-image for both. Signing is deterministic (RFC 6979),
        so buggy firmware returns the SAME signature twice and this fails.
        Correct firmware hashes 0x21 0x05 vs 0x11 0x05, which must differ.

        Note a comparison against chain_id=5 would NOT work: the RLP length was
        always derived from the full value, so the buggy pre-image for 8453 is
        malformed rather than equal to a well-formed single-byte encoding. The
        twin must match on both low byte and byte-width.
        """
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        def sign(chain_id):
            return self.client.ethereum_sign_tx(
                n=[0x80000000 | 44, 0x80000000 | 60, 0x80000000, 0, 0],
                nonce=0,
                gas_limit=0x5ac3,
                max_fee_per_gas=0x16854be509,
                max_priority_fee_per_gas=0x540ae480,
                to=binascii.unhexlify("fc0cc6e85dff3d75e3985e0cb83b090cfd498dd1"),
                value=0x1550f7dca70000,
                chain_id=chain_id,
            )

        _, base_r, base_s = sign(8453)
        _, twin_r, twin_s = sign(4357)

        self.assertNotEqual(
            (binascii.hexlify(base_r), binascii.hexlify(base_s)),
            (binascii.hexlify(twin_r), binascii.hexlify(twin_s)),
            "chain_id 8453 and 4357 produced the same signature — only the low "
            "byte of chain_id reached the EIP-1559 hash",
        )

    def test_ethereum_signtx_nodata_eip_1559(self):
        self.requires_fullFeature()
        self.requires_firmware("7.2.1")
        self.setup_mnemonic_allallall()

        # from trezor test vector:
        # https://github.com/trezor/trezor-firmware/blob/master/common/tests/fixtures/ethereum/sign_tx_eip1559.json#L9
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0x80000000 | 44, 0x80000000 | 60, 0x80000000, 0, 100],
            nonce=0,
            max_fee_per_gas=20,
            max_priority_fee_per_gas=1,
            gas_limit=20,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=10,
            chain_id=1
        )
        self.assertEqual(sig_v, 1)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "2ceeaabc994fbce2fbd66551f9d48fc711c8db2a12e93779eeddede11e41f636",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "2db4a9ecc73da91206f84397ae9287a399076fdc01ed7f3c6554b1c57c39bf8c",
        )

    def test_ethereum_signtx_knownerc20_eip_1559(self):
        self.requires_fullFeature()
        self.requires_firmware("7.2.1")
        self.setup_mnemonic_allallall()

        # from trezor test vector:
        # https://github.com/trezor/trezor-firmware/blob/master/common/tests/fixtures/ethereum/sign_tx_eip1559.json#L65
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0x80000000 | 44, 0x80000000 | 60, 0x80000000, 0, 0],
            nonce=0,
            max_fee_per_gas=20,
            max_priority_fee_per_gas=1,
            gas_limit=20,
            to=binascii.unhexlify("d0d6d6c5fe4a677d343cc433536bb717bae167dd"),
            value=0,
            chain_id=1,
            data=binascii.unhexlify('a9059cbb000000000000000000000000574bbb36871ba6b78e27f4b4dcfb76ea0091880b000000000000000000000000000000000000000000000000000000000bebc200')
        )

        self.assertEqual(sig_v, 1)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "94d67bacb7966f881339d91103f5d738d9c491fff4c01a6513c554ab15e86cc0",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "405bd19a7bf4ae62d41fcb7844e36c786b106b456185c3d0877a7ce7eab6c751",
        )

    def test_ethereum_signtx_data1_eip_1559(self):
        self.requires_fullFeature()
        self.requires_firmware("7.2.1")
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 1)

        # from trezor test vector:
        # https://github.com/trezor/trezor-firmware/blob/master/common/tests/fixtures/ethereum/sign_tx_eip1559.json#L27
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0x80000000 | 44, 0x80000000 | 60, 0x80000000, 0, 0],
            nonce=0,
            max_fee_per_gas=20,
            max_priority_fee_per_gas=1,
            gas_limit=20,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=10,
            chain_id=1,
            data=binascii.unhexlify('6162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f70')
        )

        self.assertEqual(sig_v, 0)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "8e4361e40e76a7cab17e0a982724bbeaf5079cd02d50c20d431ba7dde2404ea4",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "411930f091bb508e593e22a9ee45bd4d9eeb504ac398123aec889d5951bdebc3",
        )

    def test_ethereum_signtx_nodata(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 0)

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_price=20,
            gas_limit=20,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=10,
            chain_id=1,
        )
        self.assertEqual(sig_v, 38)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "e66bea09792bbb60b3166bd4526a26c741ad298266da6d86a32c828a6e5499b6",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "604c59f8aece9170a1d91fe7c6b09ce52e4de41b8bd572d945af171adbeafab6",
        )

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=123456,
            gas_price=20000,
            gas_limit=20000,
            to=binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            value=12345678901234567890,
            chain_id=1,
        )
        self.assertEqual(sig_v, 38)
        self.assertEqual(
            binascii.hexlify(sig_r),
            "b37433f196fb64c7d6028907e5a7b75a4b02d2d822545b4d1014fe9cf172c526",
        )
        self.assertEqual(
            binascii.hexlify(sig_s),
            "47a0d7c13f3cf0b260973ba90a86b42c01b7e7cd55adba1dc40dee1a79011144",
        )


if __name__ == "__main__":
    unittest.main()
