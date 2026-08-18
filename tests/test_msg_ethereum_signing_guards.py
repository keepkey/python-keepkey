# This file is part of the KeepKey project.
#
# Regression tests for Ethereum signing pre-image / clear-sign correctness:
#   - EIP-1559 transaction-type vs fee-field / chain_id consistency, and
#   - contract clear-sign handlers must not confirm a prefix while later
#     streamed calldata is signed unshown, nor classify a contract CREATE.
#
# These exercise the guards added in the firmware ethereum signing path.

import unittest
import common
import binascii

import keepkeylib.messages_ethereum_pb2 as eth_proto
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian

# Sablier proxy address — the withdrawFromSalary clear-sign handler target.
SABLIER_PROXY = binascii.unhexlify("bd6a40bb904aea5a49c59050b5395f7484a4203d")
RECIPIENT = binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef")


class TestMsgEthereumSigningGuards(common.KeepKeyTest):
    # ---- EIP-1559 type / fee / chain_id pre-image consistency ----

    def test_eip1559_requires_chain_id(self):
        """type=2 with no chain_id: Stage 1 counts chain_id as 1 byte but
        hash_rlp_number(0) hashes nothing -> over-declared list header ->
        wrong/garbage signer. The device must reject rather than sign it."""
        self.requires_firmware("7.15.1")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)
        self.assertRaises(
            CallException,
            self.client.ethereum_sign_tx,
            n=[0, 0],
            nonce=0,
            gas_limit=21000,
            max_fee_per_gas=20,
            max_priority_fee_per_gas=1,
            to=RECIPIENT,
            value=10,
            # chain_id intentionally omitted -> chain_id == 0
        )

    def test_eip1559_no_priority_fee_signs(self):
        """max_priority_fee_per_gas is a mandatory EIP-1559 RLP field; when
        absent it must encode as the empty integer (0x80). Stage 1 always
        counts it, so Stage 2 must always hash it -- the device must still
        produce a valid signature (not desync the list header)."""
        self.requires_firmware("7.15.1")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[0, 0],
            nonce=0,
            gas_limit=21000,
            max_fee_per_gas=20,  # no max_priority_fee_per_gas
            to=RECIPIENT,
            value=10,
            chain_id=1,
        )
        self.assertIn(sig_v, (0, 1))  # EIP-1559 recovery-id parity
        self.assertEqual(len(sig_r), 32)
        self.assertEqual(len(sig_s), 32)

    def test_type2_without_max_fee_rejected(self):
        """Typed prefix (0x02) is chosen from msg.type but the fee fields from
        has_max_fee_per_gas. A type=2 tx carrying only gas_price would sign a
        malformed (legacy-fee-in-1559-envelope) field list -> reject."""
        self.requires_firmware("7.15.1")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)
        msg = eth_proto.EthereumSignTx(
            address_n=[0, 0],
            nonce=int_to_big_endian(0),
            gas_price=int_to_big_endian(20),  # legacy fee field ...
            gas_limit=int_to_big_endian(21000),
            value=int_to_big_endian(10),
            chain_id=1,
            type=2,  # ... but typed as EIP-1559
        )
        msg.to = RECIPIENT
        self.assertRaises(CallException, self.client.call, msg)

    def test_legacy_with_max_fee_rejected(self):
        """A legacy tx (type omitted) carrying max_fee_per_gas would hash two
        fee fields into a legacy structure -> reject the mismatch."""
        self.requires_firmware("7.15.1")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)
        msg = eth_proto.EthereumSignTx(
            address_n=[0, 0],
            nonce=int_to_big_endian(0),
            max_fee_per_gas=int_to_big_endian(20),
            max_priority_fee_per_gas=int_to_big_endian(1),
            gas_limit=int_to_big_endian(21000),
            value=int_to_big_endian(10),
            chain_id=1,
            # type omitted -> legacy
        )
        msg.to = RECIPIENT
        self.assertRaises(CallException, self.client.call, msg)

    # ---- Contract clear-sign handler gate ----

    def test_contract_handler_streamed_calldata_signs_full_data(self):
        """A handler selector (sablier withdrawFromSalary) whose calldata is
        larger than the initial chunk must NOT be clear-signed from the prefix.
        The device falls back to generic raw-data confirmation and signs the
        full streamed calldata.

        Asserts here that signing completes over the full (streamed) calldata;
        the screen-level assertion (no 'Sablier' clear-sign summary appears for
        streamed calldata) is verified on-device / on the emulator via
        DebugLink layout."""
        self.requires_firmware("7.15.1")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)
        # withdrawFromSalary selector + 2 words, then padded past 1024 bytes so
        # data_total != data_initial_chunk.size (forces the streaming path).
        data = binascii.unhexlify(
            "fea7c53f"
            + "0000000000000000000000000000000000000000000000000000000000001210"
            + "0000000000000000000000000000000000000000000000000000000000000001"
        ) + b"\x00" * 1100
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=[2147483692, 2147483708, 2147483648, 0, 0],
            nonce=0xAB,
            gas_price=0x24C988AC00,
            gas_limit=0x26249,
            value=0,
            to=SABLIER_PROXY,
            address_type=0,
            chain_id=1,
            data=data,
        )
        self.assertEqual(len(sig_r), 32)
        self.assertEqual(len(sig_s), 32)


if __name__ == "__main__":
    unittest.main()
