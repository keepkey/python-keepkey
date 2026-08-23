# This file is part of the KeepKey project.
#
# Regression tests for Ethereum signing pre-image / clear-sign correctness:
#   - EIP-1559 transaction-type vs fee-field / chain_id consistency, and
#   - contract clear-sign handlers must not confirm a prefix while later
#     streamed calldata is signed unshown, nor classify a contract CREATE.
#
# These exercise the guards added in the firmware ethereum signing path.

import time
import unittest
import common
import binascii

import keepkeylib.messages_ethereum_pb2 as eth_proto
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian
from keepkeylib.signed_metadata import (
    eth_sighash_eip1559, eth_sighash_legacy, keccak256,
)

# Sablier proxy address — the withdrawFromSalary clear-sign handler target.
SABLIER_PROXY = binascii.unhexlify("bd6a40bb904aea5a49c59050b5395f7484a4203d")
RECIPIENT = binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef")


def recover_eth_signer(sig_r, sig_s, recovery_id, digest):
    """Recover the 20-byte signer from (r, s, recovery_id) over `digest`.

    Same approach as test_msg_thorchain_signtx.py. Recovering the signer --
    rather than asserting r/s are 32 bytes -- is what makes these tests able to
    fail: the regressions they describe (a desynced RLP list header, a prefix
    hashed instead of the full calldata) still produce a perfectly well-formed
    32-byte r/s, so a length assertion passes while the device signs a
    pre-image that is not the transaction under test.
    """
    from ecdsa import VerifyingKey, SECP256k1, util
    keys = VerifyingKey.from_public_key_recovery_with_digest(
        sig_r + sig_s, digest, SECP256k1, hashfunc=None,
        sigdecode=util.sigdecode_string,
    )
    return keccak256(keys[recovery_id].to_string())[-20:]


class _ScreenRecorder(object):
    """Record the framebuffer of every confirm screen an operation draws.

    Mirrors ScreenRecorder in test_msg_ethereum_clearsign_additive.py.
    """

    SETTLE = 0.3

    def __init__(self, client):
        self.client = client
        self.frames = []

    def __enter__(self):
        original = self.client.callback_ButtonRequest

        def record(msg):
            time.sleep(self.SETTLE)
            self.frames.append((msg.code, bytes(self.client.debug.read_layout())))
            return original(msg)

        self.client.callback_ButtonRequest = record
        return self

    def __exit__(self, *exc):
        del self.client.callback_ButtonRequest
        return False

    @property
    def layouts(self):
        return [layout for _, layout in self.frames]


class TestMsgEthereumSigningGuards(common.KeepKeyTest):
    # ---- EIP-1559 type / fee / chain_id pre-image consistency ----

    def test_eip1559_requires_chain_id(self):
        """type=2 with no chain_id: Stage 1 counts chain_id as 1 byte but
        hash_rlp_number(0) hashes nothing -> over-declared list header ->
        wrong/garbage signer. The device must reject rather than sign it."""
        self.requires_firmware("7.15.0")
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
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        address_n = [0, 0]
        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=address_n,
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
        # The regression this test names -- Stage 1 counting the priority-fee
        # field while Stage 2 skips hashing it -- desyncs the RLP list header
        # and yields a signature over a DIFFERENT pre-image. That signature is
        # still 32+32 bytes, so only reconstructing the intended digest and
        # recovering the signer can detect it. The absent field must encode as
        # the empty integer, i.e. exactly max_priority_fee_per_gas = 0.
        digest = eth_sighash_eip1559(
            chain_id=1, nonce=0, max_priority_fee_per_gas=0,
            max_fee_per_gas=20, gas_limit=21000, to=RECIPIENT,
            value=10, data=b'',
        )
        signer = recover_eth_signer(sig_r, sig_s, sig_v, digest)
        # NB: KeepKeyTest's assertEqual override takes no msg argument.
        self.assertEqual(signer, self.client.ethereum_get_address(address_n))

    def test_type2_without_max_fee_rejected(self):
        """Typed prefix (0x02) is chosen from msg.type but the fee fields from
        has_max_fee_per_gas. A type=2 tx carrying only gas_price would sign a
        malformed (legacy-fee-in-1559-envelope) field list -> reject."""
        self.requires_firmware("7.15.0")
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
        self.requires_firmware("7.15.0")
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

    # withdrawFromSalary selector + 2 words, then padded past 1024 bytes so
    # data_total != data_initial_chunk.size (forces the streaming path).
    STREAMED_TAIL = (
        binascii.unhexlify(
            "0000000000000000000000000000000000000000000000000000000000001210"
            "0000000000000000000000000000000000000000000000000000000000000001"
        ) + b"\x00" * 1100
    )
    HANDLER_SELECTOR = binascii.unhexlify("fea7c53f")   # withdrawFromSalary
    # A selector the device has no clear-sign handler for. Same length, same
    # streaming path, same `to` -- so the only thing that can change the screen
    # sequence is whether the handler fired.
    NO_HANDLER_SELECTOR = binascii.unhexlify("deadbeef")

    STREAM_TX = dict(
        n=[2147483692, 2147483708, 2147483648, 0, 0],
        nonce=0xAB,
        gas_price=0x24C988AC00,
        gas_limit=0x26249,
        value=0,
        to=SABLIER_PROXY,
        address_type=0,
        chain_id=1,
    )

    def _sign_streamed(self, selector):
        """Sign the streaming-path tx with `selector`, recording its screens."""
        data = selector + self.STREAMED_TAIL
        with _ScreenRecorder(self.client) as rec:
            sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
                data=data, **self.STREAM_TX)
        return rec, data, (sig_v, sig_r, sig_s)

    def _assert_signed_full_calldata(self, data, sig):
        """Recover the signer against a digest over the COMPLETE calldata."""
        sig_v, sig_r, sig_s = sig
        self.assertEqual(len(sig_r), 32)
        self.assertEqual(len(sig_s), 32)
        self.assertIn(sig_v, [37, 38])  # EIP-155, chain_id = 1
        digest = eth_sighash_legacy(
            self.STREAM_TX['nonce'], self.STREAM_TX['gas_price'],
            self.STREAM_TX['gas_limit'], SABLIER_PROXY,
            self.STREAM_TX['value'], data, 1,
        )
        signer = recover_eth_signer(sig_r, sig_s, sig_v - 37, digest)
        # NB: KeepKeyTest's assertEqual override takes no msg argument.
        self.assertEqual(
            signer, self.client.ethereum_get_address(self.STREAM_TX['n']))

    def test_contract_handler_streamed_calldata_signs_full_data(self):
        """A handler selector whose calldata is larger than the initial chunk
        must sign the FULL streamed calldata, not the confirmed prefix.

        Recovering the signer against a digest built over the complete `data`
        is what makes this test able to fail: if the device hashed only the
        first chunk it would still return a well-formed 32-byte r/s, and the
        length assertions this test used to make would pass.
        """
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

        _, data, sig = self._sign_streamed(self.HANDLER_SELECTOR)
        self._assert_signed_full_calldata(data, sig)

    def test_streamed_handler_calldata_is_not_clear_signed(self):
        """The Sablier summary must NOT be drawn for streamed calldata.

        The handler may only clear-sign what it actually verified, and it
        cannot verify calldata it has not seen. So the streamed run must fall
        back to the ordinary raw-data review -- the same screens a selector
        with no handler at all draws.

        Compared against a no-handler baseline of identical shape (same `to`,
        same calldata length, same streaming path) rather than a hardcoded
        screen count, because the raw-data screen paginates with the calldata.
        A clear-signed run would add summary frames the baseline does not have.
        """
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

        baseline, base_data, base_sig = self._sign_streamed(
            self.NO_HANDLER_SELECTOR)
        self._assert_signed_full_calldata(base_data, base_sig)

        observed, data, sig = self._sign_streamed(self.HANDLER_SELECTOR)
        self._assert_signed_full_calldata(data, sig)

        # Any clear-sign summary would be one or more EXTRA confirm screens.
        self.assertEqual(len(observed.frames), len(baseline.frames))


if __name__ == "__main__":
    unittest.main()
