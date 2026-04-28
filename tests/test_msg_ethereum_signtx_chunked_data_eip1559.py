# Regression — EIP-1559 sign-tx with data > 1024 bytes (chunked transmission).
#
# Background:
#   The KeepKey USB transport carries the first up-to-1024 bytes of EVM
#   tx-data inside the EthereumSignTx message; remaining bytes arrive in
#   subsequent EthereumTxAck frames. For EIP-1559 transactions, the empty
#   access-list byte (0xC0) closes the RLP body and MUST be the last byte
#   fed to keccak before signing.
#
#   Firmware versions 7.x.0 .. 7.14.0 hash 0xC0 inside ethereum_signing_init()
#   immediately after data_initial_chunk — i.e. BEFORE the host has sent the
#   remaining EthereumTxAck frames. For any tx with data <= 1024 bytes this
#   accidentally lands at the end of the stream; for tx-data > 1024 bytes the
#   0xC0 is sandwiched between the first chunk and the rest of the data,
#   producing a non-canonical pre-image:
#
#     keccak( ...header... || data_len_prefix
#             || data[0..1024] || 0xC0 || data[1024..end] )
#
#   The signature is mathematically valid for that mangled hash so RPCs
#   accept the broadcast (signature checks pass), but the recovered signer
#   is a wrong-but-deterministic address that does not match the device's
#   own EOA. The transaction is dropped from the mempool because the
#   recovered "from" has no balance / wrong nonce.
#
#   Visible production symptom: every Uniswap Universal Router swap, Permit2
#   batch, and large multicall on this firmware hung at "Confirm in wallet"
#   — broadcast accepted, never confirmed.
#
#   Fix: hash 0xC0 immediately before send_signature() in BOTH the
#   single-chunk path (ethereum_signing_init) and the multi-chunk path
#   (ethereum_signing_txack). Released in firmware 7.14.1.
#
# This test pairs the device, signs a 1550-byte EIP-1559 transaction with
# the all-all-all test mnemonic, then verifies that ECDSA recovery against
# the canonical type-2 pre-image yields the device's own ETH address.
# It will FAIL on firmware 7.14.0 and earlier; PASS on 7.14.1+.

import unittest
import common
import binascii

import keepkeylib.messages_ethereum_pb2 as eth_proto


class TestMsgEthereumSigntxChunkedDataEip1559(common.KeepKeyTest):

    # m/44'/60'/0'/0/0 hardened path
    ETH_PATH = [0x80000000 | 44, 0x80000000 | 60, 0x80000000, 0, 0]

    # Universal Router on Ethereum mainnet — `to` from the captured
    # production failure (Uniswap LINK -> USDT swap). Address itself is
    # immaterial; what matters is `data` is large enough to require
    # multi-chunk transmission.
    UNISWAP_UR = binascii.unhexlify("4c82d1fbfe28c977cbb58d8c7ff8fcf9f70a2cca")

    @staticmethod
    def _rlp_int(n):
        # Canonical RLP encoding of a non-negative integer is its big-endian
        # representation with leading zeros stripped (zero -> empty bytes).
        if n == 0:
            return b""
        out = bytearray()
        while n:
            out.append(n & 0xff)
            n >>= 8
        return bytes(reversed(out))

    @classmethod
    def _build_canonical_eip1559_pre_image(cls, chain_id, nonce, max_priority_fee_per_gas,
                                           max_fee_per_gas, gas_limit, to, value, data):
        """Build keccak(0x02 || rlp([fields..., access_list=[]])).

        Mirrors what ethers / @ethereumjs/tx / go-ethereum produce for the
        unsigned type-2 envelope.
        """
        import rlp  # listed in CI install (`pip install ... rlp ...`)
        from eth_utils import keccak  # ships with eth-keys
        body = rlp.encode([
            cls._rlp_int(chain_id),
            cls._rlp_int(nonce),
            cls._rlp_int(max_priority_fee_per_gas),
            cls._rlp_int(max_fee_per_gas),
            cls._rlp_int(gas_limit),
            to,
            cls._rlp_int(value),
            data,
            [],  # empty access list
        ])
        return keccak(b"\x02" + body)

    @staticmethod
    def _recover_eth_address(msg_hash, v, r, s):
        """Return the 20-byte ETH address that signed `msg_hash`."""
        from eth_keys import keys
        # EIP-1559 returns v in {0, 1} (raw recovery id), which is what
        # eth_keys.Signature expects for `vrs`.
        sig = keys.Signature(vrs=(v, int.from_bytes(r, 'big'), int.from_bytes(s, 'big')))
        return sig.recover_public_key_from_msg_hash(msg_hash).to_canonical_address()

    def test_eip1559_chunked_data_signature_recovers_to_device_address(self):
        self.requires_fullFeature()
        self.requires_firmware("7.2.1")  # EIP-1559 support landed here
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 1)  # blind-sign opt-in

        device_address = self.client.ethereum_get_address(self.ETH_PATH)

        # 1550 bytes -> first 1024 ride in EthereumSignTx, remaining 526 ride
        # in one EthereumTxAck. Same size class as the captured production
        # failure (Uniswap Universal Router calldata).
        data = bytes((i & 0xff) for i in range(1550))
        chain_id = 1
        nonce = 0
        max_priority_fee_per_gas = 0x218711a00
        max_fee_per_gas = 0x291d5740f
        gas_limit = 0x6c8b8
        value = 0

        sig_v, sig_r, sig_s = self.client.ethereum_sign_tx(
            n=self.ETH_PATH,
            nonce=nonce,
            max_fee_per_gas=max_fee_per_gas,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            gas_limit=gas_limit,
            to=self.UNISWAP_UR,
            value=value,
            chain_id=chain_id,
            data=data,
        )

        canonical_hash = self._build_canonical_eip1559_pre_image(
            chain_id=chain_id,
            nonce=nonce,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            max_fee_per_gas=max_fee_per_gas,
            gas_limit=gas_limit,
            to=self.UNISWAP_UR,
            value=value,
            data=data,
        )

        recovered = self._recover_eth_address(canonical_hash, sig_v, sig_r, sig_s)

        # On broken firmware (<= 7.14.0) the device signs a different hash
        # whose recovered signer is a wrong-but-deterministic address. The
        # check below catches that and prints the divergence for triage.
        self.assertEqual(
            binascii.hexlify(recovered).decode(),
            binascii.hexlify(device_address).decode(),
            "EIP-1559 chunked-data signature does not recover to device address — "
            "this is the firmware/ethereum.c access-list ordering bug fixed in 7.14.1.",
        )


if __name__ == '__main__':
    unittest.main()
