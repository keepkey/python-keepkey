# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Integer fields sign the same with or without leading zero bytes.

RLP encodes an integer without leading zeros, so the firmware strips them
both when it sizes the list (stage 1) and when it hashes the bytes (stage 2).
If the two stages disagreed the pre-image would be malformed. A padded
encoding must therefore produce exactly the signature of the canonical one.
"""

import unittest

import common
from keepkeylib import messages_ethereum_pb2 as eth_proto

TO = bytes.fromhex("1d1c328764a41bda0492b66baa30c4a339ff85ef")


class TestEthereumSignTxIntegerEncoding(common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.requires_firmware("7.15.0")
        self.requires_fullFeature()
        # The stripping shipped in the same release block as this capability.
        self.requires_release_capability("evm-max-amount-review")
        self.setup_mnemonic_allallall()

    def _sign(self, **fields):
        resp = self.client.call(eth_proto.EthereumSignTx(
            address_n=self.client.expand_path("m/44'/60'/0'/0/0"),
            to=TO, chain_id=1, **fields))
        self.assertIsInstance(resp, eth_proto.EthereumTxRequest)
        self.assertTrue(resp.HasField("signature_r"))
        return resp.signature_v, resp.signature_r, resp.signature_s

    def _assert_same_signature(self, canonical, padded):
        self.assertEqual(self._sign(**canonical), self._sign(**padded))

    def test_legacy_fields_with_leading_zeros(self):
        self._assert_same_signature(
            dict(nonce=b"\x01", gas_price=b"\x14", gas_limit=b"\x52\x08",
                 value=b"\x0d\xe0\xb6\xb3\xa7\x64\x00\x00"),
            dict(nonce=b"\x00\x00\x01", gas_price=b"\x00\x14",
                 gas_limit=b"\x00\x52\x08",
                 value=b"\x00\x0d\xe0\xb6\xb3\xa7\x64\x00\x00"))

    def test_zero_value_in_every_spelling(self):
        canonical = dict(nonce=b"", gas_price=b"\x14", gas_limit=b"\x52\x08",
                         value=b"")
        for zero in (b"\x00", b"\x00\x00\x00"):
            with self.subTest(zero=zero):
                self._assert_same_signature(
                    canonical, dict(canonical, nonce=zero, value=zero))

    def test_eip1559_fees_with_leading_zeros(self):
        self._assert_same_signature(
            dict(type=2, nonce=b"\x07", max_fee_per_gas=b"\x77\x35\x94\x00",
                 max_priority_fee_per_gas=b"\x3b\x9a\xca\x00",
                 gas_limit=b"\x52\x08", value=b"\x01"),
            dict(type=2, nonce=b"\x00\x07",
                 max_fee_per_gas=b"\x00\x00\x77\x35\x94\x00",
                 max_priority_fee_per_gas=b"\x00\x3b\x9a\xca\x00",
                 gas_limit=b"\x00\x00\x52\x08", value=b"\x00\x01"))


if __name__ == '__main__':
    unittest.main()
