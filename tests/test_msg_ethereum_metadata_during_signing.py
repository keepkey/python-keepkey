# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""EthereumTxMetadata must arrive before signing starts.

Metadata processing clears the transaction<->metadata binding, so metadata
sent while a signing stream waits for more data is refused, and the refusal
ends that stream.
"""

import unittest

import common
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_ethereum_pb2 as eth_proto
from keepkeylib import types_pb2 as types
from keepkeylib.tools import int_to_big_endian


class TestEthereumMetadataDuringSigning(common.KeepKeyTest):
    def test_metadata_during_signing_is_refused_and_ends_the_stream(self):
        self.requires_firmware("7.15.0")
        self.requires_message("EthereumTxMetadata")
        self.requires_fullFeature()
        self.requires_release_capability("evm-tx-metadata")
        self.setup_mnemonic_allallall()
        # With AdvancedMode on, metadata is otherwise processable, so only the
        # in-progress signing session can explain a refusal.
        self.client.apply_policy("AdvancedMode", 1)

        data = b"\xa9\x05\x9c\xbb" + b"\x00" * 1996  # longer than one chunk
        resp = self.client.call(eth_proto.EthereumSignTx(
            address_n=self.client.expand_path("m/44'/60'/0'/0/0"),
            nonce=int_to_big_endian(0),
            gas_price=int_to_big_endian(20),
            gas_limit=int_to_big_endian(100000),
            value=int_to_big_endian(0),
            to=bytes.fromhex("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            chain_id=1,
            data_length=len(data),
            data_initial_chunk=data[:1024]))
        self.assertIsInstance(resp, eth_proto.EthereumTxRequest)
        self.assertTrue(resp.HasField("data_length"))

        ret = self.client.call_raw(
            eth_proto.EthereumTxMetadata(signed_payload=b"\x00" * 64))
        self.assertIsInstance(ret, proto.Failure)
        self.assertEqual(ret.code, types.Failure_UnexpectedMessage)
        self.assertEqual(ret.message, "Metadata not allowed during signing")

        ret = self.client.call_raw(
            eth_proto.EthereumTxAck(data_chunk=data[1024:]))
        self.assertIsInstance(ret, proto.Failure)
        self.assertEqual(ret.code, types.Failure_UnexpectedMessage)

    def test_signer_load_during_signing_is_refused_and_ends_the_stream(self):
        self.requires_firmware("7.15.0")
        self.requires_message("LoadClearsignSigner")
        self.requires_fullFeature()
        self.requires_release_capability("evm-tx-metadata")
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 1)

        data = b"\xa9\x05\x9c\xbb" + b"\x00" * 1996
        resp = self.client.call(self._streamed_sign_tx(data))
        self.assertIsInstance(resp, eth_proto.EthereumTxRequest)
        self.assertTrue(resp.HasField("data_length"))

        # Storing a signer clears the same binding metadata does.
        ret = self.client.call_raw(eth_proto.LoadClearsignSigner(
            key_id=0, pubkey=b"\x02" + b"\x11" * 32, alias="test"))
        self.assertIsInstance(ret, proto.Failure)
        self.assertEqual(ret.code, types.Failure_UnexpectedMessage)
        self.assertEqual(ret.message, "Signer load not allowed during signing")

        ret = self.client.call_raw(
            eth_proto.EthereumTxAck(data_chunk=data[1024:]))
        self.assertIsInstance(ret, proto.Failure)
        self.assertEqual(ret.code, types.Failure_UnexpectedMessage)

    def _streamed_sign_tx(self, data):
        return eth_proto.EthereumSignTx(
            address_n=self.client.expand_path("m/44'/60'/0'/0/0"),
            nonce=int_to_big_endian(0),
            gas_price=int_to_big_endian(20),
            gas_limit=int_to_big_endian(100000),
            value=int_to_big_endian(0),
            to=bytes.fromhex("1d1c328764a41bda0492b66baa30c4a339ff85ef"),
            chain_id=1,
            data_length=len(data),
            data_initial_chunk=data[:1024])


if __name__ == '__main__':
    unittest.main()
