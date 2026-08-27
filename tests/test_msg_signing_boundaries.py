# This file is part of the KeepKey project.

"""Signing state and decoded multisig lengths must fail closed."""

from __future__ import print_function

import binascii
import unittest

import common

import keepkeylib.ckd_public as ckd_public
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types


XPUB = (
    "xpub661MyMwAqRbcF1zGijBb2K6x9YiJPh58xpcCeLvTxMX6spkY3PcpJ4ABcCy"
    "Wfskq5DDxM3e6Ez5ePCqG5bnPUXR4wL8TZWyoDaUdiWW7bKy"
)


class TestSigningBoundaries(common.KeepKeyTest):
    def setUp(self):
        super(TestSigningBoundaries, self).setUp()
        self.requires_firmware("7.14.2")
        self.setup_mnemonic_nopin_nopassphrase()

    def test_multisig_signature_over_72_bytes_is_rejected(self):
        """A decoder-sized 74-byte signature must never reach serialization."""
        node = ckd_public.deserialize(XPUB)
        multisig = types.MultisigRedeemScriptType(
            pubkeys=[
                types.HDNodePathType(node=node, address_n=[1]),
                types.HDNodePathType(node=node, address_n=[2]),
                types.HDNodePathType(node=node, address_n=[3]),
            ],
            # Nanopb's static decoder historically accepted this even though
            # the schema storage is smaller because the repeated-element
            # stride includes structure padding.
            signatures=[b"\x30" * 74, b"", b""],
            m=2,
        )
        tx_input = types.TxInputType(
            address_n=[1],
            prev_hash=binascii.unhexlify(
                "c6091adf4c0c23982a35899a6e58ae11"
                "e703eacd7954f588ed4b9cdefc4dba52"
            ),
            prev_index=1,
            script_type=types.SPENDMULTISIG,
            multisig=multisig,
        )

        first = self.client.call_raw(proto.SignTx(
            inputs_count=1, outputs_count=1, coin_name="Bitcoin"
        ))
        self.assertIsInstance(first, proto.TxRequest)
        rejected = self.client.call_raw(proto.TxAck(
            tx=types.TransactionType(inputs=[tx_input])
        ))
        self.assertIsInstance(rejected, proto.Failure)
        self.assertEqual(rejected.code, types.Failure_SyntaxError)

        # Rejection is terminal rather than leaving a partially initialized
        # signer available to a follow-up TxAck.
        stale = self.client.call_raw(proto.TxAck(tx=types.TransactionType()))
        self.assertIsInstance(stale, proto.Failure)
        self.assertEqual(stale.code, types.Failure_UnexpectedMessage)

    def test_clear_session_aborts_active_bitcoin_signing(self):
        """Authorization loss must also destroy the in-flight signer."""
        first = self.client.call_raw(proto.SignTx(
            inputs_count=1, outputs_count=1, coin_name="Bitcoin"
        ))
        self.assertIsInstance(first, proto.TxRequest)

        cleared = self.client.call_raw(proto.ClearSession())
        self.assertIsInstance(cleared, proto.Success)

        stale = self.client.call_raw(proto.TxAck(tx=types.TransactionType()))
        self.assertIsInstance(stale, proto.Failure)
        self.assertEqual(stale.code, types.Failure_UnexpectedMessage)

        features = self.client.call_raw(proto.Initialize())
        self.assertIsInstance(features, proto.Features)


if __name__ == "__main__":
    unittest.main()
