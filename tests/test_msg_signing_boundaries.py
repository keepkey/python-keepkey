# This file is part of the TREZOR project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from __future__ import print_function

import binascii
import unittest

import common
import keepkeylib.ckd_public as ckd_public
import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException


class TestSigningBoundaries(common.KeepKeyTest):
    PREV_HASH = binascii.unhexlify(
        'd5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882')
    XPUB = (
        'xpub661MyMwAqRbcF1zGijBb2K6x9YiJPh58xpcCeLvTxMX6spkY3PcpJ4ABcCyW'
        'fskq5DDxM3e6Ez5ePCqG5bnPUXR4wL8TZWyoDaUdiWW7bKy')

    def _input(self):
        return proto_types.TxInputType(
            address_n=[0],
            prev_hash=self.PREV_HASH,
            prev_index=0,
        )

    def _ordinary_output(self):
        return proto_types.TxOutputType(
            address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1',
            amount=380000,
            script_type=proto_types.PAYTOADDRESS,
        )

    @staticmethod
    def _request_key(request):
        return (
            request.request_type,
            request.details.request_index,
            bytes(request.details.tx_hash),
            request.details.extra_data_offset,
            request.details.extra_data_len,
        )

    def _assert_late_txack_rejected(self):
        response = self.client.call_raw(
            proto.TxAck(tx=proto_types.TransactionType()))
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.code, proto_types.Failure_UnexpectedMessage)

    def test_clear_session_aborts_every_txrequest_stage(self):
        self.setup_mnemonic_nopin_nopassphrase()

        stage_trace = []

        def record_stage(request, message):
            stage_trace.append(self._request_key(request))
            return message

        signatures, serialized_tx = self.client.sign_tx(
            'Bitcoin', [self._input()], [self._ordinary_output()],
            debug_processor=record_stage)
        self.assertTrue(signatures[0])
        self.assertTrue(serialized_tx)
        self.assertTrue(stage_trace)
        self.assertIn(proto_types.TXMETA,
                      [stage[0] for stage in stage_trace])
        self.assertIn(proto_types.TXINPUT,
                      [stage[0] for stage in stage_trace])
        self.assertIn(proto_types.TXOUTPUT,
                      [stage[0] for stage in stage_trace])

        for target_index, expected_stage in enumerate(stage_trace):
            seen = []

            def clear_at_target(request, message):
                seen.append(self._request_key(request))
                if len(seen) - 1 == target_index:
                    response = self.client.call_raw(proto.ClearSession())
                    self.assertIsInstance(response, proto.Success)
                return message

            with self.assertRaises(CallException):
                self.client.sign_tx(
                    'Bitcoin', [self._input()], [self._ordinary_output()],
                    debug_processor=clear_at_target)

            self.assertEqual(seen[-1], expected_stage)
            self.assertEqual(len(seen), target_index + 1)
            self._assert_late_txack_rejected()

    def _invalid_multisig(self, m, n):
        node = ckd_public.deserialize(self.XPUB)
        return proto_types.MultisigRedeemScriptType(
            pubkeys=[
                proto_types.HDNodePathType(node=node, address_n=[i + 1])
                for i in range(n)
            ],
            signatures=[b''] * n,
            m=m,
        )

    def test_invalid_multisig_outputs_never_serialize_or_sign(self):
        self.setup_mnemonic_nopin_nopassphrase()

        invalid_quorums = (
            (0, 1),    # m == 0
            (1, 0),    # n == 0
            (2, 1),    # m > n
            (16, 15),  # m > 15
            (1, 16),   # n > 15
        )

        for internal in (False, True):
            for m, n in invalid_quorums:
                output = proto_types.TxOutputType(
                    address_n=[1] if internal else [],
                    amount=380000,
                    script_type=proto_types.PAYTOMULTISIG,
                    multisig=self._invalid_multisig(m, n),
                )
                signed_material = []

                def observe_response(request, message):
                    if request.HasField('serialized'):
                        serialized = request.serialized
                        if (serialized.HasField('serialized_tx') or
                                serialized.HasField('signature')):
                            signed_material.append(serialized)
                    return message

                with self.assertRaises(CallException):
                    self.client.sign_tx(
                        'Bitcoin', [self._input()], [output],
                        debug_processor=observe_response)

                self.assertEqual(signed_material, [])
                response = self.client.call_raw(
                    proto.TxAck(tx=proto_types.TransactionType()))
                self.assertIsInstance(response, proto.Failure)
                self.client.call_raw(proto.ClearSession())

    def test_multisig_signature_over_72_bytes_is_rejected(self):
        """A decoder-sized 74-byte signature must never reach serialization."""
        self.requires_firmware("7.14.2")
        self.setup_mnemonic_nopin_nopassphrase()
        node = ckd_public.deserialize(self.XPUB)
        multisig = proto_types.MultisigRedeemScriptType(
            pubkeys=[
                proto_types.HDNodePathType(node=node, address_n=[1]),
                proto_types.HDNodePathType(node=node, address_n=[2]),
                proto_types.HDNodePathType(node=node, address_n=[3]),
            ],
            signatures=[b"\x30" * 74, b"", b""],
            m=2,
        )
        tx_input = proto_types.TxInputType(
            address_n=[1],
            prev_hash=binascii.unhexlify(
                "c6091adf4c0c23982a35899a6e58ae11"
                "e703eacd7954f588ed4b9cdefc4dba52"
            ),
            prev_index=1,
            script_type=proto_types.SPENDMULTISIG,
            multisig=multisig,
        )

        first = self.client.call_raw(proto.SignTx(
            inputs_count=1, outputs_count=1, coin_name="Bitcoin"
        ))
        self.assertIsInstance(first, proto.TxRequest)
        rejected = self.client.call_raw(proto.TxAck(
            tx=proto_types.TransactionType(inputs=[tx_input])
        ))
        self.assertIsInstance(rejected, proto.Failure)
        self.assertEqual(rejected.code, proto_types.Failure_SyntaxError)
        self._assert_late_txack_rejected()

    def test_clear_session_aborts_active_bitcoin_signing(self):
        """Authorization loss destroys a signer before its first TxAck."""
        self.requires_firmware("7.14.2")
        self.setup_mnemonic_nopin_nopassphrase()
        first = self.client.call_raw(proto.SignTx(
            inputs_count=1, outputs_count=1, coin_name="Bitcoin"
        ))
        self.assertIsInstance(first, proto.TxRequest)
        cleared = self.client.call_raw(proto.ClearSession())
        self.assertIsInstance(cleared, proto.Success)
        self._assert_late_txack_rejected()
        features = self.client.call_raw(proto.Initialize())
        self.assertIsInstance(features, proto.Features)


if __name__ == '__main__':
    unittest.main()
