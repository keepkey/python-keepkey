"""Offline contract tests for the firmware 7.15 Zcash PCZT client flow."""

import unittest

from keepkeylib.client import ProtocolMixin
from keepkeylib import messages_zcash_pb2 as zcash_proto


H = 0x80000000
ADDRESS_N = [H + 32, H + 133, H]
T_ADDRESS_N = [H + 44, H + 133, H, 0, 0]


class ScriptedTransport(object):
    def __init__(self, reads=None):
        self.reads = list(reads or [])
        self.session_depth = 0

    def session_begin(self):
        self.session_depth += 1

    def session_end(self):
        self.session_depth -= 1

    def read_blocking(self):
        if not self.reads:
            raise AssertionError("unexpected transport read")
        return self.reads.pop(0)


class ScriptedClient(object):
    zcash_sign_pczt = ProtocolMixin.zcash_sign_pczt

    def __init__(self, responses, reads=None):
        self.responses = list(responses)
        self.transport = ScriptedTransport(reads)
        self.sent = []

    def call(self, message):
        self.sent.append(message)
        if not self.responses:
            raise AssertionError("unexpected device call: %s" % type(message))
        return self.responses.pop(0)


def action(index, is_spend):
    return {
        'alpha': bytes([index + 1]) * 32,
        'cv_net': bytes([index + 11]) * 32,
        'value': 10000 + index,
        'is_spend': is_spend,
    }


def sign_kwargs(actions):
    return {
        'address_n': ADDRESS_N,
        'actions': actions,
        'account': 0,
        'total_amount': 50000,
        'fee': 15000,
        'branch_id': 0x5437F330,
        'header_digest': b'\x10' * 32,
        'transparent_digest': b'\x11' * 32,
        'orchard_digest': b'\x12' * 32,
        'orchard_flags': 3,
        'orchard_value_balance': -50000,
        'orchard_anchor': b'\x13' * 32,
        'tx_version': 5,
        'version_group_id': 0x26A7270A,
        'lock_time': 0,
        'expiry_height': 0,
    }


def ironwood_sign_kwargs(actions):
    kwargs = sign_kwargs(actions)
    kwargs.update({
        'branch_id': 0x37A5165B,
        'orchard_digest': b'\x14' * 32,
        'shielded_pool': zcash_proto.ZCASH_SHIELDED_POOL_IRONWOOD,
        'ironwood_digest': b'\x15' * 32,
        'orchard_value_balance': 0,
        'tx_version': 6,
        'version_group_id': 0xD884B698,
    })
    return kwargs


class TestZcashSignPCZTClient(unittest.TestCase):
    def test_ironwood_v6_metadata_is_forwarded_exactly(self):
        actions = [action(0, False)]
        client = ScriptedClient([
            zcash_proto.ZcashPCZTActionAck(next_index=0),
            zcash_proto.ZcashSignedPCZT(signatures=[]),
        ])

        signed = client.zcash_sign_pczt(**ironwood_sign_kwargs(actions))

        self.assertEqual(list(signed.signatures), [])
        request = client.sent[0]
        self.assertEqual(request.branch_id, 0x37A5165B)
        self.assertEqual(request.tx_version, 6)
        self.assertEqual(request.version_group_id, 0xD884B698)
        self.assertEqual(
            request.shielded_pool,
            zcash_proto.ZCASH_SHIELDED_POOL_IRONWOOD,
        )
        self.assertEqual(request.orchard_digest, b'\x14' * 32)
        self.assertEqual(request.ironwood_digest, b'\x15' * 32)

    def test_all_dummy_shield_streams_outputs_inputs_and_no_orchard_sigs(self):
        actions = [action(0, False), action(1, False)]
        responses = [
            zcash_proto.ZcashTransparentAck(next_output_index=0),
            zcash_proto.ZcashTransparentAck(next_input_index=0),
            zcash_proto.ZcashPCZTActionAck(next_index=0),
            zcash_proto.ZcashPCZTActionAck(next_index=1),
            zcash_proto.ZcashTransparentSigned(signatures=[b'\x30\x01']),
        ]
        final = zcash_proto.ZcashSignedPCZT(signatures=[])
        client = ScriptedClient(responses, reads=[final])

        kwargs = sign_kwargs(actions)
        kwargs.update({
            'transparent_outputs': [{
                'amount': 10000,
                'script_pubkey': b'\x76\xa9\x14' + b'\x21' * 20 + b'\x88\xac',
            }],
            'transparent_inputs': [{
                'address_n': T_ADDRESS_N,
                'amount': 75000,
                'prevout_txid': b'\x22' * 32,
                'prevout_index': 1,
                'sequence': 0xFFFFFFFF,
                'script_pubkey': b'\x76\xa9\x14' + b'\x23' * 20 + b'\x88\xac',
            }],
            'return_transparent_signatures': True,
        })

        signed, transparent_sigs = client.zcash_sign_pczt(**kwargs)

        self.assertIs(signed, final)
        self.assertEqual(list(signed.signatures), [])
        self.assertEqual(transparent_sigs, [b'\x30\x01'])
        self.assertEqual(
            [type(message) for message in client.sent],
            [
                zcash_proto.ZcashSignPCZT,
                zcash_proto.ZcashTransparentOutput,
                zcash_proto.ZcashTransparentInput,
                zcash_proto.ZcashPCZTAction,
                zcash_proto.ZcashPCZTAction,
            ],
        )

        request = client.sent[0]
        self.assertEqual(request.n_transparent_outputs, 1)
        self.assertEqual(request.n_transparent_inputs, 1)
        self.assertEqual(request.tx_version, 5)
        self.assertEqual(request.version_group_id, 0x26A7270A)
        self.assertFalse(request.HasField('sapling_digest'))
        self.assertFalse(request.HasField('shielded_pool'))
        self.assertFalse(request.HasField('ironwood_digest'))
        self.assertFalse(client.sent[3].is_spend)
        self.assertFalse(client.sent[4].is_spend)
        self.assertFalse(client.sent[2].HasField('sighash'))
        self.assertEqual(client.transport.session_depth, 0)

    def test_mixed_deshield_returns_only_real_spend_signature(self):
        actions = [action(0, True), action(1, False)]
        signature = b'\x40' * 64
        client = ScriptedClient([
            zcash_proto.ZcashPCZTActionAck(next_index=0),
            zcash_proto.ZcashPCZTActionAck(next_index=1),
            zcash_proto.ZcashSignedPCZT(signatures=[signature]),
        ])

        signed = client.zcash_sign_pczt(**sign_kwargs(actions))

        self.assertEqual(list(signed.signatures), [signature])
        self.assertTrue(client.sent[1].is_spend)
        self.assertFalse(client.sent[2].is_spend)

    def test_private_send_preserves_compact_real_spend_order(self):
        actions = [action(0, True), action(1, False), action(2, True)]
        signatures = [b'\x50' * 64, b'\x51' * 64]
        client = ScriptedClient([
            zcash_proto.ZcashPCZTActionAck(next_index=0),
            zcash_proto.ZcashPCZTActionAck(next_index=1),
            zcash_proto.ZcashPCZTActionAck(next_index=2),
            zcash_proto.ZcashSignedPCZT(signatures=signatures),
        ])

        signed = client.zcash_sign_pczt(**sign_kwargs(actions))

        self.assertEqual(list(signed.signatures), signatures)
        self.assertEqual(
            [message.index for message in client.sent[1:]],
            [0, 1, 2],
        )

    def test_missing_is_spend_is_rejected_before_device_call(self):
        malformed = action(0, True)
        del malformed['is_spend']
        client = ScriptedClient([])

        with self.assertRaisesRegex(ValueError, "explicitly set boolean is_spend"):
            client.zcash_sign_pczt(**sign_kwargs([malformed]))

        self.assertEqual(client.sent, [])
        self.assertEqual(client.transport.session_depth, 0)

    def test_host_transparent_sighash_is_rejected_before_device_call(self):
        client = ScriptedClient([])
        kwargs = sign_kwargs([action(0, False)])
        kwargs['transparent_inputs'] = [{
            'address_n': T_ADDRESS_N,
            'amount': 75000,
            'sighash': b'\x60' * 32,
        }]

        with self.assertRaisesRegex(ValueError, "Host-provided transparent sighash"):
            client.zcash_sign_pczt(**kwargs)

        self.assertEqual(client.sent, [])

    def test_signature_count_must_match_real_spends(self):
        actions = [action(0, True), action(1, False)]
        client = ScriptedClient([
            zcash_proto.ZcashPCZTActionAck(next_index=0),
            zcash_proto.ZcashPCZTActionAck(next_index=1),
            zcash_proto.ZcashSignedPCZT(signatures=[]),
        ])

        with self.assertRaisesRegex(Exception, "0 Orchard signatures for 1 real spends"):
            client.zcash_sign_pczt(**sign_kwargs(actions))

    def _transparent_kwargs(self, actions, n_inputs):
        """One transparent output plus n_inputs transparent inputs."""
        kwargs = sign_kwargs(actions)
        kwargs.update({
            'transparent_outputs': [{
                'amount': 10000,
                'script_pubkey': b'\x76\xa9\x14' + b'\x21' * 20 + b'\x88\xac',
            }],
            'transparent_inputs': [{
                'address_n': T_ADDRESS_N,
                'amount': 75000 + i,
                'prevout_txid': bytes([0x22 + i]) * 32,
                'prevout_index': i,
                'sequence': 0xFFFFFFFF,
                'script_pubkey': b'\x76\xa9\x14' + b'\x23' * 20 + b'\x88\xac',
            } for i in range(n_inputs)],
            'return_transparent_signatures': True,
        })
        return kwargs

    def _transparent_acks(self, n_inputs):
        return ([zcash_proto.ZcashTransparentAck(next_output_index=0)] +
                [zcash_proto.ZcashTransparentAck(next_input_index=i)
                 for i in range(n_inputs)] +
                [zcash_proto.ZcashPCZTActionAck(next_index=0)])

    def test_short_transparent_signature_list_is_rejected(self):
        """Two transparent inputs, one signature back.

        The unsignable input would otherwise reach the caller as success.
        """
        actions = [action(0, False)]
        responses = self._transparent_acks(2) + [
            zcash_proto.ZcashTransparentSigned(signatures=[b'\x30\x01']),
        ]
        client = ScriptedClient(
            responses, reads=[zcash_proto.ZcashSignedPCZT(signatures=[])])

        with self.assertRaisesRegex(
                Exception, "1 transparent signatures for 2 transparent inputs"):
            client.zcash_sign_pczt(**self._transparent_kwargs(actions, 2))

    def test_omitted_transparent_signed_message_is_rejected(self):
        """The device jumps straight to ZcashSignedPCZT with inputs pending."""
        actions = [action(0, False)]
        responses = self._transparent_acks(1) + [
            zcash_proto.ZcashSignedPCZT(signatures=[]),
        ]
        client = ScriptedClient(responses)

        with self.assertRaisesRegex(
                Exception, "0 transparent signatures for 1 transparent inputs"):
            client.zcash_sign_pczt(**self._transparent_kwargs(actions, 1))

    def test_empty_transparent_signature_is_rejected(self):
        """A present-but-empty entry is a missing signature, not a signature."""
        actions = [action(0, False)]
        responses = self._transparent_acks(1) + [
            zcash_proto.ZcashTransparentSigned(signatures=[b'']),
        ]
        client = ScriptedClient(
            responses, reads=[zcash_proto.ZcashSignedPCZT(signatures=[])])

        with self.assertRaisesRegex(Exception, "empty transparent signature"):
            client.zcash_sign_pczt(**self._transparent_kwargs(actions, 1))

    def test_transparent_signature_per_input_is_accepted(self):
        """The matching-count case still succeeds, in device order."""
        actions = [action(0, False)]
        sigs = [b'\x30\x01', b'\x30\x02']
        responses = self._transparent_acks(2) + [
            zcash_proto.ZcashTransparentSigned(signatures=sigs),
        ]
        final = zcash_proto.ZcashSignedPCZT(signatures=[])
        client = ScriptedClient(responses, reads=[final])

        signed, transparent_sigs = client.zcash_sign_pczt(
            **self._transparent_kwargs(actions, 2))

        self.assertIs(signed, final)
        self.assertEqual(transparent_sigs, sigs)

    def test_duplicate_action_request_is_rejected(self):
        actions = [action(0, True), action(1, False)]
        client = ScriptedClient([
            zcash_proto.ZcashPCZTActionAck(next_index=0),
            zcash_proto.ZcashPCZTActionAck(next_index=0),
        ])

        with self.assertRaisesRegex(Exception, "Orchard action 0 twice"):
            client.zcash_sign_pczt(**sign_kwargs(actions))


if __name__ == '__main__':
    unittest.main()
