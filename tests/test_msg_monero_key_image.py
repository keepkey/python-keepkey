"""Monero key-image sync (MoneroKeyImageExportInit / SyncStep / SyncFinal).

The wallet sends outputs it owns; the device returns each key image with
Core's one-member ring signature, encrypted under a key it releases only at
the end of a correctly bound transcript. Key images are checked against
Monero Core fixtures; decryption and the signature check are independent of
the firmware (monero_fixtures.py).
"""

import unittest

import common
import monero_fixtures as xmr
from keepkeylib import messages_monero_pb2 as monero_proto
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import CallException


def details(output, explicit=True):
    td = monero_proto.MoneroTransferDetails(
        out_key=bytes.fromhex(output['output_public']),
        tx_pub_key=bytes.fromhex(output['tx_public']),
        internal_output_index=output['index'])
    if explicit:
        td.sub_addr_major = output['major']
        td.sub_addr_minor = output['minor']
    return td


def subaddresses():
    return [monero_proto.MoneroSubAddressIndicesList(account=0, minor_indices=[1]),
            monero_proto.MoneroSubAddressIndicesList(account=1, minor_indices=[0]),
            monero_proto.MoneroSubAddressIndicesList(account=100, minor_indices=[100])]


class TestMsgMoneroKeyImage(common.KeepKeyTest):

    def setUp(self):
        super(TestMsgMoneroKeyImage, self).setUp()
        self.requires_firmware(common.CAPABILITIES_SINCE)
        self.requires_fullFeature()
        self.requires_release_capability('monero-signing')
        self.setup_mnemonic_abandon()

    def init(self, outputs, transcript=None, count=None):
        return self.client.monero_key_image_export_init(
            num=len(outputs) if count is None else count,
            hash=xmr.transcript_hash(outputs) if transcript is None else transcript,
            address_n=xmr.path(0), network_type=0, subs=subaddresses())

    def check_exported(self, outputs, exported, key):
        self.assertEqual(len(exported), len(outputs))
        for output, item in zip(outputs, exported):
            self.assertEqual(len(item.iv), 12)
            self.assertEqual(len(item.blob), 112)
            plain = xmr.decrypt(key, item.iv, item.blob)
            self.assertEqual(plain[:32].hex(), output['key_image'])
            self.assertTrue(xmr.ring_signature_valid(plain, output))

    def test_key_images_match_monero_core(self):
        outputs = xmr.OWNED_OUTPUTS
        with xmr.Screens(self.client) as screens:
            ack = self.init(outputs)
        self.assertIsInstance(ack, monero_proto.MoneroKeyImageExportInitAck)
        self.assertTrue(screens.shown("Monero Mainnet"))
        self.assertTrue(screens.shown(
            "Sync key images of 4 outputs? This computer will see which of "
            "them are spent."))
        # Batches of three and one; half the outputs name their subaddress,
        # the device finds the others among the init's subaddresses.
        exported = []
        for start in range(0, len(outputs), 3):
            batch = outputs[start:start + 3]
            step = self.client.monero_key_image_sync_step(
                [details(o, explicit=i % 2 == 0) for i, o in enumerate(batch, start)])
            self.assertIsInstance(step, monero_proto.MoneroKeyImageSyncStepAck)
            exported += step.kis
        final = self.client.monero_key_image_sync_final()
        self.assertIsInstance(final, monero_proto.MoneroKeyImageSyncFinalAck)
        self.assertEqual(len(final.enc_key), 32)
        self.check_exported(outputs, exported, final.enc_key)

    def test_cancel_at_consent_starts_nothing(self):
        outputs = xmr.OWNED_OUTPUTS[:1]
        with xmr.Screens(self.client, [False]):
            with self.assertRaises(CallException) as caught:
                self.init(outputs)
        self.assertEqual(caught.exception.args[0],
                         proto_types.Failure_ActionCancelled)
        step = self.client.call_raw(monero_proto.MoneroKeyImageSyncStepRequest(
            tdis=[details(outputs[0])]))
        self.assertIsInstance(step, proto.Failure)
        self.assertEqual(step.code, proto_types.Failure_UnexpectedMessage)

    def test_wrong_transcript_releases_no_key(self):
        outputs = xmr.OWNED_OUTPUTS[:2]
        self.init(outputs, transcript=b'\x00' * 32)
        self.client.monero_key_image_sync_step([details(o) for o in outputs])
        final = self.client.call_raw(monero_proto.MoneroKeyImageSyncFinalRequest())
        self.assertIsInstance(final, proto.Failure)
        self.assertEqual(final.code, proto_types.Failure_SyntaxError)

    def test_missing_output_releases_no_key(self):
        outputs = xmr.OWNED_OUTPUTS[:2]
        self.init(outputs)
        self.client.monero_key_image_sync_step([details(outputs[0])])
        final = self.client.call_raw(monero_proto.MoneroKeyImageSyncFinalRequest())
        self.assertIsInstance(final, proto.Failure)

    def test_foreign_output_ends_the_sync(self):
        outputs = xmr.OWNED_OUTPUTS[:2]
        self.init(outputs)
        foreign = details(outputs[0])
        foreign.internal_output_index = 7  # derives a different one-time key
        step = self.client.call_raw(monero_proto.MoneroKeyImageSyncStepRequest(
            tdis=[foreign]))
        self.assertIsInstance(step, proto.Failure)
        self.assertEqual(step.code, proto_types.Failure_SyntaxError)
        again = self.client.call_raw(monero_proto.MoneroKeyImageSyncStepRequest(
            tdis=[details(outputs[1])]))
        self.assertIsInstance(again, proto.Failure)
        self.assertEqual(again.code, proto_types.Failure_UnexpectedMessage)

    def test_features_keep_the_sync_and_ping_ends_it(self):
        outputs = xmr.OWNED_OUTPUTS[:2]
        self.init(outputs)
        self.client.call(proto.GetFeatures())
        step = self.client.monero_key_image_sync_step([details(outputs[0])])
        self.assertIsInstance(step, monero_proto.MoneroKeyImageSyncStepAck)
        self.client.ping('ends the sync')
        step = self.client.call_raw(monero_proto.MoneroKeyImageSyncStepRequest(
            tdis=[details(outputs[1])]))
        self.assertIsInstance(step, proto.Failure)
        self.assertEqual(step.code, proto_types.Failure_UnexpectedMessage)

    def test_invalid_init_is_refused(self):
        outputs = xmr.OWNED_OUTPUTS[:1]
        for fields in (dict(num=0), dict(num=65), dict(hash=b'\x00' * 31),
                       dict(address_n=[xmr.H + 44, xmr.H + 128, 0])):
            request = dict(num=1, hash=xmr.transcript_hash(outputs),
                           address_n=xmr.path(0))
            request.update(fields)
            with self.subTest(fields=fields):
                resp = self.client.call_raw(
                    monero_proto.MoneroKeyImageExportInitRequest(**request))
                self.assertIsInstance(resp, proto.Failure)
                self.assertEqual(resp.code, proto_types.Failure_SyntaxError)


if __name__ == '__main__':
    unittest.main()
