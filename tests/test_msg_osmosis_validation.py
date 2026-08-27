import common

from keepkeylib import messages_osmosis_pb2 as osmosis_proto
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types


class TestOsmosisValidation(common.KeepKeyTest):
    def setUp(self):
        super(TestOsmosisValidation, self).setUp()
        self.requires_firmware("7.14.2")
        self.requires_message("OsmosisSignTx")
        self.setup_mnemonic_nopin_nopassphrase()

    def _start_signing(self):
        ret = self.client.call_raw(osmosis_proto.OsmosisSignTx(
            address_n=[0x8000002c, 0x80000076, 0x80000000, 0, 0],
            account_number=1,
            chain_id="osmosis-1",
            fee_amount=5000,
            gas=300000,
            memo="",
            sequence=1,
            msg_count=1,
        ))
        self.assertIsInstance(ret, osmosis_proto.OsmosisMsgRequest)

    def _assert_missing_parameter_failure(self, ack):
        ret = self.client.call_raw(ack)
        self.assertIsInstance(ret, proto.Failure)
        self.assertEqual(ret.code, proto_types.Failure_FirmwareError)
        self.assertEndsWith(ret.message, "missing required parameters")

    def test_present_but_empty_amount_is_rejected_before_review(self):
        self._start_signing()
        send = osmosis_proto.OsmosisMsgSend(
            to_address="osmo1g9el7lzjwh9yun2c4jjzhy09j98vkhfx8tzcpt",
            amount="",
            denom="uosmo",
        )
        self.assertTrue(send.HasField("amount"))
        self._assert_missing_parameter_failure(
            osmosis_proto.OsmosisMsgAck(send=send))

    def test_ibc_omitted_amount_and_receiver_are_rejected_before_review(self):
        self._start_signing()
        transfer = osmosis_proto.OsmosisMsgIBCTransfer(
            sender="osmo1g9el7lzjwh9yun2c4jjzhy09j98vkhfx8tzcpt",
            source_channel="channel-0",
            source_port="transfer",
            revision_height="1",
            revision_number="1",
            denom="uosmo",
        )
        self.assertFalse(transfer.HasField("amount"))
        self.assertFalse(transfer.HasField("receiver"))
        self._assert_missing_parameter_failure(
            osmosis_proto.OsmosisMsgAck(ibc_transfer=transfer))
