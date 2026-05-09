import unittest

from keepkeylib import mapping
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_solana_pb2 as solana_proto
from keepkeylib import messages_ton_pb2 as ton_proto
from keepkeylib import messages_tron_pb2 as tron_proto


class TestMessageSigningProtocolBindings(unittest.TestCase):

    def test_solana_offchain_messages_are_mapped(self):
        self.assertEqual(proto.MessageType_SolanaSignOffchainMessage, 756)
        self.assertEqual(proto.MessageType_SolanaOffchainMessageSignature, 757)
        self.assertIs(
            mapping.get_class(proto.MessageType_SolanaSignOffchainMessage),
            solana_proto.SolanaSignOffchainMessage,
        )
        self.assertIs(
            mapping.get_class(proto.MessageType_SolanaOffchainMessageSignature),
            solana_proto.SolanaOffchainMessageSignature,
        )

    def test_tron_message_signing_messages_are_mapped(self):
        self.assertEqual(proto.MessageType_TronSignMessage, 1404)
        self.assertEqual(proto.MessageType_TronMessageSignature, 1405)
        self.assertEqual(proto.MessageType_TronVerifyMessage, 1406)
        self.assertEqual(proto.MessageType_TronSignTypedHash, 1407)
        self.assertEqual(proto.MessageType_TronTypedDataSignature, 1408)
        self.assertIs(
            mapping.get_class(proto.MessageType_TronSignMessage),
            tron_proto.TronSignMessage,
        )
        self.assertIs(
            mapping.get_class(proto.MessageType_TronMessageSignature),
            tron_proto.TronMessageSignature,
        )
        self.assertIs(
            mapping.get_class(proto.MessageType_TronVerifyMessage),
            tron_proto.TronVerifyMessage,
        )
        self.assertIs(
            mapping.get_class(proto.MessageType_TronSignTypedHash),
            tron_proto.TronSignTypedHash,
        )
        self.assertIs(
            mapping.get_class(proto.MessageType_TronTypedDataSignature),
            tron_proto.TronTypedDataSignature,
        )

    def test_ton_message_signing_messages_are_mapped(self):
        self.assertEqual(proto.MessageType_TonSignMessage, 1504)
        self.assertEqual(proto.MessageType_TonMessageSignature, 1505)
        self.assertIs(
            mapping.get_class(proto.MessageType_TonSignMessage),
            ton_proto.TonSignMessage,
        )
        self.assertIs(
            mapping.get_class(proto.MessageType_TonMessageSignature),
            ton_proto.TonMessageSignature,
        )


if __name__ == '__main__':
    unittest.main()
