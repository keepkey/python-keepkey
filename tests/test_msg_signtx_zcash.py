import unittest
import common
import binascii

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tx_api import TxApiZcashTestnet

class TestMsgSigntx(common.KeepKeyTest):

    def test_one_one_fee_overthreshold(self):
        self.setup_mnemonic_allallall()

        # tx: 93373e63cc626c4a7d049ad775d6511bb5eba985f142db660c9b9f955c722f5c
        # input 0: 1.234567 TAZ

        inp1 = proto_types.TxInputType(address_n=[2147483692, 2147483649, 2147483648, 0, 0],  # tmQoJ3PTXgQLaRRZZYT6xk8XtjRbr2kCqwu
                             # amount=123456700,
                             prev_hash=binascii.unhexlify(b'c8ff96d72e80c01792146d8f0970cbc970882fb315ab1ae043342b4d455e6b56'),
                             prev_index=0,
                             )

        out1 = proto_types.TxOutputType(address='tmJ1xYxP8XNTtCoDgvdmQPSrxh5qZJgy65Z',
                              amount=123456700 - 1940,
                              script_type=proto_types.PAYTOADDRESS,
                              )

        with self.client:
            self.client.set_tx_api(TxApiZcashTestnet)
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"c8ff96d72e80c01792146d8f0970cbc970882fb315ab1ae043342b4d455e6b56"))),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify(b"c8ff96d72e80c01792146d8f0970cbc970882fb315ab1ae043342b4d455e6b56"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify(b"c8ff96d72e80c01792146d8f0970cbc970882fb315ab1ae043342b4d455e6b56"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1, tx_hash=binascii.unhexlify(b"c8ff96d72e80c01792146d8f0970cbc970882fb315ab1ae043342b4d455e6b56"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_FeeOverThreshold),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),

                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),

            ])

            (signatures, serialized_tx) = self.client.sign_tx('Zcash Testnet', [inp1, ], [out1, ])

        # Accepted by network: tx dcc2a10894e0e8a785c2afd4de2d958207329b9acc2b987fd768a09c5efc4547
        self.assertEqual(binascii.hexlify(serialized_tx), b'0100000001566b5e454d2b3443e01aab15b32f8870c9cb70098f6d149217c0802ed796ffc8000000006a473044022076ab59722b9e3a66dbf66708ace85210be7f5706ba79c18648389180ea24ba1702203e7e4b8c1735e0f290129d15fbaf743d87a0b98f2349bd50ff6c2faf5ec5843c0121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff0128c55b07000000001976a914255b157a678a10021243307e4bb58f36375aa80e88ac00000000')

    def test_one_one_fee(self):
        self.setup_mnemonic_allallall()

        # tx: 93373e63cc626c4a7d049ad775d6511bb5eba985f142db660c9b9f955c722f5c
        # input 0: 1.234567 TAZ

        inp1 = proto_types.TxInputType(address_n=[2147483692, 2147483649, 2147483648, 0, 0],  # tmQoJ3PTXgQLaRRZZYT6xk8XtjRbr2kCqwu
                             # amount=123456700,
                             prev_hash=binascii.unhexlify(b'93373e63cc626c4a7d049ad775d6511bb5eba985f142db660c9b9f955c722f5c'),
                             prev_index=0,
                             )

        out1 = proto_types.TxOutputType(address='tmJ1xYxP8XNTtCoDgvdmQPSrxh5qZJgy65Z',
                              amount=123456700 - 1940,
                              script_type=proto_types.PAYTOADDRESS,
                              )

        with self.client:
            self.client.set_tx_api(TxApiZcashTestnet)
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXMETA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"93373e63cc626c4a7d049ad775d6511bb5eba985f142db660c9b9f955c722f5c"))),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0, tx_hash=binascii.unhexlify(b"93373e63cc626c4a7d049ad775d6511bb5eba985f142db660c9b9f955c722f5c"))),
                proto.TxRequest(request_type=proto_types.TXEXTRADATA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"93373e63cc626c4a7d049ad775d6511bb5eba985f142db660c9b9f955c722f5c"),extra_data_offset=0, extra_data_len=1024)),
                proto.TxRequest(request_type=proto_types.TXEXTRADATA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"93373e63cc626c4a7d049ad775d6511bb5eba985f142db660c9b9f955c722f5c"),extra_data_offset=1024, extra_data_len=1024)),
                proto.TxRequest(request_type=proto_types.TXEXTRADATA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"93373e63cc626c4a7d049ad775d6511bb5eba985f142db660c9b9f955c722f5c"),extra_data_offset=2048, extra_data_len=1024)),
                proto.TxRequest(request_type=proto_types.TXEXTRADATA, details=proto_types.TxRequestDetailsType(tx_hash=binascii.unhexlify(b"93373e63cc626c4a7d049ad775d6511bb5eba985f142db660c9b9f955c722f5c"),extra_data_offset=3072, extra_data_len=629)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])

            (signatures, serialized_tx) = self.client.sign_tx('Zcash Testnet', [inp1, ], [out1, ])

        # Accepted by network: tx dcc2a10894e0e8a785c2afd4de2d958207329b9acc2b987fd768a09c5efc4547
        self.assertEqual(binascii.hexlify(serialized_tx), b'01000000015c2f725c959f9b0c66db42f185a9ebb51b51d675d79a047d4a6c62cc633e3793000000006a4730440220670b2b63d749a7038f9aea6ddf0302fe63bdcad93dafa4a89a1f0e7300ae2484022002c50af43fd867490cea0c527273c5828ff1b9a5115678f155a1830737cf29390121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff0128c55b07000000001976a9145b157a678a10021243307e4bb58f36375aa80e1088ac00000000')

if __name__ == '__main__':
    unittest.main()
