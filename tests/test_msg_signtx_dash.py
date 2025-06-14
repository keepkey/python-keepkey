# This file is part of the Trezor project.
#
# Copyright (C) 2012-2018 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import unittest
import common
import binascii

from keepkeylib.tools import parse_path
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib import tx_api

class TestMsgSigntxDash(common.KeepKeyTest):
    def test_send_dash(self):
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.set_tx_api(tx_api.TxApiDash)
        inp1 = proto_types.TxInputType(
            address_n=parse_path("44'/5'/0'/0/0"),
            # dash:XdTw4G5AWW4cogGd7ayybyBNDbuB45UpgH
            amount=1000000000,
            prev_hash=binascii.unhexlify(
                "5579eaa64b2a0233e7d8d037f5a5afc957cedf48f1c4067e9e33ca6df22ab04f"
            ),
            prev_index=1,
            script_type=proto_types.SPENDADDRESS,
        )
        out1 = proto_types.TxOutputType(
            address="XpTc36DPAeWmaueNBA9JqCg2GC8XDLKSYe",
            amount=999999000,
            script_type=proto_types.PAYTOADDRESS,
        )
        with self.client:
            self.client.set_expected_responses(
                [
                    proto.TxRequest(
                        request_type=proto_types.TXINPUT,
                        details=proto_types.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXMETA,
                        details=proto_types.TxRequestDetailsType(tx_hash=inp1.prev_hash),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXINPUT,
                        details=proto_types.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXINPUT,
                        details=proto_types.TxRequestDetailsType(
                            request_index=1, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(
                            request_index=1, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(request_index=0),
                    ),
                    proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                    proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                    proto.TxRequest(
                        request_type=proto_types.TXINPUT,
                        details=proto_types.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(request_type=proto_types.TXFINISHED),
                ]
            )
            _, serialized_tx = self.client.sign_tx(
                "Dash", [inp1], [out1]
            )

        self.assertEqual(
            binascii.hexlify(serialized_tx),
            "01000000014fb02af26dca339e7e06c4f148dfce57c9afa5f537d0d8e733022a4ba6ea7955010000006a4730440220387be4d1e4b5e355614091416373e99e1a3532b8cc9a8629368060aff2681bdb02200a0c4a5e9eb2ce6adb6c2e01ec8f954463dcc04f531ed8a89a2b40019d5aeb0b012102936f80cac2ba719ddb238646eb6b78a170a55a52a9b9f08c43523a4a6bd5c896ffffffff0118c69a3b000000001976a9149710d6545407e78c326aa8c8ae386ec7f883b0af88ac00000000"
        )

    def test_send_dash_dip2_input(self):
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.set_tx_api(tx_api.TxApiDash)
        inp1 = proto_types.TxInputType(
            address_n=parse_path("44'/5'/0'/0/0"),
            # dash:XdTw4G5AWW4cogGd7ayybyBNDbuB45UpgH
            amount=4095000260,
            prev_hash=binascii.unhexlify(
                "15575a1c874bd60a819884e116c42e6791c8283ce1fc3b79f0d18531a61bbb8a"
            ),
            prev_index=1,
            script_type=proto_types.SPENDADDRESS,
        )
        out1 = proto_types.TxOutputType(
            address_n=parse_path("44'/5'/0'/1/0"),
            amount=4000000000,
            script_type=proto_types.PAYTOADDRESS,
        )
        out2 = proto_types.TxOutputType(
            address="XrEFMNkxeipYHgEQKiJuqch8XzwrtfH5fm",
            amount=95000000,
            script_type=proto_types.PAYTOADDRESS,
        )
        with self.client:
            self.client.set_expected_responses(
                [
                    proto.TxRequest(
                        request_type=proto_types.TXINPUT,
                        details=proto_types.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXMETA,
                        details=proto_types.TxRequestDetailsType(tx_hash=inp1.prev_hash),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXINPUT,
                        details=proto_types.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(
                            request_index=1, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXEXTRADATA,
                        details=proto_types.TxRequestDetailsType(
                            extra_data_len=39,
                            extra_data_offset=0,
                            tx_hash=inp1.prev_hash,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(request_index=1),
                    ),
                    proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                    proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                    proto.TxRequest(
                        request_type=proto_types.TXINPUT,
                        details=proto_types.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(request_index=1),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(request_index=1),
                    ),
                    proto.TxRequest(request_type=proto_types.TXFINISHED),
                ]
            )
            _, serialized_tx = self.client.sign_tx(
                "Dash", [inp1], [out1, out2]
            )

        self.assertEqual(
            binascii.hexlify(serialized_tx),
            "01000000018abb1ba63185d1f0793bfce13c28c891672ec416e18498810ad64b871c5a5715010000006b483045022100f0442b6d9c7533cd6f74afa993b280ed9475276d69df4dac631bc3b5591ba71b022051daf125372c1c477681bbd804a6445d8ff6840901854fb0b485b1c6c7866c44012102936f80cac2ba719ddb238646eb6b78a170a55a52a9b9f08c43523a4a6bd5c896ffffffff0200286bee000000001976a914fd61dd017dad1f505c0511142cc9ac51ef3a5beb88acc095a905000000001976a914aa7a6a1f43dfc34d17e562ce1845b804b73fc31e88ac00000000"
        )

if __name__ == '__main__':
    unittest.main()

