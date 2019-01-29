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

import common

from binascii import hexlify, unhexlify
import unittest

from keepkeylib import ckd_public as bip32
from common import KeepKeyTest

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from keepkeylib.tx_api import TxApiTestnet


class TestMsgSigntxSegwit(KeepKeyTest):

    def test_send_p2sh(self):
        self.setup_mnemonic_allallall()
        self.client.set_tx_api(TxApiTestnet)
        inp1 = proto_types.TxInputType(
            address_n=parse_path("49'/1'/0'/1/0"),
            # 2N1LGaGg836mqSQqiuUBLfcyGBhyZbremDX
            amount=123456789,
            prev_hash=unhexlify('20912f98ea3ed849042efed0fdac8cb4fc301961c5988cba56902d8ffb61c337'),
            prev_index=0,
            script_type=proto_types.SPENDP2SHWITNESS,
        )
        out1 = proto_types.TxOutputType(
            address='mhRx1CeVfaayqRwq5zgRQmD7W5aWBfD5mC',
            amount=12300000,
            script_type=proto_types.PAYTOADDRESS,
        )
        out2 = proto_types.TxOutputType(
            address='2N1LGaGg836mqSQqiuUBLfcyGBhyZbremDX',
            script_type=proto_types.PAYTOADDRESS,
            amount=123456789 - 11000 - 12300000,
        )
        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures, serialized_tx) = self.client.sign_tx('Testnet', [inp1], [out1, out2])

        self.assertEquals(hexlify(serialized_tx), b'0100000000010137c361fb8f2d9056ba8c98c5611930fcb48cacfdd0fe2e0449d83eea982f91200000000017160014d16b8c0680c61fc6ed2e407455715055e41052f5ffffffff02e0aebb00000000001976a91414fdede0ddc3be652a0ce1afbc1b509a55b6b94888ac3df39f060000000017a91458b53ea7f832e8f096e896b8713a8c6df0e892ca8702483045022100ccd253bfdf8a5593cd7b6701370c531199f0f05a418cd547dfc7da3f21515f0f02203fa08a0753688871c220648f9edadbdb98af42e5d8269364a326572cf703895b012103e7bfe10708f715e8538c92d46ca50db6f657bbc455b7494e6a0303ccdb868b7900000000')

    def test_send_mixed(self):
        self.setup_mnemonic_allallall()
        self.client.set_tx_api(TxApiTestnet)
        inp1 = proto_types.TxInputType(
            address_n=parse_path("49'/1'/0'/1/0"),
            # 2N1LGaGg836mqSQqiuUBLfcyGBhyZbremDX
            amount=123456789,
            prev_hash=unhexlify('20912f98ea3ed849042efed0fdac8cb4fc301961c5988cba56902d8ffb61c337'),
            prev_index=0,
            script_type=proto_types.SPENDP2SHWITNESS,
        )

        inp2 = proto_types.TxInputType(
            address_n=parse_path("44'/1'/0'/0/0"),
            # amount=31000000,
            prev_hash=unhexlify('e5040e1bc1ae7667ffb9e5248e90b2fb93cd9150234151ce90e14ab2f5933bcd'),
            prev_index=0,
            script_type=proto_types.PAYTOADDRESS,
        )

        inp3 = proto_types.TxInputType(
            address_n=parse_path("84'/1'/0'/1/0"),
            amount=7289000,
            prev_hash=unhexlify('65b811d3eca0fe6915d9f2d77c86c5a7f19bf66b1b1253c2c51cb4ae5f0c017b'),
            prev_index=1,
            script_type=proto_types.SPENDWITNESS
        )

        out1 = proto_types.TxOutputType(
            address_n=parse_path("44'/1'/0'/1/0"),
            amount=900000,
            script_type=proto_types.PAYTOADDRESS,
        )
        out2 = proto_types.TxOutputType(
            address='2N1LGaGg836mqSQqiuUBLfcyGBhyZbremDX',
            script_type=proto_types.PAYTOADDRESS,
            amount=123456789 + 31000000 + 7289000 - 9000000,
        )
        with self.client:
            (signatures, serialized_tx) = self.client.sign_tx('Testnet', [inp1, inp2, inp3], [out1, out2])

        self.assertEquals(hexlify(serialized_tx), b'0100000000010337c361fb8f2d9056ba8c98c5611930fcb48cacfdd0fe2e0449d83eea982f91200000000017160014d16b8c0680c61fc6ed2e407455715055e41052f5ffffffffcd3b93f5b24ae190ce5141235091cd93fbb2908e24e5b9ff6776aec11b0e04e5000000006a47304402200451ce6fb777e9023a9d9e39370384de734562dc081ab75397d934b3be21218f02207882a9b1f1d27694bba71a9f4cf01eead6d4b517c5239cabe9042dc05a4b7dd10121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff7b010c5faeb41cc5c253121b6bf69bf1a7c5867cd7f2d91569fea0ecd311b8650100000000ffffffff02a0bb0d00000000001976a9143d3cca567e00a04819742b21a696a67da796498b88ac3db71a090000000017a91458b53ea7f832e8f096e896b8713a8c6df0e892ca870247304402200a2e68318041e40d0ff6e87a070be4b80e48a756410d90551c9fdd733dbf2e1202201a853ac548f47fa1727019fc5cbc84c49678be6eed8554357c608ff7d2390db8012103e7bfe10708f715e8538c92d46ca50db6f657bbc455b7494e6a0303ccdb868b79000247304402202c14d58e6d0788ffd8165e4a5892dc39d0955a62c471125cc1771a37675dc0e402203e52c774404200bfefbbbe07153bf96efa7787b1607f4b1437c3857380e034c4012103505647c017ff2156eb6da20fae72173d3b681a1d0a629f95f49e884db300689f00000000')

    def test_send_p2sh_change(self):
        self.setup_mnemonic_allallall()
        self.client.set_tx_api(TxApiTestnet)
        inp1 = proto_types.TxInputType(
            address_n=parse_path("49'/1'/0'/1/0"),
            # 2N1LGaGg836mqSQqiuUBLfcyGBhyZbremDX
            amount=123456789,
            prev_hash=unhexlify('20912f98ea3ed849042efed0fdac8cb4fc301961c5988cba56902d8ffb61c337'),
            prev_index=0,
            script_type=proto_types.SPENDP2SHWITNESS,
        )
        out1 = proto_types.TxOutputType(
            address='mhRx1CeVfaayqRwq5zgRQmD7W5aWBfD5mC',
            amount=12300000,
            script_type=proto_types.PAYTOADDRESS,
        )
        out2 = proto_types.TxOutputType(
            address_n=parse_path("49'/1'/0'/1/0"),
            script_type=proto_types.PAYTOP2SHWITNESS,
            amount=123456789 - 11000 - 12300000,
        )
        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures, serialized_tx) = self.client.sign_tx('Testnet', [inp1], [out1, out2])

        self.assertEquals(hexlify(serialized_tx), b'0100000000010137c361fb8f2d9056ba8c98c5611930fcb48cacfdd0fe2e0449d83eea982f91200000000017160014d16b8c0680c61fc6ed2e407455715055e41052f5ffffffff02e0aebb00000000001976a91414fdede0ddc3be652a0ce1afbc1b509a55b6b94888ac3df39f060000000017a91458b53ea7f832e8f096e896b8713a8c6df0e892ca8702483045022100ccd253bfdf8a5593cd7b6701370c531199f0f05a418cd547dfc7da3f21515f0f02203fa08a0753688871c220648f9edadbdb98af42e5d8269364a326572cf703895b012103e7bfe10708f715e8538c92d46ca50db6f657bbc455b7494e6a0303ccdb868b7900000000')

    def test_send_multisig_1(self):
        self.setup_mnemonic_allallall()
        self.client.set_tx_api(TxApiTestnet)
        nodes = map(lambda index: self.client.get_public_node(parse_path("999'/1'/%d'" % index)), range(1, 4))
        multisig = proto_types.MultisigRedeemScriptType(
            pubkeys=list(map(lambda n: proto_types.HDNodePathType(node=bip32.deserialize(n.xpub), address_n=[2, 0]), nodes)),
            signatures=[b'', b'', b''],
            m=2,
        )

        inp1 = proto_types.TxInputType(
            address_n=parse_path("999'/1'/1'/2/0"),
            prev_hash=unhexlify('9c31922be756c06d02167656465c8dc83bb553bf386a3f478ae65b5c021002be'),
            prev_index=1,
            script_type=proto_types.SPENDP2SHWITNESS,
            multisig=multisig,
            amount=1610436
        )

        out1 = proto_types.TxOutputType(address='mhRx1CeVfaayqRwq5zgRQmD7W5aWBfD5mC',
                                  amount=1605000,
                                  script_type=proto_types.PAYTOADDRESS)

        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures1, _) = self.client.sign_tx('Testnet', [inp1], [out1])
            # store signature
            inp1.multisig.signatures[0] = signatures1[0]
            # sign with third key
            inp1.address_n[2] = 0x80000003
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures2, serialized_tx) = self.client.sign_tx('Testnet', [inp1], [out1])

        self.assertEquals(hexlify(serialized_tx), b'01000000000101be0210025c5be68a473f6a38bf53b53bc88d5c46567616026dc056e72b92319c01000000232200201e8dda334f11171190b3da72e526d441491464769679a319a2f011da5ad312a1ffffffff01887d1800000000001976a91414fdede0ddc3be652a0ce1afbc1b509a55b6b94888ac040047304402205b44c20cf2681690edaaf7cd2e30d4704124dd8b7eb1fb7f459d3906c3c374a602205ca359b6544ce2c101c979899c782f7d141c3b0454ea69202b1fb4c09d3b715701473044022052fafa64022554ae436dbf781e550bf0d326fef31eea1438350b3ff1940a180102202851bd19203b7fe8582a9ef52e82aa9f61cd52d4bcedfe6dcc0cf782468e6a8e01695221038e81669c085a5846e68e03875113ddb339ecbb7cb11376d4163bca5dc2e2a0c1210348c5c3be9f0e6cf1954ded1c0475beccc4d26aaa9d0cce2dd902538ff1018a112103931140ebe0fbbb7df0be04ed032a54e9589e30339ba7bbb8b0b71b15df1294da53ae00000000')

    def test_attack_change_input_address(self):
        # This unit test attempts to modify input address after the Trezor checked
        # that it matches the change output

        self.setup_mnemonic_allallall()
        self.client.set_tx_api(TxApiTestnet)
        inp1 = proto_types.TxInputType(
            address_n=parse_path("49'/1'/0'/1/0"),
            # 2N1LGaGg836mqSQqiuUBLfcyGBhyZbremDX
            amount=123456789,
            prev_hash=unhexlify('20912f98ea3ed849042efed0fdac8cb4fc301961c5988cba56902d8ffb61c337'),
            prev_index=0,
            script_type=proto_types.SPENDP2SHWITNESS,
        )
        out1 = proto_types.TxOutputType(
            address='mhRx1CeVfaayqRwq5zgRQmD7W5aWBfD5mC',
            amount=12300000,
            script_type=proto_types.PAYTOADDRESS,
        )
        out2 = proto_types.TxOutputType(
            address_n=parse_path("49'/1'/12345'/1/0"),
            script_type=proto_types.PAYTOP2SHWITNESS,
            amount=123456789 - 11000 - 12300000,
        )

        global run_attack
        run_attack = True

        def attack_processor(req, msg):
            global run_attack

            if req.details.tx_hash is not None:
                return msg

            if req.request_type != proto.TXINPUT:
                return msg

            if req.details.request_index != 0:
                return msg

            if not run_attack:
                return msg

            msg.inputs[0].address_n[2] = 12345 + 0x80000000
            run_attack = False
            return msg

        # Test if the transaction can be signed normally
        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmTransferToAccount),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXFINISHED),
            ])
            (signatures, serialized_tx) = self.client.sign_tx('Testnet', [inp1], [out1, out2])

        self.assertEquals(hexlify(serialized_tx), b'0100000000010137c361fb8f2d9056ba8c98c5611930fcb48cacfdd0fe2e0449d83eea982f91200000000017160014d16b8c0680c61fc6ed2e407455715055e41052f5ffffffff02e0aebb00000000001976a91414fdede0ddc3be652a0ce1afbc1b509a55b6b94888ac3df39f060000000017a914dae9e09a7fc3bbe5a716fffec1bbb340b82a4fb9870248304502210099b5c4f8fd4402c9c0136fee5f711137d64fc9f14587e01bfa7798f5428f845d0220253e21c98f5b1b64efae69bc2ea9799c5620a43450baa6762a0c3cf4fdc886e5012103e7bfe10708f715e8538c92d46ca50db6f657bbc455b7494e6a0303ccdb868b7900000000')

        # Now run the attack, must trigger the exception
        with self.client:
            self.client.set_expected_responses([
                proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_ConfirmOutput),
                proto.TxRequest(request_type=proto_types.TXOUTPUT, details=proto_types.TxRequestDetailsType(request_index=1)),
                proto.ButtonRequest(code=proto_types.ButtonRequest_SignTx),
                #proto.TxRequest(request_type=proto_types.TXINPUT, details=proto_types.TxRequestDetailsType(request_index=0)),
                #proto.Failure(code=proto_types.Failure_Other),
            ])
            self.assertRaises(CallException, self.client.sign_tx, 'Testnet', [inp1], [out1, out2], debug_processor=attack_processor)
            #self.assertEquals(exc.value.args[0], proto.FailureType.Failure_Other)
            #self.assertEquals(exc.value.args[1].endswith("Failed to compile input")

if __name__ == '__main__':
    unittest.main()
