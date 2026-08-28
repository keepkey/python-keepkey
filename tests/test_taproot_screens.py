"""Gate-3 OLED capture: long bech32 addresses on the verification screen."""
import common
import unittest

from common import KeepKeyTest
from keepkeylib import ckd_public as bip32
from keepkeylib import types_pb2 as proto_types
from keepkeylib.tools import parse_path


class TestTaprootScreens(KeepKeyTest):

    def test_show_taproot_receive_address(self):
        self.requires_taproot()
        self.setup_mnemonic_abandon()
        self.client.clear_session()
        addr = self.client.get_address(
            "Bitcoin", parse_path("86'/0'/0'/0/0"), True, None,
            script_type=proto_types.SPENDTAPROOT)
        self.assertEqual(
            addr,
            'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr')

    def test_show_p2wsh_multisig_address(self):
        """Native segwit multisig: 62 chars, same as p2tr. Predates taproot."""
        self.setup_mnemonic_allallall()
        self.client.clear_session()
        nodes = [self.client.get_public_node(parse_path("999'/1'/%d'" % i))
                 for i in range(1, 4)]
        multisig = proto_types.MultisigRedeemScriptType(
            pubkeys=[proto_types.HDNodePathType(
                node=bip32.deserialize(n.xpub), address_n=[2, 0]) for n in nodes],
            signatures=[b'', b'', b''],
            m=2,
        )
        addr = self.client.get_address(
            "Testnet", parse_path("999'/1'/1'/2/0"), True, multisig,
            script_type=proto_types.SPENDWITNESS)
        print("\nP2WSH address (%d chars): %s" % (len(addr), addr))


if __name__ == '__main__':
    unittest.main()
