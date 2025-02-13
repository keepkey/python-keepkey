# This file is part of the Trezor project.
#
# Copyright (C) 2018 KeepKey
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
#
# The script has been modified for KeepKey Device.

from datetime import datetime
import unittest
import binascii
import json
import common
import keepkeylib.ckd_public as bip32
from keepkeylib import types_pb2, messages_eos_pb2 as proto
from keepkeylib.client import CallException
from keepkeylib import eos
from keepkeylib.tools import parse_path
from keepkeylib.eos import parse_action

EOS_CHAIN_ID = binascii.unhexlify("aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906")

class TestMsgEosSignTx(common.KeepKeyTest):

    def test_name_to_number(self):
        self.requires_fullFeature()
        self.assertEqual(eos.name_to_number("eosio"), 0x5530ea0000000000)
        self.assertEqual(eos.name_to_number("eosio.token"), 0x5530EA033482A600)
        self.assertEqual(eos.name_to_number("eos42freedom"), 0x5530412eea526920)

    def header(self):
        return proto.EosTxHeader(
            expiration=1544644800, # 2018-12-12 20:00:00 UTC
            ref_block_num=0,
            ref_block_prefix=0,
            max_net_usage_words=0,
            max_cpu_usage_ms=0,
            delay_sec=((3 * 60) + 42) * 60 + 17
            )

    def action_transfer(self):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio.token'),
                    name=eos.name_to_number('transfer'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio.token'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionTransfer(
                    sender=eos.name_to_number('mcfakeface'),
                    receiver=eos.name_to_number('glutton'),
                    quantity=proto.EosAsset(
                        amount=42,
                        symbol=0x004e45584f4600),
                    memo="For fox treats"))

    def action_delegatebw(self, transfer):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('delegatebw'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio.token'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionDelegate(
                    sender=eos.name_to_number('fromfromfrom'),
                    receiver=eos.name_to_number('totototototo'),
                    cpu_quantity=proto.EosAsset(
                        amount=15,
                        symbol=0x004e45584f4600 | 0x01),
                    net_quantity=proto.EosAsset(
                        amount=15,
                        symbol=0x004e45584f4600 | 0x01),
                    transfer=transfer))

    def action_undelegatebw(self):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('undelegatebw'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio.token'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionUndelegate(
                    sender=eos.name_to_number('inininininin'),
                    receiver=eos.name_to_number('outoutoutout'),
                    cpu_quantity=proto.EosAsset(
                        amount=42,
                        symbol=0x004e45584f4600 | 0x02),
                    net_quantity=proto.EosAsset(
                        amount=170,
                        symbol=0x004e45584f4600 | 0x07)))

    def action_refund(self):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('refund'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionRefund(
                    owner=eos.name_to_number('memememememe')))

    def action_buyram(self):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('buyram'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionBuyRam(
                    payer=eos.name_to_number('memememememe'),
                    receiver=eos.name_to_number('youyouyou'),
                    quantity=proto.EosAsset(
                        amount=1,
                        symbol=0x004e45584f4600 | 0x01)))

    def action_buyrambytes(self):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('buyrambytes'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionBuyRamBytes(
                    payer=eos.name_to_number('memememememe'),
                    receiver=eos.name_to_number('youyouyou'),
                    bytes=256))

    def action_sellram(self):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('sellram'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionSellRam(
                    account=eos.name_to_number('memememememe'),
                    bytes=256))

    def action_voteproducer_proxy(self):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('voteproducer'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionVoteProducer(
                    voter=eos.name_to_number('memememememe'),
                    proxy=eos.name_to_number('youyouyou')))

    def action_voteproducers(self):
        producers = [eos.name_to_number('aaaaaaaaaaaa'),
                     eos.name_to_number('bbbbbbbbbbbb'),
                     eos.name_to_number('cccccccccccc'),
                     eos.name_to_number('dddddddddddd'),
                     eos.name_to_number('eeeeeeeeeeee'),
                     eos.name_to_number('ffffffffffff'),
                     eos.name_to_number('gggggggggggg'),
                     eos.name_to_number('hhhhhhhhhhhh'),
                     eos.name_to_number('iiiiiiiiiiii'),
                     eos.name_to_number('jjjjjjjjjjjj'),
                     eos.name_to_number('kkkkkkkkkkkk'),
                     eos.name_to_number('llllllllllll'),
                     eos.name_to_number('mmmmmmmmmmmm'),
                     eos.name_to_number('nnnnnnnnnnnn'),
                     eos.name_to_number('oooooooooooo'),
                     eos.name_to_number('pppppppppppp'),
                     eos.name_to_number('qqqqqqqqqqqq'),
                     eos.name_to_number('rrrrrrrrrrrr'),
                     eos.name_to_number('ssssssssssss'),
                     eos.name_to_number('tttttttttttt'),
                     eos.name_to_number('uuuuuuuuuuuu'),
                     eos.name_to_number('vvvvvvvvvvvv'),
                     eos.name_to_number('wwwwwwwwwwww'),
                     eos.name_to_number('xxxxxxxxxxxx'),
                     eos.name_to_number('yyyyyyyyyyyy'),
                     eos.name_to_number('zzzzzzzzzzzz')]
        producers.sort()
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('voteproducer'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionVoteProducer(
                    voter=eos.name_to_number('memememememe'),
                    producers=producers))

    def action_voteproducer_cancel(self):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('voteproducer'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionVoteProducer(
                    voter=eos.name_to_number('memememememe')))

    def action_updateauth(self, is_slip48):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('updateauth'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio'),
                            permission=eos.name_to_number('owner'))
                    ]),
                proto.EosActionUpdateAuth(
                    account=eos.name_to_number('memememememe'),
                    permission=eos.name_to_number('active'),
                    parent=eos.name_to_number('momomomomom'),
                    auth=self.authorization(is_slip48)))

    def authorization(self, is_slip48):
        if is_slip48:
            # SLIP48 permissions
            return proto.EosAuthorization(
                threshold=1,
                keys=[
                    proto.EosAuthorizationKey(
                        type=1,
                        address_n=parse_path("m/48'/4'/1'/0'/0'"),
                        weight=1)
                ],
                accounts=[
                    proto.EosAuthorizationAccount(
                        account=proto.EosPermissionLevel(
                            actor=eos.name_to_number('memememememe'),
                            permission=eos.name_to_number('active')),
                        weight=1)
                ],
                waits=[
                ])

        else:
            # SLIP44 / Exodus-style permissions
            return proto.EosAuthorization(
                threshold=2,
                keys=[
                    proto.EosAuthorizationKey(
                        type=1,
                        address_n=parse_path("m/44'/194'/0'/0/0"),
                        weight=2)
                ],
                accounts=[
                    proto.EosAuthorizationAccount(
                        account=proto.EosPermissionLevel(
                            actor=eos.name_to_number('memememememe'),
                            permission=eos.name_to_number('active')),
                        weight=1)
                ],
                waits=[
                    proto.EosAuthorizationWait(
                        wait_sec=3600,
                        weight=1)
                ])

    def action_deleteauth(self):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('deleteauth'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionDeleteAuth(
                    account=eos.name_to_number('memememememe'),
                    permission=eos.name_to_number('active')))

    def action_linkauth(self):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('linkauth'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionLinkAuth(
                    account=eos.name_to_number('memememememe'),
                    code=eos.name_to_number('eosbet'),
                    type=eos.name_to_number('whatever'),
                    requirement=eos.name_to_number('active')))

    def action_unlinkauth(self):
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('unlinkauth'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionUnlinkAuth(
                    account=eos.name_to_number('memememememe'),
                    code=eos.name_to_number('eosbet'),
                    type=eos.name_to_number('whatever')))

    def action_newaccount(self):
        device_auth=proto.EosAuthorization(
                    threshold=1,
                    keys=[
                        proto.EosAuthorizationKey(
                            type=1,
                            address_n=parse_path("m/44'/194'/0'/0/0"),
                            weight=1)
                    ],
                    accounts=[],
                    waits=[])
        return (proto.EosActionCommon(
                    account=eos.name_to_number('eosio'),
                    name=eos.name_to_number('newaccount'),
                    authorization=[
                        proto.EosPermissionLevel(
                            actor=eos.name_to_number('eosio'),
                            permission=eos.name_to_number('active'))
                    ]),
                proto.EosActionNewAccount(
                    creator=eos.name_to_number('memememememe'),
                    name=eos.name_to_number('newnewnewnew'),
                    owner=device_auth,
                    active=device_auth))

    def action_unknown(self, account, name, data):
        n = 256
        ret = []
        total = len(data)
        while 0 < len(data):
            chunk = data[:n]
            ret += [(proto.EosActionCommon(
                        account=eos.name_to_number(account),
                        name=eos.name_to_number(name),
                        authorization=[
                            proto.EosPermissionLevel(
                                actor=eos.name_to_number('eosio'),
                                permission=eos.name_to_number('active'))
                        ]),
                     proto.EosActionUnknown(
                        data_size=total,
                        data_chunk=chunk))]
            data = data[n:]
        return ret

    def test_action_surplus(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        try:
            self.client.eos_sign_tx_raw(
                    proto.EosSignTx(
                        address_n=parse_path("m/44'/194'/0'/0/0"),
                        chain_id=EOS_CHAIN_ID,
                        header=self.header(),
                        num_actions=1),
                    [self.action_transfer()] * 2)
        except CallException as e:
            self.assertEndsWith(e.args[1], "Action count mismatch")
        else:
            self.assert_(False, "Negative test passed")

    def test_action_deficit(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        try:
            self.client.eos_sign_tx_raw(
                    proto.EosSignTx(
                        address_n=parse_path("m/44'/194'/0'/0/0"),
                        chain_id=EOS_CHAIN_ID,
                        header=self.header(),
                        num_actions=2),
                    [self.action_transfer()])
        except Exception as e:
            self.assertEndsWith(e.args[0], "Unexpected EOS signing response")
        else:
            self.assert_(False, "Negative test passed")

    def test_wrong_account(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        try:
            self.client.eos_sign_tx_raw(
                    proto.EosSignTx(
                        address_n=parse_path("m/44'/194'/0'/0/0"),
                        chain_id=EOS_CHAIN_ID,
                        header=self.header(),
                        num_actions=1),
                    [(proto.EosActionCommon(
                          account=eos.name_to_number('foobarctrct'),
                          name=eos.name_to_number('refund'),
                          authorization=[
                              proto.EosPermissionLevel(
                                  actor=eos.name_to_number('eosio'),
                                  permission=eos.name_to_number('active'))
                          ]),
                      proto.EosActionRefund(
                          owner=eos.name_to_number('memememememe')))])
        except Exception as e:
            self.assertEndsWith(e.args[1], "Incorrect account name")
        else:
            self.assert_(False, "Negative test passed")

    def test_transfer(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=1),
            [self.action_transfer()])

        self.assertEqual(binascii.hexlify(res.hash), "c7c33bd395fb7764021082abe1a02609492b8b1209ce6a3cf2db381d89128c71")

    def test_delegatebw(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=2),
            [self.action_delegatebw(False),
             self.action_delegatebw(True)])

        self.assertEqual(binascii.hexlify(res.hash), "b4921554b1ae7a7960477e9b89cb4d410493cef8a71bc60ead48882721eadcbd")

    def test_undelegatebw(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=1),
            [self.action_undelegatebw()])

        self.assertEqual(binascii.hexlify(res.hash), "af1471bb07540299f6f9cabb1fdf542063bd6c73d6535534f4627ef765ef21b3")

    def test_refund(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=1),
            [self.action_refund()])

        self.assertEqual(binascii.hexlify(res.hash), "c87fbd785bb6b3463f781d8a90a096719d15164f288c3a731ad3d00c65df93ab")

    def test_buyram(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=1),
            [self.action_buyram()])

        self.assertEqual(binascii.hexlify(res.hash), "b78f9754929c06ba92115756a0385cf74058353171bb1a29c471259ae6a6f67c")

    def test_buyrambytes(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=1),
            [self.action_buyrambytes()])

        self.assertEqual(binascii.hexlify(res.hash), "27c6be3d214fa69a2bfabf31de2f05951fe8ff903c5af2933489b2d06aa48c11")

    def test_sellram(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=1),
            [self.action_sellram()])

        self.assertEqual(binascii.hexlify(res.hash), "98445e80a9800d62227dc1d0ebfd0fa3fd060b79fbb6717f9c9bb462f21c6aef")

    def test_voteproducer(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=3),
            [self.action_voteproducer_proxy(),
             self.action_voteproducers(),
             self.action_voteproducer_cancel()])

        self.assertEqual(binascii.hexlify(res.hash), "ea13aad2ddb8485b1ff28399f350bf8e7182f68809957a226ccb9d9bed1e7e15")

    def test_updateauth(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=1),
            [self.action_updateauth(False)])

        self.assertEqual(binascii.hexlify(res.hash), "0282c00575f451a47e99902ab2a51243499ea004df309148d1f2e23c007520b7")

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/48'/4'/0'/0'/0'"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=1),
            [self.action_updateauth(True)])

        self.assertEqual(binascii.hexlify(res.hash), "fb936ef1be4bda680d93bd10b6d062357d8dd7272038a706dc0d61a91f39c5ee")

    def test_deleteauth(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=1),
            [self.action_deleteauth()])

        self.assertEqual(binascii.hexlify(res.hash), "90870fe5ac29ab077764e5ce88d24aef9b85b6670755f8cf4f42562e8faca431")

    def test_linkauth(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=1),
            [self.action_linkauth()])

        self.assertEqual(binascii.hexlify(res.hash), "8705a2a7e96a8043fd034443e308b84fc9d8560434393b0520dce324e92afeba")

    def test_unlinkauth(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=1),
            [self.action_unlinkauth()])

        self.assertEqual(binascii.hexlify(res.hash), "7f8668920192ab6132821e823cf05f52ccfd4bc724341903acf827db30a0c280")

    def test_newaccount(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()

        res = self.client.eos_sign_tx_raw(
            proto.EosSignTx(
                address_n=parse_path("m/44'/194'/0'/0/0"),
                chain_id=EOS_CHAIN_ID,
                header=self.header(),
                num_actions=1),
            [self.action_newaccount()])

        self.assertEqual(binascii.hexlify(res.hash), "8e0accde9fb6529b5d72b4d9a9859e1dae0c6ae9a159bb1ea8c8f579f942c291")

    def test_unknown_advanced(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('AdvancedMode', 1)

        vec = [
            (16, "da06ce61c12b2909fc75983e7e09ed6595065bd32013602d87ec51491a20db07"),
            (54, "310ecf420b31c9f3b0716534d1c6bb75b4b7441c4587595a07ed10e6765a43d5"),
            (55, "e115004ce55dd7fbb4b3429c99e6bad1d38309895273007e0802828dfed83c8c"),
            (196, "50e47d07bfb36c6dae132f1419808c8528a15c8b9ff51fcc3d2800a45506b10d"),
            (255, "ead4f8397e53df46dce7d340a88d4e4e7c906b6444d974d8fcd01e69ae70045a"),
            (1023, "4175a0034aa668534c765bf2b151a89c6a3b737eb12e72d433cc9292027e44a9")
        ]

        for i, h in vec:
            res = self.client.eos_sign_tx_raw(
                proto.EosSignTx(
                    address_n=parse_path("m/44'/194'/0'/0/0"),
                    chain_id=EOS_CHAIN_ID,
                    header=self.header(),
                    num_actions=1),
                self.action_unknown('acbdefghijkl', 'mnopqrstuvwx', binascii.unhexlify('AB' * i)))

            self.assertEqual(binascii.hexlify(res.hash), h)

    def test_eos_signtx_transfer_token(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
                {
                "account": "eosio.token",
                "name": "transfer",
                "authorization": [
                    {
                    "actor": "miniminimini",
                    "permission": "active"
                    }
                ],
                "data": {
                    "from": "miniminimini",
                    "to": "maximaximaxi",
                    "quantity": "1.0000 EOS",
                    "memo": "testtest"
                }
                }
            ],
            "transaction_extensions": []
            }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "729e0a94e5a587d7f10001214fc017e56c8753ff0fc785eb3e91b3f471d58864")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "532ee29e14bc925b37dec2cab72863b5bf82af581f2250b5149722582b56998d")
        self.assertEqual(actionResp.signature_v, 31)

    def test_eos_signtx_buyram(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "buyram",
                "authorization": [
                {
                "actor": "miniminimini",
                "permission": "active"
                }
                ],
                "data": {
                "payer": "miniminimini",
                "receiver": "miniminimini",
                "quant": "1000000000.0000 EOS"
                }
                }
            ],
            "transaction_extensions": []
            }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "25eebc6591e2c06bb0a5ac1a6e7d79a65e5b5ec2c098362676ba88a0921a9daa")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "2f5f9b0f6a3bfe6981d4db99cfe2ab88329bf86fb04b40a3a8828453e54cef2c")
        self.assertEqual(actionResp.signature_v, 31)

    def test_eos_signtx_buyrambytes(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "buyrambytes",
                "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
                "data": {
                "payer": "miniminimini",
                "receiver": "miniminimini",
                "bytes": 1023
            }
            }
            ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "56a5a2bb2a4ad9426209f2ce1d48e8722bbb9c692fd2f42fd1a830431d6e86e0")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "6caa1786e0913574b78e95685600f84f21c2db54a0454b62dfee637feaa5f4c7")
        self.assertEqual(actionResp.signature_v, 32)

    def test_eos_signtx_sellram(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "sellram",
                "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
                "data": {
                "account": "miniminimini",
                "bytes": 1024
            }
            }
            ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "651fb86faa118464fb0ad273fb83a4af03bf800fe304924a809448ee0ba6ce9b")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "1cbf9773df9ad2d4cc300df070102ac76308f19617d30807105b14393cb07354")
        self.assertEqual(actionResp.signature_v, 32)

    def test_eos_signtx_delegate(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "delegatebw",
                "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
                "data": {
                "from": "miniminimini",
                "receiver": "maximaximaxi",
                "stake_net": "1.0000 EOS",
                "stake_cpu": "1.0000 EOS",
                "transfer": true
            }
            }
            ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "36f341e5c1ad5bfc088ca2ca901faa66d71a92643f88b62bd7ada7dfe1c5c52d")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "1fe42c07959e6e0e85ec9e05dc7a2c87be96c8217cd0a886bda2f8af0e434d77")
        self.assertEqual(actionResp.signature_v, 32)

    def test_eos_signtx_undelegate(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "undelegatebw",
            "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
                "data": {
                "from": "miniminimini",
                "receiver": "maximaximaxi",
                "unstake_net_quantity": "1.0000 EOS",
                "unstake_cpu_quantity": "1.0000 EOS"
            }
            }
            ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "657438398a9f49d8e38629943277a3f3735b800eb0478f137edd11246ce9eae4")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "2e6530c1482c6168356500b87bd90a904a8b935a1d68555888f7ca3ce5780264")
        self.assertEqual(actionResp.signature_v, 31)

    def test_eos_signtx_refund(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "refund",
            "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
                "data": {
                "owner": "miniminimini"
            }
            }
            ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "0c72f3379801af5e74e4b345e02453001fb8ee1bab709004c7a0a2f437fddfb1")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "287b8de9871b352c316724295e2378b959d5ba2c6420a50bfafa16f6b3ba6051")
        self.assertEqual(actionResp.signature_v, 32)

    def test_eos_signtx_linkauth(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "linkauth",
                "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
            "data": {
                "account": "maximaximaxi",
                "code": "eosbet",
                "type": "whatever",
                "requirement": "active"
            }
            }
            ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "729d5ca3d116676cef12606c610a9b88d88c6617a3e6f7afb77899762ba703da")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "2a117e2b36c7bc5997369bb6092a233c67c78541a0f5d816cd93fb69c681d60f")
        self.assertEqual(actionResp.signature_v, 32)

    def test_eos_signtx_unlinkauth(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "unlinkauth",
                "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
            "data": {
                "account": "miniminimini",
                "code": "eosbet",
                "type": "whatever"
            }
            }
            ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "68ee06fb0ebc1e92bd950df7a088cb740826146cbf423430b737755184f50820")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "22001faccf560006dffa04befacdaeee0f071a026fc1b0d118daf6e4c5b39664")
        self.assertEqual(actionResp.signature_v, 32)

    def test_eos_signtx_updateauth(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "updateauth",
                "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
            "data": {
                "account": "miniminimini",
                "permission": "active",
                "parent": "owner",
            "auth": {
                "threshold": 1,
                "keys": [
                {
                  "key": "EOS8Dkj827FpinZBGmhTM28B85H9eXiFH5XzvLoeukCJV5sKfLc6K",
                  "weight": 1
                },
                {
                  "key": "EOS8Dkj827FpinZBGmhTM28B85H9eXiFH5XzvLoeukCJV5sKfLc6K",
                  "weight": 2
                }
                ],
                "accounts": [
                {
                    "permission": {
                        "actor": "miniminimini",
                        "permission": "active"
                    },
                    "weight": 3
                }
                ],
                "waits": [
                {
                  "wait_sec": 55,
                  "weight": 4
                }
              ]
            }
          }
        }
        ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "510b711d19b090dbe9615341d5ae5cbe058520d0bf3f0b4e4fa48466103b3718")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "7c2cb5c0174d8a84bb41c1b124424ec6a3a28f95dbd014b191ac6f7766fa2914")
        self.assertEqual(actionResp.signature_v, 31)

    def test_eos_signtx_deleteauth(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "deleteauth",
                "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
            "data": {
                "account": "maximaximaxi",
                "permission": "active"
            }
            }
            ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "544c40147f98c1570aae56c01ad1ade165fcba1557bd6db7e05c53f1c09addd7")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "78e840f9190c92482f51713c3b569984e172ffb1a0004db814832f2d52d706e2")
        self.assertEqual(actionResp.signature_v, 32)

    def test_eos_signtx_vote(self):
        self.requires_fullFeature()

        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "voteproducer",
                "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
            "data": {
            "account": "miniminimini",
            "proxy": "",
            "producers": [
              "argentinaeos",
              "bitfinexeos1",
              "cryptolions1",
              "eos42freedom",
              "eosamsterdam",
              "eosasia11111",
              "eosauthority",
              "eosbeijingbp",

              "eosbixinboot",
              "eoscafeblock",
              "eoscanadacom",
              "eoscannonchn",
              "eoscleanerbp",
              "eosdacserver",
              "eosfishrocks",
              "eosflytomars",

              "eoshuobipool",
              "eosisgravity",
              "eoslaomaocom",
              "eosliquideos",
              "eosnewyorkio",
              "eosriobrazil",
              "eosswedenorg",
              "eostribeprod",

              "helloeoscnbp",
              "jedaaaaaaaaa",
              "libertyblock",
              "starteosiobp",
              "teamgreymass"
              ]
            }
            }
            ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "765dee35f135cdebbeb29a6c01e92749c2fef5f3b25450876a2cd00cbcbae53a")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "79c3b1dabec258ed90f29f407df3f7a92783b4f36a3fc4cf2521f97014008eee")
        self.assertEqual(actionResp.signature_v, 31)

    def test_eos_signtx_vote_proxy(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "voteproducer",
                "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
            "data": {
                "account": "miniminimini",
                "proxy": "",
                "producers": []
            }
            }
            ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "1081ad2f20f65d5f81a6767e0b0171597216cfeb9a619d44ae44445365a287ca")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "4172a2b4a34864a6ad65ab5ab6454925017bcf52a94c79073c29bd5ad136dbcf")
        self.assertEqual(actionResp.signature_v, 32)

    def test_eos_signtx_unknown(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('AdvancedMode', 1)
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "foocontract",
                "name": "baraction",
                "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
                "data": "deadbeef"
            }
            ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "324ba8d98ae336c28ceb8187047a1a1c883ea85f830184218facec82f456720e")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "29128593f90caf038659b8a20de9d963187279d2cd4a1025a3344856f671b731")
        self.assertEqual(actionResp.signature_v, 32)

    def test_eos_signtx_newaccount(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-07-14T07:43:28",
            "ref_block_num": 6439,
            "ref_block_prefix": 2995713264,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
            {
                "account": "eosio",
                "name": "newaccount",
            "authorization": [
            {
                "actor": "miniminimini",
                "permission": "active"
            }
            ],
            "data": {
                "creator": "miniminimini",
                "name": "maximaximaxi",
                "owner": {
                "threshold": 1,
                "keys": [
                {
                  "address_n": "44'/194'/0'/0/0",
                  "weight": 1
                }
              ],
              "accounts": [],
              "waits": []
            },
            "active": {
              "threshold": 1,
              "keys": [
                {
                  "address_n": "44'/194'/0'/0/0",
                  "weight": 1
                }
              ],
              "accounts": [],
              "waits": []
            }
            }
            },
            {
            "account": "eosio",
            "name": "buyrambytes",
            "authorization": [
            {
              "actor": "miniminimini",
              "permission": "active"
            }
            ],
                "data": {
                "payer": "miniminimini",
                "receiver": "maximaximaxi",
                "bytes": 4096
                }
            },
            {
                "account": "eosio",
                "name": "delegatebw",
                "authorization": [
                {
                "actor": "miniminimini",
                "permission": "active"
                }
                ],
                "data": {
                "from": "miniminimini",
                "receiver": "maximaximaxi",
                "stake_net": "1.0000 EOS",
                "stake_cpu": "1.0000 EOS",
                "transfer": true
                }
            }
            ],
        "transaction_extensions": []
        }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "61317ec7dc5c6e62ef7e45b4961ad89fe748c5a9076f23e0c6afc90ad1f93f47")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "056996515e6c6e28be136821859cf2092f719a8da25171ce6534c2bf9a013d3d")
        self.assertEqual(actionResp.signature_v, 32)

    def test_eos_signtx_setcontract(self):
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy('AdvancedMode', 1)
        data = '''{
            "chain_id": "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f",
            "transaction": {
            "expiration": "2018-06-19T10:29:53",
            "ref_block_num": 30587,
            "ref_block_prefix": 338239089,
            "max_net_usage_words": 0,
            "max_cpu_usage_ms": 0,
            "delay_sec": 0,
            "context_free_actions": [],
            "actions": [
                {
                    "account": "eosio",
                    "name": "setcode",
                    "authorization": [
                        {
                        "actor": "ednazztokens",
                        "permission": "active"
                        }
                    ],
                    "data": "80a78234ff6f665200009594010061736d01000000017e1560037f7e7f0060057f7e7e7f7f0060047f7e7f7f006000006000017e60027e7e0060017e0060027f7f0060047e7e7e7e017f60067e7e7e7e7f7f017f60037f7f7f017f60017e017f60017f006000017f60027f7f017f60017f017f60047f7f7f7f0060047f7e7f7e0060047e7e7f7f0060037f7e7f017f60037e7e7e0002c5021103656e760561626f7274000303656e7610616374696f6e5f646174615f73697a65000d03656e761063757272656e745f7265636569766572000403656e760c63757272656e745f74696d65000403656e760b64625f66696e645f693634000803656e760a64625f6765745f693634000a03656e760d64625f72656d6f76655f693634000c03656e760c64625f73746f72655f693634000903656e760d64625f7570646174655f693634000203656e760c656f73696f5f617373657274000703656e760a69735f6163636f756e74000b03656e76066d656d637079000a03656e7610726561645f616374696f6e5f64617461000e03656e760c726571756972655f61757468000603656e760d726571756972655f6175746832000503656e7611726571756972655f726563697069656e74000603656e760b73656e645f696e6c696e6500070331300e0e0e0d0c000e0f0710070211120707070e0e0e0e100113001307140e0e0e07070e0e070f0c0c070c0e0a0f0e0f0c0304050170010404050301000107f7030f066d656d6f72790200165f5a6571524b3131636865636b73756d32353653315f0011165f5a6571524b3131636865636b73756d31363053315f0012165f5a6e65524b3131636865636b73756d31363053315f0013036e6f770014305f5a4e35656f73696f3132726571756972655f6175746845524b4e535f31367065726d697373696f6e5f6c6576656c450015225f5a4e35656f73696f35746f6b656e3663726561746545794e535f356173736574450016615f5a4e35656f73696f35746f6b656e35697373756545794e535f356173736574454e5374335f5f31313262617369635f737472696e6749634e53325f3131636861725f747261697473496345454e53325f39616c6c6f6361746f72496345454545001c295f5a4e35656f73696f35746f6b656e31316164645f62616c616e636545794e535f3561737365744579001d655f5a4e35656f73696f35746f6b656e387472616e736665724579794e535f356173736574454e5374335f5f31313262617369635f737472696e6749634e53325f3131636861725f747261697473496345454e53325f39616c6c6f6361746f724963454545450027285f5a4e35656f73696f35746f6b656e31317375625f62616c616e636545794e535f356173736574450029056170706c79002c066d656d636d70003b066d616c6c6f63003c0466726565003f090a010041000b044016271c0ae37f300b00200020014120103b450b0b00200020014120103b450b0d00200020014120103b4100470b0a00100342c0843d80a70b0e0020002903002000290308100e0bda0704037e017f017e027f410041002802044180016b22093602042000290300100d4100210820022903082203420888220421070240024003402007a741187441ffffffff7b6a41feffffd7014b0d0102402007420888220742ff01834200520d0003402007420888220742ff01834200520d03200841016a22084107480d000b0b41012106200841016a22084107480d000c020b0b410021060b2006411010094100210602402002290300220542ffffffffffffffff3f7c42feffffffffffffffff00560d004100210820042107024003402007a741187441ffffffff7b6a41feffffd7014b0d0102402007420888220742ff01834200520d0003402007420888220742ff01834200520d03200841016a22084107480d000b0b41012106200841016a22084107480d000c020b0b410021060b200641301009200542005541c0001009200941086a41206a41003602002009427f3703182009420037032020092000290300220737030820092004370310024002402007200442808080808080e4a6462004100422084100480d00200941086a20081017280228200941086a4641e0001009410021080c010b410121080b200841a001100920002903002104200929030810025141d001100941381035220810181a2008200941086a360228200820033703082008411c6a2002410c6a280200360200200841186a200241086a280200360200200841146a200241046a28020036020020082002280200360210200820013703202009200941306a41286a3602602009200941306a36025c2009200941306a3602582009200941d8006a3602682009200841106a360274200920083602702009200841206a360278200941f0006a200941e8006a10192008200941086a41086a29030042808080808080e4a646200420082903084208882207200941306a41281007220636022c02402007200941086a41106a2202290300540d002002200742017c3703000b200920083602702009200841086a29030042088822073703302009200636025802400240200941086a411c6a2802002202200941286a2802004f0d0020022007370308200220063602102009410036027020022008360200200941246a200241186a3602000c010b200941206a200941f0006a200941306a200941d8006a101a0b200928027021082009410036027002402008450d00200810360b024020092802202206450d0002400240200941246a220028020022082006460d000340200841686a220828020021022008410036020002402002450d00200210360b20062008470d000b200941206a28020021080c010b200621080b20002006360200200810360b410020094180016a3602040bd50303037f017e047f410028020441306b220921084100200936020402402000411c6a280200220720002802182202460d00410020026b2103200741686a21060340200641106a2802002001460d0120062107200641686a22042106200420036a4168470d000b0b0240024020072002460d00200741686a28020021060c010b20014100410010052206411f7641017341e0021009024002402006418104490d002006103c21040c010b410020092006410f6a4170716b22043602040b20012004200610051a2008200436020c200820043602082008200420066a36021002402006418104490d002004103f0b41381035220610181a200620003602282008200841086a3602182008200641106a360224200820063602202008200641206a360228200841206a200841186a101b2006200136022c200820063602182008200629030842088822053703202008200628022c2207360204024002402000411c6a22012802002204200041206a2802004f0d00200420053703082004200736021020084100360218200420063602002001200441186a3602000c010b200041186a200841186a200841206a200841046a101a0b20082802182104200841003602182004450d00200410360b4100200841306a36020420060bb50202017e027f20004284a6e59a0537030820004200370300410141a002100920002903084208882101410021020240024003402001a741187441ffffffff7b6a41feffffd7014b0d0102402001420888220142ff01834200520d0003402001420888220142ff01834200520d03200241016a22024107480d000b0b41012103200241016a22024107480d000c020b0b410021030b200341101009200041186a22024284a6e59a0537030020004200370310410141a002100920022903004208882101410021020240024003402001a741187441ffffffff7b6a41feffffd7014b0d0102402001420888220142ff01834200520d0003402001420888220142ff01834200520d03200241016a22024107480d000b0b41012103200241016a22024107480d000c020b0b410021030b20034110100920000b880201037f200028020021032001280200220228020820022802046b41074a4190021009200228020420034108100b1a2002200228020441086a2204360204200228020820046b41074a41900210092002280204200341086a4108100b1a2002200228020441086a360204200028020421032001280200220228020820022802046b41074a4190021009200228020420034108100b1a2002200228020441086a2204360204200228020820046b41074a41900210092002280204200341086a4108100b1a2002200228020441086a360204200028020821002001280200220228020820022802046b41074a4190021009200228020420004108100b1a2002200228020441086a3602040baa0301047f024002402000280204200028020022066b41186d220441016a220541abd5aad5004f0d0041aad5aad500210702400240200028020820066b41186d220641d4aad52a4b0d0020052006410174220720072005491b2207450d010b200741186c103521060c020b41002107410021060c010b20001039000b20012802002105200141003602002006200441186c6a2201200536020020012002290300370308200120032802003602102006200741186c6a2104200141186a210502400240200041046a280200220620002802002207460d000340200641686a2202280200210320024100360200200141686a2003360200200141786a200641786a280200360200200141746a200641746a280200360200200141706a200641706a280200360200200141686a21012002210620072002470d000b200041046a2802002107200028020021060c010b200721060b20002001360200200041046a2005360200200041086a2004360200024020072006460d000340200741686a220728020021012007410036020002402001450d00200110360b20062007470d000b0b02402006450d00200610360b0b880201037f200028020021032001280200220228020820022802046b41074b4180031009200320022802044108100b1a2002200228020441086a2204360204200228020820046b41074b4180031009200341086a20022802044108100b1a2002200228020441086a360204200028020421032001280200220228020820022802046b41074b4180031009200320022802044108100b1a2002200228020441086a2204360204200228020820046b41074b4180031009200341086a20022802044108100b1a2002200228020441086a360204200028020821002001280200220228020820022802046b41074b4180031009200020022802044108100b1a2002200228020441086a3602040bac0c07017f027e017f017e027f037e017f4100410028020441e0016b220e360204410021092002290308220b420888220d21080240024003402008a741187441ffffffff7b6a41feffffd7014b0d0102402008420888220842ff01834200520d0003402008420888220842ff01834200520d03200941016a22094107480d000b0b41012107200941016a22094107480d000c020b0b410021070b2007411010090240024020032d000022094101710d00200941017621090c010b200328020421090b20094181024941900310094100210a200e41d8006a41206a4100360200200e427f370368200e4200370370200e20002903002208370358200e200d3703604100210702402008200d42808080808080e4a646200d100422094100480d00200e41d8006a200910172207280228200e41d8006a4641e00010090b200741004741b00310092007290320100d200741206a210402402002290300220842ffffffffffffffff3f7c42feffffffffffffffff00560d004100210902400340200da741187441ffffffff7b6a41feffffd7014b0d010240200d420888220d42ff01834200520d000340200d420888220d42ff01834200520d03200941016a22094107480d000b0b4101210a200941016a22094107480d000c020b0b4100210a0b200a41f003100920084200554190041009200b20072903085141b00410092008200729031020072903007d5741d00410092007280228200e41d8006a464180051009200e29035810025141b0051009200b2007290308220d5141f00510092007200729030020087c22083703002008428080808080808080405541a00610092007290300428080808080808080c0005341c0061009200d420888220820072903084208885141e0061009200e200e4180016a41286a3602c001200e200e4180016a3602bc01200e200e4180016a3602b801200e200e41b8016a3602c801200e200741106a3602d401200e20073602d001200e20043602d801200e41d0016a200e41c8016a1019200728022c4200200e4180016a4128100802402008200e41d8006a41106a2209290300540d002009200842017c3703000b200e41c8006a410c6a22092002410c6a280200360200200e41c8006a41086a2207200241086a280200360200200e200241046a28020036024c200e200228020036024820042903002108200e41086a410c6a2009280200360200200e41086a41086a2007280200360200200e200e28024c36020c200e200e28024836020820002008200e41086a2008101d0240200429030022052001510d002000290300210642002108423b210b41a00721094200210c03400240024002400240024020084205560d0020092c00002207419f7f6a41ff017141194b0d01200741a5016a21070c020b4200210d2008420b580d020c030b200741d0016a41002007414f6a41ff01714105491b21070b2007ad423886423887210d0b200d421f83200b42ffffffff0f8386210d0b200941016a2109200842017c2108200d200c84210c200b427b7c220b427a520d000b200e41346a2002410c6a280200360200200e41186a41186a2207200241086a280200360200200e412c6a200241046a280200360200200e2001370320200e2005370318200e2002280200360228200e41386a2003103a1a41101035220920053703002009200c370308200e20093602d001200e200941106a22093602d801200e20093602d401200e200e29031837038001200e200e29032037038801200e4180016a41186a2007290300370300200e200e29032837039001200e4180016a41286a2207200e41186a41286a2209280200360200200e200e2903383703a001200e4100360238200e413c6a410036020020094100360200200642808080b8d585cfe64d200e41d0016a200e4180016a101e0240200e2d00a001410171450d00200728020010360b0240200e2802d0012209450d00200e20093602d401200910360b200e41386a2d0000410171450d00200e41c0006a28020010360b0240200e2802702202450d0002400240200e41f4006a220a28020022092002460d000340200941686a220928020021072009410036020002402007450d00200710360b20022009470d000b200e41f0006a28020021090c010b200221090b200a2002360200200910360b4100200e41e0016a3602040bbc0704017e017f017e037f4100410028020441d0006b220936020441002108200941086a41206a41003602002009427f370318200942003703202009200029030022063703082009200137031002400240024002402006200142808080c0f3a9d3883220022903082204420888100422004100480d00200941086a200010252208280210200941086a4641e0001009410141b00710092008280210200941086a464180051009200929030810025141b00510092004200829030822015141f00510092008200829030020022903007c22063703002006428080808080808080405541a00610092008290300428080808080808080c0005341c00610092001420888220120082903084208885141e006100941014190021009200941c0006a20084108100b1a41014190021009200941c0006a410872200841086a4108100b1a20082802144200200941c0006a411010082001200941086a41106a2208290300540d012008200142017c370300200928022022020d020c030b200929030810025141d00110094120103522004284a6e59a0537030820004200370300410141a0021009200041086a210542d3b2cd02210102400340410021072001a741187441ffffffff7b6a41feffffd7014b0d0102402001420888220142ff01834200520d0003402001420888220142ff01834200520d03200841016a22084107480d000b0b41012107200841016a22084107480d000b0b2007411010092000200941086a360210200041086a2208200241086a2903003703002000200229030037030041014190021009200941c0006a20004108100b1a41014190021009200941c0006a41087220054108100b1a2000200941086a41086a29030042808080c0f3a9d38832200320082903004208882201200941c0006a41101007220236021402402001200941086a41106a2207290300540d002007200142017c3703000b200920003602382009200829030042088822013703402009200236023402400240200941246a22072802002208200941286a2802004f0d00200820013703082008200236021020094100360238200820003602002007200841186a3602000c010b200941206a200941386a200941c0006a200941346a10260b20092802382108200941003602382008450d00200810360b20092802202202450d010b02400240200941246a220728020022082002460d000340200841686a220828020021002008410036020002402000450d00200010360b20022008470d000b200941206a28020021080c010b200221080b20072002360200200810360b4100200941d0006a3602040bc50401067f4100410028020441e0006b2209360204200941003602102009420037030841002106410021074100210802400240200228020420022802006b22044104752205450d0020054180808080014f0d01200941106a20041035220820054104746a2206360200200920083602082009200836020c0240200241046a280200200228020022076b22024101480d00200820072002100b1a2009200820026a220736020c0c010b200821070b2009412c6a200736020020092001370320200941106a4100360200200941306a200636020020092000370318200920083602282009420037030820094100360234200941186a41206a4100360200200941186a41246a4100360200200341246a28020020032d0020220841017620084101711b220241206a21082002ad2100200941346a21020340200841016a2108200042078822004200520d000b024002402008450d0020022008101f200941386a2802002102200941346a28020021080c010b41002102410021080b2009200836025420092008360250200920023602582009200941d0006a36024020092003360248200941c8006a200941c0006a1020200941d0006a200941186a102120092802502208200928025420086b1010024020092802502208450d0020092008360254200810360b024020092802342208450d00200941386a2008360200200810360b024020092802282208450d002009412c6a2008360200200810360b024020092802082208450d002009200836020c200810360b4100200941e0006a3602040f0b200941086a1039000bad0201057f0240024002400240024020002802082202200028020422066b20014f0d002006200028020022056b220320016a2204417f4c0d0241ffffffff0721060240200220056b220241feffffff034b0d0020042002410174220620062004491b2206450d020b2006103521020c030b200041046a21000340200641003a00002000200028020041016a22063602002001417f6a22010d000c040b0b41002106410021020c010b20001039000b200220066a2104200220036a220521060340200641003a0000200641016a21062001417f6a22010d000b2005200041046a2203280200200028020022016b22026b2105024020024101480d00200520012002100b1a200028020021010b2000200536020020032006360200200041086a20043602002001450d00200110360f0b0be60101027f200028020021022001280200220328020820032802046b41074a4190021009200328020420024108100b1a2003200328020441086a360204200028020021002001280200220328020820032802046b41074a41900210092003280204200041086a4108100b1a2003200328020441086a3602042001280200220328020820032802046b41074a41900210092003280204200041106a4108100b1a2003200328020441086a2202360204200328020820026b41074a41900210092003280204200041186a4108100b1a2003200328020441086a3602042001280200200041206a10241a0bc00203047f017e027f4100410028020441106b2208360204200041003602082000420037020041102105200141106a2102200141146a2802002207200128021022036b2204410475ad21060340200541016a2105200642078822064200520d000b024020032007460d00200441707120056a21050b200128021c220720056b200141206a28020022036b21052001411c6a2104200320076bad210603402005417f6a2105200642078822064200520d000b41002107024002402005450d002000410020056b101f200041046a2802002107200028020021050c010b410021050b2008200536020020082007360208200720056b41074a4190021009200520014108100b1a2007200541086a22006b41074a41900210092000200141086a4108100b1a2008200541106a360204200820021022200410231a4100200841106a3602040ba70203027f017e037f4100410028020441106b2207360204200128020420012802006b410475ad210420002802042105200041086a210203402004a721032007200442078822044200522206410774200341ff0071723a000f200228020020056b41004a4190021009200041046a22032802002007410f6a4101100b1a2003200328020041016a220536020020060d000b024020012802002206200141046a2802002201460d00200041046a21030340200041086a220228020020056b41074a4190021009200328020020064108100b1a2003200328020041086a2205360200200228020020056b41074a41900210092003280200200641086a4108100b1a2003200328020041086a2205360200200641106a22062001470d000b0b4100200741106a36020420000bdc0103057f017e017f4100410028020441106b2208360204200128020420012802006bad210720002802042106200041086a2104200041046a210503402007a721022008200742078822074200522203410774200241ff0071723a000f200428020020066b41004a419002100920052802002008410f6a4101100b1a2005200528020041016a220636020020030d000b200041086a28020020066b200141046a280200200128020022026b22054e4190021009200041046a220628020020022005100b1a2006200628020020056a3602004100200841106a36020420000b870203057f017e017f4100410028020441106b2208360204200128020420012d0000220541017620054101711bad210720002802042106200041086a2104200041046a210503402007a721022008200742078822074200522203410774200241ff0071723a000f200428020020066b41004a419002100920052802002008410f6a4101100b1a2005200528020041016a220636020020030d000b0240200141046a28020020012d00002205410176200541017122021b2205450d0020012802082103200041086a28020020066b20054e4190021009200041046a22062802002003200141016a20021b2005100b1a2006200628020020056a3602000b4100200841106a36020420000bce0403067f017e027f410028020441206b220a21094100200a36020402402000411c6a280200220720002802182203460d00410020036b2104200741686a21060340200641106a2802002001460d0120062107200641686a22052106200520046a4168470d000b0b0240024020072003460d00200741686a28020021050c010b20014100410010052207411f7641017341e00210090240024020074180044d0d0020012007103c2203200710051a2003103f0c010b4100200a2007410f6a4170716b220336020420012003200710051a0b200041186a21024120103522054284a6e59a0537030820054200370300410141a0021009200541086a210a42d3b2cd022108410021060240024003402008a741187441ffffffff7b6a41feffffd7014b0d0102402008420888220842ff01834200520d0003402008420888220842ff01834200520d03200641016a22064107480d000b0b41012104200641016a22064107480d000c020b0b410021040b20044110100920052000360210200741074b4180031009200520034108100b1a20074178714108474180031009200a200341086a4108100b1a20052001360214200920053602182009200541086a290300420888220837031020092005280214220736020c024002402000411c6a22012802002206200041206a2802004f0d00200620083703082006200736021020094100360218200620053602002001200641186a3602000c010b2002200941186a200941106a2009410c6a10260b20092802182106200941003602182006450d00200610360b4100200941206a36020420050baa0301047f024002402000280204200028020022066b41186d220441016a220541abd5aad5004f0d0041aad5aad500210702400240200028020820066b41186d220641d4aad52a4b0d0020052006410174220720072005491b2207450d010b200741186c103521060c020b41002107410021060c010b20001039000b20012802002105200141003602002006200441186c6a2201200536020020012002290300370308200120032802003602102006200741186c6a2104200141186a210502400240200041046a280200220620002802002207460d000340200641686a2202280200210320024100360200200141686a2003360200200141786a200641786a280200360200200141746a200641746a280200360200200141706a200641706a280200360200200141686a21012002210620072002470d000b200041046a2802002107200028020021060c010b200721060b20002001360200200041046a2005360200200041086a2004360200024020072006460d000340200741686a220728020021012007410036020002402001450d00200110360b20062007470d000b0b02402006450d00200610360b0ba20506017e017f017e017f017e027f4100410028020441f0006b220b360204200120025241e00710092001100d2002100a41800810092003290308210541002108200b41e8006a4100360200200b20054208882209370350200b427f370358200b4200370360200b2000290300370348200b41c8006a200941a008102821062001100f2002100f02402003290300220742ffffffffffffffff3f7c42feffffffffffffffff00560d004100210a024003402009a741187441ffffffff7b6a41feffffd7014b0d0102402009420888220942ff01834200520d0003402009420888220942ff01834200520d03200a41016a220a4107480d000b0b41012108200a41016a220a4107480d000c020b0b410021080b200841f0031009200742005541c0081009200520062903085141b00410090240024020042d0000220a4101710d00200a410176210a0c010b2004280204210a0b200a418102494190031009200b41386a41086a220a200341086a220829030037030020032903002109200b41186a410c6a200b41386a410c6a280200360200200b41186a41086a200a280200360200200b2009370338200b200b28023c36021c200b200b28023836021820002001200b41186a1029200b41286a41086a220a200829030037030020032903002109200b41086a410c6a200b41286a410c6a280200360200200b41086a41086a200a280200360200200b2009370328200b200b28022c36020c200b200b28022836020820002002200b41086a2001101d0240200b2802602208450d0002400240200b41e4006a2200280200220a2008460d000340200a41686a220a2802002103200a410036020002402003450d00200310360b2008200a470d000b200b41e0006a280200210a0c010b2008210a0b20002008360200200a10360b4100200b41f0006a3602040bb80101057f02402000411c6a280200220720002802182203460d00200741686a2106410020036b2104034020062802002903084208882001510d0120062107200641686a22052106200520046a4168470d000b0b0240024020072003460d00200741686a280200220628022820004641e00010090c010b410021062000290300200029030842808080808080e4a6462001100422054100480d00200020051017220628022820004641e00010090b20064100472002100920060bd30304027e017f017e027f4100410028020441c0006b2208360204200841286a4100360200200820013703102008427f3703182008420037032020082000290300370308200841086a2002290308220342088841e008102a22002903002002290300220459418009100902400240024020042000290300520d00200841086a2000102b200828022022050d010c020b2000280210200841086a464180051009200829030810025141b00510092003200029030822065141a00910092000200029030020047d22043703002004428080808080808080405541d00910092000290300428080808080808080c0005341f00910092006420888220420002903084208885141e006100941014190021009200841306a20004108100b1a41014190021009200841306a410872200041086a4108100b1a20002802142001200841306a4110100802402004200841086a41106a2200290300540d002000200442017c3703000b20082802202205450d010b02400240200841246a220728020022002005460d000340200041686a220028020021022000410036020002402002450d00200210360b20052000470d000b200841206a28020021000c010b200521000b20072005360200200010360b4100200841c0006a3602040bb80101057f02402000411c6a280200220720002802182203460d00200741686a2106410020036b2104034020062802002903084208882001510d0120062107200641686a22052106200520046a4168470d000b0b0240024020072003460d00200741686a280200220628021020004641e00010090c010b410021062000290300200029030842808080c0f3a9d388322001100422054100480d00200020051025220628021020004641e00010090b20064100472002100920060bce0202017e067f200128021020004641900a1009200029030010025141c00a100902402000411c6a2205280200220720002802182203460d0020012903082102410020036b2106200741686a210803402008280200290308200285428002540d0120082107200841686a22042108200420066a4168470d000b0b200720034741800b1009200741686a210802400240200720052802002204460d00410020046b2103200821070340200741186a2208280200210620084100360200200728020021042007200636020002402004450d00200410360b200741106a200741286a280200360200200741086a200741206a29030037030020082107200820036a4168470d000b2000411c6a28020022072008460d010b0340200741686a220728020021042007410036020002402004450d00200410360b20082007470d000b0b2000411c6a2008360200200128021410060bf50503027f047e017f4100410028020441c0006b220936020442002106423b210541c00b21044200210703400240024002400240024020064206560d0020042c00002203419f7f6a41ff017141194b0d01200341a5016a21030c020b420021082006420b580d020c030b200341d0016a41002003414f6a41ff01714105491b21030b2003ad42388642388721080b2008421f83200542ffffffff0f838621080b200441016a2104200642017c2106200820078421072005427b7c2205427a520d000b024020072002520d0042002106423b210541d00b21044200210703400240024002400240024020064204560d0020042c00002203419f7f6a41ff017141194b0d01200341a5016a21030c020b420021082006420b580d020c030b200341d0016a41002003414f6a41ff01714105491b21030b2003ad42388642388721080b2008421f83200542ffffffff0f838621080b200441016a2104200642017c2106200820078421072005427b7c2205427a520d000b200720015141e00b10090b0240024020012000510d0042002106423b210541c00b21044200210703400240024002400240024020064206560d0020042c00002203419f7f6a41ff017141194b0d01200341a5016a21030c020b420021082006420b580d020c030b200341d0016a41002003414f6a41ff01714105491b21030b2003ad42388642388721080b2008421f83200542ffffffff0f838621080b200441016a2104200642017c2106200820078421072005427b7c2205427a520d000b20072002520d010b2009200037033802400240200242808080b8d585cfe64d510d002002428080808080a0e998f600510d012002428080808080959beac500520d02200941003602342009410136023020092009290330370208200941386a200941086a102d1a0c020b200941003602242009410236022020092009290320370218200941386a200941186a102f1a0c010b2009410036022c2009410336022820092009290328370210200941386a200941106a102e1a0b4100200941c0006a3602040b9d0405027f017e017f017e037f410028020441e0006b220721094100200736020420012802042102200128020021084100210141002105024010012203450d00024002402003418104490d002003103c21050c010b410020072003410f6a4170716b22053602040b20052003100c1a0b200941286a4284a6e59a053703002009420037032020094200370318410141a002100942d3b2cd02210602400340410021072006a741187441ffffffff7b6a41feffffd7014b0d0102402006420888220642ff01834200520d0003402006420888220642ff01834200520d03200141016a22014107480d000b0b41012107200141016a22014107480d000b0b200741101009200341074b4180031009200941186a20054108100b1a200341787122074108474180031009200941186a41086a2201200541086a4108100b1a20074110474180031009200941186a41106a200541106a4108100b1a02402003418104490d002005103f0b200941306a41086a2207200141086a2903003703002009290318210620092001290300370330200941c0006a41086a200729030037030020092009290330370340200020024101756a210102402002410171450d00200128020020086a28020021080b200941d0006a41086a200941c0006a41086a2903002204370300200941086a41086a20043703002009200929034022043703502009200437030820012006200941086a20081100004100200941e0006a36020441010bf90303017f017e027f4100410028020441d0006b220436020420042205200036023c20052001280200360230200520012802043602344100210141002100024010012202450d00024002402002418104490d002002103c21000c010b410020042002410f6a4170716b22003602040b20002002100c1a0b200541186a4284a6e59a053703002005420037031020054200370308410141a002100942d3b2cd0221030240024003402003a741187441ffffffff7b6a41feffffd7014b0d0102402003420888220342ff01834200520d0003402003420888220342ff01834200520d03200141016a22014107480d000b0b41012104200141016a22014107480d000c020b0b410021040b200441101009200541286a410036020020054200370320200520003602402005200020026a2201360248200241074b4180031009200541086a20004108100b1a2001200041086a22046b41074b4180031009200541086a41086a20044108100b1a2001200041106a22046b41074b4180031009200541086a41106a20044108100b1a2005200041186a360244200541c0006a200541086a41186a10321a02402002418104490d002000103f0b2005200541306a36024420052005413c6a360240200541c0006a200541086a1034024020052d0020410171450d00200541286a28020010360b4100200541d0006a36020441010baf0303017f017e027f4100410028020441e0006b220436020420042205200036023c20052001280200360230200520012802043602344100210141002100024010012202450d00024002402002418104490d002002103c21000c010b410020042002410f6a4170716b22003602040b20002002100c1a0b200541186a4284a6e59a05370300200542003703082005420037030020054200370310410141a002100942d3b2cd0221030240024003402003a741187441ffffffff7b6a41feffffd7014b0d0102402003420888220342ff01834200520d0003402003420888220342ff01834200520d03200141016a22014107480d000b0b41012104200141016a22014107480d000c020b0b410021040b200441101009200541286a41003602002005420037032020052000360244200520003602402005200020026a3602482005200541c0006a36025020052005360258200541d8006a200541d0006a103002402002418104490d002000103f0b2005200541306a36024420052005413c6a360240200541c0006a20051031024020052d0020410171450d00200541286a28020010360b4100200541e0006a36020441010be60101027f200028020021022001280200220328020820032802046b41074b4180031009200220032802044108100b1a2003200328020441086a360204200028020021002001280200220328020820032802046b41074b4180031009200041086a20032802044108100b1a2003200328020441086a3602042001280200220328020820032802046b41074b4180031009200041106a20032802044108100b1a2003200328020441086a2202360204200328020820026b41074b4180031009200041186a20032802044108100b1a2003200328020441086a3602042001280200200041206a10321a0bd00202027e027f4100410028020441e0006b22053602042005412c6a2001411c6a280200360200200541206a41086a2204200141186a280200360200200520012802103602202005200141146a2802003602242001290308210320012903002102200541106a200141206a103a1a200541306a41086a20042903003703002005200529032037033020002802002802002000280204220128020422044101756a21002001280200210102402004410171450d00200028020020016a28020021010b200541d0006a41086a2204200541306a41086a29030037030020052005290330370350200541c0006a200541106a103a1a200541086a2004290300370300200520052903503703002000200220032005200541c0006a2001110100024020052d0040410171450d00200528024810360b024020052d0010410171450d00200528021810360b4100200541e0006a3602040bb40301067f4100410028020441206b220736020420074100360218200742003703102000200741106a10331a0240024002400240024002400240024002402007280214220520072802102204470d0020012d00004101710d01200141003b0100200141086a21040c020b200741086a410036020020074200370300200520046b220241704f0d072002410b4f0d02200720024101743a00002007410172210620020d030c040b200128020841003a000020014100360204200141086a21040b2001410010382004410036020020014200370200200728021022040d030c040b200241106a4170712205103521062007200541017236020020072006360208200720023602040b20022103200621050340200520042d00003a0000200541016a2105200441016a21042003417f6a22030d000b200620026a21060b200641003a00000240024020012d00004101710d00200141003b01000c010b200128020841003a0000200141003602040b200141001038200141086a200741086a2802003602002001200729030037020020072802102204450d010b20072004360214200410360b4100200741206a36020420000f0b20071037000b830203047f017e017f200028020421054100210742002106200041086a2102200041046a21030340200520022802004941a00c1009200328020022052d000021042003200541016a2205360200200441ff0071200741ff0171220774ad2006842106200741076a210720044107760d000b024002402006a7220320012802042207200128020022046b22024d0d002001200320026b101f200041046a2802002105200141046a2802002107200128020021040c010b200320024f0d00200141046a200420036a22073602000b200041086a28020020056b200720046b22054f41800310092004200041046a22072802002005100b1a2007200728020020056a36020020000bca0202017e027f4100410028020441e0006b2204360204200441206a410c6a200141146a280200360200200441206a41086a2203200141106a2802003602002004200128020836022020042001410c6a28020036022420012903002102200441106a200141186a103a1a200441306a41086a20032903003703002004200429032037033020002802002802002000280204220128020422034101756a21002001280200210102402003410171450d00200028020020016a28020021010b200441d0006a41086a2203200441306a41086a29030037030020042004290330370350200441c0006a200441106a103a1a200441086a200329030037030020042004290350370300200020022004200441c0006a2001110200024020042d0040410171450d00200428024810360b024020042d0010410171450d00200428021810360b4100200441e0006a3602040b3801027f02402000410120001b2201103c22000d0003404100210041002802a40c2202450d0120021103002001103c2200450d000b0b20000b0e0002402000450d002000103f0b0b05001000000be20201067f0240200141704f0d00410a2102024020002d00002205410171450d0020002802002205417e71417f6a21020b0240024020054101710d00200541fe017141017621030c010b200028020421030b410a2104024020032001200320014b1b2201410b490d00200141106a417071417f6a21040b024020042002460d00024002402004410a470d0041012106200041016a210120002802082102410021070c010b200441016a103521010240200420024b0d002001450d020b024020002d000022054101710d0041012107200041016a2102410021060c010b2000280208210241012106410121070b0240024020054101710d00200541fe017141017621050c010b200028020421050b0240200541016a2205450d00200120022005100b1a0b02402006450d00200210360b02402007450d0020002003360204200020013602082000200441016a4101723602000f0b200020034101743a00000b0f0b1000000b05001000000bba0101037f20004200370200200041086a22034100360200024020012d00004101710d00200020012902003702002003200141086a28020036020020000f0b02402001280204220341704f0d00200128020821020240024002402003410b4f0d00200020034101743a0000200041016a210120030d010c020b200341106a4170712204103521012000200441017236020020002001360208200020033602040b200120022003100b1a0b200120036a41003a000020000f0b1000000b4901037f4100210502402002450d000240034020002d0000220320012d00002204470d01200141016a2101200041016a21002002417f6a22020d000c020b0b200320046b21050b20050b090041a80c2000103d0bcd04010c7f02402001450d00024020002802c041220d0d004110210d200041c0c1006a41103602000b200141086a200141046a41077122026b200120021b210202400240024020002802c441220a200d4f0d002000200a410c6c6a4180c0006a21010240200a0d0020004184c0006a220d2802000d0020014180c000360200200d20003602000b200241046a210a034002402001280208220d200a6a20012802004b0d002001280204200d6a220d200d28020041808080807871200272360200200141086a22012001280200200a6a360200200d200d28020041808080807872360200200d41046a22010d030b2000103e22010d000b0b41fcffffff0720026b2104200041c8c1006a210b200041c0c1006a210c20002802c8412203210d03402000200d410c6c6a22014188c0006a28020020014180c0006a2205280200464180ce00100920014184c0006a280200220641046a210d0340200620052802006a2107200d417c6a2208280200220941ffffffff07712101024020094100480d000240200120024f0d000340200d20016a220a20074f0d01200a280200220a4100480d012001200a41ffffffff07716a41046a22012002490d000b0b20082001200220012002491b200941808080807871723602000240200120024d0d00200d20026a200420016a41ffffffff07713602000b200120024f0d040b200d20016a41046a220d2007490d000b41002101200b4100200b28020041016a220d200d200c280200461b220d360200200d2003470d000b0b20010f0b2008200828020041808080807872360200200d0f0b41000b870501087f20002802c44121010240024041002d00d64e450d0041002802d84e21070c010b3f002107410041013a00d64e4100200741107422073602d84e0b200721030240024002400240200741ffff036a41107622023f0022084d0d00200220086b40001a4100210820023f00470d0141002802d84e21030b41002108410020033602d84e20074100480d0020002001410c6c6a210220074180800441808008200741ffff037122084181f8034922061b6a2008200741ffff077120061b6b20076b2107024041002d00d64e0d003f002103410041013a00d64e4100200341107422033602d84e0b20024180c0006a210220074100480d01200321060240200741076a417871220520036a41ffff036a41107622083f0022044d0d00200820046b40001a20083f00470d0241002802d84e21060b4100200620056a3602d84e2003417f460d0120002001410c6c6a22014184c0006a2802002206200228020022086a2003460d020240200820014188c0006a22052802002201460d00200620016a2206200628020041808080807871417c20016b20086a72360200200520022802003602002006200628020041ffffffff07713602000b200041c4c1006a2202200228020041016a220236020020002002410c6c6a22004184c0006a200336020020004180c0006a220820073602000b20080f0b02402002280200220820002001410c6c6a22034188c0006a22012802002207460d0020034184c0006a28020020076a2203200328020041808080807871417c20076b20086a72360200200120022802003602002003200328020041ffffffff07713602000b2000200041c4c1006a220728020041016a22033602c0412007200336020041000f0b2002200820076a36020020020b7b01037f024002402000450d0041002802e84d22024101480d0041a8cc0021032002410c6c41a8cc006a21010340200341046a2802002202450d010240200241046a20004b0d00200220032802006a20004b0d030b2003410c6a22032001490d000b0b0f0b2000417c6a2203200328020041ffffffff07713602000b0300000b0b970c2a0041040b04604f00000041100b14696e76616c69642073796d626f6c206e616d65000041300b0f696e76616c696420737570706c79000041c0000b1c6d61782d737570706c79206d75737420626520706f736974697665000041e0000b336f626a6563742070617373656420746f206974657261746f725f746f206973206e6f7420696e206d756c74695f696e646578000041a0010b21746f6b656e20776974682073796d626f6c20616c726561647920657869737473000041d0010b3363616e6e6f7420637265617465206f626a6563747320696e207461626c65206f6620616e6f7468657220636f6e747261637400004190020b067772697465000041a0020b316d61676e6974756465206f6620617373657420616d6f756e74206d757374206265206c657373207468616e20325e3632000041e0020b176572726f722072656164696e67206974657261746f7200004180030b057265616400004190030b1d6d656d6f20686173206d6f7265207468616e20323536206279746573000041b0030b3c746f6b656e20776974682073796d626f6c20646f6573206e6f742065786973742c2063726561746520746f6b656e206265666f7265206973737565000041f0030b11696e76616c6964207175616e7469747900004190040b1d6d75737420697373756520706f736974697665207175616e74697479000041b0040b1a73796d626f6c20707265636973696f6e206d69736d61746368000041d0040b227175616e74697479206578636565647320617661696c61626c6520737570706c7900004180050b2e6f626a6563742070617373656420746f206d6f64696679206973206e6f7420696e206d756c74695f696e646578000041b0050b3363616e6e6f74206d6f64696679206f626a6563747320696e207461626c65206f6620616e6f7468657220636f6e7472616374000041f0050b2b617474656d707420746f20616464206173736574207769746820646966666572656e742073796d626f6c000041a0060b136164646974696f6e20756e646572666c6f77000041c0060b126164646974696f6e206f766572666c6f77000041e0060b3b757064617465722063616e6e6f74206368616e6765207072696d617279206b6579207768656e206d6f64696679696e6720616e206f626a656374000041a0070b07616374697665000041b0070b2363616e6e6f74207061737320656e64206974657261746f7220746f206d6f64696679000041e0070b1863616e6e6f74207472616e7366657220746f2073656c6600004180080b1a746f206163636f756e7420646f6573206e6f74206578697374000041a0080b13756e61626c6520746f2066696e64206b6579000041c0080b206d757374207472616e7366657220706f736974697665207175616e74697479000041e0080b186e6f2062616c616e6365206f626a65637420666f756e6400004180090b126f766572647261776e2062616c616e6365000041a0090b30617474656d707420746f207375627472616374206173736574207769746820646966666572656e742073796d626f6c000041d0090b167375627472616374696f6e20756e646572666c6f77000041f0090b157375627472616374696f6e206f766572666c6f77000041900a0b2d6f626a6563742070617373656420746f206572617365206973206e6f7420696e206d756c74695f696e646578000041c00a0b3263616e6e6f74206572617365206f626a6563747320696e207461626c65206f6620616e6f7468657220636f6e7472616374000041800b0b35617474656d707420746f2072656d6f7665206f626a656374207468617420776173206e6f7420696e206d756c74695f696e646578000041c00b0b086f6e6572726f72000041d00b0b06656f73696f000041e00b0b406f6e6572726f7220616374696f6e277320617265206f6e6c792076616c69642066726f6d207468652022656f73696f222073797374656d206163636f756e74000041a00c0b0467657400004180ce000b566d616c6c6f635f66726f6d5f6672656564207761732064657369676e656420746f206f6e6c792062652063616c6c6564206166746572205f686561702077617320636f6d706c6574656c7920616c6c6f636174656400"
                },
                {
                    "account": "eosio",
                    "name": "setabi",
                    "authorization": [
                        {
                        "actor": "ednazztokens",
                        "permission": "active"
                        }
                    ],
                    "data": "80a78234ff6f6652b4030e656f73696f3a3a6162692f312e30010c6163636f756e745f6e616d65046e616d6505087472616e7366657200040466726f6d0c6163636f756e745f6e616d6502746f0c6163636f756e745f6e616d65087175616e74697479056173736574046d656d6f06737472696e67066372656174650002066973737565720c6163636f756e745f6e616d650e6d6178696d756d5f737570706c79056173736574056973737565000302746f0c6163636f756e745f6e616d65087175616e74697479056173736574046d656d6f06737472696e67076163636f756e7400010762616c616e63650561737365740e63757272656e63795f7374617473000306737570706c790561737365740a6d61785f737570706c79056173736574066973737565720c6163636f756e745f6e616d6503000000572d3ccdcd087472616e73666572000000000000a531760569737375650000000000a86cd445066372656174650002000000384f4d113203693634010863757272656e6379010675696e743634076163636f756e740000000000904dc603693634010863757272656e6379010675696e7436340e63757272656e63795f7374617473000000"
                }
            ],
            "transaction_extensions": [],
            "context_free_data": []
            }
        }'''

        actionResp = self.client.eos_sign_tx(
            parse_path("m/44'/194'/0'/0/0"),
            json.loads(data))

        assert isinstance(actionResp, proto.EosSignedTx)
        self.assertEqual(binascii.hexlify(actionResp.signature_r), "05544203cc043f3d87c114fdcb7a41769db30cc2f08993541a355c2c52c4be7f")
        self.assertEqual(binascii.hexlify(actionResp.signature_s), "2d9f0799051e023388f1a6fb1d7a1ce489150857a5e0a005f42cf7234a0b2828")
        self.assertEqual(actionResp.signature_v, 32)


def _tx_header(tx):
    header = proto.EosTxHeader(
        expiration=tx.expiration,
        ref_block_num=tx.ref_block_num,
        ref_block_prefix=tx.ref_block_prefix,
        max_net_usage_words=tx.net_usage_words,
        max_cpu_usage_ms=tx.max_cpu_usage_ms,
        delay_sec=tx.delay_sec)

    return header


def _tx_msg(tx):
    msg = proto.EosSignTx(
        address_n=parse_path("m/44'/194'/0'/0/0"),
        chain_id=tx.chain_id,
        header=_tx_header(tx),
        num_actions=tx.num_actions)

    return msg

if __name__ == '__main__':
    unittest.main()
