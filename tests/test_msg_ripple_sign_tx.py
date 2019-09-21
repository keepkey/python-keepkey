# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
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

import pytest
import unittest
import common
import binascii

from keepkeylib import messages_ripple_pb2 as messages
from keepkeylib import types_pb2 as types
from keepkeylib import ripple
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

class TestMsgRippleSignTx(common.KeepKeyTest):
    def test_sign(self):
        self.setup_mnemonic_allallall()

        msg = messages.RippleSignTx(
            address_n=parse_path("m/44'/144'/0'/0/0"),
            payment=messages.RipplePayment(
                amount=100000000,
                destination="rBKz5MC2iXdoS3XgnNSYmF69K1Yo4NS3Ws"
            ),
            flags=0x80000000,
            fee=100000,
            sequence=25
        )
        resp = self.client.call(msg)

        self.assertEqual(
            binascii.hexlify(resp.serialized_tx),
            "12000022800000002400000019614000000005f5e1006840000000000186a0732102131facd1eab748d6cddc492f54b04e8c35658894f4add2232ebc5afe7521dbe474473045022100e243ef623675eeeb95965c35c3e06d63a9fc68bb37e17dc87af9c0af83ec057e02206ca8aa5eaab8396397aef6d38d25710441faf7c79d292ee1d627df15ad9346c081148fb40e1ffa5d557ce9851a535af94965e0dd098883147148ebebf7304ccdf1676fefcf9734cf1e780826"
        )
        self.assertEqual(
            binascii.hexlify(resp.signature),
            "3045022100e243ef623675eeeb95965c35c3e06d63a9fc68bb37e17dc87af9c0af83ec057e02206ca8aa5eaab8396397aef6d38d25710441faf7c79d292ee1d627df15ad9346c0"
        )

        # ----

        msg = messages.RippleSignTx(
            address_n=parse_path("m/44'/144'/0'/0/2"),
            payment=messages.RipplePayment(
                amount=1,
                destination="rNaqKtKrMSwpwZSzRckPf7S96DkimjkF4H"
            ),
            fee=10,
            sequence=1
        )
        resp = self.client.call(msg)

        self.assertEqual(
            binascii.hexlify(resp.signature),
            "3044022069900e6e578997fad5189981b74b16badc7ba8b9f1052694033fa2779113ddc002206c8006ada310edf099fb22c0c12073550c8fc73247b236a974c5f1144831dd5f"
        )
        self.assertEqual(
            binascii.hexlify(resp.serialized_tx),
            "1200002280000000240000000161400000000000000168400000000000000a732103dbed1e77cb91a005e2ec71afbccce5444c9be58276665a3859040f692de8fed274463044022069900e6e578997fad5189981b74b16badc7ba8b9f1052694033fa2779113ddc002206c8006ada310edf099fb22c0c12073550c8fc73247b236a974c5f1144831dd5f8114bdf86f3ae715ba346b7772ea0e133f48828b766483148fb40e1ffa5d557ce9851a535af94965e0dd0988"
        )

        # ----

        msg = messages.RippleSignTx(
            address_n=parse_path("m/44'/144'/0'/0/2"),
            payment=messages.RipplePayment(
                amount=100000009,
                destination="rNaqKtKrMSwpwZSzRckPf7S96DkimjkF4H",
                destination_tag=123456
            ),
            fee=100,
            sequence=100,
            last_ledger_sequence=333111
        )
        resp = self.client.call(msg)

        self.assertEqual(
            binascii.hexlify(resp.signature),
            "30450221008770743a472bb2d1c746a53ef131cc17cc118d538ec910ca928d221db4494cf702201e4ef242d6c3bff110c3cc3897a471fed0f5ac10987ea57da63f98dfa01e94df"
        )
        self.assertEqual(
            binascii.hexlify(resp.serialized_tx),
            "120000228000000024000000642e0001e240201b00051537614000000005f5e109684000000000000064732103dbed1e77cb91a005e2ec71afbccce5444c9be58276665a3859040f692de8fed2744730450221008770743a472bb2d1c746a53ef131cc17cc118d538ec910ca928d221db4494cf702201e4ef242d6c3bff110c3cc3897a471fed0f5ac10987ea57da63f98dfa01e94df8114bdf86f3ae715ba346b7772ea0e133f48828b766483148fb40e1ffa5d557ce9851a535af94965e0dd0988"
        )


    def test_ripple_sign_invalid_fee(self):
        self.setup_mnemonic_allallall()

        msg = messages.RippleSignTx(
            address_n=parse_path("m/44'/144'/0'/0/2"),
            payment=messages.RipplePayment(
                amount=1,
                destination="rNaqKtKrMSwpwZSzRckPf7S96DkimjkF4H"
            ),
            fee=1,
            flags=1,
            sequence=1
        )

        with pytest.raises(CallException) as exc:
            self.client.call(msg)
        self.assertEqual(exc.value.args[0], types.FailureType.Failure_SyntaxError)
        self.assertEndsWith(exc.value.args[1], "Fee must be between 10 and 1,000,000 drops")

if __name__ == '__main__':
    unittest.main()
