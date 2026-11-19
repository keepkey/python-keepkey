"""Monero signing, hostile host: plans TxInit must refuse.

Each plan is the honest one with a single thing wrong, sent while an earlier
signing session is still live. It must be refused with the exact reason
before any screen is drawn, and the earlier session must be gone too.
"""

import unittest

import common
import monero_fixtures as xmr
import monero_sign_negative as neg
from monero_sign_negative import SYNTAX, UNEXPECTED
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_monero_pb2 as monero_proto
from keepkeylib import types_pb2 as proto_types

U64 = 2 ** 64 - 1


class TestMsgMoneroSignNegativePlan(neg.SignFlow):

    def setUp(self):
        super(TestMsgMoneroSignNegativePlan, self).setUp()
        self.assert_fresh()

    def refuse(self, change, text, code=SYNTAX, inputs=1, **request):
        """The honest plan after `change(data)` is refused with `text`."""
        p = neg.plan(inputs)
        if change(p['data']) is False:
            p['data'] = None
        response, pages = self.review(p['data'], **request)
        self.assertEqual(pages, [])  # refused before any screen
        self.ends(response, code, text)

    def own(self, data):
        """The index of the wallet's own output in the honest plan."""
        spend = neg.signtx.address_keys(neg.OWN)[0]
        return [d.spend_public_key for d in data.outputs].index(spend)

    def test_nonzero_unlock_time(self):
        for unlock_time in (1, 3000000, U64):
            self.refuse(lambda d: setattr(d, 'unlock_time', unlock_time),
                        'Monero unlock time must be zero')
        self.signs()

    def test_output_count(self):
        def outputs(count):
            def change(data):
                extra = [neg.signtx.destination(neg.PAYEE_SUB, 1, True)
                         for _ in range(count)]
                kept = list(data.outputs)[:count]
                del data.outputs[:]
                data.outputs.extend((kept + extra)[:count])
            return change
        for count in (0, 1, 3, 4, 16):
            self.refuse(outputs(count), neg.OUTPUT_COUNT)
        # More than the message can carry never reaches the handler.
        self.refuse(outputs(17), neg.UNPARSED, UNEXPECTED)
        self.signs()

    def test_ring_size_fork_and_proof_type(self):
        for ring_size in (0, 1, 11, 15, 17, 2 ** 32 - 1):
            self.refuse(lambda d: setattr(d, 'ring_size', ring_size),
                        neg.RING_SIZE)
        self.refuse(lambda d: d.ClearField('ring_size'), neg.RING_SIZE)
        for hard_fork in (0, 1, 15):
            self.refuse(lambda d: setattr(d, 'hard_fork', hard_fork),
                        neg.HARD_FORK)
        self.refuse(lambda d: d.ClearField('hard_fork'), neg.HARD_FORK)
        for bp_version in (0, 1, 2, 3, 5):
            self.refuse(lambda d: setattr(d, 'bp_version', bp_version),
                        neg.RCT_TYPE)
        self.refuse(lambda d: d.ClearField('bp_version'), neg.RCT_TYPE)
        self.signs()

    def test_input_count(self):
        for count in (0, 65, 2 ** 32 - 1):
            self.refuse(lambda d: setattr(d, 'num_inputs', count),
                        neg.INPUT_COUNT)
        self.refuse(lambda d: d.ClearField('num_inputs'), neg.INPUT_COUNT)
        self.signs()

    def test_missing_and_malformed_fields(self):
        self.refuse(lambda d: False, neg.REQUEST)  # no plan at all
        self.refuse(lambda d: d.ClearField('fee'), neg.REQUEST)
        for j in (0, 1):
            for field in ('amount', 'spend_public_key', 'view_public_key'):
                self.refuse(lambda d: d.outputs[j].ClearField(field),
                            neg.REQUEST)
            for field in ('spend_public_key', 'view_public_key'):
                self.refuse(lambda d: setattr(
                    d.outputs[j], field, getattr(d.outputs[j], field)[:31]),
                    neg.REQUEST)
                self.refuse(lambda d: setattr(d.outputs[j], field, b''),
                            neg.REQUEST)
                # 33 bytes do not fit the field.
                self.refuse(lambda d: setattr(
                    d.outputs[j], field,
                    getattr(d.outputs[j], field) + b'\x00'),
                    neg.UNPARSED, UNEXPECTED)
        self.signs()

    def test_path_and_network(self):
        path = "Expected Monero path m/44'/128'/account'"
        for address_n in ([], xmr.path(0)[:2], xmr.path(0) + [0],
                          [xmr.H + 44, xmr.H + 128, 0],
                          [xmr.H + 44, xmr.H + 0, xmr.H + 0],
                          [xmr.H + 49, xmr.H + 128, xmr.H + 0]):
            self.refuse(lambda d: None, path, address_n=address_n)
        # Another wallet of the same seed: the plan's change is not its own.
        self.refuse(lambda d: None, neg.CHANGE, address_n=xmr.path(1))
        # Network 3 does not exist (sent as a raw varint; the enum is closed).
        p = neg.plan()
        request = monero_proto.MoneroTxInitRequest(address_n=xmr.path(0),
                                                   tsx_data=p['data'])
        request.MergeFromString(b'\x10\x03')
        self.ends(self.call(request), SYNTAX, 'Invalid Monero network')
        self.signs()

    def test_payment_id_sizes(self):
        def integrated(size):
            def change(data):
                data.outputs[1 - self.own(data)].is_integrated = True
                data.payment_id = bytes(range(1, size + 1))
            return change
        for size in range(8):
            self.refuse(integrated(size), neg.PAYMENT_ID)
        # Longer than 8 bytes does not fit the field: the old 32-byte
        # unencrypted payment ID cannot even be asked for.
        for size in (9, 16, 32):
            self.refuse(integrated(size), neg.UNPARSED, UNEXPECTED)
        # A payment ID with nowhere to go, and an integrated address
        # without one.
        self.refuse(lambda d: setattr(d, 'payment_id', bytes(8)),
                    neg.PAYMENT_ID)
        self.refuse(
            lambda d: setattr(d.outputs[1 - self.own(d)], 'is_integrated',
                              True), neg.PAYMENT_ID)
        self.signs()

    def test_integrated_destinations(self):
        def both(data):
            data.payment_id = bytes(8)
            for output in data.outputs:
                output.is_integrated = True
        self.refuse(both, neg.INTEGRATED)

        def two_recipients(data):
            # Neither is the change, so this is refused either way; the
            # reason given is the two integrated addresses.
            j = self.own(data)
            data.outputs[j].CopyFrom(neg.signtx.destination(
                xmr.ADDRESSES[('alcohol', 1)][(0, 0)], data.outputs[j].amount))
            both(data)
        self.refuse(two_recipients, neg.INTEGRATED)

        def integrated_subaddress(data):
            data.payment_id = bytes(8)
            payee = data.outputs[1 - self.own(data)]
            payee.is_integrated = payee.is_subaddress = True
        self.refuse(integrated_subaddress, neg.REQUEST)
        self.signs()

    def test_wrong_or_missing_change(self):
        foreign_spend, foreign_view = neg.signtx.address_keys(neg.PAYEE)
        other_own = neg.signtx.address_keys(
            xmr.ADDRESSES[('abandon', 0)][(0, 1)])
        account_1 = neg.signtx.address_keys(
            xmr.ADDRESSES[('abandon', 0)][(1, 0)])

        # No declared change is a send-max plan: allowed, and both outputs
        # are then reviewed as payments (see the screens tests).
        for field in ('amount', 'spend_public_key', 'view_public_key'):
            self.refuse(lambda d: d.change_dts.ClearField(field), neg.CHANGE)
        for field in ('spend_public_key', 'view_public_key'):
            self.refuse(lambda d: setattr(
                d.change_dts, field, getattr(d.change_dts, field)[:31]),
                neg.CHANGE)

        # Declared change that is not this wallet's (account, 0) address.
        def declared(spend=None, view=None):
            def change(data):
                if spend:
                    data.change_dts.spend_public_key = spend
                if view:
                    data.change_dts.view_public_key = view
            return change
        self.refuse(declared(foreign_spend, foreign_view), neg.CHANGE)
        self.refuse(declared(spend=foreign_spend), neg.CHANGE)
        self.refuse(declared(view=foreign_view), neg.CHANGE)
        self.refuse(declared(*other_own), neg.CHANGE)
        self.refuse(declared(*account_1), neg.CHANGE)
        spend, view = neg.signtx.address_keys(neg.OWN)
        self.refuse(declared(spend=neg.torsioned(spend)), neg.CHANGE)
        self.refuse(declared(view=neg.torsioned(view)), neg.CHANGE)
        # The right keys under the wrong index.
        self.refuse(lambda d: setattr(d.change_dts, 'major', 1), neg.CHANGE)
        self.refuse(lambda d: setattr(d.change_dts, 'minor', 1), neg.CHANGE)
        self.refuse(lambda d: setattr(d, 'account', 1), neg.CHANGE)

        def account(data):
            data.account = data.change_dts.major = 1
        self.refuse(account, neg.CHANGE)

        # No output pays the declared change.
        def to(address, subaddress=False):
            def change(data):
                j = self.own(data)
                data.outputs[j].CopyFrom(neg.signtx.destination(
                    address, data.outputs[j].amount, subaddress))
            return change
        self.refuse(to(neg.PAYEE_SUB, True), neg.CHANGE)
        self.refuse(to(xmr.ADDRESSES[('abandon', 0)][(0, 1)], True),
                    neg.CHANGE)
        self.refuse(to(xmr.ADDRESSES[('abandon', 1)][(0, 0)]), neg.CHANGE)

        # What Monero Core builds for a sweep: the recipient and a dummy
        # output of 0 to a random address, no change. 7.17 refuses it.
        def sweep(data):
            j = self.own(data)
            data.outputs[1 - j].amount += data.outputs[j].amount
            data.outputs[j].CopyFrom(neg.signtx.destination(
                xmr.ADDRESSES[('alcohol', 1)][(1, 0)], 0, True))
            data.change_dts.amount = 0
        self.refuse(sweep, neg.CHANGE)

        def torsioned_output(field):
            def change(data):
                output = data.outputs[self.own(data)]
                setattr(output, field, neg.torsioned(getattr(output, field)))
            return change
        self.refuse(torsioned_output('spend_public_key'), neg.POINT)
        self.refuse(torsioned_output('view_public_key'), neg.POINT)

        # The wallet's own address, wrongly described.
        self.refuse(lambda d: setattr(d.outputs[self.own(d)], 'is_subaddress',
                                      True), neg.REQUEST)

        def own_integrated(data):
            data.payment_id = bytes(8)
            data.outputs[self.own(data)].is_integrated = True
        self.refuse(own_integrated, neg.CHANGE)
        self.signs()

    def test_change_amount_mismatch(self):
        for delta in (1, -1, 100000000000):
            # The declared change differs from what the own output is paid.
            self.refuse(lambda d: setattr(d.change_dts, 'amount',
                                          d.change_dts.amount + delta),
                        neg.CHANGE)

            # The own output is paid something else; the recipient makes up
            # the difference, so the totals still balance.
            def moved(data):
                j = self.own(data)
                data.outputs[j].amount += delta
                data.outputs[1 - j].amount -= delta
            self.refuse(moved, neg.CHANGE)
        self.refuse(lambda d: setattr(d.change_dts, 'amount', 0), neg.CHANGE)
        self.refuse(lambda d: setattr(d.change_dts, 'amount', U64),
                    neg.CHANGE)
        self.signs()

    def test_amount_overflow(self):
        def amounts(payee, change, fee):
            def apply(data):
                j = self.own(data)
                data.outputs[1 - j].amount = payee
                data.outputs[j].amount = data.change_dts.amount = change
                data.fee = fee
            return apply
        for payee, change, fee in (
                (U64, 1, 0), (1, U64, 0), (U64, U64, U64), (2 ** 63, 2 ** 63, 0),
                (U64 - 1, 1, 1), (2 ** 63, 2 ** 63 - 1, 1), (0, U64, 1),
                (U64, 0, 1), (1, 1, U64)):
            self.refuse(amounts(payee, change, fee), neg.AMOUNT)
        self.signs()

    def test_recipient_keys_outside_the_group(self):
        own = neg.signtx.address_keys(neg.OWN)
        for field in ('spend_public_key', 'view_public_key'):
            for name, bad in neg.BAD_POINTS:
                self.refuse(lambda d: setattr(d.outputs[1 - self.own(d)],
                                              field, bad), neg.POINT)
            self.refuse(lambda d: setattr(
                d.outputs[1 - self.own(d)], field,
                neg.torsioned(getattr(d.outputs[1 - self.own(d)], field))),
                neg.POINT)
        # The recipient's keys with the wallet's own in the other half.
        self.refuse(lambda d: setattr(d.outputs[1 - self.own(d)],
                                      'view_public_key',
                                      neg.torsioned(own[1])), neg.POINT)
        self.signs()


class TestMsgMoneroSignNegativeNoWallet(common.KeepKeyTest):

    def test_a_wiped_device_starts_nothing(self):
        self.requires_firmware(common.CAPABILITIES_SINCE)
        self.requires_fullFeature()
        self.requires_release_capability('monero-signing')
        response = self.client.call_raw(monero_proto.MoneroTxInitRequest(
            address_n=xmr.path(0), tsx_data=neg.plan()['data']))
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(
            (response.code, response.message),
            (proto_types.Failure_NotInitialized, 'Device not initialized'))
        for message in neg.continuations():
            response = self.client.call_raw(message)
            self.assertIsInstance(response, proto.Failure)
            self.assertEqual((response.code, response.message),
                             (UNEXPECTED, neg.NO_SESSION))


if __name__ == '__main__':
    unittest.main()
