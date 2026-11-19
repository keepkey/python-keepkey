"""Monero signing: what the device showed before it signed.

The host never gets to describe the transaction. These tests read every
page of the review through the debug link, text and pixels, and require the
complete address of every output (never shortened, never cut at a page
break), exact 12-decimal amounts, the fee and the total, and change shown as
change only where the device itself found it. One send is then signed and
its outputs are checked to pay exactly the addresses that were on screen.
"""

import unittest

import monero_fixtures as xmr
import monero_sign_negative as neg
import oled_text
from confirmation_pages import ConfirmationPages
from keepkeylib import messages_monero_pb2 as monero_proto

U64 = 2 ** 64 - 1
OWN_KEYS = neg.signtx.address_keys(neg.OWN)


def xmr_amount(atomic):
    return '%d.%012d XMR' % divmod(atomic, 10 ** 12)


class TestMsgMoneroSignNegativeScreens(neg.SignFlow):

    def reviewed(self, p, network=None, answers=(True,)):
        """TxInit, watched: the response, and each confirmation as
        (title, whole body) after every page was checked on the OLED."""
        response, pages = self.review(p['data'], answers, network, watch=True)
        joined = ConfirmationPages()
        for code, title, body, layout in pages:
            # The pixels are this page's text: nothing clipped or dropped.
            # (A page may end at the line break before an address.)
            self.assertTrue(oled_text.shows(layout, body.rstrip('\n')))
            self.assertIsNotNone(oled_text.find_line(
                layout, title.upper(), oled_text.TITLE_FONT))
            for mark in ('...', '..', u'…', '~'):
                self.assertNotIn(mark, body)
            joined.add(code, (title, body))
        joined.finish()
        return response, list(joined.texts)

    def expect(self, p, shown, network=0, name='Monero', kinds=None,
               payment_id=None, account=0):
        """The whole review, word for word, built from the plan the way the
        device must have built it from its own classification."""
        data = p['data']
        change = [d.spend_public_key for d in data.outputs].index(
            data.change_dts.spend_public_key)
        expected, total = [], data.fee
        for j, d in enumerate(data.outputs):
            if j == change:
                address = neg.encode_address(
                    d.spend_public_key, d.view_public_key, network,
                    subaddress=account != 0)
                expected.append((
                    name + ' change',
                    'Change %s returns to this wallet (account %d), to your '
                    'address\n%s' % (xmr_amount(d.amount), account, address)))
                continue
            total += d.amount
            kind = 'integrated address' if d.is_integrated else \
                'subaddress' if d.is_subaddress else 'standard address'
            address = neg.encode_address(
                d.spend_public_key, d.view_public_key, network,
                d.is_subaddress, payment_id if d.is_integrated else None)
            self.assertEqual(len(address), 106 if d.is_integrated else 95)
            expected.append((name + ' send', 'Send %s to %s\n%s' % (
                xmr_amount(d.amount), kind, address)))
            if d.is_integrated:
                expected.append((
                    name + ' payment ID',
                    'Payment ID %s is sent with this payment.' %
                    payment_id.hex()))
        inputs = data.num_inputs
        expected.append((
            'Sign ' + name, 'Fee %s\nTotal %s\n%d input(s), ring 16, about '
            '%d s' % (xmr_amount(data.fee), xmr_amount(total), inputs,
                      18 + 2 * inputs)))
        self.assertEqual(shown, expected)

    def test_one_full_send(self):
        p = neg.plan()
        self.assertEqual(neg.encode_address(*OWN_KEYS), neg.OWN)
        response, shown = self.reviewed(p)
        self.assertIsInstance(response, monero_proto.MoneroTxInitAck)
        self.expect(p, shown)
        # The literal screens of this send, independent of expect().
        self.assertEqual(shown, [
            ('Monero send',
             'Send 0.666666666666 XMR to standard address\n' + neg.PAYEE),
            ('Monero change',
             'Change 1.333302333334 XMR returns to this wallet (account 0), '
             'to your address\n' + neg.OWN),
            ('Sign Monero',
             'Fee 0.000031000000 XMR\nTotal 0.666697666666 XMR\n'
             '1 input(s), ring 16, about 20 s')])
        # The session that review opened signs exactly that: check() scans
        # each output with the keys of the address that was on screen.
        f = {'p': p, 'init': response, 'ins': [], 'order': [], 'vinis': 0,
             'outs': [], 'signed': []}
        self.set_input(f)
        self.set_vini(f)
        self.ok(monero_proto.MoneroTxAllInputsSetRequest(),
                monero_proto.MoneroTxAllInputsSetAck)
        self.set_output(f)
        self.set_output(f)
        f['all_out'] = self.ok(monero_proto.MoneroTxAllOutSetRequest(),
                               monero_proto.MoneroTxAllOutSetAck)
        self.sign_input(f)
        self.check(p, self.finish(f))
        for (title, body), d in zip(shown, p['data'].outputs):
            address = body.split('\n')[1]
            self.assertEqual(neg.signtx.address_keys(address),
                             (d.spend_public_key, d.view_public_key))

    def test_subaddress_and_change_first(self):
        p = neg.plan(2, neg.PAYEE_SUB, True, change_first=True)
        response, shown = self.reviewed(p)
        self.assertIsInstance(response, monero_proto.MoneroTxInitAck)
        self.expect(p, shown)
        self.assertEqual([title for title, _ in shown],
                         ['Monero change', 'Monero send', 'Sign Monero'])
        self.assertIn(neg.PAYEE_SUB, shown[1][1])
        self.signs(p)

    def test_integrated_address_and_payment_id(self):
        payment_id = bytes.fromhex('f0e1d2c3b4a59687')
        p = neg.integrate(neg.plan(2), payment_id)
        response, shown = self.reviewed(p)
        self.assertIsInstance(response, monero_proto.MoneroTxInitAck)
        self.expect(p, shown, payment_id=payment_id)
        self.assertEqual(shown[1], (
            'Monero payment ID',
            'Payment ID f0e1d2c3b4a59687 is sent with this payment.'))
        # All 106 characters, and they are not the plain address.
        address = shown[0][1].split('\n')[1]
        self.assertEqual(len(address), 106)
        self.assertNotIn(neg.PAYEE, shown[0][1])
        self.signs()

    def test_change_to_another_account(self):
        own_1 = xmr.ADDRESSES[('abandon', 0)][(1, 0)]
        self.assertEqual(
            neg.encode_address(*neg.own_subaddress(1, 0), subaddress=True),
            own_1)
        p = neg.account_plan(1, [(neg.OUTPUTS[2], 3000000000000)])
        response, shown = self.reviewed(p)
        self.assertIsInstance(response, monero_proto.MoneroTxInitAck)
        self.expect(p, shown, account=1)
        self.assertIn('(account 1), to your address\n' + own_1, shown[1][1])
        self.signs(p)

    def test_other_networks_are_named_on_every_screen(self):
        payment_id = bytes(range(8))
        for network, name in ((1, 'Monero TESTNET'), (2, 'Monero STAGENET')):
            p = neg.integrate(neg.plan(2), payment_id)
            response, shown = self.reviewed(p, network)
            self.assertIsInstance(response, monero_proto.MoneroTxInitAck)
            self.expect(p, shown, network, name, payment_id=payment_id)
            self.assertEqual(len(shown), 4)
            # None of this network's addresses is a mainnet one.
            for _, body in shown[:3:2]:
                self.assertNotIn(neg.PAYEE[:8], body)
                self.assertNotIn(neg.OWN[:8], body)
            f = self.finish(self.reach(p, 'signed', network))
            self.assertEqual(len(f['clsags']), 2)
            self.assert_dead()
        self.signs()

    def test_second_own_output_is_shown_as_a_payment(self):
        # Two outputs to the wallet's own address. Only one can be the
        # change, the one the declared change amount matches; the other is a
        # payment like any other and counts in the total.
        for send, change in ((1000000000000, 969000000), (5, 5),
                             (0, 1999969000000)):
            for change_first in (False, True):
                p = neg.plan()
                data = p['data']
                amounts = [change, send] if change_first else [send, change]
                for output, amount in zip(data.outputs, amounts):
                    output.CopyFrom(neg.signtx.destination(neg.OWN, amount))
                data.change_dts.amount = change
                data.fee = 2000000000000 - send - change
                response, shown = self.reviewed(p)
                self.assertIsInstance(response, monero_proto.MoneroTxInitAck)
                # With equal amounts the first is the change.
                first = change_first or send == change
                paid = 'Monero send' if send else 'Monero zero-amount output'
                titles = ['Monero change', paid] if first else \
                    [paid, 'Monero change']
                bodies = dict(shown)
                self.assertEqual([t for t, _ in shown],
                                 titles + ['Sign Monero'])
                self.assertEqual(
                    bodies[paid],
                    ('Send %s to standard address\n%s' if send else
                     'Zero-amount output: %s to standard address\n%s') %
                    (xmr_amount(send), neg.OWN))
                self.assertEqual(
                    bodies['Monero change'],
                    'Change %s returns to this wallet (account 0), to your '
                    'address\n%s' % (xmr_amount(change), neg.OWN))
                self.assertIn('Total %s\n' % xmr_amount(send + data.fee),
                              bodies['Sign Monero'])
                f = self.finish(self.reach(p, 'signed'))
                self.assertEqual(len(f['clsags']), 1)
        self.signs()

    def test_no_declared_change_reviews_both_outputs_as_payments(self):
        # A send-max plan declares no change. Nothing is taken on trust:
        # both outputs are reviewed as payments, the wallet's own included,
        # and the total counts both.
        p = neg.plan()
        data = p['data']
        data.ClearField('change_dts')
        response, shown = self.reviewed(p)
        self.assertIsInstance(response, monero_proto.MoneroTxInitAck)
        self.assertEqual([t for t, _ in shown],
                         ['Monero send', 'Monero send', 'Sign Monero'])
        total = sum(o.amount for o in data.outputs) + data.fee
        self.assertIn('Total %s\n' % xmr_amount(total), shown[-1][1])
        for output, (_, body) in zip(data.outputs, shown):
            self.assertIn(xmr_amount(output.amount), body)

    def test_largest_amounts_and_longest_screens(self):
        # The longest text each screen can carry: the largest account, the
        # largest amounts and an integrated recipient.
        account, payment_id = 2 ** 32 - 1, bytes([0xff] * 8)
        p = neg.account_plan(account, [(neg.OUTPUTS[0], 10 ** 12)] * 64)
        neg.integrate(p, payment_id)
        data = p['data']
        own = [d.spend_public_key for d in data.outputs].index(
            data.change_dts.spend_public_key)
        data.fee = 1000000000000
        data.outputs[own].amount = data.change_dts.amount = \
            10000000000000000000
        data.outputs[1 - own].amount = U64 - data.fee - 10 ** 19
        response, shown = self.reviewed(p)
        self.assertIsInstance(response, monero_proto.MoneroTxInitAck)
        self.expect(p, shown, payment_id=payment_id, account=account)
        self.assertIn('Send 8446743.073709551615 XMR', shown[0][1])
        self.assertIn('Change 10000000.000000000000 XMR', shown[2][1])
        self.assertIn('(account 4294967295)', shown[2][1])
        self.assertIn('Total 8446744.073709551615 XMR\n64 input(s)',
                      shown[3][1])
        # One input worth every atomic unit there is still signs.
        p = neg.plan()
        data = p['data']
        own = [d.spend_public_key for d in data.outputs].index(OWN_KEYS[0])
        data.outputs[own].amount = data.change_dts.amount = 1
        data.outputs[1 - own].amount = U64 - 1 - data.fee
        p['sources'][0].amount = U64
        p['sources'][0].ring[p['sources'][0].real_index].commitment = \
            neg.signtx.commit(int.from_bytes(p['sources'][0].mask, 'little'),
                              U64)
        response, shown = self.reviewed(p)
        self.expect(p, shown)
        self.assertIn('Send 18446744.073678551614 XMR', shown[0][1])
        self.assertIn('Total 18446744.073709551614 XMR', shown[2][1])
        self.signs(p)


if __name__ == '__main__':
    unittest.main()
