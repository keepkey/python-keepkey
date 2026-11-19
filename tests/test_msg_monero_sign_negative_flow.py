"""Monero signing, hostile host: interruptions.

Cancel on every page of the review and in the middle of a proof, Initialize,
ClearSession, an idle lock, PIN and passphrase prompts, unrelated requests
between steps and during a proof, continuations that arrive nested in a
prompt or after their session is gone. Whatever interrupts a signing session
ends it: nothing half-done survives, and nothing is signed.
"""

import unittest

import monero_fixtures as xmr
import monero_sign_negative as neg
import test_msg_monero_key_image as key_image
from monero_sign_negative import UNEXPECTED, CANCELLED, SYNTAX
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_monero_pb2 as monero_proto
from keepkeylib import types_pb2 as proto_types

TINY_UNKNOWN = 'Unknown message'
TINY_MALFORMED = 'Malformed tiny packet'


def long_plan():
    """The review with the most pages: an integrated recipient with its
    payment ID and change."""
    p = neg.plan(2)
    neg.integrate(p)
    return p


class TestMsgMoneroSignNegativeFlow(neg.SignFlow):

    def setUp(self):
        super(TestMsgMoneroSignNegativeFlow, self).setUp()
        # Before any TxInit there is nothing to continue.
        self.assert_dead()
        self.assert_fresh()

    def proving(self, p, stage):
        """A session at `stage` and the request that starts its next proof:
        the range proof after 'out0', a CLSAG after 'all_out' or 'sign1'."""
        f = self.reach(p, stage)
        if stage == 'out0':
            return f, self.output_request(f, 1)
        return f, self.sign_request(f, f['order'][len(f['signed'])])

    # ---- the review ----

    def test_cancel_on_every_review_page(self):
        p = long_plan()
        ack, pages = self.review(p['data'], watch=True)
        self.assertIsInstance(ack, monero_proto.MoneroTxInitAck)
        titles = [title for _, title, _, _ in pages]
        self.assertEqual(
            [t.rsplit(' ', 1)[0] if t[-1].isdigit() else t for t in titles],
            ['Monero send'] * 2 + ['Monero payment ID'] +
            ['Monero change'] * 2 + ['Sign Monero'])
        for k in range(len(pages)):
            before = (True,) * k
            # The button, the host's Cancel, and a restart of the host.
            for answer in (False, proto.Cancel()):
                response, seen = self.review(p['data'], before + (answer,))
                self.assertEqual(len(seen), k + 1)
                self.ends(response, CANCELLED, neg.SIGNING_CANCELLED)
            response, seen = self.review(p['data'],
                                         before + (proto.Initialize(),))
            self.assertEqual(len(seen), k + 1)
            self.assertIsInstance(response, proto.Features)
            self.assertEqual(self.pending(), [])
            self.assert_dead()
            self.assert_fresh()
        self.signs()

    def test_other_messages_on_every_review_page(self):
        p = long_plan()
        old = self.reach(neg.plan(2), 'inputs')
        ack, pages = self.review(p['data'])
        self.assertIsInstance(ack, monero_proto.MoneroTxInitAck)
        self.assertEqual(len(pages), 6)
        for k in range(len(pages)):
            before = (True,) * k
            # What a prompt does not expect, from the answers to other
            # prompts to the next steps of the session that was live before.
            for answer, text in (
                    (proto.PinMatrixAck(pin='1'),
                     'Unexpected message during protected wait'),
                    (proto.PassphraseAck(passphrase='x'),
                     'Unexpected message during protected wait'),
                    (proto.Ping(message='x'), TINY_UNKNOWN),
                    (proto.GetFeatures(), TINY_UNKNOWN),
                    (monero_proto.MoneroTxAllInputsSetRequest(), TINY_UNKNOWN),
                    (monero_proto.MoneroTxFinalRequest(), TINY_UNKNOWN)):
                response, seen = self.review(p['data'], before + (answer,))
                self.assertEqual(len(seen), k + 1)
                self.assertEqual(self.pending(), [])
                self.ends(response, UNEXPECTED, text)
            # Requests of more than one packet: a vini of the earlier
            # session, and a whole new TxInit. Every packet is refused.
            for answer in (self.vini_request(old, old['order'][0]),
                           monero_proto.MoneroTxInitRequest(
                               address_n=xmr.path(0), tsx_data=p['data'])):
                response, seen = self.review(p['data'], before + (answer,))
                self.refused(response, UNEXPECTED, TINY_MALFORMED)
                rest = self.pending()
                self.assertTrue(rest)
                for failure in rest:
                    self.refused(failure, UNEXPECTED, 'Malformed packet')
                self.assert_dead()
                self.assert_fresh()
        self.signs()

    # ---- during a proof ----

    def test_cancel_during_proving(self):
        p = neg.plan(2)
        for stage in ('out0', 'all_out', 'sign1'):
            f, request = self.proving(p, stage)
            response = self.during(request, proto.Cancel())
            self.assertEqual(self.pending(), [])
            self.ends(response, CANCELLED, neg.SIGNING_CANCELLED)
            # A restarting host: answered as Initialize, session gone.
            f, request = self.proving(p, stage)
            response = self.during(request, proto.Initialize())
            self.assertIsInstance(response, proto.Features)
            self.assertEqual(self.pending(), [])
            self.assert_dead()
            self.assert_fresh()
        self.signs(p)

    def test_unrelated_message_during_proving(self):
        p = neg.plan(2)
        for stage in ('out0', 'all_out', 'sign1'):
            # Whole requests, the session's own next steps among them, and
            # the read-only ones that would not disturb it between steps.
            for message in (proto.Ping(message='x'), proto.GetFeatures(),
                            proto.GetCoinTable(), proto.ClearSession(),
                            proto.GetPublicKey(address_n=[]),
                            monero_proto.MoneroTxAllOutSetRequest(),
                            monero_proto.MoneroTxFinalRequest()):
                f, request = self.proving(p, stage)
                response = self.during(request, message)
                self.assertEqual(self.pending(), [])
                self.ends(response, UNEXPECTED, TINY_UNKNOWN)
            # Answers to prompts that are not there.
            for message in (proto.ButtonAck(), proto.PinMatrixAck(pin='1'),
                            proto.PassphraseAck(passphrase='x')):
                f, request = self.proving(p, stage)
                response = self.during(request, message)
                self.assertEqual(self.pending(), [])
                self.ends(response, CANCELLED, neg.SIGNING_CANCELLED)
            # Packets that are no message at all: short, without a header,
            # of no known type, a Cancel that does not parse, a message
            # announced longer than its packet.
            cancel = neg.message_id(proto.Cancel())
            for datagram, code, text in (
                    (b'?##ab', UNEXPECTED, TINY_MALFORMED),
                    (b'?', UNEXPECTED, TINY_MALFORMED),
                    (b'?abc' + bytes(60), UNEXPECTED, TINY_MALFORMED),
                    (bytes(64), UNEXPECTED, TINY_MALFORMED),
                    (neg.frame(9999), UNEXPECTED, TINY_UNKNOWN),
                    (neg.frame(cancel, b'\xff\xff\xff'), SYNTAX,
                     TINY_MALFORMED),
                    (neg.frame(cancel, declared=56), UNEXPECTED,
                     TINY_MALFORMED),
                    (neg.frame(cancel, declared=2 ** 32 - 1), UNEXPECTED,
                     TINY_MALFORMED)):
                f, request = self.proving(p, stage)
                response = self.during_raw(request, datagram)
                self.assertEqual(self.pending(), [])
                self.ends(response, code, text)
            # The next proof's request, of several packets, pipelined.
            f, request = self.proving(p, stage)
            response = self.during(request, request)
            self.refused(response, UNEXPECTED, TINY_MALFORMED)
            rest = self.pending()
            self.assertTrue(rest)
            for failure in rest:
                self.refused(failure, UNEXPECTED, 'Malformed packet')
            self.assert_dead()
            self.assert_fresh()
        self.signs(p)

    # ---- between steps ----

    def test_other_requests_end_the_session(self):
        p = neg.plan(2)
        set_input = neg.message_id(monero_proto.MoneroTxSetInputRequest())

        def initialize():
            return self.assertIsInstance(self.call(proto.Initialize()),
                                         proto.Features)

        def clear_session():
            return self.assertIsInstance(self.call(proto.ClearSession()),
                                         proto.Success)

        def ping():
            return self.assertIsInstance(self.call(proto.Ping(message='x')),
                                         proto.Success)

        def cancel():
            return self.refused(self.call(proto.Cancel()), CANCELLED,
                                'Aborted')

        def public_key():
            return self.assertIsInstance(
                self.call(proto.GetPublicKey(address_n=[])), proto.PublicKey)

        def monero_address():
            return self.assertIsInstance(
                self.call(monero_proto.MoneroGetAddress(
                    address_n=xmr.path(0))), monero_proto.MoneroAddress)

        def unknown_message():
            return self.refused(self.send_raw(9999), UNEXPECTED,
                                'Unknown message')

        def unparsed_step():
            return self.refused(self.send_raw(set_input, b'\xff\xff\xff'),
                                UNEXPECTED, neg.UNPARSED)

        def malformed_packet():
            self.client.transport.socket.send(b'?abc' + bytes(60))
            return self.refused(self.client.transport.read_blocking(),
                                UNEXPECTED, 'Malformed packet')

        def short_packet():
            self.client.transport.socket.send(b'?##ab')
            return self.refused(self.client.transport.read_blocking(),
                                UNEXPECTED, 'Buffer too small')

        def stray_answers():
            # Answers to prompts that are not on screen.
            for answer in (proto.ButtonAck(), proto.PinMatrixAck(pin='1'),
                           proto.PassphraseAck(passphrase='x')):
                self.refused(self.call(answer), UNEXPECTED,
                             'Unexpected message')

        for stage in ('init', 'input1', 'inputs', 'vinis', 'all_in', 'out0',
                      'out1', 'all_out', 'sign1', 'signed'):
            for interruption in (initialize, clear_session, ping, cancel,
                                 public_key, monero_address, unknown_message,
                                 unparsed_step, malformed_packet,
                                 short_packet, stray_answers):
                self.reach(p, stage)
                interruption()
                self.assertEqual(self.pending(), [])
                self.assert_dead()
        self.signs(p)

    def test_status_requests_keep_the_session(self):
        # The control for the test above: the session is not simply dead
        # after any request. Features and the coin table may be read at
        # every step, and the transaction still verifies.
        p = neg.plan(2)

        def status():
            self.assertIsInstance(self.call(proto.GetFeatures()),
                                  proto.Features)
            self.assertIsInstance(self.call(proto.GetCoinTable()),
                                  proto.CoinTable)
        f = self.start(p)
        status()
        for _ in range(2):
            self.set_input(f)
            status()
        for _ in range(2):
            self.set_vini(f)
            status()
        self.ok(monero_proto.MoneroTxAllInputsSetRequest(),
                monero_proto.MoneroTxAllInputsSetAck)
        for _ in range(2):
            status()
            self.set_output(f)
        status()
        f['all_out'] = self.ok(monero_proto.MoneroTxAllOutSetRequest(),
                               monero_proto.MoneroTxAllOutSetAck)
        for _ in range(2):
            status()
            self.sign_input(f)
        status()
        self.check(p, self.finish(f))
        self.assert_dead()

    def test_nested_init(self):
        p = neg.plan(2)
        # A second TxInit, declined: the first session does not come back.
        old = self.reach(p, 'inputs')
        response, _ = self.review(p['data'], answers=(False,))
        self.refused(response, CANCELLED, neg.SIGNING_CANCELLED)
        self.refused(self.call(self.vini_request(old, old['order'][0])),
                     UNEXPECTED, neg.NO_SESSION)
        self.assert_dead()
        # A second TxInit, approved: the first session's steps do not
        # continue the second one.
        for stage, request in (
                ('inputs', lambda f: self.vini_request(f, f['order'][0])),
                ('all_in', lambda f: self.output_request(f, 0)),
                ('all_out', lambda f: self.sign_request(f, f['order'][0]))):
            old = self.reach(p, stage)
            new = self.reach(p, stage)
            self.assertNotEqual(old['init'].dst_hmacs, new['init'].dst_hmacs)
            self.ends(self.call(request(old)), neg.OTHER, neg.MAC)
        self.signs(p)

    def test_key_image_sync_and_signing_do_not_coexist(self):
        p = neg.plan(2)
        outputs = neg.OUTPUTS[:2]

        def sync():
            return self.client.monero_key_image_export_init(
                num=len(outputs), hash=xmr.transcript_hash(outputs),
                address_n=xmr.path(0), network_type=0,
                subs=key_image.subaddresses())
        step = monero_proto.MoneroKeyImageSyncStepRequest(
            tdis=[key_image.details(outputs[0])])
        gone = 'Monero key-image sync not in progress'

        # A sync started in the middle of signing ends the signing.
        for stage in ('inputs', 'out0', 'all_out'):
            self.reach(p, stage)
            self.assertIsInstance(sync(),
                                  monero_proto.MoneroKeyImageExportInitAck)
            self.assert_dead()
            # ... and signing started in the middle of a sync ends the sync,
            # whether the review is approved, declined or refused.
            self.reach(p, 'input1')
            self.refused(self.call(step), UNEXPECTED, gone)
            self.assert_dead()
            sync()
            response, _ = self.review(p['data'], answers=(False,))
            self.refused(response, CANCELLED, neg.SIGNING_CANCELLED)
            self.refused(self.call(step), UNEXPECTED, gone)
            sync()
            p['data'].ring_size = 11
            response, _ = self.review(p['data'])
            p['data'].ring_size = 16
            self.refused(response, SYNTAX, neg.RING_SIZE)
            self.refused(self.call(step), UNEXPECTED, gone)
            self.assert_dead()
        # A sync step sent into a signing session ends it too.
        self.reach(p, 'inputs')
        self.refused(self.call(step), UNEXPECTED, gone)
        self.assert_dead()
        self.signs(p)

    def test_bitcoin_signing_and_monero_signing_do_not_coexist(self):
        p = neg.plan(2)
        sign_tx = proto.SignTx(inputs_count=1, outputs_count=1,
                               coin_name='Bitcoin')
        stale = 'Signing not in progress'
        # A Bitcoin signing that waits for its first input is ended by a
        # Monero TxInit, approved or declined; its stale TxAck then ends
        # the Monero session in turn.
        for answers in ((True,), (False,)):
            self.assertIsInstance(self.call(sign_tx), proto.TxRequest)
            self.review(p['data'], answers)
            self.refused(self.call(proto.TxAck()), UNEXPECTED, stale)
            self.assert_dead()
        # A Monero session is ended by a Bitcoin SignTx.
        for stage in ('inputs', 'out0', 'all_out', 'signed'):
            self.reach(p, stage)
            self.assertIsInstance(self.call(sign_tx), proto.TxRequest)
            self.assert_dead()
            self.refused(self.call(proto.TxAck()), UNEXPECTED, stale)
        self.signs(p)


class TestMsgMoneroSignNegativePin(neg.SignFlow):
    PIN = '1234'

    def setUp(self):
        super(TestMsgMoneroSignNegativePin, self).setUp()
        self.lock()

    def lock(self):
        self.assertIsInstance(self.call(proto.ClearSession()), proto.Success)
        self.assertFalse(self.call(proto.GetFeatures()).pin_cached)

    def init(self, p):
        return self.call(monero_proto.MoneroTxInitRequest(
            address_n=xmr.path(0), tsx_data=p['data']))

    def test_pin_prompt_before_the_review(self):
        p = neg.plan()
        # Locked: TxInit asks for the PIN before it shows anything.
        self.assertIsInstance(self.init(p), proto.PinMatrixRequest)
        self.refused(self.call(proto.Cancel()),
                     proto_types.Failure_PinCancelled, 'PIN Cancelled')
        self.assert_dead()
        self.assertIsInstance(self.init(p), proto.PinMatrixRequest)
        self.refused(self.call(proto.PinMatrixAck(pin='444222')),
                     proto_types.Failure_PinInvalid, 'Invalid PIN')
        self.assert_dead()
        self.assertFalse(self.call(proto.GetFeatures()).pin_cached)
        # Steps sent to the PIN prompt are no answer to it.
        for message in (monero_proto.MoneroTxAllInputsSetRequest(),
                        monero_proto.MoneroTxFinalRequest(),
                        proto.ButtonAck()):
            self.assertIsInstance(self.init(p), proto.PinMatrixRequest)
            response = self.call(message)
            self.assertIsInstance(response, proto.Failure)
            self.assertEqual(self.pending(), [])
            self.assert_dead()
            self.assertFalse(self.call(proto.GetFeatures()).pin_cached)
        self.assertIsInstance(self.init(p), proto.PinMatrixRequest)
        self.assertIsInstance(self.call(proto.Initialize()), proto.Features)
        self.assert_dead()
        # With the PIN, the same device signs.
        self.signs()

    def test_losing_the_pin_ends_the_session(self):
        p = neg.plan(2)
        for stage in ('init', 'inputs', 'out0', 'all_out', 'sign1', 'signed'):
            f = self.reach(p, stage)
            self.assertTrue(self.call(proto.GetFeatures()).pin_cached)
            self.lock()
            self.assert_dead()
            # The next TxInit starts at the PIN prompt again.
            self.assertIsInstance(self.init(p), proto.PinMatrixRequest)
            self.refused(self.call(proto.Cancel()),
                         proto_types.Failure_PinCancelled, 'PIN Cancelled')
            self.assert_dead()
        self.signs(p)

    def test_pin_change_and_wipe_prompts_end_the_session(self):
        p = neg.plan(2)
        for request, text in ((proto.ChangePin(), 'PIN change cancelled'),
                              (proto.ChangePin(remove=True),
                               'PIN removal cancelled'),
                              (proto.WipeDevice(), 'Wipe cancelled')):
            for stage in ('inputs', 'out0', 'all_out'):
                self.reach(p, stage)
                self.assertIsInstance(self.call(request), proto.ButtonRequest)
                self.refused(self.call(proto.Cancel()), CANCELLED, text)
                self.assert_dead()
        self.signs(p)

    def test_idle_lock_ends_the_session(self):
        p = neg.plan(2)
        # The shortest idle lock the device accepts: 30 seconds.
        self.reach(p, 'init')
        response = self.client.call(proto.ApplySettings(
            auto_lock_delay_ms=30000))
        self.assertIsInstance(response, proto.Success)
        self.assert_dead()
        self.assertEqual(self.call(proto.GetFeatures()).auto_lock_delay_ms,
                         30000)
        f = self.reach(p, 'inputs')
        self.assertTrue(self.call(proto.GetFeatures()).pin_cached)
        neg.wait(31)
        # The emulator's clock can run behind the wall clock on a busy
        # machine. Reading the features neither ends a session nor counts
        # as activity, so it is safe to ask until the lock has happened.
        for _ in range(30):
            if not self.call(proto.GetFeatures()).pin_cached:
                break
            neg.wait(2)
        self.assertFalse(self.call(proto.GetFeatures()).pin_cached)
        # Locked: the stalled session went with the PIN.
        self.refused(self.call(self.vini_request(f, f['order'][0])),
                     UNEXPECTED, neg.NO_SESSION)
        self.assert_dead()
        self.assertIsInstance(self.init(p), proto.PinMatrixRequest)
        self.refused(self.call(proto.Cancel()),
                     proto_types.Failure_PinCancelled, 'PIN Cancelled')
        self.signs(p)


class TestMsgMoneroSignNegativePassphrase(neg.SignFlow):
    PASSPHRASE = ''

    def test_passphrase_prompt_and_change(self):
        p = neg.plan(2)
        request = monero_proto.MoneroTxInitRequest(address_n=xmr.path(0),
                                                   tsx_data=p['data'])
        # Cancelled at the passphrase prompt: nothing starts.
        self.assertIsInstance(self.call(request), proto.PassphraseRequest)
        self.refused(self.call(proto.Cancel()),
                     proto_types.Failure_NotInitialized,
                     'Device not initialized or passphrase request cancelled')
        self.assert_dead()
        # The empty passphrase is the wallet the plan was made for.
        self.signs(p)
        for stage in ('inputs', 'out0', 'all_out'):
            self.passphrase = ''
            f = self.reach(p, stage)
            # Forgetting the passphrase ends the session ...
            self.assertIsInstance(self.call(proto.ClearSession()),
                                  proto.Success)
            self.assert_dead()
            # ... and under another passphrase this is another wallet: the
            # plan's change is not its own, and no part of it is shown.
            self.passphrase = 'another wallet'
            response, pages = self.review(p['data'], watch=True)
            self.refused(response, SYNTAX, neg.CHANGE)
            for _, title, body, _ in pages:
                self.assertNotIn('Monero', title + body)
                self.assertNotIn('XMR', body)
            self.assert_dead()
            self.assertIsInstance(self.call(proto.ClearSession()),
                                  proto.Success)
        self.passphrase = ''
        self.signs(p)

    def test_turning_the_passphrase_off_ends_the_session(self):
        p = neg.plan(2)
        self.reach(p, 'all_out')
        response = self.client.call(proto.ApplySettings(use_passphrase=False))
        self.assertIsInstance(response, proto.Success)
        self.assert_dead()
        self.signs(p)


if __name__ == '__main__':
    unittest.main()
