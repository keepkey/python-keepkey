"""Monero signing, hostile host: the state the host holds between steps.

The device keeps a small session and hands the host the public pieces, each
with a MAC. These tests change every such piece, replay pieces of an earlier
session, send the steps in the wrong order, repeat inputs, lie about what an
input is worth and present inputs the wallet cannot spend. Every attempt
must end the session with its exact Failure.
"""

import unittest

import monero_fixtures as xmr
import monero_sign_negative as neg
from monero_sign_negative import SYNTAX, OTHER, UNEXPECTED, MAC, flipped
from keepkeylib import messages_monero_pb2 as monero_proto

U64 = 2 ** 64 - 1


def real(src):
    return src.ring[src.real_index]


def revalue(src, amount):
    """The input is worth `amount`, and its commitment says so too."""
    src.amount = amount
    real(src).commitment = neg.signtx.commit(
        int.from_bytes(src.mask, 'little'), amount)


class TestMsgMoneroSignNegativeState(neg.SignFlow):

    # ---- every MAC'd piece, changed ----

    def test_tampered_vini(self):
        p = neg.plan(2)

        def attempt(change, code=OTHER, text=MAC, position=0):
            f = self.reach(p, 'inputs' if position == 0 else 'vini1')
            i, other = f['order'][position], f['order'][1 - position]
            request = self.vini_request(f, i)
            change(request, f['ins'][other], other)
            self.ends(self.call(request), code, text)

        def vini(edit):
            return lambda r, o, k: setattr(r, 'vini', edit(r.vini))

        for position in (0, 1):
            # tag, amount, ring count, first and last offset, key image
            for index in (0, 1, 2, 3, -33, -32, -1):
                attempt(vini(lambda v: flipped(v, index)), position=position)
            attempt(vini(lambda v: v[:-1]), position=position)
            attempt(vini(lambda v: v + b'\x00'), position=position)
            attempt(lambda r, o, k: setattr(r, 'vini', o.vini),
                    position=position)
            for index in (0, 31):
                attempt(lambda r, o, k: setattr(
                    r, 'vini_hmac', flipped(r.vini_hmac, index)),
                    position=position)
            attempt(lambda r, o, k: setattr(r, 'vini_hmac', o.vini_hmac),
                    position=position)
            attempt(lambda r, o, k: setattr(r, 'vini_hmac', bytes(32)),
                    position=position)
        # A vini under the other input's index.
        attempt(lambda r, o, k: setattr(r, 'orig_idx', k))
        # Not a vini at all.
        attempt(vini(lambda v: v[:34]), SYNTAX, neg.REQUEST)
        attempt(vini(lambda v: b''), SYNTAX, neg.REQUEST)
        attempt(lambda r, o, k: r.ClearField('vini'), SYNTAX, neg.REQUEST)
        attempt(lambda r, o, k: setattr(r, 'vini_hmac', r.vini_hmac[:31]),
                SYNTAX, neg.REQUEST)
        attempt(lambda r, o, k: r.ClearField('vini_hmac'), SYNTAX, neg.REQUEST)
        attempt(lambda r, o, k: r.ClearField('orig_idx'), SYNTAX, neg.REQUEST)
        attempt(vini(lambda v: v + bytes(201 - len(v))), UNEXPECTED,
                neg.UNPARSED)
        # An input the plan does not have.
        for index in (2, 63, 64, 2 ** 32 - 1):
            attempt(lambda r, o, k: setattr(r, 'orig_idx', index), OTHER,
                    neg.ORDER)
        self.signs(p)

    def test_tampered_output(self):
        p = neg.plan(2)
        other_keys = neg.signtx.address_keys(
            xmr.ADDRESSES[('alcohol', 1)][(0, 0)])

        def attempt(j, change, code=OTHER, text=MAC):
            f = self.reach(p, 'all_in' if j == 0 else 'out0')
            request = self.output_request(f, j)
            change(request, self.output_request(f, 1 - j))
            self.ends(self.call(request), code, text)

        def dst(field, edit):
            return lambda r, o: setattr(r.dst, field,
                                        edit(getattr(r.dst, field)))

        for j in (0, 1):
            for edit in (lambda a: a + 1, lambda a: a - 1, lambda a: 0,
                         lambda a: a + 2 ** 32, lambda a: U64):
                attempt(j, dst('amount', edit))
            # The other output's amount: recipient and change swapped.
            attempt(j, lambda r, o: setattr(r.dst, 'amount', o.dst.amount))
            attempt(j, dst('spend_public_key', lambda k: other_keys[0]))
            attempt(j, dst('view_public_key', lambda k: other_keys[1]))
            attempt(j, dst('spend_public_key', neg.torsioned))
            attempt(j, dst('view_public_key', neg.torsioned))
            attempt(j, dst('is_subaddress', lambda flag: not flag))
            attempt(j, dst('is_integrated', lambda flag: not flag))
            for index in (0, 31):
                attempt(j, lambda r, o: setattr(
                    r, 'dst_hmac', flipped(r.dst_hmac, index)))
            attempt(j, lambda r, o: setattr(r, 'dst_hmac', bytes(32)))
            # The other output: under this MAC, under its own, and its MAC
            # over this one.
            attempt(j, lambda r, o: r.dst.CopyFrom(o.dst))
            attempt(j, lambda r, o: r.CopyFrom(o))
            attempt(j, lambda r, o: setattr(r, 'dst_hmac', o.dst_hmac))
            attempt(j, lambda r, o: r.ClearField('dst_hmac'), SYNTAX,
                    neg.REQUEST)
            attempt(j, lambda r, o: setattr(r, 'dst_hmac', r.dst_hmac[:31]),
                    SYNTAX, neg.REQUEST)
            attempt(j, lambda r, o: r.ClearField('dst'), SYNTAX, neg.REQUEST)
            for field in ('amount', 'spend_public_key', 'view_public_key'):
                attempt(j, lambda r, o: r.dst.ClearField(field), SYNTAX,
                        neg.REQUEST)
            attempt(j, lambda r, o: setattr(r, 'dst_hmac', bytes(33)),
                    UNEXPECTED, neg.UNPARSED)
        self.signs(p)

    def test_tampered_sign_input(self):
        p = neg.plan(2)

        def attempt(change, code=OTHER, text=MAC, position=0):
            f = self.reach(p, 'all_out' if position == 0 else 'sign1')
            i, other = f['order'][position], f['order'][1 - position]
            request = self.sign_request(f, i)
            change(request, self.sign_request(f, other))
            self.ends(self.call(request), code, text)

        def field(name, edit):
            return lambda r, o: setattr(r, name, edit(getattr(r, name)))

        def src(edit):
            return lambda r, o: edit(r.src)

        for position in (0, 1):
            for name in ('vini', 'vini_hmac', 'pseudo_out',
                         'pseudo_out_hmac'):
                attempt(field(name, lambda v: flipped(v, -1)),
                        position=position)
                attempt(lambda r, o: setattr(r, name, getattr(o, name)),
                        position=position)

            def other_pseudo_out(r, o):
                r.pseudo_out, r.pseudo_out_hmac = \
                    o.pseudo_out, o.pseudo_out_hmac
            attempt(other_pseudo_out, position=position)

            def other_vini(r, o):
                r.vini, r.vini_hmac = o.vini, o.vini_hmac
            attempt(other_vini, position=position)
            # Another source under this input's MACs.
            attempt(lambda r, o: r.src.CopyFrom(o.src), position=position)
            # Out of turn: the other input (at position 1, the one that was
            # signed already), alone or with everything that belongs to it.
            attempt(lambda r, o: setattr(r, 'orig_idx', o.orig_idx), OTHER,
                    neg.ORDER, position)
            attempt(lambda r, o: r.CopyFrom(o), OTHER, neg.ORDER, position)
            # Worth more than when it was set, commitment included: the
            # pseudo-output the device made no longer matches.
            attempt(src(lambda s: revalue(s, s.amount + 1)),
                    position=position)
            attempt(src(lambda s: revalue(s, 0)), position=position)
            # Another ring: the offsets are part of the vini.
            attempt(src(lambda s: setattr(s.ring[15], 'global_index',
                                          s.ring[15].global_index + 1)),
                    position=position)
        for index in (2, 64, 2 ** 32 - 1):
            attempt(lambda r, o: setattr(r, 'orig_idx', index), OTHER,
                    neg.ORDER)
        # The source is opened again: it must still be spendable.
        attempt(src(lambda s: setattr(s, 'amount', s.amount + 1)), OTHER,
                neg.COMMITMENT)
        attempt(src(lambda s: setattr(s, 'real_index',
                                      (s.real_index + 1) % 16)), OTHER,
                neg.NOT_OWNED)
        attempt(src(lambda s: setattr(s, 'real_out_tx_key',
                                      neg.signtx.point(b'foreign', 1))),
                OTHER, neg.NOT_OWNED)
        attempt(src(lambda s: setattr(s, 'real_out_tx_key',
                                      neg.torsioned(s.real_out_tx_key))),
                SYNTAX, neg.POINT)
        attempt(src(lambda s: setattr(
            s, 'mask', (int.from_bytes(s.mask, 'little') + xmr.L).to_bytes(
                32, 'little'))), SYNTAX, neg.SCALAR)

        def short_ring(s):
            del s.ring[15]
        attempt(src(short_ring), SYNTAX, neg.RING)
        # A decoy that is no point: nothing can be signed over it.
        attempt(src(lambda s: setattr(s.ring[(s.real_index + 1) % 16], 'dest',
                                      neg.OFF_CURVE)), OTHER, neg.PROOF)
        attempt(src(lambda s: setattr(s.ring[(s.real_index + 1) % 16],
                                      'commitment', neg.OFF_CURVE)), OTHER,
                neg.PROOF)
        attempt(lambda r, o: r.ClearField('src'), SYNTAX, neg.REQUEST)
        for name in ('vini', 'vini_hmac', 'pseudo_out', 'pseudo_out_hmac',
                     'orig_idx'):
            attempt(lambda r, o: r.ClearField(name), SYNTAX, neg.REQUEST)
        for name in ('vini_hmac', 'pseudo_out', 'pseudo_out_hmac'):
            attempt(field(name, lambda v: v[:31]), SYNTAX, neg.REQUEST)
        self.signs(p)

    # ---- an earlier session's pieces ----

    def test_replay_from_an_earlier_session(self):
        p = neg.plan(2)
        # A whole honest session of the same plan, signed and finished. Its
        # key images, vini bytes and destinations are identical to the next
        # session's; only the MACs differ.
        old = self.finish(self.reach(p, 'signed'))
        self.check(p, old)

        def attempt(stage, build, code=OTHER, text=MAC):
            f = self.reach(p, stage)
            self.assertEqual([a.vini for a in f['ins']],
                             [a.vini for a in old['ins']][:len(f['ins'])])
            self.ends(self.call(build(f)), code, text)

        attempt('inputs', lambda f: self.vini_request(old, f['order'][0]))
        attempt('vini1', lambda f: self.vini_request(old, f['order'][1]))
        attempt('all_in', lambda f: self.output_request(old, 0))
        attempt('out0', lambda f: self.output_request(old, 1))
        attempt('all_out', lambda f: self.sign_request(old, f['order'][0]))
        attempt('sign1', lambda f: self.sign_request(old, f['order'][1]))

        # The new session's own pieces with one old one among them.
        def mixed(names):
            def build(f):
                i = f['order'][0]
                request = self.sign_request(f, i)
                stale = self.sign_request(old, i)
                for name in names:
                    setattr(request, name, getattr(stale, name))
                return request
            return build
        attempt('all_out', mixed(['vini_hmac']))
        attempt('all_out', mixed(['pseudo_out', 'pseudo_out_hmac']))
        attempt('all_out', mixed(['pseudo_out_hmac']))
        attempt('all_out', mixed(['pseudo_out']))
        self.signs(p)

    # ---- the steps, in any other order ----

    def test_steps_out_of_order(self):
        p = neg.plan(2)
        allowed = {'init': 'set_input', 'input1': 'set_input',
                   'inputs': 'vini', 'vini1': 'vini', 'vinis': 'all_in',
                   'all_in': 'set_output', 'out0': 'set_output',
                   'out1': 'all_out', 'all_out': 'sign', 'sign1': 'sign',
                   'signed': 'final'}

        def requests(f):
            """The most plausible request of each kind at this point."""
            ins = len(f['ins'])
            if ins == 2:
                vini = self.vini_request(f, f['order'][min(f['vinis'], 1)])
                sign = self.sign_request(
                    f, f['order'][min(len(f['signed']), 1)])
            elif ins == 1:
                vini, sign = self.vini_request(f, 0), self.sign_request(f, 0)
            else:
                vini = monero_proto.MoneroTxInputViniRequest()
                sign = monero_proto.MoneroTxSignInputRequest(
                    src=p['sources'][0])
            return {
                'set_input': monero_proto.MoneroTxSetInputRequest(
                    src=p['sources'][min(ins, 1)]),
                'vini': vini,
                'all_in': monero_proto.MoneroTxAllInputsSetRequest(),
                'set_output': self.output_request(f, min(len(f['outs']), 1)),
                'all_out': monero_proto.MoneroTxAllOutSetRequest(),
                'sign': sign,
                'final': monero_proto.MoneroTxFinalRequest()}

        attempts = 0
        for stage in neg.STAGES:
            for name in ('set_input', 'vini', 'all_in', 'set_output',
                         'all_out', 'sign', 'final'):
                if name == allowed[stage]:
                    continue
                f = self.reach(p, stage)
                self.ends(self.call(requests(f)[name]), UNEXPECTED, neg.STEP)
                attempts += 1
        self.assertEqual(attempts, 66)
        self.signs(p)

    # ---- inputs repeated or out of order ----

    def test_duplicate_input(self):
        amount = 2000000000000
        # The same output twice, hidden in two different rings.
        p = neg.signtx.plan(neg.PAYEE, False, [(neg.OUTPUTS[0], amount),
                                               (neg.OUTPUTS[0], amount)])
        f = self.reach(p, 'vini1')
        self.assertEqual(f['ins'][0].vini[-32:], f['ins'][1].vini[-32:])
        self.assertNotEqual(f['ins'][0].vini, f['ins'][1].vini)
        self.ends(self.call(self.vini_request(f, f['order'][1])), OTHER,
                  neg.ORDER)
        # The same source twice, ring and all.
        p['sources'][1].CopyFrom(p['sources'][0])
        f = self.reach(p, 'vini1')
        self.assertEqual(f['ins'][0].vini, f['ins'][1].vini)
        self.ends(self.call(self.vini_request(f, f['order'][1])), OTHER,
                  neg.ORDER)
        # One of three inputs repeats another.
        p = neg.plan(3)
        p['sources'][2].CopyFrom(p['sources'][0])
        f = self.reach(p, 'inputs')
        images = [f['ins'][i].vini[-32:] for i in f['order']]
        self.assertEqual(len(set(images)), 2)
        responses = [self.call(self.vini_request(f, i)) for i in f['order']]
        repeat = [k for k in (1, 2) if images[k] == images[k - 1]][0]
        self.ends(responses[repeat], OTHER, neg.ORDER)
        # An honest plan, one vini sent twice.
        for inputs, sent in ((2, (0, 0)), (3, (0, 1, 1)), (3, (0, 1, 0))):
            p = neg.plan(inputs)
            f = self.reach(p, 'inputs')
            for k in sent[:-1]:
                self.ok(self.vini_request(f, f['order'][k]),
                        monero_proto.MoneroTxInputViniAck)
            self.ends(self.call(self.vini_request(f, f['order'][sent[-1]])),
                      OTHER, neg.ORDER)
        self.signs()

    def test_key_images_out_of_order(self):
        for inputs, sent in ((2, (1, 0)), (3, (0, 2, 1)), (3, (1, 0)),
                             (3, (2, 1)), (4, (0, 1, 3, 2)),
                             (4, (3, 2))):
            p = neg.plan(inputs)
            f = self.reach(p, 'inputs')
            images = [f['ins'][i].vini[-32:] for i in f['order']]
            self.assertEqual(sorted(set(images), reverse=True), images)
            for k in sent[:-1]:
                self.ok(self.vini_request(f, f['order'][k]),
                        monero_proto.MoneroTxInputViniAck)
            self.ends(self.call(self.vini_request(f, f['order'][sent[-1]])),
                      OTHER, neg.ORDER)
        self.signs()

    # ---- inputs the wallet cannot spend ----

    def attempt_input(self, change, code, text, inputs=1, at=0):
        p = neg.plan(inputs)
        if change(p['sources'][at]) is False:
            request = monero_proto.MoneroTxSetInputRequest()
        else:
            request = monero_proto.MoneroTxSetInputRequest(src=p['sources'][at])
        self.reach(p, 'init' if at == 0 else 'input1')
        self.ends(self.call(request), code, text)

    def test_input_scalars_and_amounts(self):
        attempt = self.attempt_input

        def mask(edit):
            return lambda s: setattr(
                s, 'mask', edit(int.from_bytes(s.mask, 'little')).to_bytes(
                    32, 'little'))
        # The same value mod l, and values no reduction is defined for.
        for edit in (lambda m: m + xmr.L, lambda m: xmr.L, lambda m: xmr.L + 1,
                     lambda m: 2 ** 256 - 1, lambda m: m | 1 << 255,
                     lambda m: 2 ** 253):
            attempt(mask(edit), SYNTAX, neg.SCALAR)
        attempt(lambda s: setattr(s, 'mask', s.mask[:31]), SYNTAX, neg.REQUEST)
        attempt(lambda s: s.ClearField('mask'), SYNTAX, neg.REQUEST)
        attempt(lambda s: setattr(s, 'mask', bytes(33)), UNEXPECTED,
                neg.UNPARSED)
        # A canonical mask that is not the commitment's.
        attempt(mask(lambda m: m + 1), OTHER, neg.COMMITMENT)
        attempt(mask(lambda m: 0), OTHER, neg.COMMITMENT)
        # An amount that is not the commitment's.
        for edit in (lambda a: a + 1, lambda a: a - 1, lambda a: 0,
                     lambda a: U64, lambda a: a + 2 ** 32):
            attempt(lambda s: setattr(s, 'amount', edit(s.amount)), OTHER,
                    neg.COMMITMENT)
        attempt(lambda s: s.ClearField('amount'), SYNTAX, neg.REQUEST)
        # A commitment outside the group, or of small order.
        attempt(lambda s: setattr(real(s), 'commitment',
                                  neg.torsioned(real(s).commitment)), OTHER,
                neg.COMMITMENT)
        for bad in (neg.IDENTITY, neg.ORDER_2, neg.ORDER_4, neg.ORDER_8):
            attempt(lambda s: setattr(real(s), 'commitment', bad), OTHER,
                    neg.COMMITMENT)
        # The inputs together are worth more than 64 bits hold.
        attempt(lambda s: revalue(s, U64), SYNTAX, neg.AMOUNT, inputs=2, at=1)
        attempt(lambda s: revalue(s, U64 - 2000000000000 + 1), SYNTAX,
                neg.AMOUNT, inputs=2, at=1)
        self.signs()

    def test_input_not_owned(self):
        attempt = self.attempt_input
        attempt(lambda s: setattr(real(s), 'dest',
                                  neg.torsioned(real(s).dest)), OTHER,
                neg.NOT_OWNED)
        attempt(lambda s: setattr(real(s), 'dest',
                                  s.ring[(s.real_index + 1) % 16].dest),
                OTHER, neg.NOT_OWNED)
        attempt(lambda s: setattr(s, 'real_index', (s.real_index + 1) % 16),
                OTHER, neg.NOT_OWNED)
        attempt(lambda s: setattr(s, 'real_out_tx_key', bytes.fromhex(
            neg.OUTPUTS[1]['tx_public'])), OTHER, neg.NOT_OWNED)
        attempt(lambda s: setattr(s, 'real_out_tx_key',
                                  neg.signtx.point(b'foreign', 1)), OTHER,
                neg.NOT_OWNED)
        # The index of the output in its transaction, out of bounds.
        for index in (1, 2 ** 31, 2 ** 32 - 1):
            attempt(lambda s: setattr(s, 'real_output_in_tx_index', index),
                    OTHER, neg.NOT_OWNED)
        attempt(lambda s: s.ClearField('real_output_in_tx_index'), SYNTAX,
                neg.REQUEST)
        # Received on another subaddress than claimed.
        for minor in (1, 2 ** 32 - 1):
            attempt(lambda s: setattr(s, 'sub_minor', minor), OTHER,
                    neg.NOT_OWNED)
        attempt(lambda s: setattr(s, 'sub_minor', 0), OTHER, neg.NOT_OWNED,
                inputs=2, at=1)
        # Another account's output cannot be mixed into this one's spend.
        attempt(lambda s: setattr(s, 'sub_major', 1), SYNTAX, neg.REQUEST)
        attempt(lambda s: s.ClearField('sub_major'), SYNTAX, neg.REQUEST)
        attempt(lambda s: s.ClearField('sub_minor'), SYNTAX, neg.REQUEST)
        attempt(lambda s: False, SYNTAX, neg.REQUEST)  # no source at all
        self.signs(neg.plan(2))

    def test_additional_key_must_be_the_outputs_own(self):
        output = neg.paid_subaddress_output(1, 1, 2)

        def attempt(change, code=None, text=None):
            p = neg.signtx.plan(neg.PAYEE, False, [(output, 10 ** 12)])
            src = p['sources'][0]
            src.real_out_additional_key = output['additional']
            change(src)
            self.reach(p, 'init')
            response = self.call(monero_proto.MoneroTxSetInputRequest(src=src))
            if code is None:
                self.assertIsInstance(response,
                                      monero_proto.MoneroTxSetInputAck)
                return p
            self.ends(response, code, text)

        # The control: with its own additional key the output is spendable,
        # and the session signs.
        p = attempt(lambda s: None)
        f = self.finish(self.reach(p, 'signed'))
        self.assertEqual(len(f['clsags'][0]), 18 * 32)
        # Without it, or under another index of that transaction, it is not.
        attempt(lambda s: s.ClearField('real_out_additional_key'), OTHER,
                neg.NOT_OWNED)
        for index in (0, 1, 3, 16, 2 ** 32 - 1):
            attempt(lambda s: setattr(s, 'real_output_in_tx_index', index),
                    OTHER, neg.NOT_OWNED)
        # The additional key of another output.
        attempt(lambda s: setattr(
            s, 'real_out_additional_key',
            neg.paid_subaddress_output(2, 1, 2)['additional']), OTHER,
            neg.NOT_OWNED)
        attempt(lambda s: setattr(s, 'sub_minor', 2), OTHER, neg.NOT_OWNED)
        attempt(lambda s: setattr(
            s, 'real_out_additional_key',
            neg.torsioned(s.real_out_additional_key)), SYNTAX, neg.POINT)
        self.signs()

    def test_input_keys_outside_the_group(self):
        attempt = self.attempt_input
        valid = neg.signtx.point(b'additional', 1)
        for field in ('real_out_tx_key', 'real_out_additional_key'):
            for name, bad in neg.BAD_POINTS:
                attempt(lambda s: setattr(s, field, bad), SYNTAX, neg.POINT)
            attempt(lambda s: setattr(s, field, valid[:31]), SYNTAX,
                    neg.REQUEST)
            attempt(lambda s: setattr(s, field, b''), SYNTAX, neg.REQUEST)
            attempt(lambda s: setattr(s, field, valid + b'\x00'), UNEXPECTED,
                    neg.UNPARSED)
        # 8*a*(R + T) is 8*a*R: without the group check the output would
        # still be found, through a key that is not R.
        attempt(lambda s: setattr(s, 'real_out_tx_key',
                                  neg.torsioned(s.real_out_tx_key)), SYNTAX,
                neg.POINT)
        attempt(lambda s: setattr(s, 'real_out_additional_key',
                                  neg.torsioned(valid)), SYNTAX, neg.POINT)
        attempt(lambda s: s.ClearField('real_out_tx_key'), SYNTAX,
                neg.REQUEST)
        self.signs()

    def test_malformed_ring(self):
        attempt = self.attempt_input

        def members(count):
            def change(s):
                while len(s.ring) > count:
                    del s.ring[len(s.ring) - 1]
                while len(s.ring) < count:
                    extra = s.ring.add()
                    extra.CopyFrom(s.ring[0])
                    extra.global_index = s.ring[len(s.ring) - 2].global_index + 1
                s.real_index = min(s.real_index, max(count - 1, 0))
            return change
        for count in (0, 1, 11, 15):
            attempt(members(count), SYNTAX, neg.RING)
        attempt(members(17), UNEXPECTED, neg.UNPARSED)

        def swapped(a, b):
            def change(s):
                s.ring[a].global_index, s.ring[b].global_index = \
                    s.ring[b].global_index, s.ring[a].global_index
            return change
        for a, b in ((0, 1), (14, 15), (0, 15), (7, 8)):
            attempt(swapped(a, b), SYNTAX, neg.RING)
        # The same output twice in one ring.
        for a in (0, 7, 14):
            attempt(lambda s: setattr(s.ring[a + 1], 'global_index',
                                      s.ring[a].global_index), SYNTAX,
                    neg.RING)
        attempt(lambda s: setattr(s.ring[15], 'global_index', 0), SYNTAX,
                neg.RING)
        for index in (16, 17, 2 ** 32 - 1):
            attempt(lambda s: setattr(s, 'real_index', index), SYNTAX,
                    neg.RING)
        attempt(lambda s: s.ClearField('real_index'), SYNTAX, neg.RING)
        for field in ('global_index', 'dest', 'commitment'):
            attempt(lambda s: s.ring[5].ClearField(field), SYNTAX, neg.RING)
        for field in ('dest', 'commitment'):
            attempt(lambda s: setattr(s.ring[5], field,
                                      getattr(s.ring[5], field)[:31]), SYNTAX,
                    neg.RING)
            # Decoys must at least be canonical points.
            for bad in (neg.OFF_CURVE, neg.Y_ABOVE_P, neg.NEGATIVE_ZERO):
                attempt(lambda s: setattr(
                    s.ring[(s.real_index + 3) % 16], field, bad), SYNTAX,
                    neg.POINT)
        self.signs()

    # ---- what the inputs leave ----

    def test_fee_mismatch(self):
        def attempt(change, inputs=2):
            p = neg.plan(inputs)
            change(p)
            self.reach(p, 'out1')
            # Refused before any signature exists.
            self.ends(self.call(monero_proto.MoneroTxAllOutSetRequest()),
                      OTHER, neg.BALANCE)

        def fee(edit):
            return lambda p: setattr(p['data'], 'fee', edit(p['data'].fee))
        for edit in (lambda v: v + 1, lambda v: v - 1, lambda v: 0,
                     lambda v: 2 * v, lambda v: v + 10 ** 12):
            attempt(fee(edit))
            attempt(fee(edit), inputs=1)
        # An input worth more or less than the plan spends: the difference
        # would be an unreviewed fee, or money from nowhere.
        for delta in (1, -1, 10 ** 12, -10 ** 11):
            attempt(lambda p: revalue(p['sources'][1],
                                      p['sources'][1].amount + delta))

        def payee(delta):
            def change(p):
                spend = neg.signtx.address_keys(neg.OWN)[0]
                for output in p['data'].outputs:
                    if output.spend_public_key != spend:
                        output.amount += delta
            return change
        attempt(payee(1))
        attempt(payee(-1))
        self.signs(neg.plan(2))


if __name__ == '__main__':
    unittest.main()
