"""The hostile host shared by the test_msg_monero_sign_negative_* files.

Every test there plays a host that tries to get a Monero signature the user
did not approve, or to leave the device holding half a signing session. Each
attempt must be answered with one exact Failure, and afterwards the session
must be gone: every continuation is refused as "not in progress" and a new
TxInit starts cleanly. Each test ends by signing a transaction through to
TxFinal and checking it host-side, so a device that merely refuses everything
does not pass.

The honest half of the host (plans, sources, the checks of a signed
transaction) is test_msg_monero_signtx's; it is used here, not copied.
"""

import select
import struct
import time

import common
import monero_fixtures as xmr
import test_msg_monero_signtx as signtx
from keepkeylib import mapping
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_monero_pb2 as monero_proto
from keepkeylib import types_pb2 as proto_types

SYNTAX = proto_types.Failure_SyntaxError
OTHER = proto_types.Failure_Other
UNEXPECTED = proto_types.Failure_UnexpectedMessage
CANCELLED = proto_types.Failure_ActionCancelled

# The firmware's reasons (lib/firmware/monero_tx.c, monero_tx_result_text).
STEP = 'Monero signing step out of order'
REQUEST = 'Invalid Monero signing request'
OUTPUT_COUNT = 'Monero: only transactions with exactly 2 outputs are supported'
RING_SIZE = 'Monero ring size must be 16'
HARD_FORK = 'Monero hard fork must be 16 or later'
RCT_TYPE = 'Monero: only CLSAG with Bulletproofs+ is supported'
INPUT_COUNT = 'Monero: 1 to 64 inputs are supported'
PAYMENT_ID = 'Monero payment ID must be 8 bytes for one integrated address'
INTEGRATED = 'Monero: only one integrated destination is supported'
POINT = 'Invalid Monero public key'
SCALAR = 'Invalid Monero scalar'
CHANGE = 'Monero change must return to this wallet'
AMOUNT = 'Monero amount overflow'
RING = 'Monero ring must be 16 sorted, distinct members'
NOT_OWNED = 'Monero input does not belong to this wallet'
COMMITMENT = 'Monero input amount does not match its commitment'
MAC = 'Monero signing state was changed or replayed'
ORDER = 'Monero inputs out of key-image order'
BALANCE = 'Monero inputs do not equal outputs plus fee'
PROOF = 'Monero proving failed or was cancelled'
SIGNING_CANCELLED = 'Monero signing cancelled'
NO_SESSION = 'Monero signing not in progress'
UNPARSED = 'Could not parse protocol buffer message'

OWN = signtx.OWN
PAYEE = signtx.PAYEE
PAYEE_SUB = signtx.PAYEE_SUB
FEE = signtx.FEE
OUTPUTS = xmr.OWNED_OUTPUTS

# Points a public key must never be. A point of order 8, and the others of
# small order: the identity, order 2 (y = -1) and order 4 (y = 0).
ORDER_8 = bytes.fromhex(
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05')
IDENTITY = bytes([1]) + bytes(31)
ORDER_2 = bytes([0xec]) + bytes([0xff]) * 30 + bytes([0x7f])
ORDER_4 = bytes(32)
# Encodings no canonical encoder produces: y = p + 1 (the identity again)
# and x = 0 with the sign bit set.
Y_ABOVE_P = bytes([0xee]) + bytes([0xff]) * 30 + bytes([0x7f])
NEGATIVE_ZERO = bytes([1]) + bytes(30) + bytes([0x80])


def off_curve():
    """The smallest y that is no point's."""
    for y in range(2, 64):
        try:
            xmr._decode(y.to_bytes(32, 'little'))
        except ValueError:
            return y.to_bytes(32, 'little')
    raise AssertionError('no off-curve y found')


OFF_CURVE = off_curve()


def torsioned(key):
    """`key` plus a point of order 8: on the curve, canonical, and 8 times it
    is 8 times `key`, but it is outside the prime-order group."""
    return xmr._encode(xmr._add(xmr._decode(key), xmr._decode(ORDER_8)))


BAD_POINTS = (
    ('the identity', IDENTITY), ('order 2', ORDER_2), ('order 4', ORDER_4),
    ('order 8', ORDER_8), ('y above p', Y_ABOVE_P),
    ('negative zero', NEGATIVE_ZERO), ('off the curve', OFF_CURVE),
)


def base58(data):
    """Monero's base58: 8-byte blocks, each 11 characters."""
    sizes = {8: 11, 7: 10, 6: 9, 5: 7, 4: 6, 3: 5, 2: 3, 1: 2}
    out = ''
    for i in range(0, len(data), 8):
        block = data[i:i + 8]
        value, text = int.from_bytes(block, 'big'), ''
        for _ in range(sizes[len(block)]):
            value, digit = divmod(value, 58)
            text = signtx.ALPHABET[digit] + text
        out += text
    return out


# network -> (standard, integrated, subaddress) address prefix
PREFIXES = {0: (18, 19, 42), 1: (53, 54, 63), 2: (24, 25, 36)}


def encode_address(spend, view, network=0, subaddress=False, payment_id=None):
    kind = 1 if payment_id is not None else 2 if subaddress else 0
    data = bytes([PREFIXES[network][kind]]) + spend + view + (payment_id or b'')
    return base58(data + xmr.keccak256(data)[:4])


def own_subaddress(major, minor):
    """(spend, view) public keys of the abandon wallet's subaddress, from
    its view key and its primary address, as any watch-only wallet does."""
    spend = signtx.address_keys(OWN)[0]
    m = signtx.hs(b'SubAddr\x00' + signtx.OWN_VIEW +
                  struct.pack('<II', major, minor))
    d = xmr._add(xmr._decode(spend), xmr._mul(xmr.G, m))
    a = int.from_bytes(signtx.OWN_VIEW, 'little')
    return xmr._encode(d), xmr._encode(xmr._mul(d, a))


def account_plan(account, inputs):
    """An honest plan that spends from `account`: its change returns to
    that account's own address, the subaddress (account, 0)."""
    p = signtx.plan(PAYEE, False, inputs)
    data = p['data']
    own = [d.spend_public_key for d in data.outputs].index(
        signtx.address_keys(OWN)[0])
    spend, view = own_subaddress(account, 0)
    data.account = data.change_dts.major = account
    for keys in (data.change_dts, data.outputs[own]):
        keys.spend_public_key, keys.view_public_key = spend, view
    data.outputs[own].is_subaddress = True
    return p


def frame(message_id, payload=b'', declared=None):
    """One 64-byte packet: any message ID, any body, any declared size."""
    size = len(payload) if declared is None else declared
    data = b'?##' + struct.pack('>HL', message_id, size) + payload
    return data + bytes(64 - len(data))


def flipped(data, index=0):
    out = bytearray(data)
    out[index] ^= 1
    return bytes(out)


def continuations():
    return [monero_proto.MoneroTxSetInputRequest(),
            monero_proto.MoneroTxInputViniRequest(),
            monero_proto.MoneroTxAllInputsSetRequest(),
            monero_proto.MoneroTxSetOutputRequest(),
            monero_proto.MoneroTxAllOutSetRequest(),
            monero_proto.MoneroTxSignInputRequest(),
            monero_proto.MoneroTxFinalRequest()]


def paid_output(tag, index=0):
    """One more output of the abandon wallet's primary address, made as a
    sender makes one: from the address alone and a new transaction key.
    Only the wallet can spend it; its key image is not known here."""
    spend, view = signtx.address_keys(OWN)
    r = signtx.scalar(b'sender', tag)
    derivation = xmr._encode(xmr._mul(xmr._decode(view), 8 * r))
    key = xmr._add(
        xmr._mul(xmr.G, signtx.hs(derivation + xmr.varint(index))),
        xmr._decode(spend))
    return {'major': 0, 'minor': 0, 'index': index,
            'tx_public': xmr._encode(xmr._mul(xmr.G, r)).hex(),
            'output_public': xmr._encode(key).hex()}


def paid_subaddress_output(tag, minor, index):
    """An output paid to the wallet's subaddress (0, minor) by a transaction
    with several recipients: its key comes from the additional transaction
    key at its own index ('additional'), not from the main one."""
    spend, view = own_subaddress(0, minor)
    r = signtx.scalar(b'additional', tag)
    derivation = xmr._encode(xmr._mul(xmr._decode(view), 8 * r))
    key = xmr._add(
        xmr._mul(xmr.G, signtx.hs(derivation + xmr.varint(index))),
        xmr._decode(spend))
    return {'major': 0, 'minor': minor, 'index': index,
            'tx_public': signtx.point(b'main', tag).hex(),
            'additional': xmr._encode(xmr._mul(xmr._decode(spend), r)),
            'output_public': xmr._encode(key).hex()}


def plan(inputs=1, payee=PAYEE, subaddress=False, change_first=False):
    """The honest plan the attacks start from: `inputs` owned outputs, one
    recipient, change to the wallet's primary address. The first two inputs
    are Monero Core's fixtures; signs() checks only plans of those."""
    amounts = (2000000000000, 700000000000, 900000000000, 400000000000)
    outputs = OUTPUTS[:2] + [paid_output(1), paid_output(2, 3)]
    return signtx.plan(payee, subaddress,
                       [(outputs[i], amounts[i]) for i in range(inputs)],
                       change_first)


def integrate(p, payment_id=bytes(range(1, 9))):
    """Makes the plan's recipient an integrated address."""
    for output in p['data'].outputs:
        if output.spend_public_key != p['data'].change_dts.spend_public_key:
            output.is_integrated = True
    p['data'].payment_id = payment_id
    return p


STAGES = ('init', 'input1', 'inputs', 'vini1', 'vinis', 'all_in', 'out0',
          'out1', 'all_out', 'sign1', 'signed')


class SignFlow(common.KeepKeyTest):
    PIN = ''
    PASSPHRASE = None  # None: no passphrase protection

    def setUp(self):
        super(SignFlow, self).setUp()
        self.requires_firmware(common.CAPABILITIES_SINCE)
        self.requires_fullFeature()
        self.requires_release_capability('monero-signing')
        self.client.load_device_by_mnemonic(
            mnemonic=self.mnemonic_abandon, pin=self.PIN,
            passphrase_protection=self.PASSPHRASE is not None, label='test',
            language='english')
        common.reset_screenshot_capture(self.client)
        self.passphrase = self.PASSPHRASE or ''

    # The checks of a finished transaction, from the positive tests.
    prefix = signtx.TestMsgMoneroSignTx.prefix
    transaction = signtx.TestMsgMoneroSignTx.transaction
    check = signtx.TestMsgMoneroSignTx.check
    core_verify = signtx.TestMsgMoneroSignTx.core_verify

    # ---- the wire ----

    def call(self, message):
        return self.client.call_raw(message)

    def ok(self, message, kind):
        response = self.call(message)
        self.assertIsInstance(response, kind, response)
        return response

    def send_raw(self, message_id, payload=b''):
        """One frame with any message ID and any bytes for a body."""
        frame = b'##' + struct.pack('>HL', message_id, len(payload)) + payload
        self.client.transport._write(frame, None)
        return self.client.transport.read_blocking()

    def require_udp_socket(self):
        if not hasattr(self.client.transport, 'socket'):
            self.skipTest("wire interruption checks require a UDP socket")

    def pending(self, quiet=0.1):
        """Whatever the device sends without being asked, until it has been
        silent for `quiet` seconds. (An answer later than that would be read
        as the next request's and fail the test there.)"""
        out = []
        while select.select([self.client.transport.socket], [], [], quiet)[0]:
            out.append(self.client.transport.read_blocking())
        return out

    def during(self, long_step, interruption):
        """Sends `interruption` while the device is still computing
        `long_step`: both are on the wire before the device reads either, so
        the second one arrives at the first poll of the proof."""
        self.client.transport.write(long_step)
        self.client.transport.write(interruption)
        return self.client.transport.read_blocking()

    def during_raw(self, long_step, datagram):
        """The same with any bytes for the second packet."""
        self.client.transport.write(long_step)
        self.client.transport.socket.send(datagram)
        return self.client.transport.read_blocking()

    # ---- TxInit and its review ----

    def review(self, data, answers=(True,), network=None, watch=False,
               address_n=None):
        """TxInit, answering review page k with answers[k] (the last one
        repeats): True holds the button, False refuses, a protobuf message is
        sent in place of the ButtonAck. Returns the first response that is
        not a prompt, and the pages: (code, title, body, layout) when
        watched, else the ButtonRequest codes."""
        request = monero_proto.MoneroTxInitRequest(
            address_n=xmr.path(0) if address_n is None else address_n)
        if data is not None:
            request.tsx_data.CopyFrom(data)
        if network is not None:
            request.network_type = network
        return self.answer(self.call(request), answers, watch)

    def answer(self, response, answers=(True,), watch=False):
        pages = []
        while True:
            if isinstance(response, proto.PinMatrixRequest):
                response = self.call(proto.PinMatrixAck(
                    pin=self.client.debug.read_pin_encoded()))
            elif isinstance(response, proto.PassphraseRequest):
                response = self.call(
                    proto.PassphraseAck(passphrase=self.passphrase))
            elif isinstance(response, proto.ButtonRequest):
                answer = answers[min(len(pages), len(answers) - 1)]
                if watch:
                    layout = self.client._read_oled_after_settle()
                    # Into the screenshot report, when one is being made.
                    self.client._capture_oled(layout)
                    title, body = self.client.debug.read_confirm_text()
                    pages.append((response.code, title, body, layout))
                else:
                    pages.append(response.code)
                if answer is True:
                    self.client.debug.press_yes()
                    response = self.call(proto.ButtonAck())
                elif answer is False:
                    self.client.debug.press_no()
                    response = self.call(proto.ButtonAck())
                else:
                    return self.call(answer), pages
            else:
                return response, pages

    # ---- the honest steps ----

    def start(self, p, network=None):
        ack, _ = self.review(p['data'], network=network)
        self.assertIsInstance(ack, monero_proto.MoneroTxInitAck, ack)
        return {'p': p, 'init': ack, 'ins': [], 'order': [], 'vinis': 0,
                'outs': [], 'signed': []}

    def set_input(self, f):
        f['ins'].append(self.ok(
            monero_proto.MoneroTxSetInputRequest(
                src=f['p']['sources'][len(f['ins'])]),
            monero_proto.MoneroTxSetInputAck))
        if len(f['ins']) == len(f['p']['sources']):
            # Core's input order: key images descending.
            f['order'] = sorted(range(len(f['ins'])),
                                key=lambda i: f['ins'][i].vini[-32:],
                                reverse=True)

    def vini_request(self, f, i):
        return monero_proto.MoneroTxInputViniRequest(
            vini=f['ins'][i].vini, vini_hmac=f['ins'][i].vini_hmac, orig_idx=i)

    def output_request(self, f, j):
        return monero_proto.MoneroTxSetOutputRequest(
            dst=f['p']['data'].outputs[j], dst_hmac=f['init'].dst_hmacs[j])

    def sign_request(self, f, i):
        return monero_proto.MoneroTxSignInputRequest(
            src=f['p']['sources'][i], vini=f['ins'][i].vini,
            vini_hmac=f['ins'][i].vini_hmac, pseudo_out=f['ins'][i].pseudo_out,
            pseudo_out_hmac=f['ins'][i].pseudo_out_hmac, orig_idx=i)

    def set_vini(self, f):
        self.ok(self.vini_request(f, f['order'][f['vinis']]),
                monero_proto.MoneroTxInputViniAck)
        f['vinis'] += 1

    def set_output(self, f):
        f['outs'].append(self.ok(self.output_request(f, len(f['outs'])),
                                 monero_proto.MoneroTxSetOutputAck))

    def sign_input(self, f):
        f['signed'].append(self.ok(
            self.sign_request(f, f['order'][len(f['signed'])]),
            monero_proto.MoneroTxSignInputAck))

    def reach(self, p, stage, network=None):
        """A session for `p`, honestly driven up to and including `stage`."""
        n = len(p['sources'])
        f = self.start(p, network)
        steps = [
            ('input1', lambda: self.set_input(f)),
            ('inputs', lambda: [self.set_input(f) for _ in range(n - 1)]),
            ('vini1', lambda: self.set_vini(f)),
            ('vinis', lambda: [self.set_vini(f) for _ in range(n - 1)]),
            ('all_in', lambda: self.ok(
                monero_proto.MoneroTxAllInputsSetRequest(),
                monero_proto.MoneroTxAllInputsSetAck)),
            ('out0', lambda: self.set_output(f)),
            ('out1', lambda: self.set_output(f)),
            ('all_out', lambda: f.update(all_out=self.ok(
                monero_proto.MoneroTxAllOutSetRequest(),
                monero_proto.MoneroTxAllOutSetAck))),
            ('sign1', lambda: self.sign_input(f)),
            ('signed', lambda: [self.sign_input(f) for _ in range(n - 1)]),
        ]
        self.assertIn(stage, STAGES)
        for name, step in steps[:STAGES.index(stage)]:
            step()
        return f

    def finish(self, f):
        final = self.ok(monero_proto.MoneroTxFinalRequest(),
                        monero_proto.MoneroTxFinalAck)
        f['clsags'] = [xmr.decrypt(final.opening_key,
                                   struct.pack('<I', k) + bytes(8), s.clsag_enc)
                       for k, s in enumerate(f['signed'])]
        return f

    # ---- what every attack must end in ----

    def refused(self, response, code, text):
        # The attempt number tells which case of a loop was not refused.
        self.attempt = getattr(self, 'attempt', 0) + 1
        self.assertIsInstance(response, proto.Failure,
                              'attempt %d: %r' % (self.attempt, response))
        self.assertEqual((self.attempt, response.code, response.message),
                         (self.attempt, code, text))

    def assert_dead(self):
        """No session: every continuation is refused before its handler."""
        for message in continuations():
            self.refused(self.call(message), UNEXPECTED, NO_SESSION)

    def assert_fresh(self):
        """A new TxInit starts cleanly; it leaves a live session behind, so
        the next attack also proves that it ends one."""
        self.reach(plan(), 'input1')

    def ends(self, response, code, text):
        """The exact Failure, a dead session, and a clean restart."""
        self.refused(response, code, text)
        self.assert_dead()
        self.assert_fresh()

    def signs(self, p=None):
        """The device still signs: a whole transaction, checked host-side
        (and by Monero Core when KK_MONERO_TX_CORE_VERIFY is set)."""
        p = p or plan()
        f = self.finish(self.reach(p, 'signed'))
        self.check(p, f)
        self.assert_dead()
        return f


def wait(seconds):
    time.sleep(seconds)


def message_id(message):
    return mapping.get_type(message)
