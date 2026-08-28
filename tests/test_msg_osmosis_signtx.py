"""Osmosis MsgSend signing — with the confirm-screen amount as the point.

Osmosis had NO device tests at all: the confirm screens that render amounts
were covered only by host-side unit tests of the formatter in isolation. That
matters more than it sounds, because 7.15.0 CHANGED how every Osmosis amount
is drawn.

Before, fsm_msg_osmosis.h rendered amounts with atof() + "%.6f". A float
carries ~7 significant decimal digits, so a large amount was displayed
ROUNDED on the very screen the user approves:

    123456789123456 uosmo  ->  shown as "123456792.000000 OSMO"
                               actual     123456789.123456 OSMO

The signature was over the correct amount either way — the lie was only on
the screen, which is the half a hardware wallet exists to get right. It now
formats with bounded decimal-string arithmetic. Native uosmo values must be
canonical uint64 strings; alternate spellings and overflow are rejected
before confirmation or hashing.

These tests are paired with SECTIONS entries carrying screenshot hints, so
the rendered frame is captured as evidence. A test asserting only "it signed"
cannot prove what the OLED drew.

pyk's osmosis_sign_tx currently implements osmosis-sdk/MsgSend only; the
delegate/undelegate/LP/swap/IBC screens share the same formatter but are not
reachable from here until the client learns those message types.
"""
import unittest
import common

from binascii import hexlify

from keepkeylib import messages_pb2 as base_proto
from keepkeylib import messages_osmosis_pb2 as osmosis_proto
from keepkeylib.client import CallException, ProtocolMixin
from keepkeylib.tools import parse_path

# Osmosis uses the Cosmos coin type (118), not one of its own.
DEFAULT_BIP32_PATH = "m/44h/118h/0h/0/0"


def make_send(from_address, to_address, amount, denom='uosmo'):
    return {
        'type': 'osmosis-sdk/MsgSend',
        'value': {
            'from_address': from_address,
            'to_address': to_address,
            'amount': [{'denom': denom, 'amount': str(amount)}],
        },
    }


class TestMsgOsmosisSignTx(common.KeepKeyTest):

    def _address(self):
        """Ask the device for its own osmo1 address.

        Deliberately NOT a hardcoded constant: the firmware bech32-decodes
        to_address and refuses a bad checksum, so a literal invented by
        swapping a cosmos1 prefix for osmo1 fails with the opaque "Failed to
        include send message in transaction". Deriving it keeps the fixture
        honest and makes these self-sends.
        """
        # osmosis_get_address is decorated @field('address'), so it already
        # returns the string rather than the OsmosisAddress message.
        return self.client.osmosis_get_address(
            address_n=parse_path(DEFAULT_BIP32_PATH)
        )

    def _sign(self, amount, denom='uosmo'):
        addr = self._address()
        return self.client.osmosis_sign_tx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=16359,
            chain_id="osmosis-1",
            fee=800,
            gas=290000,
            msgs=[make_send(addr, addr, amount, denom)],
            memo="",
            sequence=17,
        )

    def _start_raw_signing(self):
        """Start the wire protocol without the high-level MsgSend checks."""
        addr = self._address()
        resp = self.client.call(osmosis_proto.OsmosisSignTx(
            address_n=parse_path(DEFAULT_BIP32_PATH),
            account_number=16359,
            chain_id="osmosis-1",
            fee_amount=800,
            gas=290000,
            memo="",
            sequence=17,
            msg_count=1,
        ))
        self.assertIsInstance(resp, osmosis_proto.OsmosisMsgRequest)
        return addr

    def test_osmosis_sign_tx(self):
        """Baseline: a whole-OSMO send signs and returns a well-formed
        secp256k1 signature + compressed pubkey."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        sig = self._sign(1500000)  # 1.500000 OSMO
        self.assertEqual(len(sig.signature), 64)
        self.assertEqual(len(sig.public_key), 33)
        self.assertIn(hexlify(sig.public_key)[:2], (b'02', b'03'))

    def test_osmosis_send_amount_beyond_float_precision(self):
        """THE regression. 123456789123456 uosmo needs 15 significant digits;
        a float holds ~7, so the old atof()+"%.6f" path drew
        "123456792.000000 OSMO" over a transaction that actually moves
        123456789.123456 OSMO. The captured frame is the proof — assert here
        only that the device signs it, and read the amount off the screenshot.
        """
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        sig = self._sign(123456789123456)
        self.assertEqual(len(sig.signature), 64)

    def test_osmosis_send_subunit_amount(self):
        """500 uosmo is 0.000500 OSMO — six decimal places, no integer part.
        The formatter must not collapse it to "0" or drop the tail."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        sig = self._sign(500)
        self.assertEqual(len(sig.signature), 64)

    def test_osmosis_send_denom_is_committed_to_the_signature(self):
        """A raw MsgSend signs the reviewed canonical denomination.

        Two otherwise-identical sends must produce different signatures when
        only the denomination changes. This catches both the old hardcoded
        ``uosmo`` serializer and any future display/signing mismatch.
        """
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        def sign_denom(denom):
            addr = self._start_raw_signing()
            response = self.client.call(osmosis_proto.OsmosisMsgAck(
                send=osmosis_proto.OsmosisMsgSend(
                    from_address=addr,
                    to_address=addr,
                    denom=denom,
                    amount='1500000',
                )
            ))
            self.assertIsInstance(response, osmosis_proto.OsmosisSignedTx)
            self.assertEqual(len(response.signature), 64)
            return response

        native = sign_denom('uosmo')
        non_native = sign_denom('uatom')
        self.assertNotEqual(hexlify(native.signature),
                            hexlify(non_native.signature))
        self.assertEqual(hexlify(native.public_key),
                         hexlify(non_native.public_key))

    def test_osmosis_send_rejects_noncanonical_wire_amounts(self):
        """Wire callers cannot exploit strtoull spellings or saturation."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        for amount in ('01', '-1', ' 1', '18446744073709551616'):
            addr = self._start_raw_signing()
            with self.assertRaises(CallException) as ctx:
                self.client.call(osmosis_proto.OsmosisMsgAck(
                    send=osmosis_proto.OsmosisMsgSend(
                        from_address=addr,
                        to_address=addr,
                        denom='uosmo',
                        amount=amount,
                    )
                ))
            self.assertIn('Invalid Osmosis amount', str(ctx.exception))

    def test_osmosis_swap_max_fields_are_fully_paged(self):
        """Maximum Swap assets exercise separate three-row screen bounds."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        addr = self._start_raw_signing()
        denom = 'ibc/' + ('A' * 64)
        resp = self.client.call(osmosis_proto.OsmosisMsgAck(
            swap=osmosis_proto.OsmosisMsgSwap(
                sender=addr,
                pool_id=1,
                token_out_denom=denom,
                token_in_denom=denom,
                token_in_amount='12345678901234567890123456789012',
                token_out_min_amount='12345678901234567890123456789012',
            )
        ))
        self.assertIsInstance(resp, osmosis_proto.OsmosisSignedTx)
        self.assertEqual(len(resp.signature), 64)

    def test_osmosis_amount_is_committed_to_the_signature(self):
        """Guards the pairing between what is shown and what is signed: two
        sends differing ONLY in amount must produce different signatures. If
        they matched, the amount would not be in the digest and the confirm
        screen would be decorative."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        a = self._sign(1500000)
        b = self._sign(1500001)
        self.assertNotEqual(hexlify(a.signature), hexlify(b.signature))
        # Same key throughout — only the message differed.
        self.assertEqual(hexlify(a.public_key), hexlify(b.public_key))

    def test_osmosis_signing_is_deterministic(self):
        """RFC6979: identical input must yield an identical signature. A
        mismatch here means nonce generation is not deterministic, which is a
        key-recovery risk long before it is a display problem."""
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.setup_mnemonic_nopin_nopassphrase()

        first = self._sign(1500000)
        second = self._sign(1500000)
        self.assertEqual(hexlify(first.signature), hexlify(second.signature))


class _SessionTransport(object):
    def session_begin(self):
        pass

    def session_end(self):
        pass


class _ScriptedOsmosisClient(object):
    """Offline driver for the public osmosis_sign_tx helper.

    Mirrors _ScriptedThorchainClient in test_msg_thorchain_signtx.py: no
    device, so the version gate can be exercised at both firmware versions in
    a run that does not need an emulator.
    """

    osmosis_sign_tx = ProtocolMixin.osmosis_sign_tx

    def __init__(self, version):
        self.features = base_proto.Features(
            major_version=version[0],
            minor_version=version[1],
            patch_version=version[2],
        )
        self.transport = _SessionTransport()
        self.responses = [
            osmosis_proto.OsmosisMsgRequest(),
            osmosis_proto.OsmosisSignedTx(
                public_key=b'\x02' + b'\x11' * 32,
                signature=b'\x22' * 64,
            ),
        ]
        self.sent = []

    def call(self, message):
        self.sent.append(message)
        if not self.responses:
            raise AssertionError('unexpected device call: %s' % type(message))
        return self.responses.pop(0)


class TestOsmosisClientDenom(unittest.TestCase):
    """The public helper must reach the denominations firmware supports.

    Firmware commits the host-supplied denom to the signed Amino document from
    7.14.2 on (osmosis_signTxUpdateMsgSend escapes it verbatim), so an
    unconditional uosmo-only check in the helper made every supported IBC and
    factory denom unreachable except by driving OsmosisMsgAck by hand.
    Before 7.14.2 the serializer hardcoded uosmo, so a non-uosmo send there
    would sign a uosmo transfer the caller never asked for -- fail closed.
    """

    ADDRESS_N = [0x8000002C, 0x80000076, 0x80000000, 0, 0]
    ADDR = 'osmo1ls33ayg26kmltw7jjy55p32ghjna09zp6z69y8'
    IBC_DENOM = 'ibc/' + ('A' * 64)

    def _sign(self, client, denom):
        return client.osmosis_sign_tx(
            address_n=self.ADDRESS_N,
            account_number=92,
            chain_id='osmosis-1',
            fee=3000,
            gas=200000,
            msgs=[{
                'type': 'osmosis-sdk/MsgSend',
                'value': {
                    'amount': [{'denom': denom, 'amount': '1500000'}],
                    'from_address': self.ADDR,
                    'to_address': self.ADDR,
                },
            }],
            memo='client denom test',
            sequence=3,
        )

    def test_ibc_denom_is_forwarded_on_7_15(self):
        client = _ScriptedOsmosisClient((7, 15, 0))
        response = self._sign(client, self.IBC_DENOM)

        self.assertIsInstance(response, osmosis_proto.OsmosisSignedTx)
        self.assertEqual(client.sent[1].send.denom, self.IBC_DENOM)

    def test_ibc_denom_is_forwarded_on_7_14_2(self):
        """7.14.2 is the first release whose serializer commits the denom."""
        client = _ScriptedOsmosisClient((7, 14, 2))
        response = self._sign(client, self.IBC_DENOM)

        self.assertIsInstance(response, osmosis_proto.OsmosisSignedTx)
        self.assertEqual(client.sent[1].send.denom, self.IBC_DENOM)

    def test_non_uosmo_denom_is_rejected_before_7_14_2(self):
        client = _ScriptedOsmosisClient((7, 14, 1))

        with self.assertRaises(CallException) as ctx:
            self._sign(client, self.IBC_DENOM)
        self.assertIn('Unsupported denomination before firmware 7.14.2',
                      str(ctx.exception))

    def test_uosmo_still_signs_on_legacy_firmware(self):
        client = _ScriptedOsmosisClient((7, 14, 1))
        response = self._sign(client, 'uosmo')

        self.assertIsInstance(response, osmosis_proto.OsmosisSignedTx)
        self.assertEqual(client.sent[1].send.denom, 'uosmo')


if __name__ == '__main__':
    unittest.main()
