"""Bitcoin-only variant -- the product boundary, measured over the wire.

KK_BITCOIN_ONLY=ON builds a second shipping product: coins.def keeps only
Bitcoin and Testnet, messagemap.def drops every altcoin handler, ZCASH_PRIVACY
is forced OFF, and lib/firmware/transaction.c takes a BITCOIN_ONLY arm on the
OP_RETURN path that confirms raw bytes instead of decoding a THORChain memo.
None of that had a test, and CI only ever ran the multi-chain emulator -- so
the whole variant was unaudited.

NOTHING HERE SKIPS. Each test asserts the behaviour that is correct for the
variant it is talking to, so it is evidence on both builds: on the bitcoin-only
image it proves the strip happened, and on the regular image it proves the
strip did NOT happen (a guard that leaked into the multi-chain product would
fail here just as loudly). `requires_fullFeature()` is deliberately not used --
see test_firmware_variant_names_the_bitcoin_only_product for why it cannot
work.

The variant is identified by GetCoinTable, not by features.firmware_variant:
the coin table comes from coins.def, which is a different mechanism from the
message map, the Zcash gate and the OP_RETURN arm that the other tests probe,
so nothing here is circular.
"""

import binascii
import time
import unittest

import common

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException

from keepkeylib import messages_binance_pb2 as messages_binance
from keepkeylib import messages_cosmos_pb2 as messages_cosmos
from keepkeylib import messages_eos_pb2 as messages_eos
from keepkeylib import messages_ethereum_pb2 as messages_eth
from keepkeylib import messages_hive_pb2 as messages_hive
from keepkeylib import messages_mayachain_pb2 as messages_maya
from keepkeylib import messages_nano_pb2 as messages_nano
from keepkeylib import messages_osmosis_pb2 as messages_osmosis
from keepkeylib import messages_ripple_pb2 as messages_ripple
from keepkeylib import messages_solana_pb2 as messages_solana
from keepkeylib import messages_thorchain_pb2 as messages_thorchain
from keepkeylib import messages_ton_pb2 as messages_ton
from keepkeylib import messages_tron_pb2 as messages_tron
from keepkeylib import messages_zcash_pb2 as messages_zcash


# tx d5f65ee8... input 0 is 0.0039 BTC; the vector every other Bitcoin test in
# this directory spends, and it is in txcache/, so nothing here needs network.
PREV_HASH = binascii.unhexlify(
    'd5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882')
PREV_INDEX = 0
INPUT_AMOUNT = 390000
OUT_ADDRESS = '1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1'
OUT_AMOUNT = 380000  # 0.0001 BTC fee

# A well-formed THORChain swap memo. The multi-chain firmware parses this and
# renders who/what/how-much; the bitcoin-only firmware has no parser linked and
# must disclose the bytes themselves.
THORCHAIN_MEMO = (b'SWAP:ETH.ETH:'
                  b'0x41e5560054824ea6b0732e656e3ad64e20e94e45:420:kk:75')

# OMNI simple send, 1.00000000 OMNI. The OMNI branch of compile_output() sits
# ABOVE the #if BITCOIN_ONLY, so it must survive the strip untouched.
OMNI_SIMPLE_SEND = binascii.unhexlify('6f6d6e6900000000000000010000000005f5e100')
# The same 20 bytes with the 'o' of "omni" changed to 'p', so the OMNI prefix
# test fails and the payload falls through to the raw-data confirmation.
NOT_OMNI = b'p' + OMNI_SIMPLE_SEND[1:]

# A BIP-44 path that is valid on every chain probed below, so a refusal can
# only be the message type being absent, never a path rejection.
BIP44_PATH = [2147483692, 2147483708, 2147483648, 0, 0]

# Matches client.SCREENSHOT_SETTLE_SECONDS. The firmware writes ButtonRequest
# immediately BEFORE drawing, so read_layout() must be given time to settle or
# it returns the previous screen.
BUTTON_RENDER_SETTLE_SECONDS = 0.5


def lit_pixels(layout):
    """Count set pixels in a raw 2048-byte OLED framebuffer.

    read_layout() returns the framebuffer, not text, and there is no glyph
    decoder in this repo. Screen assertions here are therefore structural: a
    screen that draws nothing, and two screens that draw identically, are both
    detectable without OCR.
    """
    total = 0
    for b in layout:
        if isinstance(b, str):
            b = ord(b)
        total += bin(b).count('1')
    return total


class TestBitcoinOnlyVariant(common.KeepKeyTest):

    def setUp(self):
        super(TestBitcoinOnlyVariant, self).setUp()
        # The Bitcoin-only product shipped on the 7.14.3 release fork before
        # 7.15. The variant check below keeps these product assertions away
        # from regular 7.14.x images, while this exact floor prevents the
        # stripped 7.14.3 emulator from silently skipping its entire suite.
        self.requires_firmware("7.14.3")
        # This whole file describes the BITCOIN-ONLY product. Several tests
        # assert screen sequences that differ on the multi-chain build -- the
        # OP_RETURN one decodes a THORChain memo there and draws more screens --
        # so running them against a full-feature device is a category error, not
        # a finding. CI points the pyk suite at the full emulator image.
        self.requires_bitcoinOnly()
        self.screens = []
        # Refuse (press NO) on the Nth ButtonRequest of the current flow;
        # None means confirm everything.
        self.refuse_on = None
        self._install_screen_capture()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _install_screen_capture(self):
        """Record the framebuffer at each ButtonRequest, before it is acked."""
        original = self.client.callback_ButtonRequest

        def capture(msg):
            # Unconditional settle, unlike client.callback_ButtonRequest's
            # SCREENSHOT-gated sleep: these are structural assertions that must
            # hold on every run, not just screenshot runs.
            time.sleep(BUTTON_RENDER_SETTLE_SECONDS)
            self.screens.append((msg.code, self.client.debug.read_layout()))
            self.client.button = (self.refuse_on != len(self.screens))
            return original(msg)

        self.client.callback_ButtonRequest = capture

    def _reset_screens(self):
        self.screens = []
        self.client.button = True

    def _confirm_codes(self):
        return [code for code, _ in self.screens]

    def _screen(self, index):
        return self.screens[index][1]

    def _is_bitcoin_only(self):
        """Identify the product from coins.def, over the wire.

        Deliberately NOT features.firmware_variant: that field does not
        distinguish the two builds at all (see
        test_firmware_variant_names_the_bitcoin_only_product).
        """
        return self.client.call(proto.GetCoinTable()).num_coins == 2

    def _coin_names(self):
        table = self.client.call(proto.GetCoinTable())
        end = min(table.num_coins, table.chunk_size)
        chunk = self.client.call(proto.GetCoinTable(start=0, end=end))
        return [entry.coin_name for entry in chunk.table]

    def _data_output(self, op_return_data):
        return proto_types.TxOutputType(op_return_data=op_return_data,
                                        amount=0,
                                        script_type=proto_types.PAYTOOPRETURN)

    def _sign(self, outputs):
        inp = proto_types.TxInputType(address_n=[0], prev_hash=PREV_HASH,
                                      prev_index=PREV_INDEX)
        return self.client.sign_tx('Bitcoin', [inp], outputs)

    def _sign_with_op_return(self, op_return_data):
        out_pay = proto_types.TxOutputType(address=OUT_ADDRESS,
                                           amount=OUT_AMOUNT,
                                           script_type=proto_types.PAYTOADDRESS)
        return self._sign([out_pay, self._data_output(op_return_data)])

    def _probe(self, msg):
        """Send one message and return the response, leaving the device idle."""
        resp = self.client.call_raw(msg)
        self.client.call_raw(proto.Initialize())
        return resp

    def _assert_unknown_message(self, name, resp):
        self.assertTrue(
            isinstance(resp, proto.Failure),
            "%s: expected a Failure on the bitcoin-only image, got %s"
            % (name, type(resp).__name__))
        self.assertTrue(
            resp.code == proto_types.Failure_UnexpectedMessage,
            "%s: expected Failure_UnexpectedMessage (the handler is not in the "
            "message map at all); got code %d %r"
            % (name, resp.code, resp.message))

    def _assert_handler_present(self, name, resp):
        self.assertTrue(
            not (isinstance(resp, proto.Failure)
                 and resp.code == proto_types.Failure_UnexpectedMessage),
            "%s: the multi-chain image answered Failure_UnexpectedMessage, so "
            "a BITCOIN_ONLY guard leaked into the regular product" % name)

    # ------------------------------------------------------------------
    # L1 -- Bitcoin still signs
    # ------------------------------------------------------------------

    def test_bitcoin_signing_survives_the_strip(self):
        """The one thing the bitcoin-only product must still do.

        Stripping coins, message handlers and the Zcash engine touches
        coins.def, messagemap.def, fsm.c and the AES table selection. Any of
        those going wrong shows up here first: the signature is compared
        against the exact vector test_msg_signtx.test_one_one_fee pins on the
        multi-chain build, so the two products must produce byte-identical
        Bitcoin transactions from the same seed.
        """
        self.setup_mnemonic_nopin_nopassphrase()
        self._reset_screens()

        inp = proto_types.TxInputType(address_n=[0], prev_hash=PREV_HASH,
                                      prev_index=PREV_INDEX)
        out = proto_types.TxOutputType(address=OUT_ADDRESS, amount=OUT_AMOUNT,
                                       script_type=proto_types.PAYTOADDRESS)
        _, serialized_tx = self.client.sign_tx('Bitcoin', [inp], [out])

        self.assertEqual(
            binascii.hexlify(serialized_tx),
            '010000000182488650ef25a58fef6788bd71b8212038d7f2bbe4750bc7bcb4470'
            '1e85ef6d5000000006b4830450221009a0b7be0d4ed3146ee262b42202841834'
            '698bb3ee39c24e7437df208b8b7077102202b79ab1e7736219387dffe8d615bbd'
            'ba87e11477104b867ef47afed1a5ede7810121023230848585885f63803a0a8ae'
            'cdd6538792d5c539215c91698e315bf0253b43dffffffff0160cc050000000000'
            '1976a914de9b2a8da088824e8fe51debea566617d851537888ac00000000')

        # One output review, then the whole-transaction confirmation. Measured,
        # not modelled: a silently dropped output screen is exactly the failure
        # a signing test alone cannot see.
        self.assertEqual(
            self._confirm_codes(),
            [proto_types.ButtonRequest_ConfirmOutput,
             proto_types.ButtonRequest_SignTx])
        for index in range(len(self.screens)):
            self.assertGreater(lit_pixels(self._screen(index)), 200)

    # ------------------------------------------------------------------
    # L2 -- the coin table IS the product boundary
    # ------------------------------------------------------------------

    def test_coin_table_is_bitcoin_and_testnet_only(self):
        """coins.def under BITCOIN_ONLY keeps exactly two entries.

        "Bitcoin-only" is not "UTXO-only": Litecoin, Dogecoin, Bitcoin Cash and
        transparent Zcash are all stripped too, and ERC-20 tokens leave the
        table entirely (TOKENS_COUNT is 0 and `tokens` is not linked). A host
        that enumerates coins is the only way a user learns what the device
        will sign, so the count and the names are both part of the product.
        """
        table = self.client.call(proto.GetCoinTable())
        names = self._coin_names()

        if self._is_bitcoin_only():
            self.assertEqual(table.num_coins, 2)
            self.assertEqual(names, ['Bitcoin', 'Testnet'])
        else:
            self.assertGreater(table.num_coins, 2)
            self.assertTrue('Ethereum' in names or len(names) > 2,
                            "multi-chain image reported %r" % (names,))

    # ------------------------------------------------------------------
    # L3 -- the variant string
    # ------------------------------------------------------------------

    def test_firmware_variant_names_the_bitcoin_only_product(self):
        """features.firmware_variant must distinguish the two products.

        It is the only wire-visible product identifier, and the whole test
        suite gates on it: common.requires_fullFeature() skips a test when
        firmware_variant is "KeepKeyBTC" or "EmulatorBTC".

        variant_getName() has two arms. Under EMULATOR it returns a literal;
        otherwise it returns the model's variant name from variant_getInfo(),
        and THAT arm has no BITCOIN_ONLY case at all -- a bitcoin-only device
        reports whatever a multi-chain device of the same model reports. So
        this is asserted by suffix rather than against a fixed string: the
        contract is that the two products are distinguishable, on the emulator
        and on hardware alike.

        If it fails, requires_fullFeature() is dead code and every altcoin test
        in this directory runs -- and fails -- against a bitcoin-only image
        instead of skipping.
        """
        self.client.init_device()
        variant = self.client.features.firmware_variant

        if self._is_bitcoin_only():
            self.assertTrue(
                variant.endswith('BTC'),
                "coins.def carries only Bitcoin+Testnet, so this is the "
                "bitcoin-only product, but firmware_variant is %r. "
                "common.requires_fullFeature() compares against 'KeepKeyBTC'/"
                "'EmulatorBTC' and therefore never skips anything." % variant)
        else:
            self.assertTrue(
                not variant.endswith('BTC'),
                "multi-chain image reported the bitcoin-only variant %r"
                % variant)

    # ------------------------------------------------------------------
    # L4 -- altcoin handlers are absent, not broken
    # ------------------------------------------------------------------

    def test_altcoin_message_handlers_are_absent(self):
        """Every stripped chain must refuse cleanly and leave the screen alone.

        messagemap.def drops these MSG_IN entries under BITCOIN_ONLY, so the
        board-level dispatcher answers Failure_UnexpectedMessage without ever
        reaching a handler. The two things that could go wrong are a handler
        that is half-linked (wrong failure, or a hang) and one that draws
        something before refusing -- a bitcoin-only device must never render a
        chain it cannot sign. The framebuffer is compared byte-for-byte across
        all fifteen probes for exactly that reason.
        """
        self.setup_mnemonic_nopin_nopassphrase()
        probes = [
            ('EthereumGetAddress', messages_eth.EthereumGetAddress(address_n=BIP44_PATH)),
            ('CosmosGetAddress', messages_cosmos.CosmosGetAddress(address_n=BIP44_PATH)),
            ('OsmosisGetAddress', messages_osmosis.OsmosisGetAddress(address_n=BIP44_PATH)),
            ('NanoGetAddress', messages_nano.NanoGetAddress(address_n=BIP44_PATH)),
            ('EosGetPublicKey', messages_eos.EosGetPublicKey(address_n=BIP44_PATH)),
            ('ThorchainGetAddress', messages_thorchain.ThorchainGetAddress(address_n=BIP44_PATH)),
            ('MayachainGetAddress', messages_maya.MayachainGetAddress(address_n=BIP44_PATH)),
            ('RippleGetAddress', messages_ripple.RippleGetAddress(address_n=BIP44_PATH)),
            ('BinanceGetAddress', messages_binance.BinanceGetAddress(address_n=BIP44_PATH)),
            ('TronGetAddress', messages_tron.TronGetAddress(address_n=BIP44_PATH)),
            ('TonGetAddress', messages_ton.TonGetAddress(address_n=BIP44_PATH)),
            ('SolanaGetAddress', messages_solana.SolanaGetAddress(address_n=BIP44_PATH)),
            ('HiveGetPublicKey', messages_hive.HiveGetPublicKey(address_n=BIP44_PATH)),
        ]

        bitcoin_only = self._is_bitcoin_only()
        home_before = self.client.debug.read_layout()

        for name, msg in probes:
            resp = self._probe(msg)
            if bitcoin_only:
                self._assert_unknown_message(name, resp)
            else:
                self._assert_handler_present(name, resp)

        if bitcoin_only:
            time.sleep(BUTTON_RENDER_SETTLE_SECONDS)
            home_after = self.client.debug.read_layout()
            self.assertEqual(bytes(home_before), bytes(home_after))

        # The device is still usable after all of that: a refusal must not
        # wedge the message loop.
        self.assertEqual(self.client.call(proto.Ping(message='alive')).message,
                         'alive')

    # ------------------------------------------------------------------
    # L5 -- stripped coin NAMES are refused
    # ------------------------------------------------------------------

    def test_altcoin_coin_names_are_refused(self):
        """A stripped coin is refused by name, on a handler that still exists.

        GetPublicKey is a Bitcoin-family message and stays in the message map,
        so this is the other half of the boundary: coinByName() must fail for
        every coin the image no longer carries, rather than falling back to
        Bitcoin's parameters and handing back an xpub with the wrong version
        bytes under a Litecoin label.
        """
        self.setup_mnemonic_nopin_nopassphrase()
        bitcoin_only = self._is_bitcoin_only()
        account = [2147483692, 2147483648, 2147483648]

        for name in ('Bitcoin', 'Testnet'):
            resp = self._probe(proto.GetPublicKey(address_n=account,
                                                  coin_name=name))
            self.assertTrue(isinstance(resp, proto.PublicKey),
                            "%s must always be supported; got %s"
                            % (name, type(resp).__name__))

        for name in ('Litecoin', 'Dogecoin', 'BitcoinCash', 'Zcash',
                     'DigiByte', 'Dash'):
            resp = self._probe(proto.GetPublicKey(address_n=account,
                                                  coin_name=name))
            if bitcoin_only:
                self.assertTrue(
                    isinstance(resp, proto.Failure)
                    and resp.code == proto_types.Failure_Other,
                    "%s is not in the bitcoin-only coin table, so it must be "
                    "refused by name; got %s" % (name, type(resp).__name__))
            else:
                self.assertTrue(isinstance(resp, proto.PublicKey),
                                "%s must work on the multi-chain image; got %s"
                                % (name, type(resp).__name__))

    # ------------------------------------------------------------------
    # L6 -- Zcash privacy is compiled out
    # ------------------------------------------------------------------

    def test_zcash_privacy_is_compiled_out(self):
        """KK_ZCASH_PRIVACY is forced OFF whenever KK_BITCOIN_ONLY is ON.

        The Orchard engine is the largest thing in the image and its handlers
        live behind ZCASH_PRIVACY, not BITCOIN_ONLY, so the two gates are wired
        together in CMakeLists rather than in the source. If that wiring ever
        breaks, the bitcoin-only image ships a shielded-Zcash signer it does
        not have the coin table to support -- and the transparent side is gone
        too, so 'Zcash' is refused as a coin name in the same breath.
        """
        self.setup_mnemonic_nopin_nopassphrase()
        bitcoin_only = self._is_bitcoin_only()
        probes = [
            ('ZcashGetOrchardFVK',
             messages_zcash.ZcashGetOrchardFVK(address_n=BIP44_PATH)),
            ('ZcashDisplayAddress',
             messages_zcash.ZcashDisplayAddress(address_n=BIP44_PATH)),
        ]
        for name, msg in probes:
            resp = self._probe(msg)
            if bitcoin_only:
                self._assert_unknown_message(name, resp)
            else:
                self._assert_handler_present(name, resp)

        resp = self._probe(proto.GetAddress(
            address_n=[2147483692, 2147483781, 2147483648, 0, 0],
            coin_name='Zcash'))
        if bitcoin_only:
            self.assertTrue(
                isinstance(resp, proto.Failure)
                and resp.code == proto_types.Failure_Other,
                "transparent Zcash must be gone from the coin table too; got %s"
                % type(resp).__name__)
        else:
            self.assertTrue(isinstance(resp, proto.Address),
                            "multi-chain image refused transparent Zcash: %s"
                            % type(resp).__name__)

    # ------------------------------------------------------------------
    # L7 -- the BITCOIN_ONLY arm of the OP_RETURN path
    # ------------------------------------------------------------------

    def test_op_return_thorchain_memo_is_confirmed_raw(self):
        """The arm added to compile_output() by the alpha merge.

        transaction.c wraps the THORChain memo decode in `#if !BITCOIN_ONLY`
        and confirms the raw OP_RETURN bytes in the #else. So a memo that the
        multi-chain image explains -- swap, asset, destination, affiliate --
        is shown on the bitcoin-only image as the bytes themselves. That is the
        right answer (a decode the image cannot perform must not be faked), but
        it had never been executed: CI runs only the multi-chain emulator.

        The screen count is measured, not modelled. Bitcoin-only: one output
        review, one raw OP_RETURN screen, one SignTx -- three. Multi-chain: the
        same memo expands to several decoded screens, so the count is strictly
        higher. Either way the signed script must carry the memo verbatim, so
        the disclosure and the signature are pinned to the same bytes.
        """
        self.setup_mnemonic_nopin_nopassphrase()
        self._reset_screens()

        _, serialized_tx = self._sign_with_op_return(THORCHAIN_MEMO)

        # OP_RETURN <push 0x41> <memo> -- what was signed.
        expected_script = (b'\x6a' + bytes([len(THORCHAIN_MEMO)])
                           + THORCHAIN_MEMO)
        self.assertTrue(
            expected_script in serialized_tx,
            "the signed script must carry the memo bytes verbatim")

        confirm_outputs = [c for c in self._confirm_codes()
                           if c == proto_types.ButtonRequest_ConfirmOutput]

        if self._is_bitcoin_only():
            self.assertEqual(
                self._confirm_codes(),
                [proto_types.ButtonRequest_ConfirmOutput,   # pay-to-address
                 proto_types.ButtonRequest_ConfirmOutput,   # raw OP_RETURN
                 proto_types.ButtonRequest_SignTx])
            op_return_screen = self._screen(1)
            # It has to actually draw the memo: a blank or near-blank screen
            # here would mean the user approved bytes they never saw.
            self.assertGreater(lit_pixels(op_return_screen), 400)
            self.assertNotEqual(bytes(op_return_screen),
                                bytes(self._screen(0)))
        else:
            self.assertGreater(
                len(confirm_outputs), 2,
                "the multi-chain image must decode the memo into its own "
                "screens; %d ConfirmOutput screen(s) means it fell through to "
                "the raw-data path" % len(confirm_outputs))

    def test_op_return_refusal_cancels_the_signature(self):
        """Refusing the OP_RETURN screen must abort, on both products.

        The BITCOIN_ONLY arm returns -1 from compile_output() when confirm_data
        is refused, and the multi-chain arm has its own THORCHAIN_MEMO_CANCELLED
        path that must not answer a refusal by asking again on a second screen.
        Both must surface as Failure_ActionCancelled with no signature, and the
        flow must stop AT the refused screen -- a SignTx request afterwards
        would mean the refusal was recorded and then ignored.
        """
        self.setup_mnemonic_nopin_nopassphrase()
        self._reset_screens()
        self.refuse_on = 2  # the screen after the pay-to-address review

        try:
            self._sign_with_op_return(THORCHAIN_MEMO)
            self.fail("the device signed a transaction whose OP_RETURN output "
                      "the user refused")
        except CallException as exc:
            self.assertEqual(exc.args[0], proto_types.Failure_ActionCancelled)

        self.assertEqual(len(self.screens), 2)
        self.assertTrue(
            proto_types.ButtonRequest_SignTx not in self._confirm_codes(),
            "the flow reached the SignTx confirmation after the user refused "
            "an output")

    # ------------------------------------------------------------------
    # L9 -- the shared OMNI branch survived the strip
    # ------------------------------------------------------------------

    def test_omni_op_return_is_still_decoded(self):
        """The OMNI branch sits above the #if and must be untouched.

        compile_output() tests for an "omni" prefix BEFORE the BITCOIN_ONLY
        split, so an OMNI simple send is still decoded into "Do you want to
        send 1.0 OMNI?" on the bitcoin-only image. The regression this guards
        against is the new #else swallowing the OMNI case, which would silently
        downgrade a decoded amount to a hex dump.

        Proved by contrast rather than by OCR: the same twenty bytes with the
        leading 'o' changed to 'p' are no longer OMNI and fall through to the
        raw-data confirmation. The two screens must differ, and the decoded one
        must be the sparser of the two -- one short sentence against forty hex
        digits.

        Both payloads ride in ONE transaction, as two data outputs, rather than
        in two signings. That is not stylistic: a transaction ending in
        OP_RETURN poisons the duplicate-transaction detector, so a second
        signing in the same session is refused (see
        test_op_return_does_not_poison_the_duplicate_detector).
        """
        self.setup_mnemonic_nopin_nopassphrase()
        self._reset_screens()

        out_pay = proto_types.TxOutputType(address=OUT_ADDRESS,
                                           amount=OUT_AMOUNT,
                                           script_type=proto_types.PAYTOADDRESS)
        self._sign([self._data_output(OMNI_SIMPLE_SEND),
                    self._data_output(NOT_OMNI),
                    out_pay])

        self.assertEqual(
            self._confirm_codes(),
            [proto_types.ButtonRequest_ConfirmOutput,   # OMNI, decoded
             proto_types.ButtonRequest_ConfirmOutput,   # same bytes, raw
             proto_types.ButtonRequest_ConfirmOutput,   # pay-to-address
             proto_types.ButtonRequest_SignTx])

        omni_screen = self._screen(0)
        raw_screen = self._screen(1)

        self.assertNotEqual(bytes(omni_screen), bytes(raw_screen))
        self.assertGreater(lit_pixels(omni_screen), 200)
        self.assertGreater(lit_pixels(raw_screen), lit_pixels(omni_screen))


    # ------------------------------------------------------------------
    # L10/L11 -- the duplicate-transaction detector and OP_RETURN
    # ------------------------------------------------------------------

    def test_repeated_transaction_is_allowed_without_op_return(self):
        """The control for the test below: an exact repeat is NOT a duplicate.

        compile_output() carries an anti-malware check (txin_check.c): warn
        when a transaction pays the SAME amount to the SAME address as the
        previous one but was built from DIFFERENT inputs, which is what host
        malware rewriting a segwit txid looks like. An exact repeat -- same
        outputs AND same inputs -- is not that, and is deliberately allowed.

        This is signed twice from the same input here to pin that, so the
        refusal in the next test cannot be explained away as the duplicate
        guard doing its job.
        """
        self.setup_mnemonic_nopin_nopassphrase()
        out_pay = proto_types.TxOutputType(address=OUT_ADDRESS,
                                           amount=OUT_AMOUNT,
                                           script_type=proto_types.PAYTOADDRESS)

        _, first = self._sign([out_pay])
        _, second = self._sign([out_pay])
        self.assertEqual(binascii.hexlify(first), binascii.hexlify(second))

    def test_op_return_does_not_poison_the_duplicate_detector(self):
        """An OP_RETURN output must not falsely condemn the next transaction.

        Found while exercising the BITCOIN_ONLY arm above and NOT caused by it:
        it reproduces identically on the multi-chain build, because the code is
        shared. Sign a transaction whose LAST output is OP_RETURN, then sign
        the transaction the test above just proved is allowed -- and the device
        answers "WARNING: DUPLICATE TRANSACTION! Already signed a tx with the
        same outputs. To try again, unplug/replug KeepKey." and aborts.

        Mechanism. signing.c calls txin_dgst_final() once per output, and
        compile_output() calls txin_dgst_save_and_reset() -- the only thing
        that re-initialises the SHA-256 context -- only on the pay-to-address
        path. An OP_RETURN output returns before it. So a transaction ending
        in OP_RETURN leaves the context finalised and never re-initialised, and
        the NEXT transaction's inputs are hashed into a finalised context. Its
        digest no longer matches, while the amount and address still do, which
        is exactly the (same outputs, different inputs) pattern the check
        exists to flag.

        The failure is fail-safe -- it refuses rather than signs -- but it
        refuses a legitimate transaction and tells the user to replug, and
        every OP_RETURN-terminated transaction arms it. That is every
        THORChain/Maya swap the wallet builds.

        Nothing caught it because common.KeepKeyTest wipes the device in
        setUp, so no existing test signs two transactions in one session.
        """
        self.setup_mnemonic_nopin_nopassphrase()

        out_pay = proto_types.TxOutputType(address=OUT_ADDRESS,
                                           amount=OUT_AMOUNT,
                                           script_type=proto_types.PAYTOADDRESS)

        self._reset_screens()
        self._sign([out_pay, self._data_output(THORCHAIN_MEMO)])
        self.assertEqual(
            self._confirm_codes(),
            [proto_types.ButtonRequest_ConfirmOutput,   # pay-to-address
             proto_types.ButtonRequest_ConfirmOutput,   # OP_RETURN
             proto_types.ButtonRequest_SignTx])

        self._reset_screens()
        try:
            self._sign([out_pay])
        except CallException as exc:
            self.fail(
                "after an OP_RETURN-terminated transaction the device refused "
                "the next one with %r; its review screens were %r -- a "
                "ConfirmOutput followed by the ButtonRequest_Other of the "
                "duplicate-transaction warning. The same transaction signs "
                "twice in a row when no OP_RETURN precedes it."
                % (exc.args, self._confirm_codes()))

        self.assertEqual(
            self._confirm_codes(),
            [proto_types.ButtonRequest_ConfirmOutput,
             proto_types.ButtonRequest_SignTx])


if __name__ == '__main__':
    unittest.main()
