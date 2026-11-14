"""ERC-7730 runtime (7.15): what the device shows for a certified definition.

Each test signs the same transaction on the ordinary path and then with a
certified ERC-7730 definition, reads every confirmation's exact title and
body over DebugLink, and requires the same signature both times: the
definition adds screens, never changes what is signed.

The definition is signed by a throwaway catalog key loaded as a runtime
signer ("NOT verified by KeepKey"); AdvancedMode is required. Uses only the
public test mnemonic. Also imported by keepkey-firmware's
scripts/emulator/test_stack07_regressions.py for its harness.
"""

import copy
import hashlib

import semver

import common
from confirmation_pages import ConfirmationPages
from keepkeylib import erc7730, erc7730_compiler, eip712_stream
from keepkeylib import messages_ethereum_pb2 as eth
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types
from keepkeylib.signed_metadata import TEST_PRIVATE_KEY, test_signer_compressed_pubkey as signer_pubkey


PATH = [0x8000002C, 0x8000003C, 0x80000000, 0, 0]
ADDRESS = bytes.fromhex("11" * 20)
OTHER_ADDRESS = bytes.fromhex("33" * 20)
# An unrelated throwaway key that is never loaded into any signer slot.
UNKNOWN_SIGNER_KEY = bytes.fromhex("42" * 32)
# The ordinary review that follows every certified one. Its screens are not
# captured for the report: they are unchanged, which the identical signature
# already proves, and the report's frame picker would otherwise prefer the
# per-transaction data hash over the screens the definition adds.
ORDINARY_REVIEW = ("Send", "Transaction", "Ethereum Data Hash")


def assert_failure(test, result, code, message):
    test.assertIsInstance(result, proto.Failure)
    test.assertEqual((result.code, result.message), (code, message))


class Erc7730Harness(object):
    """Preload, sign and walk helpers. Not a TestCase: importing it collects
    no tests."""

    def _envelope(self, program, signer_key=TEST_PRIVATE_KEY, signer_pub=None,
                  chain=1):
        cert = bytearray(139)
        cert[0] = 1
        cert[2:6] = chain.to_bytes(4, "big")
        cert[10:21] = b"Host alias\0"
        cert[42:75] = signer_pub if signer_pub is not None else signer_pubkey()
        return erc7730.sign_envelope(program, cert, signer_key)

    def _definition(self, program, envelope):
        return erc7730.Definition(
            envelope, program[7], 1, ADDRESS,
            program[38:42] if program[7] == 1 else program[38:70])

    def _load_signer(self):
        self.client.load_clearsign_signer(
            key_id=3, pubkey=signer_pubkey(), alias="Audit signer")

    def _preload(self, program):
        self._load_signer()
        envelope = self._envelope(program)
        erc7730.preload(self.client, self._definition(program, envelope))
        self._drop_setup_screenshots()
        return envelope

    def _raw_preload(self, envelope):
        """Stream an envelope; return the first non-Ack response.

        Every refusal contract below is a refusal BEFORE any ButtonRequest,
        so a ButtonRequest here is returned (and fails the caller's Failure
        assertion) rather than acknowledged.
        """
        definition_id = hashlib.sha256(envelope).digest()
        offset = 0
        while offset < len(envelope):
            data = envelope[offset:offset + erc7730.MAX_CHUNK]
            response = self.client.call_raw(eth.EthereumClearSignDefinition(
                definition_id=definition_id, offset=offset,
                total_length=len(envelope), data=data))
            if not isinstance(response, eth.EthereumClearSignDefinitionAck):
                return response
            offset += len(data)
        return response

    def _first_pages(self):
        """Complete confirmations, after checking every numbered page."""
        self.confirmations.finish()
        return self.confirmations.texts

    def _walk(self, start, envelope=b"", doc=None, change_pass=None, cancel_button=None,
              arguments=None, catalog=None, altered=None, cancel_title=None,
              chunk_size=None, typed_altered=None, max_steps=20000):
        response = self.client.call_raw(start)
        self.definition_requests = 0
        self.button_codes = []
        self.confirmations = ConfirmationPages()
        # Keep one entry per physical ButtonRequest for cancellation sweeps.
        # Complete bodies are available separately through _first_pages().
        self.screens = []
        self.calldata_chunk_sizes = []
        buttons = 0
        calldata_passes = 0
        calldata_offset = 0
        typed_passes = 0
        # A safety bound, not a budget: a typed-data iteration (Seaport) walks
        # the message once per item field, a few thousand messages in all.
        for _ in range(max_steps):
            if isinstance(response, proto.ButtonRequest):
                buttons += 1
                self.button_codes.append(response.code)
                text = self.client.debug.read_confirm_text()
                title = self.confirmations.add(response.code, text)
                self.screens.append((title, text[1]))
                if self.screens[-1][0] not in ORDINARY_REVIEW:
                    self.client.capture_oled()
                decline = (buttons == cancel_button or
                           self.screens[-1][0] == cancel_title)
                self.client.debug.press_no() if decline else self.client.debug.press_yes()
                response = self.client.call_raw(proto.ButtonAck())
            elif isinstance(response, eth.EthereumClearSignDefinitionRequest) and catalog:
                self.definition_requests += 1
                response = self.client.call_raw(catalog.chunk(response))
            elif isinstance(response, eth.EthereumClearSignDefinitionRequest):
                self.definition_requests += 1
                offset = response.offset
                response = self.client.call_raw(eth.EthereumClearSignDefinitionChunk(
                    definition_id=hashlib.sha256(envelope).digest(), offset=offset,
                    total_length=len(envelope), data=envelope[offset:offset + response.length]))
            elif isinstance(response, eth.EthereumTypedDataStructRequest):
                response = self.client.call_raw(eip712_stream.build_struct_ack(
                    eip712_stream.struct_members(doc, response.name)))
            elif isinstance(response, eth.EthereumTypedDataValueRequest):
                path = list(response.member_path)
                if path == [1, 0]:
                    typed_passes += 1
                current = copy.deepcopy(doc)
                if change_pass == typed_passes:
                    current["message"]["first"] += 1
                if typed_altered:
                    typed_altered(current, typed_passes, path)
                response = self.client.call_raw(eip712_stream.value_ack(
                    current, response, chunked=True))
            elif isinstance(response, eth.EthereumTxRequest) and response.HasField("data_length"):
                if calldata_offset == 0:
                    calldata_passes += 1
                data = arguments
                if altered and altered[0] == calldata_passes:
                    data = altered[1]
                if data is None:
                    data = (43 if change_pass == calldata_passes else 42).to_bytes(32, "big")
                    data += (7).to_bytes(32, "big")
                self.assertGreater(response.data_length, 0)
                self.assertLessEqual(response.data_length,
                                     len(data) - calldata_offset)
                length = min(response.data_length,
                             chunk_size or response.data_length)
                chunk = data[calldata_offset:calldata_offset + length]
                self.calldata_chunk_sizes.append(length)
                calldata_offset += length
                if calldata_offset == len(data):
                    calldata_offset = 0
                response = self.client.call_raw(eth.EthereumTxAck(data_chunk=chunk))
            else:
                if not isinstance(response, proto.Failure):
                    self.confirmations.finish()
                return response, buttons, calldata_passes, typed_passes
        self.fail("protocol did not terminate")


class Recording(erc7730.Catalog):
    """A catalog that records the depth of every inner lookup."""
    depths = None

    def chunk(self, request):
        if request.HasField("recursion_depth") and self.depths is not None:
            if request.offset == 0:
                self.depths.append(request.recursion_depth)
        return erc7730.Catalog.chunk(self, request)


class TestMsgEthereumErc7730Runtime(Erc7730Harness, common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.requires_fullFeature()
        self.requires_firmware("7.15.0")
        self.requires_release_capability("erc7730-runtime-review")
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

    # Phase 0 of the ERC-7730 formatter plan: the preload verifier and the
    # runtime share one capability table, so a program the runtime cannot
    # finish is refused before the first screen instead of after the user has
    # approved the signer, intent and earlier fields.
    def _audit_start(self, program, data_length=68):
        return eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=data_length, data_initial_chunk=program[38:42])

    def test_program_outside_capability_table_is_refused_at_preload(self):
        signature = "audit(uint256 first,uint256 second)"
        # Conditions that could hide or veto a field are never executed.
        fields = {
            "ifNotIn": {"path": "first", "label": "First value",
                        "format": "raw", "visible": {"ifNotIn": [0]}},
            "mustMatch": {"path": "first", "label": "First value",
                          "format": "raw", "visible": {"mustMatch": [42]}},
        }
        self._load_signer()
        for name, field in sorted(fields.items()):
            descriptor = {"display": {"formats": {signature: {
                "intent": "Audit action", "fields": [
                    field,
                    {"path": "second", "label": "Second value",
                     "format": "raw"}]}}}}
            with self.assertRaises(erc7730_compiler.DeviceCannotExecute):
                erc7730_compiler.compile_calldata(
                    descriptor, signature, 1, ADDRESS)
            program = erc7730_compiler.compile_calldata(
                descriptor, signature, 1, ADDRESS, executable_only=False)
            result = self._raw_preload(self._envelope(program))
            assert_failure(self, result, types.Failure_SyntaxError,
                           "Invalid certified ERC-7730 definition")
            # Nothing is left preloaded: the transaction takes the ordinary,
            # uncertified path and never asks for a definition.
            result, _, passes, _ = self._walk(self._audit_start(program))
            self.assertIsInstance(result, eth.EthereumTxRequest, msg=name)
            self.assertTrue(result.HasField("signature_r"), msg=name)
            self.assertEqual((name, passes, self.definition_requests),
                             (name, 1, 0))

    def test_path_outside_abi_is_refused_at_preload(self):
        signature = "audit(uint256 first,uint256 second)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": [
                {"path": "second", "label": "Second value",
                 "format": "raw"}]}}}}
        program = bytearray(erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS))
        # The single value path is (source 1, one step, index 1). Point it at
        # a third argument the function does not have.
        step = program.index(bytes([1, 1, 0xff, 0xff, 1, 0, 0, 0, 1]))
        program[step + 8] = 2
        self._load_signer()
        result = self._raw_preload(self._envelope(bytes(program)))
        assert_failure(self, result, types.Failure_SyntaxError,
                       "Invalid certified ERC-7730 definition")

    def test_raw_field_screens_show_exact_text(self):
        signature = "audit(uint256 first,uint256 second)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": [
                {"path": "first", "label": "First value", "format": "raw"},
                {"path": "second", "label": "Second value",
                 "format": "raw"}]}}}}
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        self._certified(program, self._word(42) + self._word(7))
        self.assertEqual(self.calldata_passes, 4)
        certified = [screen for screen in self.screens if screen[0] in (
            "Runtime signer", "Unverified data", "Contract action",
            "Signer field")]
        self.assertEqual(certified[1:], [
            ("Unverified data", "NOT verified by KeepKey"),
            ("Contract action", "Audit action"),
            ("Signer field", "First value:\n42"),
            ("Signer field", "Second value:\n7"),
        ])
        self.assertEqual(certified[0][0], "Runtime signer")
        self.assertTrue(certified[0][1].startswith("Audit signer ("),
                        certified[0][1])

    # Phase A: tokenAmount, addressName, @.from/@.to and signed constants.
    # Asset facts come only from the firmware token table; an address is always
    # shown in full; the signer's message sits beside the value.
    USDC = bytes.fromhex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
    # Not in the firmware token table on chain 1 (0xeeee..ee is: there the
    # table's own entry wins over any signer alias).
    NATIVE = bytes.fromhex("44" * 20)

    def _certified(self, program, arguments, preload=None, catalog=None):
        """Sign once on the ordinary path, then with the definition, and
        require the same signature: the annotations are additive only."""
        start = self._audit_start(program, 4 + len(arguments))
        baseline, _, _, _ = self._walk(start, arguments=arguments)
        self.assertIsInstance(baseline, eth.EthereumTxRequest)
        self.assertTrue(baseline.HasField("signature_r"))
        envelope = self._preload(program) if preload is None else preload()
        result, _, passes, _ = self._walk(start, envelope, arguments=arguments,
                                          catalog=catalog)
        self.calldata_passes = passes
        # The certified path ran: the device asked for its definition.
        self.assertGreater(self.definition_requests, 0)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertEqual((result.signature_r, result.signature_s),
                         (baseline.signature_r, baseline.signature_s))
        return result

    def _field_screens(self, descriptor, signature, arguments):
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        self._certified(program, arguments)
        return [body for title, body in self._first_pages()
                if title == "Signer field"]

    @staticmethod
    def _word(value):
        if isinstance(value, bytes):
            return bytes(12) + value
        return value.to_bytes(32, "big")

    def _token_screen(self, token, amount, params=None):
        signature = "send(address token,uint256 amount)"
        fields = [{"path": "amount", "label": "Amount", "format": "tokenAmount",
                   "params": dict({"tokenPath": "token"}, **(params or {}))}]
        descriptor = {"display": {"formats": {signature: {
            "intent": "Send", "fields": fields}}}}
        return self._field_screens(descriptor, signature,
                                   self._word(token) + self._word(amount))

    def test_token_amount_uses_the_firmware_token_table(self):
        self.assertEqual(self._token_screen(self.USDC, 1500000),
                         ["Amount:\n1.5 USDC"])

    def test_token_named_by_calldata_wins_over_the_hosts_claim(self):
        # The transaction goes to ADDRESS and a host might call it USDC; the
        # calldata names another token, which the firmware table does not know.
        self.assertEqual(self._token_screen(OTHER_ADDRESS, 42), [
            "Amount:\n42\nunknown token\n0x" + OTHER_ADDRESS.hex()])

    def test_signer_label_cannot_name_an_unknown_token(self):
        signature = "send(uint256 amount)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Send", "fields": [{
                "path": "amount", "label": "USDC amount",
                "format": "tokenAmount",
                "params": {"token": "0x" + OTHER_ADDRESS.hex()}}]}}}}
        self.assertEqual(
            self._field_screens(descriptor, signature, self._word(42)),
            ["USDC amount:\n42\nunknown token\n0x" + OTHER_ADDRESS.hex()])

    def test_threshold_message_is_shown_beside_the_exact_amount(self):
        params = {"threshold": 1000000, "message": "Large amount"}
        self.assertEqual(self._token_screen(self.USDC, 999999, params),
                         ["Amount:\n0.999999 USDC"])
        self.assertEqual(self._token_screen(self.USDC, 1500000, params),
                         ["Amount:\nSigner: Large amount\n1.5 USDC"])

    def test_native_alias_discloses_signer_mapping_and_token_address(self):
        params = {"nativeCurrencyAddress": ["0x" + self.NATIVE.hex()]}
        # An address outside the alias set is not the native asset.
        self.assertEqual(
            self._token_screen(OTHER_ADDRESS, 1500000000000000000, params),
            ["Amount:\n1500000000000000000\nunknown token\n0x" +
             OTHER_ADDRESS.hex()])
        self.assertEqual(
            self._token_screen(self.NATIVE, 1500000000000000000, params),
            ["Amount:\nSigner native alias:\n0x" + self.NATIVE.hex() +
             "\n1.5 ETH"])

    def test_native_placeholder_alias_reads_as_the_native_coin(self):
        """7.17: the zero address a signer calls native (a Safe's gas token)
        reads as the coin itself, not as a signer mapping."""
        self.requires_firmware("7.17.0")
        zero = bytes(20)
        params = {"nativeCurrencyAddress": ["0x" + zero.hex()]}
        self.assertEqual(self._token_screen(zero, 10 * 10 ** 18, params),
                         ["Amount:\n10 ETH"])
        # Not aliased, the zero address is still an unknown token.
        self.assertEqual(self._token_screen(zero, 42), [
            "Amount:\n42\nunknown token\n0x" + zero.hex()])

    def test_address_name_marks_only_the_signing_account(self):
        signer = self.client.ethereum_get_address(PATH)
        if not isinstance(signer, bytes):
            signer = bytes.fromhex(signer[2:])
        signature = "pay(address recipient)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Pay", "fields": [{
                "path": "recipient", "label": "Recipient",
                "format": "addressName"}]}}}}
        from keepkeylib.signed_metadata import keccak256

        def checksummed(address):
            digest = keccak256(address.hex().encode("ascii")).hex()
            return "0x" + "".join(
                c.upper() if c.isalpha() and int(digest[i], 16) >= 8 else c
                for i, c in enumerate(address.hex()))

        near = bytes(signer[:19]) + bytes([signer[19] ^ 1])
        self.assertEqual(
            self._field_screens(descriptor, signature, self._word(near)),
            ["Recipient:\n" + checksummed(near)])
        self.assertEqual(
            self._field_screens(descriptor, signature, self._word(signer)),
            ["Recipient:\n" + checksummed(signer) + "\n(this wallet)"])

    def test_containers_and_signed_constants(self):
        signature = "audit(uint256 first,uint256 second)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": [
                {"path": "@.to", "label": "Contract", "format": "addressName"},
                {"value": "Audit protocol", "label": "Protocol"}]}}}}
        self.assertEqual(
            self._field_screens(descriptor, signature,
                                self._word(42) + self._word(7)),
            ["Contract:\n0x" + ADDRESS.hex(), "Protocol:\nAudit protocol"])

    # Phase B: the interpolated intent is shown as numbered parts after the
    # plain intent. Each value part is formatted exactly as its field is.
    def test_interpolated_intent_parts_show_the_same_values_as_fields(self):
        signature = "send(address token,uint256 amount)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Send tokens",
            "interpolatedIntent": "Send {amount} now",
            "fields": [{"path": "amount", "label": "Amount",
                        "format": "tokenAmount",
                        "params": {"tokenPath": "token"}}]}}}}
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        self._certified(program, self._word(self.USDC) + self._word(1500000))
        shown = [screen for screen in self._first_pages()
                 if screen[0] in ("Contract action", "Intent text 1 of 3",
                                  "Intent value 2 of 3", "Intent text 3 of 3",
                                  "Signer field")]
        self.assertEqual(shown, [
            ("Contract action", "Send tokens"),
            ("Intent text 1 of 3", "Send"),
            ("Intent value 2 of 3", "1.5 USDC"),
            ("Intent text 3 of 3", "now"),
            ("Signer field", "Amount:\n1.5 USDC"),
        ])

    # Phase C: amount, date, duration, unit, enum and nftName. Signer-supplied
    # units and enum labels appear beside the raw value, never instead.
    def _one_field(self, field, arguments, signature="act(uint256 a,address b)",
                   metadata=None):
        descriptor = {"display": {"formats": {signature: {
            "intent": "Act", "fields": [field]}}}}
        if metadata:
            descriptor["metadata"] = metadata
        return self._field_screens(descriptor, signature, arguments)

    def test_phase_c_formatters_show_exact_text(self):
        pad = self._word(OTHER_ADDRESS)
        cases = [
            ({"path": "a", "label": "Value", "format": "amount"},
             1500000000000000000, "Value:\n1.5 ETH"),
            ({"path": "a", "label": "When", "format": "date",
              "params": {"encoding": "timestamp"}},
             1700000000, "When:\n2023-11-14 22:13:20 UTC\n(1700000000)"),
            ({"path": "a", "label": "At", "format": "date",
              "params": {"encoding": "blockheight"}},
             19000000, "At:\nBlock 19000000"),
            ({"path": "a", "label": "Lock", "format": "duration"},
             93784, "Lock:\n1d 2h 3m 4s\n(93784 s)"),
            ({"path": "a", "label": "Weight", "format": "unit",
              "params": {"base": "kg", "decimals": 3}},
             93784, "Weight:\nunit set by signer\n93.784 kg\nraw 93784"),
        ]
        for field, value, expected in cases:
            self.assertEqual(
                (field["format"],
                 self._one_field(field, self._word(value) + pad)),
                (field["format"], [expected]))

    def test_enum_labels_are_the_signers_claim_beside_the_value(self):
        field = {"path": "a", "label": "Side", "format": "enum",
                 "params": {"$ref": "$.metadata.enums.side"}}
        metadata = {"enums": {"side": {"0": "Buy", "1": "Sell"}}}
        pad = self._word(OTHER_ADDRESS)
        self.assertEqual(self._one_field(field, self._word(1) + pad,
                                         metadata=metadata),
                         ["Side:\nlabel set by signer\nSell (1)"])
        self.assertEqual(self._one_field(field, self._word(5) + pad,
                                         metadata=metadata),
                         ["Side:\n5 (unmapped)"])

    def test_nft_shows_the_collection_address(self):
        field = {"path": "a", "label": "Item", "format": "nftName",
                 "params": {"collectionPath": "b"}}
        self.assertEqual(
            self._one_field(field, self._word(42) + self._word(self.USDC)),
            ["Item:\nToken ID 42\nCollection\n"
             "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"])

    def test_malformed_calldata_is_refused_before_a_constant_field(self):
        # The first field shows a signed constant and captures nothing, so
        # only the up-front validation pass stands between malformed calldata
        # and the first screen.
        signature = "pay(address recipient)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Pay", "fields": [
                {"value": "Audit protocol", "label": "Protocol"},
                {"path": "recipient", "label": "Recipient",
                 "format": "addressName"}]}}}}
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        envelope = self._preload(program)
        dirty = b"\x01" + bytes(11) + OTHER_ADDRESS  # non-canonical address
        result, buttons, passes, _ = self._walk(
            self._audit_start(program, 36), envelope, arguments=dirty)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 calldata does not match definition")
        self.assertEqual((buttons, passes), (0, 1))

    # Phase D: groups, "optional" fields and one iteration at a time. Every
    # element gets its own numbered screens; nothing is ever hidden.
    def _titled_fields(self, descriptor, signature, arguments):
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        self._certified(program, arguments)
        return [screen for screen in self._first_pages()
                if screen[0].startswith("Signer field")]

    def test_iteration_shows_every_element_numbered(self):
        signature = "pay(address[] recipients)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Pay", "fields": [{
                "path": "recipients.[]", "label": "Recipient",
                "format": "addressName"}]}}}}
        # An empty array shows no element and still signs.
        self.assertEqual(
            self._titled_fields(descriptor, signature,
                                self._word(32) + self._word(0)), [])
        arguments = (self._word(32) + self._word(2) +
                     self._word(OTHER_ADDRESS) + self._word(ADDRESS))
        self.assertEqual(
            self._titled_fields(descriptor, signature, arguments), [
                ("Signer field 1 of 2", "Recipient:\n0x" + OTHER_ADDRESS.hex()),
                ("Signer field 2 of 2", "Recipient:\n0x" + ADDRESS.hex()),
            ])
        # A fixed ABI array has no length word. Capture still binds the
        # declared count before replaying both element screens.
        fixed_signature = "payFixed(address[2] recipients)"
        fixed_descriptor = {"display": {"formats": {fixed_signature: {
            "intent": "Pay fixed", "fields": [{
                "path": "recipients.[]", "label": "Recipient",
                "format": "addressName"}]}}}}
        self.assertEqual(
            self._titled_fields(
                fixed_descriptor, fixed_signature,
                self._word(OTHER_ADDRESS) + self._word(ADDRESS)), [
                ("Signer field 1 of 2", "Recipient:\n0x" +
                 OTHER_ADDRESS.hex()),
                ("Signer field 2 of 2", "Recipient:\n0x" + ADDRESS.hex()),
            ])

    def test_grouped_tuple_iteration_and_optional_fields(self):
        signature = "batch((address to,uint256 amount)[] items,uint256 fee)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Batch", "fields": [
                {"path": "items.[]", "label": "Transfer", "fields": [
                    {"path": "to", "label": "To", "format": "addressName"},
                    {"path": "amount", "label": "Amount", "format": "raw"}]},
                {"path": "fee", "label": "Fee", "format": "raw",
                 "visible": "optional"}]}}}}
        arguments = (self._word(64) + self._word(9) + self._word(2) +
                     self._word(OTHER_ADDRESS) + self._word(5) +
                     self._word(ADDRESS) + self._word(6))
        self.assertEqual(
            self._titled_fields(descriptor, signature, arguments), [
                ("Signer field 1 of 2", "To:\n0x" + OTHER_ADDRESS.hex()),
                ("Signer field 1 of 2", "Amount:\n5"),
                ("Signer field 2 of 2", "To:\n0x" + ADDRESS.hex()),
                ("Signer field 2 of 2", "Amount:\n6"),
                ("Signer field", "Fee:\n9"),
            ])

    # Phase E1 (7.15): an embedded call the device cannot clear-sign is shown
    # under a blind-sign warning: its callee, selector, length, value and
    # authority, all read from the signed calldata. 7.16 rejects it instead.
    def _exec_screens(self, inner, value=1500000000000000000):
        signature = ("execTransaction(address to,uint256 value,bytes data,"
                     "uint8 operation)")
        descriptor = {"display": {"formats": {signature: {
            "intent": "sign multisig operation", "fields": [
                {"path": "data", "label": "Transaction", "format": "calldata",
                 "params": {"calleePath": "to", "amountPath": "value",
                            "spenderPath": "@.to"}}]}}}}
        padded = inner + bytes(-len(inner) % 32)
        arguments = (self._word(OTHER_ADDRESS) + self._word(value) +
                     self._word(128) + self._word(0) +
                     self._word(len(inner)) + padded)
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        self._certified(program, arguments)
        return [screen for screen in self._first_pages()
                if screen[0] in ("Blind signature", "Signer field")]

    def test_embedded_call_is_shown_under_a_blind_sign_warning(self):
        self.requires_firmware_below("7.16.0")  # 7.16 refuses instead
        inner = bytes.fromhex("a9059cbb") + bytes(296)  # 300 bytes: no capture
        self.assertEqual(self._exec_screens(inner), [
            ("Blind signature", "The inner call is not clear-signed"),
            ("Signer field",
             "Transaction:\nTo 0x" + OTHER_ADDRESS.hex() +
             "\nFunction 0xa9059cbb\nData 300 bytes\nValue 1.5 ETH\nAs 0x" +
             ADDRESS.hex()),
        ])
        self.assertEqual(self._exec_screens(b"", value=0), [
            ("Blind signature", "The inner call is not clear-signed"),
            ("Signer field",
             "Transaction:\nTo 0x" + OTHER_ADDRESS.hex() +
             "\nNo data\nValue 0 Wei\nAs 0x" + ADDRESS.hex()),
        ])

    # Phase E2: the inner call is clear-signed with its own definition, bound
    # to the callee and selector in the signed calldata. Every inner pass
    # replays the whole outer calldata against the reviewed digest.
    EXEC = ("execTransaction(address to,uint256 value,bytes data,"
            "uint8 operation)")
    TRANSFER = "transfer(address to,uint256 amount)"

    def _exec_setup(self, amount_path=True, spender="@.to", memo=None,
                    trailing_data=False, inner_suffix=b""):
        inner_signature = (self.TRANSFER if memo is None else
                           "transfer(address to,uint256 amount,bytes memo)")
        params = {"calleePath": "to"}
        if spender:
            params["spenderPath"] = spender
        if amount_path:
            params["amountPath"] = "value"
        outer_descriptor = {"display": {"formats": {self.EXEC: {
            "intent": "sign multisig operation", "fields": [
                {"path": "data", "label": "Transaction", "format": "calldata",
                 "params": params},
                {"path": "operation", "label": "Operation", "format": "raw"}]}}}}
        inner_descriptor = {"display": {"formats": {inner_signature: {
            "intent": "Transfer", "fields": [
                {"path": "to", "label": "Recipient", "format": "addressName"},
                {"path": "amount", "label": "Amount", "format": "tokenAmount",
                 "params": {"tokenPath": "@.to"}}]}}}}
        outer = erc7730_compiler.compile_calldata(
            outer_descriptor, self.EXEC, 1, ADDRESS,
            trailing_data=trailing_data)
        inner = erc7730_compiler.compile_calldata(
            inner_descriptor, inner_signature, 1, self.USDC,
            trailing_data=trailing_data)
        self._load_signer()
        outer_env = self._envelope(outer)
        inner_def = erc7730.Definition(self._envelope(inner), 1, 1, self.USDC,
                                       inner[38:42])
        outer_def = self._definition(outer, outer_env)
        self._exec_outer = (outer, outer_def)
        call = (bytes.fromhex("a9059cbb") + self._word(OTHER_ADDRESS) +
                self._word(1500000))
        if memo is not None:
            call = (inner[38:42] + self._word(OTHER_ADDRESS) +
                    self._word(1500000) + self._word(96) +
                    self._word(len(memo)) + memo + bytes(-len(memo) % 32))
        call += inner_suffix
        arguments = (self._word(self.USDC) + self._word(0) +
                     self._word(128) + self._word(0) +
                     self._word(len(call)) + call +
                     bytes(-len(call) % 32))
        start = self._audit_start(outer, 4 + len(arguments))
        return start, arguments, outer_def, inner_def

    def _exec_certified(self, arguments, catalog):
        outer, outer_def = self._exec_outer

        def preload():
            erc7730.preload(self.client, outer_def)
            self._drop_setup_screenshots()
            return b""
        return self._certified(outer, arguments, preload=preload,
                               catalog=catalog)

    def _relevant(self):
        titles = ("Runtime signer", "Inner signer", "Contract action",
                  "Inner action", "Signer field", "Inner field",
                  "Blind signature")
        return [screen for screen in self._first_pages() if screen[0] in titles]

    def test_inner_call_is_clear_signed_with_its_own_definition(self):
        start, arguments, outer_def, inner_def = self._exec_setup()
        self._exec_certified(arguments, erc7730.Catalog((outer_def, inner_def)))
        shown = [s for s in self._relevant()
                 if s[0] not in ("Runtime signer", "Inner signer")]
        self.assertEqual(shown, [
            ("Contract action", "sign multisig operation"),
            ("Signer field",
             "Transaction:\nTo 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
             "\nFunction 0xa9059cbb\nData 68 bytes\nValue 0 Wei\nAs 0x" +
             ADDRESS.hex()),
            ("Inner action", "Transfer"),
            ("Inner field", "Recipient:\n0x" + OTHER_ADDRESS.hex()),
            ("Inner field", "Amount:\n1.5 USDC"),
            ("Signer field", "Operation:\n0"),
        ])
        self.assertIn("Inner signer", [s[0] for s in self.screens])

    APPROVE = "approve(address spender,uint256 amount)"
    MAX = (1 << 256) - 1

    def _exec_approve(self, amount, spender=None, with_definition=True):
        """execTransaction carrying approve(OTHER_ADDRESS, amount) on USDC."""
        self._exec_setup()
        inner = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.APPROVE: {
                "intent": "Approve", "fields": [
                    {"path": "spender", "label": "Spender",
                     "format": "addressName"},
                    {"path": "amount", "label": "Amount", "format": "raw"}]}}}},
            self.APPROVE, 1, self.USDC)
        inner_def = erc7730.Definition(self._envelope(inner), 1, 1, self.USDC,
                                       inner[38:42])
        outer_def = self._exec_outer[1]
        call = (bytes.fromhex("095ea7b3") +
                (spender or self._word(OTHER_ADDRESS)) + self._word(amount))
        arguments = (self._word(self.USDC) + self._word(0) +
                     self._word(128) + self._word(0) +
                     self._word(len(call)) + call + bytes(-len(call) % 32))
        catalog = erc7730.Catalog(
            (outer_def, inner_def) if with_definition else (outer_def,))
        return arguments, catalog

    UNLIMITED = ("UNLIMITED approval",
                 "Allow 0x" + OTHER_ADDRESS.hex() + " to spend ALL your USDC")

    def _approve_screens(self):
        return [s for s in self._first_pages()
                if s[0] in ("UNLIMITED approval", "Contract action",
                            "Signer field", "Inner signer", "Inner action",
                            "Blind signature")]

    def test_inner_unlimited_approve_warns_before_the_inner_review(self):
        self.requires_release_capability("erc20-unlimited-approve-review")
        arguments, catalog = self._exec_approve(self.MAX)
        self._exec_certified(arguments, catalog)
        shown = self._approve_screens()
        self.assertEqual(shown[:2], [
            ("Contract action", "sign multisig operation"), self.UNLIMITED])
        self.assertEqual(shown[2][0], "Signer field")
        self.assertEqual(shown[3][0], "Inner signer")
        self.assertEqual([s[0] for s in self._first_pages()].count(
            "UNLIMITED approval"), 1)

    def test_declining_an_inner_unlimited_approve_signs_nothing(self):
        self.requires_release_capability("erc20-unlimited-approve-review")
        arguments, catalog = self._exec_approve(self.MAX)
        outer, outer_def = self._exec_outer

        def preload():
            erc7730.preload(self.client, outer_def)
            self._drop_setup_screenshots()
            return b""
        self._declined(outer, arguments, "UNLIMITED approval",
                       preload=preload, catalog=catalog)
        self.assertNotIn("Inner signer", [s[0] for s in self.screens])

    def test_inner_finite_approve_shows_no_unlimited_warning(self):
        # 2^255 - 1: finite under every firmware's threshold.
        arguments, catalog = self._exec_approve((1 << 255) - 1)
        self._exec_certified(arguments, catalog)
        titles = [s[0] for s in self.screens]
        self.assertNotIn("UNLIMITED approval", titles)
        self.assertIn("Inner action", titles)

    def test_inner_approve_uses_the_top_level_threshold(self):
        # 7.17: an embedded approve of 2^255 or more is UNLIMITED, as a
        # top-level one is (7.16 warned only at 2^256 - 1).
        self.requires_firmware("7.17.0")
        arguments, catalog = self._exec_approve(1 << 255)
        self._exec_certified(arguments, catalog)
        shown = self._approve_screens()
        self.assertEqual(shown[:2], [
            ("Contract action", "sign multisig operation"), self.UNLIMITED])
        self.assertEqual([s[0] for s in self._first_pages()].count(
            "UNLIMITED approval"), 1)

    def test_blind_inner_unlimited_approve_still_warns_in_715(self):
        self.requires_firmware_below("7.16.0")  # 7.16 refuses blind calls
        self.requires_release_capability("erc20-unlimited-approve-review")
        arguments, catalog = self._exec_approve(self.MAX,
                                                with_definition=False)
        self._exec_certified(arguments, catalog)
        shown = self._approve_screens()
        self.assertEqual(shown[:3], [
            ("Contract action", "sign multisig operation"), self.UNLIMITED,
            ("Blind signature", "The inner call is not clear-signed")])

    def test_inner_approve_with_a_dirty_spender_word_is_refused(self):
        self.requires_release_capability("erc20-unlimited-approve-review")
        arguments, catalog = self._exec_approve(
            self.MAX, spender=b"\x01" + bytes(11) + OTHER_ADDRESS)
        outer, outer_def = self._exec_outer
        erc7730.preload(self.client, outer_def)
        self._drop_setup_screenshots()
        result, _, _, _ = self._walk(
            self._audit_start(outer, 4 + len(arguments)), b"",
            arguments=arguments, catalog=catalog)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "Invalid ERC-7730 embedded call")
        self.assertNotIn("UNLIMITED approval", [s[0] for s in self.screens])
        self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)

    # 7.17: a definition for approve() or increaseAllowance() itself. The
    # host sends only the selector; the first calldata pass reads both words
    # and the top-level allowance policy runs on them before any screen.
    INCREASE = "increaseAllowance(address spender,uint256 addedValue)"

    def _allowance(self, signature, amount, spender=None):
        """Program and arguments for `signature` granting OTHER_ADDRESS
        `amount` of USDC."""
        self.requires_firmware("7.17.0")
        program = erc7730_compiler.compile_calldata(
            {"display": {"formats": {signature: {
                "intent": "Allow spending", "fields": [
                    {"path": signature.split(",")[0].split(" ")[1],
                     "label": "Spender", "format": "addressName"},
                    {"path": signature.split(" ")[-1][:-1],
                     "label": "Amount", "format": "raw"}]}}}},
            signature, 1, self.USDC)
        arguments = (spender or self._word(OTHER_ADDRESS)) + self._word(amount)
        return program, arguments

    def _allowance_start(self, data):
        return eth.EthereumSignTx(
            address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=self.USDC, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=data)

    def _allowance_signed(self, program, arguments):
        """Certified approve: same signature as the ordinary path, which needs
        all 68 bytes in its first chunk."""
        baseline, _, _, _ = self._walk(
            self._allowance_start(program[38:42] + arguments))
        self.assertTrue(baseline.HasField("signature_r"))
        envelope = self._preload(program)
        result, _, passes, _ = self._walk(
            self._allowance_start(program[38:42]), envelope,
            arguments=arguments)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertEqual((result.signature_r, result.signature_s),
                         (baseline.signature_r, baseline.signature_s))
        self.assertGreater(passes, 1)
        return self._first_pages()


    def test_certified_finite_approve_signs_after_its_review(self):
        program, arguments = self._allowance(self.APPROVE, 42)
        shown = self._allowance_signed(program, arguments)
        self.assertNotIn("UNLIMITED approval", [s[0] for s in shown])
        fields = [s for s in shown
                  if s[0] in ("Contract action", "Signer field")]
        self.assertEqual(fields, [
            ("Contract action", "Allow spending"),
            ("Signer field", "Spender:\n0x" + OTHER_ADDRESS.hex()),
            ("Signer field", "Amount:\n42")])

    def test_certified_unlimited_approve_warns_before_any_screen(self):
        # 2^255 and up is UNLIMITED, for approve() and increaseAllowance().
        for signature in (self.APPROVE, self.INCREASE):
            for amount in (self.MAX, 1 << 255):
                program, arguments = self._allowance(signature, amount)
                shown = self._allowance_signed(program, arguments)
                self.assertEqual((signature, amount, shown[0]),
                                 (signature, amount, self.UNLIMITED))
                self.assertEqual(
                    [s[0] for s in shown].count("UNLIMITED approval"), 1)
                self.assertIn(("Contract action", "Allow spending"), shown)

    def test_declining_a_certified_unlimited_approve_signs_nothing(self):
        program, arguments = self._allowance(self.APPROVE, self.MAX)
        envelope = self._preload(program)
        result, _, _, _ = self._walk(
            self._allowance_start(program[38:42]), envelope,
            arguments=arguments, cancel_title="UNLIMITED approval")
        assert_failure(self, result, types.Failure_ActionCancelled,
                       "Signing cancelled by user")
        self.assertEqual([s[0] for s in self.screens], ["UNLIMITED approval"])

    def test_certified_approve_with_a_dirty_spender_word_is_refused(self):
        # Refused before any screen: the address word does not decode (and
        # the allowance policy refuses a dirty spender word in any case).
        program, arguments = self._allowance(
            self.APPROVE, self.MAX, spender=b"\x01" + bytes(11) + OTHER_ADDRESS)
        envelope = self._preload(program)
        result, buttons, _, _ = self._walk(
            self._allowance_start(program[38:42]), envelope,
            arguments=arguments)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 calldata does not match definition")
        self.assertEqual(buttons, 0)

    def test_certified_approve_words_swapped_in_a_later_pass_are_refused(self):
        # The allowance facts come from the first pass; every later pass,
        # the signing pass included, must match the digest it fixed. An
        # unlimited amount or a dirty spender word slipped into any of them
        # is refused, with no UNLIMITED warning and no signature.
        program, arguments = self._allowance(self.APPROVE, 42)
        start = self._allowance_start(program[38:42])
        envelope = self._preload(program)
        result, _, passes, _ = self._walk(start, envelope, arguments=arguments)
        self.assertTrue(result.HasField("signature_r"))
        self.assertGreater(passes, 1)
        unlimited = self._word(OTHER_ADDRESS) + self._word(self.MAX)
        dirty = b"\x01" + bytes(11) + OTHER_ADDRESS + self._word(42)
        for swapped in (unlimited, dirty):
            for altered in range(2, passes + 1):
                envelope = self._preload(program)
                result, _, _, _ = self._walk(
                    start, envelope, arguments=arguments,
                    altered=(altered, swapped))
                assert_failure(self, result, types.Failure_SyntaxError,
                               "ERC-7730 calldata does not match definition")
                self.assertNotIn("UNLIMITED approval",
                                 [s[0] for s in self.screens])

    def test_plain_approve_still_needs_its_68_bytes_up_front(self):
        # Without a definition, approve() and increaseAllowance() carry both
        # words in their first chunk, or are refused before any screen; a
        # certified approve signed just before changes nothing.
        for signature in (self.APPROVE, self.INCREASE):
            program, arguments = self._allowance(signature, self.MAX)
            start = self._allowance_start(program[38:42])
            for _ in range(2):
                result, buttons, _, _ = self._walk(start, arguments=arguments)
                assert_failure(self, result, types.Failure_SyntaxError,
                               "Approval requires at least 68 initial bytes")
                self.assertEqual(buttons, 0)
                self._allowance_signed(program, arguments)

    def test_certified_dirty_approve_word_is_malformed(self):
        # A definition whose first argument is no address decodes a dirty
        # spender word; the allowance policy refuses it before any screen.
        self.requires_firmware("7.17.0")
        signature = "approve(uint256 spender,uint256 amount)"
        program = bytearray(erc7730_compiler.compile_calldata(
            {"display": {"formats": {signature: {
                "intent": "Allow spending", "fields": [
                    {"path": "spender", "label": "Spender", "format": "raw"},
                    {"path": "amount", "label": "Amount", "format": "raw"}]}}}},
            signature, 1, self.USDC))
        program[38:42] = bytes.fromhex("095ea7b3")
        program = bytes(program)
        envelope = self._preload(program)
        result, buttons, _, _ = self._walk(
            self._allowance_start(program[38:42]), envelope,
            arguments=b"\x01" + bytes(11) + OTHER_ADDRESS + self._word(42))
        assert_failure(self, result, types.Failure_SyntaxError,
                       "Malformed ERC20 approval")
        self.assertEqual(buttons, 0)

    def test_certified_approve_with_fewer_arguments_reads_the_amount_word(self):
        # A definition declaring approve(address) with trailing data allowed
        # still gets the policy on the real amount word, then shows that word
        # as the extra data.
        self.requires_firmware("7.17.0")
        signature = "approve(address spender)"
        program = bytearray(erc7730_compiler.compile_calldata(
            {"display": {"formats": {signature: {
                "intent": "Allow spending", "fields": [
                    {"path": "spender", "label": "Spender",
                     "format": "addressName"}]}}}},
            signature, 1, self.USDC, trailing_data=True))
        program[38:42] = bytes.fromhex("095ea7b3")
        arguments = self._word(OTHER_ADDRESS) + self._word(self.MAX)
        shown = self._allowance_signed(bytes(program), arguments)
        self.assertEqual(shown[0], self.UNLIMITED)
        self.assertIn(self._extra_data(self._word(self.MAX)), shown)

    NFT_APPROVE = "approve(address to,uint256 tokenId)"

    def _nft_approve(self, fields):
        return erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.NFT_APPROVE: {
                "intent": "Approve NFT", "fields": fields}}}},
            self.NFT_APPROVE, 1, self.USDC)

    def test_runtime_nft_approve_of_a_high_token_id_still_warns_unlimited(self):
        # ERC-721 approve(to, tokenId) shares approve()'s selector. Only a
        # KeepKey-certified definition may say the second word is a token id
        # and so not an UNLIMITED allowance: the device cannot tell an ERC-721
        # contract from an ERC-20 one. This runtime signer's definition is
        # annotation only, so an ENS-style id of 2^255 or more still gets the
        # device's UNLIMITED warning first (the certified exemption is pinned
        # by the firmware unit test Erc7730Workflow.TokenIdExemption...).
        self.requires_firmware("7.17.0")
        operator = {"path": "to", "label": "Operator", "format": "addressName"}
        token = {"path": "tokenId", "label": "Token", "format": "nftName",
                 "params": {"collectionPath": "@.to"}}
        token_id = (1 << 255) + 1001
        arguments = self._word(OTHER_ADDRESS) + self._word(token_id)
        shown = self._allowance_signed(self._nft_approve([operator, token]),
                                       arguments)
        self.assertEqual(shown[0], self.UNLIMITED)
        self.assertEqual(
            [s for s in shown if s[0] in ("Contract action", "Signer field")], [
                ("Contract action", "Approve NFT"),
                ("Signer field", "Operator:\n0x" + OTHER_ADDRESS.hex()),
                ("Signer field", "Token:\nToken ID %d\nCollection\n"
                 "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" % token_id)])
        # Shown any other way as well, the word is still an allowance amount.
        raw = {"path": "tokenId", "label": "Raw", "format": "raw"}
        shown = self._allowance_signed(
            self._nft_approve([operator, token, raw]), arguments)
        self.assertEqual(shown[0], self.UNLIMITED)
        # ...and a dirty operator word is refused as for any approve().
        envelope = self._preload(self._nft_approve([operator, token]))
        result, buttons, _, _ = self._walk(
            self._allowance_start(bytes.fromhex("095ea7b3")), envelope,
            arguments=b"\x01" + bytes(11) + OTHER_ADDRESS +
            self._word(token_id))
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 calldata does not match definition")
        self.assertEqual(buttons, 0)

    def test_inner_call_without_a_definition_is_blind_in_715(self):
        self.requires_firmware_below("7.16.0")  # 7.16 refuses instead
        start, arguments, outer_def, _ = self._exec_setup()
        self._exec_certified(arguments, erc7730.Catalog((outer_def,)))
        shown = [s for s in self._relevant()
                 if s[0] != "Runtime signer"]
        self.assertEqual(shown[1:3], [
            ("Blind signature", "The inner call is not clear-signed"),
            ("Signer field",
             "Transaction:\nTo 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
             "\nFunction 0xa9059cbb\nData 68 bytes\nValue 0 Wei\nAs 0x" +
             ADDRESS.hex()),
        ])

    def test_inner_definition_for_another_call_is_refused(self):
        start, arguments, outer_def, inner_def = self._exec_setup()
        # A host that answers the inner request with a definition for another
        # selector: the device binds it to the signed selector and refuses.
        approve = erc7730_compiler.compile_calldata(
            {"display": {"formats": {"approve(address spender,uint256 amount)": {
                "intent": "Approve", "fields": []}}}},
            "approve(address spender,uint256 amount)", 1, self.USDC)
        wrong = erc7730.Definition(self._envelope(approve), 1, 1, self.USDC,
                                   approve[38:42])

        class Substituting(erc7730.Catalog):
            def chunk(self, request):
                if request.HasField("recursion_depth"):
                    request = copy.deepcopy(request)
                    request.selector_or_type_hash = wrong.selector_or_type_hash
                return erc7730.Catalog.chunk(self, request)

        erc7730.preload(self.client, outer_def)
        result, _, _, _ = self._walk(
            start, arguments=arguments,
            catalog=Substituting((outer_def, inner_def, wrong)))
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 inner definition does not match")
        self.assertNotIn("Inner action", [s[0] for s in self.screens])

    def test_inner_bytes_changed_in_an_inner_pass_are_refused(self):
        start, arguments, outer_def, inner_def = self._exec_setup()
        # Pass 1 validates and fixes the digest; passes 2-4 capture the outer
        # fields up to the inner call. Pass 5 is the inner call's own
        # validation pass: change one byte of its amount there.
        altered = bytearray(arguments)
        altered[-40] ^= 1
        erc7730.preload(self.client, outer_def)
        result, buttons, passes, _ = self._walk(
            start, arguments=arguments, altered=(5, bytes(altered)),
            catalog=erc7730.Catalog((outer_def, inner_def)))
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 calldata does not match definition")
        self.assertEqual(passes, 5)
        self.assertNotIn("Inner field", [s[0] for s in self.screens])

    def test_large_inner_call_is_bound_across_transport_chunks(self):
        # The inner bytes exceed both the capture buffer and one transport
        # reply. A 31-byte reply splits selectors, offsets and ABI words.
        for chunk_size in (1024, 31):
            with self.subTest(chunk_size=chunk_size):
                _, arguments, outer_def, inner_def = self._exec_setup(
                    memo=b"Z" * 1200)
                outer = self._exec_outer[0]
                erc7730.preload(self.client, outer_def)
                self._drop_setup_screenshots()
                start = self._audit_start(outer, 4 + len(arguments))
                reviewed, _, _, _ = self._walk(
                    start, arguments=arguments, chunk_size=chunk_size,
                    catalog=erc7730.Catalog((outer_def, inner_def)))
                self.assertIsInstance(reviewed, eth.EthereumTxRequest)
                self.assertTrue(reviewed.HasField("signature_r"))
                reviewed_chunks = list(self.calldata_chunk_sizes)
                self.assertGreater(len(reviewed_chunks), 1)
                self.assertLessEqual(max(reviewed_chunks), chunk_size)
                if chunk_size == 31:
                    self.assertGreater(len(reviewed_chunks), 40)
                self.assertIn(("Inner field", "Amount:\n1.5 USDC"),
                              self._relevant())
                ordinary, _, _, _ = self._walk(
                    start, arguments=arguments, chunk_size=chunk_size)
                self.assertIsInstance(ordinary, eth.EthereumTxRequest)
                self.assertTrue(ordinary.HasField("signature_r"))
                self.assertGreater(len(self.calldata_chunk_sizes), 1)
                self.assertLessEqual(max(self.calldata_chunk_sizes), chunk_size)
                self.assertEqual(self.definition_requests, 0)
                self.assertEqual(
                    (reviewed.signature_r, reviewed.signature_s,
                     reviewed.signature_v),
                    (ordinary.signature_r, ordinary.signature_s,
                     ordinary.signature_v))
                if chunk_size == 31:
                    # Change an embedded memo byte on the inner validation
                    # pass, after the outer review fixed the signed digest.
                    altered = bytearray(arguments)
                    altered[-40] ^= 1
                    erc7730.preload(self.client, outer_def)
                    self._drop_setup_screenshots()
                    rejected, _, passes, _ = self._walk(
                        start, arguments=arguments, altered=(5, bytes(altered)),
                        chunk_size=chunk_size,
                        catalog=erc7730.Catalog((outer_def, inner_def)))
                    assert_failure(self, rejected, types.Failure_SyntaxError,
                                   "ERC-7730 calldata does not match definition")
                    self.assertEqual(passes, 5)
                    self.assertNotIn("Inner field", [s[0] for s in self.screens])

    def test_outer_bytes_changed_during_inner_review_are_refused(self):
        start, arguments, outer_def, inner_def = self._exec_setup()
        # The operation word belongs to the outer call, outside the inner
        # byte range. Inner validation must still bind the whole transaction.
        altered = bytearray(arguments)
        altered[127] = 1
        erc7730.preload(self.client, outer_def)
        result, _, passes, _ = self._walk(
            start, arguments=arguments, altered=(5, bytes(altered)),
            catalog=erc7730.Catalog((outer_def, inner_def)))
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 calldata does not match definition")
        self.assertEqual(passes, 5)
        self.assertNotIn("Inner field", [s[0] for s in self.screens])

    def test_restoring_outer_definition_rejects_another_valid_definition(self):
        start, arguments, outer_def, inner_def = self._exec_setup()
        replacement = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.EXEC: {
                "intent": "Replacement", "fields": []}}}},
            self.EXEC, 1, ADDRESS)
        wrong = self._definition(replacement, self._envelope(replacement))
        # Establish that this is a valid signed definition for the same call;
        # the failure must come from the frozen outer definition identity.
        erc7730.preload(self.client, wrong)
        erc7730.preload(self.client, outer_def)
        self._drop_setup_screenshots()

        class Substituting(erc7730.Catalog):
            substituted = False

            def chunk(self, request):
                if (request.HasField("definition_id") and
                        not request.HasField("contract_address")):
                    self.substituted = True
                    return eth.EthereumClearSignDefinitionChunk(
                        definition_id=wrong.definition_id, offset=0,
                        total_length=len(wrong.envelope),
                        data=wrong.envelope[:request.length])
                return super().chunk(request)

        catalog = Substituting((outer_def, inner_def))
        result, _, _, _ = self._walk(start, arguments=arguments,
                                      catalog=catalog)
        self.assertTrue(catalog.substituted)
        self.assertIn(("Inner field", "Amount:\n1.5 USDC"), self._relevant())
        assert_failure(self, result, types.Failure_SyntaxError,
                       "Invalid certified ERC-7730 definition")
        self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)

    def test_inner_definition_identity_cannot_change_between_chunks(self):
        start, arguments, outer_def, inner_def = self._exec_setup()
        erc7730.preload(self.client, outer_def)

        class ChangingIdentity(erc7730.Catalog):
            changed = False

            def chunk(self, request):
                response = super().chunk(request)
                if request.HasField("recursion_depth"):
                    if request.offset == 0:
                        response.data = response.data[:31]
                    else:
                        self.changed = True
                        response.definition_id = bytes(32)
                return response

        catalog = ChangingIdentity((outer_def, inner_def))
        result, _, _, _ = self._walk(start, arguments=arguments,
                                      catalog=catalog)
        self.assertTrue(catalog.changed)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "Invalid certified ERC-7730 definition")
        self.assertNotIn("Inner action", [s[0] for s in self.screens])

    def test_cancelled_inner_review_clears_preload_in_the_same_session(self):
        for title in ("Inner signer", "Inner action", "Inner field"):
            with self.subTest(title=title):
                start, arguments, outer_def, inner_def = self._exec_setup()
                erc7730.preload(self.client, outer_def)
                self._drop_setup_screenshots()
                result, _, _, _ = self._walk(
                    start, arguments=arguments, cancel_title=title,
                    catalog=erc7730.Catalog((outer_def, inner_def)))
                assert_failure(self, result, types.Failure_ActionCancelled,
                               "Signing cancelled by user")
                self.assertEqual(self.screens[-1][0], title)
                self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)
                # No Initialize, signer reset or new preload between calls.
                result, _, _, _ = self._walk(start, arguments=arguments)
                self.assertIsInstance(result, eth.EthereumTxRequest)
                self.assertTrue(result.HasField("signature_r"))
                self.assertEqual(self.definition_requests, 0)
                self.assertEqual(self._relevant(), [])

    # ---- Audit remediation: each of these used to fail mid-review, take a
    # fact from the wrong source, or was untested. ----

    def test_only_a_raw_field_shows_a_signer_constant(self):
        # Formatters show values the device decodes. A signer constant
        # formatted as an amount would look decoded, so preload refuses it;
        # as a raw field it is the signer's own field, and shows.
        signature = "act(uint256 a,address b)"
        for constant in (5, 1000):
            descriptor = {"display": {"formats": {signature: {
                "intent": "Act", "fields": [{
                    "value": constant, "label": "Fee", "format": "amount"}]}}}}
            with self.assertRaises(erc7730_compiler.DeviceCannotExecute):
                erc7730_compiler.compile_calldata(
                    descriptor, signature, 1, ADDRESS)
            program = erc7730_compiler.compile_calldata(
                descriptor, signature, 1, ADDRESS, executable_only=False)
            self._load_signer()
            assert_failure(self, self._raw_preload(self._envelope(program)),
                           types.Failure_SyntaxError,
                           "Invalid certified ERC-7730 definition")
        self.assertEqual(
            self._one_field({"value": 1000, "label": "Fee"},
                            self._word(1) + self._word(OTHER_ADDRESS)),
            ["Fee:\n1000"])

    def test_a_wanchain_transaction_is_never_certified(self):
        # tx_type marks a Wanchain transaction, whose value is WAN; the
        # certified review would name it ETH. Refused before any screen.
        signature = "audit(uint256 first,uint256 second)"
        program = erc7730_compiler.compile_calldata(
            {"display": {"formats": {signature: {
                "intent": "Audit action", "fields": [
                    {"path": "first", "label": "First",
                     "format": "amount"}]}}}},
            signature, 1, ADDRESS)
        self._preload(program)
        start = self._audit_start(program)
        start.tx_type = 1
        result, buttons, _, _ = self._walk(start)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 definition does not match transaction")
        self.assertEqual(buttons, 0)

    def test_control_characters_in_a_value_are_escaped(self):
        signature = "note(string text)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Note", "fields": [
                {"path": "text", "label": "Text", "format": "raw"}]}}}}
        text = b"a\nb\tc"
        arguments = (self._word(32) + self._word(len(text)) + text +
                     bytes(-len(text) % 32))
        self.assertEqual(self._field_screens(descriptor, signature, arguments),
                         ["Text:\na\\x0ab\\x09c"])

    def test_a_raw_value_too_long_to_capture_is_shown_blind(self):
        self.requires_firmware_below("7.16.0")  # 7.16 refuses instead
        signature = "blob(bytes data)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Blob", "fields": [
                {"path": "data", "label": "Data", "format": "raw"}]}}}}
        data = bytes(range(200))
        arguments = (self._word(32) + self._word(len(data)) + data +
                     bytes(-len(data) % 32))
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        self._certified(program, arguments)
        self.assertEqual(
            [s for s in self._first_pages()
             if s[0] in ("Blind signature", "Signer field")],
            [("Blind signature", "The value is too long to show"),
             ("Signer field", "Data:\nNot shown: 200 bytes")])

    def test_a_long_typed_data_value_points_to_the_walk_not_blind(self):
        # Typed data: the walk shows every leaf in full, so a raw field too
        # long to capture says where it was shown, with no blind warning.
        data = bytes(range(200))
        doc = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}],
                "Blob": [{"name": "data", "type": "bytes"}]},
            "primaryType": "Blob",
            "domain": {"name": "Audit app", "chainId": 1,
                       "verifyingContract": "0x" + ADDRESS.hex()},
            "message": {"data": "0x" + data.hex()}}
        program = erc7730_compiler.compile_eip712(
            {"display": {"formats": {"Blob(bytes data)": {
                "intent": "Blob", "fields": [
                    {"path": "data", "label": "Data", "format": "raw"}]}}}},
            doc)
        start = eth.EthereumSignTypedData(address_n=PATH, primary_type="Blob",
                                          metamask_v4_compat=True)
        baseline, _, _, _ = self._walk(start, doc=doc)
        self.assertIsInstance(baseline, eth.EthereumTypedDataSignature)
        envelope = self._preload(program)
        result, _, _, _ = self._walk(start, envelope, doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(result.signature, baseline.signature)
        self.assertNotIn("Blind signature", [s[0] for s in self.screens])
        self.assertIn(("Signer field", "Data:\nShown above in full: 200 bytes"),
                      self._first_pages())

    PERMIT = ("Permit(address owner,address spender,uint256 value,"
              "uint256 nonce,uint256 deadline)")

    def test_typed_data_to_is_the_verifying_contract(self):
        # 7.17: in typed data @.to is the domain's verifyingContract, the
        # deployment the definition is bound to, so an ERC-2612 permit names
        # its token by the contract it is signed for.
        self.requires_firmware("7.17.0")
        doc = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}],
                "Permit": [
                    {"name": "owner", "type": "address"},
                    {"name": "spender", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"}]},
            "primaryType": "Permit",
            "domain": {"name": "USD Coin", "version": "2", "chainId": 1,
                       "verifyingContract": "0x" + self.USDC.hex()},
            "message": {"owner": "0x" + ADDRESS.hex(),
                        "spender": "0x" + OTHER_ADDRESS.hex(),
                        "value": 1500000, "nonce": 0,
                        "deadline": 1900000000}}
        program = erc7730_compiler.compile_eip712(
            {"display": {"formats": {self.PERMIT: {
                "intent": "Authorize spending", "fields": [
                    {"path": "spender", "label": "Spender",
                     "format": "addressName"},
                    {"path": "value", "label": "Amount",
                     "format": "tokenAmount",
                     "params": {"tokenPath": "@.to"}},
                    {"path": "@.to", "label": "Token",
                     "format": "addressName"}]}}}},
            doc)
        start = eth.EthereumSignTypedData(
            address_n=PATH, primary_type="Permit", metamask_v4_compat=True)
        baseline, _, _, _ = self._walk(start, doc=doc)
        self.assertIsInstance(baseline, eth.EthereumTypedDataSignature)
        envelope = self._preload(program)
        result, _, _, _ = self._walk(start, envelope, doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(result.signature, baseline.signature)
        self.assertEqual(
            [s for s in self._first_pages() if s[0] == "Signer field"], [
                ("Signer field", "Spender:\n0x" + OTHER_ADDRESS.hex()),
                ("Signer field", "Amount:\n1.5 USDC"),
                ("Signer field", "Token:\n0xA0b86991c6218b36c1d19D4a2e9Eb0cE"
                                 "3606eB48")])

    # 7.17: a definition may allow bytes after the ABI-encoded arguments, as
    # referral and integrator tags (1inch, Morpho vaults) append. The review
    # says they exist; a definition that does not allow them is refused.
    DEPOSIT = "deposit(uint256 assets,address receiver)"

    def _deposit(self, trailing_data):
        return erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.DEPOSIT: {
                "intent": "Deposit", "fields": [
                    {"path": "assets", "label": "Assets", "format": "raw"},
                    {"path": "receiver", "label": "Receiver",
                     "format": "addressName"}]}}}},
            self.DEPOSIT, 1, ADDRESS, trailing_data=trailing_data)

    @staticmethod
    def _extra_data(tag):
        """The device's screen for a suffix: shown in hex up to 128 bytes,
        stated by its length beyond."""
        if len(tag) == 1:
            text = ("1 more byte follows the arguments. The description "
                    "above does not cover it")
        else:
            text = ("%d more bytes follow the arguments. The description "
                    "above does not cover them" % len(tag))
        return ("Extra data", text + (":\n0x" + tag.hex() if len(tag) <= 128
                                      else ". They are too long to show "
                                      "here."))

    def test_allowed_trailing_bytes_are_shown(self):
        self.requires_firmware("7.17.0")
        arguments = self._word(42) + self._word(OTHER_ADDRESS)
        for tag in (b"\x01", bytes.fromhex("0bad1dea"), bytes(range(24)),
                    bytes(32), bytes(range(40)), bytes(range(128)),
                    bytes(range(129)), bytes(range(256)) * 2):
            self._certified(self._deposit(True), arguments + tag)
            shown = [s for s in self._first_pages()
                     if s[0] in ("Signer field", "Extra data")]
            self.assertEqual(shown, [
                ("Signer field", "Assets:\n42"),
                ("Signer field", "Receiver:\n0x" + OTHER_ADDRESS.hex()),
                self._extra_data(tag)])
        # Without a tag there is nothing to say.
        self._certified(self._deposit(True), arguments)
        self.assertNotIn("Extra data", [s[0] for s in self.screens])

    def test_a_suffix_altered_in_any_pass_is_refused(self):
        # The suffix is bound by the reviewed digest like the arguments.
        self.requires_firmware("7.17.0")
        program = self._deposit(True)
        arguments = (self._word(42) + self._word(OTHER_ADDRESS) +
                     bytes.fromhex("0bad1dea"))
        start = self._audit_start(program, 4 + len(arguments))
        envelope = self._preload(program)
        result, _, passes, _ = self._walk(start, envelope, arguments=arguments)
        self.assertTrue(result.HasField("signature_r"))
        self.assertGreater(passes, 1)
        for altered in range(1, passes + 1):
            envelope = self._preload(program)
            result, _, _, _ = self._walk(
                start, envelope, arguments=arguments,
                altered=(altered, arguments[:-4] + bytes.fromhex("deadbeef")))
            assert_failure(self, result, types.Failure_SyntaxError,
                           "ERC-7730 calldata does not match definition")

    def test_trailing_bytes_are_refused_unless_the_definition_allows(self):
        self.requires_firmware("7.17.0")
        program = self._deposit(False)
        # A misaligned tag fails the stream's length check; a whole extra
        # word is no canonical encoding of the arguments.
        for tag, message in (
                (bytes.fromhex("0bad1dea"), "Invalid ERC-7730 execution program"),
                (bytes(range(32)), "ERC-7730 calldata does not match definition")):
            arguments = self._word(42) + self._word(OTHER_ADDRESS) + tag
            envelope = self._preload(program)
            result, buttons, _, _ = self._walk(
                self._audit_start(program, 4 + len(arguments)), envelope,
                arguments=arguments)
            assert_failure(self, result, types.Failure_SyntaxError, message)
            self.assertEqual(buttons, 0)

    def test_an_inner_call_never_carries_trailing_bytes(self):
        # Only the outer call may carry bytes after its arguments: an inner
        # call with any is refused, even when both definitions allow them.
        self.requires_firmware("7.17.0")
        # A misaligned tag leaves the inner definition unusable; a whole
        # extra word is no canonical encoding of the inner arguments.
        for tag, code, message in (
                (bytes.fromhex("0bad1dea"), types.Failure_Other,
                 "Inner call cannot be clear-signed"),
                (bytes(range(32)), types.Failure_SyntaxError,
                 "ERC-7730 calldata does not match definition")):
            start, arguments, outer_def, inner_def = self._exec_setup(
                trailing_data=True, inner_suffix=tag)
            erc7730.preload(self.client, outer_def)
            self._drop_setup_screenshots()
            result, _, _, _ = self._walk(
                start, arguments=arguments,
                catalog=erc7730.Catalog((outer_def, inner_def)))
            assert_failure(self, result, code, message)
            self.assertNotIn("Inner field", [s[0] for s in self.screens])
            self.assertNotIn("Extra data", [s[0] for s in self.screens])
            self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)
        # The same call without the tag clear-signs under those definitions.
        _, arguments, outer_def, inner_def = self._exec_setup(
            trailing_data=True)
        self._exec_certified(arguments, erc7730.Catalog((outer_def, inner_def)))
        self.assertIn(("Inner field", "Amount:\n1.5 USDC"), self._first_pages())

    def test_declining_the_extra_data_screen_signs_nothing(self):
        self.requires_firmware("7.17.0")
        self._declined(self._deposit(True),
                       self._word(42) + self._word(OTHER_ADDRESS) + b"\x01",
                       "Extra data")
        self.assertEqual(self.screens[-1], self._extra_data(b"\x01"))

    def test_multiline_values_split_between_lines(self):
        # A label of 64 non-ASCII bytes escapes to 256 characters, leaving 93
        # per confirmation: the unknown-token body splits into numbered
        # confirmations between lines, so no confirmation ends mid-address.
        label = "é" * 32
        signature = "send(address token,uint256 amount)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Send", "fields": [{
                "path": "amount", "label": label, "format": "tokenAmount",
                "params": {"tokenPath": "token"}}]}}}}
        arguments = self._word(OTHER_ADDRESS) + self._word(10 ** 60)
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        self._certified(program, arguments)
        parts = [body for title, body in self._first_pages()
                 if title.startswith("Signer field")]
        self.assertGreater(len(parts), 1)
        address = "0x" + OTHER_ADDRESS.hex()
        self.assertEqual(sum(1 for body in parts if body.endswith(address)), 1)
        for body in parts:
            self.assertFalse(body.endswith(address[:10]), body)

    def _exec_inner_catalog(self, inner_program, chain=1, signer=None):
        env = (self._envelope(inner_program, chain=chain) if signer is None
               else self._envelope(inner_program, *signer, chain=chain))
        return erc7730.Definition(env, 1, chain, inner_program[18:38],
                                  inner_program[38:42])

    def _refused_inner_catalogs(self):
        """Inner definitions the device refuses: a program it cannot run
        (BAD_PROGRAM), one from an unloaded signer (UNTRUSTED), and an
        untrusted one large enough to be refused on a later chunk."""
        refused = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.TRANSFER: {
                "intent": "Transfer", "fields": [{
                    "path": "to", "label": "Recipient", "format": "raw",
                    "visible": {"ifNotIn": ["0x" + ADDRESS.hex()]}}]}}}},
            self.TRANSFER, 1, self.USDC, executable_only=False)
        from ecdsa import SigningKey, SECP256k1
        unknown = SigningKey.from_string(
            UNKNOWN_SIGNER_KEY, curve=SECP256k1).get_verifying_key().to_string(
                "compressed")
        clear = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.TRANSFER: {
                "intent": "Transfer", "fields": []}}}},
            self.TRANSFER, 1, self.USDC)
        # Large enough to stream in several chunks, so the refusal comes on a
        # later chunk and the fetch position must be reset for the outer.
        large = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.TRANSFER: {
                "intent": "Transfer", "fields": [
                    {"path": "to", "label": "Recipient %02d %s" % (i, "r" * 44),
                     "format": "raw"} for i in range(24)]}}}},
            self.TRANSFER, 1, self.USDC)
        signed_large = self._exec_inner_catalog(
            large, signer=(UNKNOWN_SIGNER_KEY, unknown))
        self.assertGreater(len(signed_large.envelope), 2 * erc7730.MAX_CHUNK)
        return (self._exec_inner_catalog(refused),
                self._exec_inner_catalog(
                    clear, signer=(UNKNOWN_SIGNER_KEY, unknown)),
                signed_large)

    def test_an_inner_definition_the_device_refuses_falls_back_to_blind(self):
        self.requires_firmware_below("7.16.0")  # 7.16 refuses instead
        start, arguments, outer_def, _ = self._exec_setup()
        for inner in self._refused_inner_catalogs():
            self._exec_certified(arguments,
                                 erc7730.Catalog((outer_def, inner)))
            shown = self._relevant()
            self.assertIn(("Blind signature",
                           "The inner call is not clear-signed"), shown)
            self.assertNotIn("Inner action", [s[0] for s in shown])
            self.assertEqual(shown[-1], ("Signer field", "Operation:\n0"))

    def test_an_inner_definition_the_device_refuses_is_refused_from_716(self):
        self.requires_firmware("7.16.0")
        for inner in self._refused_inner_catalogs():
            _, arguments, outer_def, _ = self._exec_setup()
            self._exec_refused(arguments, erc7730.Catalog((outer_def, inner)))
            self.assertNotIn("Inner action", [s[0] for s in self.screens])

    def test_inner_definition_for_another_callee_or_chain_is_refused(self):
        start, arguments, outer_def, inner_def = self._exec_setup()
        other_callee = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.TRANSFER: {
                "intent": "Transfer", "fields": []}}}},
            self.TRANSFER, 1, OTHER_ADDRESS)
        other_chain = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.TRANSFER: {
                "intent": "Transfer", "fields": []}}}},
            self.TRANSFER, 56, self.USDC)
        for wrong in (self._exec_inner_catalog(other_callee),
                      self._exec_inner_catalog(other_chain, chain=56)):
            class Substituting(erc7730.Catalog):
                def chunk(self, request):
                    if request.HasField("recursion_depth") and request.recursion_depth:
                        replaced = copy.deepcopy(request)
                        replaced.chain_id = wrong.chain_id
                        replaced.contract_address = wrong.contract_address
                        return erc7730.Catalog.chunk(self, replaced)
                    return erc7730.Catalog.chunk(self, request)
            erc7730.preload(self.client, outer_def)
            result, _, _, _ = self._walk(
                start, arguments=arguments,
                catalog=Substituting((outer_def, inner_def, wrong)))
            assert_failure(self, result, types.Failure_SyntaxError,
                           "ERC-7730 inner definition does not match")
            self.assertNotIn("Inner action", [s[0] for s in self.screens])

    def test_inner_calls_read_their_own_containers(self):
        # Inside the inner call @.value is the value it moves and @.from
        # whose authority it runs with: the outer spenderPath, or without
        # one the outer contract.
        inner = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.TRANSFER: {
                "intent": "Transfer", "fields": [
                    {"path": "@.value", "label": "Moves", "format": "amount"},
                    {"path": "@.from", "label": "As", "format": "addressName"},
                    {"path": "@.to", "label": "Token", "format": "addressName"},
                ]}}}},
            self.TRANSFER, 1, self.USDC)
        usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        for spender, authority in ((None, "0x" + ADDRESS.hex()),
                                   ("to", usdc)):
            _, arguments, outer_def, _ = self._exec_setup(spender=spender)
            # Give the outer call a value: the inner call moves 2 ETH.
            moving = bytearray(arguments)
            moving[32:64] = self._word(2 * 10 ** 18)
            self._exec_certified(bytes(moving), erc7730.Catalog(
                (outer_def, self._exec_inner_catalog(inner))))
            inner_fields = [s[1] for s in self._relevant()
                            if s[0] == "Inner field"]
            self.assertEqual(inner_fields, [
                "Moves:\n2 ETH", "As:\n" + authority, "Token:\n" + usdc])

    def test_embedded_calls_inside_an_iteration_are_shown_blind(self):
        self.requires_firmware_below("7.16.0")  # 7.16 refuses instead
        signature = "multicall((address callee,bytes data)[] calls)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Multicall", "fields": [{
                "path": "calls.[].data", "label": "Call", "format": "calldata",
                "params": {"calleePath": "calls.[].callee"}}]}}}}
        call = bytes.fromhex("a9059cbb") + self._word(OTHER_ADDRESS) + self._word(1)
        padded = call + bytes(-len(call) % 32)
        element = (self._word(OTHER_ADDRESS) + self._word(64) +
                   self._word(len(call)) + padded)
        arguments = (self._word(32) + self._word(2) + self._word(64) +
                     self._word(64 + len(element)) + element + element)
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        self._certified(program, arguments)
        shown = [s for s in self._first_pages()
                 if s[0] == "Blind signature" or s[0].startswith("Signer field")]
        body = ("Call:\nTo 0x" + OTHER_ADDRESS.hex() +
                "\nFunction 0xa9059cbb\nData 68 bytes")
        self.assertEqual(shown, [
            ("Blind signature", "The inner call is not clear-signed"),
            ("Signer field 1 of 2", body),
            ("Blind signature", "The inner call is not clear-signed"),
            ("Signer field 2 of 2", body),
        ])

    def test_a_fixed_index_into_a_short_array_fails_closed(self):
        # Data-dependent: preload cannot know the array's length. The device
        # refuses without a signature when it reaches the field.
        signature = "swap(address[] path,uint256 amount)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Swap", "fields": [{
                "path": "amount", "label": "Amount", "format": "tokenAmount",
                "params": {"tokenPath": "path.[0]"}}]}}}}
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        arguments = self._word(64) + self._word(5) + self._word(0)
        envelope = self._preload(program)
        result, _, _, _ = self._walk(
            self._audit_start(program, 4 + len(arguments)), envelope,
            arguments=arguments)
        self.assertIsInstance(result, proto.Failure)
        self.assertEqual(result.message,
                         "ERC-7730 calldata does not match definition")
        self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)

    def test_an_inner_value_the_calldata_does_not_carry_is_never_shown(self):
        # Without amountPath the calldata does not say what the inner call
        # moves: an inner definition that shows @.value is shown blind, while
        # one that does not is still clear-signed. (7.16 refuses the former.)
        # Read the version first: it re-initialises the device, which would
        # drop the signer the setup below loads.
        refuses = self.firmware_version() >= semver.VersionInfo.parse("7.16.0")
        _, arguments, outer_def, inner_def = self._exec_setup(amount_path=False)
        self._exec_certified(arguments, erc7730.Catalog((outer_def, inner_def)))
        self.assertIn("Inner field", [s[0] for s in self._relevant()])
        _, arguments, outer_def, _ = self._exec_setup(amount_path=False)
        shows_value = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.TRANSFER: {
                "intent": "Transfer", "fields": [
                    {"path": "@.value", "label": "Moves", "format": "amount"}]}}}},
            self.TRANSFER, 1, self.USDC)
        catalog = erc7730.Catalog(
            (outer_def, self._exec_inner_catalog(shows_value)))
        if refuses:
            self._exec_refused(arguments, catalog)
            return
        self._exec_certified(arguments, catalog)
        shown = self._relevant()
        self.assertIn(("Blind signature",
                       "The inner call is not clear-signed"), shown)
        self.assertNotIn("Inner field", [s[0] for s in shown])

    def test_parallel_arrays_are_refused_before_preload(self):
        # A token formatter cannot pair amounts[i] with an independent
        # tokens[i] array: the auxiliary token path must read the active array.
        signature = "batch(address[] tokens,uint256[] amounts)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Batch", "fields": [{
                "path": "amounts.[]", "label": "Amount", "format": "tokenAmount",
                "params": {"tokenPath": "tokens.[]"}}]}}}}

        with self.assertRaisesRegex(
                erc7730_compiler.DeviceCannotExecute,
                "a field reads another array than its iteration"):
            erc7730_compiler.compile_calldata(
                descriptor, signature, 1, ADDRESS)

    def test_a_call_at_depth_two_is_shown_blind(self):
        self.requires_firmware_below("7.16.0")  # 7.16 refuses instead
        # A Safe executing a call on a second Safe: the second Safe's
        # definition is clear-signed one level deep, and the transfer it
        # carries is shown blind. The device never fetches a depth-2
        # definition.
        from keepkeylib.signed_metadata import keccak256
        _, _, outer_def, _ = self._exec_setup()
        second_safe = bytes.fromhex("55" * 20)
        middle = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.EXEC: {
                "intent": "sign multisig operation", "fields": [
                    {"path": "data", "label": "Transaction", "format": "calldata",
                     "params": {"calleePath": "to", "amountPath": "value",
                                "spenderPath": "@.to"}},
                    {"path": "operation", "label": "Operation",
                     "format": "raw"}]}}}},
            self.EXEC, 1, second_safe)

        def execute(to, data):
            return (self._word(to) + self._word(0) + self._word(128) +
                    self._word(0) + self._word(len(data)) + data +
                    bytes(-len(data) % 32))
        selector = keccak256(
            b"execTransaction(address,uint256,bytes,uint8)")[:4]
        transfer = (bytes.fromhex("a9059cbb") + self._word(OTHER_ADDRESS) +
                    self._word(1500000))
        arguments = execute(second_safe,
                            selector + execute(self.USDC, transfer))
        depths = []

        class Recording(erc7730.Catalog):
            def chunk(self, request):
                depths.append(request.recursion_depth)
                return erc7730.Catalog.chunk(self, request)
        self._exec_certified(arguments, Recording(
            (outer_def, self._exec_inner_catalog(middle))))
        self.assertEqual(max(depths), 1)
        shown = [s for s in self._relevant()
                 if s[0] not in ("Runtime signer", "Inner signer")]
        self.assertEqual([s[0] for s in shown], [
            "Contract action", "Signer field", "Inner action",
            "Blind signature", "Inner field", "Inner field", "Signer field"])
        self.assertEqual(shown[3][1], "The inner call is not clear-signed")
        self.assertTrue(shown[4][1].startswith(
            "Transaction:\nTo 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            "\nFunction 0xa9059cbb\nData 68 bytes"), shown[4][1])
        self.assertEqual(shown[5][1], "Operation:\n0")
        self.assertEqual(shown[6][1], "Operation:\n0")


    def _refused(self, program, arguments, message, preload=None,
                 catalog=None):
        """7.16+: what 7.15 showed under a blind-sign warning is refused,
        with no warning screen and no signature, while the same transaction
        still signs on the ordinary path."""
        start = self._audit_start(program, 4 + len(arguments))
        # The same transaction still signs on the ordinary path: the refusal
        # is the definition's, not the transaction's.
        baseline, _, _, _ = self._walk(start, arguments=arguments)
        self.assertTrue(baseline.HasField("signature_r"))
        envelope = self._preload(program) if preload is None else preload()
        result, _, _, _ = self._walk(start, envelope, arguments=arguments,
                                     catalog=catalog)
        assert_failure(self, result, types.Failure_Other, message)
        self.assertNotIn("Blind signature", [s[0] for s in self.screens])
        self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)

    def _exec_refused(self, arguments, catalog):
        outer, outer_def = self._exec_outer

        def preload():
            erc7730.preload(self.client, outer_def)
            self._drop_setup_screenshots()
            return b""
        self._refused(outer, arguments, "Inner call cannot be clear-signed",
                      preload=preload, catalog=catalog)

    def test_inner_call_without_a_definition_is_refused_from_716(self):
        self.requires_firmware("7.16.0")
        _, arguments, outer_def, _ = self._exec_setup()
        self._exec_refused(arguments, erc7730.Catalog((outer_def,)))

    # 7.17: a Safe exec whose operation is not 0 (CALL) delegatecalls its
    # inner call: the callee's code runs as the Safe, so the callee's own
    # definition does not describe it. The device reads the operation from
    # the signed calldata and says so right after the intent, whatever the
    # definition shows. An embedded call is then refused: it never fetches or
    # shows the inner definition.
    SAFE_EXEC = ("execTransaction(address to,uint256 value,bytes data,"
                 "uint8 operation,uint256 safeTxGas,uint256 baseGas,"
                 "uint256 gasPrice,address gasToken,address refundReceiver,"
                 "bytes signatures)")
    SAFE_MODULE_EXEC = ("execTransactionFromModule(address to,uint256 value,"
                        "bytes data,uint8 operation)")
    SAFE_MODULE_EXEC_DATA = ("execTransactionFromModuleReturnData(address to,"
                             "uint256 value,bytes data,uint8 operation)")
    # Zodiac Roles: sent by an EOA, executed by the Safe with `operation`.
    ROLES_EXEC = ("execTransactionWithRole(address to,uint256 value,"
                  "bytes data,uint8 operation,bytes32 roleKey,"
                  "bool shouldRevert)")
    DELEGATECALL = ("DELEGATECALL",
                    "Runs the contract in 'to' as the Safe, with its full "
                    "authority. Not checked.")
    SAFE_EMBEDDED_FIELDS = [
        {"path": "data", "label": "Transaction", "format": "calldata",
         "params": {"calleePath": "to", "amountPath": "value",
                    "spenderPath": "@.to"}},
        {"path": "operation", "label": "Operation", "format": "raw"}]

    def _safe_exec(self, signature, operation, fields=None):
        """A real Safe exec of USDC transfer(OTHER_ADDRESS, 1.5 USDC): its
        arguments and the outer and inner definitions."""
        inner_def = self._exec_setup()[3]  # also loads the signer
        outer = erc7730_compiler.compile_calldata(
            {"display": {"formats": {signature: {
                "intent": "sign multisig operation",
                "fields": fields or self.SAFE_EMBEDDED_FIELDS}}}},
            signature, 1, ADDRESS)
        outer_def = self._definition(outer, self._envelope(outer))
        self._exec_outer = (outer, outer_def)
        call = (bytes.fromhex("a9059cbb") + self._word(OTHER_ADDRESS) +
                self._word(1500000))
        tail = self._word(len(call)) + call + bytes(-len(call) % 32)
        if signature != self.SAFE_EXEC:
            extra = (self._word(7) + self._word(0)
                     if signature == self.ROLES_EXEC else b"")
            head = (self._word(self.USDC) + self._word(0) +
                    self._word(128 + len(extra)) + self._word(operation) +
                    extra)
            return head + tail, outer_def, inner_def
        signatures = bytes(65)
        head = (self._word(self.USDC) + self._word(0) + self._word(320) +
                self._word(operation) + self._word(150000) + self._word(0) +
                self._word(0) + self._word(bytes(20)) + self._word(bytes(20)) +
                self._word(320 + len(tail)))
        return (head + tail + self._word(len(signatures)) + signatures +
                bytes(-len(signatures) % 32)), outer_def, inner_def

    def _after_intent(self, pages):
        """The pages after the outer intent, which must come first."""
        titles = [page[0] for page in pages]
        return pages[titles.index("Contract action") + 1:]

    def test_safe_delegatecall_is_named_and_refused(self):
        self.requires_firmware("7.17.0")
        for signature in (self.SAFE_EXEC, self.SAFE_MODULE_EXEC,
                          self.SAFE_MODULE_EXEC_DATA, self.ROLES_EXEC):
            for operation in (1, 2):
                arguments, outer_def, inner_def = self._safe_exec(
                    signature, operation)
                depths = []

                class Recording(erc7730.Catalog):
                    def chunk(self, request):
                        depths.append(request.recursion_depth)
                        return erc7730.Catalog.chunk(self, request)
                outer = self._exec_outer[0]

                def preload():
                    erc7730.preload(self.client, outer_def)
                    self._drop_setup_screenshots()
                    return b""
                self._refused(outer, arguments,
                              "DELEGATECALL cannot be clear-signed",
                              preload=preload,
                              catalog=Recording((outer_def, inner_def)))
                titles = [s[0] for s in self.screens]
                self.assertEqual(self._after_intent(self._first_pages()),
                                 [self.DELEGATECALL])
                self.assertNotIn("Inner action", titles)
                self.assertNotIn("Inner signer", titles)
                self.assertNotIn("Inner field", titles)
                self.assertEqual(max(depths), 0)

    def test_safe_delegatecall_is_named_when_no_field_embeds_it(self):
        # A definition that shows `data` raw, or not at all, still gets the
        # DELEGATECALL screen before its fields, then signs.
        self.requires_firmware("7.17.0")
        fields = [{"path": "to", "label": "To", "format": "raw"},
                  {"path": "data", "label": "Data", "format": "raw"}]
        for signature in (self.SAFE_MODULE_EXEC, self.ROLES_EXEC):
            for operation in (1, 0):
                arguments, outer_def, _ = self._safe_exec(
                    signature, operation, fields)
                self._exec_certified(arguments, erc7730.Catalog((outer_def,)))
                shown = [page[0] for page in
                         self._after_intent(self._first_pages())
                         if page[0] not in ORDINARY_REVIEW]
                self.assertEqual(shown, (["DELEGATECALL"] if operation else []) +
                                 ["Signer field", "Signer field"])
                if operation:
                    self.assertEqual(
                        self._after_intent(self._first_pages())[0],
                        self.DELEGATECALL)

    def test_declining_the_delegatecall_screen_cancels(self):
        self.requires_firmware("7.17.0")
        for fields in (None, [{"path": "to", "label": "To", "format": "raw"}]):
            arguments, outer_def, inner_def = self._safe_exec(
                self.SAFE_MODULE_EXEC, 1, fields)
            outer = self._exec_outer[0]
            erc7730.preload(self.client, outer_def)
            self._drop_setup_screenshots()
            start = self._audit_start(outer, 4 + len(arguments))
            result, _, _, _ = self._walk(
                start, b"", arguments=arguments, cancel_title="DELEGATECALL",
                catalog=erc7730.Catalog((outer_def, inner_def)))
            assert_failure(self, result, types.Failure_ActionCancelled,
                           "Signing cancelled by user")
            self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)

    def test_safe_call_is_still_clear_signed(self):
        self.requires_firmware("7.17.0")
        for signature in (self.SAFE_EXEC, self.SAFE_MODULE_EXEC,
                          self.ROLES_EXEC):
            arguments, outer_def, inner_def = self._safe_exec(signature, 0)
            self._exec_certified(arguments,
                                 erc7730.Catalog((outer_def, inner_def)))
            shown = [s for s in self._relevant()
                     if s[0] not in ("Runtime signer", "Inner signer")]
            self.assertEqual([s[0] for s in shown], [
                "Contract action", "Signer field", "Inner action",
                "Inner field", "Inner field", "Signer field"])
            self.assertEqual(shown[2], ("Inner action", "Transfer"))
            self.assertEqual(shown[-1], ("Signer field", "Operation:\n0"))
            self.assertNotIn("DELEGATECALL", [s[0] for s in self.screens])

    def test_a_raw_value_too_long_to_capture_is_refused_from_716(self):
        self.requires_firmware("7.16.0")
        signature = "blob(bytes data)"
        program = erc7730_compiler.compile_calldata(
            {"display": {"formats": {signature: {"intent": "Blob", "fields": [
                {"path": "data", "label": "Data", "format": "raw"}]}}}},
            signature, 1, ADDRESS)
        data = bytes(range(200))
        self._refused(program, self._word(32) + self._word(len(data)) + data +
                      bytes(-len(data) % 32), "Value too long to clear-sign")

    def _declined(self, program, arguments, title, preload=None,
                  catalog=None):
        envelope = self._preload(program) if preload is None else preload()
        result, _, _, _ = self._walk(
            self._audit_start(program, 4 + len(arguments)), envelope,
            arguments=arguments, catalog=catalog, cancel_title=title)
        assert_failure(self, result, types.Failure_ActionCancelled,
                       "Signing cancelled by user")
        self.assertEqual(self.screens[-1][0], title)
        self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)

    def test_declining_any_certified_screen_returns_no_signature(self):
        # Every certified screen is a consent: the blind-sign warnings, a
        # later part of a split value and an inner field each abort when
        # declined, with no signature.
        signature = "blob(bytes data)"
        blob = erc7730_compiler.compile_calldata(
            {"display": {"formats": {signature: {"intent": "Blob", "fields": [
                {"path": "data", "label": "Data", "format": "raw"}]}}}},
            signature, 1, ADDRESS)
        data = bytes(range(200))
        blind = self.firmware_version() < semver.VersionInfo.parse("7.16.0")
        if blind:  # 7.16 refuses these instead: no warning to decline
            self._declined(blob, self._word(32) + self._word(len(data)) +
                           data + bytes(-len(data) % 32), "Blind signature")

        signature = "send(address token,uint256 amount)"
        split = erc7730_compiler.compile_calldata(
            {"display": {"formats": {signature: {"intent": "Send", "fields": [{
                "path": "amount", "label": "\u00e9" * 32,
                "format": "tokenAmount",
                "params": {"tokenPath": "token"}}]}}}},
            signature, 1, ADDRESS)
        self._declined(split, self._word(OTHER_ADDRESS) + self._word(10 ** 60),
                       "Signer field (2/2)")

        _, arguments, outer_def, inner_def = self._exec_setup()
        outer = self._exec_outer[0]

        def preload():
            erc7730.preload(self.client, outer_def)
            self._drop_setup_screenshots()
            return b""
        # No inner definition: the E1 warning.
        if blind:
            self._declined(outer, arguments, "Blind signature",
                           preload=preload,
                           catalog=erc7730.Catalog((outer_def,)))
        # A refused inner definition: the warning on the blind re-run.
        refused = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.TRANSFER: {
                "intent": "Transfer", "fields": [{
                    "path": "to", "label": "Recipient", "format": "raw",
                    "visible": {"ifNotIn": ["0x" + ADDRESS.hex()]}}]}}}},
            self.TRANSFER, 1, self.USDC, executable_only=False)
        if blind:
            self._declined(outer, arguments, "Blind signature",
                           preload=preload,
                           catalog=erc7730.Catalog(
                               (outer_def, self._exec_inner_catalog(refused))))
        # A clear-signed inner call: its field.
        self._declined(outer, arguments, "Inner field", preload=preload,
                       catalog=erc7730.Catalog((outer_def, inner_def)))


    def test_a_refused_inner_call_does_not_blind_the_next_one(self):
        self.requires_firmware_below("7.16.0")  # 7.16 refuses instead
        # Two embedded calls: the first inner definition is refused and shown
        # blind; the second is still clear-signed with its own definition.
        signature = "execTwo(address a,bytes da,address b,bytes db)"
        other_token = bytes.fromhex("55" * 20)
        outer = erc7730_compiler.compile_calldata(
            {"display": {"formats": {signature: {
                "intent": "Run two calls", "fields": [
                    {"path": "da", "label": "First", "format": "calldata",
                     "params": {"calleePath": "a"}},
                    {"path": "db", "label": "Second", "format": "calldata",
                     "params": {"calleePath": "b"}}]}}}},
            signature, 1, ADDRESS)
        refused = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.TRANSFER: {
                "intent": "Transfer", "fields": [{
                    "path": "to", "label": "Recipient", "format": "raw",
                    "visible": {"ifNotIn": ["0x" + ADDRESS.hex()]}}]}}}},
            self.TRANSFER, 1, self.USDC, executable_only=False)
        second = erc7730_compiler.compile_calldata(
            {"display": {"formats": {self.TRANSFER: {
                "intent": "Transfer", "fields": [
                    {"path": "to", "label": "Recipient",
                     "format": "addressName"}]}}}},
            self.TRANSFER, 1, other_token)
        call = (bytes.fromhex("a9059cbb") + self._word(OTHER_ADDRESS) +
                self._word(1500000))
        padded = self._word(len(call)) + call + bytes(-len(call) % 32)
        arguments = (self._word(self.USDC) + self._word(128) +
                     self._word(other_token) + self._word(128 + len(padded)) +
                     padded + padded)
        self._load_signer()
        outer_def = self._definition(outer, self._envelope(outer))

        def preload():
            erc7730.preload(self.client, outer_def)
            self._drop_setup_screenshots()
            return b""
        self._certified(outer, arguments, preload=preload,
                        catalog=erc7730.Catalog((
                            outer_def, self._exec_inner_catalog(refused),
                            self._exec_inner_catalog(second))))
        titles = [s[0] for s in self._relevant()
                  if s[0] not in ("Runtime signer", "Inner signer")]
        self.assertEqual(titles, [
            "Contract action", "Blind signature", "Signer field",
            "Signer field", "Inner action", "Inner field"])
        self.assertEqual(self._relevant()[-1],
                         ("Inner field", "Recipient:\n0x" + OTHER_ADDRESS.hex()))

    def test_groups_and_optional_fields_are_always_visible(self):
        signature = "pay(address recipient,uint256 amount,uint256 fee)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Pay", "fields": [
                {"label": "Payment", "visible": "optional", "fields": [
                    {"path": "recipient", "label": "Recipient",
                     "format": "addressName"},
                    {"label": "Details", "fields": [
                        {"path": "amount", "label": "Amount", "format": "raw",
                         "visible": "optional"}]}]},
                {"path": "fee", "label": "Fee", "format": "raw",
                 "visible": "optional"}]}}}}
        for amount, fee in ((0, 0), (5, 9)):
            self.assertEqual(
                self._field_screens(descriptor, signature,
                    self._word(OTHER_ADDRESS) + self._word(amount) + self._word(fee)),
                ["Recipient:\n0x" + OTHER_ADDRESS.hex(),
                 "Amount:\n" + str(amount), "Fee:\n" + str(fee)])

    # 7.17 (D-020): embedded calls nested two levels below the transaction
    # and inside iterations, an embedded call with no data, and the RECIPIENT
    # and TX_VALUE constraints, over real calldata. Each signs the same
    # transaction on the ordinary path first and requires the same signature.
    # The arguments of mainnet tx 0x27ee4abbee000e5c7d26d11ea41d826756e57540
    # 977ec423c900e34bd13f480c: SwapRouter02 multicall(deadline,
    # [exactInput, unwrapWETH9]).
    ROUTER02_MULTICALL_ARGS = bytes.fromhex(
        "000000000000000000000000000000000000000000000000000000006ae3d83c"
        "0000000000000000000000000000000000000000000000000000000000000040"
        "0000000000000000000000000000000000000000000000000000000000000002"
        "0000000000000000000000000000000000000000000000000000000000000040"
        "00000000000000000000000000000000000000000000000000000000000001a0"
        "0000000000000000000000000000000000000000000000000000000000000124"
        "b858183f00000000000000000000000000000000000000000000000000000000"
        "0000002000000000000000000000000000000000000000000000000000000000"
        "0000008000000000000000000000000000000000000000000000000000000000"
        "000000020000000000000000000000000000000000000000000001e90a8d027c"
        "9ee99999000000000000000000000000000000000000000000000000340c6aa0"
        "af5469e800000000000000000000000000000000000000000000000000000000"
        "000000424c9edd5852cd905f086c759e8383e09bff1e68b3000064a0b86991c6"
        "218b36c1d19d4a2e9eb0ce3606eb480001f4c02aaa39b223fe8d0a0e5c4f27ea"
        "d9083c756cc20000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000044"
        "49404b7c000000000000000000000000000000000000000000000000340c6aa0"
        "af5469e8000000000000000000000000b3ddec0ccc5c3ba733fcdf5a15f98c95"
        "ec5a5fdb00000000000000000000000000000000000000000000000000000000")
    # Mainnet tx 0x8f5df072258c8b3a1dbeb89d61df6e6be3a997a3f2b167614ad03a416
    # cf9400f: SafeProxyFactory 1.4.1 createProxyWithNonce of a 1-of-2 Safe.
    SAFE_CREATE_ARGS = bytes.fromhex(
        "00000000000000000000000029fcb43b46531bca003ddc8fcb67ffe91900c762"
        "0000000000000000000000000000000000000000000000000000000000000060"
        "87818588a63dc1031b9d46b1ba35b204eff451a125dd8cc312e8f32f956a1736"
        "0000000000000000000000000000000000000000000000000000000000000184"
        "b63e800d00000000000000000000000000000000000000000000000000000000"
        "0000010000000000000000000000000000000000000000000000000000000000"
        "0000000100000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000160000000000000000000000000fd0732dc9e303f09fcef3a7388ad10a8"
        "3459ec9900000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000002000000000000000000000000e4f420a0786451a10bf2fd4702e9b766"
        "32c081090000000000000000000000003ef438c34ce51a697a24247fe033c456"
        "2c94f0fd00000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000")
    # Mainnet tx 0x08c3fb8c366cb80588b334e3c43bf4240dc7243160b96dff4d7b7f03c
    # f8ff720: Safe{Wallet}'s 1.4.1 creation, whose setup() module call
    # DELEGATECALLs SafeToL2Setup.setupToL2.
    SAFE_CREATE_L2_SETUP_ARGS = bytes.fromhex(
        "00000000000000000000000041675c099f32341bf84bfc5382af534df5c7461a"
        "0000000000000000000000000000000000000000000000000000000000000060"
        "0000000000000000000000000000000000000000000000000000000000000004"
        "0000000000000000000000000000000000000000000000000000000000000204"
        "b63e800d00000000000000000000000000000000000000000000000000000000"
        "0000010000000000000000000000000000000000000000000000000000000000"
        "00000002000000000000000000000000bd89a1ce4dde368ffab0ec35506eece0"
        "b1ffdc5400000000000000000000000000000000000000000000000000000000"
        "000001a0000000000000000000000000fd0732dc9e303f09fcef3a7388ad10a8"
        "3459ec9900000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000005afe7a11e70000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000004000000000000000000000000bf0bdf3801794d81a0253ec56f5be14b"
        "d9e15fc6000000000000000000000000575b921289484c6db476cbc4ce49db30"
        "572c3260000000000000000000000000bea6c4bc16257d416e5b5fcc49f35505"
        "9cb52d5800000000000000000000000059f5fad60115845b3030774da2584d35"
        "0bec5b0300000000000000000000000000000000000000000000000000000000"
        "00000024fe51f64300000000000000000000000029fcb43b46531bca003ddc8f"
        "cb67ffe91900c762000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000")
    SAFE_141 = bytes.fromhex("41675c099f32341bf84bfc5382af534df5c7461a")
    SAFE_TO_L2_SETUP = bytes.fromhex("bd89a1ce4dde368ffab0ec35506eece0b1ffdc54")
    # The swaps.pro request of 2026-10-29: CoW EthFlow createOrder selling
    # 10 ETH for USDC.
    COW_ORDER_ARGS = bytes.fromhex(
        "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        "0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda94"
        "0000000000000000000000000000000000000000000000008ac7230489e80000"
        "000000000000000000000000000000000000000000000000000000055f39e075"
        "048680e79dfa12d06c2362b19faa34b7c754a3ed153d204656c48f82e84d4e60"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000006ae3c1e0"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000009f9f3f72")
    ROUTER02 = bytes.fromhex("68b3465833fb72a70ecdf485e0e4c7bd8665fc45")
    SAFE_L2 = bytes.fromhex("29fcb43b46531bca003ddc8fcb67ffe91900c762")
    MULTICALL = "multicall(uint256 deadline,bytes[] data)"
    EXACT_INPUT = ("exactInput((bytes path,address recipient,uint256 amountIn,"
                   "uint256 amountOutMinimum) params)")
    UNWRAP = "unwrapWETH9(uint256 amountMinimum,address recipient)"
    CREATE_PROXY = ("createProxyWithNonce(address _singleton,bytes initializer,"
                    "uint256 saltNonce)")
    SETUP = ("setup(address[] _owners,uint256 _threshold,address to,bytes data,"
             "address fallbackHandler,address paymentToken,uint256 payment,"
             "address paymentReceiver)")
    CREATE_ORDER = ("createOrder((address buyToken,address receiver,"
                    "uint256 sellAmount,uint256 buyAmount,bytes32 appData,"
                    "uint256 feeAmount,uint32 validTo,bool partiallyFillable,"
                    "int64 quoteId) order)")

    def _program(self, signature, intent, fields, address=ADDRESS):
        return erc7730_compiler.compile_calldata(
            {"display": {"formats": {signature: {
                "intent": intent, "fields": fields}}}},
            signature, 1, address)

    def _router02(self, address):
        """The multicall and its two steps, all at `address`."""
        outer = self._program(self.MULTICALL, "Swap", [
            {"path": "deadline", "label": "Deadline", "format": "date",
             "params": {"encoding": "timestamp"}},
            {"path": "data.[]", "label": "Step", "format": "calldata",
             "params": {"calleePath": "@.to", "amountPath": "@.value",
                        "spenderPath": "@.from"}}], address)
        steps = [self._program(self.EXACT_INPUT, "Swap exact input", [
            {"path": "params.recipient", "label": "Recipient",
             "format": "addressName"},
            {"path": "params.amountOutMinimum", "label": "Minimum out",
             "format": "raw"}], address),
                 self._program(self.UNWRAP, "Unwrap WETH", [
            {"path": "amountMinimum", "label": "Minimum", "format": "amount"},
            {"path": "recipient", "label": "Recipient",
             "format": "addressName", "params": {"recipient": True}}],
                     address)]
        return outer, steps

    def _signed_with(self, outer, inner, arguments, value=b""):
        self._load_signer()
        outer_def = self._definition(outer, self._envelope(outer))
        catalog = Recording([outer_def] + [
            self._exec_inner_catalog(program) for program in inner])

        def preload():
            erc7730.preload(self.client, outer_def)
            self._drop_setup_screenshots()
            return b""
        start = self._audit_start(outer, 4 + len(arguments))
        start.value = value
        baseline, _, _, _ = self._walk(start, arguments=arguments)
        self.assertTrue(baseline.HasField("signature_r"))
        preload()
        catalog.depths = []
        result, _, _, _ = self._walk(start, arguments=arguments,
                                     catalog=catalog)
        self.depths = catalog.depths
        return result, baseline

    def _shown(self):
        """The review's own screens, numbered titles included."""
        return [s for s in self._first_pages() if s[0] in (
            "Contract action", "Inner action") or s[0].startswith(
                ("Signer field", "Inner field"))]

    def test_717_every_multicall_step_is_clear_signed(self):
        self.requires_firmware("7.17.0")
        outer, steps = self._router02(ADDRESS)
        result, baseline = self._signed_with(outer, steps,
                                             self.ROUTER02_MULTICALL_ARGS)
        self.assertEqual((result.signature_r, result.signature_s),
                         (baseline.signature_r, baseline.signature_s))
        self.assertEqual(self.depths, [1, 1])
        shown = [s for s in self._shown()
                 if s[0] not in ("Runtime signer", "Inner signer")]
        self.assertEqual([s[0] for s in shown], [
            "Contract action", "Signer field", "Signer field 1 of 2",
            "Inner action", "Inner field", "Inner field",
            "Signer field 2 of 2", "Inner action", "Inner field",
            "Inner field"])
        self.assertEqual(shown[1][1],
                         "Deadline:\n2026-10-29 23:35:24 UTC\n(1793316924)")
        self.assertTrue(shown[2][1].startswith(
            "Step:\nTo 0x" + ADDRESS.hex() + "\nFunction 0xb858183f\n"
            "Data 292 bytes\nValue 0 Wei\nAs 0x"), shown[2][1])
        self.assertEqual(shown[5][1], "Minimum out:\n3750489828061637096")
        self.assertTrue(shown[6][1].startswith(
            "Step:\nTo 0x" + ADDRESS.hex() + "\nFunction 0x49404b7c\n"
            "Data 68 bytes"), shown[6][1])
        self.assertEqual(shown[8][1], "Minimum:\n3.750489828061637096 ETH")
        # RECIPIENT: the ETH goes to the capture's account, not this wallet.
        self.assertEqual(shown[9][1],
                         "Recipient:\n0xB3ddeC0cCC5C3ba733FCdf5a15f98c95Ec5a5FdB"
                         "\nNOT this wallet")

    def _exec_of(self, to, data, operation=0):
        padded = data + bytes(-len(data) % 32)
        return (self._word(to) + self._word(0) + self._word(128) +
                self._word(operation) + self._word(len(data)) + padded)

    def test_717_calls_nest_two_levels_and_no_deeper(self):
        # A Safe executing the real multicall, whose steps are level 2. A
        # Safe executing a second Safe executing it is refused at level 3,
        # which is never asked for.
        self.requires_firmware("7.17.0")
        from keepkeylib.signed_metadata import keccak256
        selector = keccak256(b"execTransaction(address,uint256,bytes,uint8)")[:4]
        multicall = keccak256(b"multicall(uint256,bytes[])")[:4]
        second = bytes.fromhex("55" * 20)
        exec_fields = [
            {"path": "data", "label": "Transaction", "format": "calldata",
             "params": {"calleePath": "to", "amountPath": "value",
                        "spenderPath": "@.to"}},
            {"path": "operation", "label": "Operation", "format": "raw"}]
        outer = self._program(self.EXEC, "sign multisig operation",
                              exec_fields)
        middle = self._program(self.EXEC, "sign multisig operation",
                               exec_fields, second)
        router, steps = self._router02(self.ROUTER02)
        call = multicall + self.ROUTER02_MULTICALL_ARGS
        result, baseline = self._signed_with(
            outer, [router] + steps, self._exec_of(self.ROUTER02, call))
        self.assertEqual(result.signature_r, baseline.signature_r)
        self.assertEqual(self.depths, [1, 2, 2])
        shown = [s for s in self._shown()
                 if s[0] not in ("Runtime signer", "Inner signer")]
        self.assertIn(("Inner field", "Minimum:\n3.750489828061637096 ETH"),
                      shown)
        self.assertEqual(shown[-1], ("Signer field", "Operation:\n0"))
        self._load_signer()
        deeper = self._exec_of(second, selector + self._exec_of(
            self.ROUTER02, call))
        result, _ = self._signed_with(outer, [middle, router] + steps, deeper)
        assert_failure(self, result, types.Failure_Other,
                       "Inner call cannot be clear-signed")
        self.assertEqual(self.depths, [1, 2])
        self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)

    def test_717_safe_creation_shows_owners_and_no_module(self):
        # The registry's createProxyWithNonce and setup() formats over the
        # real creation: setup() embeds (to, data) = (0, empty), which calls
        # nothing; the device says so instead of refusing the creation.
        self.requires_firmware("7.17.0")
        factory = self._program(self.CREATE_PROXY, "Create Safe", [
            {"path": "_singleton", "label": "Safe singleton",
             "format": "addressName"},
            {"path": "initializer", "label": "Account setup",
             "format": "calldata", "params": {"calleePath": "_singleton"}}])
        setup = self._program(self.SETUP, "Setup Safe", [
            {"path": "_owners.[]", "label": "Signer", "format": "addressName"},
            {"path": "_threshold", "label": "Threshold", "format": "raw"},
            {"path": "data", "label": "Module", "format": "calldata",
             "params": {"calleePath": "to"}}], self.SAFE_L2)
        result, baseline = self._signed_with(factory, [setup],
                                             self.SAFE_CREATE_ARGS)
        self.assertEqual(result.signature_r, baseline.signature_r)
        inner = [s for s in self._shown() if s[0].startswith("Inner field")]
        self.assertEqual(inner, [
            ("Inner field 1 of 2",
             "Signer:\n0xe4f420A0786451a10bf2Fd4702E9b76632c08109"),
            ("Inner field 2 of 2",
             "Signer:\n0x3Ef438C34cE51A697a24247fe033C4562C94F0Fd"),
            ("Inner field", "Threshold:\n1"),
            ("Inner field",
             "Module:\nTo 0x0000000000000000000000000000000000000000\nNo data")])

    def test_717_safe_creation_with_safe_to_l2_setup_signs(self):
        # Safe{Wallet}'s own creation: setup() DELEGATECALLs SafeToL2Setup
        # .setupToL2(SafeL2 1.4.1), Safe's deployments pinned on chain 1. The
        # device says what that does, calmly, and signs; it never asks for
        # (or shows) a definition of the callee.
        self.requires_firmware("7.17.0")
        factory = self._program(self.CREATE_PROXY, "Create Safe", [
            {"path": "initializer", "label": "Account setup",
             "format": "calldata", "params": {"calleePath": "_singleton"}}])
        setup = self._program(self.SETUP, "Setup Safe", [
            {"path": "_threshold", "label": "Threshold", "format": "raw"},
            {"path": "data", "label": "Module", "format": "calldata",
             "params": {"calleePath": "to"}}], self.SAFE_141)
        to_l2 = self._program("setupToL2(address l2Singleton)",
                              "Use L2 singleton", [
            {"path": "l2Singleton", "label": "L2 singleton",
             "format": "addressName"}], self.SAFE_TO_L2_SETUP)
        result, baseline = self._signed_with(factory, [setup, to_l2],
                                             self.SAFE_CREATE_L2_SETUP_ARGS)
        self.assertEqual(result.signature_r, baseline.signature_r)
        self.assertEqual(self.depths, [1])
        pages = self._first_pages()
        self.assertIn(("Inner field",
                       "Module:\nTo 0xBD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54"
                       "\nSafe's SafeToL2Setup: off Ethereum, your Safe runs "
                       "Safe's SafeL2 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762"),
                      pages)
        self.assertNotIn(self.DELEGATECALL, pages)
        self.assertNotIn(("Inner action", "Use L2 singleton"), pages)

        # One byte off (`to` at 208..227, the SafeL2 word's address at
        # 596..615): no longer Safe's own module. Named and refused.
        for at in (227, 615):
            altered = bytearray(self.SAFE_CREATE_L2_SETUP_ARGS)
            altered[at] ^= 1
            result, _ = self._signed_with(factory, [setup, to_l2],
                                          bytes(altered))
            assert_failure(self, result, types.Failure_Other,
                           "DELEGATECALL cannot be clear-signed")
            self.assertEqual(self.depths, [1])
            self.assertIn(self.DELEGATECALL, self._first_pages())
            self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)

    def test_717_cow_order_sells_exactly_the_transaction_value(self):
        # TX_VALUE: the order's sell amount must be the transaction's value.
        # On the runtime tier the ordinary Send screen stays.
        self.requires_firmware("7.17.0")
        order = self._program(self.CREATE_ORDER, "Sell ETH", [
            {"path": "order.sellAmount", "label": "Sell", "format": "amount",
             "params": {"equalsTxValue": True}},
            {"path": "order.receiver", "label": "Receiver",
             "format": "addressName", "params": {"recipient": True}},
            {"path": "order.validTo", "label": "Valid until", "format": "date",
             "params": {"encoding": "timestamp"}}])
        ten = (10 * 10 ** 18).to_bytes(8, "big")
        result, baseline = self._signed_with(order, [], self.COW_ORDER_ARGS,
                                             value=ten)
        self.assertEqual(result.signature_r, baseline.signature_r)
        self.assertEqual(
            [s for s in self._shown() if s[0] == "Signer field"], [
                ("Signer field", "Sell:\n10 ETH"),
                ("Signer field",
                 "Receiver:\n0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n"
                 "NOT this wallet"),
                ("Signer field",
                 "Valid until:\n2026-10-29 22:00:00 UTC\n(1793311200)")])
        self.assertIn("Send", [s[0] for s in self.screens])
        self._load_signer()
        result, _ = self._signed_with(order, [], self.COW_ORDER_ARGS,
                                      value=ten[:-1] + b"\x01")
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 value does not match the call")
        self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)
