from __future__ import absolute_import

import hashlib
import json
import os
import subprocess
import struct
import tempfile

import pytest

from keepkeylib.erc7730_compiler import (
    HEADER_SIZE, DeviceCannotExecute, compile_calldata, compile_eip712,
    device_refusal, eip712_encode_type, load_descriptor,
    parse_function_signature,
)
from keepkeylib.signed_metadata import keccak256


# CI sets KK_REQUIRE_ERC7730_EVIDENCE=1. There, a missing firmware validator or
# official registry is a FAILURE: these tests are reported as firmware and
# registry conformance evidence, and silently skipping that step would let a
# host-only compile masquerade as firmware acceptance. Elsewhere the absence is
# reported as an explicit skip, never as a pass.
REQUIRE_EVIDENCE = os.environ.get("KK_REQUIRE_ERC7730_EVIDENCE") == "1"


def _evidence_input(name):
    value = os.environ.get(name)
    if value:
        return value
    message = "%s is not configured" % name
    if REQUIRE_EVIDENCE:
        pytest.fail(message + " (required by KK_REQUIRE_ERC7730_EVIDENCE=1)")
    pytest.skip(message)


def _firmware_accepts(program):
    validator = _evidence_input("ERC7730_FIRMWARE_VALIDATOR")
    with tempfile.NamedTemporaryFile() as compiled:
        compiled.write(program)
        compiled.flush()
        return subprocess.call([validator, compiled.name],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) == 0


def _unchecked(compile, *args, **kwargs):
    return compile(*args, executable_only=False, **kwargs)


def _firmware_validate(program, refusal=None):
    """The device verifier accepts `program` exactly when the compiler's
    capability mirror does, and `refusal` names the expected reason (None
    for a program the device executes)."""
    assert device_refusal(program) == refusal
    assert _firmware_accepts(program) == (refusal is None)


def _sections(program):
    count = program[178]
    offset = HEADER_SIZE
    result = {}
    for _ in range(count):
        kind = program[offset]
        length = struct.unpack(">I", program[offset + 1:offset + 5])[0]
        result[kind] = program[offset + 5:offset + 5 + length]
        offset += 5 + length
    assert offset == len(program)
    return result


def _rlp_item(data, offset=0):
    prefix = data[offset]
    if prefix <= 0x7f:
        return bytes([prefix]), offset + 1
    if prefix <= 0xb7:
        length = prefix - 0x80
        start = offset + 1
        return data[start:start + length], start + length
    if prefix <= 0xbf:
        width = prefix - 0xb7
        length = int.from_bytes(data[offset + 1:offset + 1 + width], "big")
        start = offset + 1 + width
        return data[start:start + length], start + length
    if prefix <= 0xf7:
        length = prefix - 0xc0
        start = offset + 1
    else:
        width = prefix - 0xf7
        length = int.from_bytes(data[offset + 1:offset + 1 + width], "big")
        start = offset + 1 + width
    end = start + length
    values = []
    while start < end:
        value, start = _rlp_item(data, start)
        values.append(value)
    assert start == end
    return values, end


def _ethereum_transaction(raw_hex):
    raw = bytes.fromhex(raw_hex[2:])
    typed = raw[0] in (1, 2, 3, 4)
    transaction, end = _rlp_item(raw, 1 if typed else 0)
    assert end == len(raw)
    if typed and raw[0] == 2:
        return int.from_bytes(transaction[0], "big"), transaction[5], transaction[7]
    if typed:
        raise ValueError("unsupported typed fixture")
    return None, transaction[3], transaction[5]


def test_parses_recursive_tuple_and_array_signature():
    name, root = parse_function_signature(
        "route((address token,uint256 amount)[] legs,address recipient)")
    assert name == "route"
    assert root.children[0].name == "legs"
    assert root.children[0].kind == 9
    assert root.children[0].children[0].children[1].name == "amount"


def test_compiles_deterministic_canonical_calldata_program():
    descriptor = {
        "$schema": "https://eips.ethereum.org/assets/eip-7730/erc7730-v2.schema.json",
        "context": {"contract": {"deployments": [
            {"chainId": 1,
             "address": "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45"}
        ]}},
        "display": {"formats": {
            "swapExactTokensForTokens(uint256 amountIn,uint256 amountOutMin,address[] path,address to)": {
                "intent": "Swap",
                "fields": [
                    {"path": "amountIn", "label": "Amount to Send",
                     "format": "tokenAmount",
                     "params": {"tokenPath": "path.[0]"}},
                    {"path": "amountOutMin", "label": "Minimum to Receive",
                     "format": "tokenAmount",
                     "params": {"tokenPath": "path.[-1]"}},
                    {"path": "to", "label": "Recipient",
                     "format": "addressName"},
                ],
            }
        }},
    }
    kwargs = dict(
        signature="swapExactTokensForTokens(uint256 amountIn,uint256 amountOutMin,address[] path,address to)",
        chain_id=1,
        address="0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
        token_records=[
            (1, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "WETH", 18),
        ],
        network_records=[(1, "Ethereum", "ETH", 18)],
    )
    first = _unchecked(compile_calldata, descriptor, **kwargs)
    second = _unchecked(compile_calldata, descriptor, **kwargs)
    assert first == second
    assert first[:4] == b"C773"
    assert first[4:8] == bytes([1, 2, 0, 1])
    assert first[10:18] == struct.pack(">Q", 1)
    assert first[18:38] == bytes.fromhex(
        "68b3465833fb72a70ecdf485e0e4c7bd8665fc45")
    # Registry fixture has the four-argument router variant; the selector is
    # computed from its canonical ABI rather than copied from descriptor data.
    assert first[38:42].hex() == "472b43f3"
    assert first[42:70] == bytes(28)
    sections = _sections(first)
    assert set(sections) == {1, 2, 3, 6, 7, 8, 9}
    assert hashlib.sha256(first).digest() == hashlib.sha256(second).digest()
    assert len(first) < 16384
    _firmware_validate(first)


def test_compiles_official_uniswap_tuple_fixture_through_firmware():
    registry = _evidence_input("ERC7730_REGISTRY")
    path = os.path.join(
        registry, "registry", "uniswap", "calldata-UniswapV3Router02.json")
    with open(path, "r") as source:
        descriptor = json.load(source)
    tests_path = os.path.join(
        registry, "registry", "uniswap", "testsv2",
        "calldata-UniswapV3Router02.tests.json")
    with open(tests_path, "r") as source:
        fixtures = json.load(source)["tests"]
    signature = (
        "exactInputSingle((address tokenIn, address tokenOut, uint24 fee, "
        "address recipient, uint256 amountIn, uint256 amountOutMinimum, "
        "uint160 sqrtPriceLimitX96) params)")
    compiled = _unchecked(compile_calldata, 
        descriptor, signature, 1,
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
        token_records=[
            (1, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "WETH", 18),
            (1, "0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT", 6),
        ],
        network_records=[(1, "Ethereum", "ETH", 18)],
    )
    assert compiled[38:42].hex() == "04e45aaf"
    chain_id, target, calldata = _ethereum_transaction(fixtures[1]["rawTx"])
    assert chain_id == 1
    assert target.hex() == "68b3465833fb72a70ecdf485e0e4c7bd8665fc45"
    assert calldata[:4] == compiled[38:42]
    assert fixtures[1]["txHash"] == (
        "0xb25281abb3e6bbfe18c746187522c2e915aa02fdb8175082005340e00c1f0b30")
    _firmware_validate(compiled)


def test_compiles_and_checks_exact_keepkey_sdk_thorchain_swap():
    fixture_path = os.path.join(
        os.path.dirname(__file__), "fixtures", "erc7730-thorchain-router-v3.json")
    with open(fixture_path, "r") as source:
        fixture = json.load(source)
    calldata = bytes.fromhex(fixture["data"][2:])
    expected = fixture["expected"]
    assert calldata[:4].hex() == expected["selector"]
    assert ("0x" + calldata[16:36].hex()) == expected["vault"]
    assert ("0x" + calldata[48:68].hex()) == expected["asset"]
    assert str(int.from_bytes(calldata[68:100], "big")) == expected["amount"]
    dynamic_offset = int.from_bytes(calldata[100:132], "big")
    memo_length = int.from_bytes(
        calldata[4 + dynamic_offset:4 + dynamic_offset + 32], "big")
    memo = calldata[4 + dynamic_offset + 32:
                    4 + dynamic_offset + 32 + memo_length].decode("utf-8")
    assert memo == expected["memo"]
    assert int(fixture["value"], 16) == int(expected["amount"])

    compiled = _unchecked(compile_calldata, 
        fixture["descriptor"], fixture["signature"], fixture["chainId"],
        fixture["to"], network_records=[(1, "Ethereum", "ETH", 18)])
    assert compiled[38:42].hex() == expected["selector"]
    _firmware_validate(compiled)


def test_compiles_array_iteration_separator_and_optional_visibility():
    descriptor = {
        "display": {"formats": {
            "batch((address recipient,uint256 amount)[] items)": {
                "intent": "Batch transfer",
                "fields": [{
                    "path": "items.[].recipient",
                    "label": "Recipient",
                    "format": "addressName",
                    "separator": "Next recipient",
                    "visible": "optional",
                }],
            }
        }}
    }
    compiled = _unchecked(compile_calldata, 
        descriptor,
        "batch((address recipient,uint256 amount)[] items)", 1,
        "0x1111111111111111111111111111111111111111")
    sections = _sections(compiled)
    assert 5 in sections
    display = sections[7]
    count = int.from_bytes(display[:2], "big")
    opcodes = [display[2 + i * 8] for i in range(count)]
    assert opcodes == [1, 7, 4, 8, 10]
    begin = display[10:18]
    end = display[26:34]
    assert int.from_bytes(begin[6:8], "big") == 3
    assert int.from_bytes(end[2:4], "big") == 1
    _firmware_validate(compiled)


def test_refuses_nested_array_iteration_the_device_cannot_verify():
    # The device's catalog verifier accepts one "[]" step per path, so a
    # program iterating a nested array could never be loaded. The compiler
    # refuses it by name instead of emitting a program the device rejects.
    descriptor = {"display": {"formats": {
        "matrix(uint256[][] values)": {
            "intent": "Review matrix",
            "fields": [{"path": "values.[].[]", "label": "Value",
                        "format": "raw", "separator": "Next row"}],
        }
    }}}
    with pytest.raises(ValueError, match="iterates more than one array"):
        compile_calldata(
            descriptor, "matrix(uint256[][] values)", 1,
            "0x1111111111111111111111111111111111111111")


def test_token_amount_without_token_uses_firmware_raw_fallback():
    descriptor = {"display": {"formats": {
        "quote(uint256 amount)": {
            "intent": "Review quote",
            "fields": [{"path": "amount", "label": "Unknown token amount",
                        "format": "tokenAmount"}],
        }
    }}}
    compiled = _unchecked(compile_calldata, 
        descriptor, "quote(uint256 amount)", 1,
        "0x1111111111111111111111111111111111111111")
    # With no token named the device can only show the raw integer, and its
    # verifier refuses a tokenAmount formatter without a token argument.
    formatter = _sections(compiled)[6]
    assert formatter[2:5] == bytes([1, 0, 1])
    assert formatter[5:9] == bytes([1, 1, 0, 0])
    _firmware_validate(compiled)


def test_compiles_typed_if_not_in_and_must_match_conditions():
    descriptor = {"display": {"formats": {
        "guard(uint256 mode,address recipient)": {
            "intent": "Guarded call",
            "fields": [
                {"path": "mode", "label": "Mode", "format": "raw",
                 "visible": {"ifNotIn": [0, 255]}},
                {"path": "recipient", "label": "Bound recipient",
                 "format": "addressName",
                 "visible": {"mustMatch": [
                     "0x2222222222222222222222222222222222222222"]}},
            ],
        }
    }}}
    compiled = _unchecked(compile_calldata, 
        descriptor, "guard(uint256 mode,address recipient)", 1,
        "0x1111111111111111111111111111111111111111")
    sections = _sections(compiled)
    conditions = sections[5]
    assert int.from_bytes(conditions[:2], "big") == 2
    assert conditions[2] == 7
    assert conditions[10] == 8
    literals = sections[4]
    assert int.from_bytes(literals[:2], "big") == 5
    _firmware_validate(compiled,
                       "condition opcode 7 is not executed")


def test_compiles_interpolated_intent_and_metadata_enum():
    descriptor = {
        "metadata": {"enums": {"side": {"false": "Buy", "true": "Sell"}}},
        "display": {"formats": {
            "swap(bool selling,uint256 amount)": {
                "intent": "Swap",
                "interpolatedIntent": "Swap {amount} as {selling}",
                "fields": [
                    {"path": "selling", "label": "Side", "format": "enum",
                     "params": {"$ref": "$.metadata.enums.side"},
                     "visible": "always"},
                    {"path": "amount", "label": "Amount", "format": "raw",
                     "visible": "always"},
                ],
            }
        }}
    }
    compiled = _unchecked(compile_calldata, 
        descriptor, "swap(bool selling,uint256 amount)", 1,
        "0x1111111111111111111111111111111111111111")
    sections = _sections(compiled)
    display = sections[7]
    count = int.from_bytes(display[:2], "big")
    opcodes = [display[2 + i * 8] for i in range(count)]
    assert opcodes == [1, 2, 3, 2, 3, 4, 4, 10]
    formatters = sections[6]
    assert int.from_bytes(formatters[:2], "big") == 2
    assert formatters[2] == 8
    literals = sections[4]
    assert int.from_bytes(literals[:2], "big") == 3
    _firmware_validate(compiled)


def test_compiles_nested_field_group_with_balanced_links():
    descriptor = {"display": {"formats": {
        "act((address owner,uint256 amount) details)": {
            "intent": "Grouped action",
            "fields": [{
                "path": "details", "label": "Details", "fields": [
                    {"path": "owner", "label": "Owner",
                     "format": "addressName"},
                    {"path": "amount", "label": "Amount", "format": "raw"},
                ],
            }],
        }
    }}}
    compiled = _unchecked(compile_calldata, 
        descriptor, "act((address owner,uint256 amount) details)", 1,
        "0x1111111111111111111111111111111111111111")
    display = _sections(compiled)[7]
    count = int.from_bytes(display[:2], "big")
    instructions = [display[2 + i * 8:10 + i * 8] for i in range(count)]
    assert [item[0] for item in instructions] == [1, 5, 4, 4, 6, 10]
    assert int.from_bytes(instructions[1][6:8], "big") == 4
    assert int.from_bytes(instructions[4][2:4], "big") == 1
    _firmware_validate(compiled)


def test_loads_bounded_includes_and_compiles_array_backed_group(tmp_path):
    shared = {
        "display": {"definitions": {
            "recipient": {"label": "Recipient", "format": "addressName"}
        }}
    }
    descriptor = {
        "includes": "shared.json",
        "display": {"formats": {
            "batch((address to,uint256 amount)[] items)": {
                "intent": "Batch",
                "fields": [{"path": "items.[]", "label": "Item",
                            "fields": [
                                {"path": "to",
                                 "$ref": "$.display.definitions.recipient"},
                                {"path": "amount", "label": "Amount",
                                 "format": "raw"},
                            ]}],
            }
        }}
    }
    (tmp_path / "shared.json").write_text(json.dumps(shared))
    path = tmp_path / "descriptor.json"
    path.write_text(json.dumps(descriptor))
    loaded = load_descriptor(str(path), str(tmp_path))
    compiled = _unchecked(compile_calldata, 
        loaded, "batch((address to,uint256 amount)[] items)", 1,
        "0x1111111111111111111111111111111111111111")
    display = _sections(compiled)[7]
    count = int.from_bytes(display[:2], "big")
    opcodes = [display[2 + i * 8] for i in range(count)]
    assert opcodes == [1, 7, 5, 4, 4, 6, 8, 10]
    _firmware_validate(compiled)


DEVICE_LIMITS = (
    "iterates more than one array",
    "nests deeper than the device supports",
)


# Formats the device can fully sign with this firmware's capability table.
# Each later phase of the ERC-7730 formatter plan raises this number
# (docs/security/HANDOFF-ERC7730-715-FORMATTERS.md in keepkey-firmware).
# Phase 0 signed 92 (raw fields only). Phase A adds tokenAmount, addressName,
# @.from/@.to and signed constants: 812. It refuses addressName and
# tokenAmount over bytes32/uint256 words that pack an address or an encrypted
# amount, rather than reinterpret bytes the calldata does not say are one.
# Phase B adds the interpolated intent, shown as numbered parts: 954.
# Phase C adds amount, nftName, date, duration, unit, enum and @.value: 1138.
# Phase D adds groups, single-array iteration and "optional" fields: 1294.
# Phase E1 adds embedded calldata, shown under a blind-sign warning: 1326.
REGISTRY_SIGNABLE = 1326


def test_official_registry_all_calldata_formats_reach_firmware():
    registry = _evidence_input("ERC7730_REGISTRY")
    _evidence_input("ERC7730_FIRMWARE_VALIDATOR")
    import glob
    failures = []
    unsupported = []
    signable = 0
    checked = 0
    for path in glob.glob(os.path.join(
            registry, "registry", "**", "calldata-*.json"), recursive=True):
        descriptor = load_descriptor(path, registry)
        deployments = descriptor.get("context", {}).get(
            "contract", {}).get("deployments", [])
        if not deployments:
            continue
        deployment = deployments[0]
        if (not isinstance(deployment.get("chainId"), int) or
                not isinstance(deployment.get("address"), str)):
            continue
        for signature in descriptor.get("display", {}).get("formats", {}):
            checked += 1
            try:
                try:
                    program = _unchecked(
                        compile_calldata, descriptor, signature,
                        deployment["chainId"], deployment["address"])
                except ValueError as exc:
                    if any(reason in str(exc) for reason in DEVICE_LIMITS):
                        unsupported.append(signature)
                        continue
                    raise
                # The device verifier and the compiler's capability mirror
                # must agree on every format, in both directions.
                executable = device_refusal(program) is None
                if _firmware_accepts(program) != executable:
                    raise AssertionError(
                        "device and compiler disagree: %r" %
                        device_refusal(program))
                signable += executable
            except Exception as exc:
                failures.append("%s :: %s :: %s" % (
                    os.path.basename(path), signature, exc))
    assert checked == 1450
    assert failures == []
    # Every other format is refused by the compiler for a named device limit:
    # 8 iterate nested arrays, 2 nest their ABI deeper than 8 levels.
    assert len(unsupported) == 10
    # Passing the parser is not signability: only these pass the device's
    # preload capability checks.
    assert signable == REGISTRY_SIGNABLE


def test_compiles_official_uniswap_eip712_fixture_through_firmware():
    registry = _evidence_input("ERC7730_REGISTRY")
    with open(os.path.join(registry, "registry", "uniswap",
                           "eip712-uniswap-permit2.json"), "r") as source:
        descriptor = json.load(source)
    with open(os.path.join(registry, "registry", "uniswap", "testsv2",
                           "eip712-uniswap-permit2.tests.json"), "r") as source:
        fixture = json.load(source)["tests"][0]["data"]
    encoded = eip712_encode_type(fixture["primaryType"], fixture["types"])
    assert encoded == (
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)"
        "PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")
    compiled = _unchecked(compile_eip712, 
        descriptor, fixture,
        token_records=[
            (1, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "USDC", 6)
        ], network_records=[(1, "Ethereum", "ETH", 18)])
    assert compiled[7] == 2
    assert compiled[10:18] == (1).to_bytes(8, "big")
    assert compiled[18:38].hex() == "000000000022d473030f116ddee9f6b43ac78ba3"
    assert compiled[38:70] == keccak256(encoded.encode("ascii"))
    sections = _sections(compiled)
    binding = sections[8]
    # deployment + name/chain/contract domain facts + token + network
    assert int.from_bytes(binding[:2], "big") == 6
    _firmware_validate(compiled)


def test_mirror_applies_the_devices_abi_and_text_limits():
    # Each shape the device refuses at preload is refused by the mirror too,
    # and a neighbour inside the limit is accepted by both.
    address = "0x" + "11" * 20
    for length, refusal in ((64, None),
                            (65, "an ABI array exceeds the device limit")):
        signature = "f(uint256[%d] a,uint256 b)" % length
        descriptor = {"display": {"formats": {signature: {
            "intent": "F", "fields": [
                {"path": "b", "label": "B", "format": "raw"}]}}}}
        _firmware_validate(_unchecked(compile_calldata, descriptor, signature,
                                      1, address), refusal)
    for label, refusal in (("Line one", None),
                           ("Line\none", "a program string is not printable text"),
                           ("Tab\there", "a program string is not printable text"),
                           ("Del\x7f", "a program string is not printable text")):
        descriptor = {"display": {"formats": {"f(uint256 a)": {
            "intent": "F", "fields": [
                {"path": "a", "label": label, "format": "raw"}]}}}}
        _firmware_validate(_unchecked(compile_calldata, descriptor,
                                      "f(uint256 a)", 1, address), refusal)


def test_signed_enum_keys_are_minimal_twos_complement():
    # -128 fits one byte (0x80); the device refuses a longer encoding.
    for signature, key in (("f(int8 side)", -128), ("f(int16 side)", -32768),
                           ("f(int16 side)", -129), ("f(int8 side)", 127)):
        descriptor = {
            "metadata": {"enums": {"side": {str(key): "Edge", "1": "Long"}}},
            "display": {"formats": {signature: {
                "intent": "F", "fields": [{
                    "path": "side", "label": "Side", "format": "enum",
                    "params": {"$ref": "$.metadata.enums.side"}}]}}}}
        _firmware_validate(compile_calldata(descriptor, signature, 1,
                                            "0x" + "11" * 20), None)
