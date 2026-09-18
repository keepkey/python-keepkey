from __future__ import absolute_import

import hashlib
import json
import os
import subprocess
import struct
import tempfile

import pytest

from keepkeylib.erc7730_compiler import (
    HEADER_SIZE, compile_calldata, compile_eip712, eip712_encode_type,
    parse_function_signature,
)
from keepkeylib.signed_metadata import keccak256


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
    first = compile_calldata(descriptor, **kwargs)
    second = compile_calldata(descriptor, **kwargs)
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
    validator = os.environ.get("ERC7730_FIRMWARE_VALIDATOR")
    if validator:
        with tempfile.NamedTemporaryFile() as compiled:
            compiled.write(first)
            compiled.flush()
            subprocess.check_call([validator, compiled.name])


def test_compiles_official_uniswap_tuple_fixture_through_firmware():
    registry = os.environ.get("ERC7730_REGISTRY")
    if not registry:
        pytest.skip("official ERC-7730 registry not configured")
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
    compiled = compile_calldata(
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
    validator = os.environ.get("ERC7730_FIRMWARE_VALIDATOR")
    if validator:
        with tempfile.NamedTemporaryFile() as output:
            output.write(compiled)
            output.flush()
            subprocess.check_call([validator, output.name])


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

    compiled = compile_calldata(
        fixture["descriptor"], fixture["signature"], fixture["chainId"],
        fixture["to"], network_records=[(1, "Ethereum", "ETH", 18)])
    assert compiled[38:42].hex() == expected["selector"]
    validator = os.environ.get("ERC7730_FIRMWARE_VALIDATOR")
    if validator:
        with tempfile.NamedTemporaryFile() as output:
            output.write(compiled)
            output.flush()
            subprocess.check_call([validator, output.name])


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
    compiled = compile_calldata(
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
    validator = os.environ.get("ERC7730_FIRMWARE_VALIDATOR")
    if validator:
        with tempfile.NamedTemporaryFile() as output:
            output.write(compiled)
            output.flush()
            subprocess.check_call([validator, output.name])


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
    compiled = compile_calldata(
        descriptor, "guard(uint256 mode,address recipient)", 1,
        "0x1111111111111111111111111111111111111111")
    sections = _sections(compiled)
    conditions = sections[5]
    assert int.from_bytes(conditions[:2], "big") == 2
    assert conditions[2] == 7
    assert conditions[10] == 8
    literals = sections[4]
    assert int.from_bytes(literals[:2], "big") == 5
    validator = os.environ.get("ERC7730_FIRMWARE_VALIDATOR")
    if validator:
        with tempfile.NamedTemporaryFile() as output:
            output.write(compiled)
            output.flush()
            subprocess.check_call([validator, output.name])


def test_compiles_official_uniswap_eip712_fixture_through_firmware():
    registry = os.environ.get("ERC7730_REGISTRY")
    if not registry:
        pytest.skip("official ERC-7730 registry not configured")
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
    compiled = compile_eip712(
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
    validator = os.environ.get("ERC7730_FIRMWARE_VALIDATOR")
    if validator:
        with tempfile.NamedTemporaryFile() as output:
            output.write(compiled)
            output.flush()
            subprocess.check_call([validator, output.name])
