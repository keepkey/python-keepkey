from __future__ import absolute_import

import hashlib
import json
import os
import subprocess
import struct
import tempfile

import pytest

from keepkeylib.erc7730_compiler import (
    HEADER_SIZE, compile_calldata, parse_function_signature,
)


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
    validator = os.environ.get("ERC7730_FIRMWARE_VALIDATOR")
    if validator:
        with tempfile.NamedTemporaryFile() as output:
            output.write(compiled)
            output.flush()
            subprocess.check_call([validator, output.name])
