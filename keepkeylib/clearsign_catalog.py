"""
CLEARSIGN_FLOWS — the canonical reference catalog of real-world EVM contract
calls for KeepKey clear-signing, and the single source of truth for:
  - the per-flow device tests in tests/test_msg_ethereum_clear_signing.py
    (each flow: build the real tx -> bind metadata to its exact sighash ->
    confirm the who/what/why screens -> sign -> recover the signer)
  - the batch device test (signs + validates every flow in one run)
  - the offline reference vectors (RFC 6979 deterministic — frozen
    sha256+length snapshots any signer implementation can be checked against)
  - the PDF report's EVM Clear-Signing section (V), generated FROM this
    catalog so there is no hand-duplicated, driftable copy of the flow list

Every flow's real contract address and function signature is sourced from a
public reference (Etherscan / official protocol docs / GitHub) — see the
`source` field. Calldata is built with keepkeylib.clearsign_abi (a small
deterministic Solidity ABI encoder; selectors are always DERIVED via
keccak256(signature), never hand-typed) so there is no hand-typed hex to get
wrong. A handful of flows involve genuinely dynamic ABI types (bytes[],
nested structs) that the encoder deliberately doesn't support — those are
hand-built with an explicit REPRESENTATIVE comment; they still use a real
selector and a real contract address, so "who" is authentic even where the
exact byte layout is a simplification rather than a literal captured tx.

Display formats used (the entire point: no calldata hex on the OLED, ever):
  ADDRESS      full 20-byte address, checksummed on-device, never truncated
  STRING       short attested printable label (protocol name, a deadline
               description, a percentage, an NFT id, "N batched calls", ...)
  TOKEN_AMOUNT decimals + symbol + big-endian amount -> device renders
               "10.5 DAI" (decimal-scaled) or "UNLIMITED <symbol>" for
               max-uint256 approvals. This is the human-readable "why".
"""

from .signed_metadata import (
    ARG_FORMAT_ADDRESS, ARG_FORMAT_STRING, ARG_FORMAT_TOKEN_AMOUNT,
    token_amount_value, serialize_metadata, sign_metadata, eth_sighash_legacy,
    keccak256,
)


def _ens_namehash(name):
    """Standard ENS namehash (EIP-137): recursive keccak256, computed here
    rather than hand-typed to avoid transcription errors in a 32-byte value."""
    node = b'\x00' * 32
    for label in reversed(name.split('.')):
        node = keccak256(node + keccak256(label.encode()))
    return node
from .clearsign_abi import (
    build_calldata, selector as abi_selector, parse_signature,
    encode_static_args,
)

# Fixed tx params so every flow's sighash — and therefore its reference blob
# — is deterministic. Matches the values the device tests actually sign with.
FLOW_CHAIN_ID = 1
FLOW_NONCE = 0
FLOW_GAS_PRICE = 20000000000
FLOW_GAS_LIMIT = 250000
REFERENCE_TIMESTAMP = 1700000000  # fixed for byte-reproducible reference blobs


def addr(hexstr):
    """'0xAbc...' or 'Abc...' -> 20 raw bytes."""
    h = hexstr[2:] if hexstr.startswith('0x') else hexstr
    b = bytes.fromhex(h)
    assert len(b) == 20, 'not a 20-byte address: %r' % hexstr
    return b


def flow(key, protocol, category, method, signature, contract, arg_values,
        display_args, value=0, why='', source='', chain_id=FLOW_CHAIN_ID,
        abi_types=None):
    """Build one catalog entry: REAL calldata (selector + ABI-encoded static
    args, derived — never hand-typed) plus the typed who/what/why args the
    metadata attests for display.

    signature: the canonical Solidity signature used to derive the 4-byte
        selector (e.g. 'exactInputSingle((address,address,uint24,address,
        uint256,uint256,uint256,uint160))' for a single-struct-param
        function — the real on-chain selector for a struct of only static
        members is computed from this parenthesized form).
    arg_values: positional values to ABI-encode, in signature order. By
        default types are parsed from `signature`; pass abi_types to encode
        against a FLATTENED type list instead (needed when `signature` has a
        nested tuple param: ABI-encodes a struct of only-static members
        head-only/inline, byte-identical to flattening it, so this is exact
        — not an approximation).
    display_args: list of {'name','format','value'} dicts in metadata wire
        format (ARG_FORMAT_ADDRESS/STRING/TOKEN_AMOUNT) — what the device
        screen shows. Not required to be 1:1 with arg_values.
    """
    contract_bytes = addr(contract)
    sel = abi_selector(signature)
    types = abi_types if abi_types is not None else parse_signature(signature)[1]
    data = sel + encode_static_args(types, arg_values)
    return {
        'key': key, 'protocol': protocol, 'category': category,
        'method': method, 'signature': signature,
        'to': contract_bytes, 'value': value, 'data': data,
        'args': display_args, 'why': why, 'source': source,
        'chain_id': chain_id,
    }


def flow_raw(key, protocol, category, method, contract, data,
            display_args, value=0, why='', source='', chain_id=FLOW_CHAIN_ID):
    """Like flow(), but for calls with dynamic ABI types (bytes[], nested
    structs) that clearsign_abi can't encode — `data` is hand-built at the
    call site from a REAL selector (via abi_selector) and REAL contract, with
    a representative (not necessarily literal-mainnet-tx) argument layout.
    See each call site's comment for what's simplified and why."""
    return {
        'key': key, 'protocol': protocol, 'category': category,
        'method': method, 'signature': '(dynamic — hand-built, see source)',
        'to': addr(contract), 'value': value, 'data': data,
        'args': display_args, 'why': why, 'source': source,
        'chain_id': chain_id,
    }


def flow_tx_hash(f):
    return eth_sighash_legacy(FLOW_NONCE, FLOW_GAS_PRICE, FLOW_GAS_LIMIT,
                              f['to'], f['value'], f['data'], f['chain_id'])


def flow_blob(f, key_id, timestamp=None):
    """Per-tx-bound signed metadata blob for a catalog flow. Pass
    timestamp=REFERENCE_TIMESTAMP for byte-reproducible reference vectors."""
    payload = serialize_metadata(
        chain_id=f['chain_id'],
        contract_address=f['to'],
        selector=f['data'][:4],
        tx_hash=flow_tx_hash(f),
        method_name=f['method'],
        args=f['args'],
        key_id=key_id,
        timestamp=timestamp,
    )
    return sign_metadata(payload)


CLEARSIGN_FLOWS = []
CLEARSIGN_FLOWS_BY_KEY = {}


def _register(*flows):
    for f in flows:
        assert f['key'] not in CLEARSIGN_FLOWS_BY_KEY, 'duplicate key: %s' % f['key']
        CLEARSIGN_FLOWS.append(f)
        CLEARSIGN_FLOWS_BY_KEY[f['key']] = f
    return flows


def _word(v):
    return int(v).to_bytes(32, 'big')


def _addr_word(a):
    return b'\x00' * 12 + addr(a)


# ── Common addresses (mainnet, verified against Etherscan) ────────────────
# Aave V3 Pool proxy on Ethereum mainnet. This used to hold
# 0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9, which is the Aave **V2**
# LendingPool -- pairing it with V3's supply() selector (617ba037; V2
# exposes deposit(), e8eda9df) described a call that would revert, so the
# fixture attested a transaction that cannot exist. The `source` field on
# every entry using this constant already named the correct proxy.
AAVE_V3_POOL = '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2'
DAI = '0x6b175474e89094c44da98b954eedeac495271d0f'
USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'
UNISWAP_V2_ROUTER = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d'
UNISWAP_V3_ROUTER = '0xe592427a0aece92de3edee1f18e0157c05861564'
UNISWAP_V3_ROUTER2 = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45'
VITALIK = '0xd8da6bf26964af9d7eed9e03e53415d37aa96045'
RECIPIENT_742 = '0x742d35cc6634c0532950a20547b231011e30c8e7'


# ═══════════════════════════════════════════════════════════════════════
# Category: DeFi lending & DEX (device-verified this session)
# ═══════════════════════════════════════════════════════════════════════

_register(
    flow(
        'aave-v3-supply', 'Aave V3', 'lending', 'supply',
        'supply(address,uint256,address,uint16)', AAVE_V3_POOL,
        [DAI, 10500000000000000000, VITALIK, 0],
        [{'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Aave V3'},
         {'name': 'asset', 'format': ARG_FORMAT_ADDRESS, 'value': addr(DAI)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT,
          'value': token_amount_value(10500000000000000000, 18, 'DAI')},
         {'name': 'onBehalfOf', 'format': ARG_FORMAT_ADDRESS, 'value': addr(VITALIK)}],
        why='Deposit collateral into Aave to earn yield / enable borrowing.',
        source='https://etherscan.io/address/0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 (Aave V3 Pool proxy)',
    ),
    flow(
        'erc20-transfer', 'ERC-20', 'core-tokens', 'transfer',
        'transfer(address,uint256)', USDC,
        [RECIPIENT_742, 1000000],
        [{'name': 'token', 'format': ARG_FORMAT_STRING, 'value': b'USD Coin'},
         {'name': 'to', 'format': ARG_FORMAT_ADDRESS, 'value': addr(RECIPIENT_742)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT,
          'value': token_amount_value(1000000, 6, 'USDC')}],
        why='The most common on-chain action: send tokens to an address.',
        source='https://eips.ethereum.org/EIPS/eip-20',
    ),
    flow(
        'erc20-approve', 'ERC-20', 'approvals', 'approve',
        'approve(address,uint256)', USDC,
        [UNISWAP_V3_ROUTER2, 1000000000],
        [{'name': 'spender', 'format': ARG_FORMAT_ADDRESS, 'value': addr(UNISWAP_V3_ROUTER2)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT,
          'value': token_amount_value(1000000000, 6, 'USDC')}],
        why='Grants a contract permission to move up to this amount of your tokens.',
        source='https://eips.ethereum.org/EIPS/eip-20',
    ),
    flow(
        'erc20-approve-unlimited', 'ERC-20', 'approvals', 'approve',
        'approve(address,uint256)', USDC,
        [UNISWAP_V3_ROUTER2, (2 ** 256) - 1],
        [{'name': 'spender', 'format': ARG_FORMAT_ADDRESS, 'value': addr(UNISWAP_V3_ROUTER2)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT,
          'value': token_amount_value((2 ** 256) - 1, 6, 'USDC')}],
        why='The single most drainer-abused action in EVM: max.uint256 approval. '
            'Must render as "UNLIMITED", never as a raw 78-digit number or hex.',
        source='https://eips.ethereum.org/EIPS/eip-20',
    ),
    flow_raw(
        'uniswap-v2-eth-to-token', 'Uniswap V2', 'dex-swaps',
        'swapExactETHForTokens', UNISWAP_V2_ROUTER,
        # swapExactETHForTokens(uint256 amountOutMin, address[] path, address to,
        # uint256 deadline) — path is a dynamic address[]; head = 4 static-slot
        # words (amountOutMin, offset-to-path, to, deadline), tail = the array
        # (length + elements). offset=0x80 = 4*32 bytes = start of tail.
        abi_selector('swapExactETHForTokens(uint256,address[],address,uint256)')
        + _word(9500000) + _word(0x80) + _addr_word(RECIPIENT_742) + _word(1700000000)
        + _word(2) + _addr_word(WETH) + _addr_word(USDC),
        [{'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Uniswap V2'},
         {'name': 'amountOutMin', 'format': ARG_FORMAT_TOKEN_AMOUNT,
          'value': token_amount_value(9500000, 6, 'USDC')},
         {'name': 'to', 'format': ARG_FORMAT_ADDRESS, 'value': addr(RECIPIENT_742)}],
        value=10000000000000000,  # 0.01 ETH in
        why='Swap ETH for a token; the tx VALUE leaving the wallet is real and '
            'shown on the final gas-confirm screen, not hidden in calldata.',
        source='https://etherscan.io/address/0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D#code',
    ),
    flow_raw(
        'uniswap-v2-token-to-eth', 'Uniswap V2', 'dex-swaps',
        'swapExactTokensForETH', UNISWAP_V2_ROUTER,
        # swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin,
        # address[] path, address to, uint256 deadline) — head = 5 static
        # slots (amountIn, amountOutMin, offset-to-path, to, deadline);
        # offset=0xa0 = 5*32 bytes.
        abi_selector('swapExactTokensForETH(uint256,uint256,address[],address,uint256)')
        + _word(100000000) + _word(3000000000000000) + _word(0xa0)
        + _addr_word(RECIPIENT_742) + _word(1700000000)
        + _word(2) + _addr_word(USDC) + _addr_word(WETH),
        [{'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Uniswap V2'},
         {'name': 'amountIn', 'format': ARG_FORMAT_TOKEN_AMOUNT,
          'value': token_amount_value(100000000, 6, 'USDC')},
         {'name': 'amountOutMin', 'format': ARG_FORMAT_TOKEN_AMOUNT,
          'value': token_amount_value(3000000000000000, 18, 'ETH')},
         {'name': 'to', 'format': ARG_FORMAT_ADDRESS, 'value': addr(RECIPIENT_742)}],
        why='Both legs of a swap (token in, ETH min-out) shown in human units.',
        source='https://etherscan.io/address/0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D#code',
    ),
    flow(
        'uniswap-v3-exact-input', 'Uniswap V3', 'dex-swaps', 'exactInputSingle',
        # ExactInputSingleParams is a struct of ONLY static members, so it
        # ABI-encodes head-only/inline — byte-identical to flattening it.
        'exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))',
        UNISWAP_V3_ROUTER,
        # tokenIn, tokenOut, fee, recipient, deadline, amountIn, amountOutMinimum, sqrtPriceLimitX96
        [WETH, USDC, 3000, RECIPIENT_742, 1700000000, 10000000000000000, 9500000, 0],
        [{'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Uniswap V3'},
         {'name': 'tokenIn', 'format': ARG_FORMAT_ADDRESS, 'value': addr(WETH)},
         {'name': 'tokenOut', 'format': ARG_FORMAT_ADDRESS, 'value': addr(USDC)},
         {'name': 'amountIn', 'format': ARG_FORMAT_TOKEN_AMOUNT,
          'value': token_amount_value(10000000000000000, 18, 'WETH')},
         {'name': 'amountOutMin', 'format': ARG_FORMAT_TOKEN_AMOUNT,
          'value': token_amount_value(9500000, 6, 'USDC')}],
        abi_types=['address', 'address', 'uint24', 'address', 'uint256', 'uint256', 'uint256', 'uint160'],
        why='V3 single-hop swap with an explicit fee tier; typed in/out amounts.',
        source='https://etherscan.io/address/0xE592427A0AEce92De3Edee1F18E0157C05861564#code',
    ),
    flow_raw(
        'uniswap-v3-multicall', 'Uniswap V3', 'dex-swaps', 'multicall',
        UNISWAP_V3_ROUTER2,
        # multicall(uint256 deadline, bytes[] data) — REPRESENTATIVE: real
        # selector + real router address, one inner call (refundETH(), a
        # real V3 Router method) batched, rather than a literal captured
        # mainnet multicall (those bundle many different calls and would
        # obscure the point being tested: opaque inner calls still render
        # as a named, human-readable summary, never as hex).
        # Head: [deadline, offset-to-data(0x40)]. Tail: [len=1, elem0-offset
        # (0x20), elem0: len(4) + refundETH() selector, padded to 32 bytes].
        abi_selector('multicall(uint256,bytes[])')
        + _word(1700000000) + _word(0x40)
        + _word(1) + _word(0x20) + _word(4)
        + abi_selector('refundETH()') + b'\x00' * 28,
        [{'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Uniswap V3'},
         {'name': 'calls', 'format': ARG_FORMAT_STRING,
          'value': b'1 inner call: refundETH'}],
        why='Batched calls are opaque by nature; the decode still names the '
            'protocol and summarizes in words instead of showing raw bytes[].',
        source='https://etherscan.io/address/0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45#code',
    ),
)


def _fmt_unix(ts):
    """Unix timestamp -> a short human date string for a STRING display arg
    (e.g. deadlines/expiries). Computed at catalog-build time — the device
    never does date math, it just displays the attested string."""
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


# ═══════════════════════════════════════════════════════════════════════
# Category: Lending & borrowing (Aave V3, Compound V3, Spark)
#
# Real contract addresses/signatures researched against Etherscan + official
# docs (see each flow's `source`). Any real ABI parameter NOT chosen for
# display (e.g. Aave's referralCode, always 0 in practice) still gets a real,
# neutral value in the encoded calldata — only the DISPLAY is a curated
# subset, matching the ERC-7730 field-hiding pattern Ledger/Trezor also use
# for non-security-relevant fields.
# ═══════════════════════════════════════════════════════════════════════

ONBEHALF_PLACEHOLDER = '0x1234567890AbcdEF1234567890aBcdef12345678'
DEADBEEF_PLACEHOLDER = '0x' + '00' * 16 + 'DeaDBeef'
ZERO_ADDRESS = '0x' + '00' * 20

_register(
    flow(
        'aave-v3-pool-borrow', 'Aave V3', 'lending', 'borrow',
        'borrow(address,uint256,uint256,uint16,address)', '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2',
        [USDC, 1000000000, 2, 0, ONBEHALF_PLACEHOLDER],
        [{'name': 'asset', 'format': ARG_FORMAT_ADDRESS, 'value': addr(USDC)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000, 6, 'USDC')},
         {'name': 'interestRateMode', 'format': ARG_FORMAT_STRING, 'value': b'rate mode: Variable'},
         {'name': 'onBehalfOf', 'format': ARG_FORMAT_ADDRESS, 'value': addr(ONBEHALF_PLACEHOLDER)}],
        why='Draws down a variable-rate loan against posted collateral; onBehalfOf lets a delegator drain credit.',
        source='https://etherscan.io/address/0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 (Aave V3 Pool proxy)',
    ),
    flow(
        'aave-v3-pool-repay', 'Aave V3', 'lending', 'repay',
        'repay(address,uint256,uint256,address)', '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2',
        [USDC, 500000000, 2, ONBEHALF_PLACEHOLDER],
        [{'name': 'asset', 'format': ARG_FORMAT_ADDRESS, 'value': addr(USDC)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(500000000, 6, 'USDC')},
         {'name': 'interestRateMode', 'format': ARG_FORMAT_STRING, 'value': b'rate mode: Variable'},
         {'name': 'onBehalfOf', 'format': ARG_FORMAT_ADDRESS, 'value': addr(ONBEHALF_PLACEHOLDER)}],
        why='Pays down outstanding debt; onBehalfOf can pay off someone else\'s loan.',
        source='https://etherscan.io/address/0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 (Aave V3 Pool proxy)',
    ),
    flow(
        'aave-v3-pool-withdraw', 'Aave V3', 'lending', 'withdraw',
        'withdraw(address,uint256,address)', '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2',
        [WETH, 2000000000000000000, ONBEHALF_PLACEHOLDER],
        [{'name': 'asset', 'format': ARG_FORMAT_ADDRESS, 'value': addr(WETH)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(2000000000000000000, 18, 'WETH')},
         {'name': 'to', 'format': ARG_FORMAT_ADDRESS, 'value': addr(ONBEHALF_PLACEHOLDER)}],
        why='Redeems supplied collateral for the underlying asset; the classic drainer pattern is a spoofed "to".',
        source='https://etherscan.io/address/0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 (Aave V3 Pool proxy)',
    ),
    flow(
        'compound-v3-comet-supply', 'Compound V3 (Comet)', 'lending', 'supply',
        'supply(address,uint256)', '0xc3d688B66703497DAA19211EEdff47f25384cdc3',
        [USDC, 1000000000],
        [{'name': 'asset', 'format': ARG_FORMAT_ADDRESS, 'value': addr(USDC)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000, 6, 'USDC')},
         {'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Compound V3 Comet'}],
        why='Deposits the base asset into the USDC Comet market to earn yield or back borrows.',
        source='https://etherscan.io/address/0xc3d688B66703497DAA19211EEdff47f25384cdc3 (cUSDCv3)',
    ),
    flow(
        'compound-v3-comet-withdraw', 'Compound V3 (Comet)', 'lending', 'withdraw',
        'withdraw(address,uint256)', '0xc3d688B66703497DAA19211EEdff47f25384cdc3',
        [WETH, 1000000000000000000],
        [{'name': 'asset', 'format': ARG_FORMAT_ADDRESS, 'value': addr(WETH)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000000000000, 18, 'WETH')},
         {'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Compound V3 Comet'}],
        why='Withdraws supplied collateral or base-asset balance from the caller\'s own Comet account.',
        source='https://etherscan.io/address/0xc3d688B66703497DAA19211EEdff47f25384cdc3 (cUSDCv3)',
    ),
    flow(
        'spark-protocol-supply', 'Spark Protocol', 'lending', 'supply',
        'supply(address,uint256,address,uint16)', '0xC13e21B648A5Ee794902342038FF3aDAB66BE987',
        [DAI, 5000000000000000000000, ONBEHALF_PLACEHOLDER, 0],
        [{'name': 'asset', 'format': ARG_FORMAT_ADDRESS, 'value': addr(DAI)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(5000000000000000000000, 18, 'DAI')},
         {'name': 'onBehalfOf', 'format': ARG_FORMAT_ADDRESS, 'value': addr(ONBEHALF_PLACEHOLDER)},
         {'name': 'referralCode', 'format': ARG_FORMAT_STRING, 'value': b'referral code: 0 (none)'}],
        why='Spark is a permissioned Aave V3 fork run by the Sky/MakerDAO ecosystem, sharing Aave\'s Pool ABI.',
        source='https://etherscan.io/address/0xC13e21B648A5Ee794902342038FF3aDAB66BE987 (SparkLend Pool)',
    ),
)


# ═══════════════════════════════════════════════════════════════════════
# Category: Liquid staking & restaking (Lido, Rocket Pool, ether.fi, EigenLayer)
# ═══════════════════════════════════════════════════════════════════════

_register(
    flow(
        'lido-steth-submit', 'Lido', 'staking', 'submit',
        'submit(address)', '0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84',
        [ZERO_ADDRESS],
        [{'name': '_referral', 'format': ARG_FORMAT_ADDRESS, 'value': addr(ZERO_ADDRESS)},
         {'name': 'action', 'format': ARG_FORMAT_STRING, 'value': b'Lido stETH stake'}],
        value=1000000000000000000,
        why='User stakes ETH directly with Lido\'s stETH contract and is minted stETH 1:1.',
        source='https://etherscan.io/address/0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84 (stETH)',
    ),
    flow(
        'rocketpool-deposit-pool-deposit', 'Rocket Pool', 'staking', 'deposit',
        'deposit()', '0xDD3f50F8A6CafbE9b31a427582963f465E745AF8',
        [],
        [{'name': 'value', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000000000000, 18, 'ETH')},
         {'name': 'action', 'format': ARG_FORMAT_STRING, 'value': b'Rocket Pool deposit'}],
        value=1000000000000000000,
        why='User deposits ETH into Rocket Pool\'s deposit pool and is minted rETH at the current exchange rate.',
        source='https://etherscan.io/address/0xDD3f50F8A6CafbE9b31a427582963f465E745AF8 (RocketDepositPool)',
    ),
    flow(
        'etherfi-liquiditypool-deposit', 'ether.fi', 'staking', 'deposit',
        'deposit(address)', '0x308861A430be4cce5502d0A12724771Fc6DaF216',
        [ZERO_ADDRESS],
        [{'name': '_referral', 'format': ARG_FORMAT_ADDRESS, 'value': addr(ZERO_ADDRESS)},
         {'name': 'value', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000000000000, 18, 'ETH')},
         {'name': 'action', 'format': ARG_FORMAT_STRING, 'value': b'ether.fi stake'}],
        value=1000000000000000000,
        why='User deposits ETH into ether.fi\'s LiquidityPool and is minted rebasing eETH 1:1 in value.',
        source='https://etherscan.io/address/0x308861A430be4cce5502d0A12724771Fc6DaF216 (LiquidityPool)',
    ),
    flow(
        'eigenlayer-strategymanager-deposit', 'EigenLayer', 'restaking', 'depositIntoStrategy',
        'depositIntoStrategy(address,address,uint256)', '0x858646372CC42E1Ab8f579C244C0AE3F9dcbCE72',
        ['0x93c4b944D05dfe6df7645A86cd2206016c51564D', WETH, 1000000000000000000],
        [{'name': 'strategy', 'format': ARG_FORMAT_ADDRESS, 'value': addr('0x93c4b944D05dfe6df7645A86cd2206016c51564D')},
         {'name': 'token', 'format': ARG_FORMAT_ADDRESS, 'value': addr(WETH)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000000000000, 18, 'WETH')},
         {'name': 'action', 'format': ARG_FORMAT_STRING, 'value': b'EigenLayer restake'}],
        why='User restakes a token by depositing it into a whitelisted EigenLayer strategy vault.',
        source='https://etherscan.io/address/0x858646372CC42E1Ab8f579C244C0AE3F9dcbCE72 (StrategyManager)',
    ),
    flow(
        'eigenlayer-strategymanager-deposit-steth', 'EigenLayer', 'restaking', 'depositIntoStrategy',
        'depositIntoStrategy(address,address,uint256)', '0x858646372CC42E1Ab8f579C244C0AE3F9dcbCE72',
        ['0x93c4b944D05dfe6df7645A86cd2206016c51564D', '0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84', 2000000000000000000],
        [{'name': 'strategy', 'format': ARG_FORMAT_ADDRESS, 'value': addr('0x93c4b944D05dfe6df7645A86cd2206016c51564D')},
         {'name': 'token', 'format': ARG_FORMAT_ADDRESS, 'value': addr('0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84')},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(2000000000000000000, 18, 'stETH')},
         {'name': 'action', 'format': ARG_FORMAT_STRING, 'value': b'EigenLayer restake stETH'}],
        why='Same StrategyManager entry point, restaking stETH — the most common real-world case.',
        source='https://etherscan.io/address/0x858646372CC42E1Ab8f579C244C0AE3F9dcbCE72 (StrategyManager)',
    ),
)


# ═══════════════════════════════════════════════════════════════════════
# Category: Token approvals & permits — the highest-risk category for
# wallet drainers. Precision here matters most: an unlimited approval or a
# permit's spender/amount MUST render as exactly what it is.
# ═══════════════════════════════════════════════════════════════════════

SPENDER_1 = '0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD'
PERMIT2_ADDRESS = '0x000000000022D473030F116dDEE9F6B43aC78BA3'

_register(
    flow(
        'erc20-usdc-increase-allowance', 'ERC-20 (USDC)', 'approvals', 'increaseAllowance',
        'increaseAllowance(address,uint256)', USDC,
        [SPENDER_1, 1000000000000],
        [{'name': 'spender', 'format': ARG_FORMAT_ADDRESS, 'value': addr(SPENDER_1)},
         {'name': 'addedValue', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000000, 6, 'USDC')}],
        why='The front-running-safe alternative to approve() — still grants real spending power.',
        source='https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48#code (USDC FiatTokenV2)',
    ),
    flow(
        'erc20-usdc-decrease-allowance', 'ERC-20 (USDC)', 'approvals', 'decreaseAllowance',
        'decreaseAllowance(address,uint256)', USDC,
        [SPENDER_1, 500000000000],
        [{'name': 'spender', 'format': ARG_FORMAT_ADDRESS, 'value': addr(SPENDER_1)},
         {'name': 'subtractedValue', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(500000000000, 6, 'USDC')}],
        why='Revocation counterpart to approve/increaseAllowance — legitimate when reducing a stale allowance.',
        source='https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48#code (USDC FiatTokenV2)',
    ),
    flow(
        'eip2612-usdc-permit', 'ERC-20 (USDC, EIP-2612)', 'approvals', 'permit',
        'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)', USDC,
        # v/r/s are the inner EIP-2612 signature bytes — not security-relevant
        # to DISPLAY (the user already reviewed owner/spender/value/deadline;
        # v/r/s only prove someone signed exactly that data). Placeholder
        # values here are just to make the calldata SHAPE correct for the
        # test; they don't need to verify as a real signature.
        [ZERO_ADDRESS, SPENDER_1, (2 ** 256) - 1, 1830000000, 27, b'\x00' * 32, b'\x00' * 32],
        [{'name': 'owner', 'format': ARG_FORMAT_ADDRESS, 'value': addr(ZERO_ADDRESS)},
         {'name': 'spender', 'format': ARG_FORMAT_ADDRESS, 'value': addr(SPENDER_1)},
         {'name': 'value', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value((2 ** 256) - 1, 6, 'USDC')},
         {'name': 'deadline', 'format': ARG_FORMAT_STRING, 'value': ('expires ' + _fmt_unix(1830000000)).encode()}],
        why='The #1 wallet-drainer vector in production: an off-chain gasless approval, no on-chain fee gate.',
        source='https://eips.ethereum.org/EIPS/eip-2612',
    ),
    flow(
        'permit2-approve', 'Uniswap Permit2', 'approvals', 'approve',
        'approve(address,address,uint160,uint48)', PERMIT2_ADDRESS,
        [USDC, SPENDER_1, (2 ** 160) - 1, 1830000000],
        [{'name': 'token', 'format': ARG_FORMAT_ADDRESS, 'value': addr(USDC)},
         {'name': 'spender', 'format': ARG_FORMAT_ADDRESS, 'value': addr(SPENDER_1)},
         # Metadata amount is 2**256-1, NOT the real 2**160-1 uint160 max:
         # firmware's UNLIMITED detection requires an exact 32-byte all-0xFF
         # amount (signed_metadata.c: is_max = amt_len == 32). The minimal
         # big-endian form of a uint160 max is only 20 bytes, which would
         # silently fail that check and show a raw 49-digit number instead
         # of UNLIMITED. The display arg is independent of the real calldata
         # value (which correctly encodes the true uint160 max below) —
         # 2**256-1 is simply the firmware's API for "render as unlimited".
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value((2 ** 256) - 1, 6, 'USDC')},
         {'name': 'expiration', 'format': ARG_FORMAT_STRING, 'value': ('expires ' + _fmt_unix(1830000000)).encode()}],
        why='Permit2 is a singleton router between the user\'s ERC-20 allowance and every downstream spender.',
        source='https://etherscan.io/address/0x000000000022D473030F116dDEE9F6B43aC78BA3 (Uniswap Permit2)',
    ),
    flow(
        'erc721-bayc-set-approval-for-all', 'Bored Ape Yacht Club', 'approvals', 'setApprovalForAll',
        'setApprovalForAll(address,bool)', '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D',
        [SPENDER_1, True],
        [{'name': 'operator', 'format': ARG_FORMAT_ADDRESS, 'value': addr(SPENDER_1)},
         {'name': 'approved', 'format': ARG_FORMAT_STRING, 'value': b'grants control of ALL NFTs'},
         {'name': 'collection', 'format': ARG_FORMAT_STRING, 'value': b'Bored Ape Yacht Club'}],
        why='Grants an operator blanket control over EVERY token the owner holds in this collection.',
        source='https://etherscan.io/address/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D (BAYC)',
    ),
    flow(
        'erc1155-opensea-storefront-set-approval-for-all', 'OpenSea Shared Storefront', 'approvals', 'setApprovalForAll',
        'setApprovalForAll(address,bool)', '0x495f947276749Ce646f68AC8c248420045cb7b5e',
        [SPENDER_1, True],
        [{'name': 'operator', 'format': ARG_FORMAT_ADDRESS, 'value': addr(SPENDER_1)},
         {'name': 'approved', 'format': ARG_FORMAT_STRING, 'value': b'grants control of ALL items'},
         {'name': 'collection', 'format': ARG_FORMAT_STRING, 'value': b'OpenSea Storefront'}],
        why='Identical blanket-operator risk to ERC-721, on a shared ERC-1155 storefront contract.',
        source='https://etherscan.io/address/0x495f947276749Ce646f68AC8c248420045cb7b5e (OpenStore)',
    ),
    flow(
        'usdt-approve', 'ERC-20 (USDT)', 'approvals', 'approve',
        'approve(address,uint256)', '0xdAC17F958D2ee523a2206206994597C13D831ec7',
        [SPENDER_1, 500000000],
        [{'name': 'spender', 'format': ARG_FORMAT_ADDRESS, 'value': addr(SPENDER_1)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(500000000, 6, 'USDT')}],
        why='USDT\'s approve() omits the standard non-zero-to-non-zero guard other tokens have.',
        source='https://etherscan.io/address/0xdAC17F958D2ee523a2206206994597C13D831ec7 (Tether USD)',
    ),
    flow(
        'dai-permit', 'Dai Stablecoin', 'approvals', 'permit',
        # DAI predates EIP-2612 and uses its own non-standard permit layout:
        # permit(holder,spender,nonce,expiry,allowed,v,r,s) — note the extra
        # bool `allowed` in place of a `value`: DAI permits are ALWAYS either
        # zero or unlimited, there is no partial-amount permit.
        'permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)', DAI,
        ['0x28C6c06298d514Db089934071355E5743bf21d60', SPENDER_1, 0, 1830000000, True, 27, b'\x00' * 32, b'\x00' * 32],
        [{'name': 'holder', 'format': ARG_FORMAT_ADDRESS, 'value': addr('0x28C6c06298d514Db089934071355E5743bf21d60')},
         {'name': 'spender', 'format': ARG_FORMAT_ADDRESS, 'value': addr(SPENDER_1)},
         {'name': 'allowed', 'format': ARG_FORMAT_STRING, 'value': b'grant: unlimited allowance'},
         {'name': 'expiry', 'format': ARG_FORMAT_STRING, 'value': _fmt_unix(1830000000).encode()}],
        why='DAI\'s permit is boolean allowed/not-allowed, not a partial amount — a subtle drainer trap if a '
            'wallet renders it like a normal EIP-2612 permit.',
        source='https://etherscan.io/address/0x6B175474E89094C44Da98b954EedeAC495271d0f#code (Dai Stablecoin)',
    ),
)


# ═══════════════════════════════════════════════════════════════════════
# Category: NFT transfers, governance/ENS, cross-chain bridges, core tokens
# ═══════════════════════════════════════════════════════════════════════

FROM_742 = '0x7a16Ff8270133F063aAb6C9977183D9e7283542A'

_register(
    flow(
        'erc721-safe-transfer-from', 'ERC-721 (BAYC)', 'nft-transfer', 'safeTransferFrom',
        'safeTransferFrom(address,address,uint256)', '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D',
        [FROM_742, RECIPIENT_742, 4576],
        [{'name': 'from', 'format': ARG_FORMAT_ADDRESS, 'value': addr(FROM_742)},
         {'name': 'to', 'format': ARG_FORMAT_ADDRESS, 'value': addr(RECIPIENT_742)},
         {'name': 'tokenId', 'format': ARG_FORMAT_STRING, 'value': b'NFT: BAYC #4576'}],
        why='Direct peer-to-peer ERC-721 transfer with no on-chain price/consideration.',
        source='https://etherscan.io/address/0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D (BAYC)',
    ),
    flow(
        'safe-addownerwiththreshold', 'Safe (Gnosis Safe)', 'account-abstraction', 'addOwnerWithThreshold',
        'addOwnerWithThreshold(address,uint256)', '0x1B9Cef6Bdd029f378c511E5e6C20eE556b6781b9',
        [DEADBEEF_PLACEHOLDER, 3],
        [{'name': 'owner', 'format': ARG_FORMAT_ADDRESS, 'value': addr(DEADBEEF_PLACEHOLDER)},
         {'name': '_threshold', 'format': ARG_FORMAT_STRING, 'value': b'new threshold: 3 owners'},
         {'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Safe: governance change'}],
        why='Only reachable self-referentially inside a Safe\'s own execTransaction — a malicious co-signer '
            'could try to add an attacker-controlled owner and lower the threshold to seize the Safe.',
        source='https://etherscan.io/address/0x1B9Cef6Bdd029f378c511E5e6C20eE556b6781b9 (a Safe proxy)',
    ),
    flow(
        'hop-protocol-l1-bridge-sendtol2', 'Hop Protocol', 'bridge', 'sendToL2',
        'sendToL2(uint256,address,uint256,uint256,uint256,address,uint256)', '0x3666f603Cc164936C1b87e207F36BEBa4AC5f18a',
        [137, RECIPIENT_742, 250000000, 245000000, 1830000000, ZERO_ADDRESS, 0],
        [{'name': 'chainId', 'format': ARG_FORMAT_STRING, 'value': b'destination: Polygon'},
         {'name': 'recipient', 'format': ARG_FORMAT_ADDRESS, 'value': addr(RECIPIENT_742)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(250000000, 6, 'USDC')},
         {'name': 'relayerFee', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(500000, 6, 'USDC')}],
        why='Deposits into Hop\'s L1 AMM/bridge; a bonder fronts liquidity on the destination chain.',
        source='https://etherscan.io/address/0x3666f603Cc164936C1b87e207F36BEBa4AC5f18a (Hop L1_Bridge, USDC)',
    ),
    flow(
        'wormhole-token-bridge-transfertokens', 'Wormhole', 'bridge', 'transferTokens',
        'transferTokens(address,uint256,uint16,bytes32,uint256,uint32)', '0x3ee18B2214AFF97000D974cf647E7C347E8fa585',
        [USDC, 100000000, 23, addr(RECIPIENT_742).rjust(32, b'\x00'), 0, 0],
        [{'name': 'token', 'format': ARG_FORMAT_ADDRESS, 'value': addr(USDC)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(100000000, 6, 'USDC')},
         {'name': 'recipientChain', 'format': ARG_FORMAT_STRING, 'value': b'dest: Arbitrum (Wormhole)'},
         {'name': 'recipient', 'format': ARG_FORMAT_ADDRESS, 'value': addr(RECIPIENT_742)}],
        why='Locks the ERC-20 in Token Bridge custody and emits a message Wormhole\'s guardians attest to.',
        source='https://etherscan.io/address/0x3ee18B2214AFF97000D974cf647E7C347E8fa585 (Wormhole TokenBridge)',
    ),
    flow(
        'compound-governor-bravo-castvote', 'Compound', 'governance', 'castVote',
        'castVote(uint256,uint8)', '0xc0Da02939E1441F497fd74F78cE7Decb17B66529',
        [203, 1],
        [{'name': 'proposalId', 'format': ARG_FORMAT_STRING, 'value': b'proposal ID: 203'},
         {'name': 'support', 'format': ARG_FORMAT_STRING, 'value': b'0=Against 1=For 2=Abstain'}],
        why='Casts a governance vote on Compound\'s GovernorBravo; weight is the voter\'s COMP balance/delegation.',
        source='https://etherscan.io/address/0xc0Da02939E1441F497fd74F78cE7Decb17B66529 (GovernorBravoDelegator)',
    ),
    flow(
        'ens-public-resolver-setaddr', 'ENS', 'governance', 'setAddr',
        'setAddr(bytes32,address)', '0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63',
        # Real ENS namehash("vitalik.eth"), computed via the standard
        # recursive-keccak256 algorithm (not hand-typed — the research
        # agent's transcription of this value had a truncated tail).
        [_ens_namehash('vitalik.eth'), VITALIK],
        [{'name': 'node', 'format': ARG_FORMAT_STRING, 'value': b'ENS name (namehash)'},
         {'name': 'a', 'format': ARG_FORMAT_ADDRESS, 'value': addr(VITALIK)}],
        why='Updates the ETH address a .eth name resolves to; callable only by the name\'s controller.',
        source='https://etherscan.io/address/0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63 (ENS PublicResolver)',
    ),
)


# ═══════════════════════════════════════════════════════════════════════
# Category: Yield vaults (ERC-4626 and legacy) — the "deposit into a
# strategy I trust" pattern shared by Morpho/MetaMorpho, Yearn V2/V3,
# Compound III.
# ═══════════════════════════════════════════════════════════════════════

_register(
    flow(
        'metamorpho-steakhouse-usdc-deposit', 'Morpho (Steakhouse USDC)', 'vaults', 'deposit',
        'deposit(uint256,address)', '0xBEEF01735c132Ada46AA9aA4c54623cAA92A64CB',
        [1000000000, DEADBEEF_PLACEHOLDER],
        [{'name': 'assets', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000, 6, 'USDC')},
         {'name': 'receiver', 'format': ARG_FORMAT_ADDRESS, 'value': addr(DEADBEEF_PLACEHOLDER)},
         {'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Steakhouse USDC vault'}],
        why='Standard ERC-4626 deposit into a MetaMorpho vault built on Morpho Blue.',
        source='https://etherscan.io/address/0xBEEF01735c132Ada46AA9aA4c54623cAA92A64CB (Steakhouse USDC)',
    ),
    flow(
        'metamorpho-steakhouse-usdc-withdraw', 'Morpho (Steakhouse USDC)', 'vaults', 'withdraw',
        'withdraw(uint256,address,address)', '0xBEEF01735c132Ada46AA9aA4c54623cAA92A64CB',
        [1000000000, DEADBEEF_PLACEHOLDER, DEADBEEF_PLACEHOLDER],
        [{'name': 'assets', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000, 6, 'USDC')},
         {'name': 'receiver', 'format': ARG_FORMAT_ADDRESS, 'value': addr(DEADBEEF_PLACEHOLDER)},
         {'name': 'owner', 'format': ARG_FORMAT_ADDRESS, 'value': addr(DEADBEEF_PLACEHOLDER)}],
        why='ERC-4626 withdraw burns the caller\'s (or an approved owner\'s) shares to redeem underlying USDC.',
        source='https://etherscan.io/address/0xBEEF01735c132Ada46AA9aA4c54623cAA92A64CB (Steakhouse USDC)',
    ),
    flow(
        'yearn-v2-yusdc-deposit', 'Yearn Finance (V2)', 'vaults', 'deposit',
        'deposit(uint256)', '0x5f18C75AbDAe578b483E5F43f12a39cF75b973a9',
        [1000000000],
        [{'name': '_amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000, 6, 'USDC')},
         {'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Yearn V2 yUSDC Vault'}],
        why='Legacy Yearn V2 vault mints yUSDC shares in proportion to the vault\'s price-per-share.',
        source='https://etherscan.io/address/0x5f18C75AbDAe578b483E5F43f12a39cF75b973a9 (yUSDC)',
    ),
    flow(
        'yearn-v3-aave-usdc-lender-deposit', 'Yearn Finance (V3)', 'vaults', 'deposit',
        'deposit(uint256,address)', '0xbDb97eC319c41c6FA383E94eCE6Bdf383dFC7BE4',
        [1000000000, DEADBEEF_PLACEHOLDER],
        [{'name': 'assets', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000, 6, 'USDC')},
         {'name': 'receiver', 'format': ARG_FORMAT_ADDRESS, 'value': addr(DEADBEEF_PLACEHOLDER)},
         {'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Yearn V3 Aave USDC'}],
        why='Yearn V3\'s tokenized-strategy ERC-4626 vault passes deposits through to Aave V3.',
        source='https://etherscan.io/address/0xbDb97eC319c41c6FA383E94eCE6Bdf383dFC7BE4 (Yearn V3 Aave USDC Lender)',
    ),
    flow(
        'compound-iii-comet-usdc-supply', 'Compound III (Comet)', 'vaults', 'supply',
        'supply(address,uint256)', '0xc3d688B66703497DAA19211EEdff47f25384cdc3',
        [USDC, 1000000000],
        [{'name': 'asset', 'format': ARG_FORMAT_ADDRESS, 'value': addr(USDC)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000, 6, 'USDC')},
         {'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Compound III Comet'}],
        why='Supplying USDC as the Comet base asset mints a rebasing cUSDCv3 balance earning yield.',
        source='https://etherscan.io/address/0xc3d688B66703497DAA19211EEdff47f25384cdc3 (cUSDCv3)',
    ),
)


# ═══════════════════════════════════════════════════════════════════════
# Category: Core ERC-20 / WETH primitives that round out coverage.
# ═══════════════════════════════════════════════════════════════════════

_register(
    flow(
        'weth-deposit', 'WETH9', 'core-tokens', 'deposit',
        'deposit()', WETH,
        [],
        [{'name': 'action', 'format': ARG_FORMAT_STRING, 'value': b'Wrap ETH into WETH'},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000000000000, 18, 'ETH')}],
        value=1000000000000000000,
        why='deposit() takes no calldata; the ETH being wrapped is carried entirely in the tx value.',
        source='https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 (WETH9)',
    ),
    flow(
        'weth-withdraw', 'WETH9', 'core-tokens', 'withdraw',
        'withdraw(uint256)', WETH,
        [500000000000000000],
        [{'name': 'wad', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(500000000000000000, 18, 'WETH')}],
        why='Burns wad WETH from the caller and sends wad ETH back to msg.sender.',
        source='https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 (WETH9)',
    ),
    flow(
        'erc20-transferfrom', 'ERC-20 (USDT)', 'core-tokens', 'transferFrom',
        'transferFrom(address,address,uint256)', '0xdAC17F958D2ee523a2206206994597C13D831ec7',
        [FROM_742, RECIPIENT_742, 1000000000],
        [{'name': 'action', 'format': ARG_FORMAT_STRING, 'value': b'pull from approved account'},
         {'name': 'from', 'format': ARG_FORMAT_ADDRESS, 'value': addr(FROM_742)},
         {'name': 'to', 'format': ARG_FORMAT_ADDRESS, 'value': addr(RECIPIENT_742)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000, 6, 'USDT')}],
        why='The highest-risk ERC-20 call for a hardware wallet to sign: the signer (msg.sender/spender) '
            'moves funds OUT of a DIFFERENT account (from) that pre-approved it — "from" is not the signer.',
        source='https://eips.ethereum.org/EIPS/eip-20',
    ),
)


# ═══════════════════════════════════════════════════════════════════════
# Category: more DEX swaps (V3 reverse-direction, Curve stableswap)
# ═══════════════════════════════════════════════════════════════════════

_register(
    flow(
        'uniswap-v3-exact-output-single', 'Uniswap V3', 'dex-swaps', 'exactOutputSingle',
        # ExactOutputSingleParams is a struct of only-static members -> encodes
        # head-only/inline, same rule as exactInputSingle above.
        'exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))',
        UNISWAP_V3_ROUTER2,
        [USDC, WETH, 3000, DEADBEEF_PLACEHOLDER, 1000000000000000000, 3200000000, 0],
        [{'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Uniswap V3'},
         {'name': 'tokenIn', 'format': ARG_FORMAT_ADDRESS, 'value': addr(USDC)},
         {'name': 'tokenOut', 'format': ARG_FORMAT_ADDRESS, 'value': addr(WETH)},
         {'name': 'amountOut', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000000000000, 18, 'WETH')},
         {'name': 'amountInMax', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(3200000000, 6, 'USDC')},
         {'name': 'recipient', 'format': ARG_FORMAT_ADDRESS, 'value': addr(DEADBEEF_PLACEHOLDER)}],
        abi_types=['address', 'address', 'uint24', 'address', 'uint256', 'uint256', 'uint160'],
        why='Reverse-direction swap (buy an exact output instead of spending an exact input) — '
            'the risk is amountInMax, an implicit "pay up to" ceiling.',
        source='https://etherscan.io/address/0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45 (SwapRouter02)',
    ),
    flow(
        'curve-3pool-exchange', 'Curve Finance (3pool)', 'dex-swaps', 'exchange',
        'exchange(int128,int128,uint256,uint256)', '0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7',
        [1, 2, 1000000000, 999000000],
        [{'name': 'i', 'format': ARG_FORMAT_STRING, 'value': b'sell coin index: 1 (USDC)'},
         {'name': 'j', 'format': ARG_FORMAT_STRING, 'value': b'buy coin index: 2 (USDT)'},
         {'name': 'dx', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000, 6, 'USDC')},
         {'name': 'min_dy', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(999000000, 6, 'USDT')}],
        why='3pool coin indices (0=DAI,1=USDC,2=USDT) are fixed but not self-describing on-chain — '
            'a hardware wallet must translate the index to a coin name, not show a bare "1".',
        source='https://etherscan.io/address/0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7 (Curve 3pool)',
    ),
)


# ═══════════════════════════════════════════════════════════════════════
# Category: account abstraction, cross-chain intents, and the newest
# transaction shapes (2024-2026 EIPs) — the whole point of "latest tx
# types." These all involve genuinely dynamic ABI encoding (nested
# structs/arrays with dynamic bytes members) that clearsign_abi's static-
# only encoder deliberately doesn't support, so they're hand-built here.
# Every encoding below was verified by an offline round-trip decode (build
# calldata -> read the head/tail structure back -> confirm the recovered
# values match the inputs) before being committed — see the session's
# construction notes for the exact checks. Selectors are still always
# DERIVED via clearsign_abi.selector(), never hand-typed.
# ═══════════════════════════════════════════════════════════════════════

def _bytes_tail(b):
    """[length] + data, padded to a 32-byte multiple. The standard ABI tail
    encoding for a single dynamic `bytes` value."""
    pad = (-len(b)) % 32
    return _word(len(b)) + b + b'\x00' * pad


_register(
    flow_raw(
        'erc1155-safe-transfer-from', 'ERC-1155', 'nft-transfer', 'safeTransferFrom',
        '0x495f947276749Ce646f68AC8c248420045cb7b5e',
        # safeTransferFrom(address,address,uint256,uint256,bytes) — 4 static
        # head words (from,to,id,amount) + 1 offset word for the trailing
        # `bytes data` (empty here); tail = [length=0].
        abi_selector('safeTransferFrom(address,address,uint256,uint256,bytes)')
        + _addr_word(FROM_742) + _addr_word(RECIPIENT_742)
        + _word(25675324701249476258287739024130209949696035953385936214507264967972457807873)
        + _word(1) + _word(5 * 32) + _bytes_tail(b''),
        [{'name': 'from', 'format': ARG_FORMAT_ADDRESS, 'value': addr(FROM_742)},
         {'name': 'to', 'format': ARG_FORMAT_ADDRESS, 'value': addr(RECIPIENT_742)},
         {'name': 'tokenId', 'format': ARG_FORMAT_STRING, 'value': b'NFT: OpenSea Storefront item'},
         {'name': 'quantity', 'format': ARG_FORMAT_STRING, 'value': b'quantity: 1'}],
        why='ERC-1155 amount is a raw edition count, not a decimal-scaled token amount — a '
            'wallet that runs it through TOKEN_AMOUNT formatting would show a nonsense value.',
        source='https://etherscan.io/address/0x495f947276749Ce646f68AC8c248420045cb7b5e (OpenStore)',
    ),
    flow_raw(
        'erc1155-safe-batch-transfer-from', 'ERC-1155', 'nft-transfer', 'safeBatchTransferFrom',
        '0x495f947276749Ce646f68AC8c248420045cb7b5e',
        # safeBatchTransferFrom(address,address,uint256[],uint256[],bytes) —
        # 2 static head words (from,to) + 3 offset words (ids[],amounts[],
        # data); each array tail = [length, elem0, elem1, ...], data tail
        # empty. Verified round-trip: decoding this exact byte layout
        # recovers both arrays correctly.
        abi_selector('safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)')
        + _addr_word(FROM_742) + _addr_word(RECIPIENT_742)
        + _word(5 * 32) + _word(5 * 32 + 3 * 32) + _word(5 * 32 + 6 * 32)
        + (_word(2) + _word(103581308236793043998666146738681730055218429023339494195862881700814449116832) + _word(555))
        + (_word(2) + _word(2) + _word(1))
        + _bytes_tail(b''),
        [{'name': 'from', 'format': ARG_FORMAT_ADDRESS, 'value': addr(FROM_742)},
         {'name': 'to', 'format': ARG_FORMAT_ADDRESS, 'value': addr(RECIPIENT_742)},
         {'name': 'ids', 'format': ARG_FORMAT_STRING, 'value': b'2 NFT ids in this batch'},
         {'name': 'amounts', 'format': ARG_FORMAT_STRING, 'value': b'quantities: 2, then 1'}],
        why='Atomic batch transfer of multiple ids/quantities — a wallet screen can only show a '
            'handful of typed fields, so a long batch MUST be summarized, never left as raw arrays.',
        source='https://etherscan.io/address/0x495f947276749Ce646f68AC8c248420045cb7b5e (OpenStore)',
    ),
    flow_raw(
        'uniswap-v4-universal-router-swap', 'Uniswap V4', 'dex-swaps', 'execute',
        '0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af',
        # execute(bytes commands, bytes[] inputs, uint256 deadline). There is
        # no standalone EOA-callable PoolManager.swap() in V4 — it can only
        # be invoked from inside the pool manager's own unlock() callback,
        # so ALL V4 swaps go through the Universal Router's execute(), which
        # packs one or more encoded "commands" (single bytes) + per-command
        # input blobs. Representative: one command byte (0x10 = V4_SWAP)
        # with an empty (placeholder) input blob — real command payloads are
        # themselves further ABI-encoded structs, out of scope here.
        abi_selector('execute(bytes,bytes[],uint256)')
        + _word(3 * 32) + _word(3 * 32 + len(_bytes_tail(bytes.fromhex('10')))) + _word(1830000000)
        + _bytes_tail(bytes.fromhex('10'))
        + (_word(1) + _word(0x20) + _bytes_tail(b'')),
        [{'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Uniswap V4 (Universal Router)'},
         {'name': 'commands', 'format': ARG_FORMAT_STRING, 'value': b'command: 0x10 (V4_SWAP)'},
         {'name': 'deadline', 'format': ARG_FORMAT_STRING, 'value': ('expires ' + _fmt_unix(1830000000)).encode()}],
        why='V4\'s command-based router means the swap itself is opaque bytes; the decode must at '
            'least name the protocol and the command type, not show raw commands hex.',
        source='https://github.com/Uniswap/v4-periphery (UniversalRouter, V4_SWAP command)',
    ),
    flow_raw(
        'permit2-permit-transfer-from', 'Uniswap Permit2 (SignatureTransfer)', 'approvals', 'permitTransferFrom',
        PERMIT2_ADDRESS,
        # permitTransferFrom(((address,uint256),uint256,uint256),(address,
        # uint256),address,bytes) — the permit+transferDetails structs are
        # ALL-static so they inline (7 static words: token,amount,nonce,
        # deadline,to,requestedAmount,owner) + 1 offset word for the
        # trailing `bytes signature` (a 65-byte placeholder here — this is
        # the moment funds actually move on an off-chain-signed EIP-712
        # authorization the user produced earlier).
        abi_selector('permitTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes)')
        + _addr_word(USDC) + _word(250000000000) + _word(0) + _word(1830000000)
        + _addr_word(SPENDER_1) + _word(250000000000)
        + _addr_word(DEADBEEF_PLACEHOLDER) + _word(8 * 32)
        + _bytes_tail(b'\x00' * 65),
        [{'name': 'token', 'format': ARG_FORMAT_ADDRESS, 'value': addr(USDC)},
         {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(250000000000, 6, 'USDC')},
         {'name': 'recipient', 'format': ARG_FORMAT_ADDRESS, 'value': addr(SPENDER_1)},
         {'name': 'deadline', 'format': ARG_FORMAT_STRING, 'value': ('expires ' + _fmt_unix(1830000000)).encode()}],
        why='The authorization for this transfer was a PURE off-chain EIP-712 signature made earlier '
            '(often on a phishing site) — this call is the moment the funds actually move.',
        source='https://github.com/Uniswap/permit2 (SignatureTransfer.permitTransferFrom)',
    ),
    flow_raw(
        'across-spokepool-depositv3', 'Across Protocol', 'bridge', 'depositV3',
        '0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5',
        # depositV3(depositor,recipient,inputToken,outputToken,inputAmount,
        # outputAmount,destinationChainId,exclusiveRelayer,quoteTimestamp,
        # fillDeadline,exclusivityDeadline,bytes message) — an ERC-7683-
        # style cross-chain intent: 11 static head words + 1 offset word for
        # the trailing `bytes message` (empty).
        abi_selector('depositV3(address,address,address,address,uint256,uint256,uint256,address,uint32,uint32,uint32,bytes)')
        + _addr_word(RECIPIENT_742) + _addr_word('0x9406Cc6185a346906296840746125a0E44976454')
        + _addr_word(USDC) + _addr_word('0xaf88d065e77c8cC2239327C5EDb3A432268e5831')
        + _word(1000000000) + _word(995000000) + _word(42161)
        + _addr_word(ZERO_ADDRESS)
        + _word(1751000000) + _word(1830000000) + _word(0)
        + _word(12 * 32) + _bytes_tail(b''),
        [{'name': 'inputToken', 'format': ARG_FORMAT_ADDRESS, 'value': addr(USDC)},
         {'name': 'inputAmount', 'format': ARG_FORMAT_TOKEN_AMOUNT, 'value': token_amount_value(1000000000, 6, 'USDC')},
         {'name': 'outputToken', 'format': ARG_FORMAT_ADDRESS, 'value': addr('0xaf88d065e77c8cC2239327C5EDb3A432268e5831')},
         {'name': 'recipient', 'format': ARG_FORMAT_ADDRESS, 'value': addr('0x9406Cc6185a346906296840746125a0E44976454')},
         {'name': 'destination', 'format': ARG_FORMAT_STRING, 'value': b'destination: Arbitrum One'}],
        why='ERC-7683-style intent bridge: locks the input token so an unbonded relayer can front '
            'the output token on the destination chain — the signature doesn\'t show final asset '
            'movement, so the decode must make output token/amount/chain explicit.',
        source='https://etherscan.io/address/0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5 (Across SpokePool)',
    ),
    flow_raw(
        'safe-exectransaction', 'Safe (Gnosis Safe)', 'account-abstraction', 'execTransaction',
        '0x1B9Cef6Bdd029f378c511E5e6C20eE556b6781b9',
        # execTransaction(to,value,bytes data,operation,safeTxGas,baseGas,
        # gasPrice,gasToken,refundReceiver,bytes signatures) — 8 static head
        # words + 2 offset words (data, signatures). operation=0 (CALL);
        # operation=1 (DELEGATECALL) would run arbitrary code AS the Safe —
        # the single highest-stakes field in this call. data=empty (a plain
        # value-transfer through the Safe); signatures=a 65-byte placeholder
        # (real execution needs >=threshold owner signatures packed here).
        abi_selector('execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)')
        + _addr_word(USDC) + _word(0) + _word(10 * 32) + _word(0)
        + _word(150000) + _word(0) + _word(0)
        + _addr_word(ZERO_ADDRESS) + _addr_word(ZERO_ADDRESS)
        + _word(10 * 32 + len(_bytes_tail(b'')))
        + _bytes_tail(b'') + _bytes_tail(b'\x00' * 65),
        [{'name': 'to', 'format': ARG_FORMAT_ADDRESS, 'value': addr(USDC)},
         {'name': 'operation', 'format': ARG_FORMAT_STRING, 'value': b'call type: 0=CALL'},
         {'name': 'gasBudget', 'format': ARG_FORMAT_STRING, 'value': b'gas budget: 150000'},
         {'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Safe: execute transaction'}],
        why='A co-signing Safe owner signs this off-chain "Safe transaction hash" with their hardware '
            'wallet before relaying; operation=1 (DELEGATECALL) would run arbitrary code as the Safe '
            'itself — the single field a wallet must never let slide by unshown.',
        source='https://etherscan.io/address/0x1B9Cef6Bdd029f378c511E5e6C20eE556b6781b9 (a Safe proxy)',
    ),
    flow_raw(
        'erc4337-entrypoint-v0.7-handleops', 'ERC-4337 Account Abstraction', 'account-abstraction', 'handleOps',
        '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
        # handleOps(PackedUserOperation[] ops, address beneficiary) — a
        # bundler-submitted meta-transaction. Each UserOperation is itself a
        # 9-field struct with FOUR dynamic bytes members (initCode, callData,
        # paymasterAndData, signature), making this array-of-dynamic-tuples
        # the deepest nesting in this catalog. Representative: ONE UserOp
        # with all four dynamic fields empty (real ones carry a decoded
        # inner call — see the callDataSummary display arg for what a host
        # would show once it decodes callData separately). Verified via an
        # offline round-trip decode that recovers `sender` and `nonce` from
        # inside the nested structure byte-for-byte.
        abi_selector('handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)')
        + _word(2 * 32) + _addr_word('0x' + '43' * 20)
        + (_word(1) + _word(0x20) + (
            _addr_word('0x9406Cc6185a346906296840746125a0E44976454') + _word(12) +
            _word(9 * 32) + _word(9 * 32 + len(_bytes_tail(b''))) +
            b'\x00' * 32 + _word(50000) + b'\x00' * 32 +
            _word(9 * 32 + 2 * len(_bytes_tail(b''))) + _word(9 * 32 + 3 * len(_bytes_tail(b''))) +
            _bytes_tail(b'') + _bytes_tail(b'') + _bytes_tail(b'') + _bytes_tail(b'')
        )),
        [{'name': 'sender', 'format': ARG_FORMAT_ADDRESS, 'value': addr('0x9406Cc6185a346906296840746125a0E44976454')},
         {'name': 'nonce', 'format': ARG_FORMAT_STRING, 'value': b'UserOperation nonce: 12'},
         {'name': 'beneficiary', 'format': ARG_FORMAT_ADDRESS, 'value': addr('0x' + '43' * 20)},
         {'name': 'innerCall', 'format': ARG_FORMAT_STRING, 'value': b'empty (representative)'}],
        why='A bundler-submitted meta-tx: the EntryPoint singleton validates and executes a batch of '
            'smart-account operations. KNOWN GAP, disclosed: this representative UserOp carries an '
            'EMPTY inner callData (the array-of-dynamic-tuples nesting is beyond the current static '
            'ABI encoder), so this flow proves sender/nonce/beneficiary are decoded but does NOT '
            'prove the inner callData — what the smart account will actually do — is decoded. A real '
            'UserOp with non-empty callData would need it decoded and shown, never left as an opaque '
            'blob one layer inside another; that inner-decode capability is future work.',
        source='https://etherscan.io/address/0x0000000071727De22E5E9d8BAf0edAc6f37da032 (EntryPoint v0.7)',
    ),
)


# ═══════════════════════════════════════════════════════════════════════
# EIP-7702 (Pectra): NOT a contract call. A type-0x04 transaction embeds an
# `authorization_list` of (chain_id, address, nonce, y_parity, r, s) tuples;
# signing one installs `0xef0100 || address` as the SIGNING EOA's own code,
# turning it into a smart account. There is no "to"/calldata in the usual
# sense — the security-critical fact is the DELEGATE address the account is
# handing its execution to. Represented here with a synthetic legacy-style
# tx shape (to=self, empty data) purely so it fits this catalog's tx-hash-
# binding test harness; the REAL security review is the delegate address in
# `args`, not calldata bytes (there are none).
# ═══════════════════════════════════════════════════════════════════════

_register(
    flow_raw(
        'eip7702-setcode-authorization', 'EIP-7702 (Set Code for EOAs)', 'account-abstraction', 'authorization',
        '0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9',
        # Not a function call — no real selector exists. A 4-byte marker
        # (the tx type byte + padding) keeps this flow flowing through the
        # same tx_hash-binding/metadata machinery as every other catalog
        # entry without special-casing the test harness.
        b'\x04\x00\x00\x00',
        [{'name': 'txType', 'format': ARG_FORMAT_STRING, 'value': b'NEW: type-0x04 (EIP-7702)'},
         {'name': 'delegate', 'format': ARG_FORMAT_ADDRESS,
          'value': addr('0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9')},
         {'name': 'chainScope', 'format': ARG_FORMAT_STRING,
          'value': b'chain 1 only (0 = ALL chains)'},
         {'name': 'effect', 'format': ARG_FORMAT_STRING,
          'value': b'EOA becomes alias for this code'}],
        why='This EOA is authorizing delegation to a contract — NOT a normal contract call. '
            'A malicious 7702 delegation disguised as a routine signature is effectively account '
            'takeover; the delegate address must be shown with the same weight as a recipient.',
        source='https://eips.ethereum.org/EIPS/eip-7702',
    ),
)
