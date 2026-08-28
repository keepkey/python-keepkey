"""Which ERC-20s earn their place in firmware flash.

The built-in token table is the single largest read-only symbol in the ARM
image -- 31,104 bytes of `tokens` for 1,945 entries, larger than MessagesMap or
the BIP-39 wordlist. It exists so the device can render "10.5 DAI" instead of a
raw amount against a bare contract address.

It cannot be complete, and should not try to be. Two facts settle that:

  * The vetted source (ethereum-lists) is a SNAPSHOT and is stale. It has no
    UNI, no AAVE, no stETH, no PEPE, none of the modern stables (FRAX, PYUSD,
    crvUSD, USDe), and its `ARB` entry is a 2018 token called "ARBITRAGE", not
    Arbitrum's. Shipping 1,945 entries does not make the table current; it
    makes it 1,945 entries of mostly-2018 long tail.
  * Anything outside the table is not undisplayable -- it is the clear-sign
    provider's job, which is exactly the direction
    docs/security/token-table-retirement.md sets out.

So the table's job is narrow: the assets a user is most likely to hold, whose
addresses this repository can actually vouch for. Everything else is a provider
schema away.

POLICY
  1. A budget, because flash is finite and this symbol is the biggest one.
  2. Priority symbols first -- stablecoins, then majors.
  3. A priority symbol is only taken when the vetted source gives it exactly
     ONE address. Two entries sharing a symbol is how a scam token inherits a
     real one's label, and the device would render the attacker's name.
  4. Remaining budget filled in the existing deterministic order (by address),
     so the result is reproducible and diffable.

Addresses are NEVER written here. They come from the vetted source, matched by
symbol. A hand-typed address in a token table is a mislabelling defect waiting
to happen, and this file must not become the place one appears.
"""

# 500 entries * 16 bytes = ~8 KB, against 31 KB today.
TOKEN_BUDGET = 500

# Split across the two generators, which emit into one array.
BUDGET_ETHEREUM_LISTS = 350
BUDGET_UNISWAP_LIST = 150

STABLECOINS = [
    "USDC", "USDT", "DAI", "TUSD", "BUSD", "USDP", "GUSD", "SAI",
    "EURS", "EURT", "sUSD", "USDS", "FRAX", "LUSD", "PYUSD", "crvUSD", "USDe",
]

MAJORS = [
    "WETH", "WBTC", "stETH", "wstETH", "rETH", "cbETH", "LINK", "UNI", "AAVE",
    "MKR", "LDO", "CRV", "SNX", "COMP", "ENS", "GRT", "MATIC", "ARB", "OP",
    "SHIB", "PEPE", "APE", "SAND", "MANA", "AXS", "IMX", "INJ", "RNDR", "FET",
    "STG", "BAL", "1INCH", "SUSHI", "YFI", "BAT", "ZRX", "KNC", "LRC", "GNO",
    "RPL", "FXS", "CVX", "PAXG", "AMPL", "OMG", "REP", "ZIL", "ENJ", "STORJ",
    "GUSD",
]

# Required by coins[] in the firmware, not by popularity. Each of these is a
# display-only entry in the device's own coin table carrying a contract
# address, and unittests/firmware/coins.cpp (Coins.TableSanity) asserts every
# one of them resolves UNIQUELY in this token table. Dropping any is a build
# failure, correctly: the device would advertise a coin it cannot name.
#
# They are overwhelmingly 2017-era ICO tokens and are exactly the long tail
# this budget exists to cut -- but the cut has to happen in coins[] first, and
# coins[] is itself a 23,808-byte symbol. That is the next reduction, not this
# one. See docs/security/token-table-retirement.md.
REQUIRED_BY_COINS = [
    "0xBTC", "1ST", "AE", "ANT", "CVC", "DGD", "ELF", "FOX", "FUN", "GNT",
    "GUP", "ICN", "MLN", "MTL", "PAY", "POLY", "PPT", "RCN", "RLC", "SALT",
    "SNGLS", "SNT", "SPANK", "SWT", "TRST", "WINGS",
]

# Required by a TEST FIXTURE rather than by the product. ADT (AdToken) is a
# 2017 ICO token that test_ethereum_signtx_knownerc20_eip_1559 uses as its
# canonical "known ERC-20", asserting a hardcoded signature over a transfer to
# its address -- so dropping it fails the suite, and the fixture cannot be
# repointed at a current token without regenerating that signature.
#
# It is listed separately and deliberately: a fixture should not get to pin
# firmware flash. Migrating that test to USDC (which every user actually holds)
# retires this entry, and is tracked as fixture debt rather than done here,
# because changing a signature fixture is a change to what the test proves.
REQUIRED_BY_TESTS = ["ADT"]

PRIORITY_SYMBOLS = (REQUIRED_BY_COINS + REQUIRED_BY_TESTS
                    + STABLECOINS + MAJORS)


def select(records, budget, symbol_of, address_of, chain_of=None):
    """Return `records` trimmed to `budget`, priority symbols first.

    `records` is any iterable; `symbol_of`/`address_of` pull the two fields.
    Priority symbols with more than one address in `records` are DROPPED from
    the priority pass -- see rule 3 -- though they may still be picked up by
    the deterministic fill, where they carry no special standing.

    `chain_of` supplies the chain id. A token's identity is (chain_id,
    address), NOT address alone: the vetted source carries the same address on
    several chains -- 0x0000..0000 is listed as BURNER under EXP (2), OP (10)
    and MATIC (137) -- and deduplicating on address alone silently dropped
    every chain after the first from the generated firmware table. Left as
    None the key falls back to address alone, which is only correct for a
    single-chain source.
    """
    if chain_of is None:
        chain_of = lambda r: None

    def key_of(r):
        return (chain_of(r), address_of(r))
    records = list(records)
    by_symbol = {}
    for r in records:
        by_symbol.setdefault(symbol_of(r), []).append(r)

    chosen, seen = [], set()
    ambiguous = []
    for sym in PRIORITY_SYMBOLS:
        hits = by_symbol.get(sym, [])
        if len(hits) > 1:
            ambiguous.append(sym)
            continue
        for r in hits:
            key = key_of(r)
            if key not in seen:
                seen.add(key)
                chosen.append(r)

    for r in sorted(records, key=address_of):
        if len(chosen) >= budget:
            break
        key = key_of(r)
        if key not in seen:
            seen.add(key)
            chosen.append(r)

    return chosen[:budget], ambiguous
