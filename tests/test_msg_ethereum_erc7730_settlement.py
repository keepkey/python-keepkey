"""Seaport phishing protection: what the signer receives (7.17).

A drainer site asks the victim to sign a Seaport order that gives away the
victim's NFT and pays the victim nothing (one wei to a stranger, or the real
payments with the seller's own payment redirected), or a payment that only
looks like one: one wei, or a token the attacker made. Through 7.17's first
Seaport definition every such order signed under "Verified by KeepKey" with
the same calm screens as a real listing.

A typed-data definition may now opt in to a settlement review: it marks the
type, identifier and amounts of every item of the order, and the recipient
of each item it pays out ("settlement": "type", "id", "amount", "to"); an
item without a recipient is one the order gives away. The device keeps what
is paid to the signing address it derives itself, and what is given, and
after the definition's last field shows both sides on a screen the
definition cannot change or skip: "You give:" (every item given) and "You
receive:" (net of the same coin given; WETH nets as ETH). The device has no
prices, so the screen never calls an order fair: it is a neutral "Order
summary", or "WARNING" with one line per fact the device can tell from the
order: nothing received net, only unknown tokens or NFTs for what it gives,
every known coin under a floor, a given item it could not read, an NFT item
naming a coin or 0xEeee...EEeE, an ERC-721 ID of 2^64 or more outside the
collections it knows, or an unknown ERC-20 given. What is signed never
changes, and every value is still shown exactly once.

An item whose type is marked is also shown as Seaport moves it: an NFT
item's amount reads as its identifier and count ("NFT ID 446", "2 of NFT ID
650", "1 NFT by criteria"), never as an amount of its token, because Seaport
moves an ERC-721 item by its identifier whatever its token is. An NFT item
naming a coin of the firmware's table (an ERC-721 "WETH" moves its identifier
in wei of WETH) makes the last screen a warning. The other way round,
Seaport moves an ERC-20 item with transferFrom(from, to, amount), which an
ERC-721 answers too: an ERC-20 item naming an NFT collection gives the NFT
whose ID is the amount. So giving an ERC-20 the table does not list on the
chain makes the last screen a warning.

The floor is counted in units, not value: 0.0001 of one coin, or 0.01 of
one for six decimals or fewer (one base unit of USDC is under it). Paying
above it removes that line, never the side given.

On the certified tier ("Verified by KeepKey") the firmware refuses a Seaport
OrderComponents definition without the settlement review (firmware unit
test); these tests sign on the runtime tier, which is not bound.

Wallets compared (2026-10): Ledger and Trezor show the typed-data fields and
have no on-device rule over who is paid in a Seaport order; Blockaid
(MetaMask), Pocket Universe and Rabby simulate the order on the host and warn
there. This check runs on the device, from the signed bytes.

Real orders: thirteen OpenSea Seaport 1.6 listings rebuilt from their
fulfillBasicOrder fills (order hash equals the OrderFulfilled event, the
signature recovers the offerer), as this wallet would sign them: the offerer
and the seller's payment are this wallet. The phishing orders are derived
from them. The device signs with the "abandon" test mnemonic; signatures are
compared with plain streaming, and the definition is signed by the throwaway
runtime key (AdvancedMode, "NOT verified by KeepKey").
"""

import copy
import re
from decimal import Decimal

import common
from keepkeylib import erc7730, erc7730_compiler
from keepkeylib import messages_ethereum_pb2 as eth
from keepkeylib import types_pb2 as types
from test_msg_ethereum_erc7730_runtime import Erc7730Harness, assert_failure
from test_msg_ethereum_erc7730_typed_iteration import (
    CREATOR, CREATOR_FEE, LISTING, OPENSEA_FEE, ORDER_FORMAT, PATH,
    SEAPORT_DOMAIN, SEAPORT_TYPES, ZERO, ZERO32)

# The "abandon ... about" mnemonic at m/44'/60'/0'/0/0.
SIGNER = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
STRANGER = "0x00000000000000000000000000000000DeaDBeef"
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
WORTHLESS = "0x1111111111111111111111111111111111111111"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
USDE = "0x4c9EDD5852cd905f086C759E8383e09bff1E68B3"
STETH = "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84"  # not in the table
APE = "0x4d224452801ACEd8B2F0aebE155379bb5D594381"  # not in the table
# ERC-20s the table does not list, and no firmware list names (review r3).
LDO = "0x5A98FcBEA516Cf06857215779Fd812CA3beF1B32"
RETH = "0xae78736Cd615f374D3085123A210448E74Fc6393"
# Chain-1 ERC-721s whose live IDs are hashes or packed (review r3; each ID
# moved on chain, ~/keepkey-audit-rigs batch6
# sources/hashed-ids-onchain-6d.json).
HASHED_ID = [
    ("0xD1E5b0FF1287aA9f9A268759062E4Ab08b9Dacbe",  # Unstoppable .crypto
     "2640479375954687368405108873679577913755247171701477055198822272924474"
     "546773"),
    ("0xF87E31492Faf9A91B02Ee0dEAAd50d51d56D5d4d",  # Decentraland LAND
     "1157920892373161954235709850086879078505477257302730563317505871484589"
     "83948410"),
    ("0x2A187453064356c898cAe034EAed119E1663ACb8",  # Decentraland Names
     "1104886426554971316873225178934451429952489820850483521117029452396656"
     "89743296"),
    ("0x629A673A8242c2AC4B7B8C5D8735fbeac21A6205",  # Sorare
     "8486410100290593993614660320003782926703175571181795977402868013196166"
     "933584"),
    ("0xF6793dA657495ffeFF9Ee6350824910Abc21356C",  # Rarible
     "4198952414451092601333812763749611905246708960792447852956960428300143"
     "1130114"),
]
# Review r4: the hashed-ID list from real data. The eight chain-1 ERC-721s
# with the most Seaport 1.6 listings moving IDs of 2^64 or more over blocks
# 26263701-26313700, each read on chain; each ID is one a real listing sold
# (~/keepkey-audit-rigs batch6 sources/hashed-ids-from-fills-6d.json).
HASHED_ID_R4 = [
    ("0x20262e3433306a4FF250a64d20a8E0F09B2C7F68",  # ENS Commemorative
     "4800339746304215113505442909383013170834154924283749081808552991793306"
     "7218499"),
    ("0x0bfa9AFF76FD91756F837Ab47e11BD99e04C15bD",  # Unetwork Operator Software License
     "4576591384459525819354822824087780623876878923053159931781766556648552"
     "9869688"),
    ("0x572E33FFa523865791aB1C26B42a86aC244Df784",  # Gucci
     "340282366920938542673693659940582850561"),
    ("0x51bd5948CF84a1041d2720F56DEd5e173396FC95",  # Zer0 Name Service
     "7956835364388832789985426334073616726165905345450434453319174395065344"
     "2050388"),
    ("0x05F81F870cBca79E9171f22886b58b5597A603AA",  # Zer0 Name Service
     "1889289441097877424889029978620228441072846434811872990092939913119975"
     "2586985"),
    ("0x741512954Cb6f8e5d3cD9321c07462b05B7cC8D5",  # OKX AI NFT
     "4894621097800733791606173110553506964654181500179553434699681112865701"
     "7831425"),
    ("0xc2e9678A71e50E5AEd036e00e9c5caeb1aC5987D",  # Zero Name Service
     "5804190919614418592259370525208415466303453209166590916760934043604458"
     "3769244"),
    ("0xc9154424B823b10579895cCBE442d41b9Abd96Ed",  # Rarible
     "2826039867819840215306711511831437299585336968281979299548049622915281"
     "322105"),
]
# Chain-1 ERC-20s the table does not list that the firmware names as never an
# NFT (review r3): symbol, contract.
NEVER_NFT = [
    ("cbBTC", "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf"),
    ("PYUSD", "0x6c3ea9036406852006290770BEdFcAbA0e23A0e8"),
    ("XAUt", "0x68749665FF8D2d112Fa859AA293F07A622782F38"),
    ("EURC", "0x1aBaEA1f7C830bD89Acc67eC4af516284b1bC33c"),
    ("stETH", STETH),
    ("wstETH", "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"),
    ("USDe", USDE),
    ("APE", APE),
]
UD = "0x049aba7510f45BA5b64ea9E658E342F904DB358D"  # Unstoppable Domains
DCN = "0x08d32b0da63e2C3bcF8019c9c5d849d7a9d791e6"
EEEE = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"
CONDUIT = "0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000"
SELLER = "seller"  # the real offerer: this wallet in every test

REAL_ORDERS = [
    # 0x6a99d606f13ab4379635426908cdbcc0dd8d04aa510a9dc8e76ff7e53281a9ce
    (137, [(3, '0x22d5f9B75c524Fec1D6619787e582644CD4D7422', '446', '1')],
     [(1, '0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619', '3613500000000000', SELLER),
      (1, '0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619', '36500000000000', OPENSEA_FEE)],
     0, '1793306151', '1793910951',
     '27855337018906766782546881864045825683096516384821792734234868703509530967094',
     '0'),
    # 0x5b7c66b708716a7138cfd0ddb3f2329b542592b6eb9d72f4e307d1f6deb734cd
    (137, [(2, '0x251BE3A17Af4892035C37ebf5890F4a4D889dcAD', '34359448840295777673655050614723288121325103585739033537781777436162294190250', '1')],
     [(1, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', '13206000', SELLER),
      (1, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', '142000', OPENSEA_FEE),
      (1, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', '852000', '0x732134D7f99b90C704d736B360dB45425073380f')],
     0, '1793396070', '1798580070',
     '27855337018906766782546881864045825683096516384821792734247637289137771993225',
     '0'),
    # 0x3adf19be32efec69cd9440299f763cca49fb129c6fa3393b7e33c504fcf2eb64
    (137, [(2, '0x251BE3A17Af4892035C37ebf5890F4a4D889dcAD', '60105492021038956789376004874433832340660385680807576982244478177608196469233', '1')],
     [(1, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', '23250000', SELLER),
      (1, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', '250000', OPENSEA_FEE),
      (1, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', '1500000', '0x732134D7f99b90C704d736B360dB45425073380f')],
     0, '1793394838', '1793398438',
     '27855337018906766782546881864045825683096516384821792734239831000570884848736',
     '0'),
    # 0x529284af5624ef9907cb59fce6528deeb464cbc15f8604957ce70cdf7add7908
    (42161, [(2, '0xC227e25544EdD261A9066932C71a25F4504972f1', '10925', '1')],
     [(0, '0x0000000000000000000000000000000000000000', '51965100000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '524900000000000', OPENSEA_FEE)],
     0, '1793388508', '1801164508',
     '27855337018906766782546881864045825683096516384821792734238018274238790998880',
     '0'),
    # 0xf6592a9d697431fed763548254b96e645cb14981d267874977d814c304d74f8e
    (42161, [(2, '0xC227e25544EdD261A9066932C71a25F4504972f1', '51611', '1')],
     [(0, '0x0000000000000000000000000000000000000000', '51876000000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '524000000000000', OPENSEA_FEE)],
     0, '1793337530', '1801113530',
     '27855337018906766782546881864045825683096516384821792734249439184772095363824',
     '0'),
    # 0xd0d26059399cc15d4adc71126007a6fcfa6e9a8180d3907773703979d72e08b5
    (43114, [(3, '0xa695ea0C90D89a1463A53Fa7a02168Bc46FbBF7e', '650', '2')],
     [(0, '0x0000000000000000000000000000000000000000', '55242000000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '558000000000000', OPENSEA_FEE)],
     1, '1793025427', '1793630227',
     '44352388033253391722174868795062602107181742468261888849129876456468951810407',
     '160192324572955410065383452032537714378'),
    # 0xc27875074f7e1e3a2f18d3077c2e548d5e3c537f8f818ef0cf5f4e12ec97fb26
    (43114, [(3, '0xa695ea0C90D89a1463A53Fa7a02168Bc46FbBF7e', '370', '1')],
     [(0, '0x0000000000000000000000000000000000000000', '67679060000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '719990000000000', OPENSEA_FEE),
      (0, '0x0000000000000000000000000000000000000000', '3599950000000000', '0x6F27aA71Ee313F39D2071dE0554cE55900148184')],
     0, '1793396575', '1801172575',
     '27855337018906766782546881864045825683096516384821792734236904970083784339576',
     '0'),
    # 0x61f5a0971954c7b35750f05e85ecbcf035330db4ae4997ecb24334bbf1d1b64d
    (43114, [(3, '0xa695ea0C90D89a1463A53Fa7a02168Bc46FbBF7e', '250', '2')],
     [(0, '0x0000000000000000000000000000000000000000', '29502000000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '298000000000000', OPENSEA_FEE)],
     1, '1793318538', '1793923338',
     '47116205494824075209979464729591148675478147799213783147724356185403060327312',
     '160192324572955410065383452032537714378'),
    # 0xa6ac44a7546bb1cf4ff927cf39b6bf5d47e5df1cb01bc24e8463bf7b2d437eb0
    (8453, [(2, '0xEB485363a50198B14589107c296A0d8a70479c08', '3', '1')],
     [(0, '0x0000000000000000000000000000000000000000', '25000000000000', SELLER)],
     0, '1793407456', '1793414656',
     '1793407516274553',
     '0'),
    # 0x04c7c59ba10478fbd43224714d4f3841b6f6cc37e47270ca2f5867bcd601a295
    (8453, [(2, '0xEB485363a50198B14589107c296A0d8a70479c08', '2', '1')],
     [(0, '0x0000000000000000000000000000000000000000', '19800000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '200000000000', OPENSEA_FEE)],
     0, '1793407014', '1793414214',
     '1793407134058854',
     '0'),
    # 0xbe11a1aaca3e1685f9d1b3cac86dbdf87c98e1f67d70b708b0251e9b2e7af8e7
    (8453, [(2, '0xEB485363a50198B14589107c296A0d8a70479c08', '1', '1')],
     [(0, '0x0000000000000000000000000000000000000000', '22250000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '250000000000', OPENSEA_FEE),
      (0, '0x0000000000000000000000000000000000000000', '2500000000000', '0x036CdBD5d44524e796029E54eDCb1576e129592F')],
     0, '1793406712', '1793579512',
     '27855337018906766782546881864045825683096516384821792734240101351710316449337',
     '0'),
]


def _role(roles, name, params=None):
    params = dict(params or {})
    if roles:
        params["settlement"] = name
    return params


def _item_fields(prefix, roles):
    """Seaport item fields, as batch 6-D's definition shows them; with
    `roles`, the type, identifier and amounts are marked (an offer item has
    no recipient, so it is given)."""
    def amount(path, label):
        return {"path": path, "label": label, "format": "tokenAmount",
                "params": _role(roles, "amount", {
                    "tokenPath": "token", "nativeCurrencyAddress": [ZERO]})}
    return [
        {"path": "itemType", "label": prefix + " type", "format": "enum",
         "params": _role(roles, "type",
                         {"$ref": "$.metadata.enums.itemType"})},
        {"path": "identifierOrCriteria", "label": prefix + " ID/criteria",
         "format": "raw", "params": _role(roles, "id")},
        amount("startAmount", prefix + " amount"),
        amount("endAmount", prefix + " end amount")]


def seaport_descriptor(roles=True):
    """The Seaport 1.6 OrderComponents definition; with `roles`, its fields
    carry their settlement roles."""
    return {
        "metadata": {"owner": "OpenSea", "enums": {
            "itemType": {"0": "Native coin", "1": "ERC-20",
                         "2": "NFT (ERC-721)", "3": "ERC-1155",
                         "4": "ERC-721 by criteria",
                         "5": "ERC-1155 by criteria"},
            "orderType": {"0": "Full, open", "1": "Partial, open",
                          "2": "Full, restricted", "3": "Partial, restricted",
                          "4": "Contract order"}}},
        "display": {"formats": {ORDER_FORMAT: {
            "intent": "Seaport order",
            "fields": [
                {"path": "offerer", "label": "Offerer",
                 "format": "addressName"},
                {"path": "offer.[]", "label": "You give",
                 "fields": _item_fields("Give", roles)},
                {"path": "consideration.[]", "label": "Paid out",
                 "fields": _item_fields("Payment", roles) + [
                     {"path": "recipient", "label": "Paid to",
                      "format": "addressName",
                      "params": _role(roles, "to", {"recipient": True})}]},
                {"path": "startTime", "label": "Starts", "format": "date",
                 "params": {"encoding": "timestamp"}},
                {"path": "endTime", "label": "Expires", "format": "date",
                 "params": {"encoding": "timestamp"}},
                {"path": "orderType", "label": "Order type", "format": "enum",
                 "params": {"$ref": "$.metadata.enums.orderType"}},
                {"path": "zone", "label": "Zone", "format": "addressName"},
                {"path": "zoneHash", "label": "Zone hash", "format": "raw"},
                {"path": "conduitKey", "label": "Conduit key",
                 "format": "raw"},
                {"path": "salt", "label": "Salt", "format": "raw"},
                {"path": "counter", "label": "Counter", "format": "raw"}]}}}}


def _real(order):
    chain, offer, consideration, order_type, start, end, salt, counter = order
    return {
        "types": SEAPORT_TYPES,
        "primaryType": "OrderComponents",
        "domain": dict(SEAPORT_DOMAIN, chainId=chain),
        "message": {
            "offerer": SIGNER,
            "zone": ZERO,
            "offer": [{"itemType": t, "token": token,
                       "identifierOrCriteria": i, "startAmount": a,
                       "endAmount": a} for t, token, i, a in offer],
            "consideration": [
                {"itemType": t, "token": token, "identifierOrCriteria": "0",
                 "startAmount": a, "endAmount": a,
                 "recipient": SIGNER if to == SELLER else to}
                for t, token, a, to in consideration],
            "orderType": order_type,
            "startTime": start,
            "endTime": end,
            "zoneHash": ZERO32,
            "salt": salt,
            "conduitKey": CONDUIT,
            "counter": counter}}


def _as_signer(doc):
    """A real mainnet listing as this wallet would sign it."""
    doc = copy.deepcopy(doc)
    seller = doc["message"]["offerer"]
    doc["message"]["offerer"] = SIGNER
    for item in doc["message"]["consideration"]:
        if item["recipient"] == seller:
            item["recipient"] = SIGNER
    return doc


def _paid(doc, *items):
    """`doc` paying `items` instead: (itemType, token, amount, recipient[,
    end amount[, identifier]])."""
    doc = copy.deepcopy(doc)
    doc["message"]["consideration"] = [
        {"itemType": item[0], "token": item[1],
         "identifierOrCriteria": item[5] if len(item) > 5 else "0",
         "startAmount": item[2],
         "endAmount": item[4] if len(item) > 4 else item[2],
         "recipient": item[3]} for item in items]
    return doc


MAINNET = [_as_signer(LISTING), _as_signer(CREATOR_FEE)]
NATIVE = {1: "ETH", 8453: "ETH", 42161: "ETH", 43114: "AVAX"}
SUMMARY = "Order summary"
NOTHING = "Nothing in this order is paid to this wallet."
BACK = "This wallet gets back no more than it gives."
UNKNOWN = "This wallet gets only unknown tokens or NFTs."
COIN_WETH = ("An NFT item names the token WETH: Seaport moves its ID as an "
             "amount of WETH.")
LARGE_ID = ("An NFT ID is 2^64 or more: if its contract is a token, Seaport "
            "moves that many units of it.")
NFT = LISTING["message"]["offer"][0]["token"]
GIVES_UNKNOWN = ("This wallet gives a token the device does not know: if it "
                 "is an NFT collection, Seaport moves the NFT whose ID is the "
                 "amount.")
CRITERIA = ("This wallet gives an item by criteria: the buyer picks its ID "
            "(on a token, the ID is an amount).")
MORE_ITEMS = "This wallet gives more items than this screen lists."


def _under(coin):
    return "This wallet gets under %s." % coin


def _screen(warnings, give, receive):
    """The settlement screen: its title, then its warning lines and both
    sides."""
    body = "".join(line + "\n" for line in warnings)
    body += "You give:\n%s\nYou receive:\n%s" % (give, receive)
    return ("WARNING" if warnings else SUMMARY, body)


def _nft(item_type, token, identifier, amount):
    """An NFT item as the device shows it."""
    if item_type == 2 and int(amount) == 1:
        return "NFT ID %s\n%s" % (identifier, token)
    if item_type in (2, 3):
        return "%s of NFT ID %s\n%s" % (amount, identifier, token)
    return "%s NFT by criteria\n%s" % (amount, token)


def _given(doc):
    """The side given of a listing that gives NFTs only."""
    return "\n".join(_nft(i["itemType"], i["token"], i["identifierOrCriteria"],
                          i["endAmount"]) for i in doc["message"]["offer"])


GIVEN = _given(MAINNET[0])


def _native(amount, chain):
    """The device's own rendering of a native amount."""
    if amount < 10 ** 9:
        return "%d Wei" % amount
    return "%s %s" % (format((Decimal(amount) / 10 ** 18).normalize(), "f"),
                      NATIVE[chain])


def _expected(doc):
    """The settlement screen a real listing gets, from the order alone: what
    it gives, and the seller's one payment, in the native coin, or in a
    token this firmware's table does not list on that chain (a warning)."""
    chain = doc["domain"]["chainId"]
    mine = [item for item in doc["message"]["consideration"]
            if item["recipient"] == SIGNER]
    assert len(mine) == 1
    amount = int(mine[0]["startAmount"])
    warnings = [LARGE_ID for item in doc["message"]["offer"]
                if item["itemType"] == 2 and
                int(item["identifierOrCriteria"]) >= 2 ** 64]
    if mine[0]["itemType"] == 0:
        if amount < 10 ** 14:
            warnings.append(_under("0.0001 " + NATIVE[chain]))
        receive = _native(amount, chain)
    else:
        warnings.append(UNKNOWN)
        receive = "%d\nunknown token\n%s" % (amount, mine[0]["token"])
    return _screen(warnings, _given(doc), receive)


class TestMsgEthereumErc7730Settlement(Erc7730Harness, common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.requires_fullFeature()
        self.requires_firmware("7.17.0")
        self.requires_release_capability("erc7730-runtime-review")
        self.requires_release_capability("erc7730-typed-iteration")
        self.requires_release_capability("erc7730-typed-settlement")
        self.requires_structured_eip712()
        self.setup_mnemonic_abandon()
        self.client.apply_policy("AdvancedMode", 1)
        self.assertEqual(self.client.ethereum_get_address(PATH),
                         bytes.fromhex(SIGNER[2:]))

    def _start(self, doc):
        return eth.EthereumSignTypedData(
            address_n=PATH, primary_type=doc["primaryType"],
            metamask_v4_compat=True)

    def _sign(self, doc, descriptor=None, cancel_title=None):
        """Sign `doc` streamed, then with its definition (the settlement one
        by default). Returns the certified pages; the signature must be
        streaming's, or the response a Failure when `cancel_title` declines."""
        baseline, _, _, _ = self._walk(self._start(doc), doc=doc)
        self.assertIsInstance(baseline, eth.EthereumTypedDataSignature)
        chain = doc["domain"]["chainId"]
        program = erc7730_compiler.compile_eip712(
            descriptor or seaport_descriptor(), doc)
        self._load_signer()
        envelope = self._envelope(program, chain=chain)
        erc7730.preload(self.client, self._definition(program, envelope))
        self._drop_setup_screenshots()
        result, _, _, _ = self._walk(self._start(doc), envelope, doc,
                                     cancel_title=cancel_title)
        if cancel_title:
            self.result = result
            return self.screens
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(result.signature, baseline.signature)
        return self._first_pages()

    def _settlement(self, doc, descriptor=None):
        return self._settlement_of(self._sign(doc, descriptor))

    def _settlement_of(self, pages):
        """The settlement screen(s) in `pages`, after checking where they
        are: right after the definition's last field. A body too long for
        one screen is shown in numbered parts ("WARNING (1/2)", each its own
        confirmation, split between lines); they are joined here."""
        part = re.compile(r"^(%s|WARNING)(?: \((\d+)/(\d+)\))?$" % SUMMARY)
        shown, first, expect = [], None, None
        for i, (title, body) in enumerate(pages):
            match = part.match(title)
            if not match:
                self.assertIsNone(expect, "settlement parts cut short")
                continue
            name, index, total = match.groups()
            if index is None or index == "1":
                self.assertIsNone(expect, "settlement parts cut short")
                shown.append([name, body])
                first = i if first is None else first
            else:
                self.assertEqual((name, int(index), int(total)), expect)
                shown[-1][1] += body
            expect = (None if index is None or index == total
                      else (name, int(index) + 1, int(total)))
        self.assertIsNone(expect, "settlement parts cut short")
        if shown:
            fields = [i for i, (title, _) in enumerate(pages)
                      if title.startswith("Signer field")]
            self.assertEqual(first, fields[-1] + 1)
        return [tuple(screen) for screen in shown]

    def _with_offer(self, doc, *items):
        """`doc` giving `items` instead: (itemType, token, identifier,
        amount)."""
        doc = copy.deepcopy(doc)
        doc["message"]["offer"] = [
            {"itemType": t, "token": token, "identifierOrCriteria": i,
             "startAmount": a, "endAmount": a} for t, token, i, a in items]
        return doc

    def test_real_listings_show_both_sides(self):
        # Paid in the native coin: a neutral summary (under 0.0001 ETH, the
        # three Base listings, a line says so). Paid in Polygon WETH or
        # USDC.e: a warning, because this firmware's token table lists no
        # Polygon token (a table limit; the device cannot tell them from a
        # token an attacker made). Two Polygon ERC-721 IDs are hashes over
        # 2^64: a line says so.
        for order in MAINNET + [_real(o) for o in REAL_ORDERS]:
            message = order["message"]
            with self.subTest(chain=order["domain"]["chainId"],
                              salt=message["salt"][-8:]):
                self.assertEqual(self._settlement(order), [_expected(order)])

    def test_one_wei_to_a_stranger_warns(self):
        self.assertEqual(self._settlement(
            _paid(MAINNET[0], (0, ZERO, "1", STRANGER))),
            [_screen([NOTHING], GIVEN, "Nothing")])

    def test_a_redirected_payment_warns(self):
        # The real creator-fee listing, the seller's payment sent elsewhere:
        # every payment goes to another address.
        doc = copy.deepcopy(MAINNET[1])
        doc["message"]["consideration"][0]["recipient"] = STRANGER
        self.assertEqual(self._settlement(doc),
                         [_screen([NOTHING], _given(doc), "Nothing")])

    def test_an_order_from_another_wallet_pays_this_wallet_nothing(self):
        # The real listing unchanged: its seller is not this wallet.
        self.assertEqual(self._settlement(LISTING),
                         [_screen([NOTHING], GIVEN, "Nothing")])

    def test_one_wei_to_this_wallet_warns(self):
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (0, ZERO, "1", SIGNER),
            (0, ZERO, "5589978100000000", OPENSEA_FEE))),
            [_screen([_under("0.0001 ETH")], GIVEN, "1 Wei")])

    def test_a_millionth_of_an_eth_for_an_nft_warns(self):
        # Review r1: 10^12 wei passed the old floor (a millionth of one) and
        # read as a calm "You receive: 0.000001 ETH".
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (0, ZERO, "1000000000000", SIGNER))),
            [_screen([_under("0.0001 ETH")], GIVEN, "0.000001 ETH")])

    def test_a_worthless_token_payment_warns(self):
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (1, WORTHLESS, "1000000000000000000000", SIGNER),
            (0, ZERO, "5589978100000000", OPENSEA_FEE))),
            [_screen([UNKNOWN], GIVEN,
                     "1000000000000000000000\nunknown token\n" + WORTHLESS)])

    def test_a_dead_table_token_shows_what_is_given(self):
        # Review r1: a coin the table lists that nobody values (Dentacoin,
        # no decimals) is above any floor counted in units. The device has
        # no prices and cannot tell: the screen is neutral, never "You
        # receive", and shows the NFT given.
        title, body = self._settlement(_paid(
            MAINNET[0], (1, DCN, "1000000", SIGNER)))[0]
        self.assertEqual((title, body),
                         _screen([], GIVEN, "1000000 DCN"))
        for word in ("fair", "price", "safe", "value"):
            self.assertNotIn(word, body)

    def test_a_dutch_auction_counts_its_smaller_amount(self):
        # Starts at 0.55 ETH, ends at 1 wei: the order can settle for 1 wei.
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (0, ZERO, "553407831900000000", SIGNER, "1"))),
            [_screen([_under("0.0001 ETH")], GIVEN, "1 Wei")])

    def test_an_nft_item_naming_weth_is_not_weth(self):
        # Seaport moves an ERC-721 item by its identifier (1 wei here),
        # whatever its token: it is never counted as WETH, and no NFT is a
        # coin of the firmware's table.
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (2, WETH, "1", SIGNER, "1", "1"))),
            [_screen([COIN_WETH, UNKNOWN], GIVEN, "NFT ID 1\n" + WETH)])

    def _amounts(self, pages):
        return [body for _, body in pages
                if body.split(":\n", 1)[0].endswith("amount")]

    def test_items_are_shown_as_seaport_moves_them(self):
        # Offer items marked like payments: every amount reads by its item
        # type. An NFT is its identifier and count, never an amount of its
        # token; coins keep their token amount. Two NFTs given are listed on
        # the last screen, a third is counted and warns (review r2), as does
        # giving one by criteria.
        doc = _paid(MAINNET[0], (0, ZERO, "19740000000000000", SIGNER),
                    (1, WETH, "210000000000000", OPENSEA_FEE),
                    (3, NFT, "4", SIGNER, "4", "7"))
        doc = self._with_offer(doc, (2, NFT, "446", "1"), (3, NFT, "650", "2"),
                               (5, NFT, "9", "7"))
        pages = self._sign(doc, seaport_descriptor())
        shown = []
        for label, value in (
                ("Give", "NFT ID 446\n" + NFT),
                ("Give", "2 of NFT ID 650\n" + NFT),
                ("Give", "7 NFT by criteria\n" + NFT),
                ("Payment", "0.01974 ETH"), ("Payment", "0.00021 WETH"),
                ("Payment", "4 of NFT ID 7\n" + NFT)):
            shown += ["%s amount:\n%s" % (label, value),
                      "%s end amount:\n%s" % (label, value)]
        self.assertEqual(self._amounts(pages), shown)
        self.assertEqual(self._settlement_of(pages), [_screen(
            [CRITERIA, MORE_ITEMS],
            "NFT ID 446\n%s\n2 of NFT ID 650\n%s\n+ 1 more NFT" % (NFT, NFT),
            "0.01974 ETH\n4 of NFT ID 7\n" + NFT)])

    def test_a_given_nft_naming_weth_warns(self):
        # The drain an amount screen hid: this wallet "gives" an ERC-721 by
        # criteria (any identifier) whose token is WETH. Seaport would move
        # the identifier the filler picks as wei of WETH, up to the whole
        # balance. The order may even pay this wallet.
        doc = self._with_offer(MAINNET[0], (4, WETH, "0", "1"))
        pages = self._sign(doc, seaport_descriptor())
        self.assertEqual(self._amounts(pages)[:2], [
            "Give amount:\n1 NFT by criteria\n" + WETH,
            "Give end amount:\n1 NFT by criteria\n" + WETH])
        self.assertEqual(self._settlement_of(pages), [_screen(
            [COIN_WETH, CRITERIA], "1 NFT by criteria\n" + WETH,
            "0.5534078319 ETH")])
        # The ERC-721 variant (50 WETH as an identifier), nothing paid back.
        doc = self._with_offer(_paid(MAINNET[0], (0, ZERO, "1", STRANGER)),
                               (2, WETH, "50000000000000000000", "1"))
        self.assertEqual(
            self._settlement(doc, seaport_descriptor()),
            [_screen([COIN_WETH, NOTHING],
                     "NFT ID 50000000000000000000\n" + WETH, "Nothing")])

    def test_an_erc721_naming_an_unlisted_token_warns(self):
        # Review r1: an ERC-721 item naming an ERC-20 the table does not
        # list moves "ID" units of it: 10,000 LDO as NFT ID 10^22 for 0.01
        # ETH (the review used USDe, which the firmware now names: see
        # test_never_an_nft_tokens_warn). An ID of 2^64 or more warns; the
        # item is shown by its raw contract and ID.
        doc = self._with_offer(
            _paid(MAINNET[0], (0, ZERO, "10000000000000000", SIGNER)),
            (2, LDO, "10000000000000000000000", "1"))
        self.assertEqual(self._settlement(doc), [_screen(
            [LARGE_ID], "NFT ID 10000000000000000000000\n" + LDO,
            "0.01 ETH")])
        # Control: an ID that fits 64 bits reads as any NFT (Desktop checks
        # the contract before the device).
        doc = self._with_offer(doc, (2, LDO, "18446744073709551615", "1"))
        self.assertEqual(self._settlement(doc), [_screen(
            [], "NFT ID 18446744073709551615\n" + LDO, "0.01 ETH")])

    def test_giving_by_criteria_warns(self):
        # Review r2: an item given by criteria names no ID. Seaport takes the
        # one the filler supplies: with a zero root any, otherwise any in the
        # tree. On an ERC-20 the table does not list (the review's stETH and
        # APE, now named by the firmware; LDO, rETH) that is
        # transferFrom(this wallet, filler, any amount); on a real collection
        # the filler picks which NFT. Each read calm on 3dea32ef7.
        paid = _paid(MAINNET[0], (0, ZERO, "10000000000000000", SIGNER))
        for token, root in ((LDO, "0"),
                            (RETH, "12345678901234567890123456789"),
                            (NFT, "0")):
            with self.subTest(token=token):
                self.assertEqual(
                    self._settlement(self._with_offer(paid, (4, token, root,
                                                             "1"))),
                    [_screen([CRITERIA], "1 NFT by criteria\n" + token,
                             "0.01 ETH")])
        # Control: the same collection by ID.
        self.assertEqual(
            self._settlement(self._with_offer(paid, (2, NFT, "7", "1"))),
            [_screen([], "NFT ID 7\n" + NFT, "0.01 ETH")])

    def test_nfts_past_the_list_warn(self):
        # Review r2: past the two NFTs listed, the rest were only counted, so
        # an ERC-721 item naming an unlisted ERC-20 (LDO, ID 1000, under
        # 2^64) read calm as "+ 2 more NFTs".
        paid = _paid(MAINNET[0], (0, ZERO, "10000000000000000", SIGNER))
        two = "NFT ID 1\n%s\nNFT ID 2\n%s" % (NFT, NFT)
        doc = self._with_offer(paid, (2, NFT, "1", "1"), (2, NFT, "2", "1"),
                               (2, NFT, "3", "1"), (2, LDO, "1000", "1"))
        self.assertEqual(self._settlement(doc), [_screen(
            [MORE_ITEMS], two + "\n+ 2 more NFTs", "0.01 ETH")])
        # Control: two NFTs, both listed.
        self.assertEqual(self._settlement(self._with_offer(
            paid, (2, NFT, "1", "1"), (2, NFT, "2", "1"))),
            [_screen([], two, "0.01 ETH")])

    def test_unstoppable_domains_ids_are_hashes(self):
        # Review r2: Unstoppable Domains' ERC-721 on Ethereum uses namehash
        # IDs, like ENS: a real listing must not read "2^64 or more".
        name = ("538974463791641374324267330513076226333073735129812319168380"
                "13234372094094706")
        paid = _paid(MAINNET[0], (0, ZERO, "50000000000000000", SIGNER),
                     (0, ZERO, "1250000000000000", OPENSEA_FEE))
        self.assertEqual(
            self._settlement(self._with_offer(paid, (2, UD, name, "1"))),
            [_screen([], "NFT ID %s\n%s" % (name, UD), "0.05 ETH")])
        # Control: the same ID at a contract the device does not know.
        self.assertEqual(
            self._settlement(self._with_offer(paid, (2, LDO, name, "1"))),
            [_screen([LARGE_ID], "NFT ID %s\n%s" % (name, LDO),
                     "0.05 ETH")])

    def test_hashed_id_collections_are_calm(self):
        # Review r3: real chain-1 listings of Decentraland LAND and Names,
        # Unstoppable .crypto, Sorare and Rarible read "An NFT ID is 2^64 or
        # more" (their IDs are hashes or packed coordinates).
        paid = _paid(MAINNET[0], (0, ZERO, "50000000000000000", SIGNER),
                     (0, ZERO, "1250000000000000", OPENSEA_FEE))
        for token, name in HASHED_ID:
            with self.subTest(token=token):
                self.assertEqual(
                    self._settlement(self._with_offer(paid,
                                                      (2, token, name, "1"))),
                    [_screen([], "NFT ID %s\n%s" % (name, token),
                             "0.05 ETH")])

    def test_hashed_id_collections_from_real_fills_are_calm(self):
        # Review r4: the r3 list was hand-picked; real listings of these
        # collections (ENS Commemorative first, 315 in the window) read "An
        # NFT ID is 2^64 or more".
        paid = _paid(MAINNET[0], (0, ZERO, "50000000000000000", SIGNER),
                     (0, ZERO, "1250000000000000", OPENSEA_FEE))
        for token, name in HASHED_ID_R4:
            with self.subTest(token=token):
                self.assertEqual(
                    self._settlement(self._with_offer(paid,
                                                      (2, token, name, "1"))),
                    [_screen([], "NFT ID %s\n%s" % (name, token),
                             "0.05 ETH")])

    def test_never_an_nft_tokens_warn(self):
        # Review r3: an ERC-721 item naming an ERC-20 the table does not
        # list, with an ID under 2^64, read as an NFT; for a 6- or 8-decimal
        # token that is any amount (1000 PYUSD is NFT ID 10^9). The ERC-20s
        # an NFT item is most likely to name that way warn like a table coin.
        paid = _paid(MAINNET[0], (0, ZERO, "10000000000000000", SIGNER))
        for ticker, token in NEVER_NFT:
            with self.subTest(token=ticker):
                self.assertEqual(
                    self._settlement(self._with_offer(
                        paid, (2, token, "1000000000", "1"))),
                    [_screen(["An NFT item names the token %s: Seaport moves "
                              "its ID as an amount of %s." % (ticker, ticker)],
                             "NFT ID 1000000000\n" + token, "0.01 ETH")])

    def test_an_nft_item_naming_the_native_placeholder_says_what_it_is(self):
        # Review r1: it read "names the token ETH: Seaport moves its ID as an
        # amount of ETH". 0xEeee...EEeE is no contract.
        doc = self._with_offer(MAINNET[0], (2, EEEE, "7", "1"))
        self.assertEqual(self._settlement(doc), [_screen(
            ["An NFT item names 0xEeee...EEeE, the native coin's placeholder: "
             "it is not an NFT contract."],
            "NFT ID 7\n" + EEEE, "0.5534078319 ETH")])
        # Review r4: an ID of 2^64 or more adds no 2^64 line (the table
        # answers 0xEeee as ETH on chain 1, like any coin it lists).
        doc = self._with_offer(MAINNET[0], (2, EEEE, str(1 << 64), "1"))
        self.assertEqual(self._settlement(doc), [_screen(
            ["An NFT item names 0xEeee...EEeE, the native coin's placeholder: "
             "it is not an NFT contract."],
            "NFT ID %d\n%s" % (1 << 64, EEEE), "0.5534078319 ETH")])

    def test_a_given_erc20_naming_an_nft_collection_warns(self):
        # The mirror of the drain above: this wallet "gives" an ERC-20 item
        # whose token is the listing's own NFT collection, amount = a token
        # ID. Seaport's transferFrom(from, to, 1234) moves NFT #1234. The
        # amount reads as an unknown token, and the last screen warns, even
        # with a real payment back.
        doc = self._with_offer(
            _paid(MAINNET[0], (0, ZERO, "1000000000000000", SIGNER)),
            (1, NFT, "0", "1234"))
        pages = self._sign(doc, seaport_descriptor())
        self.assertEqual(self._amounts(pages)[:2], [
            "Give amount:\n1234\nunknown token\n" + NFT,
            "Give end amount:\n1234\nunknown token\n" + NFT])
        self.assertEqual(self._settlement_of(pages), [_screen(
            [GIVES_UNKNOWN], "1234\nunknown token\n" + NFT, "0.001 ETH")])
        # Control: the same order giving WETH, a token the table lists. It
        # nets against the ETH paid back.
        doc = self._with_offer(doc, (1, WETH, "0", "1234"))
        self.assertEqual(
            self._settlement(doc, seaport_descriptor()),
            [_screen([], "0.000000000000001234 WETH",
                     "0.000999999999998766 ETH")])

    def test_one_base_unit_of_usdc_is_dust(self):
        # A millionth of one USDC is one base unit: under the floor, like
        # 1 wei.
        for amount, shown in (
                ("1", _screen([_under("0.01 USDC")], GIVEN, "0.000001 USDC")),
                ("10000", _screen([], GIVEN, "0.01 USDC"))):
            with self.subTest(amount=amount):
                self.assertEqual(self._settlement(_paid(
                    MAINNET[0], (1, USDC, amount, SIGNER),
                    (0, ZERO, "5589978100000000", OPENSEA_FEE))), [shown])

    def test_every_value_is_still_shown_once(self):
        # The same pages as the definition without roles, but for the NFT's
        # two amount pages (its identifier, not "1 unknown token") and the
        # added screen.
        doc = MAINNET[1]
        described = self._sign(doc)
        without = self._sign(doc, seaport_descriptor(roles=False))
        added = _screen([], _given(doc), "0.01974 ETH")
        self.assertEqual(len(described), len(without) + 1)
        changed = [(a, b) for a, b in zip(
            [p for p in described if p != added], without) if a != b]
        nft = doc["message"]["offer"][0]["token"]
        self.assertEqual([a[1] for a, _ in changed], [
            "Give amount:\nNFT ID 64\n" + nft,
            "Give end amount:\nNFT ID 64\n" + nft])
        self.assertEqual([b[1] for _, b in changed], [
            "Give amount:\n1\nunknown token\n" + nft,
            "Give end amount:\n1\nunknown token\n" + nft])

    def test_a_listing_paid_in_weth_shows_both_sides(self):
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (1, WETH, "500000000000000000", SIGNER),
            (1, WETH, "5000000000000000", OPENSEA_FEE),
            (1, WETH, "1000000000000000", CREATOR))),
            [_screen([], GIVEN, "0.5 WETH")])

    def test_an_offer_for_an_nft_warns(self):
        # A collection offer: this wallet gives WETH for any NFT of a
        # collection. The device cannot value an NFT, so it says so.
        doc = self._with_offer(
            _paid(MAINNET[0], (4, NFT, "1", SIGNER, "1", "0"),
                  (1, WETH, "2500000000000000", OPENSEA_FEE)),
            (1, WETH, "0", "500000000000000000"))
        self.assertEqual(self._settlement(doc), [_screen(
            [UNKNOWN], "0.5 WETH", "1 NFT by criteria\n" + NFT)])

    def test_declining_the_settlement_screen_aborts(self):
        for doc, title in ((MAINNET[1], SUMMARY),
                           (_paid(MAINNET[0], (0, ZERO, "1", STRANGER)),
                            "WARNING")):
            with self.subTest(title=title):
                screens = self._sign(doc, cancel_title=title)
                assert_failure(self, self.result,
                               types.Failure_ActionCancelled,
                               "Signing cancelled by user")
                self.assertEqual(screens[-1][0], title)

    def test_what_is_paid_back_from_what_is_given_is_not_received(self):
        # The re-review's drain: this wallet gives its NFT and 2 WETH and is
        # "paid" the same 2 WETH. The filler flash-loans that payment, fills
        # it before the offer, and keeps the NFT: the wallet gets nothing.
        doc = _paid(MAINNET[0], (1, WETH, "2000000000000000000", SIGNER))
        doc["message"]["offer"].append(
            {"itemType": 1, "token": WETH, "identifierOrCriteria": "0",
             "startAmount": "2000000000000000000",
             "endAmount": "2000000000000000000"})
        given = GIVEN + "\n2 WETH"
        self.assertEqual(self._settlement(doc),
                         [_screen([BACK], given, "Nothing")])
        # Review r1: the same drain paid back in ETH (the filler unwraps the
        # WETH it takes). WETH and ETH net as one coin.
        self.assertEqual(
            self._settlement(_paid(doc, (0, ZERO, "2000000000000000000",
                                         SIGNER))),
            [_screen([BACK], given, "Nothing")])
        # More back than given: the difference.
        more = _paid(doc, (1, WETH, "3000000000000000000", SIGNER))
        self.assertEqual(self._settlement(more),
                         [_screen([], given, "1 WETH")])
        # Control: the same payment for the NFT alone.
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (1, WETH, "2000000000000000000", SIGNER))),
            [_screen([], GIVEN, "2 WETH")])

    def test_an_erc20_item_naming_the_native_placeholder_is_not_eth(self):
        # 0xEeee...EEeE is the token table's mainnet "ETH" sentinel, not an
        # ERC-20 (Seaport would revert): never counted as ETH.
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (1, EEEE, "1000000000000000000", SIGNER))),
            [_screen([UNKNOWN], GIVEN, "+ items not listed here")])

    def test_without_the_opt_in_nothing_is_added(self):
        # Control: the same phishing order under the definition without
        # roles signs with no settlement screen, as 7.17 did before. This is
        # the runtime tier; a certified Seaport definition without roles is
        # refused (firmware unit test).
        self.assertEqual(self._settlement(
            _paid(MAINNET[0], (0, ZERO, "1", STRANGER)),
            seaport_descriptor(roles=False)), [])
