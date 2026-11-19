"""Monero test fixtures and host-side checks for the test_msg_monero_* files.

The vectors come from pinned Monero Core arithmetic over the published
"alcohol woman ..." (mnemonic12) and "abandon ... about" mnemonics: see
keepkey-firmware tools/monero-feasibility/reference.py and its output,
evidence/2026-11-04-interoperability/host.json. No wallet secrets.

The key-image checks here are independent of the firmware's crypto: AEAD by
pycryptodome, Keccak by pycryptodome, and Ed25519 point arithmetic below.
"""

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import keccak

from keepkeylib import messages_pb2 as proto
from confirmation_pages import ConfirmationPages
import oled_text

H = 0x80000000


def path(account=0):
    return [H + 44, H + 128, H + account]


# network_type = 3, which the closed proto2 enum cannot express, encoded as
# MoneroGetAddress field 3 / MoneroGetWatchKey field 2. Merged into a message
# it is kept as an unknown field and still sent.
UNKNOWN_NETWORK_3 = b'\x18\x03'
UNKNOWN_NETWORK_2 = b'\x10\x03'


# (wallet, account) -> {(major, minor): address}; view key per wallet account
ADDRESSES = {
    ('alcohol', 0): {
        (0, 0): '4Ahp23WfMrMFK3wYL2hLWQFGt87ZTeRkufS6JoQZu6MEFDokAQeGWmu9MA3GFq1yVLSJQbKJqVAn9F9DLYGpRzRAEXqAXKM',
        (0, 1): '88kwZaLw7qv9Zc2oPM1rGbdGvFs4iZB7xgV8F2oHu9Mx3zQ28ADWbav9jTZFGZiTaffcWV6etm2oqKPneDQDijn648aaLDW',
        (1, 0): '86qvtSoL7EtZkLeLmFzTrifZX3Hn6vZfU6RTgAMMmWYs8q31MTMNvjWCbcASVV2iQWVxZjxFXcBKRDR17JSkuZWuHw2cQEC',
        (100, 100): '85kHvgegaeGXPTLU6w5WDzjCLqd6CXxhuHV7UNo2PRYfYwJH4mSB1DA6L4Gbj2rUVQUYKLE6dNMNcVSvfVKqc4fv6k7aoYm',
    },
    ('alcohol', 1): {
        (0, 0): '44iAazhoAkv5a5RqLNVyh82a1n3ceNggmN4Ho7bUBJ14WkEVR8uFTe9f7v5rNnJ2kEbVXxfXiRzsD5Jtc6NvBi4D6WNHPie',
        (0, 1): '84AxZu7xYb7fi7hnQrgTBdHFyP2xz6vdrZbLaJxbe73JJTWj6JG4cV8cbNnEhMvvi9PxSHvGnXQiaaLf2HNXJfzFKtWqk3H',
        (1, 0): '89RG9ZabkJt1hSDhMAiZWzWsof9JxwJrtYymGk4BHjkTTns9ro19B7z1r8jucuDjPvaPo2nRywrwY9FDcht9xxQeHhPumB4',
        (100, 100): '8AyHJKoVVxveznpvUUp2PfV7wM7F5NuB6FHoRkQoDcYnFzGtT9P2PdL2sg8PZiaTEgJy7HqteuQ9Y3vSroLUF3wFNzHhQu1',
    },
    ('abandon', 0): {
        (0, 0): '44jKQv6ZKMd5ecLLmkNJGi7azgSptEq8ki7TFiat1TfLfdDQ1tQ7ZYa3cRh7X2uRwvLDjddWh97ajeyhR2seKSECQeDx1WR',
        (0, 1): '84JQzHWT7SjgNhmiYDb7bh9R894vS4m8VUvQib2W9s4e8CEUTg97NdoiLjP9oUBwcLJreYA2ZKdQP1mFw4EzfNALHJbCDyq',
        (1, 0): '89gMN28NBgi2ZCi11YyfaxW9rHCEKk9UddQVCDAkvL5rUxxKqNLXdTAS5bCkmSNogncXiihL8RFmKJhgcmFqmakNK5cvKyq',
        (100, 100): '86rbT4d9udLGKnTVpVTTQvTkuWZYExbYBg1VUcH1Y7Yx866uinwh25B9oHBW8wo63AQ4eeScAmegp25qTyqBHFXwBhHn6JU',
    },
    ('abandon', 1): {
        (0, 0): '43gVG8hoX8UL6wMn3Eai9dQVdP6BfQXiuSB5TqNBfHvPW5VUmx9WXV2Vnfta9b2S4v6gZwbsGF3MJ48JWh3pgnXSQQ3NhiL',
        (0, 1): '872RQxCREbkehyPY8aUTeWhZSfDSCZX7nVRF1nTN4GSBHgq19kcpiNLSBRb12dJSqHBw58AVdsbWJYyFb6xdpXzL9oRzjbA',
        (1, 0): '84mJpJsJfWE4nEfDwyGPG9BYgUeXogNNc3GuoHUfp2KP3Zaxsee8Kny9ro8TctsqQ6Q6jt3wYX9a3cJ6H3e4oz3LAbLPVho',
        (100, 100): '89U7tW9HkK4AnpK7gEcTNqabxXjA57K2AH18N3qkpWV4JTRoKxQRGyvEyaqkgaAWpXFKj6p3njunCeNEJLj3VrQZTwbA311',
    },
}

VIEW_KEYS = {
    ('alcohol', 0): '8722520a581e2a50cc1adab4a1692401effd37b0d63b9d9b60fd7f34ea2b950e',
    ('alcohol', 1): '1f70b7d9e86c11b7a5bee883b75c43d6be189c8f812726ea1ecd94b06bb7db04',
    ('abandon', 0): '84b0087a63854856686f80596a5a1a6090795b4d1311139173262170d7e7180f',
    ('abandon', 1): 'f2613790022490c2ff04c7ca08829991eda631acb2c515c4b6d40c6caf741607',
}

# Outputs received by the abandon wallet, account 0, at four subaddresses.
OWNED_OUTPUTS = [
    {'major': 0, 'minor': 0, 'index': 0,
     'tx_public': '111657cb6786dcf6e8ee44137c9cac490284d6ef02f66525cba3e30e7e242bc7',
     'output_public': 'b8f5fbec490beea3bff47e60cd9b8ec582bc2ef5e745990ba62f7142a4c41f17',
     'output_secret': 'e83ed43baa79b5ed28a1192c8999c8f8edabff29862b5549556f94483f5ae707',
     'key_image': '07204b29e6918361e8f253409e4ecf63ad088d307f33600b9437616f5231e8f9'},
    {'major': 0, 'minor': 1, 'index': 1,
     'tx_public': 'f6435f119d6f5d7013d94742263421bb8b95d7c7ee326281ac14d765845467d9',
     'output_public': '6d98537b7185cdaf2a548edd89183a966823f1b38a277f50581ad33f3f3a9ff8',
     'output_secret': 'b7e43a11e452b4b2588489bce6fac88cb53ce57ef62b32febd413a05ab059b05',
     'key_image': 'baa12c0fd6411ce8dd668a7b978c767075eb197b608ddbbb94e03d7bf29aeb8e'},
    {'major': 1, 'minor': 0, 'index': 128,
     'tx_public': '0ca3117a350afc4ae71282da84bbfaab93a914af7b0a0948a01ea0bb5bb35c57',
     'output_public': 'cff94184ba3cb10256cb49cee19f2437b475d6a0a08733fc6cb29e25d1e7182e',
     'output_secret': 'df479f22d8e3663d9f17ccf24edf4dd6aaa1c68a575edcfef4ddba9511a4dd0c',
     'key_image': '2e0ab3e315ed6950e09bd5489dc2c8a38310d56221790eb2999340e153d97e83'},
    {'major': 100, 'minor': 100, 'index': 65537,
     'tx_public': 'aa6e1bc781d4aaa67bbb5f22779e9aae36051e229caf1d2d20c20a45d4ecc97e',
     'output_public': 'dc8a1d293fa317b86cf7c051caa2678f1f0d6a154d580f1af1720fb1d9443318',
     'output_secret': 'f5b6e5abfbbd319b47acbdaa9b297f295b945def132bc2164c05b433d28dfb00',
     'key_image': '3c3512950865264d8a89ecceeafab7ded00e8b05b797f99057e093aa00ecbf0b'},
]


def keccak256(data):
    return keccak.new(digest_bits=256, data=data).digest()


def varint(value):
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def transcript_hash(outputs):
    """Keccak over Keccak(P || R || varint(index)) of each output."""
    return keccak256(b''.join(
        keccak256(bytes.fromhex(o['output_public']) +
                  bytes.fromhex(o['tx_public']) + varint(o['index']))
        for o in outputs))


def decrypt(key, iv, blob):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=iv)
    return cipher.decrypt_and_verify(blob[:-16], blob[-16:])


# Ed25519, enough to check Core's one-member ring signature.
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _decode(data):
    y = int.from_bytes(data, 'little') & ((1 << 255) - 1)
    if y >= P:
        raise ValueError('noncanonical point')
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * SQRT_M1 % P
    if (x * x - xx) % P:
        raise ValueError('not a point')
    if x & 1 != data[31] >> 7:
        x = P - x
    return (x, y, 1, x * y % P)


def _encode(point):
    x, y, z, _ = point
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | (x & 1) << 255).to_bytes(32, 'little')


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % P
    B = (y1 + x1) * (y2 + x2) % P
    C = 2 * t1 * t2 * D % P
    E = 2 * z1 * z2 % P
    e, f, g, h = B - A, E - C, E + C, B + A
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(point, scalar):
    out = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            out = _add(out, point)
        point = _add(point, point)
        scalar >>= 1
    return out


G = _decode((4 * pow(5, P - 2, P) % P).to_bytes(32, 'little'))


def ring_signature_valid(plain, output):
    """plain = I || c || r. Checks c == Hs(I || rG + cP || r*Hp(P) + cI).
    Hp(P) is x^-1 * I, from the fixture's one-time secret x."""
    image = plain[:32]
    c = int.from_bytes(plain[32:64], 'little')
    r = int.from_bytes(plain[64:96], 'little')
    if c >= L or r >= L:
        return False
    x = int.from_bytes(bytes.fromhex(output['output_secret']), 'little')
    I = _decode(image)
    hp = _mul(I, pow(x, L - 2, L))
    left = _add(_mul(G, r), _mul(_decode(bytes.fromhex(output['output_public'])), c))
    right = _add(_mul(hp, r), _mul(I, c))
    challenge = int.from_bytes(keccak256(image + _encode(left) + _encode(right)),
                               'little') % L
    return challenge == c


class Screens(object):
    """Answers each ButtonRequest with the next of `answers` (True = confirm;
    the last answer repeats), recording the settled screen and the
    confirmation text (title, body) the firmware drew, pages reassembled."""

    def __init__(self, client, answers=(True,)):
        self.client = client
        self.answers = list(answers)
        self.layouts = []
        self.pages = ConfirmationPages()

    def __enter__(self):
        def callback(msg):
            self.layouts.append(self.client._read_oled_after_settle())
            self.pages.add(msg.code, self.client.debug.read_confirm_text())
            answer = self.answers[min(len(self.layouts), len(self.answers)) - 1]
            if answer:
                self.client.debug.press_yes()
            else:
                self.client.debug.press_no()
            return proto.ButtonAck()
        self.client.callback_ButtonRequest = callback
        return self

    def __exit__(self, *exc):
        del self.client.callback_ButtonRequest

    def confirmations(self):
        """(title, complete body) of every confirmation, pages joined."""
        return list(self.pages.texts)

    def shown(self, text):
        """Some confirmation's complete body contains `text`."""
        return any(text in body for _, body in self.pages.texts)

    def drawn(self, text):
        """Every line `text` wraps into is lit on some recorded screen: the
        pixels, not only the text the firmware meant to draw."""
        return all(any(oled_text.find_line(layout, line) for layout in self.layouts)
                   for line in oled_text.wrap(text) if line)
