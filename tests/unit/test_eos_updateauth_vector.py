"""Independent EOS updateauth wire vector; no emulator or protobuf required.

Public key: test mnemonic from common.py, path m/48'/4'/1'/0'/0'.
The authority contains one account and zero waits. The corrected case hashes
that authority unchanged; the legacy case appends one six-byte zero wait
(wait_sec=0, weight=0) and updates the action-data length. This models the old
firmware using accounts_count instead of waits_count for wait serialization.
"""
import hashlib
import struct
import unittest

pub = bytes.fromhex("037eca30dbc22ecc6d38d95a7e4b49f6b77fa87be608250319b75e2564ccb60143")

def name(s):
    alphabet = '.12345abcdefghijklmnopqrstuvwxyz'
    value = 0
    for x in range(13):
        width = 5 if x < 12 else 4
        symbol = alphabet.index(s[x]) if x < len(s) else 0
        value = (value << width) | symbol
    return struct.pack('<Q', value)


def var(x):
    b = bytearray()
    while x >= 128:
        b.append((x & 127) | 128)
        x >>= 7
    b.append(x)
    return bytes(b)


auth = (
    struct.pack('<I', 1)  # threshold
    + b'\x01\x01' + pub + struct.pack('<H', 1)  # one K1 key, weight 1
    + b'\x01' + name('memememememe') + name('active')
    + struct.pack('<H', 1)  # one permission-level account, weight 1
    + b'\0'  # zero waits
)
prefix = name('memememememe') + name('active') + name('momomomomom')
header = struct.pack('<IHI', 1544644800, 0, 0) + b'\0\0' + var(13337) + b'\0\x01'
common = name('eosio') + name('updateauth') + b'\x01' + name('eosio') + name('owner')
chain = bytes.fromhex('aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906')


class UpdateAuthVector(unittest.TestCase):
    def test_zero_waits(self):
        phantom_wait = struct.pack("<IH", 0, 0)  # wait_sec=0, weight=0
        for extra, expected in [
            (b"", "5938294e65cf9e8b5dd5f2b204503b4825f277e6f4a2d5ab7a55a31065a23af1"),
            (phantom_wait, "fb936ef1be4bda680d93bd10b6d062357d8dd7272038a706dc0d61a91f39c5ee"),
        ]:
            with self.subTest(legacy_phantom_wait=bool(extra)):
                data = prefix + auth + extra
                preimage = chain + header + common + var(len(data)) + data + b"\0" + bytes(32)
                self.assertEqual(hashlib.sha256(preimage).hexdigest(), expected)

if __name__ == "__main__":
    unittest.main()
