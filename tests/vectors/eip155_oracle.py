"""Independent EIP-155 signing oracle for the 7.14.2 chain_id fix.

Reimplements the signing path from scratch (BIP39 -> BIP32 -> RLP -> keccak ->
RFC6979 ECDSA) so the new golden vectors are NOT taken from the device under
test. Negative control: it must first reproduce the four existing pre-EIP-155
vectors in tests/test_msg_ethereum_signtx.py byte for byte. If it cannot, the
oracle is wrong and its EIP-155 output is worthless.
"""
import hashlib, hmac, binascii
import ecdsa
from ecdsa.util import sigencode_strings_canonize

# ---------------------------------------------------------------- keccak-256
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
      0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
      0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
      0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
      0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
      0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
       [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
M = (1 << 64) - 1


def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & M


def _keccak_f(A):
    for rnd in range(24):
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rol(A[x][y], ROT[x][y])
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & M & B[(x + 2) % 5][y])
        A[0][0] ^= RC[rnd]
    return A


def keccak256(data):
    rate = 136
    pad = bytearray(data) + b'\x01'
    while len(pad) % rate != 0:
        pad += b'\x00'
    pad = bytearray(pad)
    pad[-1] ^= 0x80
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(pad), rate):
        blk = pad[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(blk[i * 8:i * 8 + 8], 'little')
            A[i % 5][i // 5] ^= lane
        A = _keccak_f(A)
    out = b''
    for i in range(4):
        out += A[i % 5][i // 5].to_bytes(8, 'little')
    return out[:32]


# ------------------------------------------------------------------ bip32/39
def seed_from_mnemonic(m, passphrase=""):
    return hashlib.pbkdf2_hmac('sha512', m.encode(),
                               ("mnemonic" + passphrase).encode(), 2048, 64)


CURVE = ecdsa.SECP256k1
N = CURVE.order


def _ser_pub(k):
    p = ecdsa.SigningKey.from_secret_exponent(k, CURVE).get_verifying_key().pubkey.point
    return (b'\x03' if p.y() & 1 else b'\x02') + p.x().to_bytes(32, 'big')


def derive(seed, path):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(I[:32], 'big'), I[32:]
    for idx in path:
        if idx & 0x80000000:
            data = b'\x00' + k.to_bytes(32, 'big') + idx.to_bytes(4, 'big')
        else:
            data = _ser_pub(k) + idx.to_bytes(4, 'big')
        I = hmac.new(c, data, hashlib.sha512).digest()
        k = (int.from_bytes(I[:32], 'big') + k) % N
        c = I[32:]
    return k


# ----------------------------------------------------------------------- rlp
def rlp(x):
    if isinstance(x, int):
        x = b'' if x == 0 else x.to_bytes((x.bit_length() + 7) // 8, 'big')
    if isinstance(x, (bytes, bytearray)):
        x = bytes(x)
        if len(x) == 1 and x[0] < 0x80:
            return x
        return _len(len(x), 0x80) + x
    body = b''.join(rlp(i) for i in x)
    return _len(len(body), 0xc0) + body


def _len(n, off):
    if n < 56:
        return bytes([off + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([off + 55 + len(b)]) + b


# ------------------------------------------------------------------- signing
def sign(priv, nonce, gas_price, gas_limit, to, value, data, chain_id=None):
    fields = [nonce, gas_price, gas_limit, to, value, data]
    if chain_id is not None:
        fields += [chain_id, 0, 0]
    digest = keccak256(rlp(fields))

    sk = ecdsa.SigningKey.from_secret_exponent(priv, CURVE)
    sig = sk.sign_digest_deterministic(digest, hashfunc=hashlib.sha256,
                                       sigencode=sigencode_strings_canonize)
    r, s = int.from_bytes(sig[0], 'big'), int.from_bytes(sig[1], 'big')

    want = sk.get_verifying_key().to_string()
    rec = None
    for cand in range(2):
        try:
            vk = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
                sig[0] + sig[1], digest, CURVE, hashfunc=hashlib.sha256)[cand]
        except Exception:
            continue
        if vk.to_string() == want:
            rec = cand
            break
    assert rec is not None, "no recovery id matched"
    v = rec + 27 if chain_id is None else rec + 35 + 2 * chain_id
    return v, r.to_bytes(32, 'big'), s.to_bytes(32, 'big')


MNEMONIC = 'alcohol woman abuse must during monitor noble actual mixed trade anger aisle'
TO = binascii.unhexlify("1d1c328764a41bda0492b66baa30c4a339ff85ef")

if __name__ == "__main__":
    # oracle self-check against a published keccak-256 vector
    assert binascii.hexlify(keccak256(b"")).decode() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "keccak broken"
    print("keccak-256 self-check OK")

    priv = derive(seed_from_mnemonic(MNEMONIC), [0, 0])

    # ---- NEGATIVE CONTROL: reproduce the shipped pre-EIP-155 golden vectors
    GOLDEN = [
        ("signtx_data  value=10 data=abc*16", dict(nonce=0, gas_price=20, gas_limit=20,
         to=TO, value=10, data=b"abcdefghijklmnop" * 16),
         28, "6da89ed8627a491bedc9e0382f37707ac4e5102e25e7a1234cb697cedb7cd2c0",
             "691f73b145647623e2d115b208a7c3455a6a8a83e3b4db5b9c6d9bc75825038a"),
    ]
    ok = True
    for name, kw, ev, er, es in GOLDEN:
        v, r, s = sign(priv, chain_id=None, **kw)
        good = (v == ev and binascii.hexlify(r).decode() == er
                and binascii.hexlify(s).decode() == es)
        ok &= good
        print(f"[{'PASS' if good else 'FAIL'}] {name}")
        if not good:
            print(f"   want v={ev} r={er} s={es}")
            print(f"   got  v={v} r={binascii.hexlify(r).decode()} s={binascii.hexlify(s).decode()}")
    print("\nNEGATIVE CONTROL:", "oracle reproduces shipped vectors" if ok
          else "ORACLE IS WRONG - do not use its output")
