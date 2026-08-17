"""Negative-control the oracle on ALL six shipped pre-EIP-155 vectors, then
emit their EIP-155 (chain_id=1) replacements for the 7.14.2 fix."""
import binascii
from eip155_oracle import sign, derive, seed_from_mnemonic, MNEMONIC, TO

D16 = b"abcdefghijklmnop" * 16
D256 = b"ABCDEFGHIJKLMNOP" * 256 + b"!!!"

# name, kwargs, shipped pre-155 v/r/s
VEC = [
 ("signtx_data #1", dict(nonce=0, gas_price=20, gas_limit=20, to=TO, value=10, data=D16),
  28, "6da89ed8627a491bedc9e0382f37707ac4e5102e25e7a1234cb697cedb7cd2c0",
      "691f73b145647623e2d115b208a7c3455a6a8a83e3b4db5b9c6d9bc75825038a"),
 ("signtx_data #3", dict(nonce=123456, gas_price=20000, gas_limit=20000, to=TO,
                         value=12345678901234567890, data=D256),
  28, "4e90b13c45c6a9bf4aaad0e5427c3e62d76692b36eb727c78d332441b7400404",
      "3ff236e7d05f0f9b1ee3d70599bb4200638f28388a8faf6bb36db9e04dc544be"),
 ("signtx_message", dict(nonce=0, gas_price=20000, gas_limit=20000, to=TO, value=0, data=D256),
  28, "070e9dafda4d9e733fa7b6747a75f8a4916459560efb85e3e73cd39f31aa160d",
      "7842db33ef15c27049ed52741db41fe3238a6fa3a6a0888fcfb74d6917600e41"),
 ("signtx_newcontract", dict(nonce=0, gas_price=20000, gas_limit=20000, to=b"",
                             value=12345678901234567890, data=D256),
  28, "b401884c10ae435a2e792303b5fc257a09f94403b2883ad8c0ac7a7282f5f1f9",
      "4742fc9e6a5fa8db3db15c2d856914a7f3daab21603a6c1ce9e9927482f8352e"),
 ("signtx_nodata #1", dict(nonce=0, gas_price=20, gas_limit=20, to=TO, value=10, data=b""),
  27, "9b61192a161d056c66cfbbd331edb2d783a0193bd4f65f49ee965f791d898f72",
      "49c0bbe35131592c6ed5c871ac457feeb16a1493f64237387fab9b83c1a202f7"),
 ("signtx_nodata #2", dict(nonce=123456, gas_price=20000, gas_limit=20000, to=TO,
                           value=12345678901234567890, data=b""),
  28, "6de597b8ec1b46501e5b159676e132c1aa78a95bd5892ef23560a9867528975a",
      "6e33c4230b1ecf96a8dbb514b4aec0a6d6ba53f8991c8143f77812aa6daa993f"),
]

priv = derive(seed_from_mnemonic(MNEMONIC), [0, 0])
hx = lambda b: binascii.hexlify(b).decode()

print("=" * 72)
print("NEGATIVE CONTROL - oracle vs the six SHIPPED pre-EIP-155 vectors")
print("=" * 72)
allok = True
for name, kw, ev, er, es in VEC:
    v, r, s = sign(priv, chain_id=None, **kw)
    ok = (v == ev and hx(r) == er and hx(s) == es)
    allok &= ok
    print(f"[{'PASS' if ok else 'FAIL'}] {name:22s} v={v}")
    if not ok:
        print(f"        want v={ev} r={er}\n             s={es}")
        print(f"        got  v={v} r={hx(r)}\n             s={hx(s)}")

print()
if not allok:
    print("ORACLE IS WRONG - not emitting replacements")
    raise SystemExit(1)
print("Oracle reproduces all six. Its EIP-155 output is trustworthy.\n")

print("=" * 72)
print("REPLACEMENT VECTORS - same txs with chain_id=1 (EIP-155)")
print("=" * 72)
for name, kw, _, _, _ in VEC:
    v, r, s = sign(priv, chain_id=1, **kw)
    print(f"\n{name}   chain_id=1")
    print(f"    sig_v = {v}")
    print(f"    sig_r = {hx(r)}")
    print(f"    sig_s = {hx(s)}")
