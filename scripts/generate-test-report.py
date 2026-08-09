#!/usr/bin/env python3
"""
generate-test-report.py - KeepKey Firmware Test Report (PDF)

Auto-detects firmware version, runs or reads test results, generates
a human-readable report with context for every test. stdlib only.

Usage:
  python3 scripts/generate-test-report.py --output=test-report.pdf
  python3 scripts/generate-test-report.py --fw-version=7.10.0 --junit=junit.xml --output=test-report.pdf
"""
import struct, zlib, os, sys, argparse
from datetime import datetime

# Make keepkeylib importable regardless of invocation cwd (pytest inserts it
# automatically; this script is often run standalone as
# `python3 ../scripts/generate-test-report.py` from tests/, or directly from
# the repo root during local iteration).
for _cand in (os.getcwd(), os.path.join(os.getcwd(), '..'),
             os.path.dirname(os.path.dirname(os.path.abspath(__file__)))):
    if os.path.isdir(os.path.join(_cand, 'keepkeylib')) and _cand not in sys.path:
        sys.path.insert(0, _cand)
del _cand

try:
    from keepkeylib.clearsign_catalog import CLEARSIGN_FLOWS
except ImportError:
    CLEARSIGN_FLOWS = None  # report still renders; V section just won't expand from the catalog

# ---------------------------------------------------------------
# PDF writer + page builder (stdlib only)
# ---------------------------------------------------------------
def _read_png_pixels(path):
    """Read a 256x64 grayscale PNG and return raw pixel bytes (256*64 bytes, 0 or 255)."""
    with open(path, 'rb') as f:
        data = f.read()
    # Minimal PNG parser -- skip signature, find IDAT, decompress
    assert data[:8] == b'\x89PNG\r\n\x1a\n'
    pos = 8
    idat_chunks = []
    width = height = 0
    while pos < len(data):
        length = struct.unpack('>I', data[pos:pos+4])[0]
        chunk_type = data[pos+4:pos+8]
        chunk_data = data[pos+8:pos+8+length]
        if chunk_type == b'IHDR':
            width = struct.unpack('>I', chunk_data[0:4])[0]
            height = struct.unpack('>I', chunk_data[4:8])[0]
        elif chunk_type == b'IDAT':
            idat_chunks.append(chunk_data)
        pos += 12 + length
    raw = zlib.decompress(b''.join(idat_chunks))
    # Remove filter bytes (1 byte per row)
    pixels = bytearray()
    stride = width + 1  # filter byte + pixel data
    for y in range(height):
        row_start = y * stride + 1  # skip filter byte
        pixels.extend(raw[row_start:row_start + width])
    return bytes(pixels), width, height

class PDF:
    def __init__(self):
        self.pages = []  # (ops_str, w, h, [(img_name, img_obj_placeholder)])
        self.images = {}  # name -> (pixels, width, height)
        self._img_counter = 0

    def register_image(self, path):
        """Register a PNG image, returns image name for use in pages."""
        if path in self.images:
            return self.images[path][0]
        name = f'Im{self._img_counter}'
        self._img_counter += 1
        pixels, w, h = _read_png_pixels(path)
        self.images[path] = (name, pixels, w, h)
        return name

    def add_page(self, lines, w=612, h=792):
        ops = []
        img_refs = []  # image names used on this page
        for item in lines:
            if item[0] == 'IMG':
                # ('IMG', x, y, display_w, display_h, img_name)
                _, x, y, dw, dh, img_name = item
                ops.append(f'q {dw} 0 0 {dh} {x} {y} cm /{img_name} Do Q')
                img_refs.append(img_name)
                continue
            y, sz, txt = item[0], item[1], item[2]
            style = item[3] if len(item) > 3 else False
            color = item[4] if len(item) > 4 else None
            txt = _ascii(txt).replace('\\','\\\\').replace('(','\\(').replace(')','\\)')
            if color:
                ops.append(f'{color[0]} {color[1]} {color[2]} rg')
            if style == 'ding':
                ops.append(f'BT /F3 {sz} Tf 40 {y} Td ({txt}) Tj ET')
            else:
                f = '/F2' if style else '/F1'
                ops.append(f'BT {f} {sz} Tf 40 {y} Td ({txt}) Tj ET')
            if color:
                ops.append('0 0 0 rg')
        self.pages.append(('\n'.join(ops), w, h, img_refs))

    def write(self, path):
        objs = [
            b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
            b'',  # pages placeholder
            b'3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n',
            b'4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n',
            b'5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /ZapfDingbats >>\nendobj\n',
        ]
        nxt = 6

        # Add image XObjects
        img_obj_ids = {}  # img_name -> obj_id
        for img_path, (name, pixels, iw, ih) in self.images.items():
            compressed = zlib.compress(pixels)
            obj = f'{nxt} 0 obj\n<< /Type /XObject /Subtype /Image /Width {iw} /Height {ih} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length {len(compressed)} >>\nstream\n'.encode() + compressed + b'\nendstream\nendobj\n'
            objs.append(obj)
            img_obj_ids[name] = nxt
            nxt += 1

        pids = []
        for stream, w, h, img_refs in self.pages:
            c = zlib.compress(stream.encode('latin-1', 'replace'))
            objs.append(f'{nxt} 0 obj\n<< /Length {len(c)} /Filter /FlateDecode >>\nstream\n'.encode() + c + b'\nendstream\nendobj\n')
            stream_id = nxt; nxt += 1

            # Build XObject dict for this page
            xobj_dict = ''
            if img_refs:
                xobj_entries = ' '.join(f'/{nm} {img_obj_ids[nm]} 0 R' for nm in img_refs if nm in img_obj_ids)
                if xobj_entries:
                    xobj_dict = f' /XObject << {xobj_entries} >>'

            objs.append(f'{nxt} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {w} {h}] /Contents {stream_id} 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >>{xobj_dict} >> >>\nendobj\n'.encode())
            pids.append(nxt); nxt += 1

        objs[1] = f'2 0 obj\n<< /Type /Pages /Kids [{" ".join(f"{p} 0 R" for p in pids)}] /Count {len(pids)} >>\nendobj\n'.encode()
        with open(path, 'wb') as f:
            f.write(b'%PDF-1.4\n')
            offs = []
            for o in objs: offs.append(f.tell()); f.write(o)
            xr = f.tell()
            f.write(b'xref\n')
            f.write(f'0 {len(objs)+1}\n'.encode())
            f.write(b'0000000000 65535 f \n')
            for o in offs: f.write(f'{o:010d} 00000 n \n'.encode())
            f.write(f'trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xr}\n%%EOF\n'.encode())

GREEN = (0.13, 0.55, 0.13)
RED = (0.8, 0.1, 0.1)
GRAY = (0.5, 0.5, 0.5)
# ZapfDingbats: \x34 = checkmark, \x38 = cross, \x6c = circle
CHECK = '\x34'
CROSS = '\x38'

# Map non-Latin-1 Unicode punctuation to ASCII so it survives the PDF content
# stream (encoded latin-1); em-dashes etc. were rendering as '?'.
_ASCII_MAP = {
    '—': '-', '–': '-', '→': '->', '←': '<-',
    '’': "'", '‘': "'", '“': '"', '”': '"',
    '…': '...', '•': '*', '₿': 'BTC', '≤': '<=',
    '≥': '>=', '±': '+/-',
}
def _ascii(s):
    for k, v in _ASCII_MAP.items():
        if k in s:
            s = s.replace(k, v)
    return s

class PB:
    def __init__(self, pdf):
        self.pdf = pdf; self.lines = []; self.y = 755
    def _flush(self):
        if self.lines: self.pdf.add_page(self.lines); self.lines = []; self.y = 755
    def need(self, h):
        if self.y - h < 45: self._flush()
    def text(self, sz, txt, bold=False, color=None):
        self.need(sz + 2); self.lines.append((self.y, sz, txt, bold, color) if color else (self.y, sz, txt, bold)); self.y -= sz + 2
    def check(self, sz, txt_after, passed):
        """Render checkmark/cross + text on same conceptual line"""
        self.need(sz + 2)
        if passed == 'pass':
            self.lines.append((self.y, sz, CHECK, 'ding', GREEN))
            self.lines.append((self.y, sz, f'  {txt_after}', True, GREEN))
        elif passed in ('fail', 'error'):
            self.lines.append((self.y, sz, CROSS, 'ding', RED))
            self.lines.append((self.y, sz, f'  {txt_after}', True, RED))
        elif passed == 'skip':
            self.lines.append((self.y, sz, f'--  {txt_after}', False, GRAY))
        else:
            self.lines.append((self.y, sz, f'    {txt_after}', False, GRAY))
        self.y -= sz + 2
    def image(self, png_path, display_w=400, display_h=100):
        """Embed a 256x64 OLED screenshot, scaled to display_w x display_h"""
        self.need(display_h + 4)
        img_name = self.pdf.register_image(png_path)
        # PDF images are placed from bottom-left; y is the bottom of the image
        self.lines.append(('IMG', 40, self.y - display_h, display_w, display_h, img_name))
        self.y -= display_h + 4
    def gap(self, h=4):
        self.y -= h
    def finish(self):
        self._flush()

def _lookup(results, mod, meth):
    """Look up a test result by module::method. Every SECTIONS module is a
    test_msg_* module, so parse_junit always emits a 'mod::meth' key -- there is
    no bare-method fallback (it let a cross-module method-name collision render a
    never-run test as PASS, defeating the --validate-junit release gate)."""
    return results.get(f'{mod}::{meth}', '')

def ver_t(s):
    # Defensive: tolerate pre-release tags (7.15.0-rc3), 'v' prefixes and short
    # versions ('7.15' -> (7,15,0)) so report/filter/validate never crash.
    s = str(s).split('-')[0].replace('v', '')
    parts = (s.split('.') + ['0', '0', '0'])[:3]
    return tuple(int(''.join(ch for ch in p if ch.isdigit()) or '0') for p in parts)
def ver_ge(a, b): return ver_t(a) >= ver_t(b)
def _w(text, n=95):
    words, lines, cur = text.split(), [], ''
    for w in words:
        if cur and len(cur)+1+len(w) > n: lines.append(cur); cur = w
        else: cur = f'{cur} {w}' if cur else w
    if cur: lines.append(cur)
    return lines

def _frame_lit_ratio(path):
    """Fraction of lit pixels in an OLED PNG, or None if unreadable."""
    try:
        pixels, w, h = _read_png_pixels(path)
        if not w or not h:
            return None
        return sum(1 for b in pixels if b > 128) / float(w * h)
    except Exception:
        return None


def _frame_hash(path):
    """Content hash of an OLED PNG with the top-right animation region masked
    (the scroll arrow renders in a per-capture animation state, defeating
    exact-byte comparison of otherwise identical screens). None if unreadable.
    """
    try:
        import hashlib
        pixels, w, h = _read_png_pixels(path)
        if not w or not h:
            return None
        px = bytearray(pixels)
        for y in range(min(16, h)):
            row = y * w
            for x in range(max(0, w - 64), w):
                px[row + x] = 0
        return hashlib.md5(bytes(px)).hexdigest()
    except Exception:
        return None


# hash -> number of distinct test dirs the frame appears in. 1 = the frame is
# unique to its test (its own content); large = generic device chrome shared
# across unrelated tests (load-device prompt, policy toggles, lock screens).
_FRAME_DIR_COUNTS = {}
# Hashes appearing in >= 3 distinct dirs — used to keep chrome out of the
# "extra frames" strip when a test has real content frames of its own.
_GENERIC_FRAME_HASHES = set()

def _build_frame_census(screenshot_dir):
    """Populate the cross-test frame census from every per-test capture dir."""
    _FRAME_DIR_COUNTS.clear()
    _GENERIC_FRAME_HASHES.clear()
    if not screenshot_dir or not os.path.isdir(screenshot_dir):
        return
    dirs_per_hash = {}
    for mod in sorted(os.listdir(screenshot_dir)):
        mod_dir = os.path.join(screenshot_dir, mod)
        if not os.path.isdir(mod_dir):
            continue
        for meth in sorted(os.listdir(mod_dir)):
            test_dir = os.path.join(mod_dir, meth)
            if not os.path.isdir(test_dir):
                continue
            for f in os.listdir(test_dir):
                if not f.startswith('btn'):
                    continue
                h = _frame_hash(os.path.join(test_dir, f))
                if h:
                    dirs_per_hash.setdefault(h, set()).add(test_dir)
    _FRAME_DIR_COUNTS.update((h, len(d)) for h, d in dirs_per_hash.items())
    _GENERIC_FRAME_HASHES.update(
        h for h, dirs in dirs_per_hash.items() if len(dirs) >= 3)


def _pick_best_frame(test_dir, btn_files):
    """Pick the best screenshot for a test.

    setUp noise (wipe/load frames) is removed at capture time for the signing
    tests (see reset_screenshots / setup_mnemonic_*), so the frames here are
    the test's own operation confirms. Defensive layers on top:
    - blank/near-blank frames (idle, lock glyph) are NEVER shown — a reject
      that fires before any confirm UI gets no image, not a blank one;
    - rank by how test-SPECIFIC a frame is (fewest other test dirs showing the
      byte-identical screen), so shared chrome (the load-device prompt, policy
      toggles) loses to the test's own screens, yet still renders when it IS
      the content (gate tests whose every frame is shared chrome);
    - density breaks ties (the address/amount screen carries more lit pixels
      than a bare "Sign?" prompt); dense out-of-band frames (QR screens) are
      a last resort behind in-band ones.

    ponytail: specificity census + density, no OCR — capture-time reset is the
    real guard, this is the safety net.
    """
    if not btn_files:
        return None
    inband, dense = [], []
    for f in btn_files:
        p = os.path.join(test_dir, f)
        r = _frame_lit_ratio(p)
        if r is None or r < 0.02:
            continue  # unreadable or blank/lock — never show
        if r > 0.55:
            dense.append((r, f))  # QR/near-full: last resort, real content
            continue
        h = _frame_hash(p)
        inband.append((_FRAME_DIR_COUNTS.get(h, 1), -r, f))
    if inband:
        inband.sort()
        return os.path.join(test_dir, inband[0][2])
    if dense:
        dense.sort()
        return os.path.join(test_dir, dense[-1][1])
    return None

def detect_fw():
    try:
        from keepkeylib.transport_udp import UDPTransport
        from keepkeylib.client import KeepKeyDebuglinkClient
        from keepkeylib import messages_pb2 as proto
        t = UDPTransport(os.environ.get('KK_TRANSPORT_MAIN','127.0.0.1:11044'))
        c = KeepKeyDebuglinkClient(t)
        r = c.call_raw(proto.Initialize())
        v = f'{r.major_version}.{r.minor_version}.{r.patch_version}'; c.close(); return v
    except: return None

# Census of everything the merged JUnit actually contained, so the report can
# state how much of the run it covers.  Without this the PDF silently implies
# that its catalog IS the test suite -- an RC audit read "no dice in the report"
# as "dice is untested" when test_reset_device_dice had in fact run green.
JUNIT_CENSUS = {'ran': 0, 'native': 0}


def parse_junit(path):
    """Parse junit XML for pass/fail. Returns dict keyed by 'module::method' (precise)
    and 'method' (fallback). Module is extracted from classname: tests.test_msg_foo.TestBar → test_msg_foo.

    Native gtest suites carry a bare classname ("Dice", "Storage") with no dotted
    python module, so they get keyed as 'Suite::Test'. They used to produce no
    'mod::meth' key at all, which made every native unit test structurally
    impossible to put in SECTIONS -- the firmware-unit XMLs were merged in and
    then silently unusable."""
    if not path or not os.path.exists(path): return {}
    import xml.etree.ElementTree as ET
    results = {}
    for tc in ET.parse(path).iter('testcase'):
        name = tc.get('name', '')
        cls = tc.get('classname', '')
        if tc.find('failure') is not None: status = 'fail'
        elif tc.find('error') is not None: status = 'error'
        elif tc.find('skipped') is not None: status = 'skip'
        else: status = 'pass'
        JUNIT_CENSUS['ran'] += 1
        # Extract module from classname: tests.test_msg_foo.TestBar → test_msg_foo
        mod = ''
        if cls:
            parts = cls.split('.')
            for p in parts:
                if p.startswith('test_msg_') or p.startswith('test_sign_') or p.startswith('test_verify_'):
                    mod = p
                    break
            if not mod and '.' not in cls:
                mod = cls               # native gtest suite
                JUNIT_CENSUS['native'] += 1
            results[f'{cls}.{name}'] = status
        # Key by module::method (disambiguates collisions like test_sign_btc_eth_swap)
        if mod:
            results[f'{mod}::{name}'] = status
        # Bare method fallback -- only set if no collision
        if name not in results or status == 'pass':
            results[name] = status
    return results

# ---------------------------------------------------------------
# Test catalog with full context per test
# ---------------------------------------------------------------
# (id, module, method, title, context, [screenshots])
# context = why this test exists, what it proves, what user sees

# Tests whose whole point is the ordered on-device review sequence — render
# every review screen in order (who/what/why), not a single "best" thumbnail.
FULL_SEQUENCE_TESTS = {
    ('test_msg_ethereum_clear_signing', 'test_binding_happy_path_signs_and_recovers'),
    ('test_msg_ethereum_clear_signing', 'test_clearsign_erc20_approve_unlimited'),
    ('test_msg_ethereum_clear_signing', 'test_clearsign_uniswap_v2_eth_to_token'),
    # The newest/highest-stakes tx shapes get the full ordered walkthrough too.
    ('test_msg_ethereum_clear_signing', 'test_clearsign_eip7702_setcode_authorization'),
    ('test_msg_ethereum_clear_signing', 'test_clearsign_erc4337_entrypoint_v0_7_handleops'),
    ('test_msg_ethereum_clear_signing', 'test_clearsign_safe_exectransaction'),
    ('test_msg_ethereum_clear_signing', 'test_clearsign_permit2_permit_transfer_from'),
    ('test_msg_ethereum_clear_signing',
     'test_v2_calldata_length_mismatch_falls_back_to_raw_review'),
    # Native THOR/MAYA memo hardening: the raw memo pager (MEMO 1/N .. N/N,
    # complete memo bytes, sole memo gate) IS the security story — show every
    # page for every memo variant, not a single best frame.
    ('test_msg_thorchain_signtx', 'test_thorchain_sign_tx'),
    ('test_msg_mayachain_signtx', 'test_mayachain_sign_tx_memos'),
    ('test_msg_osmosis_signtx', 'test_osmosis_swap_max_fields_are_fully_paged'),
}

def _v_catalog_tests(start_id=17):
    """Generate one V-section test entry per CLEARSIGN_FLOWS flow (skipping
    'aave-v3-supply', the flagship V9 walkthrough). THE catalog is the
    single source of truth — growing it (keepkeylib/clearsign_catalog.py)
    needs no changes here, unlike a hand-typed per-flow entry that would
    silently go stale (as happened when the old hand-written V17-V23 test
    names drifted from the dynamically-generated ones).

    Every entry gets a NON-EMPTY screenshots hint: screenshot_filter() below
    only includes tests whose hint list is non-empty in the Phase-1 capture
    filter, so an empty list here would silently exclude a flow from ever
    getting an OLED screenshot.
    """
    if not CLEARSIGN_FLOWS:
        return []
    out = []
    i = start_id
    for f in CLEARSIGN_FLOWS:
        if f['key'] == 'aave-v3-supply':
            continue
        method = 'test_clearsign_' + f['key'].replace('-', '_').replace('.', '_')

        def _arg_shown(a):
            # Render what the OLED will actually show for this arg:
            # STRING -> the attested label; ADDRESS -> abbreviated 0x…;
            # TOKEN_AMOUNT -> decimal-scaled amount + symbol (or UNLIMITED).
            v = a['value']
            if a['format'] == 4:      # ARG_FORMAT_STRING
                return v.decode('ascii', 'replace')
            if a['format'] == 1:      # ARG_FORMAT_ADDRESS
                return '0x%s..%s' % (v.hex()[:4], v.hex()[-4:])
            if a['format'] == 5:      # ARG_FORMAT_TOKEN_AMOUNT
                dec, symlen = v[0], v[1]
                sym = v[2:2+symlen].decode('ascii', 'replace')
                amt = v[2+symlen:]
                if len(amt) == 32 and amt == b'\xff' * 32:
                    return 'UNLIMITED ' + sym
                n = int.from_bytes(amt, 'big')
                if dec:
                    scaled = ('%f' % (n / 10 ** dec)).rstrip('0').rstrip('.')
                else:
                    scaled = str(n)
                return '%s %s' % (scaled, sym)
            return a['name']

        shows = '; '.join('%s: %s' % (a['name'], _arg_shown(a))
                          for a in f['args'][:3])
        # Prefer any TOKEN_AMOUNT/ADDRESS/STRING label as the screenshot hint
        # so it reads like what the OLED will actually show.
        hint_names = [a['name'] for a in f['args'][:2]] or [f['method']]
        ctx = ('%s.%s (%s). %s AdvancedMode OFF; the bound metadata is the '
              'only reason this contract data may sign. Real tx: to=0x%s..%s, '
              'chainId %d. Decode: %s.' % (
                  f['protocol'], f['method'], f['category'], f.get('why', ''),
                  f['to'].hex()[:4], f['to'].hex()[-4:], f['chain_id'], shows))
        out.append((
            'V%d' % i, 'test_msg_ethereum_clear_signing', method,
            '%s %s — clear-signed, zero hex' % (f['protocol'], f['method']),
            ctx,
            hint_names,
        ))
        i += 1
    return out


_V_CATALOG_TESTS = _v_catalog_tests(start_id=17)

SECTIONS = [
    ('X', 'Device Specifications', '0.0.0',
     'The KeepKey is an open-source hardware wallet built on an ARM Cortex-M3 (STM32F205, 120MHz) '
     'with a 256x64 monochrome OLED, single confirmation button, and micro-USB interface. The '
     'bootloader (v2.x) is flashed at manufacture and never updated - it is the immutable root of '
     'trust. On every boot, the bootloader verifies the firmware signature using redundant F3 checks '
     'before transferring control.',
     [
         'BOOT SEQUENCE:',
         '1. USB connect -> bootloader executes (always first)',
         '2. F3 signature check (redundant dual-path verify)',
         '3. Valid -> KeepKey logo -> firmware runs',
         '4. Invalid/missing -> "UPDATE FIRMWARE" screen',
         '5. Firmware upload -> verify -> flash -> reboot -> re-verify',
         '',
         'HARDWARE:',
         '- MCU: STM32F205RET6, 120MHz, 128KB bootloader + 896KB firmware',
         '- Display: 256x64 OLED (SSD1306), monochrome, used for ALL confirmations',
         '- Input: single capacitive button (confirm/reject)',
         '- USB: micro-B, HID + WebUSB transports, HID fallback',
         '- Storage: BIP-39 seed encrypted in isolated flash region',
         '- Curves: secp256k1, ed25519, NIST P-256; regular firmware also includes Pallas/Orchard',
         '',
         'SECURITY MODEL:',
         '- All private key operations happen on-device, keys never leave',
         '- Every transaction output displayed on OLED for user verification',
         '- PIN grid randomized on each prompt (position-based, not digit-based)',
         '- BIP-39 passphrase creates hidden wallets (plausible deniability)',
         '',
         'FIRMWARE VARIANTS (7.15, PR #282):',
         '- Full multi-chain (default): all coin families including Zcash Orchard privacy;',
         '  firmware_variant = model name.',
         '- Bitcoin-only (KK_BITCOIN_ONLY): only Bitcoin + Testnet; all altcoin and',
         '  shielded-Zcash handlers stripped; firmware_variant = KeepKeyBTC (EmulatorBTC',
         '  on the emulator). Clients gate multi-chain-only tests on this string.',
         '- There is no separate Zcash artifact: KK_ZCASH_PRIVACY is ON for the regular',
         '  product and OFF only for KK_BITCOIN_ONLY.',
         '',
         'SEED LOCK (7.15, PR #282):',
         '- A seed created under bitcoin-only firmware is stamped in a reserved storage-',
         '  version band. Multi-chain firmware refuses to load it and requires an explicit',
         '  wipe (wipe-to-exit); the seed is never exposed to stripped-out code. Old',
         '  multi-chain firmware treats the band as unknown and resets.',
     ], []),

    ('C', 'Core - Device Lifecycle', '7.0.0',
     'Fundamental device security operations. Every firmware version must pass these tests. '
     'A failure here is an absolute release blocker - these protect seed generation, backup, '
     'recovery, and access control.',
     [
         'WIPE: Erases all keys and settings, returns to factory state',
         'RESET: Generates cryptographic entropy -> BIP-39 mnemonic displayed on OLED only',
         'RECOVERY: Cipher-based entry (scrambled keyboard on OLED) prevents keyloggers',
         'PIN: Randomized grid on OLED, user enters position not digit',
         'PASSPHRASE: Additional BIP-39 word, empty string = default wallet',
     ],
     [
         ('C1', 'test_msg_wipedevice', 'test_wipe_device',
          'Wipe device',
          'Erases all keys, PIN, settings. Device shows "WIPE DEVICE - Do you want to erase your '
          'private keys and settings?" on OLED. User must press button to confirm. After wipe, '
          'device is uninitialized - no operations work until a new seed is loaded or generated.',
          ['Wipe confirmation screen']),
         ('C2', 'test_msg_resetdevice', 'test_reset_device',
          'Generate new seed',
          'Device generates 256 bits of entropy from hardware RNG, converts to BIP-39 mnemonic, '
          'and displays words on OLED one page at a time. Words are NEVER sent to the host. '
          'User writes them down as their backup.',
          ['Seed word display']),
         ('C3', 'test_msg_resetdevice', 'test_reset_device_pin',
          'Generate seed with PIN',
          'Same as C2 but also sets a PIN. PIN is entered twice for confirmation via the '
          'randomized 3x3 grid on OLED. Verifies PIN is stored and required for subsequent operations.',
          ['PIN entry grid']),
         ('C4', 'test_msg_resetdevice', 'test_failed_pin',
          'PIN mismatch rejects setup',
          'If the user enters different PINs during confirmation, the device rejects the setup. '
          'This prevents accidentally setting a PIN the user cannot reproduce.',
          ['PIN mismatch warning']),
         ('C5', 'test_msg_resetdevice', 'test_already_initialized',
          'Reject reset on initialized device',
          'An already-initialized device must refuse reset without a wipe first. Prevents '
          'accidental seed replacement which would strand funds on the old seed.',
          []),
         ('C6', 'test_msg_loaddevice', 'test_load_device_1',
          'Load 12-word mnemonic (debug)',
          'Debug-only operation: loads a known 12-word mnemonic for testing. In production, '
          'seeds can only be generated on-device or recovered via cipher entry.',
          []),
         ('C7', 'test_msg_loaddevice', 'test_load_device_2',
          'Load 18-word mnemonic (debug)',
          'Tests 18-word BIP-39 mnemonic support (192 bits of entropy).',
          []),
         ('C8', 'test_msg_loaddevice', 'test_load_device_3',
          'Load 24-word mnemonic (debug)',
          'Tests 24-word BIP-39 mnemonic support (256 bits of entropy, maximum security).',
          []),
         ('C9', 'test_msg_loaddevice', 'test_load_device_utf',
          'Load with UTF-8 device label',
          'Verifies the device handles non-ASCII characters in labels without corruption.',
          []),
         ('C10', 'test_msg_recoverydevice_cipher', 'test_nopin_nopassphrase',
          'Cipher recovery (no PIN)',
          'Recovery via scrambled keyboard on OLED. The letter grid is randomized per-character, '
          'so even a compromised host cannot determine which letters the user selected. After all '
          'words are entered, device verifies BIP-39 checksum and reconstructs the seed.',
          ['Cipher grid on OLED']),
         ('C11', 'test_msg_recoverydevice_cipher', 'test_pin_passphrase',
          'Cipher recovery with PIN + passphrase',
          'Same recovery flow as C10 but also sets PIN and enables passphrase protection during '
          'the recovery process.',
          ['Cipher + PIN entry']),
         ('C12', 'test_msg_recoverydevice_cipher', 'test_character_fail',
          'Invalid character rejection',
          'Verifies the cipher entry rejects characters that cannot form any BIP-39 word prefix.',
          []),
         ('C13', 'test_msg_recoverydevice_cipher', 'test_backspace',
          'Backspace during cipher entry',
          'User can correct mistakes during word entry without restarting recovery.',
          []),
         ('C14', 'test_msg_recoverydevice_cipher', 'test_reset_and_recover',
          'Full reset then recover cycle',
          'End-to-end test: generate seed -> write down words -> wipe -> recover from words -> '
          'verify same addresses are derived. Proves the backup/restore cycle works.',
          []),
         ('C15', 'test_msg_recoverydevice_cipher', 'test_wrong_number_of_words',
          'Wrong word count rejected',
          'BIP-39 only allows 12, 18, or 24 words. Other counts are rejected immediately.',
          []),
         ('C16', 'test_msg_recoverydevice_cipher_dryrun', 'test_correct_same',
          'Dry-run recovery matches',
          'User can verify their backup without wiping the device. Dry-run recovers the seed '
          'in memory and compares to the active seed. If they match, user knows their backup is valid.',
          []),
         ('C17', 'test_msg_recoverydevice_cipher_dryrun', 'test_correct_notsame',
          'Dry-run detects wrong backup',
          'If the entered words produce a different seed, the device warns the user. This catches '
          'transcription errors in the backup before an emergency.',
          []),
         ('C18', 'test_msg_recoverydevice_cipher_dryrun', 'test_incorrect',
          'Dry-run rejects bad entry',
          'Invalid words or checksum failure during dry-run are reported to the user.',
          []),
         ('C19', 'test_msg_changepin', 'test_set_pin',
          'Set new PIN',
          'Transitions from no-PIN to PIN-protected. The randomized 3x3 grid prevents screen '
          'recording attacks - the attacker sees button presses but not which digit they map to.',
          ['PIN entry grid']),
         ('C20', 'test_msg_changepin', 'test_change_pin',
          'Change existing PIN',
          'Requires entering the current PIN first (proving knowledge), then setting a new one.',
          []),
         ('C21', 'test_msg_changepin', 'test_remove_pin',
          'Remove PIN protection',
          'User can disable PIN if physical security is sufficient. Requires current PIN to remove.',
          []),
         ('C22', 'test_msg_applysettings', 'test_apply_settings',
          'Change label and language',
          'Device label appears on OLED during confirmation screens. Helps identify devices when '
          'a user has multiple KeepKeys.',
          ['Label change confirm']),
         ('C23', 'test_msg_applysettings', 'test_apply_settings_passphrase',
          'Toggle passphrase protection',
          'Enables/disables BIP-39 passphrase. When enabled, every operation prompts for a '
          'passphrase. Different passphrases derive completely different wallets from the same seed.',
          ['Passphrase enable']),
         ('C24', 'test_msg_clearsession', 'test_clearsession',
          'Clear session state',
          'Clears cached PIN, passphrase, and session data. Next operation requires re-authentication.',
          []),
         ('C25', 'test_msg_ping', 'test_ping',
          'Ping with button confirmation',
          'Basic connectivity test. Verifies the device processes messages and button confirmation works.',
          []),
         ('C26', 'test_msg_ping', 'test_ping_format_specifier_sanitize',
          'Sanitize format specifiers',
          'Security test: printf-style format specifiers in ping message must not cause crashes '
          'or information leaks. Verifies input sanitization.',
          []),
         ('C27', 'test_msg_getentropy', 'test_entropy',
          'Hardware RNG audit budget and lock policy',
          'Proves a fresh initialized, PIN-protected, locked device still requires confirmation; '
          'then proves an uninitialized device returns exactly 8 x 8192 bytes (64 KiB) without a '
          'press, with exact lengths, unique blocks, and conservative catastrophic-failure health '
          'checks. The next request must restore confirmation. These checks detect a stuck or '
          'grossly biased source; they are not a statistical certification of the hardware RNG.',
          []),
         ('C28', 'test_msg_cipherkeyvalue', 'test_encrypt',
          'Symmetric key encryption',
          'Derives a symmetric key from the HD tree and encrypts data. Used for password manager '
          'integrations and encrypted communication.',
          []),
         ('C29', 'test_msg_cipherkeyvalue', 'test_decrypt',
          'Symmetric key decryption',
          'Reverse of C28. Verifies encrypt/decrypt round-trips correctly.',
          []),
         ('C30', 'test_msg_signidentity', 'test_sign',
          'Sign identity challenge (SSH/GPG)',
          'Signs an identity challenge for SSH login or GPG key derivation. Derives a key from '
          'the identity URI and signs the challenge.',
          []),
         ('C31', 'test_msg_recoverydevice_cipher', 'test_invalid_bip39_word_rejected',
          'BIP-39 invalid word rejected during cipher recovery',
          'Enter a non-BIP-39 word ("zz") during cipher recovery with enforce_wordlist=True. '
          'Firmware must reject immediately with Failure instead of silently accepting.',
          ['Wordlist rejection warning']),
     ]),

    ('K', 'Seed Generation Hardening (7.15)', '7.15.0',
     'The 7.15 changes to how a seed comes into existence: user-supplied dice entropy folded in '
     'on-device, and the PIN key-derivation rewrap. These ran green from the first 7.15 RC but '
     'appeared nowhere in this report, because the catalog could not reference native firmware '
     'unit tests at all and nobody had catalogued the two new pyk cases. Absent evidence read as '
     'absent coverage during an RC audit, which is exactly the failure this section exists to '
     'prevent.',
     [
         'DICE: user rolls a d6 on-device; short press advances 1-6, long press commits, undo backs out.',
         'The roll string is hashed and the digest confirmed on the OLED before it is mixed in.',
         'MIX: int_entropy = SHA256(int_entropy || rolls), folded in BEFORE the host EntropyRequest,',
         'so the device commits to its own contribution first and the host cannot choose the seed.',
         'ABORT: any aborted reset must disarm EntropyAck, or a later host EntropyAck would derive',
         'a seed from sha256(0*32 || host_bytes) -- entirely host-chosen. That is K2.',
         'PIN KDF: a v16 storage blob must still unlock and then rewrap to v19, or the upgrade bricks.',
     ],
     [
         ('K1', 'test_msg_resetdevice', 'test_reset_device_dice',
          'Dice entropy end-to-end',
          'Drives the full on-device dice flow over DebugLink: 99 rolls injected in chunks with undo '
          'exercised, extras past the cap dropped. Asserts the device-computed digest equals '
          'SHA256 of exactly the expected roll string, then derives the mnemonic from the post-mix '
          'internal entropy and compares -- which is what proves the rolls actually reached the seed '
          'rather than being collected and discarded.',
          ['Dice entry screen', 'Digest confirmation']),
         ('K2', 'test_msg_resetdevice', 'test_reset_reentry_disarms_entropy_ack',
          'Aborted reset disarms EntropyAck',
          'Regression for a host-chosen-seed hole: reset_init aborts left awaiting_entropy set from '
          'an earlier run while zeroing int_entropy, so a following EntropyAck derived the seed '
          'from host bytes alone. Arms a reset, re-enters with dice, cancels, and asserts the '
          'next EntropyAck is refused with "Not in Reset mode" and the device stays uninitialized.',
          []),
         ('K3', 'Dice', 'RollsForStrength',
          'Roll count per seed strength',
          'd6 carries log2(6)=2.585 bits, so 128/192/256-bit seeds need 50/75/99 rolls '
          '(the Coldcard convention). A short count would silently weaken the seed.',
          []),
         ('K4', 'Dice', 'MixZeroEntropyVector',
          'Mix known-answer vector (zero entropy)',
          'SHA256(0x00*32 || "123456") against a hardcoded digest. Pins the mix construction so a '
          'refactor cannot quietly change how dice enter the seed.',
          []),
         ('K5', 'Dice', 'MixNonZeroEntropyVector',
          'Mix known-answer vector (non-zero entropy)',
          'Same construction with a non-zero starting entropy buffer, pinned to a hardcoded digest.',
          []),
         ('K6', 'Dice', 'MixDependsOnRolls',
          'Different rolls produce different entropy',
          'Two mixes differing only in the final roll must diverge. Catches a mix that ignores its '
          'roll argument -- the failure mode where dice appear to work and contribute nothing.',
          []),
         ('K7', 'Dice', 'MixUsesExactCount',
          'Only the counted rolls contribute',
          'Bytes past the declared roll count must not affect the result, so uninitialized tail '
          'bytes of the roll buffer can never leak into seed material.',
          []),
         ('K8', 'Storage', 'PinKdfV16RewrapsToV19AfterCorrectPin',
          'v16 storage unlocks and rewraps to v19',
          'The migration path for the hardened PIN KDF: an existing device on the old format must '
          'still unlock with its current PIN and then be rewrapped. If this regressed, every '
          'upgrading device would be locked out of its own seed.',
          []),
         ('K9', 'Storage', 'PinKdfV2FlagIsVersionedInV19',
          'KDF version flag is recorded in v19',
          'The new KDF is marked in the storage version band, so firmware can tell which derivation '
          'a blob was written with instead of guessing.',
          []),
         ('K10', 'Storage', 'StorageUpgrade_Normal',
          'Normal storage upgrade path',
          'Baseline upgrade across storage versions with policies and cache preserved.',
          []),
         ('K11', 'Storage', 'NoopSecMigrate',
          'Idempotent security migration',
          'Re-running the migration on already-migrated storage must be a no-op rather than a '
          'second rewrap.',
          []),
     ]),

    ('B', 'Bitcoin', '7.0.0',
     'Bitcoin is the primary chain and most extensively tested. Covers legacy P2PKH, P2SH-wrapped '
     'SegWit, native SegWit (bech32), and Taproot (P2TR). Transaction signing validates that the '
     'device correctly displays every output address and amount, calculates fees, detects change '
     'outputs, and resists output substitution attacks. Also covers UTXO forks sharing BTC signing code.',
     [
         'ADDRESS: Derive key from BIP-32 path -> display on OLED with QR code -> user verifies against host',
         'SIGN TX: Device shows each output (full address + amount) -> shows fee -> user confirms -> signs',
         'MESSAGE: Show text on OLED -> user confirms -> signs with address-specific key (EIP-191 equivalent)',
     ],
     [
         ('B1', 'test_msg_getaddress', 'test_btc',
          'Derive BTC legacy address',
          'Derives a P2PKH (1...) address from standard BIP-44 path m/44\'/0\'/0\'/0/0. '
          'Verifies the address matches the expected value from the test mnemonic.',
          []),
         ('B2', 'test_msg_getaddress', 'test_ltc',
          'Derive Litecoin address',
          'LTC uses the same derivation as BTC with coin_type=2. Verifies L... address format.',
          []),
         ('B3', 'test_msg_getaddress', 'test_tbtc',
          'Derive testnet address',
          'Testnet addresses use different version bytes (m/n prefix). Important for development testing.',
          []),
         ('B4', 'test_msg_getaddress_show', 'test_show',
          'Show BTC address on OLED',
          'Address displayed on OLED with QR code for visual verification. User compares the address '
          'shown on the trusted device display against the host application. This is the primary defense '
          'against address substitution attacks by compromised hosts.',
          ['BTC address + QR code']),
         ('B5', 'test_msg_getaddress_show', 'test_show_multisig_3',
          'Show 3-of-3 multisig address',
          'Multisig addresses require all co-signer xpubs. Device displays the P2SH multisig address '
          'derived from all provided public keys.',
          ['Multisig address']),
         ('B6', 'test_msg_getaddress_segwit', 'test_show_segwit',
          'Show SegWit P2SH address',
          'P2SH-wrapped SegWit (3... prefix). Backwards compatible with legacy wallets while '
          'getting SegWit fee savings.',
          ['SegWit address']),
         ('B7', 'test_msg_getaddress_segwit_native', 'test_show_segwit',
          'Show native SegWit bech32',
          'Native SegWit (bc1q... prefix). Lowest fees, modern address format. Verifies bech32 encoding.',
          ['bech32 address']),
         ('B8', 'test_msg_getpublickey', 'test_btc',
          'Get BTC xpub',
          'Exports the extended public key for a derivation path. Used by wallet software to '
          'derive addresses and monitor balances without the device connected.',
          []),
         ('B9', 'test_msg_signtx', 'test_one_one_fee',
          'Sign basic BTC transaction',
          'Simplest case: one input, one output. Device displays "Send X BTC to [address]" with '
          'the full recipient address (no truncation), then shows the fee. Verifies the signed '
          'transaction is valid.',
          ['Send amount + address', 'Fee confirmation']),
         ('B10', 'test_msg_signtx', 'test_one_two_fee',
          'Sign BTC tx with change',
          'One input, two outputs (payment + change). Device must identify the change output '
          '(same xpub tree) and only display the payment output to the user.',
          ['Output confirmation']),
         ('B11', 'test_msg_signtx', 'test_two_two',
          'Sign multi-input BTC tx',
          'Two inputs, two outputs. Verifies correct fee calculation across multiple inputs.',
          []),
         ('B12', 'test_msg_signtx', 'test_spend_coinbase',
          'Sign coinbase spend',
          'Spending a coinbase (mining reward) output. Coinbase outputs have special maturity rules.',
          []),
         ('B13', 'test_msg_signtx', 'test_lots_of_outputs',
          'Sign tx with many outputs',
          'Stress test with many recipients. Each output is displayed individually on the OLED.',
          []),
         ('B14', 'test_msg_signtx', 'test_fee_too_high',
          'Reject excessive fee',
          'If the fee exceeds a safety threshold, the device shows a prominent warning. Protects '
          'against fat-finger errors or malicious fee manipulation.',
          ['High fee warning']),
         ('B15', 'test_msg_signtx', 'test_not_enough_funds',
          'Reject insufficient funds',
          'If inputs don\'t cover outputs + fee, the device refuses to sign.',
          []),
         ('B16', 'test_msg_signtx', 'test_p2sh',
          'Sign P2SH transaction',
          'Pay-to-Script-Hash output. Used for multisig and complex scripts.',
          []),
         ('B17', 'test_msg_signtx', 'test_attack_change_outputs',
          'Detect output substitution',
          'Security test: the host attempts to substitute the change output address between '
          'the first and second signing pass. Device must detect the mismatch and refuse.',
          []),
         ('B18', 'test_msg_signtx_segwit', 'test_send_p2sh',
          'Sign SegWit P2SH tx',
          'SegWit transaction with P2SH-wrapped inputs. Different signing algorithm (BIP-143).',
          []),
         ('B19', 'test_msg_signtx_segwit', 'test_send_mixed',
          'Sign mixed legacy+SegWit tx',
          'Transaction with both legacy and SegWit inputs in the same transaction.',
          []),
         ('B20', 'test_msg_signtx_p2tr', 'test_send_p2tr_only',
          'Create a Taproot P2TR output',
          'Pays from SegWit inputs to a P2TR output. This exercises P2TR output parsing and '
          'display, but does not exercise a Schnorr key-path spend.',
          ['Taproot output confirmation']),
         ('B21', 'test_msg_signtx_taproot', 'test_send_p2tr',
          'Sign a Taproot key-path spend',
          'Spends a BIP-86 P2TR input using BIP-341 SIGHASH_DEFAULT and a BIP-340 Schnorr '
          'signature. The 64-byte witness is compared byte-for-byte with an independently '
          'computed reference value. The complete 153-byte transaction is then parsed as '
          'BIP-144 and must consume every byte, proving the witness stack and the 4-byte '
          'locktime footer actually reached the host rather than only the signature field.',
          ['P2TR recipient confirmation', 'Fee confirmation']),
         ('B22', 'test_msg_signtx_taproot', 'test_send_p2tr_with_change',
          'Sign P2TR with device-derived change',
          'Derives m/86\'/0\'/0\'/1/0 on-device, emits a P2TR change output, and verifies '
          'the Schnorr witness against an independent BIP-340/341 reference. The complete '
          '196-byte transaction is parsed as BIP-144 and must consume every byte, and the '
          'change output is matched as a full value/length/script triple.',
          ['P2TR recipient confirmation', 'Fee confirmation']),
         ('B23', 'test_msg_signtx_taproot', 'test_send_mixed_p2tr_and_legacy',
          'Sign mixed Taproot and legacy inputs',
          'Commits the P2TR signature to both inputs, including the legacy prevout amount and '
          'scriptPubKey, while independently verifying the resulting Schnorr witness. The '
          'complete 301-byte transaction is parsed as BIP-144; the Taproot input must carry '
          'a single 64-byte stack item and the legacy input its empty 0x00 witness.',
          []),
         ('B24', 'test_msg_signtx_taproot',
          'test_mixed_p2tr_requires_every_input_amount',
          'Reject incomplete mixed Taproot commitments',
          'Fails closed when any input amount is absent, preventing the device from producing '
          'a valid Schnorr signature over an incomplete BIP-341 commitment.',
          []),
         ('B25', 'test_msg_signtx_taproot',
          'test_mixed_p2tr_rejects_wrong_legacy_amount',
          'Reject a tampered legacy prevout amount',
          'Fetches the actual legacy prevout and rejects a host-provided amount that differs by '
          'one satoshi, preventing a false BIP-341 commitment in a mixed-input transaction.',
          []),
         ('B26', 'test_msg_getaddress_taproot', 'test_show_taproot_address',
          'Show BIP-86 address on OLED',
          'Displays the complete bech32m Taproot receive address and QR code on the trusted '
          'device screen for host-independent verification.',
          ['Taproot address + QR code']),
         ('B27', 'test_msg_signmessage', 'test_sign',
          'Sign message with BTC key',
          'Signs arbitrary text with a BTC address key. Used for proof-of-ownership and login.',
          ['Sign message on OLED']),
         ('B28', 'test_msg_signmessage_segwit', 'test_sign',
          'Sign message with SegWit key', 'Message signing with P2SH-SegWit address key.', []),
         ('B29', 'test_msg_signmessage_segwit_native', 'test_sign',
          'Sign message with bech32 key', 'Message signing with native SegWit address key.', []),
         ('B30', 'test_msg_verifymessage', 'test_message_verify',
          'Verify signed message', 'Device verifies a message signature against a BTC address.', []),
         ('B31', 'test_msg_signtx_bgold', 'test_send_bitcoin_gold_nochange',
          'Sign Bitcoin Gold tx', 'BTG fork uses same signing code with different chain parameters.', []),
         ('B32', 'test_msg_signtx_dash', 'test_send_dash',
          'Sign Dash transaction', 'Dash special transaction types (InstantSend-compatible).', []),
         ('B33', 'test_msg_signtx_grs', 'test_one_one_fee',
          'Sign Groestlcoin tx', 'GRS uses Groestl hash instead of SHA-256d for tx hashing.', []),
         # Zcash transparent signing moved to its own section Y (Zcash Transparent).
     ]),

    ('E', 'Ethereum', '7.0.0',
     'Ethereum covers native ETH transfers, ERC-20 tokens, EIP-1559 gas, personal message signing '
     '(EIP-191), and contract interactions. The device displays checksummed addresses (EIP-55) and '
     'gas parameters. Amount UNIT rule: values below 1 gwei (1e9 wei) show as raw "Wei" (there is '
     'no smaller human unit to scale to); values at or above 1 gwei show 18-decimal-scaled ETH (or '
     'the chain-native ticker on other EVM chains). Some tests below use small conformance-vector '
     'amounts (e.g. 10 wei) for deterministic-signature pinning — their OLED frames legitimately '
     'show raw "Wei", not a display bug.',
     [
         'ETH TRANSFER: Show "Send X ETH to 0x..." -> show gas -> confirm -> sign with secp256k1',
         'ERC-20: Decode transfer(to,amount) from contract data -> show token name + amount',
         'EIP-1559: Show maxFeePerGas + maxPriorityFeePerGas (not legacy gasPrice)',
         'MESSAGE: EIP-191 prefix -> show text on OLED -> sign with ETH key',
     ],
     [
         ('E1', 'test_msg_ethereum_getaddress', 'test_ethereum_getaddress',
          'Derive ETH address', 'Standard m/44\'/60\'/0\'/0/0 derivation. EIP-55 checksum address.', ['ETH address']),
         ('E2', 'test_msg_ethereum_signtx', 'test_ethereum_signtx_nodata',
          'Sign ETH transfer',
          'Simple value transfer with no contract data. Device shows recipient + amount + gas.',
          ['ETH send confirmation']),
         ('E3', 'test_msg_ethereum_signtx', 'test_ethereum_signtx_data',
          'Sign ETH tx with contract data',
          'Transaction with data field (contract call). Device shows data as hex since it cannot '
          'decode arbitrary ABI without metadata.',
          ['Contract data hex']),
         ('E4', 'test_msg_ethereum_signtx', 'test_ethereum_signtx_nodata_eip155',
          'Sign ETH with EIP-155 replay protection',
          'Chain ID embedded in signature v value to prevent cross-chain replay attacks.', []),
         ('E5', 'test_msg_ethereum_signtx', 'test_ethereum_eip_1559',
          'Sign EIP-1559 transaction',
          'Type 2 transaction with base fee + priority fee. Device shows both gas parameters.',
          ['EIP-1559 gas display']),
         ('E5b', 'test_msg_ethereum_signtx_chunked_data_eip1559',
          'test_eip1559_chunked_data_signature_recovers_to_device_address',
          'Sign EIP-1559 with data > 1024 B (chunked transmission)',
          'Regression for an access-list ordering bug in firmware/ethereum.c — when data exceeded '
          'the 1024-byte single-chunk threshold, the empty access-list byte (0xC0) was hashed '
          'between data chunks instead of after them, producing a non-canonical pre-image. The '
          'signature recovered to a wrong-but-deterministic address and the broadcast tx was '
          'dropped from the mempool. Fixed in 7.14.1.',
          []),
         ('E6', 'test_msg_ethereum_signtx', 'test_ethereum_signtx_knownerc20_eip_1559',
          'Sign known ERC-20 (EIP-1559)',
          'Known token (in firmware token list) via EIP-1559. Shows human-readable token name + amount.',
          ['Token transfer display']),
         ('E7', 'test_msg_ethereum_message', 'test_ethereum_sign_message',
          'Sign personal message',
          'EIP-191 personal_sign. Device shows the message text on OLED for user to verify before signing.',
          ['Sign message screen']),
         ('E8', 'test_msg_ethereum_message', 'test_ethereum_sign_bytes',
          'Sign raw bytes', 'Signs arbitrary bytes (displayed as hex on OLED).', []),
         ('E9', 'test_msg_ethereum_message', 'test_ethereum_verify_message',
          'Verify ETH signed message', 'Device-side verification of EIP-191 signed messages.', []),
         ('E10', 'test_msg_signtx_ethereum_erc20', 'test_approve_some',
          'ERC-20 approve specific amount',
          'Token approval for a specific amount. Device shows spender address + approved amount.',
          ['Approval screen']),
         ('E11', 'test_msg_signtx_ethereum_erc20', 'test_approve_all',
          'ERC-20 approve unlimited',
          'MAX_UINT256 approval. Device shows "UNLIMITED" warning since this grants infinite spending.',
          ['Unlimited approval warning']),
         ('E12', 'test_msg_ethereum_makerdao', 'test_generate',
          'MakerDAO generate DAI', 'Complex DeFi contract interaction (MakerDAO CDP).', []),
         ('E13', 'test_msg_ethereum_sablier', 'test_sign_salarywithdrawal',
          'Sablier salary withdrawal', 'Streaming payment protocol contract call.', []),
         ('E14', 'test_msg_ethereum_erc20_0x_signtx', 'test_sign_0x_swap_ETH_to_ERC20',
          '0x swap ETH to ERC-20', 'DEX aggregator swap via 0x protocol.', []),
         ('E15', 'test_msg_ethereum_cfunc', 'test_sign_execTx',
          'Contract function call', 'Generic contract call signing.', []),
         ('E16', 'test_sign_typed_data', 'test_ethereum_sign_typed_data_hash',
          'EIP-712 typed-data hash signing (legacy, no on-device display)',
          'The legacy endpoint receives two host-computed 32-byte hashes, so firmware keeps it '
          'behind AdvancedMode and cannot show readable WHO/WHAT. Structured formats such as '
          'x402 EIP-3009 use the separate device-parsed path proven by E16b.',
          []),
         ('E16b', 'test_sign_typed_data', 'test_ethereum_sign_x402_eip3009',
          'x402 EVM EIP-3009 payment clear-signs structured data',
          'The device computes the EIP-712 hashes itself and displays the Base Sepolia USDC '
          'domain plus every TransferWithAuthorization field: payer, recipient, exact value, '
          'validity window and nonce. AdvancedMode stays OFF; the facilitator pays gas but '
          'cannot alter the signed destination or amount.',
          ['USDC domain fields', 'TransferWithAuthorization fields']),
         ('E17', 'test_msg_ethereum_erc20_uniswap_liquidity', 'test_sign_uni_approve_liquidity_ETH',
          'Uniswap V2 add-liquidity approve (pending)',
          'PENDING, disclosed: known emulator limitation — an approve to an unknown (non-registry) '
          'token contract cannot complete against the kkemu emulator (matches the sibling '
          'add/remove-liquidity skips below); the device-firmware path is not in question, only '
          'CI emulator coverage. Real-device testing is unaffected.',
          []),
         ('E18', 'test_msg_ethereum_erc20_uniswap_liquidity', 'test_sign_uni_add_liquidity_ETH',
          'Uniswap V2 add liquidity ETH+token (pending)',
          'PENDING, disclosed: same emulator limitation as E17 — a daily-driver LP-deposit flow '
          'with no PDF proof on this build; tracked for real-device verification.',
          []),
         ('E19', 'test_msg_ethereum_erc20_uniswap_liquidity', 'test_sign_uni_remove_liquidity_ETH',
          'Uniswap V2 remove liquidity ETH+token (pending)',
          'PENDING, disclosed: same emulator limitation as E17.',
          []),
         ('E20', 'test_msg_ethereum_thorchain_deposit', 'test_deposit_legacy_selector',
          'THORChain router deposit() (legacy selector)',
          'Cross-chain swap via the THORChain router contract — a daily-driver EVM<->THORChain '
          'swap path, natively decoded (asset/amount/memo) without clear-sign metadata. The '
          'native amount shown is the signed msg.value (the ABI amount word is a router-ignored '
          'hint and is never displayed as the send amount).',
          ['Deposit amount (msg.value)', 'Full memo']),
         ('E21', 'test_msg_ethereum_thorchain_deposit', 'test_deposit_with_expiry_selector',
          'THORChain router depositWithExpiry()',
          'Newer router selector variant with an expiry field; same native decode path. The ABI '
          'memo length word is read from the calldata (not assumed 64 bytes) and the padded memo '
          'must end exactly at the calldata end.',
          ['Deposit amount (msg.value)', 'Full memo']),
         ('E22', 'test_msg_ethereum_thorchain_deposit',
          'test_deposit_with_expiry_non_thor_address_blind_sign_blocked',
          'THORChain router call to a non-pinned address is blind-sign gated',
          'WHY it can be trusted: the router CONTRACT ADDRESS is pinned; a call shaped like a '
          'THORChain deposit but sent to an unpinned address is refused native decoding and falls '
          'through to the ordinary blind-sign gate instead of being silently native-decoded — the '
          'fix for the router-spoofing / blind-sign-bypass class of attack.',
          ['Blind sign disabled (Blocked)']),
         ('E23', 'test_msg_ethereum_thorchain_deposit',
          'test_deposit_with_expiry_avalanche_router',
          'THORChain deposit on Avalanche clear-signs (per-chain router pin)',
          'THORChain deploys its router at a DIFFERENT address on every EVM chain, so the pin is '
          '(chain_id, address) together. Before the chain scope, only mainnet deposits ever '
          'matched and an AVAX->ETH swap fell into the blind-sign gate. The Avalanche C-Chain '
          'router (00dc61..f1d4) is verified live against THORChain /inbound_addresses; the '
          'native amount screen shows msg.value with the CHAIN\'s ticker (AVAX), and the '
          'signature is ECDSA-recovered against the host-built pre-image over chainId 43114.',
          ['Thorchain router screen', 'AVAX amount', 'Full memo']),
         ('E24', 'test_msg_ethereum_thorchain_deposit',
          'test_deposit_unpinned_chain_blind_sign_blocked',
          'Deposit on an unpinned chain is blind-sign gated',
          'The mainnet router ADDRESS on a chain with no pinned router (BSC) must not inherit '
          'the deposit UX — the same address on another chain may hold unrelated attacker code. '
          'Falls to the AdvancedMode gate; rejection is pre-UI (no frame).',
          []),
     ]),

    ('R', 'Ripple (XRP)', '7.0.0',
     'XRP Ledger support for the third-largest cryptocurrency by market cap. XRP uses a unique '
     'account-based model (not UTXO) with 20 XRP minimum reserve. Amounts are denominated in '
     'drops (1 XRP = 1,000,000 drops). Destination tags are required for exchange deposits to '
     'route funds to the correct account. The device displays the full rAddress (34 chars starting '
     'with r) and converts drop amounts to human-readable XRP values.',
     [
         'ADDRESS: Derive from m/44\'/144\'/0\'/0/0 -> display full rAddress + QR on OLED',
         'SIGN: Host sends Payment tx (destination, amount, fee, destination_tag) -> device shows XRP amount + recipient',
         'FEE: XRP requires a minimum fee (currently 10 drops). Device validates fee is within bounds.',
     ],
     [
         ('R1', 'test_msg_ripple_get_address', 'test_ripple_get_address',
          'Derive XRP address', 'Standard m/44\'/144\'/0\'/0/0 derivation.', ['XRP address']),
         ('R2', 'test_msg_ripple_sign_tx', 'test_sign',
          'Sign XRP payment', 'Payment with amount in drops (1 XRP = 1,000,000 drops).', ['XRP send']),
         ('R3', 'test_msg_ripple_sign_tx', 'test_ripple_sign_invalid_fee',
          'Reject invalid fee', 'Fee outside acceptable range is rejected.', []),
     ]),

    ('A', 'Cosmos (ATOM)', '7.0.0',
     'Cosmos Hub is the anchor chain for the Cosmos IBC ecosystem. Transactions use amino encoding '
     '(legacy Cosmos SDK format). The device supports MsgSend (transfers), MsgDelegate (staking to '
     'validators), and MsgWithdrawDelegatorReward (claiming staking rewards). Addresses use bech32 '
     'encoding with the cosmos1 prefix. Memo field is critical for exchange deposits and IBC transfers - '
     'the device displays it in full on the OLED for user verification.',
     [
         'ADDRESS: Derive from m/44\'/118\'/0\'/0/0 -> display cosmos1... bech32 address',
         'SEND: Show recipient address + ATOM amount + memo on OLED -> user confirms',
         'MEMO: Displayed in full - required for exchange deposits (e.g. numeric account ID)',
     ],
     [
         ('A1', 'test_msg_cosmos_getaddress', 'test_standard',
          'Derive Cosmos address', 'Bech32 cosmos1... address from m/44\'/118\'/0\'/0/0.',
          []),  # show_display=True + set_expected_responses breaks with screenshot mode
         ('A2', 'test_msg_cosmos_signtx', 'test_cosmos_sign_tx',
          'Sign Cosmos send', 'MsgSend with amount + recipient display.', ['ATOM send']),
         ('A3', 'test_msg_cosmos_signtx', 'test_cosmos_sign_tx_memo',
          'Sign Cosmos with memo', 'Memo field displayed for exchange deposit tags.', []),
     ]),

    ('P', 'Osmosis', '7.15.0',
     'Osmosis is the Cosmos-ecosystem DEX, signed with the same amino encoding as Cosmos Hub and '
     'derived from the same coin type (118). 7.15.0 CHANGED how every Osmosis amount is drawn: the '
     'confirm screens formatted with atof() + "%.6f", and a float carries only ~7 significant '
     'decimal digits, so a large transfer was displayed ROUNDED on the screen the user approves '
     '(123456789.123456 OSMO rendered as 123456792.000000). The signature was always over the '
     'correct amount — the error was confined to the display, which is the half a hardware wallet '
     'exists to get right. Amounts now use bounded decimal-string formatting; native uosmo is '
     'canonical uint64, unknown denominations remain exact base-unit strings, and every long '
     'signed asset is renderer-paged before signing.',
     [
         'SEND: recipient + OSMO amount rendered from integer base units, never a float',
         'PRECISION: 15-significant-digit amounts display exactly, not rounded to 7',
         'UNKNOWN DENOM: shown as raw base units — the device does not guess a decimal point',
     ],
     [
         ('P1', 'test_msg_osmosis_signtx', 'test_osmosis_sign_tx',
          'Sign Osmosis send',
          'Baseline MsgSend: recipient and a whole-OSMO amount on the confirm screen.',
          ['OSMO send']),
         ('P2', 'test_msg_osmosis_signtx', 'test_osmosis_send_amount_beyond_float_precision',
          'Amount beyond float precision displays exactly',
          'The regression this section exists for: 123456789123456 uosmo needs 15 significant '
          'digits. The old float path drew 123456792.000000 OSMO over a transaction moving '
          '123456789.123456 OSMO. The captured frame is the evidence.',
          ['Exact large amount']),
         ('P3', 'test_msg_osmosis_signtx', 'test_osmosis_send_subunit_amount',
          'Sub-unit amount keeps its tail',
          '500 uosmo is 0.000500 OSMO — no integer part and six decimals; it must not collapse '
          'to 0 or lose the trailing digits.',
          ['Sub-unit amount']),
         ('P4', 'test_msg_osmosis_signtx', 'test_osmosis_send_denom_is_committed_to_the_signature',
          'Direct-wire denomination is committed',
          'Two otherwise-identical raw MsgSend requests using uosmo and uatom produce different '
          'signatures, proving the reviewed denomination is part of the signed payload rather '
          'than a hardcoded display-only label.',
          []),
         ('P5', 'test_msg_osmosis_signtx', 'test_osmosis_send_rejects_noncanonical_wire_amounts',
          'Noncanonical and overflowing uosmo are refused',
          'Raw-wire 01, -1, leading-space and UINT64 overflow values are rejected before any '
          'display/signature divergence can occur.',
          []),
         ('P6', 'test_msg_osmosis_signtx', 'test_osmosis_swap_max_fields_are_fully_paged',
          'Maximum Swap fields are fully paged',
          'Two maximum-size 68-character IBC denominations plus 32-digit amounts force the '
          'exact OLED renderer across separate bounded screens. The full ordered input and minimum-output '
          'sequence is captured before the signature is returned.',
          ['Swap Input', 'Minimum Output']),
         ('P7', 'test_msg_osmosis_signtx', 'test_osmosis_amount_is_committed_to_the_signature',
          'Displayed amount is in the digest',
          'Two sends differing only in amount produce different signatures, so the confirm '
          'screen is bound to what is signed rather than decorative.',
          []),
         ('P8', 'test_msg_osmosis_signtx', 'test_osmosis_signing_is_deterministic',
          'Deterministic nonces (RFC6979)',
          'Identical input yields an identical signature; a mismatch is a key-recovery risk, '
          'not a cosmetic one.',
          []),
     ]),

    ('H', 'THORChain', '7.0.0',
     'THORChain is a decentralized cross-chain liquidity protocol. Native RUNE transactions use amino '
     'encoding with thor1... bech32 addresses. The memo field is the critical security element - it '
     'encodes the entire swap/LP instruction (e.g. "SWAP:BTC.BTC:bc1q..." or "=:ETH.ETH:0x..."). A '
     'compromised host could substitute the memo destination address to steal funds. The device '
     'displays the full memo text on OLED so users can verify the swap destination, pool, and '
     'parameters before signing. THORChain also supports LP add/remove operations and deposits.',
     [
         'ADDRESS: Derive from m/44\'/931\'/0\'/0/0 -> display thor1... bech32 address',
         'SEND: Show RUNE amount + recipient + full memo text on OLED',
         'SWAP MEMO: "SWAP:BTC.BTC:bc1q..." - user verifies destination chain, asset, and receiving address',
         'LP MEMO: "ADD:BTC.BTC:thor1..." or "WITHDRAW:BTC.BTC:10000" - user verifies pool and basis points',
     ],
     [
         ('H1', 'test_msg_thorchain_getaddress', 'test_thorchain_get_address',
          'Derive THORChain address', 'Bech32 thor1... address.', []),
         ('H2', 'test_msg_thorchain_signtx', 'test_thorchain_sign_tx',
          'Sign THORChain tx — raw memo paged in full (7 memo variants)',
          'Native RUNE transfer. The COMPLETE raw memo is paged on the OLED (MEMO 1/N..N/N, '
          '72-char pages) as the sole memo gate — no structured summary can hide trailing '
          'content, and a reject on any page aborts signing. The frames below show every page '
          'for each routed memo shape (SWAP/s/=/ADD/a/+ and bare-pool).',
          ['Memo pages 1/N..N/N', 'Send + asset', 'Sign confirm']),
         ('H3', 'test_msg_thorchain_signtx', 'test_sign_btc_eth_swap',
          'Sign BTC->ETH swap', 'Cross-chain swap via THORChain memo routing.', ['Swap memo']),
         ('H4', 'test_msg_2thorchain_signtx', 'test_thorchain_sign_tx_deposit',
          'Sign THORChain deposit', 'LP deposit transaction (MsgDeposit): asset, amount and the '
          'full memo are displayed from the exact bytes being signed.',
          ['Deposit asset + memo']),
     ]),

    ('M', 'Maya Protocol', '7.0.0',
     'Maya Protocol is a THORChain fork providing cross-chain liquidity with its native CACAO token. '
     'Uses identical amino transaction format and memo-based routing as THORChain but with maya1... '
     'bech32 addresses. Maya bridges assets between Bitcoin, Ethereum, THORChain, Dash, and Kujira. '
     'The same memo security considerations apply - the device must display the full memo for swap '
     'destination verification.',
     [
         'ADDRESS: Derive from m/44\'/931\'/0\'/0/0 -> display maya1... bech32 address',
         'SEND: Show CACAO amount + recipient + full memo on OLED',
         'SWAP: Same memo format as THORChain with Maya-specific pool routing',
     ],
     [
         ('M1', 'test_msg_mayachain_getaddress', 'test_mayachain_get_address',
          'Derive Maya address', 'Bech32 maya1... address.', []),
         ('M2', 'test_msg_mayachain_signtx', 'test_sign_btc_eth_swap',
          'Sign BTC-ETH swap via Maya', 'Cross-chain swap via Maya memo routing (BTC OP_RETURN '
          'side).', []),
         ('M3', 'test_msg_mayachain_signtx', 'test_sign_eth_add_liquidity',
          'Add liquidity via Maya router (EVM side)',
          'depositWithExpiry() to the firmware-pinned Maya router; the signature is recovered '
          'to the device signer over the exact calldata.', []),
         ('M4', 'test_msg_mayachain_signtx', 'test_mayachain_sign_tx',
          'Sign native CACAO MsgSend — raw memo paged',
          'Native CACAO transfer. Signature verified host-side against the amino sign-doc '
          'digest (account/chain/fee/memo/amount/addresses all bound) and the known device '
          'pubkey — no frozen vectors to go stale. The complete raw memo is paged on the OLED '
          '(thorchain_confirm_full_memo is the sole memo gate for native MAYA too).',
          ['CACAO send confirm', 'Memo page', 'Sign confirm']),
         ('M5', 'test_msg_mayachain_signtx', 'test_mayachain_sign_tx_memos',
          'Native memo variants — every routed shape paged in full',
          'Each memo shape MAYA routes on (SWAP/s/=/ADD/a/+ and bare-pool) signs, each '
          'signature is bound to its exact memo bytes via the sign-doc digest, and every page '
          'of every memo is displayed (frames below, in order).',
          ['Memo pages 1/N..N/N per variant']),
         ('M6', 'test_msg_mayachain_signtx', 'test_mayachain_remove_liquidity',
          'Native WITHDRAW memo',
          'WITHDRAW:pool:basis-points memo paged in full; signature digest-verified.',
          ['WITHDRAW memo page']),
     ]),

    # Binance Chain (BNB) - REMOVED: chain deprecated, beacon chain shut down 2024.
    # Tests remain in python-keepkey but excluded from report.

    ('O', 'EOS', '7.0.0',
     'EOS chain support with action-based transaction model. Unlike UTXO or account-based chains, EOS '
     'transactions contain a list of actions, each targeting a specific smart contract. The device '
     'displays each action individually for user review. Covers the core eosio system actions: token '
     'transfers, CPU/NET bandwidth delegation, block producer voting, and account authority management '
     '(updateauth, linkauth, newaccount). EOS uses a unique account name system (12-char names) instead '
     'of addresses.',
     [
         'PUBKEY: Derive EOS public key from m/44\'/194\'/0\'/0/0 (EOS format with EOS prefix)',
         'SIGN TX: Host sends action list -> device displays each action with contract + data -> signs',
         'STAKING: delegatebw/undelegatebw for CPU/NET resource management',
         'GOVERNANCE: voteproducer to select block producers',
     ],
     [
         ('O1', 'test_msg_eos_getpublickey', 'test_trezor',
          'Derive EOS public key', 'EOS public key from m/44\'/194\'/0\'/0/0.', []),
         ('O2', 'test_msg_eos_signtx', 'test_transfer',
          'Sign EOS transfer', 'eosio.token::transfer action.', []),
         ('O3', 'test_msg_eos_signtx', 'test_delegatebw',
          'Delegate bandwidth', 'CPU/NET resource staking.', []),
         ('O4', 'test_msg_eos_signtx', 'test_voteproducer',
          'Vote for producer', 'Block producer voting.', []),
     ]),

    ('W', 'Nano', '7.0.0',
     'Nano uses a unique block-lattice architecture where each account has its own blockchain. '
     'Transactions are feeless and near-instant. The device validates balance encoding for Nano state '
     'blocks, which represent the entire account state (balance, representative, link) in a single block. '
     'Balance values use 128-bit raw amounts (1 Nano = 10^30 raw).',
     [
         'ENCODE: Validate 128-bit balance representation for state block construction',
         'STATE BLOCK: account + previous + representative + balance + link -> hash -> sign',
     ],
     [('W1', 'test_msg_nano_signtx', 'test_encode_balance',
       'Encode Nano balance',
       'Validates the 128-bit balance encoding used in Nano state blocks. Incorrect encoding would '
       'cause fund loss or invalid transactions on the block-lattice.',
       [])]),

    # ===== 7.15.0 NEW FEATURES =====
    ('V', 'EVM Clear-Signing', '7.15.0',
     'The purpose of clear-signing: instead of blind-signing an opaque hash, the device screen '
     'answers WHO / WHAT / WHY before the user approves. WHO = the validated contract address '
     '(full, never truncated) + attested protocol name. WHAT = the decoded method and its typed '
     'arguments in human terms (recipient address, "amount: 10.5 DAI" — not raw wei). WHY it can '
     'be trusted = a signer whose key the device trusts attested that this exact description '
     'matches this exact transaction, and the signature is REFUSED unless the signed digest '
     'equals the metadata\'s committed tx hash (fail-closed, replay-proof). '
     'NEW (phase 1): there is NO built-in "KeepKey says this is safe" key — every signer is loaded '
     'at runtime (LoadClearsignSigner, user-confirmed, RAM-only) and EVERY tx it describes is '
     'preceded by a warning naming the signer alias + fingerprint ("NOT verified by KeepKey"). '
     'The built-in warning-free path returns once the signer infra is hardened. '
     'The V9 flow below shows the full ordered review of a REAL Aave V3 supply() tx: the actual '
     'calldata (selector 0x617ba037 + asset + amount + onBehalfOf + referralCode, 132 bytes) is '
     'signed, and the metadata decodes it to protocol=Aave V3, asset=DAI, amount=10.5 DAI.',
     [
         'LOAD SIGNER: LoadClearsignSigner -> on-device confirm (alias + fingerprint) -> RAM slot',
         'WHO:  warning (signer alias) + Contract: 0x… (full address) + protocol name',
         'WHAT: Call: <method> + each decoded arg (ADDRESS / TOKEN_AMOUNT "10.5 DAI" / STRING)',
         'WHY:  signature refused unless signed digest == metadata tx_hash (replay-proof)',
         'BLIND SIGN: No metadata + AdvancedMode off -> unknown contract data hard-rejected',
     ],
     [
         ('V1', 'test_msg_ethereum_clear_signing', 'test_valid_metadata_returns_verified',
          'Valid metadata accepted',
          'Correctly signed metadata blob from a loaded signer is accepted. Device shows the '
          'clearsign warning (signer alias + fingerprint) then the decoded method + contract.',
          ['Clearsign warning (signer alias)']),
         ('V2', 'test_msg_ethereum_clear_signing', 'test_wrong_key_returns_malformed',
          'Wrong signing key rejected', 'Metadata signed with wrong key is rejected as malformed.', []),
         ('V3', 'test_msg_ethereum_clear_signing', 'test_tampered_method_returns_malformed',
          'Tampered method rejected', 'Modified method name in blob fails signature check.', []),
         ('V4', 'test_msg_ethereum_clear_signing', 'test_tampered_contract_returns_malformed',
          'Tampered contract rejected', 'Modified contract address fails signature check.', []),
         ('V5', 'test_msg_ethereum_clear_signing', 'test_no_metadata_then_sign_unchanged',
          'No metadata = blind sign path',
          'Without metadata, transaction goes through existing blind-sign path.',
          ['Blind sign warning']),
         ('V6', 'test_msg_ethereum_clear_signing', 'test_signature_verification',
          'Signature verification math', 'Unit test for the metadata blob signature algorithm.', []),
         ('V7', 'test_msg_ethereum_clear_signing', 'test_tampered_blob_fails_verification',
          'Tampered blob fails', 'Any byte change in the blob invalidates the signature.', []),
         ('V7a', 'test_msg_ethereum_clear_signing', 'test_empty_payload_returns_malformed',
          'Empty metadata payload rejected', 'A zero-length blob classifies MALFORMED, never VERIFIED.', []),
         ('V7b', 'test_msg_ethereum_clear_signing', 'test_truncated_payload_returns_malformed',
          'Truncated metadata payload rejected',
          'A blob cut short of the minimum structural size classifies MALFORMED.', []),
         ('V7c', 'test_msg_ethereum_clear_signing', 'test_extra_trailing_bytes_returns_malformed',
          'Trailing garbage bytes rejected',
          'A blob with extra bytes appended past its declared structure classifies MALFORMED — '
          'the parser cannot be tricked by appended data.', []),
         ('V7d', 'test_msg_ethereum_clear_signing', 'test_wrong_version_returns_malformed',
          'Unknown version byte rejected', 'A blob with a version byte the firmware does not '
          'recognize classifies MALFORMED rather than being guessed-parsed.', []),
         ('V7e', 'test_msg_ethereum_clear_signing', 'test_zero_signature_returns_malformed',
          'All-zero signature rejected', 'A blob with a zeroed signature field classifies '
          'MALFORMED — an attacker cannot skip signing by leaving the field blank.', []),
         ('V7f', 'test_msg_ethereum_clear_signing', 'test_empty_key_slot_returns_malformed',
          'Metadata against an empty key slot rejected',
          'A blob referencing a signer slot with no key loaded classifies MALFORMED.', []),
         ('V8', 'test_msg_ethereum_signtx', 'test_ethereum_blind_sign_allowed',
          'Blind sign permitted (AdvancedMode ON)',
          'Contract data with AdvancedMode enabled. Device allows signing. '
          'Blind-sign policy gating covered in 7.15.0+.',
          []),
         ('V9', 'test_msg_ethereum_clear_signing', 'test_binding_happy_path_signs_and_recovers',
          'Full who/what/why review of a real Aave V3 supply()',
          'TX: to=0x7d27..c7a9 (Aave V3 Pool), data=0x617ba037 + asset(DAI) + amount(10.5e18) + '
          'onBehalfOf(0xd8dA..6045) + referralCode(0), chainId 1. METADATA decodes it to '
          'protocol="Aave V3", asset=0x6B17..1d0F, amount=10.5 DAI, onBehalfOf=0xd8dA..6045, '
          'bound to the exact sighash. The OLED screens below are the full ordered review the '
          'user sees: warning -> Call: supply -> Contract -> protocol -> asset -> amount (10.5 '
          'DAI, decimal-scaled, NOT wei) -> onBehalfOf -> tx confirm. The signature then recovers '
          'to the device signer over THIS tx digest, proving the metadata was bound to this tx.',
          ['warning', 'Call: supply', 'Contract', 'protocol: Aave V3', 'asset', 'amount: 10.5 DAI',
           'onBehalfOf', 'tx confirm']),
         ('V10', 'test_msg_ethereum_clear_signing', 'test_replay_rejected_when_digest_differs',
          'Replay reject (binding enforced)',
          'Metadata committed to tx A; signing tx B (same contract/selector/chain, different '
          'calldata) is refused at send_signature with "Metadata does not match signed transaction".',
          ['Verified screen then reject']),
         ('V11', 'test_msg_ethereum_clear_signing', 'test_advanced_mode_gate',
          'AdvancedMode blind-sign gate',
          'AdvancedMode OFF + unknown contract + no metadata is hard-rejected; ON signs; a '
          'natively-decoded ERC-20 transfer is unaffected.',
          ['Blind sign disabled (Blocked)']),
         ('V12', 'test_msg_ethereum_clear_signing', 'test_cancel_clears_metadata_not_reused',
          'Cancel clears metadata (no stale reuse)',
          'Cancelling the verified confirm clears the blob; a later matching tx is not silently '
          'signed with the stale metadata.',
          []),
         ('V13', 'test_msg_ethereum_clear_signing', 'test_load_required_before_verify',
          'No built-in key: load required (phase 1)',
          'On a fresh device a valid metadata blob is MALFORMED until a signer is loaded. Proves '
          'there is no hardcoded warning-free trust path in phase 1.',
          []),
         ('V14', 'test_msg_ethereum_clear_signing', 'test_load_signer_cancel_refuses',
          'Load signer requires on-device consent',
          'Pressing reject on the LoadClearsignSigner confirm refuses the signer; the slot stays '
          'empty and metadata for it is MALFORMED.',
          ['Load clearsigner confirm']),
         ('V15', 'test_msg_ethereum_clear_signing', 'test_load_signer_invalid_pubkey_rejected',
          'Invalid signer key rejected',
          'Uncompressed, zero (empty-slot sentinel), and truncated pubkeys are refused before any '
          'confirm — a malicious host cannot install a bogus key.',
          []),
         ('V16', 'test_msg_ethereum_clear_signing', 'test_load_signer_bad_alias_rejected',
          'Signer alias sanitized',
          'Empty, oversized, control-char and format-specifier aliases are rejected — the alias '
          'is rendered on the warning screen, so it cannot carry a display-spoofing payload.',
          []),

         # ── ethereum signing-path guards (the blind-sign policy negative
         # half + the EIP-1559 type/fee/chain_id regression suite) ──
         ('VG1', 'test_msg_ethereum_signtx', 'test_ethereum_blind_sign_blocked',
          'Blind sign refused (AdvancedMode OFF)',
          'Unknown contract data with AdvancedMode disabled is hard-rejected before any confirm '
          'screen — the negative half of the V8 policy pair.',
          ['Blind signing disabled (Failure)']),
         ('VG2', 'test_msg_ethereum_signing_guards', 'test_eip1559_requires_chain_id',
          'EIP-1559 requires chain_id',
          'A type-2 tx with no chain_id would hash a garbage pre-image and recover the wrong '
          'signer; the device rejects it outright instead of signing an unbroadcastable tx.',
          []),
         ('VG3', 'test_msg_ethereum_signing_guards', 'test_eip1559_no_priority_fee_signs',
          'EIP-1559 zero priority fee signs correctly',
          'Regression test for the non-canonical-RLP wrong-signer bug: a type-2 tx with zero/'
          'absent priority fee must still hash and sign to the correct device address.',
          []),
         ('VG4', 'test_msg_ethereum_signing_guards', 'test_type2_without_max_fee_rejected',
          'Type-2 tx without max_fee_per_gas rejected', '', []),
         ('VG5', 'test_msg_ethereum_signing_guards', 'test_legacy_with_max_fee_rejected',
          'Legacy tx with max_fee_per_gas rejected',
          'Mixing legacy gas_price semantics with EIP-1559 fee fields is refused rather than '
          'silently mis-hashed.',
          []),
         ('VG6', 'test_msg_ethereum_signing_guards',
          'test_contract_handler_streamed_calldata_signs_full_data',
          'Streamed calldata signs the full payload',
          'A contract-clear-sign handler must not confirm only the first chunk while signing '
          'unshown streamed bytes after it.',
          []),
     ] + _V_CATALOG_TESTS + [
         ('V%d' % (17 + len(_V_CATALOG_TESTS)),
          'test_msg_ethereum_clear_signing', 'test_clearsign_batch_all_payloads',
          'Batch: sign + device-validate the whole catalog',
          'Signs every CLEARSIGN_FLOWS payload (%d real-world flows spanning DEX swaps, lending, '
          'staking, approvals/permits, NFTs, governance, bridges, and account abstraction — '
          'ERC-4337, EIP-7702, Safe multisig, Permit2, Uniswap V4) in one batch and has the '
          'device validate each: every blob returns VERIFIED, and the same blob with one '
          'tampered byte returns MALFORMED. Together with the frozen offline reference vectors '
          '(RFC 6979 deterministic — byte-identical blobs, sha256 snapshots in the test), this '
          'makes python-keepkey the complete signer reference: produce these bytes and the '
          'device accepts them; deviate by one byte and it refuses.' % (
              len(CLEARSIGN_FLOWS) if CLEARSIGN_FLOWS else 0),
          []),

         # ── v2 static schema (no online signer) ──────────────────────
         # v2 attests only the decode SCHEMA (no tx_hash, no arg values); the
         # DEVICE decodes the argument values from the calldata it signs. This
         # removes the per-tx online signer: the catalog is signed once, offline.
         # Offline format tests run every cycle; the on-device decode test is
         # gated to the release that ships v2 (METADATA_VERSION_SCHEMA).
         ('VS1', 'test_msg_ethereum_clear_signing', 'test_layout_has_no_tx_hash',
          'v2 schema blob carries no tx_hash / no values',
          'The v2 (static schema) blob attests only how to decode a curated '
          '(chainId, contract, selector): method + per-arg name/format (+ static '
          'decimals/symbol). It has NO committed tx_hash and NO argument values — '
          'so it can be signed ONCE, offline, and served from a CDN with no hot '
          'key. The device decodes the values itself from the calldata it signs.',
          []),
         ('VS2', 'test_msg_ethereum_clear_signing',
          'test_token_arg_carries_static_decimals_symbol_not_value',
          'v2 token arg = static decimals/symbol, value decoded on-device',
          'A TOKEN_AMOUNT arg encodes the token\'s static decimals + symbol (a '
          'property of the contract), but NOT the amount — the amount is decoded '
          'from the calldata word on-device, then rendered "1.5 USDC".',
          []),
         ('VS3', 'test_msg_ethereum_clear_signing', 'test_frozen_body_snapshot',
          'v2 wire format frozen vs firmware parser',
          'The canonical v2 body\'s length + sha256 are frozen, so the '
          'serializer can never drift from firmware\'s parse_v2_args() undetected '
          '— the same byte-parity discipline the v1 reference vectors use.',
          []),
         ('VS4', 'test_msg_ethereum_clear_signing', 'test_rejects_dynamic_format',
          'v2 scope: fixed-word types only',
          'v2 decodes fixed single ABI words (ADDRESS / AMOUNT / TOKEN_AMOUNT) — '
          'approve/transfer/transferFrom and fixed-arg calls. Dynamic types '
          '(string/bytes/arrays) are rejected by the serializer and fall to the '
          'blind-sign path on-device; a bounded dynamic decoder is future work.',
          []),
         ('VS5', 'test_msg_ethereum_clear_signing',
          'test_v2_transfer_decodes_signs_and_recovers',
          'v2 on-device: decode from calldata, sign, recover',
          'END-TO-END with AdvancedMode OFF: a v2 transfer() schema blob + a real '
          'transfer(to, amount) tx. The device decodes to/amount from the calldata '
          'and clear-signs; the signature recovers to this device\'s signer over '
          'the tx digest — so the who/what/why shown was bound to the exact tx, '
          'with no tx_hash. The offline format tests above pin the wire format '
          'the device decodes.',
          ['Clearsign warning', 'v2 decoded transfer to/amount', 'Sign transaction']),
         ('VS6', 'test_msg_ethereum_clear_signing',
          'test_v2_calldata_length_mismatch_falls_back_to_raw_review',
          'v2 decode-mismatch falls back to raw review (fail-closed)',
          'THE headline v2 security property: schema says 2 words, calldata carries 3. '
          'decode_v2_args\' structural completeness check fails, so the device does NOT '
          'clear-sign a decode that would not match what it is about to sign. With '
          'AdvancedMode ON it falls through to the ordinary unverified raw review, and '
          'the ordered OLED captures prove the decoded ClearSign display was not used.',
          ['Unverified transaction warning', 'Raw data review', 'Sign transaction']),
         ('VS7', 'test_msg_ethereum_clear_signing',
          'test_v2_unsupported_arg_format_returns_malformed',
          'v2 unsupported arg format rejected at blob load',
          'A hand-crafted v2 blob using an unsupported dynamic format (STRING) — the kind the '
          'Python serializer itself refuses to build — is independently rejected by the '
          'device\'s own parser as MALFORMED, before any calldata is even considered.',
          []),
     ]),

    ('G', 'Hive', '7.15.0',
     'NEW: Hive (Graphene) support with SLIP-0048 role derivation. Four role keys per account '
     '(owner, active, posting, memo), each an STM-prefixed secp256k1 key. Signs Graphene '
     'transactions — transfer, the account-create / account-update authority operations '
     'Pioneer uses to onboard sponsored accounts, Keychain signBuffer message signing (dApp '
     'login), and parsed generic operations (vote, comment, custom_json). Every signature '
     'recovers to the role key it was signed under, each serialized field is bound at its byte '
     'position, and every user-controlled string is paged IN FULL on the OLED (72-char ASCII '
     'pages; non-ASCII shown as complete hex). Message signing is restricted to printable '
     'ASCII: a Hive transaction digest is SHA256(chain_id || binary tx), so the printable-only '
     'whitelist makes signable messages provably disjoint from every transaction preimage on '
     'ANY fork chain — closing the message->transaction signature-oracle class.',
     [
         'KEYS: SLIP-0048 m/48\'/13\'/role\'/0\'/account\' -> STM-prefixed pubkey per role',
         'SIGN TX: Graphene serialize -> per-op confirm (amount + recipient + full memo pages) -> ECDSA sign',
         'ACCOUNT CREATE: attest 4 role authorities + new-account name -> owner-key signature',
         'SIGN MESSAGE: printable ASCII only -> role named + full message paged -> SHA256(msg) signed',
         'SIGN OPS: device re-parses the Graphene bytes; unrecognized ops are refused (no blind-sign)',
     ],
     [
         ('G1', 'test_msg_hive', 'test_hive_get_public_key_active',
          'Derive active-role key',
          'Active-role key derives and returns an STM-prefixed key plus the 33-byte compressed '
          'raw pubkey (0x02/0x03 prefix).',
          []),
         ('G2', 'test_msg_hive', 'test_hive_get_public_keys_all_roles',
          'Derive all four role keys',
          'Owner, active, posting and memo keys all derive, are distinct, and STM-formatted. The '
          'bulk path agrees with the single-key path for the active role.',
          []),
         ('G3', 'test_msg_hive', 'test_hive_sign_transfer',
          'Sign Hive transfer',
          'Transfer (op 2) signs; the signature recovers to the active key. The device shows the '
          'recipient account and amount, and every serialized field (from/to/amount/asset/memo) '
          'is bound at its position so a rewritten recipient or amount fails.',
          ['Transfer amount + recipient']),
         ('G4', 'test_msg_hive', 'test_hive_sign_account_create',
          'Sign account-create attestation',
          'account_create (op 9) signs and recovers to the owner key — the attestation a Pioneer '
          'sponsor verifies before spending an account-creation token. Binds the four role '
          'authorities, creator, new-account name and fee at their exact positions.',
          ['Account-create confirm']),
         ('G5', 'test_msg_hive', 'test_hive_sign_account_update',
          'Sign account-update',
          'account_update (op 10) signs and recovers to the owner key; the replacement '
          'authorities are bound to their slots so updating the wrong authority fails.',
          ['Account-update confirm']),
         ('G6', 'test_msg_hive', 'test_hive_sign_transfer_max_memo_ok',
          'Max-length memo paged in full (boundary)',
          'A memo of exactly 440 bytes (the serialization limit) still signs, and the OLED '
          'pages the COMPLETE memo (MEMO 1/7..7/7) — nothing is truncated behind a '
          'benign-looking prefix.',
          ['Memo pages 1/7..7/7']),
         ('G7', 'test_msg_hive', 'test_hive_sign_transfer_rejects_long_memo',
          'Over-limit memo rejected',
          'A 441-byte memo fails with a specific "memo too long" error before any signing. '
          'Rejection happens before any confirm UI, so there is no OLED frame — the proof is '
          'the specific device error.',
          []),
         ('G8', 'test_msg_hive', 'test_hive_sign_transfer_rejects_foreign_path',
          'Foreign derivation paths rejected',
          'BIP-44 trees, wrong registry, unassigned roles and short paths are all refused for '
          'transaction signing — the SLIP-0048 fence.',
          []),
         ('G9', 'test_msg_hive', 'test_hive_sign_transfer_rejects_wrong_network',
          'Wrong network index rejected',
          'A path whose network index is not Hive (13\') must not sign.',
          []),
         ('G10', 'test_msg_hive', 'test_hive_sign_transfer_rejects_non_active_roles',
          'Transfer requires the active role',
          'Transfers signed under owner/posting/memo paths are refused; only active\' moves '
          'funds.',
          []),
         ('G11', 'test_msg_hive', 'test_hive_sign_message_posting',
          'Sign Hive message (dApp login)',
          'Keychain signBuffer contract: signature over SHA256(raw message bytes) with the '
          'posting key. The device names the signing role and pages the full message text. The '
          'signature recovers to the posting key — exactly what a Hive dApp verifies for login.',
          ['Signing-role screen', 'Message text']),
         ('G12', 'test_msg_hive', 'test_hive_sign_message_all_roles',
          'Message signing across roles',
          'Posting, active and memo roles may sign (owner\' is refused); each signature '
          'recovers to that role\'s distinct key.',
          ['Role + message screens']),
         ('G13', 'test_msg_hive', 'test_hive_sign_message_long_printable_ok',
          'Long message paged in full',
          'Printable text over the display budget routes through 72-char pages — never '
          'silently truncated — and the signature covers every byte.',
          ['Message pages']),
         ('G14', 'test_msg_hive', 'test_hive_sign_message_max_length_ok',
          'Max-length (1024 B) message',
          'A message of exactly 1024 bytes (the proto cap) pages and signs.',
          ['1024-byte message paged']),
         ('G15', 'test_msg_hive', 'test_hive_sign_message_nonprintable_bytes',
          'SECURITY: binary messages refused (oracle fix)',
          'A binary "message" equal to chain_id || serialized_tx would hash to a valid '
          'TRANSACTION signature on any fork chain — an active-key fund-theft oracle. The '
          'printable-ASCII whitelist refuses every binary buffer, making signable messages '
          'provably disjoint from all transaction preimages. Rejection is pre-UI (no frame); '
          'the proof is the "printable" device error.',
          []),
         ('G16', 'test_msg_hive', 'test_hive_sign_message_rejects_chain_id_prefix',
          'Chain-id-prefixed message refused',
          'Belt-and-suspenders subset of G15: a message starting with the Hive mainnet chain '
          'id is refused outright.',
          []),
         ('G17', 'test_msg_hive', 'test_hive_sign_message_rejects_oversize',
          'Oversize message refused',
          '1025 bytes must fail — the proto cap and the handler agree on 1024.',
          []),
         ('G18', 'test_msg_hive', 'test_hive_sign_message_rejects_bad_paths',
          'Message signing path fence',
          'Foreign trees, wrong network, unassigned roles, owner\' and short paths are all '
          'refused — the same SLIP-0048 fence as transactions.',
          []),
         ('G19', 'test_msg_hive', 'test_hive_sign_ops_vote',
          'Parsed vote operation',
          'The device re-parses the Graphene bytes and displays voter, author, permlink and '
          'weight from the exact bytes being signed — a host serializer bug can only produce a '
          'rejection, never a silent wrong-sign.',
          ['Vote op screens']),
         ('G20', 'test_msg_hive', 'test_hive_sign_ops_comment',
          'Parsed comment operation',
          'Comment title and body are user-controlled strings — both paged in full (72-char '
          'ASCII pages / complete hex for non-ASCII).',
          ['Comment fields paged']),
         ('G21', 'test_msg_hive', 'test_hive_sign_ops_custom_json_active',
          'Parsed custom_json (active)',
          'custom_json id and payload paged in full under the active role.',
          ['custom_json paged']),
         ('G22', 'test_msg_hive', 'test_hive_sign_ops_custom_json_posting',
          'Parsed custom_json (posting)',
          'Same shape under the posting role (the common dApp path).',
          []),
         ('G23', 'test_msg_hive', 'test_hive_sign_ops_downvote_and_default_chain_id',
          'Downvote + default chain id',
          'Negative weights display correctly and the default chain id binds the mainnet '
          'digest.',
          []),
         ('G24', 'test_msg_hive', 'test_hive_sign_ops_role_fences',
          'Ops role fences',
          'vote/comment sign under posting\'; custom_json under its declared auth; memo\' and '
          'owner\' never sign operations.',
          []),
         ('G25', 'test_msg_hive', 'test_hive_sign_ops_rejects_excluded_and_unknown_ops',
          'Unknown/excluded ops refused (no blind-sign)',
          'transfer-shaped and unrecognized operations inside SignOperations are refused — '
          'there is no blind-sign fallback for Graphene bytes the device cannot display.',
          []),
         ('G26', 'test_msg_hive', 'test_hive_sign_ops_rejects_malformed_structure',
          'Malformed Graphene structure refused',
          'Truncated fields, wrong op counts and trailing bytes are all parse failures, not '
          'sign-what-you-can.',
          []),
         ('G27', 'test_msg_hive', 'test_hive_sign_ops_rejects_oversize',
          'Oversize operations refused',
          'Payloads beyond the proto cap are refused before parsing.',
          []),
         ('G28', 'test_msg_hive', 'test_hive_sign_account_ops_reject_non_owner_roles',
          'Account authority ops require owner',
          'account_create / account_update sign only under the owner role.',
          []),
         # ── Phase 2/3 op table (fw #315) ────────────────────────────────
         # These ran green in the full suite from the day they landed, but had
         # no SECTIONS entry, so screenshot_filter() never selected them and
         # eleven newly clear-signed ops shipped with zero OLED proof. A
         # correct signature over bytes the user was shown something else for
         # is the exact failure the clear-sign table exists to prevent, so
         # every op that renders a confirm screen gets a non-empty hint.
         ('G29', 'test_msg_hive', 'test_hive_sign_ops_limit_order_create',
          'Internal market: limit_order_create',
          'The op that motivated phase 3 — a HIVE->HBD market swap. Both sides of the order '
          'are shown with their symbols pinned (a swapped symbol hides a ~2000x value '
          'difference behind an identical-looking number), and order id / fill-or-kill / '
          'expiry get their own screen so they cannot be crowded off the first.',
          ['Sell and receive amounts', 'Order terms screen']),
         ('G30', 'test_msg_hive', 'test_hive_sign_ops_limit_order_cancel',
          'Internal market: limit_order_cancel',
          'Cancelling names the order id and the owner. No recipient row is forged — the op '
          'acts on the signer\'s own book entry.',
          ['Cancel order screen']),
         ('G31', 'test_msg_hive', 'test_hive_sign_ops_active_tier_value_ops',
          'Active-tier value ops',
          'transfer_to_vesting, convert, transfer_to/from_savings, delegate_vesting_shares '
          'and withdraw_vesting all move or lock value, so all six sign only under active. '
          'Each renders its own amount + counterparty.',
          ['Power up', 'Convert', 'Savings deposit/withdraw', 'Delegation', 'Power down']),
         ('G32', 'test_msg_hive', 'test_hive_sign_ops_posting_tier_ops',
          'claim_reward_balance is posting tier',
          'Claiming is not spending, so it signs under posting. Three reward assets across '
          'two screens (the OLED body fits three rows; a fourth would be signed but never '
          'shown).',
          ['Claim rewards screens']),
         ('G33', 'test_msg_hive', 'test_hive_sign_ops_zero_amount_semantics',
          'Zero means something for two ops, nothing for the rest',
          '0 VESTS stops a power-down and removes a delegation — both legitimate, so zero is '
          'NOT rejected there and the screen must say which action it is. Everywhere else a '
          'zero amount is a no-op and refused.',
          ['Stop power down', 'Remove delegation']),
         ('G34', 'test_msg_hive', 'test_hive_sign_ops_asset_symbol_and_precision_pinned',
          'Asset symbol pinned to its protocol precision',
          'HIVE/HBD are 3-decimal, VESTS is 6. The parser refuses any other pairing: a wrong '
          'precision moves the decimal point on the confirmation screen relative to what the '
          'chain applies.',
          []),
         ('G35', 'test_msg_hive', 'test_hive_sign_ops_comment_options_binds_to_its_comment',
          'comment_options binds to its own comment',
          'Payout redirection is only accepted immediately after a comment op with the same '
          'author and permlink. Standing alone it could attach beneficiaries to a post the '
          'user published earlier and is not reviewing on this screen.',
          ['Payout options screens']),
         ('G36', 'test_msg_hive', 'test_hive_sign_ops_comment_options_beneficiary_rules',
          'Beneficiary ordering, uniqueness and total enforced on-device',
          # Scoped to exactly what the mapped test asserts. It covers three
          # rejections — unsorted, duplicate, and weights summing over 100%.
          # The extension-count cap, the 1-8 count bound and per-beneficiary
          # weight range are enforced by the parser but are NOT exercised here,
          # so the entry must not claim them.
          'Beneficiaries must be strictly ascending by account (which also makes them unique) '
          'and their weights must sum to no more than 10000 bp. Unsorted, duplicate and '
          'over-100% lists are each refused.',
          # Rejection-only: every case here is _assert_ops_fails, so the device
          # refuses before drawing anything and the capture would be three
          # frames of the idle home screen — a report entry that LOOKS like
          # visual proof and is not. The per-beneficiary confirm screens are
          # captured by G35, which actually signs a two-beneficiary payout.
          []),
         ('G37', 'test_msg_hive', 'test_hive_sign_ops_account_update2_rejects_authority_change',
          'account_update2 cannot rotate keys',
          'Only the profile-metadata form is in the table. Any owner/active/posting/memo_key '
          'field present is a hard reject — the op-9/10 device-derived-keys invariant applied '
          'field-level.',
          []),
         ('G38', 'test_msg_hive', 'test_hive_sign_ops_truncated_bodies_rejected',
          'Truncated op bodies refused',
          'A body cut short mid-field is a parse failure, not sign-what-you-can.',
          []),
     ]),

    ('S', 'Solana', '7.14.0',
     'NEW: Full Solana with Ed25519 (SLIP-10), base58 addresses, 37 instruction types across 7 '
     'programs. Key security fix: full 44-character address display replaces old 8-char truncation '
     'that was a spoofing vector.',
     [
         'ADDRESS: m/44\'/501\'/0\' Ed25519 -> full 44-char base58 on OLED',
         'SIGN TX: Parse instructions -> per-instruction confirmation -> Ed25519 sign',
         'SIGN MESSAGE: Arbitrary bytes -> hex display -> Ed25519 sign',
     ],
     [
         ('S1', 'test_msg_solana_getaddress', 'test_solana_get_address',
          'Derive Solana address', 'Full 44-character base58 address displayed on OLED.', ['Full 44-char address']),
         ('S2', 'test_msg_solana_getaddress', 'test_solana_different_accounts',
          'Different account indices', 'Verifies different accounts produce different addresses.', []),
         ('S3', 'test_msg_solana_getaddress', 'test_solana_deterministic',
          'Deterministic derivation', 'Same path always produces same address.', []),
         ('S3b', 'test_msg_solana_getaddress', 'test_solana_show_address',
          'Show address on OLED', 'Full 44-char base58 address with QR code on OLED display.', ['Solana QR + 44-char address']),
         ('S4', 'test_msg_solana_signtx', 'test_solana_sign_system_transfer',
          'Sign SOL transfer', 'System::Transfer with full address + amount display.', ['SOL amount + address']),
         ('S5', 'test_msg_solana_signtx', 'test_solana_sign_message',
          'Sign Solana message', 'Arbitrary message signing with Ed25519 key. Requires AdvancedMode policy (no domain separation).', ['Message screen']),
         ('S6', 'test_msg_solana_signtx', 'test_solana_sign_empty_rejected',
          'Empty tx rejected', 'Zero-length transaction data is refused.', []),
         ('S7', 'test_msg_solana_signtx', 'test_solana_sign_deterministic',
          'Deterministic signing', 'Same tx always produces same signature.', []),
         ('S8', 'test_msg_solana_signtx', 'test_solana_sign_token_transfer',
          'Unchecked SPL Transfer requires AdvancedMode',
          'Unchecked Transfer (op 3) carries NO signed mint — the device cannot prove which '
          'token is moving, so it is forced through the AdvancedMode blind-sign gate (matching '
          'Trezor and Ledger, which both reject it). Only TransferChecked clear-signs.',
          ['Blind-sign gate']),
         ('S9', 'test_msg_solana_signtx', 'test_solana_sign_stake_delegate',
          'Stake delegate',
          'Delegate SOL to a validator for staking rewards. OLED shows delegate confirmation.',
          ['Delegate stake confirm']),
         ('S10', 'test_msg_solana_signtx', 'test_solana_sign_memo',
          'Memo instruction',
          'Attach memo text to transaction. OLED shows memo content.',
          ['Memo text']),
         ('S11', 'test_msg_solana_signtx', 'test_solana_sign_compute_budget_unit_price',
          'Compute budget unit price',
          'Set priority fee for transaction. OLED shows compute unit price.',
          ['Unit price']),
         ('S12', 'test_msg_solana_signtx', 'test_solana_sign_token_transfer_with_metadata',
          'Host metadata does NOT bypass the unchecked-transfer gate',
          'An unchecked Transfer accompanied by host SolanaTokenInfo still requires '
          'AdvancedMode: the mint is not part of the signed instruction, so the metadata is '
          'unauthenticated and must not make the tx look clear-signable.',
          ['Blind-sign gate']),
         ('S13', 'test_msg_solana_signtx', 'test_solana_sign_token_transfer_checked',
          'TransferChecked clear-signs with the mint on its own screen',
          'TransferChecked (op 12) binds the mint in the signed instruction bytes. The device '
          'shows "Token mint <full base58>" on a DEDICATED screen before the amount — the '
          'authenticated token identity cannot be pushed off-view by a host-controlled symbol '
          '— and decimals come from the signed instruction, never from the host. AdvancedMode '
          'stays OFF.',
          ['Token mint screen', 'Amount + symbol']),
         ('S14', 'test_msg_solana_signtx',
          'test_solana_sign_token_transfer_checked_attested_symbol',
          'Signed token definition: symbol attested by a loaded signer',
          'The token_info carries a secp256k1 attestation over (mint, decimals, symbol) by a '
          'signer loaded via LoadClearsignSigner — the same chain-agnostic trust anchor as EVM '
          'clear-sign metadata (KeepKey\'s open equivalent of Trezor\'s CoSi-signed token '
          'definitions). The device verifies it, requires the attested decimals to equal the '
          'signed instruction\'s, and adds a \'Token "USDC" signed by <alias> <fingerprint>\' '
          'screen. An invalid attestation rejects the symbol outright (never falls back to the '
          'claim).',
          ['Load signer consent', 'Token mint screen', 'Signed-by alias + fingerprint']),
         ('S15', 'test_msg_solana_signtx', 'test_solana_sign_token_approve',
          'Unchecked SPL Approve requires AdvancedMode',
          'Approve (op 4) hides the delegated token\'s mint — same gate as unchecked Transfer.',
          ['Blind-sign gate']),
         ('S16', 'test_msg_solana_signtx',
          'test_solana_sign_create_account_requires_advanced_mode',
          'CreateAccount requires AdvancedMode',
          'CreateAccount assigns the new account\'s owner program and space, which the screen '
          'does not fully disclose — gated rather than partially clear-signed.',
          ['Blind-sign gate']),
         ('S17', 'test_msg_solana_signtx',
          'test_solana_sign_set_authority_requires_advanced_mode',
          'SetAuthority requires AdvancedMode',
          'SetAuthority hands over control of a mint/account (including the undistinguishable '
          '"clear authority" case) — an account-takeover vector, gated.',
          ['Blind-sign gate']),
         ('S18', 'test_msg_solana_signtx', 'test_solana_sign_stake_authorize_clearsigns',
          'StakeAuthorize clear-signs role + new authority',
          'Shows the stake account, the role being reassigned (staker/withdrawer) and the full '
          'new authority address.',
          ['Role + new authority']),
         ('S19', 'test_msg_solana_signtx', 'test_solana_sign_stake_withdraw',
          'Stake withdraw shows the destination',
          'The withdrawal destination account is displayed in full — a host cannot silently '
          'redirect withdrawn SOL.',
          ['Withdraw + destination']),
         ('S20', 'test_msg_solana_signtx', 'test_solana_sign_stake_deactivate',
          'Stake deactivate shows the stake account',
          'The acted-on stake account is named on-screen.',
          ['Stake account']),
         ('S21', 'test_msg_solana_signtx', 'test_solana_sign_multi_instruction_2x_transfer',
          'Multi-instruction: each instruction confirmed',
          'Two transfers in one tx produce INSTR 1/2 and INSTR 2/2 screens — nothing rides '
          'along unconfirmed.',
          ['INSTR 1/2 + 2/2']),
         ('S22', 'test_msg_solana_signtx',
          'test_solana_sign_multi_instruction_transfer_and_memo',
          'Transfer + memo both shown',
          'A transfer with an attached memo instruction confirms both.',
          ['Transfer + memo screens']),
         ('S23', 'test_msg_solana_signtx', 'test_solana_sign_versioned_v0_static_verified',
          'Versioned (v0) tx with static keys clear-signs',
          'A v0-format tx whose accounts are all static parses and clear-signs like legacy.',
          ['v0 instruction screens']),
         ('S24', 'test_msg_solana_signtx', 'test_solana_sign_versioned_v0_opaque',
          'v0 with address-table lookups requires AdvancedMode',
          'Lookup-table accounts cannot be resolved on-device, so the tx routes to the '
          'blind-sign gate.',
          []),
         ('S25', 'test_msg_solana_signtx',
          'test_solana_sign_x402_zero_lut_usdc_payment',
          'x402 zero-LUT v0 USDC payment is hardware verified',
          'The sponsor pays fees while the KeepKey key authorizes TransferChecked. The device '
          'renders 0.002 USDC from firmware-owned mint metadata, derives ATA(payTo, mint) '
          'offline, and displays the merchant owner only after it matches the signed '
          'destination token account. The required x402 uniqueness memo is also displayed; '
          'AdvancedMode stays OFF.',
          ['Compute budget', 'Known USDC mint', 'Verified recipient owner',
           '0.002 USDC', 'x402 memo']),
     ]),

    ('T', 'TRON', '7.14.0',
     'NEW: TRON with secp256k1 signing, base58 addresses. Blind-sign via raw_data. '
     'Structured reconstruct-then-sign and TRC-20 clear-signing deferred to a future release.',
     [
         'ADDRESS: m/44\'/195\'/0\'/0/0 -> full 34-char base58 TRON address',
         'BLIND-SIGN: Raw protobuf data -> hash + sign',
     ],
     [
         ('T1', 'test_msg_tron_getaddress', 'test_tron_get_address',
          'Derive TRON address', 'Full 34-character base58 address.', ['Full 34-char address']),
         ('T2', 'test_msg_tron_getaddress', 'test_tron_different_accounts',
          'Different accounts', 'Different indices produce different addresses.', []),
         ('T3', 'test_msg_tron_getaddress', 'test_tron_deterministic',
          'Deterministic derivation', 'Same path always produces same address.', []),
         ('T3b', 'test_msg_tron_getaddress', 'test_tron_show_address',
          'Show address on OLED', 'Full 34-char Base58Check TRON address with QR code.', ['TRON QR + 34-char address']),
         ('T4', 'test_msg_tron_signtx', 'test_tron_sign_transfer_legacy_raw_data',
          'Sign TRX blind (raw_data)', 'Raw protobuf data triggers blind sign path. Shows amount + address if provided.', ['TRON blind sign']),
         ('T5', 'test_msg_tron_signtx', 'test_tron_sign_missing_fields_rejected',
          'Missing fields rejected', 'Incomplete transaction data is refused.', []),
     ]),

    ('N', 'TON', '7.14.0',
     'NEW: TON v4r2 wallet contracts. Ed25519 signing with structured field display. '
     'Blind-sign for raw transactions. Memo/comment support. '
     'Full clear-sign with cell tree reconstruction deferred to a future release.',
     [
         'ADDRESS: m/44\'/607\'/0\' -> full 48-char base64url TON address',
         'STRUCTURED: Amount + address + memo shown as display context -> sign',
         'BLIND-SIGN: Raw tx without structured fields -> "BLIND SIGNATURE" warning',
     ],
     [
         ('N1', 'test_msg_ton_getaddress', 'test_ton_get_address',
          'Derive TON address', 'Full 48-character base64url address.', ['Full 48-char address']),
         ('N2', 'test_msg_ton_getaddress', 'test_ton_different_accounts',
          'Different accounts', 'Different indices produce different addresses.', []),
         ('N2b', 'test_msg_ton_getaddress', 'test_ton_show_address',
          'Show address on OLED', 'Full 48-char base64url TON address with QR code.', ['TON QR + 48-char address']),
         ('N3', 'test_msg_ton_getaddress', 'test_ton_address_format',
          'Address format validation', 'Bounceable/non-bounceable format check.', []),
         ('N4', 'test_msg_ton_signtx', 'test_ton_sign_structured',
          'Sign TON transfer', 'Structured fields shown as display context. Blind-sign with amount + address.', ['TON Transfer']),
         ('N5', 'test_msg_ton_signtx', 'test_ton_sign_with_memo',
          'Sign TON with memo', 'Memo/comment displayed before signing.', ['Memo display']),
         ('N6', 'test_msg_ton_signtx', 'test_ton_sign_legacy_raw_tx',
          'Sign TON blind', 'Raw tx without structured fields triggers blind sign.', ['Blind warning']),
         ('N7', 'test_msg_ton_signtx', 'test_ton_sign_missing_fields_rejected',
          'Missing fields rejected', 'Incomplete data refused.', []),
     ]),

    ('Y', 'Zcash Transparent', '7.0.0',
     'Transparent t-address Zcash (send/receive) over the generic Bitcoin UTXO signing path with '
     'Overwinter/Sapling-v4 branch handling. This is the Zcash functionality that ships ENABLED on '
     'the regular 7.15.0 build -- t1.../t3... addresses sign like Bitcoin (SECP256K1) with a '
     'FeeOverThreshold guard. No shielded/Orchard engine is involved; contrast with section Z '
     '(shielded), which also ships in the regular product and is stripped from bitcoin-only.',
     [
         'INPUT: TxInputType over the Zcash coin (t-address, SECP256K1)',
         'METADATA: version_group_id + branch_id for the target upgrade',
         'CONFIRM: amount + destination on the OLED, then sign each input',
         'FEE GUARD: an implausibly high fee triggers a confirmation prompt',
     ],
     [
         ('Y1', 'test_msg_signtx_zcash', 'test_transparent_one_one',
          'Transparent 1-in 1-out',
          'Sign a standard transparent Zcash spend; the device shows the amount and destination '
          't-address before producing a signature over the overwinter sighash.',
          ['Zcash send confirm']),
         ('Y2', 'test_msg_signtx_zcash', 'test_transparent_one_one_fee_too_high',
          'High-fee guard',
          'An implausibly high fee triggers the FeeOverThreshold confirmation before signing.',
          []),
         ('Y3', 'test_msg_signtx_zcash', 'test_shieldedIn_one_one_fee_1',
          'Transparent spend (fee scenario 1)',
          'Despite the legacy method name, this signs a transparent input/output over the same '
          'overwinter path (no Orchard).',
          []),
         ('Y4', 'test_msg_signtx_zcash', 'test_shieldedIn_one_one_fee_2',
          'Transparent spend (fee scenario 2)',
          'Second transparent fee scenario over the overwinter path.',
          []),
     ]),

    ('Z', 'Zcash Shielded (Orchard)', '7.14.0',
     'Shielded Orchard (PCZT streaming, Full Viewing Key export, unified-address display with an '
     'on-device ZIP-32 Sec 6.1 seed-fingerprint attestation) ships in the regular 7.15.0 product. '
     'KK_ZCASH_PRIVACY is enabled for the regular build and disabled only for bitcoin-only. This '
     'report covers device FVK/address behavior and the Python PCZT streaming contract. Mainnet '
     'proof construction and the physical shield, deshield, and Orchard-to-Orchard matrix are '
     'recorded separately in the RC18 release evidence.',
     [
         'FVK: Derive ak, nk, rivk components via ZIP-32 Orchard path',
         'ADDRESS: Device derives its own unified address + shows it; optional seed-fingerprint pin',
         'PCZT: Stream header -> actions one at a time -> confirm each -> return signatures',
         'HYBRID: Transparent inputs + Orchard outputs in same tx',
     ],
     [
         ('Z1', 'test_msg_zcash_orchard', 'test_fvk_reference_vectors',
          'FVK reference vectors', 'FVK output matches known test vectors.', ['FVK export']),
         ('Z2', 'test_msg_zcash_orchard', 'test_fvk_field_ranges',
          'FVK field ranges', 'ak, nk, rivk are within valid Pallas curve ranges.', []),
         ('Z3', 'test_msg_zcash_orchard', 'test_fvk_consistency_across_calls',
          'FVK deterministic', 'Same account always produces same FVK.', []),
         ('Z4', 'test_msg_zcash_orchard', 'test_fvk_different_accounts',
          'FVK different accounts', 'Different accounts produce different FVKs.', []),
         ('Z5', 'test_msg_zcash_orchard', 'test_fvk_abandon_mnemonic',
          'FVK abandon-mnemonic vector',
          'FVK derivation matches the Orchard reference vector for the standard abandon mnemonic.',
          []),
         ('Z6', 'test_msg_zcash_display_address', 'test_zcash_display_address_basic',
          'Display unified address',
          'Device derives its OWN Orchard unified address (u1...) from the ZIP-32 path, shows it '
          'on the OLED for confirmation, and returns it with the device seed fingerprint. The host '
          'does not supply the address — this defends against a compromised host showing a fake UA.',
          ['Unified address (u1...)']),
         ('Z7', 'test_msg_zcash_display_address', 'test_zcash_display_address_bad_path_rejected',
          'Reject malformed address path',
          'A path that is neither m/32\'/133\'/account\' nor an explicit account is rejected with a '
          'SyntaxError, so no wrong-account address is ever derived silently.',
          []),
         ('Z8', 'test_msg_zcash_seed_fingerprint', 'test_get_orchard_fvk_returns_seed_fingerprint',
          'FVK carries seed fingerprint',
          'ZcashGetOrchardFVK returns a 32-byte ZIP-32 §6.1 seed fingerprint alongside the FVK.',
          []),
         ('Z9', 'test_msg_zcash_seed_fingerprint', 'test_fingerprint_stable_across_accounts',
          'Fingerprint bound to seed not account',
          'The seed fingerprint is identical across account indices — it identifies the device seed.',
          []),
         ('Z10', 'test_msg_zcash_seed_fingerprint', 'test_display_address_helper_accepts_matching_fingerprint',
          'Address display accepts matching fingerprint',
          'When the host supplies expected_seed_fingerprint and it matches, the device derives and '
          'displays the address and echoes the fingerprint.',
          ['Unified address (u1...)']),
         ('Z11', 'test_msg_zcash_seed_fingerprint', 'test_display_address_helper_rejects_wrong_fingerprint',
          'Address display rejects wrong fingerprint',
          'A mismatched expected_seed_fingerprint is rejected before any derivation — the host '
          'cannot get an attestation from the wrong device.',
          []),
         ('Z12', 'test_msg_zcash_seed_fingerprint', 'test_display_address_helper_backward_compat',
          'Address display without fingerprint',
          'Omitting expected_seed_fingerprint still works; the device populates the fingerprint on '
          'the response regardless.',
          []),
         ('Z13', 'test_msg_zcash_seed_fingerprint', 'test_device_fingerprint_matches_python_helper',
          'Fingerprint matches host computation',
          'The device-derived fingerprint equals calculate_seed_fingerprint(seed) — firmware C and '
          'the python helper agree byte-for-byte for the all-all-all seed.',
          []),
         ('Z14', 'test_msg_zcash_seed_fingerprint', 'test_sign_pczt_helper_rejects_wrong_fingerprint',
          'PCZT signing rejects wrong fingerprint',
          'A wrong expected_seed_fingerprint on a PCZT signing request is rejected before any '
          'signing crypto runs.',
          []),
         ('Z15', 'test_msg_zcash_sign_pczt',
          'test_all_dummy_shield_streams_outputs_inputs_and_no_orchard_sigs',
          'Shield streams dummy actions without device signatures',
          'The client streams transparent inputs/outputs and both dummy Orchard actions, preserves '
          'their finalized PCZT signatures, and expects no compact device Orchard signatures.',
          []),
         ('Z16', 'test_msg_zcash_sign_pczt',
          'test_mixed_deshield_returns_only_real_spend_signature',
          'Deshield returns only real-spend signatures',
          'A mixed real/dummy Orchard action set returns one compact signature for the real spend.',
          []),
         ('Z17', 'test_msg_zcash_sign_pczt',
          'test_private_send_preserves_compact_real_spend_order',
          'Private send preserves real-spend signature order',
          'Compact device signatures remain ordered by the real-spend actions when dummy actions '
          'are interleaved. OFFLINE CONTRACT TEST -- like every test in test_msg_zcash_sign_pczt, '
          'it drives a ScriptedTransport with canned responses and never reaches a device. It '
          'proves the client builds and orders the messages correctly; it proves nothing about '
          'firmware behaviour, and it can never produce an OLED frame. ZcashSignPCZT is not sent '
          'to a device anywhere in this suite, so the on-device shielded signing path -- '
          'including the per-output confirm that is the designed verification gate for Orchard '
          'output values -- has no automated coverage at all. Shielded signing must be walked on '
          'real hardware.',
          []),
         ('Z18', 'test_msg_zcash_sign_pczt',
          'test_missing_is_spend_is_rejected_before_device_call',
          'Missing spend classification rejected',
          'Every action must explicitly declare is_spend before any device call is made.',
          []),
         ('Z19', 'test_msg_zcash_sign_pczt',
          'test_host_transparent_sighash_is_rejected_before_device_call',
          'Host transparent sighash rejected',
          'The client refuses a host-provided transparent sighash instead of forwarding it as '
          'trusted device input.',
          []),
         ('Z20', 'test_msg_zcash_sign_pczt',
          'test_signature_count_must_match_real_spends',
          'Signature count bound to real spends',
          'The returned compact signature count must equal the number of real-spend actions.',
          []),
         ('Z21', 'test_msg_zcash_sign_pczt',
          'test_duplicate_action_request_is_rejected',
          'Duplicate action requests rejected',
          'A repeated device request for the same action index aborts the streaming session.',
          []),
         ('Z22', 'test_msg_zcash_sign_pczt_device',
          'test_shielded_output_review_is_two_screens',
          'Shielded output review: amount and full address (ON DEVICE)',
          'The first test in this suite that sends ZcashSignPCZT to an actual device -- Z15-Z21 '
          'above are offline contract tests against a scripted transport. Signs a shielded-only '
          'transaction built from the firmware\'s own known-answer note vector, so the device '
          'accepts its recomputed commitment, and asserts the output review is two screens. It '
          'has to be: a unified address is 106 characters, three full body rows, and the body is '
          'three rows total, so a single confirm holding the question, the address and the amount '
          'renders 76 characters of address and silently drops the rest along with the amount. '
          'That screen is the verification gate for Orchard output values -- total_amount on the '
          'summary is a host-supplied prompt -- so the amount vanishing there is the whole trust '
          'story. Verified as a regression test: against the shipped 7.15.0 RC emulator it fails '
          'with "expected 2 ConfirmOutput screens, got 1".',
          ['Shielded amount review', 'Shielded recipient address']),
         ('Z23', 'test_msg_zcash_sign_pczt_device',
          'test_note_commitment_binds_the_recipient',
          'Tampered recipient breaks the note commitment (ON DEVICE)',
          'Flipping one bit of the recipient makes the device-recomputed cmx disagree with the '
          'supplied commitment, and signing is refused. This is what stops a host displaying one '
          'recipient while committing to another.',
          []),
         ('Z24', 'test_msg_zcash_sign_pczt_device',
          'test_pool_selection_is_honoured',
          'Orchard commitment rejected under the Ironwood pool (ON DEVICE)',
          'The same note commits to a different value in each pool, so offering the Orchard '
          'commitment while declaring Ironwood must be rejected. Passes trivially if the device '
          'ignores shielded_pool, which is why it is paired with Z25.',
          []),
         ('Z25', 'test_msg_zcash_sign_pczt_device',
          'test_ironwood_note_is_accepted',
          'Ironwood commitment for the same note is accepted (ON DEVICE)',
          'The positive half of Z24: identical inputs, Ironwood commitment, accepted. Together '
          'they prove the pool branch is selected by shielded_pool rather than one path serving '
          'both.',
          []),
     ]),

    ('D', 'BIP-85 Child Derivation', '7.14.0',
     'NEW: Derives child BIP-39 mnemonic from master seed via HMAC-SHA512 (BIP-85). Display-only: '
     'derived words appear on OLED, never transmitted over USB. Seed accessed in CONFIDENTIAL '
     'buffer, memzero\'d after use.',
     [
         'DERIVE: word_count + language + index -> HMAC-SHA512 -> child entropy -> BIP-39 words',
         'DISPLAY: Words shown on OLED only -> user writes down -> never sent to host',
     ],
     [
         ('D1', 'test_msg_bip85', 'test_bip85_12word_flow',
          'Derive 12-word child',
          'Derives 128 bits of child entropy -> 12-word BIP-39 mnemonic displayed on OLED.',
          ['Derivation params', 'Mnemonic on OLED']),
         ('D2', 'test_msg_bip85', 'test_bip85_24word_flow',
          'Derive 24-word child', '256 bits -> 24 words.', []),
         ('D3', 'test_msg_bip85', 'test_bip85_18word_flow',
          'Derive 18-word child', '192 bits -> 18 words.', []),
         ('D4', 'test_msg_bip85', 'test_bip85_different_indices_different_flows',
          'Different indices', 'Index 0 and index 1 must produce completely different mnemonics.', []),
         ('D5', 'test_msg_bip85', 'test_bip85_deterministic_flow',
          'Deterministic', 'Same seed + same index always produces same child mnemonic.', []),
         ('D6', 'test_msg_bip85', 'test_bip85_invalid_word_count',
          'Invalid count rejected', 'Word counts other than 12/18/24 are refused.', []),
     ]),
]

# ---------------------------------------------------------------
# Render
# ---------------------------------------------------------------
def render(output_path, fw_version, results, screenshot_dir=None):
    pdf = PDF(); pb = PB(pdf)
    _build_frame_census(screenshot_dir)
    ts = datetime.now().strftime('%Y-%m-%d %H:%M')
    build_label = os.environ.get('KK_BUILD_LABEL', '').strip()
    active = [(l,t,mf,bg,fl,tests) for l,t,mf,bg,fl,tests in SECTIONS if ver_ge(fw_version, mf)]
    # Separate specs section (no tests) from test sections
    specs = [s for s in active if not s[5]]

    # Classify each section by its strongest per-test outcome so the report
    # distinguishes "ran and passed/failed" from "skipped by design (build-flag
    # or policy gated, e.g. KK_ZCASH_PRIVACY-off shielded Zcash)" from "no result
    # at all". A design-skip is NOT missing firmware support.
    def _section_state(s):
        st = [_lookup(results, t[1], t[2]) for t in s[5]]
        if any(x in ('pass', 'fail', 'error') for x in st):
            return 'tested'
        if any(x == 'skip' for x in st):
            return 'withheld'   # only skips -> intentionally gated on this build
        return 'pending'        # nothing ran -> feature not present
    tested   = [s for s in active if s[5] and _section_state(s) == 'tested']
    withheld = [s for s in active if s[5] and _section_state(s) == 'withheld']
    pending  = [s for s in active if s[5] and _section_state(s) == 'pending']
    test_sections = tested + withheld + pending
    total = sum(len(s[5]) for s in test_sections)
    passed  = sum(1 for s in test_sections for t in s[5] if _lookup(results, t[1], t[2]) == 'pass')
    failed  = sum(1 for s in test_sections for t in s[5] if _lookup(results, t[1], t[2]) in ('fail','error'))
    skipped = sum(1 for s in test_sections for t in s[5] if _lookup(results, t[1], t[2]) == 'skip')
    missing = total - passed - failed - skipped

    # Title
    pb.text(20, 'KeepKey Firmware Test Report', bold=True)
    pb.gap(2)
    if failed > 0:
        pb.text(11, f'Firmware {fw_version}  |  {ts}  |  {failed} FAILED of {total} tests', bold=True, color=RED)
    elif missing == 0 and total > 0:
        # Everything that exists ran green; remaining are deliberate design-skips.
        extra = f', {skipped} skipped (withheld)' if skipped else ''
        pb.text(11, f'Firmware {fw_version}  |  {ts}  |  {passed}/{total} PASSED{extra}', bold=True, color=GREEN)
    else:
        parts = [f'{passed} passed']
        if skipped: parts.append(f'{skipped} skipped')
        if missing: parts.append(f'{missing} pending')
        pb.text(10, f'Firmware {fw_version}  |  {ts}  |  {total} tests: {", ".join(parts)}')
    if build_label:
        for line in _w(f'Candidate: {build_label}', 95):
            pb.text(8, line, bold=True)
    # Scope of this document. The catalog is a curated subset, and saying so is
    # the difference between evidence and a misleading completeness claim: an RC
    # audit grepped this PDF for feature keywords, found none, and reported four
    # features as untested when their tests had run green in the same CI run.
    ran = JUNIT_CENSUS['ran']
    if ran:
        pb.gap(3)
        for line in _w('Scope: this report is a curated catalog of %d tests. The CI run executed %d '
                       '(%d of them native firmware unit tests). Absence from this report is NOT '
                       'evidence that a feature is untested -- check the JUnit artifacts.'
                       % (total, ran, JUNIT_CENSUS['native']), 100):
            pb.text(8, line, color=GRAY)
    pb.gap(6)
    pb.text(12, 'Sections', bold=True)
    _hdr_withheld = _hdr_pending = False
    for letter, title, mf, _, _, tests in test_sections:
        state = _section_state((letter, title, mf, None, None, tests))
        is_new = ver_t(mf) > (7, 10, 0)
        if state == 'withheld' and not _hdr_withheld:
            pb.text(9, '  --- Withheld on this build (build-flag gated; skipped by design) ---', bold=True, color=GRAY)
            _hdr_withheld = True
        elif state == 'pending' and not _hdr_pending:
            pb.text(9, '  --- Pending (no firmware support yet) ---', bold=True, color=GRAY)
            _hdr_pending = True
        tag = ' [NEW]' if is_new else ''
        p = sum(1 for t in tests if _lookup(results, t[1], t[2]) == 'pass')
        if p == len(tests) and len(tests) > 0:
            pb.text(8, f'  {letter}  {title}{tag} -- {p}/{len(tests)} passed', color=GREEN)
        elif p > 0:
            pb.text(8, f'  {letter}  {title}{tag} -- {p}/{len(tests)} passed')
        else:
            pb.text(8, f'  {letter}  {title}{tag} -- {len(tests)} tests', color=GRAY)

    # Render test sections (specs/device info moved to appendix after tests)
    for letter, title, mf, background, user_flow, tests in test_sections:
        pb.gap(10); pb.need(80)
        tag = ' [NEW]' if ver_t(mf) > (7, 10, 0) else ''
        pb.text(14, f'{letter}. {title}{tag}', bold=True)
        pb.gap(2)
        for line in _w(background, 95): pb.text(8, line)
        pb.gap(3)
        pb.text(9, 'User Flow', bold=True)
        for line in user_flow: pb.text(7, line)
        if not tests: continue
        pb.gap(3)
        p = sum(1 for t in tests if _lookup(results, t[1], t[2]) == 'pass')
        f_count = sum(1 for t in tests if _lookup(results, t[1], t[2]) in ('fail','error'))
        if p == len(tests):
            pb.text(9, f'Tests: {p}/{len(tests)} -- ALL PASSED', bold=True, color=GREEN)
        elif f_count > 0:
            pb.text(9, f'Tests: {p}/{len(tests)} passed, {f_count} FAILED', bold=True, color=RED)
        else:
            pb.text(9, f'Tests: {len(tests)}', bold=True)
        pb.gap(2)
        for tid, mod, meth, title, ctx, scr in tests:
            pb.need(50)
            r = _lookup(results, mod, meth)
            pb.check(9, f'{tid} {meth}', r)
            pb.text(7, f'{title}  ({mod}.py)')
            for cline in _w(ctx, 95): pb.text(7, cline)
            # Embed OLED screenshots -- use _pick_best_frame for the primary image,
            # then show up to 2 more frames for multi-screen flows (signing, swaps)
            if screenshot_dir:
                test_dir = os.path.join(screenshot_dir, mod.replace('test_',''), meth)
                btn_files = sorted(f for f in os.listdir(test_dir) if f.startswith('btn')) if os.path.isdir(test_dir) else []
                # Flagship who/what/why flows: show EVERY review screen in the
                # order the user sees them, not a "best" thumbnail. This is the
                # proof that the device decodes and displays the transaction.
                if (mod, meth) in FULL_SEQUENCE_TESTS:
                    shown = 0
                    for f in btn_files:
                        p = os.path.join(test_dir, f)
                        lr = _frame_lit_ratio(p)
                        if lr is None or lr < 0.02 or lr > 0.55:
                            continue
                        try:
                            pb.need(55)
                            pb.image(p, display_w=384, display_h=96)
                            shown += 1
                        except Exception:
                            pass
                    if shown:
                        pb.text(6, f'({shown} OLED review screens, in order)', color=GRAY)
                    elif scr:
                        pb.text(7, f'OLED needed: {", ".join(scr)}', color=GRAY)
                    pb.gap(3)
                    continue
                best = _pick_best_frame(test_dir, btn_files)
                if best:
                    # Show the best frame (most representative)
                    try:
                        pb.need(55)
                        pb.image(best, display_w=384, display_h=96)
                    except Exception:
                        pass
                    # For multi-screen tests, show up to 2 more meaningful frames.
                    # setUp noise is already stripped at capture time; drop
                    # blanks, generic cross-test chrome, and the `best` frame.
                    extra = []
                    for f in btn_files:
                        p = os.path.join(test_dir, f)
                        if p == best:
                            continue
                        r = _frame_lit_ratio(p)
                        if (r is not None and 0.02 <= r <= 0.55 and
                                _frame_hash(p) not in _GENERIC_FRAME_HASHES):
                            extra.append(f)
                    if not extra:
                        # Every other frame is cross-test-shared. Outcome frames
                        # that FOLLOW the best one (a blocked-gate screen after
                        # the send preamble) are still this test's story — show
                        # moderately-shared ones; frames in 8+ dirs are pure
                        # chrome (policy toggles), and anything before `best`
                        # is setup noise.
                        seen_best = False
                        for f in btn_files:
                            p = os.path.join(test_dir, f)
                            if p == best:
                                seen_best = True
                                continue
                            if not seen_best:
                                continue
                            r = _frame_lit_ratio(p)
                            if (r is not None and 0.02 <= r <= 0.55 and
                                    _FRAME_DIR_COUNTS.get(_frame_hash(p), 1) < 8):
                                extra.append(f)
                    extra = extra[:2]
                    for frame in extra:
                        try:
                            pb.need(55)
                            pb.image(os.path.join(test_dir, frame), display_w=384, display_h=96)
                        except Exception:
                            pass
                    if len(extra) + 1 < len(btn_files):
                        pb.text(6, f'({len(btn_files)} OLED frames captured, showing {len(extra)+1})', color=GRAY)
                elif scr:
                    pb.text(7, f'OLED needed: {", ".join(scr)}', color=GRAY)
            elif scr:
                pb.text(7, f'OLED needed: {", ".join(scr)}', color=GRAY)
            pb.gap(3)

    # Appendix: Device Specifications (after all test results)
    if specs:
        pb.gap(15)
        pb.text(14, 'Appendix: Device Specifications', bold=True)
        pb.gap(4)
        for letter, title, mf, background, user_flow, tests in specs:
            for line in _w(background, 95): pb.text(7, line)
            pb.gap(2)
            for line in user_flow: pb.text(6, line)

    pb.finish()
    pdf.write(output_path)
    print(f'{output_path}: fw={fw_version}, {len(active)} sections, {total} tests '
          f'({passed} passed, {failed} failed, {skipped} skipped, {missing} pending)')

def screenshot_filter(fw_version):
    """Return pytest -k expression for tests with non-empty screenshot expectations.

    This is the SINGLE SOURCE OF TRUTH for which tests need OLED capture.
    The shell script calls this instead of maintaining a hardcoded filter.
    Adding screenshots to a test in SECTIONS automatically includes it in CI Phase 1.
    """
    active = [(l,t,mf,bg,fl,tests) for l,t,mf,bg,fl,tests in SECTIONS if ver_ge(fw_version, mf)]
    terms = []
    for letter, title, mf, bg, fl, tests in active:
        for tid, mod, meth, ttl, ctx, scr in tests:
            if scr:  # non-empty screenshot list = needs OLED capture
                # Use (method and module) for unambiguous pytest -k matching
                terms.append(f'({meth} and {mod})')
    return ' or '.join(terms)


# Modules whose tests must actually RUN once the firmware is new enough to be
# catalogued for them -- a skip is a failure, not a waiver.
#
# The general rule below treats 'skip' as a design waiver, which is right for
# build-flag-gated features (bitcoin-only, zcash-privacy). It is wrong for a
# capability the build claims to have: every taproot test opens with
# requires_taproot(), so if that capability regressed, all six would skip and
# the report would still read green -- the report would be certifying coverage
# it never obtained. Listing a module here converts that silence into a failure.
MUST_RUN_MODULES = {
    'test_msg_signtx_taproot',
    'test_msg_getaddress_taproot',
}


def validate_junit(fw_version, results):
    """Check SECTIONS tests against JUnit results. Returns (passed, failed_list).

    A test is considered failed if it appears in SECTIONS for this firmware version
    and the JUnit result is 'fail' or 'error' (not 'skip' or 'pass').
    Tests with no JUnit entry are treated as missing (also a failure).
    Tests that were skipped (gated by requires_message/requires_firmware) are OK,
    unless their module is in MUST_RUN_MODULES.
    """
    active = [(l,t,mf,bg,fl,tests) for l,t,mf,bg,fl,tests in SECTIONS if ver_ge(fw_version, mf)]
    failures = []
    for letter, title, mf, bg, fl, tests in active:
        for tid, mod, meth, ttl, ctx, scr in tests:
            status = _lookup(results, mod, meth)
            if status in ('fail', 'error'):
                failures.append((tid, mod, meth, status))
            elif status == 'skip' and mod in MUST_RUN_MODULES:
                failures.append((tid, mod, meth, 'skipped-but-required'))
            elif not status:
                failures.append((tid, mod, meth, 'missing'))
    return (len(failures) == 0, failures)


def main():
    p = argparse.ArgumentParser(description='KeepKey Firmware Test Report')
    p.add_argument('--output', default='test-report.pdf')
    p.add_argument('--fw-version', default=None)
    p.add_argument('--junit', default=None, help='JUnit XML for pass/fail results')
    p.add_argument('--screenshots', default=None, help='Directory with per-test OLED screenshots')
    p.add_argument('--screenshot-filter', action='store_true',
                   help='Print pytest -k expression for tests needing screenshots, then exit')
    p.add_argument('--validate-junit', action='store_true',
                   help='Validate JUnit results against SECTIONS, exit non-zero on failures')
    args = p.parse_args()

    fw = args.fw_version
    if not fw:
        print('Detecting firmware from emulator...', file=sys.stderr)
        fw = detect_fw()
        if fw: print(f'Detected: {fw}', file=sys.stderr)
        else: print('No emulator, defaulting to 7.10.0', file=sys.stderr); fw = '7.10.0'

    if args.screenshot_filter:
        print(screenshot_filter(fw))
        sys.exit(0)

    if args.validate_junit:
        if not args.junit:
            print('ERROR: --validate-junit requires --junit=<path>', file=sys.stderr)
            sys.exit(2)
        results = parse_junit(args.junit)
        ok, failures = validate_junit(fw, results)
        if ok:
            print(f'SECTIONS validation passed: all tests for fw {fw} are pass or skip')
            sys.exit(0)
        else:
            print(f'SECTIONS validation FAILED: {len(failures)} test(s) not green for fw {fw}:')
            for tid, mod, meth, status in failures:
                print(f'  {tid} {mod}::{meth} -> {status}')
            sys.exit(1)

    results = parse_junit(args.junit) if args.junit else {}
    render(args.output, fw, results, args.screenshots)

if __name__ == '__main__':
    main()
