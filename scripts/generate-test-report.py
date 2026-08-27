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

# Tests whose newer fail-closed behavior deliberately returns before drawing a
# confirmation screen. Keep their historical catalog text, but do not schedule
# or audit an OLED capture once the refusal behavior is active.
_NO_SCREEN_FROM = {
    ('test_msg_signtx_ethereum_erc20', 'test_approve_all'): '7.14.2',
}


def _screens_for(fw_version, mod, meth, screens):
    floor = _NO_SCREEN_FROM.get((mod, meth))
    if floor and ver_ge(fw_version, floor):
        return []
    return screens


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
JUNIT_CENSUS = {'ran': 0, 'skipped': 0, 'native': 0}


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
        # 'ran' counts every collected testcase, skips included. A version-gated
        # feature test that SKIPs on an older emulator is NOT evidence the feature
        # works, so the two must never be reported as one number.
        if status == 'skip':
            JUNIT_CENSUS['skipped'] += 1
        # Extract module from classname: tests.test_msg_foo.TestBar → test_msg_foo
        mod = ''
        if cls:
            parts = cls.split('.')
            for p in parts:
                # Any test module, not just the test_msg_/test_sign_/test_verify_
                # families. test_storage_version_gate matched none of those, so
                # it produced no 'mod::meth' key and all eight of its results
                # were invisible -- the section rendered "Pending (no firmware
                # support yet)" while the tests were passing.
                if p.startswith('test_'):
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
    # The additive invariant IS an ordered-sequence claim: the decoded screens
    # are additional and the baseline raw review still follows them. Showing a
    # best-of-3 sample would hide exactly the thing being proved.
    ('test_msg_ethereum_clearsign_additive',
     'test_successful_decode_still_runs_the_raw_review'),
    ('test_msg_ethereum_clearsign_additive',
     'test_v2_schema_decode_still_runs_the_raw_review'),
    ('test_msg_ethereum_clearsign_additive',
     'test_failed_signature_falls_back_to_the_unverified_review'),
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
    ('J', 'Display Binding - What the Device Signs Is What It Shows', '7.14.2',
     'The 7.14.2 security release changed what reaches the OLED on the signing paths. Every '
     'defect it fixed was a case of the device hashing bytes it never rendered, or rendering '
     'text it could not vouch for. These tests exist to capture those screens: a passing wire '
     'assertion proves the device refused or signed, but only the screen proves the user was '
     'told the truth about what they approved.',
     [
         'DISCLOSURE RULE: every byte covered by the signature must be reachable on screen.',
         '',
         'The defects this section guards against, all shipped at some point:',
         '- bytes past an embedded NUL were signed and never drawn ("%s" stops at 0x00)',
         '- whitespace padding pushed a tail past the cut with no warning',
         '- 456 bytes past the initial chunk were hashed with a clear-sign screen showing',
         '  confident token amounts for calldata the device had not seen',
         '- an unresolved token rendered as the literal "Unknown token value" and signed',
         '- a truncated memo dropped its last character (Confirm limit 42 vs 420)',
         '',
         'A test here with an EMPTY screenshot list is deliberate: refusal paths draw nothing,',
         'and their evidence is the Failure on the wire plus the absence of a ButtonRequest.',
     ],
     [
         ('J1', 'test_msg_ethereum_erc20_0x_signtx', 'test__sign_transformERC20',
          '0x transformERC20 raw disclosure',
          'A 1480-byte transformERC20 payload exceeds one 1024-byte chunk. The device must NOT '
          'clear-sign it as a token swap, because the bytes past the initial chunk are hashed '
          'without being decoded. With AdvancedMode on it falls to the raw path, where the byte '
          'count shown must be the FULL length (1480), not the chunk length (1024) - a short '
          'count would under-report what is being signed.',
          ['Raw contract data screen showing the full byte count']),
         ('J2', 'test_msg_ethereum_erc20_0x_signtx', 'test_sign_0x_swap_ERC20_to_ETH',
          '0x sellToUniswap names both assets',
          'Clear-signing is only honest when BOTH token words resolve to known assets. This '
          'payload resolves (USDC -> ETH) and must name both sides with real amounts. The '
          'failure this guards is a screen naming a DEX while showing no amount.',
          ['Swap screen naming both assets and amounts']),
         ('J3', 'test_msg_ethereum_erc20_0x_signtx', 'test_sign_longdata_swap',
          'Long 0x calldata stays disclosed',
          'Calldata spanning multiple chunks must not silently lose its tail from the display '
          'while remaining inside the signature.',
          ['Contract data screen']),
         ('J8', 'test_msg_ethereum_signing_guards',
          'test_contract_handler_streamed_calldata_signs_full_data',
          'Streamed calldata is fully covered',
          'Calldata delivered across several chunks must be hashed in full and disclosed in full. '
          'This is the positive control for the chunk-completeness gate. NOTE: every test in '
          'test_msg_ethereum_signing_guards currently SKIPS in CI under requires_firmware, so no '
          'screen can be captured for it yet - the screenshot list stays empty until the gate '
          'opens, rather than declaring an expectation nothing can satisfy.',
          []),
         ('J9', 'test_msg_ethereum_signing_guards', 'test_eip1559_requires_chain_id',
          'Omitted chain_id is refused before any screen',
          'Without a chain_id the device cannot name the network, and a signature would be '
          'pre-EIP-155 - replayable on every EVM chain. The refusal happens before the first '
          'confirm(), so NO screen is drawn and no ButtonRequest is emitted. The empty '
          'screenshot list below is the assertion.',
          []),
         ('J10', 'test_verify_typed_data', 'test_structured_eip712_is_refused',
          'Structured EIP-712 is closed by default',
          'The legacy JSON parser could not guarantee that every displayed value was the '
          'canonical value being hashed, and one screen took its title from the attacker-supplied '
          'domain name. The feature is withdrawn rather than shipped with a screen it could not '
          'vouch for: zero screens, refusal on the wire.',
          []),
         ('J11', 'test_msg_binance_sign_tx', 'test_transfer',
          'Binance denom renders in full',
          'A long denom must render completely and must not overflow the formatting buffer.',
          ['Transfer screen showing the full denom']),
         ('J12', 'test_msg_ping', 'test_ping_long_body_is_paged',
          'A long body is paged, not clipped',
          'A body that will not fit one screen is shown across several, with the page number '
          'in the title. Before 7.14.2 the device drew what fitted and stopped - no ellipsis, '
          'no warning - and a later warning screen claimed "Hold to view it anyway" while '
          're-drawing the same clipped text. These captures are the evidence that the '
          'remainder is now actually reachable. The press DURATIONS (click to page, hold to '
          'approve) are not assertable in an emulator with no physical button.',
          ['Numbered page screens covering the whole body']),
         ('J13', 'test_msg_ping', 'test_ping_short_body_is_not_paged',
          'A body that fits is not paged',
          'The control for J12. A fitting body must still take exactly one screen with an '
          'unnumbered title - otherwise a pager that numbered every confirmation, making '
          'ordinary approvals cost extra presses, would pass unnoticed.',
          ['Single unnumbered confirmation screen']),
     ]),
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

    ('K', 'Seed Generation Hardening (7.14.3+)', '7.14.3',
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
         ('K8', 'Storage', 'PinKdfRewrapsToActiveVersionAfterCorrectPin',
          'Correct PIN unlocks and rewraps to the ACTIVE KDF',
          'The migration path for the hardened PIN KDF: an existing device must still unlock with '
          'its current PIN, and any rewrap must target whatever KDF the build actually has '
          'enabled. Renamed from PinKdfV16RewrapsToV19AfterCorrectPin because it is no longer '
          'v19-specific -- the test now asserts BOTH sides of the STORAGE_PIN_KDF_V19 gate, so it '
          'is meaningful in the shipping build where v19 is off. If this regressed, every '
          'upgrading device would be locked out of its own seed.',
          []),
         ('K8b', 'Storage', 'PinUnlocksAfterRebootUnderV17',
          'The PIN still opens the wallet after a reboot',
          'The whole round trip in device order: create, set a PIN, serialize the V17 record as '
          'storage_commit() does, reload into fresh state as a boot would, unlock, decrypt. Every '
          'other storage test stays in RAM, and the wallet lockout this guards against lived '
          'exactly on the serialize/reboot boundary -- a wrap the persisted record could not '
          'describe, so the next boot derived the wrong KDF and every PIN failed.',
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
          'Derive ETH address', 'Standard m/44\'/60\'/0\'/0/0 derivation. EIP-55 checksum address. No screen: GetAddress without show_display returns on the wire and draws nothing.', []),
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
          'MAX_UINT256 approval. Older firmware showed an "UNLIMITED" warning; 7.14.2 and later '
          'refuse it before drawing a confirmation screen.',
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
          'EIP-712 typed data is BLIND-signed, behind AdvancedMode',
          'The only working EIP-712 path. The host computes both 32-byte hashes and the device '
          'signs them, so it cannot show a recipient, an amount or a chain -- it shows the two '
          'digests and asks whether to trust the host. The test proves both halves of the gate: '
          'with AdvancedMode ON the signature is produced, and with it OFF the device refuses '
          'with "Enable AdvancedMode to blind-sign typed hashes". Every EIP-712 signature a '
          'KeepKey produces today, Permit2 approvals included, takes this path.',
          []),
         ('E16b', 'test_sign_typed_data', 'test_ethereum_sign_x402_eip3009',
          'Structured EIP-712 is DISABLED, and x402 EIP-3009 is refused',
          'This entry asserted the opposite until 2026-08-21, and the report shipped it green: it '
          'claimed the device "computes the EIP-712 hashes itself and displays every '
          'TransferWithAuthorization field", and declared two screens for fields that are never '
          'drawn. The test underneath had already been rewritten to assert the REFUSAL. A reader '
          'would have concluded x402 EVM payments clear-sign. They do not.\n'
          'What the test actually proves: Ethereum712TypesValues is answered with '
          '"Structured EIP-712 disabled pending canonical display hardening". The JSON parser '
          'could not guarantee the displayed value was the value hashed, so 7.14.2 withdrew the '
          'path rather than ship it. The EIP-712 V4 reference hashes stay in the fixture, unused, '
          'as the vector to re-assert when the streaming implementation lands (SRS-7.16 R-4.1, '
          'R-4.2).\n'
          'The screen list is EMPTY because a refusal draws nothing -- the evidence is the '
          'Failure on the wire.',
          []),
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
          'Derive XRP address', 'Standard m/44\'/144\'/0\'/0/0 derivation. No screen: address is returned on the wire; the display path is the show variant.', []),
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
          'clearsign warning (signer alias + fingerprint) then the decoded method + contract. No screen: this asserts the VERIFIED classification on the wire, before any render.',
          []),
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
          'Type-2 tx without max_fee_per_gas rejected',
          'The 0x02 envelope prefix comes from msg.type but the fee fields come from '
          'has_max_fee_per_gas, so a type-2 tx carrying only gas_price would hash a legacy '
          'fee into a 1559 field list. Refused, because a signature over a malformed field '
          'list is still a valid signature over SOMETHING.',
          []),
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
     'Full Solana with Ed25519 (SLIP-10), base58 addresses, 37 instruction types across 7 '
     'programs. The 44-character address is displayed in full: the old 8-character truncation '
     'was a spoofing vector, because two addresses agreeing on their first eight base58 '
     'characters are cheap to grind.  The open gap this release closes is versioned (v0) '
     'transactions whose accounts live in an Address Lookup Table. The device cannot resolve a '
     'table it has never seen, so until now it routed them to the blind-sign gate (S24) and '
     'signed accounts it never showed. S26-S29 are KKSOLSW1: a loaded provider attests the '
     'resolved accounts, bound to sha256(raw_tx), and the device DISPLAYS them -- in addition '
     'to, never instead of, the review that already existed.',
     [
         'ADDRESS: m/44\'/501\'/0\' Ed25519 -> full 44-char base58 on OLED',
         'SIGN TX: Parse instructions -> per-instruction confirmation -> Ed25519 sign',
         'SIGN MESSAGE: Arbitrary bytes -> hex display -> Ed25519 sign',
     ],
     [
         ('S1', 'test_msg_solana_getaddress', 'test_solana_get_address',
          'Derive Solana address', 'Full 44-character base58 address displayed on OLED. No screen: the drawn address is test_solana_show_address (S3b).', []),
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
         # KKSOLSW1 -- the answer to S24. A v0 tx whose accounts live in a
         # lookup table cannot be resolved on-device, so today the device signs
         # accounts it never showed. These four are the additive invariant
         # (section F) restated for Solana, and R-4.1 of SRS-7.15.
         ('S26', 'test_msg_solana_lut_attestation',
          'test_attested_accounts_are_shown_and_blind_sign_still_follows',
          'Attested lookup-table accounts are shown, and the blind-sign warning survives',
          'A loaded provider attests the resolved accounts over '
          '"KeepKeySolanaTxAccounts/1" || sha256(raw_tx) || count || keys. The device verifies '
          'through the same chain-agnostic anchor as every other runtime signer, then adds one '
          'identity screen and one screen per account IN FRONT of the existing flow. The '
          'assertion is exact and it is the whole point: the attested run shows '
          'len(base) + 1 + len(accounts) screens and its TAIL equals the baseline sequence '
          'exactly. More screens, never fewer.',
          ['Provider identity + NOT verified by KeepKey', 'Lookup account 1',
           'Lookup account 2', 'Existing blind-sign warning']),
         ('S27', 'test_msg_solana_lut_attestation',
          'test_bad_signature_degrades_to_todays_flow',
          'A signature that does not verify changes nothing',
          'The failure mode of a describer must be silence, not a refusal: a provider outage '
          'or a botched signature costs the user the extra screens and nothing else. The '
          'confirmation sequence is asserted EQUAL to the no-attestation baseline, and the '
          'transaction still signs.',
          []),
         ('S28', 'test_msg_solana_lut_attestation',
          'test_attestation_does_not_replay_onto_another_transaction',
          'An attestation cannot be replayed onto another transaction',
          'sha256(raw_tx) is inside the preimage, so an attestation is worthless anywhere but '
          'the transaction it was issued for. The test perturbs one byte of the lookup-table '
          'address and replays the signature: the device falls back to the baseline flow. '
          'Without this binding, a provider\'s single honest attestation could be reused to '
          'describe a transaction it never saw -- the accounts would be real, and the '
          'transaction spending them would not be.',
          []),
         ('S29', 'test_msg_solana_lut_attestation',
          'test_no_signer_loaded_means_no_extra_screens',
          'With no signer loaded a well-formed attestation is inert',
          'Trust is opt-in and per-session. A perfectly valid attestation from a provider the '
          'user never loaded verifies against nothing and renders nothing, which is the '
          'property that keeps 7.15 safe without any key-management programme.',
          []),
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
          'Derive TRON address', 'Full 34-character base58 address. No screen: the drawn address is test_tron_show_address (T3b).', []),
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
          'Derive TON address', 'Full 48-character base64url address. No screen: the drawn address is test_ton_show_address (N2b).', []),
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
          'FVK reference vectors', 'FVK output matches known test vectors. No screen: reference-vector arithmetic, compared in memory.', []),
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
          'to a device anywhere in THIS module. On-device shielded signing is covered '
          'separately by test_msg_zcash_sign_pczt_device (see Z22), which drives a real '
          'device and asserts the per-output confirm screens; this module proves only that '
          'the client builds and orders the messages correctly.',
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
    ('Q', 'Display Disclosure - What Is Shown Is What Is Signed', '7.14.2',
     'The single property behind every display/sign divergence found in the 7.14.2 audit: two '
     'requests whose SIGNED BYTES differ must not produce IDENTICAL screens. If two payloads render '
     'the same pixels, whatever separates them was invisible when the user approved, and the '
     'signature covers the difference. A failure here means a host can show one thing and have '
     'another signed - the exact class the OLED exists to prevent.',
     [
         'ASSERTED DIFFERENTIALLY: DebugLinkState.layout is the framebuffer, not text, so these',
         'compare screen sequences. That assumes nothing about wording, fonts or truncation',
         'strategy, so it survives copy changes and cannot be satisfied by a plausible-looking screen.',
         '',
         'EACH CASE PUTS THE DIFFERENCE WHERE AN IMPLEMENTATION STOPS LOOKING:',
         '- past an embedded NUL: a protobuf bytes field is not a C string; "%s" stops, the signature does not',
         '- past whitespace padding: a leading space costs no pixels once wrapped, so a padded body measures as fitting',
         '- past one screenful: a truncating renderer drops the tail instead of paging it',
         '- behind newlines: exercises the row counter rather than the character count',
         '',
         'REFUSAL COUNTS AS A PASS. Declining to sign what it cannot display honestly satisfies',
         'the property; the failure under test is signing it while looking identical to the benign case.',
     ],
     [
         ('Q1', 'test_msg_display_disclosure', 'test_bytes_past_an_embedded_nul_are_disclosed',
          'Bytes after a NUL are shown',
          'A protobuf bytes field is not a NUL-terminated string. Rendering it with "%s" stops at the '
          'first NUL while the signature covers message.size bytes, so a payload like '
          '"benign login\\0 AND APPROVE TRANSFER" displays only the benign prefix. This asserts the '
          'two payloads do not present identically.',
          ['Message screen, plain', 'Message screen, NUL-suffixed']),
         ('Q2', 'test_msg_display_disclosure', 'test_bytes_past_whitespace_padding_are_disclosed',
          'Whitespace cannot hide signed text',
          'Whitespace is the cheapest way to push content out of view: a leading space costs zero '
          'pixels once a line has wrapped, so padding can make an over-long body measure as fitting '
          'while the tail is neither shown nor dropped from the signature.',
          ['Message screen, short', 'Message screen, padded']),
         ('Q3', 'test_msg_display_disclosure', 'test_bytes_past_the_first_screen_are_disclosed',
          'Content beyond one screen is not silently dropped',
          'Whether the device pages the remainder, states how much is hidden, or refuses is not '
          'asserted - only that a long payload with a distinct tail does not look identical to a '
          'short one.',
          ['Message screen, fits', 'Message screen, overlong']),
         ('Q4', 'test_msg_display_disclosure', 'test_newline_padding_does_not_collapse_the_screen',
          'Line counting cannot be overflowed',
          'Line counting is a security boundary once it gates a truncation warning. A body carrying '
          'many newlines exercises the row counter rather than the character count; if that counter '
          'wraps, an arbitrarily long body reports as fitting.',
          ['Message screen, one line', 'Message screen, newline-padded']),
         ('Q5', 'test_msg_display_disclosure', 'test_signing_shows_at_least_one_screen',
          'Guard: the comparisons are not vacuous',
          'Every other test in this section compares screen sequences. A flow that produced no '
          'ButtonRequest would make two payloads compare equal as empty tuples and pass while showing '
          'the user nothing. This asserts at least one non-blank screen is actually displayed.',
          ['Control message screen']),
     ]),
    ('F', 'Clear-Sign Provider Context - Additive Invariant', '7.15.0',
     'Clear-signing is annotation, not authority. A provider signer is loaded at runtime by the '
     'host (LoadClearsignSigner: RAM-only, user-confirmed, dropped on reboot) and is NOT verified '
     'by KeepKey, so its decoded who/what/why screens must be ADDED to the ordinary unverified '
     'review, never substituted for it. A runtime schema that could suppress the amount screen, '
     'the raw-calldata screen or the fee screen would be a screen-substitution oracle: a friendly '
     '"supply 10.5 DAI to Aave" on the glass with arbitrary bytes under the signature. '
     'lib/firmware/ethereum.c forces needs_confirm and data_needs_confirm back to TRUE whenever '
     'the metadata came from a loaded signer; the else-branch that is allowed to suppress is '
     'reserved for a future firmware-PINNED key and has no reachable input in this build. Every '
     'test below proves this by MEASUREMENT rather than by model: it signs the same transaction '
     'twice against the same device state, records the raw 2048-byte OLED framebuffer at every '
     'ButtonRequest, and requires the no-metadata baseline frames to reappear byte-for-byte as the '
     'tail of the clear-signed run. Adjacent sections cover "no metadata -> blind sign", replay '
     'rejection and cancel-clears-metadata; none of them proves the raw review FOLLOWS a '
     'SUCCESSFUL decode.',
     [
         'ADDITIVE RULE: a runtime provider may ADD screens. It may never REMOVE one.',
         '',
         'Measured on the Aave V3 supply() fixture (132 bytes of real ABI calldata, AdvancedMode on):',
         '- baseline, no metadata      : 3 screens - Send / Confirm Ethereum Data / Transaction',
         '- v1 metadata VERIFIED       : 10 screens - Identity, "Call: supply", Contract, one screen',
         '                               per attested argument (4), THEN the same 3 baseline screens',
         '- v2 static schema VERIFIED  : 13 screens - 7 decoded, then the same 3 baseline screens',
         '- signature fails to verify  : 3 screens - byte-identical to the baseline. The device does',
         '                               NOT refuse, and shows NO partial decoded information.',
         '',
         'The tail comparison is a byte-for-byte framebuffer match, so it is immune to pagination and',
         'to value-dependent rendering: whatever the baseline drew, the clear-signed run must draw.',
         '',
         'Phase 1 ships with every built-in verification slot zeroed, so a VERIFIED blob can only come',
         'from a runtime-loaded signer and the suppression branch cannot be reached. F5 has an EMPTY',
         'screenshot list on purpose: rejecting metadata draws nothing at all.',
     ],
     [
         ('F1', 'test_msg_ethereum_clearsign_additive',
          'test_successful_decode_still_runs_the_raw_review',
          'A successful decode adds screens, replaces none',
          'The headline invariant. A runtime provider clear-signs a real Aave V3 supply() call, and '
          'the decoded identity/method/contract/argument screens are followed by the SAME '
          'amount, raw-calldata and fee screens the device draws with no metadata at all - proven by '
          'signing the identical transaction twice and requiring the three baseline frames to '
          'reappear byte-for-byte at the tail. The signature still recovers to this device over this '
          'exact digest, so the screens shown were bound to the transaction signed.',
          ['Identity screen naming the loaded signer and its fingerprint',
           'Decoded argument screens (protocol / asset / amount / onBehalfOf)',
           'Raw contract data screen, unchanged from the baseline',
           'Fee screen']),
         ('F2', 'test_msg_ethereum_clearsign_additive',
          'test_v2_schema_decode_still_runs_the_raw_review',
          'v2 static schema is additive too',
          'v2 is where suppression would be most tempting: the blob attests a decode shape and no '
          'tx_hash, so the reserved branch drops the raw review outright and keeps the amount screen '
          'only if the schema moves value. For a runtime signer that branch is not taken. Decoded '
          'against the Aave fixture rather than an ERC-20 transfer on purpose - a recognized token '
          'contract has no raw-data screen in its own baseline, so it could not show that the raw '
          'review survives.',
          ['Decoded screens with values read from the calldata being signed (amount: 10.5 DAI)',
           'Raw contract data screen, unchanged from the baseline',
           'Fee screen']),
         ('F3', 'test_msg_ethereum_clearsign_additive',
          'test_failed_signature_falls_back_to_the_unverified_review',
          'A payload that fails to verify falls back, it does not refuse',
          'One tampered byte inside the signed region makes the blob MALFORMED. The device must then '
          'behave exactly as if no metadata had ever been sent: the ordinary unverified review, no '
          'refusal, and no partial decoded information on the glass. The assertion is that the whole '
          'signing run is frame-for-frame identical to the baseline - any decoded screen would be a '
          'frame the baseline does not contain.',
          ['Amount/recipient screen identical to the no-metadata baseline',
           'Raw contract data screen identical to the no-metadata baseline',
           'Fee screen identical to the no-metadata baseline']),
         ('F4', 'test_msg_ethereum_clearsign_additive',
          'test_no_runtime_slot_can_reach_the_suppression_branch',
          'Every runtime key slot stays additive',
          'The suppression branch is gated on a signer that is NOT runtime-loaded. All four key slots '
          'are loaded at runtime and each in turn produces a VERIFIED decode that is still followed '
          'by the complete baseline review, so no slot is a privileged one. A slot that suppressed '
          'would surface here as a missing tail frame.',
          ['Identity screen for each loaded slot',
           'Raw contract data screen after every slot\'s decode']),
         ('F5', 'test_msg_ethereum_clearsign_additive',
          'test_no_slot_verifies_without_a_runtime_load',
          'No firmware-pinned signer exists to suppress anything',
          'The complementary half. With no signer loaded, a correctly signed blob addressed to each '
          'of the four slots comes back MALFORMED: this build carries no built-in verification key, '
          'so the branch that may suppress the raw review has no reachable input. Sending metadata '
          'draws no screen, so the empty screenshot list below is the assertion.',
          []),
     ]),
    ('I', 'Session and Trust Lifetime', '7.15.0',
     'Clear-signing works by trusting somebody else. A provider key loaded with LoadClearsignSigner '
     'decides which transactions the device is willing to describe in words, and AdvancedMode decides '
     'whether the device will sign contract data it cannot describe at all. Neither is a decision a '
     'user should still be living with tomorrow. Both are session state by design: AdvancedMode is a '
     'policy the storage writer refuses to persist, and loaded signers are RAM slots that no code path '
     'writes to flash. Design intent is not evidence, so this section revokes them for real - it '
     'restarts the firmware process with its flash image intact, which is a reboot and not a wipe, and '
     'watches what comes back.',
     [
         'LIFETIME RULE: trust granted by a button press dies with the session that granted it.',
         '',
         'The two claims under test, and where they live:',
         '- AdvancedMode is session-scoped. Storage flags bit 12 is written as zero and ignored on',
         '  read at four sites in storage.c; policy.h calls the bit BURNED because firmware <= 7.15',
         '  would read a reused bit as "blind signing enabled".',
         '- Loaded signers are RAM only. session_clear() calls signed_metadata_clear_signers()',
         '  unconditionally, so Initialize and ClearSession both drop them; a reboot drops them',
         '  because they were never anywhere else.',
         '',
         'The asymmetry between the two is deliberate and is asserted, not assumed: Initialize drops',
         'the signer but LEAVES AdvancedMode armed (hosts send Initialize before nearly every',
         'operation, so disarming there would demand a button press each time), while ClearSession',
         'drops both.',
         '',
         'READING THE POWER-CYCLE TESTS: on the emulator flash_erase_word() is compiled out, so the',
         'sectors that storage_commit() abandons keep their "stor" magic and find_active_storage()',
         'may boot into a record two commits stale. A test that ignored this would read every policy',
         'back OFF for the wrong reason and pass against firmware that persisted it. Each power-cycle',
         'test therefore sets a MARKER policy (Experimental) after the state under test and commits',
         'until every sector carries it; the marker coming back is what licenses any conclusion about',
         'AdvancedMode, and the surviving seed and label are what distinguish a reboot from a wipe.',
     ],
     [
         ('I1', 'test_msg_session_trust_lifetime',
          'test_advanced_mode_is_off_after_power_cycle',
          'AdvancedMode does not survive a reboot',
          'AdvancedMode and Experimental are neighbouring bits of the same storage flags word, set by '
          'the same ApplyPolicies message and written by the same storage_writeStorageV16Plaintext '
          'call. Both are turned on, Experimental second, and the firmware is restarted with its flash '
          'image untouched. Experimental must come back - proving flash survived AND that the record '
          'read at boot was written while AdvancedMode was armed - and AdvancedMode must be OFF. A '
          'device that inherited the policy from flash would boot with blind signing already enabled '
          'and no confirmation, which is precisely why bit 12 was retired.',
          ['Enable Policy: AdvancedMode', 'Enable Policy: Experimental (marker, four commits)']),
         ('I2', 'test_msg_session_trust_lifetime',
          'test_advanced_mode_survives_initialize_but_not_clear_session',
          'Initialize keeps the policy, ClearSession revokes it',
          'session_clear_impl() disarms AdvancedMode only when clear_pin is set: ClearSession passes '
          'true, Initialize passes false. This pins the asymmetry from both sides. If Initialize ever '
          'started disarming, every host that sends it before an operation would demand a fresh '
          'confirmation and the policy would be unusable; if ClearSession ever stopped, an explicit '
          'lock would leave the blind-signing capability armed behind it.',
          ['Enable Policy: AdvancedMode']),
         ('I3', 'test_msg_session_trust_lifetime', 'test_signer_dropped_by_initialize',
          'Session teardown drops the loaded signer',
          'A signer is loaded, verified live, and then Initialize is sent. The metadata blob that was '
          'VERIFIED becomes MALFORMED. AdvancedMode is asserted still ON immediately before that probe, '
          'so the policy gate cannot be what refused it - the slot is empty. An ordinary GetFeatures is '
          'sent first as the negative control: if merely exchanging messages dropped signers, the '
          'teardown assertion would be proving nothing.',
          ['Enable Policy: AdvancedMode',
           "Load Clearsigner: Trust 'CI Test' (fingerprint) ... NOT verified by KeepKey"]),
         ('I4', 'test_msg_session_trust_lifetime', 'test_signer_dropped_by_clear_session',
          'ClearSession revokes both halves of the trust',
          'ClearSession is the explicit lock, and it must take the provider key with it. Straight '
          'afterwards the metadata message is refused outright ("AdvancedMode required") - that Failure '
          'is the policy gate and says nothing about the slot, so the policy is re-armed with a bare '
          'ApplyPolicies (no Initialize, which would clear the slot by itself) and the blob probed '
          'again. MALFORMED is the assertion: the signer itself is gone.',
          ['Enable Policy: AdvancedMode',
           "Load Clearsigner: Trust 'CI Test' (fingerprint) ... NOT verified by KeepKey",
           'Home screen at the refusal - the AdvancedMode gate draws no screen of its own',
           'Enable Policy: AdvancedMode (re-armed to isolate the slot)']),
         ('I5', 'test_msg_session_trust_lifetime', 'test_signer_dropped_by_power_cycle',
          'Reboot drops the loaded signer',
          'RAM-only should make this true by construction, but "by construction" is exactly what a '
          'persistence bug breaks, and the report should carry the reboot rather than infer it. The '
          'marker policy is set AFTER the signer is loaded, so the record the device boots into is one '
          'that was written while the signer was live - the record a firmware that persisted signers '
          'would have persisted them into. Seed, label and marker all come back; the signer does not.',
          ['Enable Policy: AdvancedMode',
           "Load Clearsigner: Trust 'CI Test' (fingerprint) ... NOT verified by KeepKey",
           'Enable Policy: Experimental (marker, four commits)',
           'Enable Policy: AdvancedMode (re-armed after the reboot to isolate the slot)']),
         ('I6', 'test_msg_session_trust_lifetime',
          'test_disabling_advanced_mode_revokes_the_signer',
          'Disabling AdvancedMode revokes the signer, it does not suspend it',
          'With the policy off, revoking and suspending are indistinguishable: every consumer in '
          'signed_metadata.c refuses a runtime slot while AdvancedMode is off, so metadata fails '
          'closed either way. The difference shows on the way back. Suspending would mean '
          're-enabling the policy silently re-arms a provider the user never re-loaded, on a '
          'confirmation screen that names the policy and never names the signer - so a user who '
          'disabled AdvancedMode to drop a provider would not have dropped it. '
          'fsm_msgApplyPolicies therefore calls signed_metadata_clear_signers() on disable. The '
          're-enable is sent as the bare ApplyPolicies with an exact expected-response list - one '
          'ButtonRequest and a Success - so the absence of a trust screen there is proof, not '
          'observation: trust cannot be restored by a policy toggle at all. Coming back costs a '
          'fresh LoadClearsignSigner consent, the screen that names the alias and fingerprint.',
          ['Enable Policy: AdvancedMode',
           "Load Clearsigner: Trust 'CI Test' (fingerprint) ... NOT verified by KeepKey",
           'Disable Policy: AdvancedMode',
           'Home screen at the refusal - the metadata message fails closed with no screen',
           'Enable Policy: AdvancedMode - the only confirm on re-arming, and the signer does NOT '
           'come back with it']),
     ]),
    ('L', 'Bitcoin-Only Variant', '7.15.0',
     'KK_BITCOIN_ONLY=ON builds a second shipping product out of the same tree: coins.def keeps '
     'only Bitcoin and Testnet, messagemap.def drops every altcoin handler, KK_ZCASH_PRIVACY is '
     'forced OFF, and transaction.c takes a BITCOIN_ONLY arm on the OP_RETURN path that confirms '
     'raw bytes instead of decoding a THORChain memo. Until this section none of it had a test and '
     'CI only ever ran the multi-chain emulator, so an entire shipping product was audited by '
     'nothing. These tests never skip: each asserts the behaviour that is correct for the variant '
     'it is talking to, so a run against the regular image proves the strip did NOT leak into the '
     'multi-chain product, and a run against the bitcoin-only image proves it happened. The '
     'variant is identified from GetCoinTable, not from features.firmware_variant -- L3 explains '
     'why that field cannot be trusted.',
     [
         'PRODUCT: two build products, one tree. Regular = every coin family plus Zcash Orchard.',
         'Bitcoin-only = Bitcoin + Testnet, no altcoins, no shielded Zcash, no ERC-20 token table.',
         'STRIPPED BY NAME: coinByName() must refuse Litecoin/Dogecoin/BCH/Zcash/DigiByte/Dash --',
         '  "bitcoin-only" is not "UTXO-only", and a silent fallback to Bitcoin parameters would',
         '  hand back an xpub with the wrong version bytes under an altcoin label.',
         'STRIPPED BY MESSAGE: an absent handler answers Failure_UnexpectedMessage from the board',
         '  dispatcher, draws nothing, and leaves the message loop usable.',
         'OP_RETURN: no memo parser is linked, so a THORChain memo is disclosed as the bytes',
         '  themselves. The OMNI branch sits ABOVE the #if and must still decode.',
         'REFUSAL: refusing the raw OP_RETURN screen returns -1 from compile_output(), which must',
         '  surface as ActionCancelled with no signature and no further screens.',
     ],
     [
         ('L1', 'test_msg_bitcoin_only_variant', 'test_bitcoin_signing_survives_the_strip',
          'Bitcoin still signs, byte for byte',
          'The one thing the bitcoin-only product must still do. Stripping coins, handlers and the '
          'Orchard engine touches coins.def, messagemap.def, fsm.c and the AES table selection; any '
          'of them going wrong surfaces here first. The signature is compared against the exact '
          'vector test_msg_signtx.test_one_one_fee pins on the multi-chain build, so both products '
          'must produce identical transactions from the same seed. The two review screens are '
          'asserted as well: a signing test alone cannot see a dropped confirmation.',
          ['Send 0.0038 BTC to 1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1',
           'TRANSACTION: send 0.0039 BTC from your wallet, including a 0.0001 BTC fee']),
         ('L2', 'test_msg_bitcoin_only_variant', 'test_coin_table_is_bitcoin_and_testnet_only',
          'The coin table is the product boundary',
          'GetCoinTable must report exactly two coins, Bitcoin and Testnet, with no ERC-20 tokens '
          '(TOKENS_COUNT is 0 and `tokens` is not linked at all). A host enumerating coins is the '
          'only way a user learns what the device will sign, so the count and the names are part '
          'of the product, not an implementation detail. On the regular image the same test '
          'asserts the table is larger -- the strip must not leak.',
          []),
         ('L3', 'test_msg_bitcoin_only_variant', 'test_firmware_variant_names_the_bitcoin_only_product',
          'features.firmware_variant must name the product',
          'FAILED ON THE BITCOIN-ONLY IMAGE AS MEASURED, and the failure is the finding. '
          'firmware_variant is the only wire-visible product identifier and the whole pyk suite '
          'gates on it: common.requires_fullFeature() skips a test when it reads "KeepKeyBTC" or '
          '"EmulatorBTC". The bitcoin-only emulator reported plain "Emulator", so '
          'requires_fullFeature() is dead code and every altcoin test in the directory runs '
          'against a bitcoin-only image and fails instead of skipping. Section X of this report '
          'states the KeepKeyBTC contract as fact. variant_getName() has two arms and only the '
          'EMULATOR one returns a literal; the hardware arm takes the model variant name from '
          'variant_getInfo() and has no BITCOIN_ONLY case at all, so bitcoin-only HARDWARE reports '
          'exactly what a multi-chain device of the same model reports. The assertion is by '
          'suffix, not against a fixed string, so it stays honest for both arms.',
          []),
         ('L4', 'test_msg_bitcoin_only_variant', 'test_altcoin_message_handlers_are_absent',
          'Every stripped chain refuses without drawing',
          'Thirteen probes -- Ethereum, Cosmos, Osmosis, Nano, EOS, THORChain, Maya, Ripple, '
          'Binance, TRON, TON, Solana, Hive -- must each answer Failure_UnexpectedMessage, the '
          'board dispatcher\'s answer for a message type that is not in the map. The two ways this '
          'goes wrong are a half-linked handler (wrong failure, or a hang) and one that renders '
          'before refusing: a bitcoin-only device must never draw a chain it cannot sign. The '
          'framebuffer is compared byte-for-byte across all thirteen for exactly that reason, and '
          'a Ping afterwards proves the message loop is not wedged. The screenshot list is '
          'deliberately empty -- the evidence is that nothing was drawn.',
          []),
         ('L5', 'test_msg_bitcoin_only_variant', 'test_altcoin_coin_names_are_refused',
          'Stripped coins are refused by name',
          'The other half of the boundary. GetPublicKey is a Bitcoin-family message and stays in '
          'the map, so coinByName() is what has to say no: Litecoin, Dogecoin, BitcoinCash, Zcash, '
          'DigiByte and Dash must each come back Failure_Other "Invalid coin name" rather than '
          'falling through to Bitcoin\'s parameters and returning an xpub with the wrong version '
          'bytes under an altcoin label. Bitcoin and Testnet must still work.',
          []),
         ('L6', 'test_msg_bitcoin_only_variant', 'test_zcash_privacy_is_compiled_out',
          'Zcash privacy is compiled out with the coin',
          'The Orchard engine is the largest thing in the image and its handlers live behind '
          'ZCASH_PRIVACY, not BITCOIN_ONLY -- the two gates are tied together in CMakeLists, not '
          'in the source, so nothing in C would catch that wiring breaking. ZcashGetOrchardFVK and '
          'ZcashDisplayAddress must be unknown messages, and transparent Zcash must be gone from '
          'the coin table in the same breath, so no Zcash path of either kind survives.',
          []),
         ('L7', 'test_msg_bitcoin_only_variant', 'test_op_return_thorchain_memo_is_confirmed_raw',
          'A THORChain memo is disclosed raw, not decoded',
          'The arm the alpha merge added to compile_output(). With no memo parser linked, a memo '
          'the multi-chain image explains -- swap, asset, destination, affiliate -- is shown on the '
          'bitcoin-only image as the bytes themselves. That is the right answer (a decode the image '
          'cannot perform must never be faked) but it had never been executed, because CI runs only '
          'the multi-chain emulator. Screen counts are measured, not modelled: bitcoin-only shows '
          'exactly three requests (output, raw OP_RETURN, SignTx) while the regular image expands '
          'the same memo into strictly more ConfirmOutput screens. Both must sign a script carrying '
          'the memo verbatim, so disclosure and signature are pinned to the same bytes.',
          ['Send 0.0038 BTC to 1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1',
           'CONFIRM OP_RETURN: SWAP:ETH.ETH:0x41e5560054824ea6b0732e656e3ad64e20e94e45:420:kk:75',
           'TRANSACTION: send 0.0039 BTC from your wallet, including a 0.0001 BTC fee']),
         ('L8', 'test_msg_bitcoin_only_variant', 'test_op_return_refusal_cancels_the_signature',
          'Refusing the OP_RETURN screen aborts the signature',
          'The BITCOIN_ONLY arm returns -1 when confirm_data is refused, and the multi-chain arm '
          'has its own CANCELLED path that must not answer a refusal by asking again on a second '
          'screen. Both must surface as Failure_ActionCancelled with no signature, and the flow '
          'must stop AT the refused screen -- a SignTx request afterwards would mean the refusal '
          'was recorded and then ignored.',
          ['Send 0.0038 BTC to 1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1',
           'CONFIRM OP_RETURN: the memo screen the user refuses']),
         ('L9', 'test_msg_bitcoin_only_variant', 'test_omni_op_return_is_still_decoded',
          'The shared OMNI branch survived the strip',
          'compile_output() tests for an "omni" prefix ABOVE the BITCOIN_ONLY split, so an OMNI '
          'simple send is still decoded into a sentence on the bitcoin-only image. The regression '
          'guarded against is the new #else swallowing the OMNI case, silently downgrading a '
          'decoded amount to a hex dump. Proved by contrast rather than by OCR: the same twenty '
          'bytes with the leading "o" changed to "p" are no longer OMNI and fall through to the '
          'raw-data screen, so the two screens must differ and the decoded one must be the sparser '
          'of the two. Both payloads ride in ONE transaction, as two data outputs, because L11 '
          'makes a second signing in the same session impossible.',
          ['CONFIRM OMNI: Do you want to send 1 OMNI?',
           'CONFIRM OP_RETURN: 706D6E6900000000000000010000000005F5E100 -- the same bytes, raw',
           'Send 0.0038 BTC to 1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1',
           'TRANSACTION: send 0.0039 BTC from your wallet, including a 0.0001 BTC fee']),
         ('L10', 'test_msg_bitcoin_only_variant', 'test_repeated_transaction_is_allowed_without_op_return',
          'An exact repeat is not a duplicate',
          'The control for L11. compile_output() carries an anti-malware check (txin_check.c): warn '
          'when a transaction pays the same amount to the same address as the previous one but was '
          'built from DIFFERENT inputs, which is what a host rewriting a segwit txid looks like. An '
          'exact repeat -- same outputs AND same inputs -- is not that and is deliberately allowed. '
          'Signing it twice here pins that, so the refusal in L11 cannot be explained away as the '
          'duplicate guard doing its job.',
          []),
         ('L11', 'test_msg_bitcoin_only_variant', 'test_op_return_does_not_poison_the_duplicate_detector',
          'An OP_RETURN output must not poison the duplicate detector',
          'FAILS ON BOTH PRODUCTS, and the failure is the finding. Sign a transaction whose last '
          'output is OP_RETURN, then sign the transaction L10 just proved is allowed, and the '
          'device answers "WARNING: DUPLICATE TRANSACTION! Already signed a tx with the same '
          'outputs. To try again, unplug/replug KeepKey." and aborts. signing.c calls '
          'txin_dgst_final() once per output, but txin_dgst_save_and_reset() -- the only thing that '
          're-initialises the SHA-256 context -- is reached only on the pay-to-address path; an '
          'OP_RETURN output returns before it. So a transaction ending in OP_RETURN leaves the '
          'context finalised and never re-initialised, the next transaction\'s inputs are hashed '
          'into a finalised context, and its digest no longer matches while amount and address '
          'still do -- precisely the (same outputs, different inputs) pattern the check exists to '
          'flag. Fail-safe, in that it refuses rather than signs, but it refuses a legitimate '
          'transaction and demands a replug, and every OP_RETURN-terminated transaction arms it: '
          'that is every THORChain and Maya swap the wallet builds. Nothing had caught it because '
          'common.KeepKeyTest wipes the device in setUp, so no existing test signs two transactions '
          'in one session.',
          ['Send 0.0038 BTC to 1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1 (first transaction)',
           'CONFIRM OP_RETURN: the memo that arms the detector',
           'WARNING: DUPLICATE TRANSACTION! Already signed a tx with the same outputs']),
     ]),
    ('U', 'Storage Upgrade Preservation', '7.15.0',
     'A signed UPGRADE must never wipe. A DOWNGRADE wipes, and that is correct. Those two '
     'sentences are the whole policy (docs/StorageVersionGate.md), and until this section '
     'nothing in the suite tested either half - every other test creates storage with the '
     'firmware under test and never crosses a release boundary, which is exactly where this '
     'class of defect lives. The mechanism is one function: storage_init() hands whatever is in '
     'flash to storage_fromFlash(), and if version_from_int() does not recognise the version it '
     'returns StorageVersion_NONE, the load reports SUS_Invalid, and storage_init() runs '
     'storage_reset() + storage_commit(). No prompt, no warning - the wallet is gone at boot. '
     'The flash format this build reads and writes is V17, the same format shipped in v7.14.1. '
     '7.15 reverted the RC27 bump to V19 (commit 6bebde7b2) because one boot silently migrated '
     '17 to 19 and from that moment no downgrade was possible without a wipe; V18, the '
     'clear-sign identity block, is dead, and the V19 serializer survives only behind '
     'STORAGE_PIN_KDF_V19 == 0. U5 pins that V17 as a literal, on purpose: the compile-time '
     'assert compares two numbers in the same header, and raising the baseline to make a build '
     'compile is the edit the SOP calls its highest-severity review item.',
     [
         'THE RULE: recognise every version any shipped firmware ever wrote, and never lower',
         'STORAGE_VERSION. Both ways of breaking it compile cleanly and pass every other test:',
         '- lowering STORAGE_VERSION below a version that has shipped;',
         '- deleting, reordering or renumbering an entry in storage_versions.inc.',
         '',
         'The reverse direction is NOT a defect. Older firmware cannot read a newer record, so a',
         'DOWNGRADE lands on SUS_Invalid and resets. Do not "fix" that: the reset is what stops',
         'an attacker flashing an older, validly signed image with a known extraction bug and',
         'keeping the seed.',
         '',
         'HOW THESE TESTS REACH THE GATE: it only runs at boot, and no host message can reboot',
         'the device. SoftReset (messages.proto type 89) has no messagemap entry and no handler',
         'body, and fsm_msgDebugLinkFlashDump() is compiled out under EMULATOR, so the emulator',
         'can neither be restarted nor have its flash read over the wire. U1-U4 therefore start',
         'their OWN kkemu on their own port pair and own its emulator.img, which lib/emulator/',
         'setup.c mmaps as the flash array. Killing that process and starting it again IS a',
         'power cycle, and restamping the version word in the image is what an arriving device',
         'presents: a record whose header says one version while the firmware says another.',
         '',
         'WHAT THIS SECTION DOES NOT COVER, stated plainly:',
         '- No signed image is involved. The bootloader preserves storage only when SIG_FLAG is',
         '  set, the firmware being replaced was officially signed, and the new image verifies.',
         '  An unsigned development or RC build fails two of those by construction, so "the',
         '  upgrade did not wipe" is finally proven only with a signed build on a production',
         '  device.',
         '- U2 restamps a record THIS build wrote rather than replaying one 7.14.x wrote, so the',
         '  V16 reader runs but the older LAYOUTS (V1-V15) and their fallthrough chain do not.',
         '- U1-U4 SKIP wherever no kkemu binary can be started. The CI python-keepkey image',
         '  (scripts/emulator/python-keepkey.Dockerfile) copies the source but never builds the',
         '  emulator, so as the pipeline stands today only U5-U8 run in CI. A skipped U1-U4 in',
         '  this report means the release was NOT audited for upgrade preservation.',
     ],
     [
         ('U1', 'test_storage_version_gate', 'test_reboot_preserves_the_wallet',
          'A power cycle keeps the wallet',
          'The boundary the ordinary storage tests never cross. Every other test lives inside '
          'one session, where the wallet is a RAM shadow; only a power cycle re-runs '
          'storage_init() and proves the bytes committed to flash were both written and '
          'readable. The PIN is load-bearing: the seed lives in encrypted_sec and the key that '
          'decrypts it is only ever stored wrapped by the PIN, so an address that still derives '
          'after the reboot proves the wrapped key, its fingerprint and the ciphertext all '
          'round-tripped together. This test is also the control for U2 - a record already at '
          'STORAGE_VERSION reports SUS_Valid, so nothing is rewritten at boot, and the flash '
          'image is asserted byte-identical across the restart.',
          ['Wipe Device confirm (the arrangement wipes before loading the seed)',
           'Import Recovery Sentence confirm',
           'Home screen after the power cycle: locked, wallet still present',
           'Bitcoin Account #0 / Address #0 showing the same address as before the reboot']),
         ('U2', 'test_storage_version_gate', 'test_v16_blob_upgrades_without_wiping',
          'A V16 wallet upgrades, it does not wipe',
          'The policy in one test: the device arrives carrying the format written by the release '
          'it is leaving, and the incoming firmware must READ it rather than reset it. '
          'storage_fromFlash() takes case StorageVersion_16, reads through storage_readV16(), '
          'restamps the record V17 and reports SUS_Updated, which storage_init() answers with a '
          'commit - a migration, not a wipe. The V16 record is built from the four things that '
          'actually differ between the formats: the version stamp, flags bits 18/19 '
          '(authdata_initialized / authdata_encrypted), authdata_fingerprint at +469, and the '
          '512-byte V16 ciphertext against the 1024-byte V17 one. The same address behind the '
          'same PIN is the assertion; it can only derive if the wrapped storage key unwrapped, '
          'the V16 ciphertext decrypted and the seed came back byte-identical. A surviving '
          'wallet alone would not prove the V16 branch ran, so the test also asserts flash was '
          'written at boot - the side effect only SUS_Updated has.',
          ['Wipe Device confirm', 'Import Recovery Sentence confirm',
           'Home screen after the migrating boot: wallet still present',
           'Bitcoin Account #0 / Address #0 - the same address the V16 record held']),
         ('U3', 'test_storage_version_gate', 'test_unrecognised_version_wipes_on_boot',
          'An unrecognised version wipes, deliberately',
          'The half of the policy nobody should be tempted to soften. A device that has run '
          'newer firmware carries a newer stamp; older firmware cannot read it, so '
          'version_from_int() returns StorageVersion_NONE and storage_init() resets. That reset '
          'is the rollback protection: without it an attacker could flash an older, validly '
          'signed image with a known extraction bug and keep the seed. The stamp used is one '
          'past the version this build just committed - measured from the device, not read out '
          'of the header - which is exactly what the next format bump will look like from here. '
          'The device must come up with no wallet, no PIN and no label.',
          ['Wipe Device confirm', 'Import Recovery Sentence confirm',
           'Home screen after the boot that reset storage: no wallet']),
         ('U4', 'test_storage_version_gate', 'test_bitcoin_only_band_refuses_without_wiping',
          'A bitcoin-only wallet is refused, not destroyed',
          'Seeds created under bitcoin-only firmware are stamped in a reserved band (10000 + the '
          'normal version). Multi-chain firmware must not load one - that seed was never meant '
          'to be multi-chain-exposed - but it must also leave it alone: SUS_BitcoinOnlyLocked '
          'resets only the RAM shadow, and storage_commit() returns early while btc_only_locked, '
          'so flash is never touched. Three assertions, in order of what they cost you: the '
          'device comes up locked and uninitialized; the storage sector is byte-for-byte what it '
          'was, everywhere except the stamp the test itself changed; and once the band stamp is '
          'removed the wallet boots again and derives the original address. Without the third, '
          '"refuse rather than wipe" would be a claim about intent rather than about bytes.',
          ['Wipe Device confirm', 'Import Recovery Sentence confirm',
           'Home screen while locked out by the bitcoin-only band: no wallet',
           'Bitcoin Account #0 / Address #0 after the band stamp is removed - the wallet is back']),
         ('U5', 'test_storage_version_gate', 'test_last_shipped_never_moves_backwards',
          'STORAGE_VERSION_LAST_SHIPPED never moves backwards',
          'An independent witness for the number the whole gate turns on. The compile-time '
          'assert in storage.c compares STORAGE_VERSION against STORAGE_VERSION_LAST_SHIPPED - '
          'two values in the same header, editable in one commit - so it cannot notice a release '
          'that raises both. 7.15 deliberately reverted to V17; if V19 (or anything else) '
          're-lands, this test fails and the bump has to be argued for in review rather than '
          'discovered in the field. Reads the firmware sources, so it runs even where no '
          'emulator can be restarted. No screen: it never touches the device, and the empty '
          'list below says so.\n'
          '7.16 moves to V20 to hold passkey credentials. It skips 18 and 19 because both were '
          'ACTIVE formats in alpha builds before 6bebde7b2 reverted to V17 - 18 the clear-sign '
          'identity block, 19 the PIN-KDF migration - so devices carrying those blobs exist, and '
          'reusing a number would make this firmware PARSE one as passkey state rather than '
          'refuse it. Upgrading preserves the wallet; downgrading to 7.15 or earlier erases it, '
          'which is normal downgrade behaviour and is in the release note rather than left to be '
          'discovered.',
          []),
         ('U5b', 'test_storage_version_gate',
          'test_burned_versions_are_dispatched_to_the_wipe_path',
          'A burned format is dispatched, and what it reaches is the wipe',
          'This used to assert the ABSENCE of a dispatch case, on the theory that a burned blob '
          'falls through to a default. It does not: storage_fromFlash() has no default case, '
          'deliberately, so that -Werror=switch names any version nobody handled. An unlisted '
          'version therefore does not fall anywhere - it fails the ARM build. So the label must '
          'exist; what must NOT exist is a reader behind it. Asserted as the real property: the '
          'burned versions are dispatched, and the arm they reach returns SUS_Invalid with no '
          'storage_readVxx call. Which versions are burned is read from '
          'storage_versions.inc rather than written down here, so the test holds on a line that '
          'burns nothing as readily as on one that burns two.',
          []),
         ('U6', 'test_storage_version_gate', 'test_version_never_drops_below_a_shipped_release',
          'The version never goes backwards or into the band',
          'Lowering STORAGE_VERSION wipes every device upgrading FROM a shipped release: its '
          'record stops being recognised, so the gate maps it to StorageVersion_NONE and '
          'storage_init() resets. The version must also stay below STORAGE_VERSION_BTC_ONLY_BASE '
          '(10000), or a multi-chain wallet would be stamped into the band that multi-chain '
          'firmware refuses to load - locking the wallet out of its own firmware.',
          []),
         ('U7', 'test_storage_version_gate',
          'test_version_ladder_is_contiguous_and_ends_at_storage_version',
          'storage_versions.inc is append-only',
          'The enum is emitted in .inc order after StorageVersion_NONE = 0, which is what makes '
          'StorageVersion_N == N. Delete or renumber an entry and version_from_int() quietly '
          'loses that case, wiping every device carrying it. This asserts the ladder is '
          'contiguous from 1 and that its last entry is STORAGE_VERSION - the two properties the '
          'in-tree static asserts depend on.',
          []),
         ('U8', 'test_storage_version_gate', 'test_every_shipped_version_has_a_reader',
          'Every shipped version still has a reader',
          'The failure the static asserts do NOT cover. They pin the enum to its own numbering '
          'and say nothing about what the switch in storage_fromFlash() does with it. Drop the '
          'reader for a version that reached hardware and every device carrying it is wiped on '
          'upgrade. Scoped to SHIPPED versions on purpose: a burned format legitimately has no '
          'reader, so asserting "every ladder version has a reader" would make burning one '
          'impossible to express. The companion assertion, that no shipped version is ever '
          'declared burned, is what stops that scoping being used as a loophole.',
          []),
     ]),

    # Two-character id because all 26 letters were taken. The catalog keys on a
    # string, not a char, so this costs nothing.
    ('TD', 'Structured EIP-712 - The Device Reads The Document', '7.15.0',
     'Until now every EIP-712 signature a KeepKey produced was BLIND. The host computed '
     'domainSeparator and messageHash and the device signed two opaque 32-byte values -- it could '
     'not see a spender, an amount or a chain. Permit2 approvals, the single most common instrument '
     'in a drainer, took that path.\n'
     'Now the device walks the document itself. It asks for one struct definition, or one leaf '
     'value, at a time, and hashes each value in the SAME call that displays it. There is no second '
     'read that could return something different, and each member_path is requested exactly once -- '
     'Trezor shipped this protocol with a hole there until 2.12.0, where a host could answer the '
     'domain name one way for the summary screen and another for the hashing pass.\n'
     'The predecessor was withdrawn in 7.14.2 because its JSON parser could not guarantee the '
     'displayed value was the value being hashed. Here that property is structural rather than '
     'reviewed.',
     ['THE HASHES COME FROM OUTSIDE THIS REPOSITORY. TD1 asserts the values published by',
      'assets/eip-712/Example.js in ethereum/EIPs -- the reference implementation the spec',
      'links to -- and independently republished by Example.sol, by eth-sig-util\'s V3 and V4',
      'snapshots, and by Mrtenz/eip-712.',
      '',
      'That matters more than it looks. The firmware C, the hdwallet TypeScript and the python',
      'client were written by one hand against one reading of the spec. Three of them agreeing',
      'proves the reading is SELF-CONSISTENT and nothing more; a shared misreading would produce',
      'three consistent wrong answers. It cannot produce these two numbers.',
      '',
      'HARDWARE, 2026-08-21, K1-14AM, unsigned build of the 7.15 line:',
      '  9 screens, one per leaf; all rendered correctly per operator review',
      '  42-character addresses displayed IN FULL -- the truncation class that shipped as a',
      '  bug at >42 chars does not reproduce',
      '  domainSeparator and messageHash matched the published values on silicon',
      '  device address 0x73d0385F4d8E00C5e6504C6030F47BF6212736A8, same as the emulator',
      '',
      'Behind AdvancedMode. This is new parser surface reachable from a website.'],
     [('TD1', 'test_msg_eip712_streaming', 'test_spec_example_matches_the_published_hashes',
       'The device\'s own hashes equal the EIP-712 reference implementation\'s',
       'The canonical Mail/Person document. Mail references Person TWICE, so the walk pushes a '
       'child frame, derives Person\'s typeHash through its own dependency closure, folds it to 32 '
       'bytes and hands it back to the parent -- the nested-struct machinery, exercised rather '
       'than reasoned about. Forty round trips. domainSeparator '
       'f2cee375...912090f and messageHash c52c0ee5...4b371e, both published, both matched on '
       'hardware and in the emulator.',
       ['Domain name', 'Domain version', 'chainId', 'verifyingContract (42 chars, in full)',
        'Cow / wallet', 'Bob / wallet', 'contents']),
      ('TD2', 'test_msg_eip712_streaming', 'test_array_of_structs_walks',
       'An array of structs walks and signs',
       'Arrays hash WITHOUT a typeHash prefix -- enc(array) is the keccak of the concatenated '
       'element encodings and nothing else -- so getting this wrong yields a digest no verifier '
       'reproduces rather than an error anyone would notice. Arrays were refused entirely until a '
       'kilobyte was reclaimed from MAX_DECODE_SIZE: at 13 KB the ARM image missed the linker\'s '
       '16,384 B runtime-reserve gate by 204 bytes, at 12 KB it clears it by 812.',
       []),
      ('TD3', 'test_msg_eip712_streaming',
       'test_fixed_array_length_must_match_the_declared_size',
       'A fixed dimension must match the document',
       'address[2] carrying three elements is refused. The dimension is part of the type string '
       'and therefore part of typeHash, and the COUNT is the only thing the device is ever told -- '
       'accept a different one and it signs a document whose type declares another, with nothing '
       'downstream able to notice.',
       []),
      ('TD4', 'test_msg_eip712_streaming', 'test_advanced_mode_gates_the_endpoint',
       'The endpoint is gated behind AdvancedMode',
       'Structured display is strictly MORE information than the blind path it replaces, so the '
       'gate is not about the feature being dangerous. It is about new parser surface reachable '
       'from a website staying closed until there is hardware evidence behind it. There now is.',
       [])]),

]

# A section may span adjacent release lines even when individual native tests
# landed later. Filter those rows before validation so a 7.14.3 report cannot
# demand 7.15-only binaries, while 7.15 still requires the coverage.
_TEST_MIN_VERSION = {
    ('Storage', 'PinKdfRewrapsToActiveVersionAfterCorrectPin'): '7.15.0',
    ('Storage', 'PinUnlocksAfterRebootUnderV17'): '7.15.0',
    ('Storage', 'PinKdfV2FlagIsVersionedInV19'): '7.15.0',
}


def _active_sections(fw_version):
    active = []
    for letter, title, minimum, background, flow, tests in SECTIONS:
        if not ver_ge(fw_version, minimum):
            continue
        filtered = [
            test for test in tests
            if ver_ge(fw_version,
                      _TEST_MIN_VERSION.get((test[1], test[2]), minimum))
        ]
        active.append((letter, title, minimum, background, flow, filtered))
    return active

# ---------------------------------------------------------------
# Render
# ---------------------------------------------------------------
def _audit_catalog():
    """Structural check on SECTIONS, run on every render.

    A catalog entry with a blank context renders as a bare test name, which is
    exactly the row a human auditor cannot evaluate -- VG4 shipped that way and
    nothing complained. Duplicate ids or letters silently overwrite each other
    in cross-references. Cheap to assert, and the report is evidence.
    """
    letters, ids = set(), set()
    for letter, title, mf, bg, notes, tests in SECTIONS:
        assert letter not in letters, 'duplicate section letter %s' % letter
        letters.add(letter)
        assert (bg or '').strip(), 'section %s has no background' % letter
        for t in tests:
            assert len(t) == 6, 'malformed entry in section %s: %r' % (letter, t)
            tid, mod, meth, ttl, ctx, scr = t
            assert tid not in ids, 'duplicate test id %s' % tid
            ids.add(tid)
            assert (ttl or '').strip(), '%s has no title' % tid
            assert (ctx or '').strip(), '%s has no context -- it would render as a bare name' % tid


def render(output_path, fw_version, results, screenshot_dir=None):
    _audit_catalog()
    pdf = PDF(); pb = PB(pdf)
    _build_frame_census(screenshot_dir)
    ts = datetime.now().strftime('%Y-%m-%d %H:%M')
    build_label = os.environ.get('KK_BUILD_LABEL', '').strip()
    active = _active_sections(fw_version)
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
    # Count DISTINCT tests, not catalog rows. A few tests are deliberately
    # catalogued twice because they carry two different arguments -- e.g.
    # test_eip1559_requires_chain_id is the replayable-signature refusal in the
    # 7.14.2 defect narrative (J9) AND a guard in the EVM catalog (VG2). Both
    # entries earn their place, but summing rows made the header claim more
    # tests than the run contains, and an auditor reconciling the header
    # against the JUnit finds a shortfall that is pure double-counting.
    distinct = {}
    for s in test_sections:
        for t in s[5]:
            distinct[(t[1], t[2])] = _lookup(results, t[1], t[2])
    total   = len(distinct)
    passed  = sum(1 for v in distinct.values() if v == 'pass')
    failed  = sum(1 for v in distinct.values() if v in ('fail', 'error'))
    skipped = sum(1 for v in distinct.values() if v == 'skip')
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
        for line in _w('Scope: this report is a curated catalog of %d tests. The CI run collected %d '
                       '(%d of them native firmware unit tests); %d SKIPPED and did not execute, '
                       'usually because the emulator predates the firmware the test targets -- a skip '
                       'is not evidence the feature works. Absence from this report is NOT '
                       'evidence that a feature is untested -- check the JUnit artifacts.'
                       % (total, ran, JUNIT_CENSUS['native'], JUNIT_CENSUS['skipped']), 100):
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
            scr = _screens_for(fw_version, mod, meth, scr)
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
    assert passed + failed + skipped + missing == total, (
        'catalog counts do not reconcile: %d+%d+%d+%d != %d'
        % (passed, failed, skipped, missing, total))
    print(f'{output_path}: fw={fw_version}, {len(active)} sections, {total} tests '
          f'({passed} passed, {failed} failed, {skipped} skipped, {missing} pending)')

def screenshot_filter(fw_version):
    """Return pytest -k expression for tests with non-empty screenshot expectations.

    This is the SINGLE SOURCE OF TRUTH for which tests need OLED capture.
    The shell script calls this instead of maintaining a hardcoded filter.
    Adding screenshots to a test in SECTIONS automatically includes it in CI Phase 1.
    """
    active = _active_sections(fw_version)
    terms = []
    for letter, title, mf, bg, fl, tests in active:
        for tid, mod, meth, ttl, ctx, scr in tests:
            if _screens_for(fw_version, mod, meth, scr):
                # Use (method and module) for unambiguous pytest -k matching
                terms.append(f'({meth} and {mod})')
    return ' or '.join(terms)


def screenshot_test_list(fw_version):
    """Return exact module::method selectors consumed by conftest.py."""
    active = _active_sections(fw_version)
    pairs = set()
    for _letter, _title, _mf, _bg, _fl, tests in active:
        for _tid, mod, meth, _ttl, _ctx, screens in tests:
            if _screens_for(fw_version, mod, meth, screens):
                pairs.add('%s::%s' % (mod, meth))
    return '\n'.join(sorted(pairs))


# Modules whose tests must actually RUN once the firmware is new enough to be
# catalogued for them -- a skip is a failure, not a waiver.
#
# The general rule below treats 'skip' as a design waiver, which is right for
# build-flag-gated features (bitcoin-only, zcash-privacy). It is wrong for a
# capability the build claims to have: every taproot test opens with
# requires_taproot(), so if that capability regressed, all six would skip and
# the report would still read green -- the report would be certifying coverage
# it never obtained. Listing a module here converts that silence into a failure.
# Mapped to the firmware version from which a skip becomes a failure. A
# version-blind set would fail every older-firmware run for a module that
# legitimately cannot exist yet.
MUST_RUN_MODULES = {
    'test_msg_signtx_taproot': '7.0.0',
    'test_msg_getaddress_taproot': '7.0.0',
    # R-4.1. Gated on requires_message('LoadClearsignSigner'), so if provider
    # loading regressed, all four would skip and the report would certify a
    # feature it never exercised.
    'test_msg_solana_lut_attestation': '7.15.0',
}

def screenshot_audit(fw_version, screenshot_root, junit_path=None):
    """Which SECTIONS tests DECLARED screens but captured none?

    The CI gate was `total PNG count > 0`, which a single captured suite
    satisfies. That cannot distinguish "captured everything" from "captured
    something": in the 7.14.2 round, 345 PNGs were produced while every suite
    the release actually changed captured zero, and the phase reported healthy.

    Returns (ok, missing) where missing is a list of (module, method) that
    declared a non-empty screenshot list, were not skipped, and produced no
    PNG directory. Skipped tests are not missing -- a version-gated test
    cannot draw.
    """
    import os as _os
    skipped = set()
    if junit_path and _os.path.exists(junit_path):
        import xml.etree.ElementTree as _ET
        root = _ET.parse(junit_path).getroot()
        suites = [root] if root.tag == 'testsuite' else root.findall('testsuite')
        for su in suites:
            for tc in su.findall('testcase'):
                if tc.find('skipped') is not None:
                    cn = tc.get('classname', '')
                    mod = next((p for p in cn.split('.') if p.startswith('test_')), '')
                    skipped.add((mod, tc.get('name')))

    active = _active_sections(fw_version)
    missing = []
    for letter, title, mf, bg, fl, tests in active:
        for tid, mod, meth, ttl, ctx, scr in tests:
            if not _screens_for(fw_version, mod, meth, scr):
                continue
            if (mod, meth) in skipped:
                continue
            d = _os.path.join(screenshot_root, mod.replace('test_', '', 1), meth)
            if not _os.path.isdir(d) or not [f for f in _os.listdir(d) if f.endswith('.png')]:
                missing.append((mod, meth))
    return (len(missing) == 0, missing)


def validate_junit(fw_version, results):
    """Check SECTIONS tests against JUnit results. Returns (passed, failed_list).

    A test is considered failed if it appears in SECTIONS for this firmware version
    and the JUnit result is 'fail' or 'error' (not 'skip' or 'pass').
    Tests with no JUnit entry are treated as missing (also a failure).
    Tests that were skipped (gated by requires_message/requires_firmware) are OK,
    unless their module is in MUST_RUN_MODULES.
    """
    active = _active_sections(fw_version)
    failures = []
    for letter, title, mf, bg, fl, tests in active:
        for tid, mod, meth, ttl, ctx, scr in tests:
            status = _lookup(results, mod, meth)
            if status in ('fail', 'error'):
                failures.append((tid, mod, meth, status))
            elif status == 'skip' and ver_ge(fw_version, MUST_RUN_MODULES.get(mod, '99.0.0')):
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
    p.add_argument('--screenshot-audit', metavar='SCREENSHOT_DIR',
                   help='exit 1 if any SECTIONS test that declared screens captured none')
    p.add_argument('--audit-junit', metavar='XML', default=None,
                   help='JUnit XML for --screenshot-audit, so skipped tests are not counted missing')
    p.add_argument('--screenshot-filter', action='store_true',
                   help='Print pytest -k expression for tests needing screenshots, then exit')
    p.add_argument('--screenshot-test-list', action='store_true',
                   help='Print exact module::method screenshot selectors, then exit')
    p.add_argument('--validate-junit', action='store_true',
                   help='Validate JUnit results against SECTIONS, exit non-zero on failures')
    p.add_argument('--firmware-sha', default=None,
                   help='Exact firmware commit represented by this report')
    p.add_argument('--python-sha', default=None,
                   help='Exact python-keepkey commit represented by this report')
    p.add_argument('--run-url', default=None,
                   help='Exact CI run that produced the evidence')
    p.add_argument('--generator-sha256', default=None,
                   help='Combined wrapper/renderer digest')
    p.add_argument('--arm-manifest-sha256', default=None,
                   help='Digest binding the complete ARM manifest set')
    args = p.parse_args()

    fw = args.fw_version
    if not fw:
        print('Detecting firmware from emulator...', file=sys.stderr)
        fw = detect_fw()
        if fw: print(f'Detected: {fw}', file=sys.stderr)
        else: print('No emulator, defaulting to 7.10.0', file=sys.stderr); fw = '7.10.0'

    if args.screenshot_audit:
        ok, missing = screenshot_audit(fw, args.screenshot_audit, args.audit_junit)
        if ok:
            print('screenshot audit: every declared screen was captured')
            sys.exit(0)
        print('screenshot audit FAILED -- declared screens with no capture:')
        for mod, meth in missing:
            print('  %s::%s' % (mod, meth))
        sys.exit(1)
    if args.screenshot_filter:
        print(screenshot_filter(fw))
        sys.exit(0)
    if args.screenshot_test_list:
        print(screenshot_test_list(fw))
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

    provenance = [
        ('firmware', args.firmware_sha),
        ('python', args.python_sha),
        ('run', args.run_url),
        ('generator', args.generator_sha256),
        ('arm-manifests', args.arm_manifest_sha256),
    ]
    supplied = ['%s=%s' % item for item in provenance if item[1]]
    if supplied:
        os.environ['KK_BUILD_LABEL'] = ' | '.join(supplied)

    results = parse_junit(args.junit) if args.junit else {}
    render(args.output, fw, results, args.screenshots)

if __name__ == '__main__':
    main()
