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

# ---------------------------------------------------------------
# PDF writer + page builder (stdlib only)
# ---------------------------------------------------------------
def _read_png_pixels(path):
    """Read a 256x64 grayscale PNG and return raw pixel bytes (256*64 bytes, 0 or 255)."""
    with open(path, 'rb') as f:
        data = f.read()
    # Minimal PNG parser — skip signature, find IDAT, decompress
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
            txt = txt.replace('\\','\\\\').replace('(','\\(').replace(')','\\)')
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
    """Look up test result by module::method (precise), then bare method (fallback)."""
    return results.get(f'{mod}::{meth}') or results.get(meth) or ''

def ver_t(s): return tuple(int(x) for x in s.replace('v','').split('.')[:3])
def ver_ge(a, b): return ver_t(a) >= ver_t(b)
def _w(text, n=95):
    words, lines, cur = text.split(), [], ''
    for w in words:
        if cur and len(cur)+1+len(w) > n: lines.append(cur); cur = w
        else: cur = f'{cur} {w}' if cur else w
    if cur: lines.append(cur)
    return lines

def _is_setup_frame(path):
    """Check if a screenshot is a setUp noise frame (IMPORT RECOVERY, WIPE, or blank/logo)."""
    try:
        pixels, w, h = _read_png_pixels(path)
        # Count non-zero pixels — blank/logo frames have very few or very specific patterns
        lit = sum(1 for b in pixels if b > 128)
        total = w * h
        # Very blank (< 5% lit) = idle/logo screen
        if lit < total * 0.05:
            return True
        # Check for "IMPORT RECOVERY" text by looking at pixel density in top-left region
        # setUp always shows this screen — it's ~20% lit with specific pattern
        # Real test screens vary widely, so we check the raw bytes for known patterns
        # Simple heuristic: if first 2 btn frames match, skip them (setUp wipe + load)
        return False
    except:
        return False

def _pick_best_frame(test_dir, btn_files):
    """Pick the best screenshot for a test, skipping setUp noise frames.
    setUp always produces: btn00000 (wipe confirm) + btn00001 (load_device confirm).
    Real test frames come after. If only setUp frames exist, return None."""
    if not btn_files:
        return None
    # 3+ frames: [0]=setUp wipe, [1]=setUp load or instruction detail, [-1]=final confirm
    # Prefer second-to-last frame — it's the instruction-specific content
    # (amounts, addresses, parameters). The last frame is usually a generic
    # "Sign this transaction?" confirmation that's the same for every tx.
    if len(btn_files) > 2:
        # Use second-to-last for instruction detail, skip setUp frames
        idx = -2 if len(btn_files) > 2 else -1
        return os.path.join(test_dir, btn_files[idx])
    elif len(btn_files) == 2:
        # 2 frames: btn00000 is always setUp (wipe confirm), btn00001 is the test.
        # Always show btn00001 — it's the only real test frame.
        return os.path.join(test_dir, btn_files[1])
    else:
        # Single frame — almost always setUp noise (wipe confirm from setUp).
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

def parse_junit(path):
    """Parse junit XML for pass/fail. Returns dict keyed by 'module::method' (precise)
    and 'method' (fallback). Module is extracted from classname: tests.test_msg_foo.TestBar → test_msg_foo."""
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
        # Extract module from classname: tests.test_msg_foo.TestBar → test_msg_foo
        mod = ''
        if cls:
            parts = cls.split('.')
            for p in parts:
                if p.startswith('test_msg_') or p.startswith('test_sign_') or p.startswith('test_verify_'):
                    mod = p
                    break
            results[f'{cls}.{name}'] = status
        # Key by module::method (disambiguates collisions like test_sign_btc_eth_swap)
        if mod:
            results[f'{mod}::{name}'] = status
        # Bare method fallback — only set if no collision
        if name not in results or status == 'pass':
            results[name] = status
    return results

# ---------------------------------------------------------------
# Test catalog with full context per test
# ---------------------------------------------------------------
# (id, module, method, title, context, [screenshots])
# context = why this test exists, what it proves, what user sees

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
         '- Curves: secp256k1, ed25519, NIST P-256, Pallas (Zcash)',
         '',
         'SECURITY MODEL:',
         '- All private key operations happen on-device, keys never leave',
         '- Every transaction output displayed on OLED for user verification',
         '- PIN grid randomized on each prompt (position-based, not digit-based)',
         '- BIP-39 passphrase creates hidden wallets (plausible deniability)',
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
          'Hardware RNG entropy',
          'Reads random bytes from the hardware RNG. Used to verify the entropy source is functional.',
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
          'Sign Taproot P2TR tx',
          'Taproot (BIP-341/342) with Schnorr signatures. Newest address type with improved '
          'privacy and efficiency.',
          ['Taproot confirmation']),
         ('B21', 'test_msg_signmessage', 'test_sign',
          'Sign message with BTC key',
          'Signs arbitrary text with a BTC address key. Used for proof-of-ownership and login.',
          ['Sign message on OLED']),
         ('B22', 'test_msg_signmessage_segwit', 'test_sign',
          'Sign message with SegWit key', 'Message signing with P2SH-SegWit address key.', []),
         ('B23', 'test_msg_signmessage_segwit_native', 'test_sign',
          'Sign message with bech32 key', 'Message signing with native SegWit address key.', []),
         ('B24', 'test_msg_verifymessage', 'test_message_verify',
          'Verify signed message', 'Device verifies a message signature against a BTC address.', []),
         ('B25', 'test_msg_signtx_bgold', 'test_send_bitcoin_gold_nochange',
          'Sign Bitcoin Gold tx', 'BTG fork uses same signing code with different chain parameters.', []),
         ('B26', 'test_msg_signtx_dash', 'test_send_dash',
          'Sign Dash transaction', 'Dash special transaction types (InstantSend-compatible).', []),
         ('B27', 'test_msg_signtx_grs', 'test_one_one_fee',
          'Sign Groestlcoin tx', 'GRS uses Groestl hash instead of SHA-256d for tx hashing.', []),
         ('B28', 'test_msg_signtx_zcash', 'test_transparent_one_one',
          'Sign Zcash transparent tx',
          'Zcash transparent transactions use Overwinter/Sapling serialization format with '
          'version group IDs and expiry height.',
          ['Zcash tx confirm']),
     ]),

    ('E', 'Ethereum', '7.0.0',
     'Ethereum covers native ETH transfers, ERC-20 tokens, EIP-1559 gas, personal message signing '
     '(EIP-191), and contract interactions. The device displays checksummed addresses (EIP-55), '
     'values in ETH with 18-decimal precision, and gas parameters.',
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
         ('E16', 'test_msg_ethereum_signtx', 'test_ethereum_blind_sign_blocked',
          'Blind sign BLOCKED (AdvancedMode OFF)',
          'Contract data with AdvancedMode disabled. Device shows BLOCKED screen and refuses to sign. '
          'This is the default behavior — blind signing must be explicitly enabled.',
          []),  # screenshots added when AdvancedMode policy lands (7-prep)
         ('E17', 'test_msg_ethereum_signtx', 'test_ethereum_blind_sign_allowed',
          'Blind sign ALLOWED (AdvancedMode ON)',
          'Contract data with AdvancedMode enabled. Device shows BLIND SIGNATURE warning '
          'before proceeding. User sees raw data and must explicitly confirm.',
          []),  # screenshots added when AdvancedMode policy lands (7-prep)
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
          'Sign THORChain tx', 'Native RUNE transfer with memo.', ['Memo display']),
         ('H3', 'test_msg_thorchain_signtx', 'test_sign_btc_eth_swap',
          'Sign BTC->ETH swap', 'Cross-chain swap via THORChain memo routing.', ['Swap memo']),
         ('H4', 'test_msg_2thorchain_signtx', 'test_thorchain_sign_tx_deposit',
          'Sign THORChain deposit', 'LP deposit transaction.', []),
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
          'Sign BTC-ETH swap via Maya', 'Cross-chain swap via Maya memo routing.', []),
         ('M3', 'test_msg_mayachain_signtx', 'test_sign_eth_add_liquidity',
          'Sign swap via Maya', 'Cross-chain swap via Maya memo routing.', []),
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

    # ===== 7.14 NEW FEATURES =====
    ('V', 'EVM Clear-Signing', '7.14.0',
     'NEW: Verified transaction metadata for EVM contracts. Host sends a signed blob with contract '
     'name, function, and decoded parameters. Device verifies blob signature against trusted key, '
     'then shows human-readable details with VERIFIED icon. AdvancedMode policy gates blind-signing '
     '(disabled by default = blind signing blocked).',
     [
         'CLEAR-SIGN: Signed metadata -> verify signature -> VERIFIED icon + method + decoded args',
         'BLIND BLOCKED: No metadata + AdvancedMode off -> device refuses',
         'BLIND ALLOWED: No metadata + AdvancedMode on -> warning -> sign',
     ],
     [
         ('V1', 'test_msg_ethereum_clear_signing', 'test_valid_metadata_returns_verified',
          'Valid metadata accepted',
          'Correctly signed metadata blob is accepted. Device shows VERIFIED icon with decoded '
          'method name and contract address.',
          ['VERIFIED icon + method']),
         ('V2', 'test_msg_ethereum_clear_signing', 'test_wrong_key_returns_malformed',
          'Wrong signing key rejected', 'Metadata signed with wrong key is rejected as malformed.', []),
         ('V3', 'test_msg_ethereum_clear_signing', 'test_tampered_method_returns_malformed',
          'Tampered method rejected', 'Modified method name in blob fails signature check.', []),
         ('V4', 'test_msg_ethereum_clear_signing', 'test_tampered_contract_returns_malformed',
          'Tampered contract rejected', 'Modified contract address fails signature check.', []),
         ('V5', 'test_msg_ethereum_clear_signing', 'test_no_metadata_then_sign_unchanged',
          'No metadata = blind sign path',
          'Without metadata, transaction goes through blind-sign path (gated by AdvancedMode).',
          ['Blind sign warning']),
         ('V6', 'test_msg_ethereum_clear_signing', 'test_signature_verification',
          'Signature verification math', 'Unit test for the metadata blob signature algorithm.', []),
         ('V7', 'test_msg_ethereum_clear_signing', 'test_tampered_blob_fails_verification',
          'Tampered blob fails', 'Any byte change in the blob invalidates the signature.', []),
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
         ('S4', 'test_msg_solana_signtx', 'test_solana_sign_system_transfer',
          'Sign SOL transfer', 'System::Transfer with full address + amount display.', ['SOL amount + address']),
         ('S5', 'test_msg_solana_signtx', 'test_solana_sign_message',
          'Sign Solana message', 'Arbitrary message signing with Ed25519 key.', ['Message screen']),
         ('S6', 'test_msg_solana_signtx', 'test_solana_sign_empty_rejected',
          'Empty tx rejected', 'Zero-length transaction data is refused.', []),
         ('S7', 'test_msg_solana_signtx', 'test_solana_sign_deterministic',
          'Deterministic signing', 'Same tx always produces same signature.', []),
         ('S8', 'test_msg_solana_signtx', 'test_solana_sign_token_transfer',
          'SPL Token transfer',
          'Send SPL tokens to destination. OLED shows token amount and recipient address.',
          ['Token amount + address']),
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
     ]),

    ('T', 'TRON', '7.14.0',
     'NEW: TRON with protobuf deserialization and reconstruct-then-sign. 13 hardcoded TRC-20 tokens. '
     'Device reconstructs tx hash from parsed fields (not raw blob) for clear-sign path.',
     [
         'ADDRESS: m/44\'/195\'/0\'/0/0 -> full 34-char base58 TRON address',
         'STRUCTURED: Parse fields -> reconstruct hash -> show amount + address -> sign',
         'TRC-20: Decode transfer(to,amount) ABI -> show token name + decoded amount',
         'LEGACY: Raw protobuf -> blind sign warning',
     ],
     [
         ('T1', 'test_msg_tron_getaddress', 'test_tron_get_address',
          'Derive TRON address', 'Full 34-character base58 address.', ['Full 34-char address']),
         ('T2', 'test_msg_tron_getaddress', 'test_tron_different_accounts',
          'Different accounts', 'Different indices produce different addresses.', []),
         ('T3', 'test_msg_tron_getaddress', 'test_tron_deterministic',
          'Deterministic derivation', 'Same path always produces same address.', []),
         ('T4', 'test_msg_tron_signtx', 'test_tron_sign_transfer_structured',
          'Sign TRX transfer', 'Structured clear-sign with full address display.', ['TRX send']),
         ('T5', 'test_msg_tron_signtx', 'test_tron_sign_transfer_legacy_raw_data',
          'Sign TRX legacy raw', 'Raw protobuf data triggers blind sign path.', ['Blind sign']),
         ('T6', 'test_msg_tron_signtx', 'test_tron_sign_trc20_transfer',
          'Sign TRC-20 token', 'Known token decoded from ABI data.', ['Token + amount']),
         ('T7', 'test_msg_tron_signtx', 'test_tron_sign_missing_fields_rejected',
          'Missing fields rejected', 'Incomplete transaction data is refused.', []),
     ]),

    ('N', 'TON', '7.14.0',
     'NEW: TON v4r2 wallet contracts. Clear-sign reconstructs cell tree + SHA-256 hash verification. '
     'Blind-sign for StateInit deploys or hash mismatch. Memo/comment support.',
     [
         'ADDRESS: m/44\'/607\'/0\' -> full 48-char base64url TON address',
         'CLEAR-SIGN: Reconstruct v4r2 cell -> SHA-256 match -> show transfer details',
         'BLIND-SIGN: Hash mismatch or deploy -> "BLIND SIGNATURE" warning',
     ],
     [
         ('N1', 'test_msg_ton_getaddress', 'test_ton_get_address',
          'Derive TON address', 'Full 48-character base64url address.', ['Full 48-char address']),
         ('N2', 'test_msg_ton_getaddress', 'test_ton_different_accounts',
          'Different accounts', 'Different indices produce different addresses.', []),
         ('N3', 'test_msg_ton_getaddress', 'test_ton_address_format',
          'Address format validation', 'Bounceable/non-bounceable format check.', []),
         ('N4', 'test_msg_ton_signtx', 'test_ton_sign_structured',
          'Sign TON clear-sign', 'Hash verification passes, shows "TON Transfer" with details.', ['TON Transfer']),
         ('N5', 'test_msg_ton_signtx', 'test_ton_sign_with_comment',
          'Sign TON with memo', 'Comment displayed before signing.', ['Memo display']),
         ('N6', 'test_msg_ton_signtx', 'test_ton_sign_legacy_raw_tx',
          'Sign TON blind', 'Raw tx without structured fields triggers blind sign.', ['Blind warning']),
         ('N7', 'test_msg_ton_signtx', 'test_ton_sign_missing_fields_rejected',
          'Missing fields rejected', 'Incomplete data refused.', []),
     ]),

    ('Z', 'Zcash Orchard', '7.14.0',
     'NEW: Shielded transactions via PCZT streaming. Orchard hides sender, recipient, and amount '
     'using ZK proofs. Raw seed access (ZIP-32 Orchard derivation uses BIP-39 seed + Pallas curve). '
     'Full Viewing Key (FVK) export for watch-only wallets.',
     [
         'FVK: Derive ak, nk, rivk components via ZIP-32 Orchard path',
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
         ('Z5', 'test_msg_zcash_sign_pczt', 'test_single_action_legacy_sighash',
          'Sign single Orchard action', 'One shielded action, device shows amount + fee.', ['Shielded confirm']),
         ('Z6', 'test_msg_zcash_sign_pczt', 'test_multi_action_legacy_sighash',
          'Sign multiple actions', 'Multiple Orchard actions in one transaction.', []),
         ('Z7', 'test_msg_zcash_sign_pczt', 'test_signatures_are_64_bytes',
          'Signature format', 'Orchard signatures must be exactly 64 bytes (RedPallas).', []),
         ('Z8', 'test_msg_zcash_sign_pczt', 'test_transparent_shielding_single_input',
          'Transparent to shielded', 'Transparent BTC-like input shielded into Orchard pool.', ['Hybrid shield']),
         ('Z9', 'test_msg_zcash_sign_pczt', 'test_transparent_shielding_multiple_inputs',
          'Multi-input shielding', 'Multiple transparent inputs shielded in one tx.', []),
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
    ts = datetime.now().strftime('%Y-%m-%d %H:%M')
    active = [(l,t,mf,bg,fl,tests) for l,t,mf,bg,fl,tests in SECTIONS if ver_ge(fw_version, mf)]
    # Separate specs section (no tests) from test sections
    specs = [s for s in active if not s[5]]
    # Sections with results first, pending sections at bottom.
    # Within each group: existing chains first (proven), then new features.
    has_results = [s for s in active if s[5] and any(_lookup(results, t[1], t[2]) for t in s[5])]
    no_results = [s for s in active if s[5] and not any(_lookup(results, t[1], t[2]) for t in s[5])]
    test_sections = has_results + no_results
    total = sum(len(s[5]) for s in test_sections)
    passed = sum(1 for s in test_sections for t in s[5] if _lookup(results, t[1], t[2]) == 'pass')
    failed = sum(1 for s in test_sections for t in s[5] if _lookup(results, t[1], t[2]) in ('fail','error'))
    skipped = total - passed - failed

    # Title
    pb.text(20, 'KeepKey Firmware Test Report', bold=True)
    pb.gap(2)
    if passed == total and total > 0:
        pb.text(11, f'Firmware {fw_version}  |  {ts}  |  ALL {total} TESTS PASSED', bold=True, color=GREEN)
    elif failed > 0:
        pb.text(11, f'Firmware {fw_version}  |  {ts}  |  {failed} FAILED of {total} tests', bold=True, color=RED)
    else:
        pb.text(10, f'Firmware {fw_version}  |  {ts}  |  {total} tests: {passed} passed, {skipped} pending')
    pb.gap(6)
    pb.text(12, 'Sections', bold=True)
    _shown_tested = _shown_pending = False
    for letter, title, mf, _, _, tests in test_sections:
        has_any = any(_lookup(results, t[1], t[2]) for t in tests)
        is_new = ver_t(mf) > (7, 10, 0)
        if has_any and not _shown_tested:
            _shown_tested = True
        elif not has_any and not _shown_pending:
            pb.text(9, f'  --- Pending (no firmware support yet) ---', bold=True, color=GRAY)
            _shown_pending = True
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
            # Embed OLED screenshots — use _pick_best_frame for the primary image,
            # then show up to 2 more frames for multi-screen flows (signing, swaps)
            if screenshot_dir:
                test_dir = os.path.join(screenshot_dir, mod.replace('test_',''), meth)
                btn_files = sorted(f for f in os.listdir(test_dir) if f.startswith('btn')) if os.path.isdir(test_dir) else []
                best = _pick_best_frame(test_dir, btn_files)
                if best:
                    # Show the best frame (most representative)
                    try:
                        pb.need(55)
                        pb.image(best, display_w=384, display_h=96)
                    except Exception:
                        pass
                    # For multi-screen tests, show up to 2 additional frames
                    test_frames = btn_files[2:] if len(btn_files) > 2 else []
                    extra = [f for f in test_frames if os.path.join(test_dir, f) != best][:2]
                    for frame in extra:
                        try:
                            pb.need(55)
                            pb.image(os.path.join(test_dir, frame), display_w=384, display_h=96)
                        except Exception:
                            pass
                    if len(btn_files) > 5:
                        pb.text(6, f'({len(btn_files)} OLED frames captured, showing best {min(3, len(test_frames)+1)})', color=GRAY)
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
    print(f'{output_path}: fw={fw_version}, {len(active)} sections, {total} tests ({passed} passed, {failed} failed, {skipped} pending)')

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


def main():
    p = argparse.ArgumentParser(description='KeepKey Firmware Test Report')
    p.add_argument('--output', default='test-report.pdf')
    p.add_argument('--fw-version', default=None)
    p.add_argument('--junit', default=None, help='JUnit XML for pass/fail results')
    p.add_argument('--screenshots', default=None, help='Directory with per-test OLED screenshots')
    p.add_argument('--screenshot-filter', action='store_true',
                   help='Print pytest -k expression for tests needing screenshots, then exit')
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

    results = parse_junit(args.junit) if args.junit else {}
    render(args.output, fw, results, args.screenshots)

if __name__ == '__main__':
    main()
