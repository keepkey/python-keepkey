# This file is part of the KeepKey project.
#
# Storage version gate -- upgrade preservation and downgrade wipe.
#
# Policy, from docs/StorageVersionGate.md, in two sentences:
#
#   A signed UPGRADE must never wipe. A DOWNGRADE wipes, and that is correct.
#
# Nothing in this suite tested either half before this file. Both directions
# are release blockers: a wiping upgrade destroys every field wallet with no
# prompt, and a downgrade that DOESN'T wipe would let an attacker roll back to
# an older signed image with a known extraction bug and keep the seed.
#
# How the wipe happens, mechanically (lib/firmware/storage.c):
#
#   storage_init() -> storage_fromFlash() -> version_from_int(raw_version)
#   An unrecognised version returns StorageVersion_NONE, storage_fromFlash()
#   returns SUS_Invalid, and storage_init() runs storage_reset() +
#   storage_commit(). No prompt, no warning -- the wallet is gone at boot.
#
# So "does this firmware recognise the version in flash?" IS the whole
# question, and every test below is a way of asking it.
#
# ---------------------------------------------------------------------------
# What runs where, and why the emulator can prove any of this at all
# ---------------------------------------------------------------------------
#
# The version gate only runs at BOOT. There is no host-driven reboot: the
# SoftReset message (messages.proto type 89) has no entry in
# lib/firmware/messagemap.def, and fsm_msgDebugLinkFlashDump() is compiled out
# under #ifndef EMULATOR, so the emulator can neither be rebooted nor have its
# flash read over the wire. The only way to cross the boot boundary is to own
# the emulator process and its flash image file.
#
# That is what TestStorageUpgradePreservation does: it starts its OWN kkemu on
# its OWN port pair in its OWN temp directory, so it never touches whichever
# emulator the rest of the suite is talking to. Killing the process and
# starting it again on the same emulator.img IS a power cycle -- lib/emulator/
# setup.c mmaps that file as the flash array, so every flash write survives.
#
# Restamping the version word in that image is not "faking an upgrade". It
# reproduces exactly what an arriving device presents to the incoming
# firmware: a blob whose header says one version while the firmware compiled
# in says another. It does NOT exercise the layout migration chain, because
# the bytes under the stamp were written by this build -- see
# test_v16_blob_upgrades_without_wiping for how far that is taken, and the
# module docstring in the report section for what is still untested.
#
# TestStorageVersionGateSource needs no device at all: it reads the firmware
# sources and asserts the gate's own invariants. Those tests run everywhere,
# including CI, so this section is never completely dark.

from __future__ import print_function

import glob
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
_PYKEEPKEY = os.path.dirname(_HERE)
if _PYKEEPKEY not in sys.path:
    sys.path.insert(0, _PYKEEPKEY)


# ---------------------------------------------------------------------------
# Flash layout constants
# ---------------------------------------------------------------------------
# Emulator flash file offsets. lib/emulator/setup.c mmaps emulator.img at
# FLASH_ORIGIN (0x08000000), so a flash address maps to file offset
# address - 0x08000000. The three storage sectors come from
# flash_sector_map[] in include/keepkey/board/memory.h.
SECTOR_OFFSETS = (0x4000, 0x8000, 0xC000)  # FLASH_STORAGE1/2/3
SECTOR_RECORD_LEN = 2572  # sizeof(flash_temp) in storage_commit()

# STORAGE_MAGIC_STR, include/keepkey/board/keepkey_board.h
STORAGE_MAGIC = b"stor"

# Metadata is 44 bytes; the Storage record starts right after it, and its
# first word is the version. Everything below is (44 + offset-within-Storage),
# with the inner offsets taken from storage_readStorageV16Plaintext() and
# storage_readStorageV17() in lib/firmware/storage.c -- NOT from docs/
# Storage.md, whose V17 table has a stale byte count.
OFF_VERSION = 44 + 0
OFF_FLAGS = 44 + 4
OFF_AUTHDATA_FINGERPRINT = 44 + 469  # 32 bytes, V17 only
OFF_ENCSEC_VERSION = 44 + 1497
OFF_ENCSEC = 44 + 1501
V16_ENCSEC_SIZE = 512  # lib/firmware/storage.h
V17_ENCSEC_SIZE = 1024

FLAG_HAS_SEC_FINGERPRINT = 1 << 14
FLAG_AUTHDATA_INITIALIZED = 1 << 18
FLAG_AUTHDATA_ENCRYPTED = 1 << 19

# include/keepkey/firmware/storage.h
STORAGE_VERSION_BTC_ONLY_BASE = 10000

MNEMONIC_ALL = " ".join(["all"] * 12)
LABEL = "storagegate"
PIN = "1234"
BIP44_ADDRESS_N = [2147483692, 2147483648, 2147483648, 0, 0]  # m/44'/0'/0'/0/0


# ---------------------------------------------------------------------------
# Firmware source access
# ---------------------------------------------------------------------------

def _repo_root():
    """Directory of the firmware checkout this python-keepkey lives under."""
    d = _HERE
    for _ in range(8):
        if os.path.isfile(os.path.join(d, "lib", "firmware", "storage.c")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


_ROOT = _repo_root()


def _read_source(rel):
    assert _ROOT, (
        "firmware sources not found above %s -- the storage version gate is a "
        "property of lib/firmware/storage.c and cannot be checked without it" % _HERE
    )
    with open(os.path.join(_ROOT, rel)) as f:
        return f.read()


def _define(text, name):
    """Value of a simple integer #define, tolerating a line continuation.

    STORAGE_VERSION is written as `#define STORAGE_VERSION \\\n  17 /* ... */`,
    so the continuation has to be folded before matching.
    """
    folded = text.replace("\\\n", " ")
    m = re.search(r"^\s*#\s*define\s+" + name + r"\b\s+(\d+)", folded, re.M)
    assert m, "no integer #define %s found" % name
    return int(m.group(1))


# ---------------------------------------------------------------------------
# Emulator process management
# ---------------------------------------------------------------------------

def _find_emulator():
    """Locate a kkemu binary this test can start and stop.

    KK_EMULATOR_BIN wins. Otherwise look where the two build recipes put it:
    scripts/emulator/Dockerfile configures in-source (bin/kkemu at the repo
    root), while local work uses an out-of-tree build-* directory. build-emu is
    named before the generic glob on purpose -- a bitcoin-only build stamps its
    own wallets into the reserved band, which is a different device under
    test_bitcoin_only_band_refuses_without_wiping.
    """
    env = os.environ.get("KK_EMULATOR_BIN")
    if env:
        return env if os.access(env, os.X_OK) else None
    if not _ROOT:
        return None
    candidates = [os.path.join(_ROOT, "bin", "kkemu"),
                  os.path.join(_ROOT, "build-emu", "bin", "kkemu")]
    candidates += sorted(glob.glob(os.path.join(_ROOT, "build*", "bin", "kkemu")))
    for c in candidates:
        if os.access(c, os.X_OK):
            return c
    return None


_EMULATOR_BIN = _find_emulator()

_NO_EMULATOR = (
    "no kkemu binary to start and stop (looked at $KK_EMULATOR_BIN, "
    "<repo>/bin/kkemu, <repo>/build*/bin/kkemu). The version gate only runs at "
    "boot, and there is no host-driven reboot -- SoftReset is unimplemented and "
    "DebugLinkFlashDump is compiled out under EMULATOR -- so these tests must "
    "own the emulator process. In CI the python-keepkey container is built from "
    "scripts/emulator/python-keepkey.Dockerfile, which copies the source but "
    "never builds the emulator, so this section is UNPROVEN there until that "
    "image ships a kkemu."
)


def _free_port_pair():
    """A UDP port p where p and p+1 are both free (kkemu uses p and p+1)."""
    for _ in range(200):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("127.0.0.1", 0))
            p = s.getsockname()[1]
        finally:
            s.close()
        if p % 2:
            continue
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            t.bind(("127.0.0.1", p + 1))
        except socket.error:
            continue
        finally:
            t.close()
        return p
    raise RuntimeError("no free UDP port pair for the emulator")


class Emulator(object):
    """One kkemu process over one flash image, restartable.

    The image is the whole point: lib/emulator/setup.c mmaps emulator.img over
    the firmware's flash array, so halting the process and booting it again
    replays storage_init() against exactly the bytes the previous run left.
    """

    def __init__(self, workdir):
        self.workdir = workdir
        self.port = _free_port_pair()
        self.img = os.path.join(workdir, "emulator.img")
        self.proc = None

    # -- process ------------------------------------------------------------

    def _ping(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        try:
            s.sendto(b"PINGPING", ("127.0.0.1", self.port))
            return s.recv(8) == b"PONGPONG"
        except socket.error:
            return False
        finally:
            s.close()

    def boot(self):
        assert self.proc is None, "already booted"
        env = dict(os.environ, KEEPKEY_UDP_PORT=str(self.port))
        with open(os.path.join(self.workdir, "emu.log"), "ab") as log:
            self.proc = subprocess.Popen(
                [_EMULATOR_BIN], cwd=self.workdir, env=env, stdout=log,
                stderr=subprocess.STDOUT)
        for _ in range(100):
            time.sleep(0.1)
            if self.proc.poll() is not None:
                raise RuntimeError(
                    "emulator exited rc=%s before answering; see %s"
                    % (self.proc.returncode, os.path.join(self.workdir, "emu.log")))
            if self._ping():
                return
        raise RuntimeError("emulator did not answer PINGPING on port %d" % self.port)

    def halt(self):
        """Power cycle, not a graceful shutdown -- flash keeps whatever
        storage_commit() already wrote, which is what a real yank does."""
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except Exception:
                self.proc.kill()
                self.proc.wait()
        self.proc = None
        time.sleep(0.2)

    # -- client -------------------------------------------------------------

    def client(self, method, pin=None):
        """Debuglink client bound to THIS emulator.

        Deliberately does not go through tests/config.py: that module picks
        HID/WebUSB when a real KeepKey is plugged in, which would send these
        wipes at somebody's hardware wallet.
        """
        from keepkeylib.client import KeepKeyDebuglinkClient
        from keepkeylib.transport_udp import UDPTransport

        c = KeepKeyDebuglinkClient(UDPTransport("127.0.0.1:%d" % self.port))
        c.set_debuglink(UDPTransport("127.0.0.1:%d" % (self.port + 1)))
        c.setup_debuglink(button=True, pin_correct=True)
        _screenshots_to(c, method)
        if pin:
            _teach_pin(c, pin)
        return c

    # -- flash image --------------------------------------------------------

    def image(self):
        with open(self.img, "rb") as f:
            return f.read()

    def active_sector(self):
        """Offset find_active_storage() would pick: FIRST sector with the magic.

        lib/board/memory.c scans FLASH_STORAGE1..3 in order and takes the first
        one whose first four bytes are "stor". Order matters, not recency.
        """
        img = self.image()
        for off in SECTOR_OFFSETS:
            if img[off:off + 4] == STORAGE_MAGIC:
                return off
        return None

    def sector(self, off):
        return self.image()[off:off + SECTOR_RECORD_LEN]

    def patch(self, off, rel, data):
        assert self.proc is None, "patch the image only while the device is off"
        with open(self.img, "r+b") as f:
            f.seek(off + rel)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

    def read_u32(self, off, rel):
        return struct.unpack("<I", self.sector(off)[rel:rel + 4])[0]

    def write_u32(self, off, rel, val):
        self.patch(off, rel, struct.pack("<I", val))


def _teach_pin(client, pin):
    """Answer PinMatrixRequest with the real PIN, encoded through the matrix.

    The stock DebugLinkMixin callback asks the DEVICE for the PIN
    (DebugLinkGetState.pin), but storage_getPin() returns `debuglink_pin`, a
    RAM-only mirror set by storage_setPin(). From V11 storage on, the PIN is
    never stored -- only the key it wraps -- so after a reboot that mirror is
    empty and the stock callback sends "". Nothing is wrong with the device;
    the harness simply cannot read a PIN back out of a rebooted wallet, which
    is precisely why no existing test crosses this boundary.
    """
    from keepkeylib import messages_pb2 as proto

    def cb(msg):
        _, matrix = client.debug.read_pin()
        return proto.PinMatrixAck(
            pin="".join(str(matrix.index(d) + 1) for d in pin))

    client.callback_PinMatrixRequest = cb


def _screenshots_to(client, method):
    """Point a fresh client at the per-test directory the report expects.

    Mirrors conftest.py's layout (SCREENSHOT_DIR/<module minus test_>/<method>),
    and must be set before the first ButtonRequest: the wipe and load confirms
    are captured by the client's own callback, and without this they land in
    the SCREENSHOT_DIR root where _build_frame_census() cannot see them.

    Set here rather than by conftest.py because these tests do not inherit
    common.KeepKeyTest -- its setUp() builds a client from config.py and wipes
    whatever that resolves to -- so the conftest hook never fires for them.
    """
    if os.environ.get("KEEPKEY_SCREENSHOT") != "1":
        return
    d = os.path.join(os.environ.get("SCREENSHOT_DIR", "screenshots"),
                     "storage_version_gate", method)
    if not os.path.isdir(d):
        os.makedirs(d)
    client.screenshot_dir = d
    client.screenshot_id = len(glob.glob(os.path.join(d, "btn*.png")))


def _capture(client):
    """Grab the OLED as it stands. The confirm screens capture themselves on
    ButtonRequest; the home screen after a boot has no button behind it, so it
    has to be asked for."""
    if os.environ.get("KEEPKEY_SCREENSHOT") != "1":
        return
    client._capture_oled()


# ---------------------------------------------------------------------------
# The gate's own invariants, read out of the firmware sources
# ---------------------------------------------------------------------------

class TestStorageVersionGateSource(unittest.TestCase):
    """No device needed. These are the checks that survive a CI runner which
    cannot restart an emulator, so the section is never entirely unmeasured."""

    def setUp(self):
        self.h = _read_source("include/keepkey/firmware/storage.h")
        self.c = _read_source("lib/firmware/storage.c")
        self.inc = _read_source("lib/firmware/storage_versions.inc")
        self.version = _define(self.h, "STORAGE_VERSION")
        self.last_shipped = _define(self.h, "STORAGE_VERSION_LAST_SHIPPED")

    def test_active_flash_format_is_v17(self):
        """alpha writes V17, the same format shipped v7.14.1.

        This literal is an INDEPENDENT witness, on purpose. The compile-time
        assert in storage.c compares STORAGE_VERSION against
        STORAGE_VERSION_LAST_SHIPPED -- two numbers in the same header, both
        editable in one commit, and raising LAST_SHIPPED to make a build
        compile is the exact edit docs/StorageVersionGate.md calls the highest
        severity review item in the file.

        7.15 reverted the flash format from V19 back to V17 (6bebde7b2). V19
        migrated 17 -> 19 on the first boot, with no prompt, after which no
        downgrade was possible without a wipe; V18's clear-sign identity block
        is dead. The V19 serializer is still in the tree behind
        STORAGE_PIN_KDF_V19 == 0. If a release re-lands it, this test must
        fail and the bump must be argued for, not discovered in the field.
        """
        self.assertEqual(
            17, self.version,
            "STORAGE_VERSION is %d, not the V17 format 7.15 reverted to. A bump "
            "is a deliberate release act (docs/StorageVersionGate.md): confirm "
            "the reader chain, the anti-rollback story, and the release notes, "
            "then update this test." % self.version)
        self.assertEqual(17, self.last_shipped)

    def test_version_never_drops_below_a_shipped_release(self):
        """Lowering STORAGE_VERSION wipes every device upgrading FROM a shipped
        release: its blob's version stops being recognised, so the gate maps it
        to StorageVersion_NONE and storage_init() resets. The version must also
        stay under the bitcoin-only band, or a multi-chain wallet would be
        stamped into the band that multi-chain firmware refuses to load."""
        self.assertGreaterEqual(self.version, self.last_shipped)
        self.assertLess(self.version, STORAGE_VERSION_BTC_ONLY_BASE)

    def test_version_ladder_is_contiguous_and_ends_at_storage_version(self):
        """storage_versions.inc may only ever be APPENDED to.

        The enum is emitted in .inc order after StorageVersion_NONE = 0, so a
        contiguous 1..N list is what makes StorageVersion_N == N. Deleting or
        renumbering an entry silently drops a version from version_from_int()
        and wipes every device carrying it.
        """
        entries = [int(m) for m in re.findall(
            r"STORAGE_VERSION_(?:ENTRY|LAST)\s*\(\s*(\d+)\s*\)", self.inc)]
        self.assertTrue(entries, "no version entries parsed from the ladder")
        self.assertEqual(list(range(1, len(entries) + 1)), entries,
                         "storage_versions.inc is not contiguous from 1")
        last = re.findall(r"STORAGE_VERSION_LAST\s*\(\s*(\d+)\s*\)", self.inc)
        self.assertEqual([str(self.version)], last)

    def test_every_ladder_version_has_a_reader(self):
        """Every version in the ladder needs a case in storage_fromFlash().

        This is the failure the static asserts do NOT cover. They pin the enum
        to its own numbering; they say nothing about the switch. Drop a case
        and control falls out of the switch to `return SUS_Invalid` -- which
        storage_init() answers with storage_reset(). Every device carrying that
        version is wiped on upgrade, and the build stays green.
        """
        body = self.c.split("StorageUpdateStatus storage_fromFlash", 1)
        self.assertEqual(2, len(body), "storage_fromFlash not found")
        cases = set(int(m) for m in re.findall(
            r"case\s+StorageVersion_(\d+)\s*:", body[1]))
        missing = sorted(set(range(1, self.version + 1)) - cases)
        self.assertEqual([], missing,
                         "storage_fromFlash has no case for version(s) %s -- a "
                         "device carrying one is wiped at boot" % missing)


# ---------------------------------------------------------------------------
# Behaviour across a real power cycle
# ---------------------------------------------------------------------------

@unittest.skipIf(_EMULATOR_BIN is None, _NO_EMULATOR)
class TestStorageUpgradePreservation(unittest.TestCase):

    def setUp(self):
        self.method = self.id().split(".")[-1]
        self.workdir = tempfile.mkdtemp(prefix="kk-storage-gate-")
        self.addCleanup(shutil.rmtree, self.workdir, True)
        self.emu = Emulator(self.workdir)
        self.addCleanup(self.emu.halt)

    # -- shared arrangement -------------------------------------------------

    def _create_wallet(self):
        """Boot a virgin device, load a known seed behind a PIN, record the
        address, and power it off. Returns the address."""
        self.emu.boot()
        c = self.emu.client(self.method)
        try:
            c.wipe_device()
            c.load_device_by_mnemonic(
                mnemonic=MNEMONIC_ALL, pin=PIN, passphrase_protection=False,
                label=LABEL, language="english")
            c.init_device()
            self.assertTrue(c.features.initialized)
            addr = c.get_address("Bitcoin", BIP44_ADDRESS_N)
        finally:
            c.close()
        self.emu.halt()

        off = self.emu.active_sector()
        self.assertIsNotNone(
            off, "no storage sector carries the %r magic after a wallet was "
                 "created -- nothing was persisted" % STORAGE_MAGIC)
        return addr, off

    def _make_v16_blob(self, off):
        """Rewrite the committed V17 record as the V16 record a 7.14.x device
        would be carrying when it arrives for this upgrade.

        Only the four things that actually differ between the two formats,
        per storage_readStorageV17() vs storage_readStorageV16():

          * the version stamp;
          * flags bits 18/19 (authdata_initialized / authdata_encrypted) --
            V16 has no authenticator section, so both are clear;
          * authdata_fingerprint at +469, reserved bytes in V16;
          * encrypted_sec is 512 bytes in V16, 1024 in V17. The upper half is
            the authenticator block, which a V16 device never wrote.

        Bit 14 (has_sec_fingerprint) is cleared too, and that is not cosmetic:
        the fingerprint is taken over 1024 bytes when encrypted_sec_version >
        16 and over 512 when it is not, so a V17 fingerprint can never match a
        V16 read. A real V16 blob carries a V16 fingerprint; we cannot forge
        one without the storage key, so we present a device that never had
        one -- storage_secMigrate() then recomputes and stores it, which is the
        same path a genuinely older wallet takes.
        """
        flags = self.emu.read_u32(off, OFF_FLAGS)
        self.emu.write_u32(off, OFF_FLAGS, flags & ~(
            FLAG_HAS_SEC_FINGERPRINT | FLAG_AUTHDATA_INITIALIZED
            | FLAG_AUTHDATA_ENCRYPTED))
        self.emu.patch(off, OFF_AUTHDATA_FINGERPRINT, b"\x00" * 32)
        self.emu.patch(off, OFF_ENCSEC + V16_ENCSEC_SIZE,
                       b"\x00" * (V17_ENCSEC_SIZE - V16_ENCSEC_SIZE))
        self.emu.write_u32(off, OFF_ENCSEC_VERSION, 16)
        self.emu.write_u32(off, OFF_VERSION, 16)

    # -- tests --------------------------------------------------------------

    def test_reboot_preserves_the_wallet(self):
        """The boundary docs/StorageVersionGate.md says the ordinary tests never
        cross. Everything else in this suite lives inside one session, where the
        wallet is a RAM shadow; only a power cycle re-runs storage_init() and
        proves the bytes in flash were both written and readable.

        The PIN is load-bearing. The seed lives in encrypted_sec, and the key
        that decrypts it is only ever stored wrapped by the PIN. An address
        that still derives after the reboot proves the wrapped key, its
        fingerprint and the ciphertext all round-tripped together.
        """
        addr, off = self._create_wallet()
        self.assertEqual(17, self.emu.read_u32(off, OFF_VERSION),
                         "this build committed a storage version other than 17")

        before = self.emu.image()
        self.emu.boot()
        c = self.emu.client(self.method, pin=PIN)
        try:
            c.init_device()
            # Steady state: storage_fromFlash() returns SUS_Valid for a record
            # already at STORAGE_VERSION, so storage_init() commits nothing.
            # This is also the control for the migration test below, where the
            # same comparison is what proves the V16 branch ran.
            self.assertEqual(before, self.emu.image(),
                             "booting an already-current record rewrote flash")
            _capture(c)
            self.assertTrue(c.features.initialized, "the wallet did not survive")
            self.assertEqual(LABEL, c.features.label)
            self.assertTrue(c.features.pin_protection)
            # show_display so the recovered address is ON SCREEN, not just on
            # the wire: the OLED frame is the report's evidence that the same
            # wallet came back.
            self.assertEqual(
                addr, c.get_address("Bitcoin", BIP44_ADDRESS_N,
                                    show_display=True))
        finally:
            c.close()

    def test_v16_blob_upgrades_without_wiping(self):
        """A V16 wallet, booted by V17 firmware, keeps its seed.

        This is the whole policy in one test: the device arrives carrying the
        format the release it is leaving wrote, and the incoming firmware must
        read it rather than reset it. storage_fromFlash() takes
        case StorageVersion_16, reads through storage_readV16(), restamps the
        record V17 and reports SUS_Updated, which storage_init() answers with a
        commit -- a migration, not a wipe.

        The same address, behind the same PIN, is the assertion. It can only
        derive if the wrapped storage key unwrapped, the 512-byte V16
        ciphertext decrypted, and the seed came back byte-identical.
        """
        addr, off = self._create_wallet()
        self._make_v16_blob(off)
        self.assertEqual(16, self.emu.read_u32(off, OFF_VERSION))

        before = self.emu.image()
        self.emu.boot()
        c = self.emu.client(self.method, pin=PIN)
        try:
            c.init_device()
            # A surviving wallet alone would not prove the V16 branch ran --
            # a V17 record decodes to the same wallet. The migration is what
            # is under test, so assert the side effect only it has: SUS_Updated
            # makes storage_init() commit at boot, where SUS_Valid writes
            # nothing (asserted as the control in the reboot test above).
            self.assertNotEqual(
                before, self.emu.image(),
                "nothing was written to flash at boot, so storage_fromFlash "
                "did not report SUS_Updated and case StorageVersion_16 never "
                "ran -- this test is not exercising the migration")
            _capture(c)
            self.assertTrue(
                c.features.initialized,
                "V17 firmware WIPED a V16 wallet at boot -- every device "
                "upgrading from 7.14.x loses its seed")
            self.assertEqual(LABEL, c.features.label)
            self.assertEqual(
                addr, c.get_address("Bitcoin", BIP44_ADDRESS_N,
                                    show_display=True),
                "the V16 wallet survived the boot but derives a DIFFERENT "
                "address -- the migration corrupted the seed, which is worse "
                "than a wipe because nothing announces it")
        finally:
            c.close()

    def test_unrecognised_version_wipes_on_boot(self):
        """A downgrade wipes, deliberately -- do not "fix" this.

        A device that has run newer firmware carries a newer stamp. Older
        firmware cannot read it, so version_from_int() returns
        StorageVersion_NONE and storage_init() resets. That is the property
        that stops an attacker flashing an older, validly signed image with a
        known extraction bug and keeping the seed.

        One past the version this build just committed is the tightest
        possible case, and it is measured from the device rather than read out
        of the header: it is exactly what the next format bump will look like
        to this firmware.
        """
        addr, off = self._create_wallet()
        unknown = self.emu.read_u32(off, OFF_VERSION) + 1
        self.emu.write_u32(off, OFF_VERSION, unknown)

        self.emu.boot()
        c = self.emu.client(self.method)
        try:
            c.init_device()
            _capture(c)
            self.assertFalse(
                c.features.initialized,
                "a storage record stamped v%d -- which this firmware does not "
                "recognise -- was loaded anyway. Rollback protection is gone: "
                "an older signed image would keep the seed." % unknown)
            self.assertFalse(c.features.pin_protection)
            self.assertNotEqual(LABEL, c.features.label)
        finally:
            c.close()

    def test_bitcoin_only_band_refuses_without_wiping(self):
        """A bitcoin-only wallet is refused, and REFUSING IS NOT WIPING.

        Seeds created under bitcoin-only firmware are stamped in a reserved
        band (10000 + the normal version). Multi-chain firmware must not load
        one -- the seed was never meant to be multi-chain-exposed -- but it
        must also leave it alone: SUS_BitcoinOnlyLocked resets only the RAM
        shadow, and storage_commit() returns early while btc_only_locked, so
        flash is never touched. Reflashing bitcoin-only firmware recovers the
        wallet; leaving requires an explicit wipe.

        Three assertions, in order of what they cost you if they fail: the
        device is locked, the sector is byte-for-byte what it was, and the
        wallet comes back once the stamp is the multi-chain one again.
        """
        addr, off = self._create_wallet()
        self.assertLess(
            self.emu.read_u32(off, OFF_VERSION), STORAGE_VERSION_BTC_ONLY_BASE,
            "this emulator already stamps its wallets into the bitcoin-only "
            "band, so it is not the multi-chain firmware this test is about")
        before = self.emu.sector(off)
        self.emu.write_u32(
            off, OFF_VERSION,
            STORAGE_VERSION_BTC_ONLY_BASE + self.emu.read_u32(off, OFF_VERSION))

        self.emu.boot()
        c = self.emu.client(self.method)
        try:
            c.init_device()
            _capture(c)
            self.assertFalse(
                c.features.initialized,
                "multi-chain firmware loaded a wallet stamped in the "
                "bitcoin-only band")
        finally:
            c.close()
        self.emu.halt()

        after = self.emu.sector(off)
        self.assertEqual(
            before[:OFF_VERSION] + before[OFF_VERSION + 4:],
            after[:OFF_VERSION] + after[OFF_VERSION + 4:],
            "the locked boot MODIFIED the bitcoin-only record. The wallet is "
            "supposed to stay recoverable by reflashing bitcoin-only firmware")

        self.emu.write_u32(off, OFF_VERSION,
                           self.emu.read_u32(off, OFF_VERSION)
                           - STORAGE_VERSION_BTC_ONLY_BASE)
        self.emu.boot()
        c = self.emu.client(self.method, pin=PIN)
        try:
            c.init_device()
            self.assertTrue(c.features.initialized)
            self.assertEqual(
                addr, c.get_address("Bitcoin", BIP44_ADDRESS_N,
                                    show_display=True),
                "the refused wallet did not come back intact, so 'refuse "
                "rather than wipe' did not actually preserve anything")
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
