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
#
# ---------------------------------------------------------------------------
# Why the source tests name no version number
# ---------------------------------------------------------------------------
#
# They used to. test_active_flash_format_is_v20 asserted STORAGE_VERSION == 20
# and test_burned_versions_are_dispatched_to_the_wipe_path asserted the literal
# string "case StorageVersion_18:", because 7.16 writes V20 and burns 18/19.
# Both are true on the passkeys branch and both are FALSE on the 7.15 line,
# where STORAGE_VERSION is 17 and nothing is burned. python-keepkey is one
# submodule shared by every firmware branch, and CI now builds the emulator
# from whichever branch is under test, so a test pinned to one branch's version
# reports a failure whose only cause is which branch you are on.
#
# A test that reads a source file has to assert properties of what it read.
# What follows is derived, per tree:
#
#   STORAGE_VERSION, STORAGE_VERSION_LAST_SHIPPED,   include/.../storage.h
#   STORAGE_VERSION_BTC_ONLY_BASE
#   the version ladder                               lib/firmware/storage_versions.inc
#   which versions are BURNED                        lib/firmware/storage_versions.inc
#   which versions have a reader / hit the wipe path lib/firmware/storage.c
#
# The only version number still written down is
# STORAGE_VERSION_LAST_SHIPPED_FLOOR, and it is a FLOOR, not an equality -- see
# its comment for why that distinction is the whole argument. (The V16 numbers
# in the emulator section are a different thing: they describe the format 7.14.x
# shipped, which is finished history and cannot change. The flash offsets are
# unchanged by the V20 bump -- V20 keeps V17's layout and puts passkey state in
# its reserved area at +501 -- so the migration test reads the same way on both
# lines.)
#
# Decoupling is not the same as weakening. The property docs/StorageVersionGate
# .md exists to protect -- "a bump is a deliberate release act, never an
# accident" -- is enforced harder than before, because it no longer rests on
# somebody also editing a constant in this file. A bare `#define
# STORAGE_VERSION 18` now has to survive:
#
#   * the ladder must be contiguous 1..N and END at STORAGE_VERSION, so the
#     bump forces an append to storage_versions.inc;
#   * every ladder version must be dispatched in storage_fromFlash, so the bump
#     forces a case label;
#   * the version this firmware WRITES must have a reader, so the bump forces a
#     reader behind that label.
#
# Three files have to move together, and every one of them is a file that has
# to move anyway for the firmware to be correct. The old constant was the only
# artifact in the set that did not.

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

# include/keepkey/firmware/storage.h. Cross-checked against the header by
# test_version_never_drops_below_a_shipped_release -- the emulator tests below
# stamp wallets into this band by hand, so a drift between the two would make
# them exercise a band the firmware does not use.
STORAGE_VERSION_BTC_ONLY_BASE = 10000

# The lowest value STORAGE_VERSION_LAST_SHIPPED may ever hold. 7.15 shipped
# storage V17; that is a fact about the past and cannot become false, so this
# is a RATCHET and not a version pin. Raise it when a later release actually
# ships (the same commit that raises the constant in storage.h); there is no
# branch on which it needs lowering, and lowering it is the edit this exists to
# stop.
#
# The distinction matters. `assertEqual(17, last_shipped)` is wrong the day
# 7.16 ships and wrong on any branch that has already bumped it, so it rots and
# gets "fixed" by whoever the failure inconveniences. `>= 17` is wrong only if
# somebody deletes history. It still catches the edit docs/StorageVersionGate.md
# calls the single highest-severity review item in the file: the static assert
# is STORAGE_VERSION >= STORAGE_VERSION_LAST_SHIPPED, so the way to make a
# LOWERED storage version compile is to lower LAST_SHIPPED to match it, and
# both numbers live in the same header where one commit reaches both. An
# independent witness is the only thing that sees it.
STORAGE_VERSION_LAST_SHIPPED_FLOOR = 17

MNEMONIC_ALL = " ".join(["all"] * 12)
LABEL = "storagegate"
PIN = "1234"
BIP44_ADDRESS_N = [2147483692, 2147483648, 2147483648, 0, 0]  # m/44'/0'/0'/0/0


# ---------------------------------------------------------------------------
# Firmware source access
# ---------------------------------------------------------------------------

def _repo_root():
    """Directory of the firmware checkout this python-keepkey lives under.

    KK_FIRMWARE_ROOT wins, so the gate can be pointed at a tree this clone is
    not nested inside. That is not a convenience: these tests now derive every
    version number from the tree, and the only way to show they hold on BOTH
    release lines is to run one checkout of them against two firmware trees.
    Unset -- which is how CI runs, from deps/python-keepkey -- the walk up is
    unchanged.
    """
    env = os.environ.get("KK_FIRMWARE_ROOT")
    if env:
        assert os.path.isfile(os.path.join(env, "lib", "firmware", "storage.c")), (
            "KK_FIRMWARE_ROOT=%s has no lib/firmware/storage.c" % env)
        return env
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


def _strip_c_comments(text):
    """Comments are prose and must never be mistaken for code.

    Both files this module parses argue their case in long comments that name
    the very identifiers being searched for -- the burned arm in storage.c says
    "there is deliberately NO reader" a few words from where a reader would be
    written. Classification runs on the stripped text so a rewording can never
    change a verdict.
    """
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


# -- lib/firmware/storage_versions.inc --------------------------------------

_LADDER_ENTRY = re.compile(
    r"STORAGE_VERSION_(?:ENTRY|LAST)\s*\(\s*(\d+)\s*\)")
_LADDER_LAST = re.compile(r"STORAGE_VERSION_LAST\s*\(\s*(\d+)\s*\)")
_ENTRY_LINE = re.compile(r"^\s*STORAGE_VERSION_ENTRY\s*\(\s*(\d+)\s*\)\s*$")
_BURNED_WORD = re.compile(r"\bBURNED\b")


def _ladder(inc):
    """Every version in storage_versions.inc, in file order.

    The x-macro definitions at the top of the file take a parameter named X,
    not a digit, so they do not match.
    """
    return [int(m) for m in _LADDER_ENTRY.findall(_strip_c_comments(inc))]


def _ladder_last(inc):
    """The single STORAGE_VERSION_LAST(N) entry: the version this build writes."""
    last = _LADDER_LAST.findall(_strip_c_comments(inc))
    assert len(last) == 1, (
        "storage_versions.inc must have exactly one STORAGE_VERSION_LAST entry, "
        "found %s" % last)
    return int(last[0])


def _burned_declared(inc):
    """Versions storage_versions.inc annotates as BURNED.

    THE DECLARATION SITE. A burned version is one that a pre-release build
    wrote with a layout that was later abandoned, so devices carrying it exist
    and no reader may ever be written for it -- parsing such a blob as the
    current format is worse than refusing it, because nothing announces the
    misparse. That is a fact about history, not about code, so it cannot be
    inferred from the code: it has to be stated somewhere and read from there.

    The convention is a comment containing the word BURNED, immediately above
    the entries it applies to:

        STORAGE_VERSION_ENTRY(17)
        /* 18 and 19 are BURNED. <why> */
        STORAGE_VERSION_ENTRY(18)
        STORAGE_VERSION_ENTRY(19)
        STORAGE_VERSION_LAST(20)

    The run ends at the first line that is not a bare STORAGE_VERSION_ENTRY --
    a blank line, another comment, or the STORAGE_VERSION_LAST line, which by
    definition is the version being written and so can never be burned.

    Numbers inside the comment text are deliberately NOT scraped: that prose
    mentions the commit that reverted the format and the version it reverted
    TO, and reading V17 out of it would declare a shipped version burned.
    Position is the annotation; the words are for humans.

    An unannotated version that turns out to be dispatched to the wipe path is
    a mismatch, not a silent pass -- see
    test_burned_versions_agree_between_the_ladder_and_the_dispatch.
    """
    burned = set()
    lines = inc.splitlines()
    i = 0
    while i < len(lines):
        if "/*" not in lines[i]:
            i += 1
            continue
        block = []
        while i < len(lines):
            block.append(lines[i])
            if "*/" in lines[i]:
                break
            i += 1
        i += 1
        if not _BURNED_WORD.search("\n".join(block)):
            continue
        while i < len(lines):
            m = _ENTRY_LINE.match(lines[i])
            if not m:
                break
            burned.add(int(m.group(1)))
            i += 1
    return burned


# -- lib/firmware/storage.c --------------------------------------------------

_CASE_LABEL = re.compile(r"case\s+StorageVersion_(\w+)\s*:")
_READER_CALL = re.compile(r"\bstorage_read\w*\s*\(")
_WIPE_RETURN = re.compile(r"return\s+SUS_Invalid\b")


def _from_flash_arms(c):
    """Map every StorageVersion_X label in storage_fromFlash to its arm text.

    Consecutive labels share one arm: `case 2: case 3: ... case 10:` is a
    single body reached by nine versions, and each of them must be credited
    with what that body does. So labels accumulate until one is followed by
    something other than whitespace and comments, and the whole group is
    assigned that text.

    Keys are the label suffixes as written -- "17", "BTC_ONLY", "NONE" -- so
    the non-numeric arms stay visible to the tests that care about them.
    """
    i = c.index("StorageUpdateStatus storage_fromFlash")
    body = c[i:c.index("\n}", i)]
    assert "case StorageVersion_NONE" in body, (
        "storage_fromFlash body was cut short before the end of its switch; "
        "the parse below would under-report every arm")

    labels = list(_CASE_LABEL.finditer(body))
    assert labels, "no case StorageVersion_* labels in storage_fromFlash"

    arms = {}
    group = []
    for idx, m in enumerate(labels):
        group.append(m.group(1))
        end = labels[idx + 1].start() if idx + 1 < len(labels) else len(body)
        own = body[m.end():end]
        if _strip_c_comments(own).strip():
            for name in group:
                arms[name] = own
            group = []
    for name in group:  # labels trailing the last statement: no body at all
        arms[name] = ""
    return arms


def _reads(arm):
    """Does this arm call a storage_readVxx reader?"""
    return bool(_READER_CALL.search(_strip_c_comments(arm)))


def _wipes(arm):
    """Does this arm return SUS_Invalid -- the reset-and-commit path?"""
    return bool(_WIPE_RETURN.search(_strip_c_comments(arm)))


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
    cannot restart an emulator, so the section is never entirely unmeasured.

    Every number these tests compare against is read out of the tree they are
    run in, so one copy of this file states the same invariants on the 7.15
    line (STORAGE_VERSION 17, nothing burned) and on 7.16 (20, with 18 and 19
    burned). See the note at the top of the module for why that is a
    strengthening rather than a relaxation.
    """

    def setUp(self):
        self.h = _read_source("include/keepkey/firmware/storage.h")
        self.c = _read_source("lib/firmware/storage.c")
        self.inc = _read_source("lib/firmware/storage_versions.inc")
        self.version = _define(self.h, "STORAGE_VERSION")
        self.last_shipped = _define(self.h, "STORAGE_VERSION_LAST_SHIPPED")

        self.ladder = _ladder(self.inc)
        self.burned = _burned_declared(self.inc)
        self.arms = _from_flash_arms(self.c)

    # -- helpers ------------------------------------------------------------

    def _arm(self, version):
        arm = self.arms.get(str(version))
        self.assertIsNotNone(
            arm,
            "storage_fromFlash has no `case StorageVersion_%d:` -- see "
            "test_every_ladder_version_is_dispatched" % version)
        return arm

    # -- the ladder ---------------------------------------------------------

    def test_version_ladder_is_contiguous_and_ends_at_storage_version(self):
        """storage_versions.inc may only ever be APPENDED to.

        The enum is emitted in .inc order after StorageVersion_NONE = 0, so a
        contiguous 1..N list is what makes StorageVersion_N == N. Deleting or
        renumbering an entry silently drops a version from version_from_int()
        and wipes every device carrying it.

        Ending AT StorageVersion is the half that makes a bare header bump
        loud: raise STORAGE_VERSION without appending here and the two numbers
        disagree.
        """
        self.assertTrue(self.ladder, "no version entries parsed from the ladder")
        self.assertEqual(list(range(1, len(self.ladder) + 1)), self.ladder,
                         "storage_versions.inc is not contiguous from 1")
        self.assertEqual(
            self.version, _ladder_last(self.inc),
            "STORAGE_VERSION is %d but the ladder ends at %d. A version this "
            "firmware writes and cannot enumerate is not recognised on the next "
            "boot -- it wipes itself." % (self.version, _ladder_last(self.inc)))

    def test_version_never_drops_below_a_shipped_release(self):
        """Lowering STORAGE_VERSION wipes every device upgrading FROM a shipped
        release: its blob's version stops being recognised, so the gate maps it
        to StorageVersion_NONE and storage_init() resets. The version must also
        stay under the bitcoin-only band, or a multi-chain wallet would be
        stamped into the band that multi-chain firmware refuses to load."""
        self.assertGreaterEqual(self.version, self.last_shipped)
        band = _define(self.h, "STORAGE_VERSION_BTC_ONLY_BASE")
        self.assertEqual(
            STORAGE_VERSION_BTC_ONLY_BASE, band,
            "the header moved the bitcoin-only band to %d; the emulator tests "
            "in this file stamp wallets into %d by hand and would be measuring "
            "a band the firmware no longer uses"
            % (band, STORAGE_VERSION_BTC_ONLY_BASE))
        self.assertLess(self.version, band)

    def test_last_shipped_never_moves_backwards(self):
        """STORAGE_VERSION_LAST_SHIPPED is a high-water mark of the FIELD.

        It records the newest format any signed release ever wrote, so it can
        only rise, and only in the commit that ships. The compile-time assert
        in storage.c is STORAGE_VERSION >= STORAGE_VERSION_LAST_SHIPPED, and
        both operands live in the same header -- so the way to make a LOWERED
        storage version build is to lower this to match, which is exactly the
        edit that turns every upgrade in the field into a silent wipe.
        docs/StorageVersionGate.md calls that the highest-severity review item
        in the file.

        A floor asserted from outside the header is the independent witness.
        It is not a version pin: it stays true when 7.16 raises the constant to
        20, and it is only ever raised, never corrected.
        """
        self.assertGreaterEqual(
            self.last_shipped, STORAGE_VERSION_LAST_SHIPPED_FLOOR,
            "STORAGE_VERSION_LAST_SHIPPED is %d, below the %d that 7.15 shipped. "
            "Either a signed release is being un-remembered to make a lowered "
            "STORAGE_VERSION compile, or the ratchet in this file is wrong -- "
            "and only one of those two has ever happened."
            % (self.last_shipped, STORAGE_VERSION_LAST_SHIPPED_FLOOR))

    # -- the dispatch -------------------------------------------------------

    def test_every_ladder_version_is_dispatched(self):
        """Every version in the ladder needs a case in storage_fromFlash().

        This is the failure the static asserts do NOT cover. They pin the enum
        to its own numbering; they say nothing about the switch.

        The switch has no default case, deliberately, so that -Werror=switch
        names any version we forget -- which means on ARM this is also a build
        failure. It is asserted anyway because the emulator and the unit tests
        are built by other toolchains and other flag sets, and because the
        message here says which device gets wiped, where the compiler says
        which enumerator is unhandled.
        """
        missing = [v for v in self.ladder if str(v) not in self.arms]
        self.assertEqual(
            [], missing,
            "storage_fromFlash has no case for version(s) %s -- a device "
            "carrying one is wiped at boot" % missing)

    def test_an_unrecognised_version_reaches_the_wipe_path(self):
        """version_from_int() maps anything off the ladder to
        StorageVersion_NONE, and that arm must return SUS_Invalid.

        This is the mechanism the downgrade half of the policy rests on: a
        device that has run newer firmware carries a stamp older firmware
        cannot read, and it must reset rather than load a blob it will
        misparse. The emulator test test_unrecognised_version_wipes_on_boot
        proves the behaviour end to end; this proves the arm still exists on a
        runner with no emulator.
        """
        arm = self.arms.get("NONE")
        self.assertIsNotNone(arm, "storage_fromFlash has no StorageVersion_NONE case")
        self.assertTrue(
            _wipes(arm),
            "StorageVersion_NONE no longer returns SUS_Invalid. An unknown "
            "storage version would be accepted, and an attacker could roll back "
            "to an older signed image with a known extraction bug and keep the "
            "seed. Arm was:\n%s" % arm)
        self.assertFalse(
            _reads(arm),
            "a reader behind StorageVersion_NONE parses a blob whose format is "
            "by definition unknown. Arm was:\n%s" % arm)

    def test_every_dispatched_version_either_reads_or_refuses(self):
        """An arm reads a blob or it refuses one. Never both, never neither.

        Neither means control reached a case that falls out of the switch --
        storage_fromFlash ends in `return SUS_Invalid`, so the device wipes,
        and nothing in the source says that was meant.

        Both means the classification below cannot say what the arm is for, and
        an arm that reads before refusing has already parsed the blob. If a
        real reader ever needs an error return, this assertion is where that
        design gets argued rather than assumed -- which is the point of the
        gate.
        """
        for version in self.ladder:
            arm = self._arm(version)
            reads, wipes = _reads(arm), _wipes(arm)
            self.assertNotEqual(
                reads, wipes,
                "version %d %s. Arm was:\n%s"
                % (version,
                   "both reads a blob and returns SUS_Invalid" if reads else
                   "neither reads a blob nor returns SUS_Invalid, so it falls "
                   "out of the switch and wipes without saying so",
                   arm))

    def test_every_shipped_version_has_a_reader(self):
        """THE upgrade-never-wipes property, for every device in the field.

        An upgrading device arrives carrying the format written by the release
        it is leaving. STORAGE_VERSION_LAST_SHIPPED is the newest of those, so
        1..LAST_SHIPPED is the set of formats that exist on real hardware, and
        every one of them must be read rather than refused. Lose a reader here
        and every wallet carrying that version is erased at boot with no
        prompt, while the build stays green.

        This is the test that carries the section on a release line with
        nothing burned, and it is the reason a burned version can never be one
        that shipped -- see test_no_shipped_version_is_burned.
        """
        for version in range(1, self.last_shipped + 1):
            arm = self._arm(version)
            self.assertTrue(
                _reads(arm),
                "version %d has SHIPPED (STORAGE_VERSION_LAST_SHIPPED is %d) "
                "but storage_fromFlash does not read it. Every device carrying "
                "it is wiped on upgrade. Arm was:\n%s"
                % (version, self.last_shipped, arm))
            self.assertFalse(
                _wipes(arm),
                "version %d has SHIPPED but its arm returns SUS_Invalid, which "
                "is storage_reset() + storage_commit() at boot. Arm was:\n%s"
                % (version, arm))

    def test_the_version_this_firmware_writes_can_be_read_back(self):
        """A device commits STORAGE_VERSION and reboots into the same firmware.

        If the arm for the version it just wrote does not read, storage_init()
        resets on the very next boot -- the wallet does not survive a power
        cycle of the build that created it. The emulator test
        test_reboot_preserves_the_wallet proves this on a running device; here
        it also makes a header bump carry a reader with it, because there is no
        version so new that the firmware writing it may refuse to read it.
        """
        arm = self._arm(self.version)
        self.assertTrue(
            _reads(arm),
            "STORAGE_VERSION is %d and storage_fromFlash does not read version "
            "%d. This firmware cannot load the blob it writes. Arm was:\n%s"
            % (self.version, self.version, arm))
        self.assertNotIn(
            self.version, self.burned,
            "storage_versions.inc declares version %d BURNED and storage.h "
            "writes it. A burned version is one no reader may exist for."
            % self.version)

    # -- burned versions ----------------------------------------------------

    def test_burned_versions_agree_between_the_ladder_and_the_dispatch(self):
        """Two files, one answer.

        storage_versions.inc DECLARES which versions are burned; storage.c
        DEMONSTRATES it by dispatching them to SUS_Invalid with no reader.
        Neither file can be the only witness:

          * derived from storage.c alone, deleting the reader for a shipped
            version would silently reclassify it as burned and the suite would
            approve of it;
          * declared in the .inc alone, a reader wired in behind a burned label
            would parse a blob written by a build whose layout was abandoned,
            and the declaration would sit there saying otherwise.

        Requiring the two to match catches both, and matching costs an edit in
        two files -- which is what "a deliberate act" means here. On a line
        with no burned versions both sides are empty and this test says so.
        """
        dispatched = set(
            v for v in self.ladder
            if not _reads(self._arm(v)) and _wipes(self._arm(v)))
        self.assertEqual(
            sorted(self.burned), sorted(dispatched),
            "storage_versions.inc declares %s BURNED; storage_fromFlash sends "
            "%s to the wipe path. Whichever is right, the other is a lie about "
            "what happens to a device carrying one of these blobs."
            % (sorted(self.burned) or "nothing", sorted(dispatched) or "nothing"))

    def test_burned_versions_are_dispatched_to_the_wipe_path(self):
        """A burned version must be listed, must refuse, and must have no reader.

        Burned means: a pre-release build wrote this format, devices carrying
        it exist, and the number was then reused for something else -- so the
        blob's bytes mean one thing and the stamp claims another. Refusing it
        wipes, which is the documented behaviour for a format we do not
        recognise and strictly better than misparsing one.

        LISTED, not defaulted. storage_fromFlash has no default case on
        purpose, so an unlisted version fails the -Werror=switch build rather
        than falling anywhere.
        """
        if not self.burned:
            self.skipTest(
                "no version is declared BURNED in storage_versions.inc on this "
                "line -- STORAGE_VERSION is %d and the whole ladder has "
                "readers. Nothing to measure here; the upgrade path is carried "
                "by test_every_shipped_version_has_a_reader." % self.version)
        for version in sorted(self.burned):
            self.assertIn(
                version, self.ladder,
                "version %d is declared BURNED but is not in the ladder. The "
                "entry has to stay: the enum is positional, so removing one "
                "renumbers every version after it." % version)
            arm = self._arm(version)
            self.assertTrue(
                _wipes(arm),
                "burned version %d does not return SUS_Invalid. Arm was:\n%s"
                % (version, arm))
            self.assertFalse(
                _reads(arm),
                "a reader behind burned version %d would parse a blob written "
                "by a build whose layout has nothing to do with the current "
                "format, and would do it silently. Arm was:\n%s" % (version, arm))

    def test_no_shipped_version_is_burned(self):
        """Burning a version that SHIPPED wipes every device carrying it.

        This is what keeps the burned set from being a loophole. Burnedness is
        declared, and a declaration can be written for any number -- so the one
        thing it may never cover is a format that reached real hardware.
        STORAGE_VERSION_LAST_SHIPPED is where the firmware records how far that
        reaches, and STORAGE_VERSION_LAST_SHIPPED_FLOOR keeps that record from
        being quietly walked back.

        A version may only be burned if it lives strictly above the last
        shipped release: written by an alpha, never by anything signed.
        """
        shipped_and_burned = sorted(
            v for v in self.burned if v <= self.last_shipped)
        self.assertEqual(
            [], shipped_and_burned,
            "version(s) %s are declared BURNED but are at or below "
            "STORAGE_VERSION_LAST_SHIPPED (%d), so signed firmware wrote them "
            "and devices in the field carry them. Burning one erases those "
            "wallets at boot."
            % (shipped_and_burned, self.last_shipped))


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
        # The stamp in flash must be the version the header declares. This is
        # not a tautology and it is not a version pin either: the emulator was
        # built from _ROOT, so the two sides are the WRITER and the DECLARATION,
        # and a writer that stamps anything else produces blobs the next boot
        # does not recognise. Reading 17 or 20 out of this file instead would
        # only record which branch the author was standing on.
        declared = _define(_read_source("include/keepkey/firmware/storage.h"),
                           "STORAGE_VERSION")
        self.assertEqual(
            declared, self.emu.read_u32(off, OFF_VERSION),
            "the firmware committed a storage version other than the %d its "
            "header declares" % declared)

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
