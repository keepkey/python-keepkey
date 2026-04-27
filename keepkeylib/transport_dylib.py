"""DylibTransport — talk to libkkemu.dylib (or libkkemu.so) over FFI ringbuffers.

This is the same firmware the standalone ``kkemu`` UDP binary runs, but loaded
in-process. Two transports cover the two ringbuffer pairs the dylib exposes:

* iface 0 (main):  rb_main_in  / rb_main_out   — host ↔ firmware protocol
* iface 1 (debug): rb_debug_in / rb_debug_out  — DebugLink

The vault uses this same FFI surface from Bun. Adding a Python transport that
mirrors it lets ``python-keepkey`` exercise the firmware contract that the
dylib path imposes — most importantly, the *caller-driven polling* model:
nothing happens inside the firmware until the host calls ``kkemu_poll``. UDP
hides this behind a thread inside ``kkemu``; the dylib does not.

Usage
-----
::

    from keepkeylib.transport_dylib import DylibState, DylibTransport

    state = DylibState.get_or_init('/path/to/libkkemu.dylib')
    main_transport = DylibTransport(state, iface=0)
    debug_transport = DylibTransport(state, iface=1)
    client = KeepKeyDebugClient(main_transport)
    client.set_debuglink(DebugLink(debug_transport))

A *single* ``DylibState`` is shared between the two transports — the dylib's
``kkemu_init`` may only be called once per process. Re-initialising means
restarting the test process (or factory-resetting via ``reset_flash``).
"""

from __future__ import print_function

import ctypes
import os
import struct
import threading
import time

from .transport import Transport, ConnectionError


# ── Dylib singleton ─────────────────────────────────────────────────────────


PACKET_SIZE = 64
FLASH_SIZE = 1 << 20  # 1 MB

# Max time we'll spin in kkemu_poll() looking for a frame on this iface.
# Has to cover firmware-internal busy-loops (confirm_helper polls usbPoll
# in a tight C loop — we just need the next outbound frame to land).
_POLL_TIMEOUT_S = 30.0
_POLL_QUANTUM_S = 0.001  # 1 ms — keep latency low without burning CPU


class DylibState(object):
    """Process-wide ``libkkemu.dylib`` handle.

    Holds the ctypes binding and the (locked) flash buffer. Only one instance
    is allowed per process because ``kkemu_init`` is single-shot. Use
    :func:`get_or_init` rather than the constructor.
    """

    _instance = None
    _lock = threading.Lock()

    def __init__(self, dylib_path):
        if not os.path.exists(dylib_path):
            raise ConnectionError("dylib not found: %s" % dylib_path)

        self.lib = ctypes.CDLL(dylib_path)

        self.lib.kkemu_init.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self.lib.kkemu_init.restype = ctypes.c_int

        self.lib.kkemu_shutdown.argtypes = []
        self.lib.kkemu_shutdown.restype = None

        self.lib.kkemu_poll.argtypes = []
        self.lib.kkemu_poll.restype = ctypes.c_int

        self.lib.kkemu_is_running.argtypes = []
        self.lib.kkemu_is_running.restype = ctypes.c_int

        self.lib.kkemu_write.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        self.lib.kkemu_write.restype = ctypes.c_int

        self.lib.kkemu_read.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        self.lib.kkemu_read.restype = ctypes.c_int

        self.lib.kkemu_get_display.argtypes = [
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int),
        ]
        self.lib.kkemu_get_display.restype = ctypes.c_void_p

        # Allocate flash as 0xFF (erased NOR state). Held by the singleton so
        # GC doesn't free it underneath the firmware's still-live mlock.
        self.flash = (ctypes.c_uint8 * FLASH_SIZE)(*([0xFF] * FLASH_SIZE))

        rc = self.lib.kkemu_init(ctypes.cast(self.flash, ctypes.c_void_p), FLASH_SIZE)
        if rc != 0:
            raise ConnectionError("kkemu_init failed: %d" % rc)

        # Single mutex around every FFI call. The dylib's internals aren't
        # thread-safe; main + debug transport may both poll/read concurrently.
        self.io_lock = threading.Lock()

        # Pump a few ticks so the firmware finishes its boot sequence (loads
        # storage, draws home screen) before the first test touches it.
        with self.io_lock:
            for _ in range(8):
                self.lib.kkemu_poll()

    @classmethod
    def get_or_init(cls, dylib_path):
        """Return the per-process singleton, creating it on first call.

        Subsequent calls ignore ``dylib_path`` — the dylib is single-shot and
        re-loading risks UB (mlock'd flash buffer would dangle).
        """
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(dylib_path)
            return cls._instance

    def shutdown(self):
        """Tear down the firmware. Used by tests; not safe to re-init after."""
        with self.io_lock:
            self.lib.kkemu_shutdown()


# ── Transport ───────────────────────────────────────────────────────────────


class DylibTransport(Transport):
    """One transport per (DylibState, iface) pair.

    ``iface=0`` is the main protocol channel, ``iface=1`` is DebugLink.
    """

    def __init__(self, state, iface=0, *args, **kwargs):
        if not isinstance(state, DylibState):
            raise TypeError("state must be a DylibState")
        if iface not in (0, 1):
            raise ValueError("iface must be 0 (main) or 1 (debug)")

        self.state = state
        self.iface = iface
        self.read_buffer = b""

        # Transport.__init__ calls self._open(); device arg is just metadata.
        super(DylibTransport, self).__init__("dylib:iface=%d" % iface, *args, **kwargs)

    # ── Transport hooks ─────────────────────────────────────────────────

    def _open(self):
        # Nothing to do — the dylib was opened when DylibState was created.
        pass

    def _close(self):
        # Don't shut the dylib down on close; the singleton outlives us.
        self.read_buffer = b""

    def ready_to_read(self):
        # Drive the firmware once so any pending outbound frame surfaces in
        # the ring. When a frame arrives, stash through the SAME path
        # _pump_one uses (strip the leading '?' HID marker before
        # appending). Mixing stripped + unstripped frames in one buffer
        # corrupts multi-frame reassembly: _read_headers would see a stray
        # '?' from one chunk in the middle of contiguous payload bytes
        # from another, and decode the wrong message-type / length.
        self._poll_and_stash()
        return bool(self.read_buffer)

    # ── Wire protocol ───────────────────────────────────────────────────

    def _write(self, msg, protobuf_msg):
        """Chunk ``msg`` into 64-byte HID frames and shove them at the firmware.

        ``msg`` already starts with ``"##"`` + msg-type + length (see
        ``Transport.write``). The first chunk needs a leading ``"?"`` marker;
        continuation chunks just get their leading ``"?"`` to round out
        the 64-byte HID report.
        """
        # 63 bytes per chunk + leading '?' = 64 bytes per HID frame
        for chunk in [msg[i : i + 63] for i in range(0, len(msg), 63)]:
            chunk = chunk + b"\0" * (63 - len(chunk))
            frame = b"?" + chunk
            assert len(frame) == PACKET_SIZE
            with self.state.io_lock:
                rc = self.state.lib.kkemu_write(frame, PACKET_SIZE, self.iface)
                if rc != 0:
                    raise ConnectionError(
                        "kkemu_write failed (iface=%d, rc=%d)" % (self.iface, rc)
                    )
                # Pump immediately so the firmware can start consuming this
                # chunk before the next one arrives. Required because the
                # caller (not a daemon) is the only thing driving the FSM.
                self.state.lib.kkemu_poll()

    def _read(self):
        """Read one full message — header parse drives chunk reassembly."""
        try:
            (msg_type, datalen) = self._read_headers(_FrameStream(self))
            payload = self._read_bytes(datalen)
            return (msg_type, payload)
        except Exception as exc:
            print("DylibTransport._read failed: %s" % exc)
            raise

    # ── Internals ───────────────────────────────────────────────────────

    def _read_bytes(self, length):
        """Block until ``length`` payload bytes have been gathered."""
        deadline = time.time() + _POLL_TIMEOUT_S
        while len(self.read_buffer) < length:
            if time.time() > deadline:
                raise ConnectionError(
                    "Timed out reading %d bytes from iface %d" % (length, self.iface)
                )
            self._pump_one()
        out = self.read_buffer[:length]
        self.read_buffer = self.read_buffer[length:]
        return out

    def _pump_one(self):
        """Run one poll/read cycle and back off briefly if no frame arrived.

        Used inside the _read_bytes deadline loop. Sleeps so we don't spin
        a hot CPU loop while waiting on the firmware.
        """
        if not self._poll_and_stash():
            time.sleep(_POLL_QUANTUM_S)

    def _poll_and_stash(self):
        """Single poll + read; append any frame to read_buffer with '?'
        marker stripped. Returns True if a frame was consumed.

        Shared by ``ready_to_read`` (no sleep) and ``_pump_one``
        (sleeps on miss). Centralises the strip-the-leading-'?' rule so
        the buffer always contains continuation+payload bytes only.
        """
        with self.state.io_lock:
            self.state.lib.kkemu_poll()
            buf = (ctypes.c_uint8 * PACKET_SIZE)()
            n = self.state.lib.kkemu_read(buf, PACKET_SIZE, self.iface)
            if n > 0:
                # Drop the leading '?' marker; rest is payload (and HID
                # padding zeros at the tail of the last frame of a short
                # message — _read_headers' magic-character search skips
                # those harmlessly on the next message).
                self.read_buffer += bytes(buf[1:n])
                return True
        return False


class _FrameStream(object):
    """File-like adapter so Transport._read_headers can drive _pump_one."""

    def __init__(self, transport):
        self.transport = transport

    def read(self, n):
        return self.transport._read_bytes(n)
