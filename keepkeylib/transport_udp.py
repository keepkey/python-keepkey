from __future__ import print_function

'''SocketTransport implements TCP socket interface for Transport.'''

import os
import socket
from select import select
from .transport import Transport

# A dead emulator must surface as an ERROR, not as an infinite wait.
#
# The socket had no timeout, so when the emulator segfaulted mid-suite,
# recv() blocked in a syscall until something outside killed the process --
# in CI that was a 30-minute job timeout reported as "cancelled", which reads
# as an infrastructure blip rather than the device crash it actually was. It
# hid a real segfault for at least six merges.
#
# Generous by default because a confirm screen legitimately waits on a human;
# override for unattended runs with KK_UDP_TIMEOUT (seconds, 0 disables).
DEFAULT_TIMEOUT = float(os.environ.get('KK_UDP_TIMEOUT', '60'))

class EmulatorNotResponding(Exception):
    """The emulator stopped answering.

    Deliberately NOT an IOError/OSError. On Python 3, IOError, OSError and
    socket.error are the same class, so the detailed timeout this transport
    raises was caught by _read()'s own `except socket.error`, printed as
    "Failed to read from device" and turned into None -- the caller never saw
    the actionable message. Raising outside that hierarchy is what lets it
    reach the caller.
    """


class FakeRead(object):
    # Let's pretend we have a file-like interface
    def __init__(self, func):
        self.func = func

    def read(self, size):
        return self.func(size)


class UDPTransport(Transport):
    def __init__(self, device, *args, **kwargs):
        self.buffer = b''
        device = device.split(':')
        if len(device) < 2:
            device = ('0.0.0.0', int(device[0]))
        else:
            device = (device[0], int(device[1]))

        self.socket = None

        super(UDPTransport, self).__init__(device, *args, **kwargs)

    def _open(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect(self.device)
        if DEFAULT_TIMEOUT > 0:
            self.socket.settimeout(DEFAULT_TIMEOUT)

    def _close(self):
        self.socket.close()
        self.socket = None
        self.buffer = ''

    def ready_to_read(self):
        rlist, _, _ = select([self.socket], [], [], 0)
        return len(rlist) > 0

    def _write(self, msg, protobuf_msg):

        for chunk in [msg[i:i+63] for i in range(0, len(msg), 63)]:
            chunk = chunk + b'\0' * (63 - len(chunk))
            self.socket.send(b'?' + chunk)

    def _read(self):
        try:
            (msg_type, datalen) = self._read_headers(FakeRead(self._raw_read))
            return (msg_type, self._raw_read(datalen))
        except EmulatorNotResponding:
            # Actionable and already explained -- let it reach the caller
            # instead of collapsing it to None. Listed first because on
            # Python 3 the handler below would otherwise catch it: IOError,
            # OSError and socket.error are one class.
            raise
        except socket.error:
            print("Failed to read from device")
            return None

    def _raw_read(self, length):
        while len(self.buffer) < length:
            try:
                data = self.socket.recv(64)
            except socket.timeout:
                # Name the cause. "timed out" alone sends people looking at the
                # test; the device is what stopped answering.
                raise EmulatorNotResponding(
                    'No response from the emulator at %s:%d after %gs -- it is '
                    'not running, has crashed, or is wedged on a confirm screen '
                    'nothing acknowledged. Set KK_UDP_TIMEOUT to change or 0 to '
                    'disable.' % (self.device[0], self.device[1],
                                  DEFAULT_TIMEOUT))
            if not data:
                raise EmulatorNotResponding('Emulator closed the connection')
            self.buffer += data[1:]

        ret = self.buffer[:length]
        self.buffer = self.buffer[length:]
        return ret
