import importlib
import logging
import sys
import time

from .transport import Transport, ConnectionError

import usb1


class FakeRead(object):
    # Let's pretend we have a file-like interface
    def __init__(self, func):
        self.func = func

    def read(self, size):
        return self.func(size)


class WebUsbTransport(Transport):
    """
    WebUsbTransport implements transport over WebUSB interface.
    """

    def __init__(self, device, *args, **kwargs):
        self.buffer = ''

        # TODO: Select between normal/debug interface
        self.interface = 0
        self.endpoint = 1
        self.device = device

        super(WebUsbTransport, self).__init__(device, *args, **kwargs)

    def _open(self):
        self.handle = self.device.open()
        # if self.handle is None:
        if sys.platform.startswith("linux"):
            args = (UDEV_RULES_STR,)
        else:
            args = ()
        # raise IOError("Cannot open device", *args)
        self.handle.claimInterface(self.interface)

    @classmethod
    def enumerate(cls):
        cls.context = usb1.USBContext()
        cls.context.open()
          #  atexit.register(cls.context.close)
        devices = []
        for dev in cls.context.getDeviceIterator(skip_on_error=True):

            usb_id = (dev.getVendorID(), dev.getProductID())
            # TODO: not magic constant
            if usb_id != (0x2B24, 0x0001):
                continue
            try:
                # workaround for issue #223:
                # on certain combinations of Windows USB drivers and libusb versions,
                # Trezor is returned twice (possibly because Windows know it as both
                # a HID and a WebUSB device), and one of the returned devices is
                # non-functional.
                dev.getProduct()
                devices.append(dev)
            except usb1.USBErrorNotSupported:
                pass
        return devices

    def _write(self, msg, protobuf_msg):

        msg = bytearray(msg)
        while len(msg):
            # add reportID and padd with zeroes if necessary
            self.handle.interruptWrite(self.endpoint, [63, ] + list(msg[:63]) + [0] * (63 - len(msg[:63])))
            msg = msg[63:]

    def _read(self):
        (msg_type, datalen) = self._read_headers(FakeRead(self._raw_read))
        return (msg_type, self._raw_read(datalen))

    def _raw_read(self, length):
        start = time.time()
        endpoint = 0x80 | self.endpoint
        while len(self.buffer) < length:
            while True:
                data = self.handle.interruptRead(endpoint, 64)
                if data:
                    break
                else:
                    time.sleep(0.001)

            if len(data) != 64:
                raise TransportException("Unexpected chunk size: %d" % len(chunk))

            self.buffer += data[1:]

        ret = self.buffer[:length]
        self.buffer = self.buffer[length:]
        return bytes(ret)

