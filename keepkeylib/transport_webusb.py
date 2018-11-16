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

   # PATH_PREFIX = "webusb"
   # context = None

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
            print("Device: ", dev)
            print("Type: ", type(dev))
            usb_id = (dev.getVendorID(), dev.getProductID())
            if usb_id != (0x2B24, 0x0001):
                print("Skipping cause usb_id")
                continue
            # if not is_vendor_class(dev):
                # continue
            try:
                # workaround for issue #223:
                # on certain combinations of Windows USB drivers and libusb versions,
                # Trezor is returned twice (possibly because Windows know it as both
                # a HID and a WebUSB device), and one of the returned devices is
                # non-functional.
                dev.getProduct()
                # devices.append(WebUsbTransport(dev))
                devices.append(dev)
            except usb1.USBErrorNotSupported:
                pass
        print("Num Devices", len(devices))
        return devices

    def _write(self, msg, protobuf_msg):
        print("Writing")

        msg = bytearray(msg)
        while len(msg):
            # add reportID and padd with zeroes if necessary
            self.handle.interruptWrite(self.endpoint, [63, ] + list(msg[:63]) + [0] * (63 - len(msg[:63])))
            msg = msg[63:]

    def _read(self):
        (msg_type, datalen) = self._read_headers(FakeRead(self._raw_read))
        return (msg_type, self._raw_read(datalen))

    def _raw_read(self, length):
        print("Read Raw: ", length)
        start = time.time()
        endpoint = 0x80 | self.endpoint
        print("endpoint:", endpoint)
        print("handle:", self.handle)
        while len(self.buffer) < length:
            print("len buffer:", len(self.buffer))
            print("length", length)
            print("interruptRead")
            while True:
                data = self.handle.interruptRead(endpoint, 64)
                print("Data: ", data)
                if data:
                    break
                else:
                    time.sleep(0.001)

            if len(data) != 64:
                raise TransportException("Unexpected chunk size: %d" % len(chunk))

            print("lendata-1", len(data[1:]))
            print("prelenbuffer", len(self.buffer))
            self.buffer += data[1:]
            print("postlenBuffer", len(self.buffer))

        ret = self.buffer[:length]
        self.buffer = self.buffer[length:]
        return bytes(ret)

