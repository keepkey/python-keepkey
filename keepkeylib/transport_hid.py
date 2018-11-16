'''USB HID implementation of Transport.'''
import math
from hashlib import sha256
import time, json, base64, struct
from .transport import Transport, ConnectionError
import binascii
from u2flib_host import hid_transport as u2fhid_transport

import platform
import hid

u2fhid_transport.DEVICES.append((0x2b24, 0x0001)) #KeepKey



DEVICE_IDS = [
    (0x2B24, 0x0001),  # KeepKey
]


MAX_MSG_SIZE = 59

INTERFACE_MAPPING = {
    "normal_usb": 0,
    "debug_link": 1,
    "normal_u2f": 2,
    "debug_u2f" : 3,
    }

class FakeRead(object):
    # Let's pretend we have a file-like interface
    def __init__(self, func):
        self.func = func

    def read(self, size):
        return self.func(size)

class HidTransport(Transport):
    def __init__(self, device_paths, *args, **kwargs):
        self.hid = None
        self.buffer = ''
        #select the appropriate transport
        self.use_u2f = kwargs.get("use_u2f", False)
        self.use_debug_link = kwargs.get("debug_link", False)
        self.interface_index = 0 if not self.use_u2f else 2
        if self.use_debug_link and not self.use_u2f: self.interface_index += 1
        #stale device paths are a problem here unless we re-enumerate
        device_paths = self.enumerate()[0]
        self.path = device_paths[self.interface_index]
        super(HidTransport, self).__init__(self.path, *args, **kwargs)

    @classmethod
    def enumerate(cls):
        """
        Return a list of available TREZOR devices.
        """
        devices = {}
        for d in hid.enumerate(0, 0):
            vendor_id = d['vendor_id']
            product_id = d['product_id']
            serial_number = d['serial_number']
            interface_number = d['interface_number']
            path = d['path']

            # HIDAPI on Mac cannot detect correct HID interfaces, so device with
            # DebugLink doesn't work on Mac...
            if devices.get(serial_number) != None and devices[serial_number][0] == path:
                raise Exception("Two devices with the same path and S/N found. This is Mac, right? :-/")

            if (vendor_id, product_id) in DEVICE_IDS:
                devices.setdefault(serial_number, [None, None, None])
                if interface_number == 0 or (interface_number == -1 and path.endswith(b'0')): # normal link
                    devices[serial_number][0] = path
                elif interface_number == 1 or (interface_number == -1 and path.endswith(b'1')): # debug link
                    devices[serial_number][1] = path
                elif interface_number == 2 or (interface_number == -1 and path.endswith(b'2')): # u2f link
                    devices[serial_number][2] = path
                else:
                    raise Exception("Unknown USB interface number: %d" % interface_number)

        # List of two-tuples (path_normal, path_debuglink)
        return list(devices.values())

    def is_connected(self):
        """
        Check if the device is still connected.
        """
        for d in hid.enumerate(0, 0):
            if d['path'] == self.device:
                return True
        return False

    def _open(self):
        self.apdus = []
        self.buffer = bytearray()
        if self.use_u2f:
            self.hid = u2fhid_transport.HIDDevice(self.path)
            self.hid.open()
        else:
            self.hid = hid.device()
            self.hid.open_path(self.device)
            self.hid.set_nonblocking(True)
        # the following was needed just for TREZOR Shield
        # self.hid.send_feature_report([0x41, 0x01]) # enable UART
        # self.hid.send_feature_report([0x43, 0x03]) # purge TX/RX FIFOs

    def _close(self):
        self.hid.close()
        self.buffer = bytearray()
        self.hid = None
        self.apdu = None

    def ready_to_read(self):
        return False

    def _msg_to_apdus(self, msg):
        #generate app/client data
        app_id  = 'https://www.keepkey.com'
        window_location = 'navigator.id.getAssertion'
        challenge = 'KPKYKPKYKPKYKPKYKPKYKPKYKPKYKPKY'
        client_data = '{{"typ": "{}", "challenge": "{}", "origin": "{}"}}'.format(window_location, challenge, app_id)
        app_param = sha256(app_id.encode('utf8')).digest()
        client_param = sha256(client_data.encode('utf8')).digest()
        total_frames = math.ceil(len(msg)/float(MAX_MSG_SIZE))
        frame_i = 0
        chunks = []
        while len(msg):
            flags = 0
            flags = flags | (0x40 if self.use_debug_link else 0)
            chunks.append(struct.pack("<BBBBB", int(total_frames), int(frame_i), 0, flags, 63) +
                          msg[:MAX_MSG_SIZE] + b"\x00" * (MAX_MSG_SIZE - len(msg[:MAX_MSG_SIZE])))
            frame_i += 1
            msg = msg[MAX_MSG_SIZE:]
        apdus = []
        for this_wire_msg in chunks:
            key_handle = this_wire_msg
            auth_request = client_param + app_param + struct.pack("B", len(key_handle)) + key_handle
            hex_request = binascii.hexlify(auth_request)
            apdus.append(str(auth_request))
        self.apdus = apdus

    def _empty_response(self, resp=None):
        if len(self.apdus):
            this_apdu = self.apdus.pop(0)
            resp = self.hid.send_apdu(0x02, 0x03, 0, this_apdu)
            self._empty_response(resp)
        else:
            self.resp = resp

    def _write(self, msg, protobuf_msg):
        if self.use_u2f:
            self._write_u2f(msg, protobuf_msg)
        else:
            self._write_usb(msg, protobuf_msg)

    def _write_usb(self, msg, protobuf_msg):
        msg = bytearray(msg)
        while len(msg):
            # Report ID, data padded to 63 bytes
            self.hid.write([63, ] + list(msg[:63]) + [0] * (63 - len(msg[:63])))
            msg = msg[63:]

    def _write_u2f(self, msg, protobuf_msg):
        msg = bytearray(msg)
        self._msg_to_apdus(msg)
        self._empty_response()

    def _read(self):
        if self.use_u2f:
            _id, _len = struct.unpack('>HL', self.resp[3:9])
            is_debuglink = self.resp[-1]
            return (_id, self.resp[9:-1])
        (msg_type, datalen) = self._read_headers(FakeRead(self._raw_read))
        return (msg_type, self._raw_read(datalen))

    def _raw_read(self, length):
        start = time.time()
        while len(self.buffer) < length:
            data = self.hid.read(64)
            if not len(data):
                time.sleep(0.001)
                continue

            report_id = data[0]

            if report_id > 63:
                # Command report
                raise Exception("Not implemented")

            # Payload received, skip the report ID
            self.buffer.extend(bytearray(data[1:]))

        ret = self.buffer[:length]
        self.buffer = self.buffer[length:]
        return bytes(ret)
