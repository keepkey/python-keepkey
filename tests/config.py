# This file is part of the TREZOR project.
#
# Copyright (C) 2012-2016 Marek Palatinus <slush@satoshilabs.com>
# Copyright (C) 2012-2016 Pavol Rusnak <stick@satoshilabs.com>
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.
#
# The script has been modified for KeepKey Device.

from __future__ import print_function

import os

import sys
sys.path = ['../',] + sys.path

from keepkeylib.transport_pipe import PipeTransport
from keepkeylib.transport_socket import SocketTransportClient
from keepkeylib.transport_udp import UDPTransport

# Skip HID/WebUSB autodetect when an explicit transport is requested.
# Otherwise a connected real KeepKey wins over `KK_TRANSPORT=dylib` and the
# dylib regression tests silently route to hardware instead.
_explicit_transport = os.getenv("KK_TRANSPORT")

if _explicit_transport:
    hid_devices = []
    webusb_devices = []
else:
    try:
        from keepkeylib.transport_hid import HidTransport
        hid_devices = HidTransport.enumerate()
    except Exception:
        print("Error loading HID. HID devices not enumerated.")
        hid_devices = []

    try:
        from keepkeylib.transport_webusb import WebUsbTransport
        webusb_devices = WebUsbTransport.enumerate()
    except Exception:
        print("Error loading WebUSB. WebUSB devices not enumerated.")
        webusb_devices = []

# Only count a hid device if it has more than just the U2F interface exposed
onlyU2F = len(hid_devices) > 0 and \
    hid_devices[0][0] == None and hid_devices[0][1] == None and hid_devices[0][2] != None

if len(hid_devices) > 0 and not onlyU2F:
    if hid_devices[0][1] != None:
        print('Using KeepKey over HID')
        TRANSPORT = HidTransport
        TRANSPORT_ARGS = (hid_devices[0],)
        TRANSPORT_KWARGS = {'debug_link': False}
        DEBUG_TRANSPORT = HidTransport
        DEBUG_TRANSPORT_ARGS = (hid_devices[0],)
        DEBUG_TRANSPORT_KWARGS = {'debug_link': True}
    else:
        print('Using Raspberry Pi')
        TRANSPORT = HidTransport
        TRANSPORT_ARGS = (hid_devices[0],)
        TRANSPORT_KWARGS = {'debug_link': False}
        DEBUG_TRANSPORT = SocketTransportClient
        DEBUG_TRANSPORT_ARGS = ('trezor.bo:2000',)
        DEBUG_TRANSPORT_KWARGS = {}

elif len(webusb_devices) > 0:
    print('Using Keepkey over webUSB')
    TRANSPORT = WebUsbTransport
    TRANSPORT_ARGS = (webusb_devices[0],)
    TRANSPORT_KWARGS = {'debug_link': False}
    DEBUG_TRANSPORT = WebUsbTransport
    DEBUG_TRANSPORT_ARGS = (webusb_devices[0],)
    DEBUG_TRANSPORT_KWARGS = {'debug_link': True}
elif os.getenv('KK_TRANSPORT') == 'dylib':
    # In-process FFI transport against libkkemu.dylib (or libkkemu.so).
    # Same firmware as UDP, different transport — exposes caller-driven
    # polling bugs that the UDP daemon hides behind its own poll thread.
    print('Using Emulator (dylib FFI)')
    from keepkeylib.transport_dylib import DylibState, DylibTransport
    _dylib_path = os.getenv('KK_DYLIB')
    if not _dylib_path:
        raise RuntimeError(
            "KK_TRANSPORT=dylib requires KK_DYLIB=/path/to/libkkemu.dylib"
        )
    _dylib_state = DylibState.get_or_init(_dylib_path)
    TRANSPORT = DylibTransport
    TRANSPORT_ARGS = (_dylib_state, 0)
    TRANSPORT_KWARGS = {}
    DEBUG_TRANSPORT = DylibTransport
    DEBUG_TRANSPORT_ARGS = (_dylib_state, 1)
    DEBUG_TRANSPORT_KWARGS = {}

else:
    print('Using Emulator')
    TRANSPORT = UDPTransport
    TRANSPORT_ARGS = (os.getenv('KK_TRANSPORT_MAIN', '127.0.0.1:11044'),)
    TRANSPORT_KWARGS = {}
    DEBUG_TRANSPORT = UDPTransport
    DEBUG_TRANSPORT_ARGS = (os.getenv('KK_TRANSPORT_DEBUG', '127.0.0.1:11045'),)
    DEBUG_TRANSPORT_KWARGS = {}

def enumerate_hid():
    global TRANSPORT, TRANSPORT_ARGS, TRANSPORT_KWARGS, DEBUG_TRANSPORT, DEBUG_TRANSPORT_ARGS, DEBUG_TRANSPORT_KWARGS

    try:
        devices = HidTransport.enumerate()
    except Exception:
        print("Error loading HID. HID devices not enumerated.")
        devices = []

    if len(devices) > 0:
        if devices[0][1] != None:
            TRANSPORT = HidTransport
            TRANSPORT_ARGS = (devices[0],)
            TRANSPORT_KWARGS = {'debug_link': False}
            DEBUG_TRANSPORT = HidTransport
            DEBUG_TRANSPORT_ARGS = (devices[0],)
            DEBUG_TRANSPORT_KWARGS = {'debug_link': True}
