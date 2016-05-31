from __future__ import print_function

import sys
sys.path = ['../',] + sys.path

from keepkeylib.transport_pipe import PipeTransport
from keepkeylib.transport_hid import HidTransport
from keepkeylib.transport_socket import SocketTransportClient
from keepkeylib.transport_bridge import BridgeTransport

devices = HidTransport.enumerate()

if len(devices) > 0:
    if devices[0][1] != None:
        print('Using TREZOR')
        TRANSPORT = HidTransport
        TRANSPORT_ARGS = (devices[0],)
        TRANSPORT_KWARGS = {'debug_link': False}
        DEBUG_TRANSPORT = HidTransport
        DEBUG_TRANSPORT_ARGS = (devices[0],)
        DEBUG_TRANSPORT_KWARGS = {'debug_link': True}
    else:
        print('Using Raspberry Pi')
        TRANSPORT = HidTransport
        TRANSPORT_ARGS = (devices[0],)
        TRANSPORT_KWARGS = {'debug_link': False}
        DEBUG_TRANSPORT = SocketTransportClient
        DEBUG_TRANSPORT_ARGS = ('trezor.bo:2000',)
        DEBUG_TRANSPORT_KWARGS = {}
else:
    print('Using Emulator')
    TRANSPORT = PipeTransport
    TRANSPORT_ARGS = ('/tmp/pipe.trezor', False)
    TRANSPORT_KWARGS = {}
    DEBUG_TRANSPORT = PipeTransport
    DEBUG_TRANSPORT_ARGS = ('/tmp/pipe.trezor_debug', False)
    DEBUG_TRANSPORT_KWARGS = {}

def enumerate_hid():
    global TRANSPORT, TRANSPORT_ARGS, TRANSPORT_KWARGS, DEBUG_TRANSPORT, DEBUG_TRANSPORT_ARGS, DEBUG_TRANSPORT_KWARGS

    devices = HidTransport.enumerate()

    if len(devices) > 0:
        if devices[0][1] != None:
            TRANSPORT = HidTransport
            TRANSPORT_ARGS = (devices[0],)
            TRANSPORT_KWARGS = {'debug_link': False}
            DEBUG_TRANSPORT = HidTransport
            DEBUG_TRANSPORT_ARGS = (devices[0],)
            DEBUG_TRANSPORT_KWARGS = {'debug_link': True}
