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

import sys
sys.path = ['../',] + sys.path

from keepkeylib.transport_pipe import PipeTransport
from keepkeylib.transport_hid import HidTransport
from keepkeylib.transport_socket import SocketTransportClient

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
