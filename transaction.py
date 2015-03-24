#!/usr/bin/python
import os
import binascii
import argparse
import json
import base64

from trezorlib.client import TrezorClient, TrezorClientDebug
from trezorlib.tx_api import TXAPIBitcoin
from trezorlib.protobuf_json import pb2json
import trezorlib.messages_pb2 as proto
import trezorlib.types_pb2 as proto_types

def get_transport(transport_string, path, **kwargs):
    if transport_string == 'usb':
        from trezorlib.transport_hid import HidTransport

        if path == '':
            try:
                path = list_usb()[0][0]
            except IndexError:
                raise Exception("No Trezor found on USB")

        for d in HidTransport.enumerate():
            # Two-tuple of (normal_interface, debug_interface)
            if path in d:
                return HidTransport(d, **kwargs)

        raise Exception("Device not found")
 
    if transport_string == 'serial':
        from trezorlib.transport_serial import SerialTransport
        return SerialTransport(path, **kwargs)

    if transport_string == 'pipe':
        from trezorlib.transport_pipe import PipeTransport
        return PipeTransport(path, is_device=False, **kwargs)
    
    if transport_string == 'socket':
        from trezorlib.transport_socket import SocketTransportClient
        return SocketTransportClient(path, **kwargs)

    if transport_string == 'bridge':
        from trezorlib.transport_bridge import BridgeTransport
        return BridgeTransport(path, **kwargs)
    
    if transport_string == 'fake':
        from trezorlib.transport_fake import FakeTransport
        return FakeTransport(path, **kwargs)
    
    raise NotImplemented("Unknown transport")


def list_usb():
    from trezorlib.transport_hid import HidTransport
    return HidTransport.enumerate()
    
def main():

    transport = get_transport('usb', '')
    client = TrezorClient(transport)

    client.set_tx_api(TXAPIBitcoin())

    inp1 = proto_types.TxInputType(address_n=[0],  # 14LmW5k4ssUrtbAB4255zdqv3b4w1TuX9e
        # amount=390000,
        prev_hash=binascii.unhexlify('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
        prev_index=0,
        )

    out1 = proto_types.TxOutputType(address='1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1',
        amount=390000 - 10000,
        script_type=proto_types.PAYTOADDRESS,
        )

    (signatures, serialized_tx) = client.sign_tx('Bitcoin', [inp1, ], [out1, ])
    
if __name__ == '__main__':
    main()
