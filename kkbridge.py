#!/usr/bin/env python
from __future__ import print_function

from os import close, error
from flask import Flask, Response, request, jsonify
from flask_cors import CORS, cross_origin

import sys
sys.path = ['../',] + sys.path

from keepkeylib import client
from keepkeylib.client import KeepKeyClient
from keepkeylib.transport_webusb import WebUsbTransport
from keepkeylib import messages_pb2 as messages

import json
import binascii


PACKET_SIZE = 64

kkClient = None

def create_app():
    app = Flask(__name__)
    CORS(app)
    app.config['CORS_HEADERS'] = 'Content-Type'

    def initDevice():
        global kkClient
        if (kkClient != None):
            kkClient.close()
            kkClient = None

        # List all connected KeepKeys on USB
        devices = WebUsbTransport.enumerate()

        # Check whether we found any
        if len(devices) == 0:
            return None

        # Use first connected device
        transport = WebUsbTransport(devices[0])

        # Creates object for manipulating KeepKey
        client = KeepKeyClient(transport)

        return client

    @app.route('/init')
    def initKK():
        global kkClient

        kkClient = initDevice()

        if (kkClient == None):
            data = "No KeepKey found"
            return Response(str(data), status=400, mimetype='application/json')
        else:
            data = kkClient.features
            return Response(str(data), status=200, mimetype='application/json')

    @app.route('/ping')
    def pingKK():
        global kkClient

        if (kkClient == None):
            kkClient = initDevice()
        else:
            pass

        if (kkClient == None):
            data = "No KeepKey found"
            return Response(str(data), status=404, mimetype='application/json')

        try:
            ping = kkClient.call(messages.Ping(message='Duck, a bridge!', button_protection = True))
        except:
            kkClient.close()
            kkClient = None
            data = "No KeepKey found"
            return Response(str(data), status=404, mimetype='application/json')

        return Response(str(ping), status=200, mimetype='application/json')

    @app.route('/exchange/<string:kind>', methods=['GET', 'POST'])
    @cross_origin()
    def rest_api(kind):
        global kkClient

        if (kkClient == None):
            kkClient = initDevice()
        else:
            pass

        if (kkClient == None):
            data = "No KeepKey found"
            return Response(str(data), status=404, mimetype='application/json')

        if request.method == 'POST':
            content = request.get_json(silent=True)
            msg = bytearray.fromhex(content["data"])
            try:
                kkClient.call_bridge(msg)
            except:
                kkClient.close()
                kkClient = None
                kkClient = initDevice()
                return Response('{}', status=404, mimetype='application/json')
            return Response('{}', status=200, mimetype='application/json')

        if request.method == 'GET':
            data = kkClient.call_bridge_read()
            body = '{"data":"' + binascii.hexlify(data).decode("utf-8") + '"}'
            return Response(body, status=200, mimetype='application/json')

        return Response('{}', status=404, mimetype='application/json')
        
    return app

if __name__ == '__main__':

    app = create_app()
    app.run(port='1646')
    #app.run()




