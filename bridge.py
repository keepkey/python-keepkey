from __future__ import print_function

from os import close
from flask import Flask, Response, request, jsonify
app = Flask(__name__)

import json
import binascii

from keepkeylib.client import KeepKeyClient
from keepkeylib.transport_webusb import WebUsbTransport

PACKET_SIZE = 64

app = Flask(__name__)

def initDevice():
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

def closeDevice(client):
    client.close()
    return


#@app.route('/', methods=['GET', 'POST'])

@app.route('/init')
def initKK():
    client = initDevice()
    if (client == None):
        data = "No KeepKey found"
    else:
        data = client.features
        
    #body = '{"data":"' + binascii.hexlify(data).decode("utf-8") + '"}'

    return Response(str(data), status=200, mimetype='application/json')



@app.route('/')
def rest_api():

    if request.method == 'POST':
        content = request.get_json(silent=True)
        msg = bytearray.fromhex(content["data"])
        #kk.send(msg)
        return Response('{}', status=200, mimetype='application/json')

    if request.method == 'GET':
        #data = kk.recv(PACKET_SIZE)
        data = "test string"
        #body = '{"data":"' + binascii.hexlify(data).decode("utf-8") + '"}'
        body = '{"data":"' + data + '"}'
        return Response(body, status=200, mimetype='application/json')

    return Response('{}', status=404, mimetype='application/json')



@app.after_request
def after(response):
    # todo with response
    print(response.status)
    print(response.headers)
    #print(response.get_data())
    return response

if __name__ == '__main__':
    #app.run(debug=True, host='0.0.0.0')
    app.run(debug=True)
