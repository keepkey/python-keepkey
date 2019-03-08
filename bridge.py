# recieve tcp
# send packet to bridge
# bridge sends packet to emulator

from flask import Flask, request, jsonify
app = Flask(__name__)

import socket
import json
import binascii

# TCP_IP = '127.0.0.1'
# TCP_PORT = 5005
# BUFFER_SIZE = 1024
# MESSAGE = "Hello"



# device = ('0.0.0.0', 21324)
# debug = ('0.0.0.0', 21325)

# msg = bytes([63, 35, 35, 0, 1, 0, 0, 0, 13, 10, 5, 104, 101, 108, 108, 111, 16, 0, 24, 1, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

# s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# s.connect(device)

# s.send(msg)

# try:
    # # (msg_type, datalen) = self._read_headers(FakeRead(self._raw_read))
    # # print (msg_type
    # data = s.recv(64)
    # print("Data", data)
# except Exception as e:
#     print(e)

@app.route('/device', methods=['GET', 'POST'])
def device():

    print(request.method)

    if request.method == 'POST':
        device = ('0.0.0.0', 21324)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(device)

        content = request.get_json(silent=True)
        print(content)

        print(content["data"])
        msg = bytearray.fromhex(content["data"])

        s.send(msg)

        data = s.recv(64)
        return '{"data":"' + binascii.hexlify(data) + '"}'

    return '{"a":"error"}'



    


# s.connect((TCP_IP, TCP_PORT))
# s.send(MESSAGE)
# data = s.recv(BUFFER_SIZE)
# s.close()

