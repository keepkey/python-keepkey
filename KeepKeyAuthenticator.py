# This file is part of the TREZOR project.
#
# Copyright (C) 2022 markrypto
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

from PyQt5 import QtWidgets, uic
from PyQt5.QtWidgets import QFileDialog, QMenuBar,QAction,QMessageBox,QPushButton
from PyQt5.QtGui import *
from PyQt5.QtCore import Qt
import sys
import os
from PIL import Image
from pyzbar.pyzbar import decode
import qdarkgraystyle
import qrcode
import time
from urllib.parse import urlparse
from PIL import ImageGrab

import binascii
import urllib
import time
from datetime import datetime

from keepkeylib.client import KeepKeyClient
from keepkeylib.transport_webusb import WebUsbTransport

class Ui(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui, self).__init__()
        uic.loadUi(r'authenticatorUI/main.ui', self)
        self.setFixedSize(500, 600)
        self.button = self.findChild(QtWidgets.QPushButton, 'qrscreencap')
        self.button.clicked.connect(self.QrScreencap) # Remember to pass the definition/method, not the return value!
        self.button2 = self.findChild(QtWidgets.QPushButton, 'otpgen')
        self.button2.clicked.connect(self.OtpGen) # Remember to pass the definition/method, not the return value!
        self.button3 = self.findChild(QtWidgets.QPushButton, 'connect')
        self.button3.clicked.connect(self.ConnectKK) # Remember to pass the definition/method, not the return value!
        self.button4 = self.findChild(QtWidgets.QPushButton, 'test')
        self.button4.clicked.connect(self.Test) # Remember to pass the definition/method, not the return value!
        self.input = self.findChild(QtWidgets.QLineEdit, 'qredit')
        self.exitAct = self.findChild(QtWidgets.QMenu,'menuMenu')
        self.label1 = self.findChild(QtWidgets.QLabel,'image_1')
        self.actionQuit = self.findChild(QtWidgets.QAction,'actionExit')
        self.actionQuit.triggered.connect(app.quit)
        self.show()    

    def QrScreencap(self):
        # grab fullscreen
        self.im = ImageGrab.grab(include_layered_windows=True)
        self.im.save("fullscreen.png")
        exit()

        try:
            #data = decode(Image.open(file_path))
            data = decode(self.im)
            print(data)
            data1 = str(data[0][0]).replace("b'",'').replace("'","")
            type1 = str(data[0][1])
            self.result1 = self.findChild(QtWidgets.QLineEdit, 'raw_text_result')
            print(data1)
            secret = urlparse(data1).query.split('=')[1].split('&')[0]
            domain = urlparse(data1).path.split('/')[1].split(':')[0]
            account = urlparse(data1).path.split('/')[1].split(':')[1]
            print(secret)
            print(domain)
            print(account)
            # os.system("python cmdkk.py auth_init %s:%s:%s" % (secret, domain, account))
            # self.result1.setText(data1)#'raw_type_result'
            # self.result2 = self.findChild(QtWidgets.QLineEdit, 'raw_type_result')
            # self.result2.setText(type1)
        except AttributeError:
            pass

    def OtpGen(self):
        #generate OTP
        print("Generate OTP")
        os.system("python cmdkk.py auth_gen")

    def Test(self):
        #test the keepkey function
        print("test function")
        if (self.client is not None):
            AuthOps.auth_test(self.client)
        else:
            print("KeepKey not connected")

    def ConnectKK(self):
        # look for keepkey connection
        # List all connected KeepKeys on USB
        self.client = None
        devices = WebUsbTransport.enumerate()

        # Check whether we found any
        if len(devices) == 0:
            print('No KeepKey found')
            return

        # Use first connected device
        transport = WebUsbTransport(devices[0])

        # Creates object for manipulating KeepKey
        self.client = KeepKeyClient(transport)

class AuthOps:
    def auth_test(client):
        client.ping(
            msg = b'\x15' + bytes("initializeAuth:" + "python-test:" + "BASE32SECRET2345AB", 'utf8')
        )
 
        interval = 30       # 30 second interval
        #T0 = 1535317397
        T0 = 1536262427
        
        T = int(T0/interval).to_bytes(8, byteorder='big')
        retval = client.ping(
            msg = b'\x16' + bytes("generateOTPFrom:" + "python-test:", 'utf8') + binascii.hexlify(bytearray(T))
        )
        print(retval)
        print("should be 007767")  

# def main():
    
    
#    # List all connected KeepKeys on USB
#     devices = WebUsbTransport.enumerate()

#     # Check whether we found any
#     if len(devices) == 0:
#         print('No KeepKey found')
#         return

#     # Use first connected device
#     transport = WebUsbTransport(devices[0])

#     # Creates object for manipulating KeepKey
#     client = KeepKeyClient(transport)

#     # Initialize authenticator
#     AuthOps.auth_test(client)

# if __name__ == '__main__':
#     main()

app = QtWidgets.QApplication(sys.argv)
app.setStyleSheet(qdarkgraystyle.load_stylesheet())
window = Ui()
app.exec_()
