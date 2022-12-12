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
from PyQt5 import QtCore
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
import sys
import semver

from keepkeylib.transport_webusb import WebUsbTransport
from keepkeylib.client import PinException, ProtocolMixin, BaseClient, CallException

from AuthMain import Ui_MainWindow as Ui
from PinUi import Ui_Dialog as PIN_Dialog
from remaccdialog import Ui_RemAccDialog as RemAcc_Dialog

class kkClient:
    def __init__(self):
        self.client = None
        
    def ConnectKK(self):
        from keepkeylib.GUImixin import GuiUIMixin
        class KeepKeyClientAuth(ProtocolMixin, GuiUIMixin, BaseClient):
            pass
    
        # look for keepkey connection
        # List all connected KeepKeys on USB
        self.client = None
        devices = WebUsbTransport.enumerate()

        # Check whether we found any
        if len(devices) == 0:
            error_popup("No KeepKey found",
"Ensure that\n1) KeepKey is plugged in\n2) There are no browser windows connected to KeepKey\nThen restart KeepKeyAuthenticator")
            return

        # Use first connected device
        try:
            transport = WebUsbTransport(devices[0])
        except Exception as E:
            if str(E) == "LIBUSB_ERROR_ACCESS [-3]":
                error_popup("KeepKey already claimed on USB","Make sure all KeepKey apps and websites are closed")
            else:
                error_popup("Unknown connection error","Make sure all KeepKey apps and websites are closed")
            return

        # Creates object for manipulating KeepKey
        self.client = KeepKeyClientAuth(transport)
        self.requires_firmware("7.7.0")
        

    def requires_firmware(self, ver_required):
        ret = self.client.init_device()
        features = self.client.features
        version = "%s.%s.%s" % (features.major_version, features.minor_version, features.patch_version)
        if semver.VersionInfo.parse(version) < semver.VersionInfo.parse(ver_required):
            error_popup("Firmware Upgrade Needed",
"Your KeepKey has v"+version+" Authenticator feature requires v"+ver_required)
            self.client = None
            
    def getClient(self):
        return self.client

def error_popup(errmsg, infotext):
    # set up error/status message box popup
    msg = QMessageBox()
    msg.setWindowTitle("ERROR")
    msg.setIcon(QMessageBox.Critical)
    msg.setDefaultButton(QMessageBox.Ok)
    msg.setText(errmsg)
    msg.setInformativeText(infotext)
    x = msg.exec_()    # show message box

class PIN_Dialog(PIN_Dialog):
    def setupUi(self, Dialog):
        super(PIN_Dialog, self).setupUi(Dialog)
        
        self.pushButton_1.clicked.connect(lambda: self.addPinClick('1'))
        self.pushButton_2.clicked.connect(lambda: self.addPinClick('2'))
        self.pushButton_3.clicked.connect(lambda: self.addPinClick('3'))
        self.pushButton_4.clicked.connect(lambda: self.addPinClick('4'))
        self.pushButton_5.clicked.connect(lambda: self.addPinClick('5'))
        self.pushButton_6.clicked.connect(lambda: self.addPinClick('6'))
        self.pushButton_7.clicked.connect(lambda: self.addPinClick('7'))
        self.pushButton_8.clicked.connect(lambda: self.addPinClick('8'))
        self.pushButton_9.clicked.connect(lambda: self.addPinClick('9'))
        self.pbUnlock.clicked.connect(lambda: self.returnPinAndClose(Dialog))
        self.encodedPin = ''
        
                
    def addPinClick(self, clickPosition):
        self.encodedPin+=clickPosition
        print("encoded pin ", self.encodedPin)
        self.lineEdit.setText(self.encodedPin)
        return
        
    def returnPinAndClose(self, Dialog): 
        print("unlock pressed")
        Dialog.close()
        
    def getEncodedPin(self): 
        # return encoded PIN when unlock button pressed
        return self.encodedPin
    
def pingui_popup():
    # set up PIN dialog        
    PINDialog = QtWidgets.QDialog()
    PIN_ui = PIN_Dialog()
    PIN_ui.setupUi(PINDialog)
    PINDialog.show()
    x = PINDialog.exec_()    # show pin dialog
    pin = PIN_ui.getEncodedPin()
    print(pin)
    return pin

class RemAcc_Dialog(RemAcc_Dialog):
    def __init__(self, client, authOps):
        self.client = client
        self.authOps = authOps
        self.accounts = None
        return

    def setupUi(self, Dialog):
        super(RemAcc_Dialog, self).setupUi(Dialog)
        
        # Remove account button group
        # Add IDs to buttons to make for easy access
        bNum = 1
        bList = self.RemoveAccButtonGroup.buttons()
        for b in bList:
            self.RemoveAccButtonGroup.setId(b, bNum)
            bNum += 1
            
        self.RemoveAccButtonGroup.idClicked.connect(self.RemoveAccount)
        self.RemGetAccounts()
        
    def RemGetAccounts(self):
        self.accounts = self.authOps.auth_accGet(self.client)
        # reset button list
        bList = self.RemoveAccButtonGroup.buttons()
        for b in bList:
            b.setText('')
            
        if len(self.accounts) > 0:
            # this forms monotonic button list of non-empty slots
            self.RemAccButton = list()
            bNum = 1
            for acc in self.accounts:
                if acc[1] == '':
                    continue;
                else:
                    self.RemoveAccButtonGroup.button(bNum).setText(acc[1])
                    self.RemAccButton.append((str(bNum), acc))
                    bNum += 1

    def RemoveAccount(self, id_):
        # First check if this is an active button with an account
        if self.RemoveAccButtonGroup.button(id_).text() == '':
            return

        if (self.client != None):
            for ba in self.RemAccButton:
                if ba[0] == str(id_):         # button clicked is in button-account list
                    dom, acc = ba[1][1].split(':')
                    print(dom+" "+acc)
                    break
            try:
                self.authOps.auth_accRem(self.client, dom, acc)                
                self.RemGetAccounts()

            except PinException as e:
                error_popup("Invalid PIN", "")
            return
        else:
            print("KeepKey not connected")
            
class Ui(Ui):
    def __init__(self):
        self.authOps = AuthClass()

    def setupUi(self, MainWindow):
        super(Ui, self).setupUi(MainWindow)
        
        self.clientOps = kkClient()
        
        self.ConnectKKButton.clicked.connect(self.KKConnect)
        self.AddAccButton.clicked.connect(self.QrScreencap)
        self.RemoveAccButton.clicked.connect(self.removeAcc)
        self.testButton.clicked.connect(self.Test)
        
        # OTP button group
        # Add IDs to buttons to make for easy access
        bNum = 1
        bList = self.OTPButtonGroup.buttons()
        for b in bList:
            self.OTPButtonGroup.setId(b, bNum)
            bNum += 1
            
        # self.OTPButtonGroup.buttonClicked.connect(self.OtpGen)
        self.OTPButtonGroup.idClicked.connect(self.OtpGen)
        
        MainWindow.show()
      
    def KKConnect(self):
        self.accounts = None
        _translate = QtCore.QCoreApplication.translate
        self.clientOps.ConnectKK()
        client = self.clientOps.getClient()
        if (client != None):
            self.ConnectKKButton.setStyleSheet("border-radius: 10px;\n"\
                "background-color: rgb(35, 40, 49);\n"\
                "border-width: 2px;\n"\
                "border-style: solid;\n"\
                "border-color: black;\n"\
                "color: rgb(0, 255, 0)")
            self.ConnectKKButton.setText(_translate("MainWindow", "KeepKey\nConnected"))
            # get accounts if connected
            #self.getAccounts(client)
            
    def getAccounts(self, client):
        self.accounts = self.authOps.auth_accGet(client)
        print(self.accounts)
        # reset button list
        bList = self.OTPButtonGroup.buttons()
        for b in bList:
            b.setText('')
 
        if len(self.accounts) > 0:
            # this forms monotonic button list of non-empty slots
            self.otpButtonAcc = list()
            bNum = 1
            for acc in self.accounts:
                if acc[1] == '':
                    continue
                else:
                    self.OTPButtonGroup.button(bNum).setText(acc[1])
                    self.otpButtonAcc.append((str(bNum), acc))
                    bNum += 1
        
    def QrScreencap(self):
        # grab fullscreen
        self.im = ImageGrab.grab(include_layered_windows=True)
        #self.im.save("fullscreen.png")

        data = decode(self.im)
        if (data == []):
            error_popup("QR Code Error", "Could not read QR code")
            return
        data1 = str(data[0][0]).replace("b'",'').replace("'","")
        type1 = str(data[0][1])
        print(data1)
        print(type1)
        secret = urlparse(data1).query.split('=')[1].split('&')[0]
        domain = urlparse(data1).path.split('/')[1].split(':')[0]
        account = urlparse(data1).path.split('/')[1].split(':')[1]
        print(secret)
        print(domain)
        print(account)
        client = self.clientOps.getClient()
        if (client != None):
            try:
                self.authOps.auth_accAdd(client, secret, domain, account)
                # re-establish otp list
                self.getAccounts(client)

            except PinException as e:
                error_popup("Invalid PIN", "")
            return
        else:
            print("KeepKey not connected")

    def OtpGen(self, id_):
        # First check if this is an active button with an account
        if self.OTPButtonGroup.button(id_).text() == '':
            return
        
        #generate OTP
        client = self.clientOps.getClient()
        
        if (client != None):
            for ba in self.otpButtonAcc:
                if ba[0] == str(id_):         # button clicked is in button-account list
                    dom, acc = ba[1][1].split(':')
                    print(dom+" "+acc)
                    break
            try:
                self.authOps.auth_otp(client, dom, acc)
            except PinException as e:
                error_popup("Invalid PIN", "")
            return
        else:
            print("KeepKey not connected")

    def removeAcc(self):
        # set up remove account dialog
        RemAccDialog = QtWidgets.QDialog()
        client = self.clientOps.getClient()
        RemAcc_ui = RemAcc_Dialog(client, self.authOps)
        RemAcc_ui.setupUi(RemAccDialog)
        RemAccDialog.show()
        x = RemAccDialog.exec_()    # show pin dialog    
        self.getAccounts(client)   
        
    def Test(self):
        #test the keepkey function
        print("test function")
        client = self.clientOps.getClient()
        if (client != None):
            try:
                self.authOps.auth_test(client)
                self.getAccounts(client)
            except PinException as e:
                error_popup("Invalid PIN", "")
            return
        else:
            print("KeepKey not connected")
            
class AuthClass:
    def auth_accAdd(self, client, secret, domain, account):
        # try:
        #     ret = client.ping(msg = b'\x15' + bytes("initializeAuth:" + "python-test:" + "BASE32SECRET2345AB", 'utf8'))
        # except PinException as e:
        #     print("Got exception in authenticator", e.args[0], " ", e.args[1])
        #     exit()

        try:
            retval = client.ping(msg = b'\x15' + bytes("initializeAuth:"+domain+":"+account+":"+secret, 'utf8'))
        except CallException as E:
                if E.args[1] == 'Authenticator secret storage full':
                    error_popup(E.args[1], "Need to remove an account to add a new one to this KeepKey")
                else:
                    error_popup(E.args[1], "")
            
    def auth_otp(self, client, domain, account):
        interval = 30       # 30 second interval
        #T0 = 1535317397
        #T0 = 1536262427
        T0 = datetime.now().timestamp()
        Tslice = int(T0/interval)
        Tremain = int((int(T0) - Tslice*30))
        print(Tremain)
        T = Tslice.to_bytes(8, byteorder='big')
        retval = client.ping(
            msg = b'\x16' + bytes("generateOTPFrom:"+domain+":"+account+":", 'utf8') + 
                                        binascii.hexlify(bytearray(T)) + bytes(":" + str(Tremain), 'utf8')
        )
        # print(retval)
        # print("should be 007767")  

    def auth_accGet(self, client):
        ctr=0
        accounts = list()
        while True:
            try:
                retval = client.ping(msg = b'\x17' + bytes("getAccount:"+str(ctr), 'utf8'))
                accounts.append([ctr, retval])
            except CallException as E:
                print(E.args[1])
                if E.args[1] == 'Account not found':
                    accounts.append([ctr, ''])
                if E.args[1] == 'Invalid PIN':
                    error_popup(E.args[1], '')
                    break
                if E.args[1] == 'Slot request out of range':
                    break
                if E.args[1] == 'Device not initialized':
                    error_popup('Device not initialized', 'Initialize KeepKey prior to using authentication feature')
                    break
            ctr+=1
            
        return accounts

    def auth_accRem(self, client, domain, account):
        try:
            client.ping(msg = b'\x18' + bytes("removeAccount:"+domain+":"+account, 'utf8'))
        except CallException as E:
            error_popup(E.args[1], domain+":"+account)
        return

    def auth_test(self, client):
        try:
            retval = client.ping(msg = b'\x15' + bytes("initializeAuth:"+"GitHub"+":"+"mooneytestgithub"+":"+"ZKLHM3W3XAHG4CBN", 'utf8'))
            retval = client.ping(msg = b'\x15' + bytes("initializeAuth:"+"Shapeshift"+":"+"markrypto"+":"+"BASE32SECRET2345AC", 'utf8'))
            retval = client.ping(msg = b'\x15' + bytes("initializeAuth:"+"KeepKey"+":"+"markrypto2"+":"+"BASE32SECRET2345AD", 'utf8'))
        except CallException as E:
                if E.args[1] == 'Authenticator secret storage full':
                    error_popup(E.args[1], "Need to remove an account to add a new one to this KeepKey")
                else:
                    error_popup(E.args[1], "")
        
        
        # ret = client.ping(msg = b'\x15' + bytes("initializeAuth:" + "python-test:" + "BASE32SECRET2345AB", 'utf8'))
            

 
        # interval = 30       # 30 second interval
        # #T0 = 1535317397
        # T0 = 1536262427
        
        # T = int(T0/interval).to_bytes(8, byteorder='big')
        # retval = client.ping(
        #     msg = b'\x16' + bytes("generateOTPFrom:" + "python-test:", 'utf8') + binascii.hexlify(bytearray(T))
        # )
        # print(retval)
        # print("should be 007767")  

def main():
    app = QtWidgets.QApplication(sys.argv)    
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui()
    ui.setupUi(MainWindow)
    sys.exit(app.exec_())
    
if __name__ == '__main__':
    main()


