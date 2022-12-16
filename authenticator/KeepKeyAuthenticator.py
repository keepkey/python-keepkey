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
import usb1 as libusb

from keepkeylib.transport_webusb import WebUsbTransport
from keepkeylib.client import PinException, ProtocolMixin, BaseClient, CallException
from keepkeylib import types_pb2 as types


from AuthMain import Ui_MainWindow as Ui
from PinUi import Ui_Dialog as PIN_Dialog
from remaccdialog import Ui_RemAccDialog as RemAcc_Dialog
from addaccui import Ui_AddAccDialog as AddAcc_Dialog
from manualaddacc import Ui_ManualAddAccDialog as ManAddAcc_Dialog

# for dev testing
_test = False

authErrs = ('Invalid PIN', 'PIN Cancelled', 'PIN expected', 'Auth secret unknown error', 
                         'Account name missing or too long, or seed/message string missing', 
                         'Authenticator secret can\'t be decoded', 'Authenticator secret seed too large')
class kkClient:
    def __init__(self):
        self.client = None
        
    def ConnectKK(self):
        from GUImixin import GuiUIMixin
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

    def closeClient(self):
        self.client.close()
        self.client=None

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
        self.unlockClicked = False
        
                
    def addPinClick(self, clickPosition):
        self.encodedPin+=clickPosition
        if _test: print("encoded pin ", self.encodedPin)
        self.lineEdit.setText(self.encodedPin)
        return
        
    def returnPinAndClose(self, Dialog): 
        if _test: print("unlock pressed")
        self.unlockClicked = True
        Dialog.close()
        
    def getEncodedPin(self): 
        # return encoded PIN when unlock button pressed
        return self.encodedPin
    
    def getUnlockClicked(self): 
        # return encoded PIN when unlock button pressed
        return self.unlockClicked

def pingui_popup():
    # set up PIN dialog        
    PINDialog = QtWidgets.QDialog()
    PIN_ui = PIN_Dialog()
    PIN_ui.setupUi(PINDialog)
    PINDialog.show()
    x = PINDialog.exec_()    # show pin dialog
    if PIN_ui.getUnlockClicked() == True:
        pin = PIN_ui.getEncodedPin()
        if _test: print(pin)
        return pin
    else:
        return 'E'  # pin cancelled

class RemAcc_Dialog(RemAcc_Dialog):
    def __init__(self, client, authOps):
        self.client = client
        self.authOps = authOps
        self.accounts = None
        self.KKDisconnect = False
        return

    def setupUi(self, Dialog):
        super(RemAcc_Dialog, self).setupUi(Dialog)
        self.Dialog = Dialog
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

        self.accounts, fail = self.authOps.auth_accGet(self.client)
        if fail in ('Invalid PIN', 'PIN Cancelled', 'PIN expected', 'usb err', 'Device not initialized'):
            self.KKDisconnect = True
            return
       
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
                    if _test: print(dom+" "+acc)
                    break
            err = self.authOps.auth_accRem(self.client, dom, acc) 
            if err == 'noerr':
                self.RemGetAccounts()
            elif err == 'usb err':
                self.KKDisconnect = True
                self.Dialog.close()
                return
            else:
                error_popup(err, '')
                return
                                
        else:
            error_popup('Keepkey not connected', '')
            
    def getKKDisconnect(self):
        return self.KKDisconnect

class ManAddAcc_Dialog(ManAddAcc_Dialog):
    def __init__(self, client, authOps):
        self.client = client
        self.authOps = authOps
        self.KKDisconnect = False
        self.secret = None
        self.domain = None
        self.account = None
        return

    def setupUi(self, Dialog):
        super(ManAddAcc_Dialog, self).setupUi(Dialog)
        self.Dialog = Dialog
        self.AddButton.clicked.connect(self.ManualAdd)
        
    def ManualAdd(self):
        
        self.secret = self.SecretlineEdit.text()
        self.domain = self.IssuerlineEdit.text()
        self.account = self.AccNamelineEdit.text()
        self.Dialog.close()
        
    def getManAuth(self):
        return self.domain, self.account, self.secret
    
    def getKKDisconnect(self):
        return self.KKDisconnect
        
class AddAcc_Dialog(AddAcc_Dialog):
    def __init__(self, client, authOps):
        self.client = client
        self.authOps = authOps
        self.accounts = None
        self.KKDisconnect = False
        return

    def setupUi(self, Dialog):
        super(AddAcc_Dialog, self).setupUi(Dialog)
        self.Dialog = Dialog
        self.ScanQrButton.clicked.connect(self.QrScreencap)
        self.EnterManuallyButton.clicked.connect(self.ManAddAcc)

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
        if _test: print(data1)
        if _test: print(type1)
        secret = urlparse(data1).query.split('=')[1].split('&')[0]
        domain = urlparse(data1).path.split('/')[1].split(':')[0]
        account = urlparse(data1).path.split('/')[1].split(':')[1]
        
        self.KKAddAcc(self.client, secret, domain, account)
        return
        
    def KKAddAcc(self, client, secret, domain, account):
        if _test: print(secret)
        if _test: print(domain)
        if _test: print(account)
        if (client != None):
            err = self.authOps.auth_accAdd(client, secret, domain, account)
            if err == 'noerr':
                self.Dialog.close()
                return
            elif err in authErrs:
                error_popup(err, '')
            else:
                error_popup(err, '')    #usb error
                self.KKDisconnect = True
                self.Dialog.close()

            return
        else:
            error_popup('Keepkey not connected', '')
            self.KKDisconnect = True
            self.Dialog.close()

    def ManAddAcc(self):
        if self.client == None:
            return

        # set up manual add account dialog
        ManAddAccDialog = QtWidgets.QDialog()            
        ManAddAcc_ui = ManAddAcc_Dialog(self.client, self.authOps)
        ManAddAcc_ui.setupUi(ManAddAccDialog)
        if ManAddAcc_ui.getKKDisconnect() == True:
            self.KKDisconnect()
            self.Dialog.close()
            return
        ManAddAccDialog.show()
        x = ManAddAccDialog.exec_()    # show dialog
        domain, account, secret = ManAddAcc_ui.getManAuth()
        if None in (domain, account, secret):
            error_popup('Must enter values for domain, account and secret')
        else:
            self.KKAddAcc(self.client, secret, domain, account)

        self.Dialog.close()

    def getKKDisconnect(self):
        return self.KKDisconnect
                
class Ui(Ui):
    def __init__(self):
        self.authOps = AuthClass()

    def setupUi(self, MainWindow):
        super(Ui, self).setupUi(MainWindow)
        
        self.clientOps = kkClient()
        
        self.ConnectKKButton.clicked.connect(self.KKConnect)
        self.AddAccButton.clicked.connect(self.addAcc)
        self.RemoveAccButton.clicked.connect(self.removeAcc)
        if _test:
            self.testButton.clicked.connect(self.Test)
        else:
            self.testButton.deleteLater()
        
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
            self.getAccounts(client)
            
    def KKDisconnect(self):
        self.accounts = None
        _translate = QtCore.QCoreApplication.translate
        self.clientOps.closeClient()
        self.ConnectKKButton.setStyleSheet("border-radius: 10px;\n"\
            "background-color: rgb(255, 128, 4);\n"\
            "border-width: 2px;\n"\
            "border-style: solid;\n"\
            "border-color: black;\n"\
            "color: rgb(255, 255, 255)")
        self.ConnectKKButton.setText(_translate("MainWindow", "Connect\nKeepKey"))
        self.clearAccounts()
            
    def getAccounts(self, client):
        self.accounts, err = self.authOps.auth_accGet(client)
        if err in ('Invalid PIN', 'PIN Cancelled', 'PIN expected', 'usb err', 'Device not initialized'):
            self.KKDisconnect()
            return
        
        if _test: print(self.accounts)
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
                    
    def clearAccounts(self):
        self.accounts = None
        bList = self.OTPButtonGroup.buttons()
        for b in bList:
            b.setText('')
 
    def addAcc(self):
        client = self.clientOps.getClient()
        if client == None:
            return

        # set up add account dialog
        AddAccDialog = QtWidgets.QDialog()            
        AddAcc_ui = AddAcc_Dialog(client, self.authOps)
        AddAcc_ui.setupUi(AddAccDialog)
        if AddAcc_ui.getKKDisconnect() == True:
            self.KKDisconnect()
            return
        AddAccDialog.show()
        x = AddAccDialog.exec_()    # show pin dialog
        self.getAccounts(client)   

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
                    if _test: print(dom+" "+acc)
                    break
            err = self.authOps.auth_otp(client, dom, acc)
            if err in authErrs:
                error_popup(err, '')
            elif err == 'usb err':
                error_popup('usb error', '')
                self.KKDisconnect()
                return
        
        else:
            error_popup('Keepkey not connected', '')

    def removeAcc(self):
        client = self.clientOps.getClient()
        if client == None:
            return

        # set up remove account dialog
        RemAccDialog = QtWidgets.QDialog()            
        RemAcc_ui = RemAcc_Dialog(client, self.authOps)
        RemAcc_ui.setupUi(RemAccDialog)
        if RemAcc_ui.getKKDisconnect() == True:
            self.KKDisconnect()
            return
        RemAccDialog.show()
        x = RemAccDialog.exec_()    # show pin dialog
        self.getAccounts(client)   
        
    def Test(self):
        #test the keepkey function
        client = self.clientOps.getClient()
        if (client != None):
            try:
                self.authOps.auth_test(client)
                self.getAccounts(client)
            except PinException as e:
                error_popup("Invalid PIN", "")
            return
        else:
            error_popup('Keepkey not connected', '')
            
class AuthClass:
    def sendMsg(self, client, msg):
        err = ''
        retval = None
        try:
            retval = client.ping(msg)
        except CallException as E:
            err = E.args[1]
            
        except libusb.USBErrorNoDevice:
            err = "No KeepKey found"
        except libusb.USBErrorTimeout:
            err = "USB error timeout"
        except libusb.USBError as error:
            err = "USB error %r" % error
        
        return retval, err

        
    def auth_accAdd(self, client, secret, domain, account):
        retval, err = self.sendMsg(client, msg = b'\x15' + bytes("initializeAuth:"+domain+":"+account+":"+secret, 'utf8'))
        if err == 'Authenticator secret storage full':
            error_popup(err, "Need to remove an account to add a new one to this KeepKey")
            return err
        elif err in authErrs: 
            error_popup(err, '')
            return err
        elif err != '':
            error_popup(err, '')
            return 'usb err'
        return 'noerr'
            
    def auth_otp(self, client, domain, account):
        interval = 30       # 30 second interval
        #T0 = 1535317397
        #T0 = 1536262427
        T0 = datetime.now().timestamp()
        Tslice = int(T0/interval)
        Tremain = int((int(T0) - Tslice*30))
        if _test: print(Tremain)
        T = Tslice.to_bytes(8, byteorder='big')
        retval, err = self.sendMsg(client, 
            msg = b'\x16' + bytes("generateOTPFrom:"+domain+":"+account+":", 'utf8') + 
                                    binascii.hexlify(bytearray(T)) + bytes(":" + str(Tremain), 'utf8')
        )
        if err in authErrs: 
            error_popup(err, '')
            return err
        elif err != '':
            error_popup(err, '')
            return 'usb err'
        return 'noerr'
    
    def auth_accGet(self, client):
        ctr=0
        accounts = list()
        while True:
            retval, err = self.sendMsg(client, msg = b'\x17' + bytes("getAccount:"+str(ctr), 'utf8'))
            if err == '':
                accounts.append([ctr, retval])
            elif err == 'Account not found':
                accounts.append([ctr, ''])
            elif err == 'Slot request out of range':
                break
            elif err == 'Device not initialized':
                error_popup(err, 'Initialize KeepKey prior to using authentication feature')
                break
            elif err in authErrs: 
                error_popup(err, '')
                return accounts, err
            else:
                error_popup(err, '')
                return accounts, 'usb err'
                
            ctr+=1
            
        return accounts, 'noerr'

    def auth_accRem(self, client, domain, account):
        retval, err = self.sendMsg(client, msg = b'\x18' + bytes("removeAccount:"+domain+":"+account, 'utf8'))
        if err in authErrs:
            error_popup(E.args[1], domain+":"+account)
        elif err != '':
            error_popup(err, '')
            return 'usb err'

        return 'noerr'

    def auth_test(self, client):
        # otpauth://totp/KeepKey:markrypto?secret=ZKLHM3W3XAHG4CBN&issuer=kk
        for msg in (
            b'\x15' + bytes("initializeAuth:"+"KeepKey"+":"+"markrypto"+":"+"ZKLHM3W3XAHG4CBN", 'utf8'),
            b'\x15' + bytes("initializeAuth:"+"Shapeshift"+":"+"markrypto"+":"+"BASE32SECRET2345AB", 'utf8'),
            b'\x15' + bytes("initializeAuth:"+"Shapeshift"+":"+"markrypto"+":"+"BASE32SECRET2345AB", 'utf8')
            ):
            retval, err = self.sendMsg(client, msg)
            if err == 'Authenticator secret storage full':
                error_popup(err, "Need to remove an account to add a new one to this KeepKey")
                return err
            elif err in authErrs: 
                error_popup(err, '')
                return err
            elif err != '':
                error_popup(err, '')
                return 'usb err'
            
        return 'noerr'

        # interval = 30       # 30 second interval
        # #T0 = 1535317397
        # T0 = 1536262427
        
        # T = int(T0/interval).to_bytes(8, byteorder='big')
        # retval = client.ping(
        #     msg = b'\x16' + bytes("generateOTPFrom:" + "python-test:", 'utf8') + binascii.hexlify(bytearray(T))
        # )
        # if _test: print(retval)
        # if _test: print("should be 007767")  

def main():
    app = QtWidgets.QApplication(sys.argv)    
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui()
    ui.setupUi(MainWindow)
    sys.exit(app.exec_())
    
if __name__ == '__main__':
    main()


