#
# Copyright (C) 2023 markrypto <cryptoakorn@gmail.com>
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

import common
import binascii
import json
import keepkeylib

def addSignedToken(self, tokenName):       
    f = open('evptests.json')
    tests = json.load(f)
    f.close()
    for payload in tests['payloads']:
        if payload['payload']['type'] == 'token' and payload['payload']['name'] == tokenName:
            break;
        
    retval = self.client.ethereum_verify_message(
        # This is a no-op address, not the address used to sign the message
        signature = bytes.fromhex(json.dumps(payload['signature'])[1:-1]),
        message = bytes(json.dumps(payload['payload']), 'utf8')
    )
    return retval

def verifySignedDapp(self, dappName):       
    f = open('evptests.json')
    tests = json.load(f)
    f.close()

    for payload in tests['payloads']:
        if payload['payload']['type'] == 'dapp' and payload['payload']['name'] == dappName:
            break;
    
    retval = self.client.ethereum_verify_message(
        # This is a no-op address, not the address used to sign the message
        signature = bytes.fromhex(json.dumps(payload['signature'])[1:-1]),
        message = bytes(json.dumps(payload['payload']), 'utf8')
    )
    return retval
