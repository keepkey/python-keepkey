#
# Copyright (C) 2022 markrypto <cryptoakorn@gmail.com>
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

def addSignedToken(self, token):       
    f = open('evptests.json')
    tokens = json.load(f)
    f.close()
    retval = self.client.ethereum_verify_message(
        # This is a no-op address, not the address used to sign the message
        signature = bytes.fromhex(json.dumps(tokens[token]['signature'])[1:-1]),
        message = bytes(json.dumps(tokens[token]['token']), 'utf8')
    )
    return retval

def addSignedIcon(self, icon):       
    f = open('evptests.json')
    icons = json.load(f)
    f.close()
    
    retval = self.client.ethereum_verify_message(
        # This is a no-op address, not the address used to sign the message
        signature = bytes.fromhex(json.dumps(icons[icon]['signature'])[1:-1]),
        message = bytes(json.dumps(icons[icon]['iconChain']), 'utf8')
    )
    return retval
