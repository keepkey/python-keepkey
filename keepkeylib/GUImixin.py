# This file is part of the KeepKey project.
#
# Copyright (C) 2022 markrypto (cryptoakorn@gmail.com)
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

from . import messages_pb2 as proto
from KeepKeyAuthenticator import pingui_popup

class GuiUIMixin(object):
    # qt gui interface
    
    def __init__(self, *args, **kwargs):
        super(GuiUIMixin, self).__init__(*args, **kwargs)
        self.character_request_first_pass = True

    def callback_ButtonRequest(self, msg):
        # log("Sending ButtonAck for %s " % get_buttonrequest_value(msg.code))
        return proto.ButtonAck()

    # def callback_RecoveryMatrix(self, msg):
    #     pass

    def callback_PinMatrixRequest(self, msg):
        # get matrix position and ack
        # pin = getPinDecoded()
        pin = pingui_popup()
        print(pin)
        return proto.PinMatrixAck(pin=pin)

    # def callback_PassphraseRequest(self, msg):
    #     pass

    # def callback_CharacterRequest(self, msg):
    #     pass
