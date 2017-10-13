# This file is part of the TREZOR project.
#
# Copyright (C) 2012-2016 Marek Palatinus <slush@satoshilabs.com>
# Copyright (C) 2012-2016 Pavol Rusnak <stick@satoshilabs.com>
# Copyright (C) 2016      Jochen Hoenicke <hoenicke@gmail.com>
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

from __future__ import print_function, absolute_import

import os
import sys
import time
import binascii
import hashlib
import unicodedata
import json
import getpass

from mnemonic import Mnemonic

from . import tools
from . import mapping
from . import messages_pb2 as proto
from . import types_pb2 as types
from .debuglink import DebugLink

# try:
#     from PIL import Image
#     SCREENSHOT = True
# except:
#     SCREENSHOT = False

SCREENSHOT = False

DEFAULT_CURVE = 'secp256k1'

# monkeypatching: text formatting of protobuf messages
tools.monkeypatch_google_protobuf_text_format()

def get_buttonrequest_value(code):
    # Converts integer code to its string representation of ButtonRequestType
    return [ k for k, v in types.ButtonRequestType.items() if v == code][0]

def pprint(msg):
    msg_class = msg.__class__.__name__
    msg_size = msg.ByteSize()
    """
    msg_ser = msg.SerializeToString()
    msg_id = mapping.get_type(msg)
    msg_json = json.dumps(protobuf_json.pb2json(msg))
    """
    if isinstance(msg, proto.FirmwareUpload):
        return "<%s> (%d bytes):\n" % (msg_class, msg_size)
    else:
        return "<%s> (%d bytes):\n%s" % (msg_class, msg_size, msg)

def log(msg):
    sys.stderr.write("%s\n" % msg)
    sys.stderr.flush()

def log_cr(msg):
    sys.stdout.write('\r%s' % msg)
    sys.stdout.flush()

def format_mnemonic(word_pos, character_pos):
    return "WORD %d: %s" % (word_pos, character_pos * '*')

def getch():
    try:
        import termios
    except ImportError:
        # Non-POSIX. Return msvcrt's (Windows') getch.
        import msvcrt
        return msvcrt.getch()

    # POSIX system. Create and return a getch that manipulates the tty.
    import sys, tty
    def _getch():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch

    return _getch()

class CallException(Exception):
    def __init__(self, code, message):
        super(CallException, self).__init__()
        self.args = [code, message]

class PinException(CallException):
    pass

class field(object):
    # Decorator extracts single value from
    # protobuf object. If the field is not
    # present, raises an exception.
    def __init__(self, field):
        self.field = field

    def __call__(self, f):
        def wrapped_f(*args, **kwargs):
            ret = f(*args, **kwargs)
            ret.HasField(self.field)
            return getattr(ret, self.field)
        return wrapped_f

class expect(object):
    # Decorator checks if the method
    # returned one of expected protobuf messages
    # or raises an exception
    def __init__(self, *expected):
        self.expected = expected

    def __call__(self, f):
        def wrapped_f(*args, **kwargs):
            ret = f(*args, **kwargs)
            if not isinstance(ret, self.expected):
                raise Exception("Got %s, expected %s" % (ret.__class__, self.expected))
            return ret
        return wrapped_f

def session(f):
    # Decorator wraps a BaseClient method
    # with session activation / deactivation
    def wrapped_f(*args, **kwargs):
        client = args[0]
        try:
            client.transport.session_begin()
            return f(*args, **kwargs)
        finally:
            client.transport.session_end()
    return wrapped_f

def normalize_nfc(txt):
    if sys.version_info[0] < 3:
        if isinstance(txt, unicode):
            return unicodedata.normalize('NFC', txt)
        if isinstance(txt, str):
            return unicodedata.normalize('NFC', txt.decode('utf-8'))
    else:
        if isinstance(txt, bytes):
            return unicodedata.normalize('NFC', txt.decode('utf-8'))
        if isinstance(txt, str):
            return unicodedata.normalize('NFC', txt)

    raise Exception('unicode/str or bytes/str expected')

class BaseClient(object):
    # Implements very basic layer of sending raw protobuf
    # messages to device and getting its response back.
    def __init__(self, transport, **kwargs):
        self.transport = transport
        super(BaseClient, self).__init__()  # *args, **kwargs)

    def cancel(self):
        self.transport.write(proto.Cancel())

    @session
    def call_raw(self, msg):
        self.transport.write(msg)
        return self.transport.read_blocking()

    @session
    def call(self, msg):
        resp = self.call_raw(msg)
        handler_name = "callback_%s" % resp.__class__.__name__
        handler = getattr(self, handler_name, None)

        if handler != None:
            msg = handler(resp)
            if msg == None:
                raise Exception("Callback %s must return protobuf message, not None" % handler)
            resp = self.call(msg)

        return resp

    def callback_Failure(self, msg):
        if msg.code in (types.Failure_PinInvalid,
            types.Failure_PinCancelled, types.Failure_PinExpected):
            raise PinException(msg.code, msg.message)

        raise CallException(msg.code, msg.message)

    def close(self):
        self.transport.close()

class DebugWireMixin(object):
    def call_raw(self, msg):
        log("SENDING " + pprint(msg))
        resp = super(DebugWireMixin, self).call_raw(msg)
        log("RECEIVED " + pprint(resp))
        return resp

class TextUIMixin(object):
    # This class demonstrates easy test-based UI
    # integration between the device and wallet.
    # You can implement similar functionality
    # by implementing your own GuiMixin with
    # graphical widgets for every type of these callbacks.

    def __init__(self, *args, **kwargs):
        super(TextUIMixin, self).__init__(*args, **kwargs)
        self.character_request_first_pass = True

    def callback_ButtonRequest(self, msg):
        # log("Sending ButtonAck for %s " % get_buttonrequest_value(msg.code))
        return proto.ButtonAck()

    def callback_RecoveryMatrix(self, msg):
        if self.recovery_matrix_first_pass:
            self.recovery_matrix_first_pass = False
            log("Use the numeric keypad to describe positions.  For the word list use only left and right keys. The layout is:")
            log("    7 8 9     7 | 9")
            log("    4 5 6     4 | 6")
            log("    1 2 3     1 | 3")
        while True:
            character = getch()
            if character in ('\x03', '\x04'):
                return proto.Cancel()

            if character in ('\x08', '\x7f'):
                return proto.WordAck(word='\x08')

            # ignore middle column if only 6 keys requested.
            if (msg.type == types.WordRequestType_Matrix6 and
                character in ('2', '5', '8')):
                continue

            if (ord(character) >= ord('1') and ord(character) <= ord('9')):
                return proto.WordAck(word=character)

    def callback_PinMatrixRequest(self, msg):
        if msg.type == 1:
            desc = 'current PIN'
        elif msg.type == 2:
            desc = 'new PIN'
        elif msg.type == 3:
            desc = 'new PIN again'
        else:
            desc = 'PIN'

        log("Use the numeric keypad to describe number positions. The layout is:")
        log("    7 8 9")
        log("    4 5 6")
        log("    1 2 3")
        log("Please enter %s: " % desc)
        pin = getpass.getpass('')
        return proto.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, msg):
        log("Passphrase required: ")
        passphrase = getpass.getpass('')
        log("Confirm your Passphrase: ")
        if passphrase == getpass.getpass(''):
            passphrase = normalize_nfc(passphrase)
            return proto.PassphraseAck(passphrase=passphrase)
        else:
            log("Passphrase did not match! ")
            exit()

    def callback_WordRequest(self, msg):
        log("Enter one word of mnemonic: ")
        try:
            word = raw_input()
        except NameError:
            word = input() # Python 3
        return proto.WordAck(word=word)

    def callback_CharacterRequest(self, msg):
        if self.character_request_first_pass:
            self.character_request_first_pass = False
            log("Use recovery cipher on device to input mnemonic. Words are autocompleted at 3 or 4 characters.")
            log("(use spacebar to progress to next word after match, use backspace to correct bad character or word entries)")

        # format mnemonic for console
        formatted_console = format_mnemonic(msg.word_pos + 1, msg.character_pos)

        # clear the runway before we display formatted mnemonic
        log_cr(' ' * 14)
        log_cr(formatted_console)

        while True:
            character = getch().lower()

            # capture escape
            if character in ('\x03', '\x04'):
                return proto.Cancel()

            character_ascii = ord(character)

            if character_ascii >= 97 and character_ascii <= 122 \
            and msg.character_pos != 4:
                # capture characters a-z
                return proto.CharacterAck(character=character)

            elif character_ascii == 32 and msg.word_pos < 23 \
            and msg.character_pos >= 3:
                # capture spaces
                return proto.CharacterAck(character=' ')

            elif character_ascii == 8 or character_ascii == 127 \
            and (msg.word_pos > 0 or msg.character_pos > 0):
                # capture backspaces
                return proto.CharacterAck(delete=True)

            elif character_ascii == 13 and msg.word_pos in (11, 17, 23):
                # capture returns
                log("")
                return proto.CharacterAck(done=True)

class DebugLinkMixin(object):
    # This class implements automatic responses
    # and other functionality for unit tests
    # for various callbacks, created in order
    # to automatically pass unit tests.
    #
    # This mixing should be used only for purposes
    # of unit testing, because it will fail to work
    # without special DebugLink interface provided
    # by the device.

    def __init__(self, *args, **kwargs):
        super(DebugLinkMixin, self).__init__(*args, **kwargs)
        self.debug = None
        self.in_with_statement = 0
        self.button_wait = 0
        self.screenshot_id = 0

        # Always press Yes and provide correct pin
        self.setup_debuglink(True, True)

        # Do not expect any specific response from device
        self.expected_responses = None

        # Use blank passphrase
        self.set_passphrase('')

    def close(self):
        super(DebugLinkMixin, self).close()
        if self.debug:
            self.debug.close()

    def set_debuglink(self, debug_transport):
        self.debug = DebugLink(debug_transport)

    def set_buttonwait(self, secs):
        self.button_wait = secs

    def __enter__(self):
        # For usage in with/expected_responses
        self.in_with_statement += 1
        return self

    def __exit__(self, _type, value, traceback):
        self.in_with_statement -= 1

        if _type != None:
            # Another exception raised
            return False

        # return isinstance(value, TypeError)
        # Evaluate missed responses in 'with' statement
        if self.expected_responses != None and len(self.expected_responses):
            raise Exception("Some of expected responses didn't come from device: %s" % \
                    [ pprint(x) for x in self.expected_responses ])

        # Cleanup
        self.expected_responses = None
        return False

    def set_expected_responses(self, expected):
        if not self.in_with_statement:
            raise Exception("Must be called inside 'with' statement")
        self.expected_responses = expected

    def setup_debuglink(self, button, pin_correct):
        self.button = button  # True -> YES button, False -> NO button
        self.pin_correct = pin_correct

    def set_passphrase(self, passphrase):
        self.passphrase = normalize_nfc(passphrase)

    def set_mnemonic(self, mnemonic):
        self.mnemonic = normalize_nfc(mnemonic).split(' ')

    def call_raw(self, msg):

        if SCREENSHOT and self.debug:
            layout = self.debug.read_layout()
            im = Image.new("RGB", (128, 64))
            pix = im.load()
            for x in range(128):
                for y in range(64):
                    rx, ry = 127 - x, 63 - y
                    if (ord(layout[rx + (ry / 8) * 128]) & (1 << (ry % 8))) > 0:
                        pix[x, y] = (255, 255, 255)
            im.save('scr%05d.png' % self.screenshot_id)
            self.screenshot_id += 1

        resp = super(DebugLinkMixin, self).call_raw(msg)
        self._check_request(resp)
        return resp

    def _check_request(self, msg):
        if self.expected_responses != None:
            try:
                expected = self.expected_responses.pop(0)
            except IndexError:
                raise CallException(types.Failure_Other,
                        "Got %s, but no message has been expected" % pprint(msg))

            if msg.__class__ != expected.__class__:
                raise CallException(types.Failure_Other,
                            "Expected %s, got %s" % (pprint(expected), pprint(msg)))

            fields = expected.ListFields()  # only filled (including extensions)
            for field, value in fields:
                if not msg.HasField(field.name) or getattr(msg, field.name) != value:
                    raise CallException(types.Failure_Other,
                            "Expected %s, got %s" % (pprint(expected), pprint(msg)))

    def callback_ButtonRequest(self, msg):
        log("ButtonRequest code: " + get_buttonrequest_value(msg.code))

        log("Pressing button " + str(self.button))
        if self.button_wait:
            log("Waiting %d seconds " % self.button_wait)
            time.sleep(self.button_wait)
        self.debug.press_button(self.button)
        return proto.ButtonAck()

    def callback_PinMatrixRequest(self, msg):
        if self.pin_correct:
            pin = self.debug.read_pin_encoded()
        else:
            pin = '444222'
        return proto.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, msg):
        log("Provided passphrase: '%s'" % self.passphrase)
        return proto.PassphraseAck(passphrase=self.passphrase)

    def callback_WordRequest(self, msg):
        (word, pos) = self.debug.read_recovery_word()
        if word != '':
            return proto.WordAck(word=word)
        if pos != 0:
            return proto.WordAck(word=self.mnemonic[pos - 1])

        raise Exception("Unexpected call")

class ProtocolMixin(object):
    PRIME_DERIVATION_FLAG = 0x80000000
    VENDORS = ('keepkey.com',)

    def __init__(self, *args, **kwargs):
        super(ProtocolMixin, self).__init__(*args, **kwargs)
        self.init_device()
        self.tx_api = None

    def set_tx_api(self, tx_api):
        self.tx_api = tx_api

    def init_device(self):
        self.features = expect(proto.Features)(self.call)(proto.Initialize())
        if str(self.features.vendor) not in self.VENDORS:
            raise Exception("Unsupported device")

    def _get_local_entropy(self):
        return os.urandom(32)

    def _convert_prime(self, n):
        # Convert minus signs to uint32 with flag
        return [ int(abs(x) | self.PRIME_DERIVATION_FLAG) if x < 0 else x for x in n ]

    @staticmethod
    def expand_path(n):
        # Convert string of bip32 path to list of uint32 integers with prime flags
        # 0/-1/1' -> [0, 0x80000001, 0x80000001]
        if not n:
            return []

        n = n.split('/')

        # m/a/b/c => a/b/c
        if n[0] == 'm':
            n = n[1:]

        # coin_name/a/b/c => 44'/SLIP44_constant'/a/b/c
        coins = { "Bitcoin": 0, "Testnet": 1, "Namecoin": 7, "Litecoin": 2, "Dogecoin": 3, "Dash": 5, "Zcash": 133, }
        if n[0] in coins:
            n = ["44'", "%d'" % coins[n[0]] ] + n[1:]

        path = []
        for x in n:
            prime = False
            if x.endswith("'"):
                x = x.replace('\'', '')
                prime = True
            if x.startswith('-'):
                prime = True

            x = abs(int(x))

            if prime:
                x |= ProtocolMixin.PRIME_DERIVATION_FLAG

            path.append(x)

        return path

    @expect(proto.PublicKey)
    def get_public_node(self, n, ecdsa_curve_name=DEFAULT_CURVE, show_display=False):
        n = self._convert_prime(n)
        if not ecdsa_curve_name:
            ecdsa_curve_name=DEFAULT_CURVE
        return self.call(proto.GetPublicKey(address_n=n, ecdsa_curve_name=ecdsa_curve_name, show_display=show_display))

    @field('address')
    @expect(proto.Address)
    def get_address(self, coin_name, n, show_display=False, multisig=None, script_type=types.SPENDADDRESS):
        n = self._convert_prime(n)
        if multisig:
            return self.call(proto.GetAddress(address_n=n, coin_name=coin_name, show_display=show_display, multisig=multisig, script_type=script_type))
        else:
            return self.call(proto.GetAddress(address_n=n, coin_name=coin_name, show_display=show_display, script_type=script_type))

    @field('address')
    @expect(proto.EthereumAddress)
    def ethereum_get_address(self, n, show_display=False, multisig=None):
        n = self._convert_prime(n)
        return self.call(proto.EthereumGetAddress(address_n=n, show_display=show_display))

    @session
    def ethereum_sign_tx(self, n, nonce, gas_price, gas_limit, value, to=None, to_n=None, address_type=None, exchange_type=None, data=None, chain_id=None):
        def int_to_big_endian(value):
            import rlp.utils
            if value == 0:
                return b''
            return rlp.utils.int_to_big_endian(value)

        n = self._convert_prime(n)

        if address_type == 1:   #Ethereum transfer transaction
            msg = proto.EthereumSignTx(
                address_n=n,
                nonce=int_to_big_endian(nonce),
                gas_price=int_to_big_endian(gas_price),
                gas_limit=int_to_big_endian(gas_limit),
                value=int_to_big_endian(value),
                to_address_n=to_n,
                )
            msg.address_type = address_type
        elif address_type == 3:   #Ethereum exchange transaction
            msg = proto.EthereumSignTx(
                address_n=n,
                nonce=int_to_big_endian(nonce),
                gas_price=int_to_big_endian(gas_price),
                gas_limit=int_to_big_endian(gas_limit),
                value=int_to_big_endian(value),
                to_address_n=to_n,
                exchange_type=exchange_type
                )
            msg.address_type = address_type
        else:
            msg = proto.EthereumSignTx(
                address_n=n,
                nonce=int_to_big_endian(nonce),
                gas_price=int_to_big_endian(gas_price),
                gas_limit=int_to_big_endian(gas_limit),
                value=int_to_big_endian(value)
                )

        if to:
            msg.to = to

        if data:
            msg.data_length = len(data)
            data, chunk = data[1024:], data[:1024]
            msg.data_initial_chunk = chunk

        if chain_id:
            msg.chain_id = chain_id

        response = self.call(msg)

        while response.HasField('data_length'):
            data_length = response.data_length
            data, chunk = data[data_length:], data[:data_length]
            response = self.call(proto.EthereumTxAck(data_chunk=chunk))

        if address_type:
            return response.signature_v, response.signature_r, response.signature_s, response.hash, response.signature_der
        else:
            return response.signature_v, response.signature_r, response.signature_s

    @field('entropy')
    @expect(proto.Entropy)
    def get_entropy(self, size):
        return self.call(proto.GetEntropy(size=size))

    @field('message')
    @expect(proto.Success)
    def ping(self, msg, button_protection=False, pin_protection=False, passphrase_protection=False):
        msg = proto.Ping(message=msg,
                         button_protection=button_protection,
                         pin_protection=pin_protection,
                         passphrase_protection=passphrase_protection)
        return self.call(msg)

    def get_device_id(self):
        return self.features.device_id

    @field('message')
    @expect(proto.Success)
    def apply_settings(self, label=None, language=None, use_passphrase=None, homescreen=None):
        settings = proto.ApplySettings()
        if label != None:
            settings.label = label
        if language:
            settings.language = language
        if use_passphrase != None:
            settings.use_passphrase = use_passphrase

        out = self.call(settings)
        self.init_device()  # Reload Features
        return out

    @field('message')
    @expect(proto.Success)
    def apply_policy(self, policy_name, enabled):
        policy = types.PolicyType(policy_name=policy_name, enabled=enabled)
        apply_policies = proto.ApplyPolicies(policy=[policy])

        out = self.call(apply_policies)
        self.init_device()  # Reload Features
        return out

    @field('message')
    @expect(proto.Success)
    def clear_session(self):
        return self.call(proto.ClearSession())

    @field('message')
    @expect(proto.Success)
    def change_pin(self, remove=False):
        ret = self.call(proto.ChangePin(remove=remove))
        self.init_device()  # Re-read features
        return ret

    @expect(proto.MessageSignature)
    def sign_message(self, coin_name, n, message):
        n = self._convert_prime(n)
        # Convert message to UTF8 NFC (seems to be a bitcoin-qt standard)
        message = normalize_nfc(message).encode("utf-8")
        return self.call(proto.SignMessage(coin_name=coin_name, address_n=n, message=message))

    @expect(proto.SignedIdentity)
    def sign_identity(self, identity, challenge_hidden, challenge_visual, ecdsa_curve_name=DEFAULT_CURVE):
        return self.call(proto.SignIdentity(identity=identity, challenge_hidden=challenge_hidden, challenge_visual=challenge_visual, ecdsa_curve_name=ecdsa_curve_name))


    def verify_message(self, coin_name, address, signature, message):
        # Convert message to UTF8 NFC (seems to be a bitcoin-qt standard)
        message = normalize_nfc(message).encode("utf-8")
        try:
            resp = self.call(proto.VerifyMessage(address=address, signature=signature, message=message, coin_name=coin_name))
        except CallException as e:
            resp = e
        if isinstance(resp, proto.Success):
            return True
        return False

    @expect(proto.EncryptedMessage)
    def encrypt_message(self, pubkey, message, display_only, coin_name, n):
        if coin_name and n:
            n = self._convert_prime(n)
            return self.call(proto.EncryptMessage(pubkey=pubkey, message=message, display_only=display_only, coin_name=coin_name, address_n=n))
        else:
            return self.call(proto.EncryptMessage(pubkey=pubkey, message=message, display_only=display_only))

    @expect(proto.DecryptedMessage)
    def decrypt_message(self, n, nonce, message, msg_hmac):
        n = self._convert_prime(n)
        return self.call(proto.DecryptMessage(address_n=n, nonce=nonce, message=message, hmac=msg_hmac))

    @field('value')
    @expect(proto.CipheredKeyValue)
    def encrypt_keyvalue(self, n, key, value, ask_on_encrypt=True, ask_on_decrypt=True, iv=b''):
        n = self._convert_prime(n)
        return self.call(proto.CipherKeyValue(address_n=n,
                                              key=key,
                                              value=value,
                                              encrypt=True,
                                              ask_on_encrypt=ask_on_encrypt,
                                              ask_on_decrypt=ask_on_decrypt,
                                              iv=iv))

    @field('value')
    @expect(proto.CipheredKeyValue)
    def decrypt_keyvalue(self, n, key, value, ask_on_encrypt=True, ask_on_decrypt=True, iv=b''):
        n = self._convert_prime(n)
        return self.call(proto.CipherKeyValue(address_n=n,
                                              key=key,
                                              value=value,
                                              encrypt=False,
                                              ask_on_encrypt=ask_on_encrypt,
                                              ask_on_decrypt=ask_on_decrypt,
                                              iv=iv))

    @field('tx_size')
    @expect(proto.TxSize)
    def estimate_tx_size(self, coin_name, inputs, outputs):
        msg = proto.EstimateTxSize()
        msg.coin_name = coin_name
        msg.inputs_count = len(inputs)
        msg.outputs_count = len(outputs)
        return self.call(msg)

    def _prepare_simple_sign_tx(self, coin_name, inputs, outputs):
        msg = proto.SimpleSignTx()
        msg.coin_name = coin_name
        msg.inputs.extend(inputs)
        msg.outputs.extend(outputs)

        known_hashes = []
        for inp in inputs:
            if inp.prev_hash in known_hashes:
                continue

            tx = msg.transactions.add()
            if self.tx_api:
                tx.CopyFrom(self.tx_api.get_tx(binascii.hexlify(inp.prev_hash)))
            else:
                raise Exception('TX_API not defined')
            known_hashes.append(inp.prev_hash)

        return msg

    def simple_sign_tx(self, coin_name, inputs, outputs):
        msg = self._prepare_simple_sign_tx(coin_name, inputs, outputs)
        return self.call(msg).serialized.serialized_tx

    def _prepare_sign_tx(self, coin_name, inputs, outputs, use_raw_tx):
        tx = types.TransactionType()
        tx.inputs.extend(inputs)
        tx.outputs.extend(outputs)

        txes = {}
        txes[b''] = tx

        known_hashes = []
        for inp in inputs:
            if inp.prev_hash in known_hashes:
                continue

            if self.tx_api:
                if use_raw_tx:
                    txes[inp.prev_hash] = self.tx_api.get_raw_tx(binascii.hexlify(inp.prev_hash))
                else:
                    txes[inp.prev_hash] = self.tx_api.get_tx(binascii.hexlify(inp.prev_hash))
            else:
                raise Exception('TX_API not defined')
            known_hashes.append(inp.prev_hash)

        return txes

    @session
    def sign_tx(self, coin_name, inputs, outputs, version=None, lock_time=None, debug_processor=None, use_raw_tx=False):

        start = time.time()
        txes = self._prepare_sign_tx(coin_name, inputs, outputs, use_raw_tx)

        # Prepare and send initial message
        tx = proto.SignTx()
        tx.inputs_count = len(inputs)
        tx.outputs_count = len(outputs)
        tx.coin_name = coin_name
        if version is not None:
            tx.version = version
        if lock_time is not None:
            tx.lock_time = lock_time
        res = self.call(tx)

        # Prepare structure for signatures
        signatures = [None] * len(inputs)
        serialized_tx = b''

        counter = 0
        while True:
            counter += 1

            if isinstance(res, proto.Failure):
                raise CallException("Signing failed")

            if not isinstance(res, proto.TxRequest):
                raise CallException("Unexpected message")

            # If there's some part of signed transaction, let's add it
            if res.HasField('serialized') and res.serialized.HasField('serialized_tx'):
                log("RECEIVED PART OF SERIALIZED TX (%d BYTES)" % len(res.serialized.serialized_tx))
                serialized_tx += res.serialized.serialized_tx

            if res.HasField('serialized') and res.serialized.HasField('signature_index'):
                if signatures[res.serialized.signature_index] != None:
                    raise Exception("Signature for index %d already filled" % res.serialized.signature_index)
                signatures[res.serialized.signature_index] = res.serialized.signature

            if res.request_type == types.TXFINISHED:
                # Device didn't ask for more information, finish workflow
                break

            # Device asked for one more information, let's process it.
            current_tx = txes[res.details.tx_hash]

            if res.request_type == types.TXMETA:
                if use_raw_tx:
                    msg = types.RawTransactionType(payload=binascii.unhexlify(current_tx))
                    res = self.call(proto.RawTxAck(tx=msg))
                else:
                    msg = types.TransactionType()
                    msg.version = current_tx.version
                    msg.lock_time = current_tx.lock_time
                    msg.inputs_cnt = len(current_tx.inputs)
                    if res.details.tx_hash:
                        msg.outputs_cnt = len(current_tx.bin_outputs)
                    else:
                        msg.outputs_cnt = len(current_tx.outputs)
                    msg.extra_data_len = len(current_tx.extra_data)
                    res = self.call(proto.TxAck(tx=msg))
                continue

            elif res.request_type == types.TXINPUT:
                msg = types.TransactionType()
                msg.inputs.extend([current_tx.inputs[res.details.request_index], ])
                res = self.call(proto.TxAck(tx=msg))
                continue

            elif res.request_type == types.TXOUTPUT:
                msg = types.TransactionType()
                if res.details.tx_hash:
                    msg.bin_outputs.extend([current_tx.bin_outputs[res.details.request_index], ])
                else:
                    msg.outputs.extend([current_tx.outputs[res.details.request_index], ])

                if debug_processor != None:
                    # If debug_processor function is provided,
                    # pass thru it the request and prepared response.
                    # This is useful for unit tests, see test_msg_signtx
                    msg = debug_processor(res, msg)

                res = self.call(proto.TxAck(tx=msg))
                continue

            elif res.request_type == types.TXEXTRADATA:
                o, l = res.details.extra_data_offset, res.details.extra_data_len
                msg = types.TransactionType()
                msg.extra_data = current_tx.extra_data[o:o + l]
                res = self.call(proto.TxAck(tx=msg))
                continue

        if None in signatures:
            raise Exception("Some signatures are missing!")

        log("SIGNED IN %.03f SECONDS, CALLED %d MESSAGES, %d BYTES" % \
                (time.time() - start, counter, len(serialized_tx)))

        return (signatures, serialized_tx)

    @field('message')
    @expect(proto.Success)
    def wipe_device(self):
        ret = self.call(proto.WipeDevice())
        self.init_device()
        return ret

    @field('message')
    @expect(proto.Success)
    def recovery_device(self, use_trezor_method, word_count, passphrase_protection, pin_protection, label, language):
        if self.features.initialized:
            raise Exception("Device is initialized already. Call wipe_device() and try again.")
        if not use_trezor_method:
            word_count = 0
        elif word_count not in (12, 18, 24):
            raise Exception("Invalid word count. Use 12/18/24")

        res = self.call(proto.RecoveryDevice(word_count=int(word_count),
                                    passphrase_protection=bool(passphrase_protection),
                                    pin_protection=bool(pin_protection),
                                    label=label,
                                    language=language,
                                    enforce_wordlist=True,
                                    use_character_cipher=bool(not use_trezor_method)))

        self.init_device()
        return res

    @field('message')
    @expect(proto.Success)
    @session
    def reset_device(self, display_random, strength, passphrase_protection, pin_protection, label, language):
        if self.features.initialized:
            raise Exception("Device is initialized already. Call wipe_device() and try again.")

        # Begin with device reset workflow
        msg = proto.ResetDevice(display_random=display_random,
                                strength=strength,
                                language=language,
                                passphrase_protection=bool(passphrase_protection),
                                pin_protection=bool(pin_protection),
                                label=label)

        resp = self.call(msg)
        if not isinstance(resp, proto.EntropyRequest):
            raise Exception("Invalid response, expected EntropyRequest")

        external_entropy = self._get_local_entropy()
        log("Computer generated entropy: " + binascii.hexlify(external_entropy).decode('ascii'))
        ret = self.call(proto.EntropyAck(entropy=external_entropy))
        self.init_device()
        return ret

    @field('message')
    @expect(proto.Success)
    def load_device_by_mnemonic(self, mnemonic, pin, passphrase_protection, label, language, skip_checksum=False):
        m = Mnemonic('english')
        if not skip_checksum and not m.check(mnemonic):
            raise Exception("Invalid mnemonic checksum")

        # Convert mnemonic to UTF8 NKFD
        mnemonic = Mnemonic.normalize_string(mnemonic)

        # Convert mnemonic to ASCII stream
        mnemonic = normalize_nfc(mnemonic)

        if self.features.initialized:
            raise Exception("Device is initialized already. Call wipe_device() and try again.")

        resp = self.call(proto.LoadDevice(mnemonic=mnemonic, pin=pin,
                                          passphrase_protection=passphrase_protection,
                                          language=language,
                                          label=label,
                                          skip_checksum=skip_checksum))
        self.init_device()
        return resp

    @field('message')
    @expect(proto.Success)
    def load_device_by_xprv(self, xprv, pin, passphrase_protection, label, language):
        if self.features.initialized:
            raise Exception("Device is initialized already. Call wipe_device() and try again.")

        if xprv[0:4] not in ('xprv', 'tprv'):
            raise Exception("Unknown type of xprv")

        if len(xprv) < 100 and len(xprv) > 112:
            raise Exception("Invalid length of xprv")

        node = types.HDNodeType()
        data = binascii.hexlify(tools.b58decode(xprv, None))

        if data[90:92] != b'00':
            raise Exception("Contain invalid private key")

        checksum = binascii.hexlify(hashlib.sha256(hashlib.sha256(binascii.unhexlify(data[:156])).digest()).digest()[:4])
        if checksum != data[156:]:
            raise Exception("Checksum doesn't match")

        # version 0488ade4
        # depth 00
        # fingerprint 00000000
        # child_num 00000000
        # chaincode 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
        # privkey   00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
        # checksum e77e9d71

        node.depth = int(data[8:10], 16)
        node.fingerprint = int(data[10:18], 16)
        node.child_num = int(data[18:26], 16)
        node.chain_code = binascii.unhexlify(data[26:90])
        node.private_key = binascii.unhexlify(data[92:156])  # skip 0x00 indicating privkey

        resp = self.call(proto.LoadDevice(node=node,
                                          pin=pin,
                                          passphrase_protection=passphrase_protection,
                                          language=language,
                                          label=label))
        self.init_device()
        return resp

    def firmware_update(self, fp):
        if self.features.bootloader_mode == False:
            raise Exception("Device must be in bootloader mode")

        resp = self.call(proto.FirmwareErase())
        if isinstance(resp, proto.Failure) and resp.code == types.Failure_FirmwareError:
            return False

        data = fp.read()
        data_hash = hashlib.sha256(data).digest()

        resp = self.call(proto.FirmwareUpload(payload_hash=data_hash, payload=data))

        if isinstance(resp, proto.Success):
            return True

        elif isinstance(resp, proto.Failure) and resp.code == types.Failure_FirmwareError:
            return False

        raise Exception("Unexpected result %s" % resp)

class KeepKeyClient(ProtocolMixin, TextUIMixin, BaseClient):
    pass

class KeepKeyClientDebug(ProtocolMixin, TextUIMixin, DebugWireMixin, BaseClient):
    pass

class KeepKeyDebugClient(ProtocolMixin, DebugLinkMixin, DebugWireMixin, BaseClient):
    pass
