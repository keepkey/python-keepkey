import sys
from ctypes.util import find_library
from ctypes import *
import struct

SHA_LBLOCK = 64
SHA256_DIGEST_LENGTH = 32

class SHA256_CTX(Structure):
    _fields_ = [
        ("h", c_long * 8),
        ("Nl", c_longlong),
        ("Nh", c_long),
        ("data", c_byte * SHA_LBLOCK),
        ("num", c_longlong),
        ("md_len", c_uint)
    ]
    def buffer(self):
        return buffer(self)[40:104]
    def state(self):
        return buffer(self)[:32]
    def bitcount(self):
        return buffer(self)[32:40]

class sha256(object):
    digest_size = SHA256_DIGEST_LENGTH

    def __init__(self, datastr=None):
        self.load_openssl()
        self.ctx = SHA256_CTX()
        self.openssl.SHA256_Init(byref(self.ctx))
        if datastr:
            self.update(datastr)

    def load_openssl(self):
        if sys.platform.startswith('win'):
            crypto = find_library('libeay32')
        else:
            crypto = find_library('crypto')

        if crypto is None:
            raise OSError("Cannot find OpenSSL library")

        self.openssl = cdll.LoadLibrary(crypto)

    def update(self, datastr):
        self.openssl.SHA256_Update(byref(self.ctx), datastr, c_int(len(datastr)))

    def get_ctx_bin(self):
        return self.ctx.state() + self.ctx.bitcount() + self.ctx.buffer()