# This file is part of the KeepKey project.
#
# Copyright (C) markrypto
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

import hashlib
import hmac
import base64
import time


### Define SharedSecret, Block size, hashing algorithm, TOTP length and frequency
hash_algo = "sha1"
B = 64
# Generate a TOTP every 30 seconds
F = 30
# Shared Secret
shared_secret = b'BASE32SECRET2345AB'
# OTP Length
Digits = 6
key=base64.b32decode(shared_secret+b'='* (8 - len(shared_secret)%8))
# Control excessive output to console
debug = True
def dbg(data):
    if (debug):
        print(data)

# Prepare time - convert integer to byte
def i2b_time(int_time):
    return int_time.to_bytes(8, byteorder='big')

### Implement the HMAC Algorithm. For details see the rfc2104.ipynb at
# https://github.com/lordloh/OPT_algorithms/blob/master/rfc2104.ipynb

def my_hmac(key, message):
    #print(key.hex())
    #print(message.hex())
    trans_5C = bytes((x ^ 0x5C) for x in range(256))
    trans_36 = bytes((x ^ 0x36) for x in range(256))
    K_zpad=key.ljust(B,b'\0')    
    K_ipad=K_zpad.translate(trans_36)
    K_opad=K_zpad.translate(trans_5C)
    hash1 = hashlib.new(hash_algo, K_ipad+message).digest()
    hmac_hash = hashlib.new(hash_algo, K_opad + hash1).digest()
    return hmac_hash
### Dynamic Truncation

def dynamic_truncate(b_hash):
    hash_len=len(b_hash)
    int_hash = int.from_bytes(b_hash, byteorder='big')
    #print("int_hash", int_hash)
    offset = int_hash & 0xF
    #print("offset", offset)
    # Geterate a mask to get bytes from left to right of the hash
    n_shift = 8*(hash_len-offset)-32
    MASK = 0xFFFFFFFF << n_shift
    hex_mask = "0x"+("{:0"+str(2*hash_len)+"x}").format(MASK)
    P = (int_hash & MASK)>>n_shift   # Get rid of left zeros
    LSB_31 = P & 0x7FFFFFFF          # Return only the lower 31 bits
    return LSB_31

# function wrapper to run the HOTP algorithm multiple times for different counter value
def generate_TOTP(time_val):
    # %30 seconds
    T = i2b_time(int(time_val/F))
    # Same algorithm as HOTP
    hmac_hash = my_hmac(key,T)
    #print("hmac_hash", hmac_hash.hex())
    trc_hash = dynamic_truncate(hmac_hash)        # Get truncated hash (int)
    #print("trc_hash", trc_hash)
    # Adjust TOTP length
    TOTP = ("{:0"+str(Digits)+"}").format(trc_hash % (10**Digits))
    #DEL dbg("\n***** ADJUST DIGITS *****\n"+str(trc_hash)+" % 10 ^ "+str(Digits)+"\nHOPT : "+HOTP)
    return TOTP

def main():

    # Google Authenticator Compatibility (BASE-32)
    # dbg("Key Base32 Decode :")
    # dbg(key)

    # Generate TOTP for current time
    # T0 = int(time.time())
    T0 = 1535317397
    T1 = T0 + F # F seconds later...
    myTOTP0=generate_TOTP(T0)
    # myTOTP1=generate_TOTP(T1)

    # Similarly, lets generate HOTPs for counter = 3..10 without a lot of output messages.
    debug=False
    # myTOTPs=[(generate_TOTP(x)) for x in range(T1+F,T1+F*5,F)]
    # myTOTPs.insert(0,myTOTP0)
    # myTOTPs.insert(1,myTOTP1)

    #print(myTOTPs)
    print(myTOTP0)
    print(" ")
    
    print(generate_TOTP(1536262427))

    
    # T = 1535317397
    # while True:
    #     print(T, "   ",  generate_TOTP(T))
    #     T = T + 30
    
if __name__ == '__main__':
    main()
