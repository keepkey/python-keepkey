python-keepkey
==============

Client side implementation for KeepKey-compatible Bitcoin hardware wallets.

This is a modified version of python-trezor.  The changes made were to 
support KeepKey's protocol, as well as the additional feature set
of KeepKey.  For example, by default, device_recovery command invokes
KeepKey's style of device recovery using the Recovery Cipher.

See http://www.keepkey.com for more information.

Example
-------

also found in ``helloworld.py``

.. code:: python

  #!/usr/bin/env python

  from keepkeylib.client import KeepKeyClient
  from keepkeylib.transport_hid import HidTransport

  def main():
      # List all connected KeepKeys on USB
      devices = HidTransport.enumerate()

      # Check whether we found any
      if len(devices) == 0:
          print('No KeepKey found')
          return

      # Use first connected device
      transport = HidTransport(devices[0])

      # Creates object for manipulating KeepKey
      client = KeepKeyClient(transport)

      # Print out KeepKey's features and settings
      print(client.features)

      # Get the first address of first BIP44 account
      # (should be the same address as shown in KeepKey wallet Chrome extension)
      bip32_path = client.expand_path("44'/0'/0'/0/0")
      address = client.get_address('Bitcoin', bip32_path)
      print('Bitcoin address:', address)

      client.close()

  if __name__ == '__main__':
      main()

PIN Entering
------------

When you are asked for PIN, you have to enter scrambled PIN. Follow the numbers shown on KeepKey display and enter the their positions using the numeric keyboard mapping:

=== === ===
 7   8   9
 4   5   6
 1   2   3
=== === ===

Example: your PIN is **1234** and KeepKey is displaying the following:

=== === ===
 2   8   3
 5   4   6
 7   9   1
=== === ===

You have to enter: **3795**

How to install (Windows)
------------------------
* Install Python 2.7 (http://python.org)
* Run C:\\python27\\scripts\\pip.exe install cython
* Install Microsoft Visual C++ Compiler for Python 2.7
* Clone repository (using TortoiseGit) to local directory
* Run C:\\python27\\python.exe setup.py install (or develop)

How to install (Debian-Ubuntu)
------------------------------
* sudo apt-get install python-dev python-setuptools cython libusb-1.0-0-dev libudev-dev git
* git clone https://github.com/keepkey/python-keepkey.git
* cd python-keepkey
* python setup.py install (or develop)
