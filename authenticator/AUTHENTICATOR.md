
KeepKey Authenticator
==============
The KeepKey Authenticator is a standalone app that enables the KeepKey device to perform as a 
hardware off-line one-time passcode (OTP) generator for two factor authentication using the 
TOPT algorithm. The KeepKey PIN and physical button gives it security features similar to other
products such as the Yubikey.

Build for MacOS
---------------
Make sure you have python-keepkey built and installed:

    $ python python-keepkey/setup.py build install

KeepKeyAuthenticator.app is built using py2app. The setup file was created from the command line:

    $ py2applet --make-setup KeepKeyAuthenticator.py authResources/*.png

and then saved as setupAuth.py. NOTE: Creating the setup.py file in this manner will overwrite
the existing setup.py file if one exists.

Create the app:

    $ python setupAuth.py py2app
