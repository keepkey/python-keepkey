
KeepKey Authenticator
==============
The KeepKey Authenticator is a standalone app intended to demo the authenticator feature. 
It enables the KeepKey device to perform as a hardware off-line one-time passcode (OTP) generator for two factor authentication using the TOPT algorithm. The KeepKey PIN and physical button gives it security features similar to other products such as the Yubikey, but with better PIN security.

Build for MacOS - Intel
-----------------------
Make sure you have python-keepkey built and installed:

    $ python python-keepkey/setup.py build install

KeepKeyAuthenticator.app is built using py2app. The setup file was created from the command line:

    $ py2applet --make-setup KeepKeyAuthenticator.py authResources/*.png

and then saved as setupAuth.py. NOTE: Creating the setup.py file in this manner will overwrite
the existing setup.py file if one exists.

Create the app:

    $ python setup.py py2app

Build for MacOS - M1
--------------------
from https://py2app.readthedocs.io/_/downloads/en/stable/pdf/

M1 Macs and libraries not available for arm64 A lot of libraries are not yet available as arm64 or universal2 libraries. For applications using those libraries you can create an x86_64 (Intel) application instead: 
1. Create a new virtual environment and activate this 
2. Use arch -x86_64 python -mpip install ... to install libraries. 
    The arch command is necessary here to ensure that pip selects variants that are compatible with the x86_64 architecture instead of arm64. 
3. Use arch -x86_64 python setup.py py2app --arch x86_64 to build 
This results in an application bundle where the launcher is an x86_64 only binary, and where included C extensions and libraries are compatible with that architecture as well.