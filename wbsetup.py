from distutils.core import setup
import py2exe

setup(console=['wait-serv.py'])
options = {
        "py2exe": {
            "dist_dir": "./windows/dist"
        }}
