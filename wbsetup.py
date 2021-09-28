from distutils.core import setup
import py2exe

#setup(console=['wait-serv.py'])
setup(
    options = {'py2exe': {'bundle_files': 1, 'compressed': True}},
    console = [{'script': "wait-serv.py"}],
    zipfile = None,
)