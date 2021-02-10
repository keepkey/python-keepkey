#!/bin/env python3

from __future__ import print_function
import json
import hashlib
import os.path
import sys
import requests

if sys.version_info[0] < 3:
    from io import BytesIO as StringIO
else:
    from io import StringIO

class USETHTokenTable(object):
    def __init__(self):
        self.ustoks = []

    def build(self):
        # uniswap_tokens.json is exported from the shapeshift axiom database.
        with open('uniswap_tokens.json') as json_file:
            ustoksjson = json.load(json_file)

        for token in ustoksjson:
            self.ustoks.append(USETHToken(token))

    def serialize_c(self):
        ser_list = []
        for token in sorted(self.ustoks, key=lambda t: t.token['contractAddress']):
            ser_list.append(token.serialize_c())
        return(ser_list)


def writeout(toklist, outf):
    for line in toklist:
        print(line, file=outf)

def is_ascii(s):
    return all(ord(c) < 128 for c in s)

class USETHToken(object):
    def __init__(self, token):
        self.token = token

    def serialize_c(self):
        # Device doesn't support printing non-ascii characters
        if not is_ascii(self.token['symbol']):
            return

        # exported json file must match format in uniswap_tokens.def
        chain_id = '1'  # all on main eth chain
        address = str(self.token['contractAddress'][2:])
        address = '\\x' + '\\x'.join([address[i:i+2] for i in range(0, len(address), 2)])
        symbol = str(self.token['symbol'])
        decimals = self.token['precision']
        net_name = 'eth'.lower().encode('utf-8')
        tok_name = self.token['identifier'].encode('utf-8')

        line = (chain_id, address, symbol, decimals, net_name, tok_name)
        return(line)

def main():
    if len(sys.argv) != 2:
        print("Usage:\n\tpython %s uniswap_tokens.def" % (__file__,))
        sys.exit(-1)

    out_filename = sys.argv[1]
    outf = StringIO()

    table = USETHTokenTable()
    table.build()

    usset = table.serialize_c()
    writeout(usset, outf)

    if os.path.isfile(out_filename):
        with open(out_filename, 'r') as inf:
            in_digest = hashlib.sha256(inf.read().encode('utf-8')).hexdigest()
            out_digest = hashlib.sha256(outf.getvalue().encode('utf-8')).hexdigest()
            if in_digest == out_digest:
                print(out_filename + ": Already up to date")
                return

    print(out_filename + ": Updating")

    with open(out_filename, 'w') as f:
        print(outf.getvalue(), file=f, end='')

if __name__ == "__main__":
    main()
