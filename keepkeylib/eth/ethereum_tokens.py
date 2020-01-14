#!/bin/env python

from __future__ import print_function
import json
import hashlib
import os.path
import sys

if sys.version_info[0] < 3:
    from io import BytesIO as StringIO
else:
    from io import StringIO

HERE = os.path.dirname(os.path.realpath(__file__))

class ETHTokenTable(object):
    def __init__(self):
        self.tokens = []

    def add_tokens(self, network):
        net_name = network['symbol'].lower()

        dirname = HERE + '/ethereum-lists/src/tokens/%s' % (net_name, )

        if not os.path.exists(dirname):
            return

        for filename in os.listdir(dirname):
            fullpath = os.path.join(dirname, filename)

            if not os.path.isfile(fullpath):
                return

            with open(fullpath, 'r') as f:
                token = json.load(f)

                self.tokens.append(ETHToken(token, network))

    def build(self):
        with open(HERE + '/ethereum_networks.json', 'r') as f:
            networks = json.load(f)

            for network in networks:
                self.add_tokens(network)

    def serialize_c(self, outf):
        for token in self.tokens:
            token.serialize_c(outf)

def is_ascii(s):
    return all(ord(c) < 128 for c in s)

class ETHToken(object):
    def __init__(self, token, network):
        self.network = network
        self.token = token

    def serialize_c(self, outf):
        # Device doesn't support printing non-ascii characters
        if not is_ascii(self.token['symbol']):
            return

        chain_id = self.network['chain_id']
        address = str(self.token['address'][2:])
        address = '\\x' + '\\x'.join([address[i:i+2] for i in range(0, len(address), 2)])
        symbol = str(self.token['symbol'])
        decimals = self.token['decimals']
        net_name = self.network['symbol'].lower().encode('utf-8')
        tok_name = self.token['name'].encode('utf-8')

        line = 'X(%d, "%s", " %s", %d) // %s / %s' % (chain_id, address, symbol, decimals, net_name, tok_name)
        print(line, file=outf)


def main():
    if len(sys.argv) != 2:
        print("Usage:\n\tpython %s ethereum_tokens.def" % (__file__,))
        sys.exit(-1)

    out_filename = sys.argv[1]
    outf = StringIO()

    table = ETHTokenTable()
    table.build()
    table.serialize_c(outf)
    print('#undef X', file=outf)

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
