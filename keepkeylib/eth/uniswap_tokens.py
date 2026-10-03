#!/usr/bin/env python3

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

HERE = os.path.dirname(os.path.realpath(__file__))

class USETHTokenTable(object):
    def __init__(self):
        self.ustoks = []

    def build(self):
        # uniswap_tokens.json is exported from the shapeshift axiom database.
        with open(HERE + '/uniswap_tokens.json', 'r') as json_file:
            ustoksjson = json.load(json_file)

        for token in ustoksjson:
            self.ustoks.append(USETHToken(token))

    def serialize_c(self):
        # Flash budget -- see token_policy.
        # Run as a standalone script by the build, so there is no package
        # context for a relative import.
        import os as _os, sys as _s
        _s.path.insert(0, _os.path.dirname(_os.path.realpath(__file__)))
        import token_policy
        import sys as _sys
        chosen, ambiguous = token_policy.select(
            self.ustoks,
            token_policy.BUDGET_UNISWAP_LIST,
            symbol_of=lambda t: t.token.get('symbol', ''),
            address_of=lambda t: t.token['contractAddress'].lower(),
            # This list is mainnet-only (serialize_c hardcodes chain_id 1),
            # so the chain component is constant rather than absent.
            chain_of=lambda t: 1)
        print('uniswap_tokens: %d of %d kept (budget %d)'
              % (len(chosen), len(self.ustoks),
                 token_policy.BUDGET_UNISWAP_LIST), file=_sys.stderr)
        if ambiguous:
            print('uniswap_tokens: priority symbols DROPPED as ambiguous: %s'
                  % ', '.join(sorted(ambiguous)), file=_sys.stderr)
        ser_list = []
        for token in sorted(chosen, key=lambda t: t.token['contractAddress']):
            ser_list.append(token.serialize_c())
        return(ser_list)


def writeout(toklist, outf):
    for line in toklist:
        pline = 'X(%d, "%s", " %s", %d) // %s / %s' % (line[0], line[1], line[2], line[3], line[4], line[5])
        print(pline, file=outf)


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
        chain_id = 1  # all on main eth chain
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
