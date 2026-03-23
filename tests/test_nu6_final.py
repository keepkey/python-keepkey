#!/usr/bin/env python3
"""
Final test: Sign and automatically broadcast NU6 transaction
"""

import sys
import os

# Add python-keepkey to path
sys.path.insert(0, 'deps/python-keepkey')
sys.path.insert(0, 'deps/python-keepkey/tests')

from keepkeylib.client import KeepKeyClient
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2
import config
import binascii
import requests
import json

# Zcash RPC
RPC_USER = "zcashrpc"
RPC_PASSWORD = "your_password_here"
RPC_HOST = "100.117.181.111"
RPC_PORT = 8232

def rpc_call(method, params=[]):
    url = f"http://{RPC_HOST}:{RPC_PORT}/"
    headers = {'content-type': 'application/json'}
    payload = {
        "jsonrpc": "2.0",
        "id": "test",
        "method": method,
        "params": params
    }
    response = requests.post(url, auth=(RPC_USER, RPC_PASSWORD),
                           headers=headers, data=json.dumps(payload))
    return response.json()

def main():
    print("=" * 70)
    print("NU6 FIRMWARE TEST - AUTOMATIC BROADCAST")
    print("=" * 70)

    # Get device using config (same as working test)
    transport = config.TRANSPORT(*config.TRANSPORT_ARGS, **config.TRANSPORT_KWARGS)
    client = KeepKeyClient(transport)

    # Get address
    address = client.get_address("Zcash", [0x80000000 | 133, 0x80000000, 0x80000000, 0, 0])
    print(f"\n✓ Address: {address}")

    # Get blockchain info
    info = rpc_call("getblockchaininfo")
    height = info['result']['blocks']
    expiry_height = height + 40
    print(f"✓ Height: {height}, Expiry: {expiry_height}")

    # Find UTXO
    utxos = rpc_call("listunspent", [0, 9999999, [address]])
    if not utxos['result']:
        print("❌ No UTXOs found")
        return False

    utxo = utxos['result'][0]
    print(f"✓ Using UTXO: {utxo['txid']}:{utxo['vout']}")
    print(f"  Amount: {utxo['amount']} ZEC")

    # Get scriptPubKey
    tx = rpc_call("getrawtransaction", [utxo['txid'], 1])
    output = tx['result']['vout'][utxo['vout']]
    scriptpubkey_hex = output['scriptPubKey']['hex']
    scriptpubkey_bytes = binascii.unhexlify(scriptpubkey_hex)

    print(f"  ScriptPubKey: {scriptpubkey_hex}")

    # Create input
    amount = int(utxo['amount'] * 100000000)
    inp = proto.TxInputType(
        address_n=[0x80000000 | 133, 0x80000000, 0x80000000, 0, 0],
        prev_hash=binascii.unhexlify(utxo['txid'])[::-1],
        prev_index=utxo['vout'],
        amount=amount,
        script_type=types_pb2.SPENDADDRESS,
        sequence=0xffffffff,
        script_pubkey=scriptpubkey_bytes  # Critical for NU6!
    )

    # Create outputs
    out_amount = 45000
    fee = 10000
    change = amount - out_amount - fee

    out1 = proto.TxOutputType(
        address="t1d3URKgTufDFhEr8pxm388kVjw1V4Ba1Ez",
        amount=out_amount,
        script_type=types_pb2.PAYTOADDRESS
    )

    out2 = proto.TxOutputType(
        address=address,
        amount=change,
        script_type=types_pb2.PAYTOADDRESS
    )

    print(f"\n✓ Outputs:")
    print(f"  1: {out_amount} sats")
    print(f"  2: {change} sats (change)")
    print(f"  Fee: {fee} sats")

    # Sign transaction
    print(f"\n✓ Signing...")
    signed = client.sign_tx("Zcash", [inp], [out1, out2], version=5,
                           version_group_id=0x26A7270A,
                           branch_id=0xC8E71055,
                           lock_time=0,
                           expiry=expiry_height)

    tx_hex = binascii.hexlify(signed[1]).decode()
    print(f"✓ Signed! ({len(tx_hex)//2} bytes)")

    # Write to file
    with open('signed_tx.hex', 'w') as f:
        f.write(tx_hex)
    print(f"✓ Written to signed_tx.hex")

    # Broadcast
    print(f"\n✓ Broadcasting...")
    try:
        result = rpc_call("sendrawtransaction", [tx_hex])
        if 'result' in result:
            txid = result['result']
            print(f"\n🎉 SUCCESS! Transaction broadcast!")
            print(f"   TXID: {txid}")
            print(f"\n✅ MONEY SENT SUCCESSFULLY FROM KEEPKEY FIRMWARE!")
            return True
        else:
            print(f"\n❌ FAILED: {result.get('error', 'Unknown error')}")
            # Try to get more details
            test_result = rpc_call("testmempoolaccept", [[tx_hex]])
            if 'result' in test_result:
                print(f"   Test result: {test_result['result']}")
            return False
    except Exception as e:
        print(f"❌ Error broadcasting: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
