#!/usr/bin/env python3
"""
Complete Zcash v5 (NU6) transaction test with proper scriptPubKey
This test addresses the root cause where firmware needs the actual UTXO's
scriptPubKey for correct ZIP-244 sighash computation.

Reference: ROOT_CAUSE_ANALYSIS_v2.md
"""
import sys
import os
import binascii
import requests
from hashlib import sha256

# Setup paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'deps/python-keepkey'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'deps/python-keepkey/tests'))

import config
from keepkeylib.client import KeepKeyClient, KeepKeyDebuglinkClient
import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib import tx_api

tx_api.cache_dir = 'txcache'

# Zcash node configuration
RPC_URL = os.getenv('ZCASH_RPC_URL', 'http://100.117.181.111:8232')
RPC_USER = os.getenv('ZCASH_RPC_USER', 'zcash')
RPC_PASS = os.getenv('ZCASH_RPC_PASS', '78787ba819a382122e2b4fd98e68db3419ba7cf11c3f22f3bcd07e5ac606e630')

def rpc_call(method, params=[]):
    """Make RPC call to zcashd node"""
    payload = {
        "jsonrpc": "1.0",
        "id": "python",
        "method": method,
        "params": params
    }
    response = requests.post(
        RPC_URL,
        json=payload,
        auth=(RPC_USER, RPC_PASS),
        timeout=30
    )
    result = response.json()

    if result.get("error"):
        raise Exception(f"RPC error: {result['error']}")

    return result["result"]

def get_utxo_details(txid, vout):
    """Get UTXO details including scriptPubKey from blockchain"""
    print(f"  Fetching UTXO: {txid}:{vout}", flush=True)

    # Get the full transaction (1 = verbose, 0 = hex only)
    tx = rpc_call("getrawtransaction", [txid, 1])

    # Get the specific output
    if vout >= len(tx['vout']):
        raise Exception(f"Output {vout} not found in transaction")

    output = tx['vout'][vout]

    # Extract scriptPubKey hex
    scriptpubkey_hex = output['scriptPubKey']['hex']
    scriptpubkey_bytes = binascii.unhexlify(scriptpubkey_hex)

    # Get amount (in satoshis)
    amount = int(output['value'] * 100000000)

    print(f"    Amount: {amount} satoshis ({output['value']} ZEC)")
    print(f"    scriptPubKey: {scriptpubkey_hex}")

    return {
        'amount': amount,
        'scriptpubkey': scriptpubkey_bytes,
        'scriptpubkey_hex': scriptpubkey_hex,
        'address': output['scriptPubKey'].get('addresses', ['unknown'])[0]
    }

def compare_sighashes(firmware_sighash, expected_sighash):
    """Compare firmware sighash with expected value"""
    print("\n=== SIGHASH COMPARISON ===")
    print(f"Firmware:  {firmware_sighash}")
    print(f"Expected:  {expected_sighash}")

    if firmware_sighash == expected_sighash:
        print("✅ SIGHASH MATCH!")
        return True
    else:
        print("❌ SIGHASH MISMATCH!")
        return False

def test_v5_signing():
    """Test Zcash v5 transaction signing with proper scriptPubKey"""

    print("=" * 70)
    print("ZCASH V5 TRANSACTION SIGNING TEST")
    print("=" * 70)

    # Step 1: Connect to emulator
    print("\nStep 1: Connecting to KeepKey emulator...")

    # Create transport
    transport = config.TRANSPORT(*config.TRANSPORT_ARGS, **config.TRANSPORT_KWARGS)

    # Create debug client if debug transport is available
    if hasattr(config, 'DEBUG_TRANSPORT'):
        debug_transport = config.DEBUG_TRANSPORT(*config.DEBUG_TRANSPORT_ARGS, **config.DEBUG_TRANSPORT_KWARGS)
        client = KeepKeyDebuglinkClient(transport)
        client.set_debuglink(debug_transport)
    else:
        client = KeepKeyClient(transport)

    client.set_tx_api(tx_api.TxApiBitcoin)
    print("  ✓ Connected")

    # Step 2: Initialize with test mnemonic
    print("\nStep 2: Initializing device...")

    # Wipe device first
    client.wipe_device()

    # Load mnemonic
    client.load_device_by_mnemonic(
        mnemonic='all all all all all all all all all all all all',
        pin='',
        passphrase_protection=False,
        label='ZcashV5Test',
        language='english'
    )
    print("  ✓ Device initialized")

    # Step 3: Get address
    print("\nStep 3: Getting Zcash address...")
    # Using path m/0/0 for Exodus address
    SOURCE_PATH = [0, 0]
    address = client.get_address('Zcash', SOURCE_PATH)
    print(f"  Address: {address}")

    # Step 4: Get current block height for expiry
    print("\nStep 4: Getting blockchain info...")
    blockchain_info = rpc_call("getblockchaininfo")
    current_height = blockchain_info['blocks']
    expiry_height = current_height + 40
    print(f"  Current height: {current_height}")
    print(f"  Expiry height: {expiry_height}")

    # Step 5: Get available UTXOs for the address
    print("\nStep 5: Finding UTXOs...")
    try:
        # Try to get UTXOs using listunspent (accept 0 confirmations for testing)
        utxos = rpc_call("listunspent", [0, 9999999, [address]])
        if not utxos:
            print(f"  ❌ No UTXOs found for {address}")
            print("  Please send some testnet ZEC to this address first")
            return False
    except Exception as e:
        print(f"  ❌ Error fetching UTXOs: {e}")
        return False

    # Sort by confirmations (prefer confirmed UTXOs to avoid getrawtransaction issues)
    utxos.sort(key=lambda x: x.get('confirmations', 0), reverse=True)

    # Use first UTXO (most confirmed)
    utxo = utxos[0]
    print(f"  ✓ Found {len(utxos)} UTXO(s), using most confirmed one")
    print(f"    TXID: {utxo['txid']}")
    print(f"    VOUT: {utxo['vout']}")
    print(f"    Amount: {utxo['amount']} ZEC")
    print(f"    Confirmations: {utxo.get('confirmations', 0)}")

    # Step 6: Get detailed UTXO info including scriptPubKey
    print("\nStep 6: Fetching UTXO details...")
    utxo_details = get_utxo_details(utxo['txid'], utxo['vout'])

    # Step 7: Create transaction inputs with scriptPubKey
    print("\nStep 7: Creating transaction inputs...")

    UTXO_TXID = utxo['txid']
    UTXO_VOUT = utxo['vout']
    UTXO_AMOUNT = utxo_details['amount']
    UTXO_SCRIPTPUBKEY = utxo_details['scriptpubkey']

    # CRITICAL: Provide the actual UTXO's scriptPubKey for ZIP-244 signing
    inp1 = proto_types.TxInputType(
        address_n=SOURCE_PATH,
        prev_hash=binascii.unhexlify(UTXO_TXID),
        prev_index=UTXO_VOUT,
        amount=UTXO_AMOUNT,
        script_pubkey=UTXO_SCRIPTPUBKEY  # ← This is the critical fix!
    )

    print(f"  ✓ Input created with scriptPubKey: {utxo_details['scriptpubkey_hex']}")

    # Step 8: Create transaction outputs
    print("\nStep 8: Creating transaction outputs...")

    # Calculate amounts based on UTXO size
    FEE = 10000  # 0.0001 ZEC (standard fee)
    SEND_AMOUNT = (UTXO_AMOUNT - FEE) // 2  # Send half, keep half as change
    CHANGE_AMOUNT = UTXO_AMOUNT - SEND_AMOUNT - FEE

    DEST_ADDRESS = "t1d3URKgTufDFhEr8pxm388kVjw1V4Ba1Ez"

    out1 = proto_types.TxOutputType(
        address=DEST_ADDRESS,
        amount=SEND_AMOUNT,
        script_type=proto_types.PAYTOADDRESS,
    )

    out2 = proto_types.TxOutputType(
        address=address,  # Change back to source
        amount=CHANGE_AMOUNT,
        script_type=proto_types.PAYTOADDRESS,
    )

    print(f"  Output 1: {SEND_AMOUNT/100000000} ZEC to {DEST_ADDRESS}")
    print(f"  Output 2: {CHANGE_AMOUNT/100000000} ZEC (change) to {address}")
    print(f"  Fee: {FEE/100000000} ZEC")

    # Step 9: Sign transaction with v5 format
    print("\nStep 9: Signing transaction (version 5)...")

    try:
        (signatures, serialized_tx) = client.sign_tx(
            'Zcash',
            [inp1],
            [out1, out2],
            version=5,  # ← Use v5 for NU6
            lock_time=0,
            expiry=expiry_height
        )

        tx_hex = binascii.hexlify(serialized_tx).decode('ascii')
        print(f"  ✓ Transaction signed successfully!")
        print(f"  Transaction length: {len(serialized_tx)} bytes")
        print(f"  TX hex: {tx_hex[:100]}...")

    except Exception as e:
        print(f"  ❌ Signing failed: {e}")
        return False

    # Step 10: Read firmware debug output
    print("\nStep 10: Reading firmware debug output...")
    firmware_sighash = None
    if os.path.exists('/tmp/zip244_debug.txt'):
        with open('/tmp/zip244_debug.txt', 'r') as f:
            debug_output = f.read()
            print("=== FIRMWARE ZIP-244 DEBUG OUTPUT ===")
            print(debug_output)

            # Extract sighash from debug output
            for line in debug_output.split('\n'):
                if line.startswith('signature_digest:'):
                    firmware_sighash = line.split(':')[1].strip()
                    break
    else:
        print("  ⚠️  Debug file not found at /tmp/zip244_debug.txt")

    # Step 11: Decode transaction to verify structure
    print("\nStep 11: Decoding transaction structure...")
    try:
        decoded = rpc_call("decoderawtransaction", [tx_hex])
        print(f"  ✓ Transaction decoded successfully")
        print(f"    Version: {decoded['version']}")
        print(f"    Inputs: {len(decoded['vin'])}")
        print(f"    Outputs: {len(decoded['vout'])}")
        print(f"    Lock time: {decoded['locktime']}")
        print(f"    Expiry: {decoded.get('expiryheight', 'N/A')}")
    except Exception as e:
        print(f"  ❌ Failed to decode transaction: {e}")
        return False

    # Step 12: Broadcast transaction (the ultimate validation!)
    print("\nStep 12: Broadcast transaction to network?")
    print(f"  This will send a real transaction to the Zcash network!")
    response = input("  Type 'yes' to broadcast: ")

    if response.lower() == 'yes':
        try:
            txid = rpc_call("sendrawtransaction", [tx_hex])
            print(f"  ✅ Transaction broadcast successfully!")
            print(f"     TXID: {txid}")
            print(f"     Explorer: https://zcashblockexplorer.com/transactions/{txid}")
        except Exception as e:
            print(f"  ❌ Broadcast failed: {e}")
            return False
    else:
        print("  Skipping broadcast")

    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)

    return True

if __name__ == "__main__":
    try:
        success = test_v5_signing()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
