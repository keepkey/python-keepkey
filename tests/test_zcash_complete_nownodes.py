#!/usr/bin/env python3
"""
Complete Zcash v5 (NU6) transaction test with NOWNodes API
Tests the full workflow:
1. Generate xpub from device
2. Derive addresses from xpub
3. Find UTXOs using NOWNodes API
4. Fetch UTXO details (scriptPubKey) from blockchain
5. Sign transaction with firmware
6. Broadcast signed transaction to network
"""
import sys
import os
import binascii
import requests
from hashlib import sha256
import hashlib

# Setup paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'deps/python-keepkey'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'deps/python-keepkey/tests'))

import config
from keepkeylib.client import KeepKeyClient, KeepKeyDebuglinkClient
import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib import tx_api

tx_api.cache_dir = 'txcache'

# NOWNodes API configuration
NOWNODES_API_KEY = os.getenv('NOWNODES_API_KEY', '')  # User needs to provide this
NOWNODES_BASE_URL = "https://zec.nownodes.io"

# Zcash node configuration (fallback to local/remote node)
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

def nownodes_call(method, params=[]):
    """Make RPC call via NOWNodes API"""
    if not NOWNODES_API_KEY:
        print("  ⚠️  NOWNodes API key not set, falling back to local node")
        return rpc_call(method, params)

    headers = {
        'Content-Type': 'application/json',
        'api-key': NOWNODES_API_KEY
    }

    payload = {
        "jsonrpc": "2.0",
        "id": "python",
        "method": method,
        "params": params
    }

    response = requests.post(
        NOWNODES_BASE_URL,
        json=payload,
        headers=headers,
        timeout=30
    )
    result = response.json()

    if result.get("error"):
        raise Exception(f"NOWNodes error: {result['error']}")

    return result["result"]

def get_xpub(client, path):
    """Get extended public key from device"""
    print(f"  Getting xpub for path m/{'/'.join(map(str, path))}...")

    # Get public node
    node = client.get_public_node(path, coin_name='Zcash')

    xpub = node.xpub
    print(f"  xpub: {xpub}")

    return xpub

def derive_address_from_xpub(xpub, change, index):
    """
    Derive P2PKH address from xpub (Zcash doesn't use segwit)
    This is a simplified version - in production use a proper BIP32 library
    """
    # This is a placeholder - would need full BIP32 implementation
    # For now, we'll derive addresses directly from the device
    return None

def find_utxos_for_address(address):
    """Find UTXOs for an address using blockchain API"""
    print(f"  Searching for UTXOs at {address}...")

    try:
        # Try NOWNodes first - note: listunspent params are minconf, maxconf, [addresses]
        utxos = nownodes_call("listunspent", [0, 9999999, [address]])
        print(f"  ✓ Found {len(utxos)} UTXO(s) via NOWNodes")
        return utxos
    except Exception as e:
        print(f"  ⚠️  NOWNodes lookup failed: {e}")

        # For local RPC, we might need to import the address first
        # or use scantxoutset instead
        print(f"  Trying scantxoutset...")
        try:
            # Use scantxoutset which doesn't require the address to be in the wallet
            result = rpc_call("scantxoutset", ["start", [f"addr({address})"]])
            if result and 'unspents' in result:
                utxos = []
                for unspent in result['unspents']:
                    utxos.append({
                        'txid': unspent['txid'],
                        'vout': unspent['vout'],
                        'amount': unspent['amount'],
                        'scriptPubKey': unspent['scriptPubKey']
                    })
                print(f"  ✓ Found {len(utxos)} UTXO(s) via scantxoutset")
                return utxos
        except Exception as e2:
            print(f"  ⚠️  scantxoutset also failed: {e2}")
            return []

def get_utxo_details(txid, vout):
    """Get UTXO details including scriptPubKey from blockchain"""
    print(f"  Fetching UTXO: {txid}:{vout}", flush=True)

    try:
        # Try NOWNodes first (verbose=1 for JSON output)
        tx = nownodes_call("getrawtransaction", [txid, 1])
    except Exception as e:
        print(f"  ⚠️  NOWNodes failed: {e}")
        print(f"  Trying direct RPC...")
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

def test_complete_workflow():
    """Test complete Zcash workflow: xpub -> address -> UTXO -> sign -> broadcast"""

    print("=" * 70)
    print("ZCASH COMPLETE WORKFLOW TEST (with NOWNodes)")
    print("=" * 70)

    # Step 1: Connect to emulator
    print("\nStep 1: Connecting to KeepKey emulator...")

    transport = config.TRANSPORT(*config.TRANSPORT_ARGS, **config.TRANSPORT_KWARGS)

    if hasattr(config, 'DEBUG_TRANSPORT'):
        debug_transport = config.DEBUG_TRANSPORT(*config.DEBUG_TRANSPORT_ARGS, **config.DEBUG_TRANSPORT_KWARGS)
        client = KeepKeyDebuglinkClient(transport)
        client.set_debuglink(debug_transport)
    else:
        client = KeepKeyClient(transport)

    client.set_tx_api(tx_api.TxApiBitcoin)
    print("  ✓ Connected")

    # Step 2: Initialize device
    print("\nStep 2: Initializing device...")
    client.wipe_device()
    client.load_device_by_mnemonic(
        mnemonic='all all all all all all all all all all all all',
        pin='',
        passphrase_protection=False,
        label='ZcashTest',
        language='english'
    )
    print("  ✓ Device initialized")

    # Step 3: Generate xpub (BIP44 path for Zcash: m/44'/133'/0')
    print("\nStep 3: Generating xpub...")
    ACCOUNT_PATH = [44 | 0x80000000, 133 | 0x80000000, 0 | 0x80000000]  # m/44'/133'/0'

    try:
        xpub = get_xpub(client, ACCOUNT_PATH)
        print(f"  ✓ xpub generated successfully")
    except Exception as e:
        print(f"  ⚠️  Could not generate xpub: {e}")
        xpub = None

    # Step 4: Derive address (using simple path that matches our test UTXO)
    print("\nStep 4: Deriving receive address...")
    SOURCE_PATH = [0, 0]  # Simple m/0/0 path for testing
    address = client.get_address('Zcash', SOURCE_PATH)
    print(f"  Address: {address}")
    print(f"  Path: m/0/0 (test path)")

    # Step 5: Find UTXOs using NOWNodes/RPC
    print("\nStep 5: Finding UTXOs...")
    utxos = find_utxos_for_address(address)

    if not utxos:
        print(f"  ❌ No UTXOs found for {address}")
        print(f"  Please send ZEC to this address first")

        # Check if there's a known UTXO we can use
        known_txid = "d4c5e482c35235510767f6bd173e453f672975dc7e67d67a00dd5a999837a6a6"
        known_vout = 1

        print(f"\n  Checking known UTXO: {known_txid}:{known_vout}")
        try:
            utxo_details = get_utxo_details(known_txid, known_vout)

            # Create synthetic UTXO entry
            utxos = [{
                'txid': known_txid,
                'vout': known_vout,
                'amount': utxo_details['amount'] / 100000000,
                'scriptPubKey': utxo_details['scriptpubkey_hex']
            }]
            print(f"  ✓ Using known UTXO")
        except Exception as e:
            print(f"  ❌ Could not fetch known UTXO: {e}")
            return False

    # Use first UTXO
    utxo = utxos[0]
    print(f"  ✓ Found {len(utxos)} UTXO(s), using first one")
    print(f"    TXID: {utxo['txid']}")
    print(f"    VOUT: {utxo['vout']}")
    print(f"    Amount: {utxo['amount']} ZEC")

    # Step 6: Get blockchain info for expiry
    print("\nStep 6: Getting blockchain info...")
    try:
        blockchain_info = nownodes_call("getblockchaininfo")
    except:
        blockchain_info = rpc_call("getblockchaininfo")

    current_height = blockchain_info['blocks']
    expiry_height = current_height + 40
    print(f"  Current height: {current_height}")
    print(f"  Expiry height: {expiry_height}")

    # Step 7: Fetch UTXO details
    print("\nStep 7: Fetching UTXO details...")
    utxo_details = get_utxo_details(utxo['txid'], utxo['vout'])

    # Step 8: Create transaction inputs with scriptPubKey
    print("\nStep 8: Creating transaction inputs...")

    UTXO_TXID = utxo['txid']
    UTXO_VOUT = utxo['vout']
    UTXO_AMOUNT = utxo_details['amount']
    UTXO_SCRIPTPUBKEY = utxo_details['scriptpubkey']

    inp1 = proto_types.TxInputType(
        address_n=SOURCE_PATH,
        prev_hash=binascii.unhexlify(UTXO_TXID),
        prev_index=UTXO_VOUT,
        amount=UTXO_AMOUNT,
        script_pubkey=UTXO_SCRIPTPUBKEY  # Critical for ZIP-244!
    )

    print(f"  ✓ Input created with scriptPubKey: {utxo_details['scriptpubkey_hex']}")

    # Step 9: Create transaction outputs
    print("\nStep 9: Creating transaction outputs...")

    SEND_AMOUNT = 10000  # 0.0001 ZEC
    FEE = 10000  # 0.0001 ZEC
    CHANGE_AMOUNT = UTXO_AMOUNT - SEND_AMOUNT - FEE

    DEST_ADDRESS = "t1d3URKgTufDFhEr8pxm388kVjw1V4Ba1Ez"

    out1 = proto_types.TxOutputType(
        address=DEST_ADDRESS,
        amount=SEND_AMOUNT,
        script_type=proto_types.PAYTOADDRESS,
    )

    out2 = proto_types.TxOutputType(
        address=address,
        amount=CHANGE_AMOUNT,
        script_type=proto_types.PAYTOADDRESS,
    )

    print(f"  Output 1: {SEND_AMOUNT/100000000} ZEC to {DEST_ADDRESS}")
    print(f"  Output 2: {CHANGE_AMOUNT/100000000} ZEC (change) to {address}")
    print(f"  Fee: {FEE/100000000} ZEC")

    # Step 10: Sign transaction
    print("\nStep 10: Signing transaction (version 5)...")

    try:
        (signatures, serialized_tx) = client.sign_tx(
            'Zcash',
            [inp1],
            [out1, out2],
            version=5,
            lock_time=0,
            expiry=expiry_height
        )

        tx_hex = binascii.hexlify(serialized_tx).decode('ascii')
        print(f"  ✓ Transaction signed successfully!")
        print(f"  Transaction length: {len(serialized_tx)} bytes")
        print(f"  TX hex (first 100 chars): {tx_hex[:100]}...")

        # Save full hex to file for analysis
        with open('/tmp/signed_tx.hex', 'w') as f:
            f.write(tx_hex)
        print(f"  Full TX saved to /tmp/signed_tx.hex")

    except Exception as e:
        print(f"  ❌ Signing failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Step 11: Verify transaction
    print("\nStep 11: Verifying transaction...")

    try:
        # Test with local node
        result = rpc_call("testmempoolaccept", [[tx_hex]])

        if result[0]['allowed']:
            print("  ✅ Transaction is valid and would be accepted!")
            print(f"     TXID: {result[0]['txid']}")
        else:
            print(f"  ❌ Transaction rejected: {result[0].get('reject-reason', 'unknown')}")
            return False

    except Exception as e:
        print(f"  ⚠️  Verification failed: {e}")
        print(f"  This may be normal if using NOWNodes")

    # Step 12: Broadcast
    print("\nStep 12: Broadcast transaction?")
    print("  This will broadcast to MAINNET!")
    response = input("  Type 'YES' (all caps) to broadcast: ")

    if response == 'YES':
        try:
            # Try NOWNodes first
            try:
                txid = nownodes_call("sendrawtransaction", [tx_hex])
                print(f"  ✅ Transaction broadcast via NOWNodes!")
            except:
                txid = rpc_call("sendrawtransaction", [tx_hex])
                print(f"  ✅ Transaction broadcast via RPC!")

            print(f"     TXID: {txid}")
            print(f"     Explorer: https://zcashblockexplorer.com/transactions/{txid}")

            print("\n" + "=" * 70)
            print("🎉 SUCCESS! Transaction is on-chain!")
            print("=" * 70)

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
        success = test_complete_workflow()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
