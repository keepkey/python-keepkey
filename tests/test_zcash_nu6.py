#!/usr/bin/env python3
"""
Test Zcash NU6 transaction signing and broadcasting
This test will:
1. Initialize emulator with test mnemonic
2. Get Zcash address
3. Sign a v4 transaction (works with NU6)
4. Broadcast to mainnet
"""

import sys
import requests
from keepkeylib.client import KeepKeyClient
from keepkeylib.transport_udp import UDPTransport


def get_utxos(address):
    """Get UTXOs for address from blockchair API"""
    url = f"https://api.blockchair.com/zcash/dashboards/address/{address}"
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Error fetching UTXOs: {response.status_code}")
        return []

    data = response.json()
    utxos = []
    if 'data' in data and address in data['data']:
        addr_data = data['data'][address]
        if 'utxo' in addr_data:
            for utxo in addr_data['utxo']:
                utxos.append({
                    'txid': utxo['transaction_hash'],
                    'vout': utxo['index'],
                    'value': utxo['value'],
                    'confirmations': utxo.get('confirmations', 0)
                })
    return utxos


def broadcast_transaction(raw_tx_hex):
    """Broadcast transaction to Zcash mainnet"""
    # Try blockchair first
    url = "https://api.blockchair.com/zcash/push/transaction"
    response = requests.post(url, json={"data": raw_tx_hex})

    if response.status_code == 200:
        result = response.json()
        if 'data' in result and 'transaction_hash' in result['data']:
            return True, result['data']['transaction_hash']
        else:
            return False, f"Unexpected response: {result}"
    else:
        return False, f"HTTP {response.status_code}: {response.text}"


def main():
    # Connect to emulator
    print("Connecting to KeepKey emulator...", flush=True)
    transport = UDPTransport('127.0.0.1:11044')

    # Disable passphrase callback to avoid issues
    class NoPassphraseClient(KeepKeyClient):
        def callback_PassphraseRequest(self, msg):
            from keepkeylib import messages_pb2 as proto
            return proto.PassphraseAck(passphrase='')

    client = NoPassphraseClient(transport)

    # Check if already initialized
    print("Checking device state...", flush=True)
    if not client.features.initialized:
        # Initialize with test mnemonic (all all all... for testing only)
        print("Initializing device...", flush=True)
        client.load_device_by_mnemonic(
            mnemonic='all all all all all all all all all all all all',
            pin='',
            passphrase_protection=False,
            label='NU6 Test'
        )
    else:
        print(f"Device already initialized: {client.features.label}", flush=True)
        # Try to wipe and reinitialize to ensure clean state
        print("Wiping device for clean test...", flush=True)
        client.wipe_device()
        print("Loading test mnemonic...", flush=True)
        client.load_device_by_mnemonic(
            mnemonic='all all all all all all all all all all all all',
            pin='',
            passphrase_protection=False,
            label='NU6 Test'
        )

    # Get Zcash address at path m/44'/133'/0'/0/0
    print("\nGetting Zcash address...", flush=True)
    address = client.get_address('Zcash', [44 | 0x80000000, 133 | 0x80000000, 0 | 0x80000000, 0, 0])
    print(f"Address: {address}", flush=True)

    # Get UTXOs
    print("\nFetching UTXOs...", flush=True)
    utxos = get_utxos(address)

    if not utxos:
        print("No UTXOs found for this address.", flush=True)
        print("You need to send some ZEC to this address first:", flush=True)
        print(f"  {address}", flush=True)
        return 1

    print(f"Found {len(utxos)} UTXO(s):", flush=True)
    for i, utxo in enumerate(utxos):
        print(f"  [{i}] {utxo['txid']}:{utxo['vout']} - {utxo['value']/100000000} ZEC ({utxo['confirmations']} confirmations)", flush=True)

    # Use first UTXO
    utxo = utxos[0]

    # Calculate fee (use 0.0001 ZEC = 10000 satoshis)
    fee = 10000
    send_amount = utxo['value'] - fee

    if send_amount <= 0:
        print(f"UTXO too small. Need at least {fee} satoshis for fee", flush=True)
        return 1

    print(f"\nCreating transaction:", flush=True)
    print(f"  Input: {utxo['value']/100000000} ZEC", flush=True)
    print(f"  Fee: {fee/100000000} ZEC", flush=True)
    print(f"  Output: {send_amount/100000000} ZEC", flush=True)
    print(f"  Change address: {address}", flush=True)

    # Sign transaction (v4 format, NU6 branch_id)
    print("\nSigning transaction...", flush=True)

    # Create inputs
    inputs = [{
        'prev_hash': bytes.fromhex(utxo['txid'])[::-1],  # Reverse byte order
        'prev_index': utxo['vout'],
        'address_n': [44 | 0x80000000, 133 | 0x80000000, 0 | 0x80000000, 0, 0],
        'amount': utxo['value'],
        'script_type': 'SPENDADDRESS'
    }]

    # Create outputs (send back to same address as change)
    outputs = [{
        'address': address,
        'amount': send_amount,
        'script_type': 'PAYTOADDRESS'
    }]

    # Sign with v4, NU6 branch_id (0xC8E71055)
    try:
        signatures, serialized_tx = client.sign_tx(
            'Zcash',
            inputs,
            outputs,
            version=4,
            version_group_id=0x892F2085,  # v4 version group
            branch_id=0xC8E71055,         # NU6 consensus branch
            lock_time=0
        )

        print(f"\n✅ Transaction signed successfully!")
        print(f"Raw transaction: {serialized_tx.hex()}")

        # Broadcast
        print("\nBroadcasting to mainnet...")
        success, result = broadcast_transaction(serialized_tx.hex())

        if success:
            print(f"\n✅ SUCCESS! Transaction broadcast:")
            print(f"   TXID: {result}")
            print(f"   Explorer: https://zcashblockexplorer.com/transactions/{result}")
            return 0
        else:
            print(f"\n❌ Broadcast failed: {result}")
            return 1

    except Exception as e:
        print(f"\n❌ Signing failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
