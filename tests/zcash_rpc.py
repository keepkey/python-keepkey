#!/usr/bin/env python3
"""
Zcash RPC client for firmware testing
"""

import requests
import json
import sys


class ZcashRPC:
    def __init__(self):
        self.url = "http://100.117.181.111:8232"
        self.auth = ("zcash", "78787ba819a382122e2b4fd98e68db3419ba7cf11c3f22f3bcd07e5ac606e630")

    def call(self, method, params=[]):
        """Make RPC call to Zcash node"""
        payload = {
            "jsonrpc": "1.0",
            "id": "python",
            "method": method,
            "params": params
        }
        response = requests.post(self.url, json=payload, auth=self.auth)
        result = response.json()

        if result.get("error"):
            raise Exception(f"RPC Error: {result['error']}")

        return result["result"]

    def broadcast_transaction(self, tx_hex):
        """Broadcast a signed transaction"""
        return self.call("sendrawtransaction", [tx_hex])

    def decode_transaction(self, tx_hex):
        """Decode transaction hex to readable format"""
        return self.call("decoderawtransaction", [tx_hex])

    def get_blockchain_info(self):
        """Get current blockchain status"""
        return self.call("getblockchaininfo")

    def get_transaction(self, txid, verbose=True):
        """Fetch transaction by TXID"""
        return self.call("getrawtransaction", [txid, 1 if verbose else 0])

    def validate_address(self, address):
        """Validate a Zcash address"""
        return self.call("validateaddress", [address])

    def get_network_info(self):
        """Get network information"""
        return self.call("getnetworkinfo")


def main():
    """Example usage"""
    rpc = ZcashRPC()

    print("Zcash Node Status")
    print("=" * 60)

    # Get blockchain info
    info = rpc.get_blockchain_info()
    print(f"Current Height: {info['blocks']:,}")
    print(f"Chain: {info['chain']}")
    print(f"Verification Progress: {info['verificationprogress']:.2%}")

    # Get network info
    net_info = rpc.get_network_info()
    print(f"\nNode Version: {net_info['subversion']}")
    print(f"Protocol Version: {net_info['protocolversion']}")
    print(f"Connections: {net_info['connections']}")

    # Network upgrades
    print("\nNetwork Upgrades:")
    print("-" * 60)
    upgrades = info['upgrades']
    for branch_id, upgrade_info in upgrades.items():
        status = upgrade_info['status']
        name = upgrade_info['name']
        height = upgrade_info.get('activationheight', 'N/A')
        emoji = '✅' if status == 'active' else '⏳' if status == 'pending' else '📦'
        print(f"{emoji} {name:12} (0x{branch_id}) - Height {height:>8} - {status.upper()}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
