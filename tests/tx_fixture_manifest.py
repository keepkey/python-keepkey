"""Deterministic integrity tooling for authoritative transaction fixtures."""

from __future__ import print_function

import ast
import hashlib
import json
import re
import struct
import sys
from decimal import Decimal
from pathlib import Path


TX_FIXTURE_RE = re.compile(
    r"^(?P<network>.+)_tx_(?P<txid>[0-9a-f]{64})\.json$"
)

NETWORK_IMPORT_ALLOWLIST = {
    "conftest.py": {"requests", "socket", "urllib"},
    # Negative control: these APIs must be imported so the autouse fixture can
    # prove every non-emulator transport is rejected at runtime.
    "test_network_policy.py": {"requests", "socket"},
    "test_storage_version_gate.py": {"socket"},
    "test_tx_fixture_integrity.py": {"requests", "socket"},
}


def validate_test_network_surface(tests_dir):
    """Reject live-network helpers, including files pytest would not collect."""
    violations = []
    for path in sorted(Path(tests_dir).rglob("*.py")):
        relative = path.relative_to(tests_dir).as_posix()
        allowed = NETWORK_IMPORT_ALLOWLIST.get(relative, set())
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            imports = []
            if isinstance(node, ast.Import):
                imports = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports = [node.module.split(".", 1)[0]]
            for imported in imports:
                if imported in {"http", "requests", "socket", "urllib"} and \
                        imported not in allowed:
                    violations.append("%s:%s imports %s" %
                                      (relative, node.lineno, imported))
    if violations:
        raise ValueError(
            "unauthorized network-capable code under tests/: %s" %
            "; ".join(violations))


def _varint(value):
    if value < 253:
        return struct.pack("<B", value)
    if value <= 0xFFFF:
        return struct.pack("<BH", 253, value)
    if value <= 0xFFFFFFFF:
        return struct.pack("<BI", 254, value)
    return struct.pack("<BQ", 255, value)


def _satoshis(value):
    amount = Decimal(str(value)) * Decimal(100000000)
    if amount != amount.to_integral_value():
        raise ValueError("transaction output has sub-satoshi value: %r" % value)
    return int(amount)


def _script_sig(vin):
    if "coinbase" in vin:
        return bytes.fromhex(vin["coinbase"])
    value = vin.get("scriptSig", {})
    if isinstance(value, dict):
        return bytes.fromhex(value.get("hex", ""))
    return bytes.fromhex(vin.get("scriptsig", ""))


def _script_pubkey(vout):
    value = vout.get("scriptPubKey", {})
    if isinstance(value, dict):
        return bytes.fromhex(value["hex"])
    return bytes.fromhex(vout["scriptpubkey"])


def serialize_insight_transaction(data, network):
    """Rebuild the canonical non-witness bytes consumed by the firmware."""
    tx_type = int(data.get("type") or 0) if network == "insight_dash" else 0
    version = int(data["version"]) | (tx_type << 16)
    raw = struct.pack("<I", version)

    raw += _varint(len(data["vin"]))
    for vin in data["vin"]:
        if "coinbase" in vin:
            raw += bytes(32)
            raw += struct.pack("<I", 0xFFFFFFFF)
        else:
            raw += bytes.fromhex(vin["txid"])[::-1]
            raw += struct.pack("<I", int(vin["vout"]))
        script = _script_sig(vin)
        raw += _varint(len(script)) + script
        raw += struct.pack("<I", int(vin["sequence"]))

    raw += _varint(len(data["vout"]))
    for vout in data["vout"]:
        script = _script_pubkey(vout)
        raw += struct.pack("<Q", _satoshis(vout["value"]))
        raw += _varint(len(script)) + script

    raw += struct.pack("<I", int(data["locktime"]))
    if tx_type:
        payload = bytes.fromhex(data["extraPayload"])
        declared = int(data["extraPayloadSize"])
        if declared != len(payload):
            raise ValueError("Dash extra payload length mismatch")
        raw += _varint(len(payload)) + payload
    return raw


def transaction_id(network, raw):
    first = hashlib.sha256(raw).digest()
    if network.startswith("insight_groestlcoin"):
        # Groestlcoin transaction IDs deliberately use one SHA-256 round.
        digest = first
        algorithm = "sha256"
    else:
        digest = hashlib.sha256(first).digest()
        algorithm = "sha256d"
    return digest[::-1].hex(), algorithm


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _referencing_tests(tests_dir, txid):
    refs = []
    for path in sorted(tests_dir.glob("test_*.py")):
        if txid in path.read_text(encoding="utf-8", errors="strict").lower():
            refs.append(path.name)
    return refs


def build_manifest(fixture_dir):
    fixture_dir = Path(fixture_dir).resolve()
    tests_dir = fixture_dir.parent
    entries = []
    accounted_files = set()

    for response_path in sorted(fixture_dir.glob("*_tx_*.json")):
        match = TX_FIXTURE_RE.match(response_path.name)
        if not match:
            raise ValueError("invalid transaction fixture filename: %s" %
                             response_path.name)
        network = match.group("network")
        expected_txid = match.group("txid")
        data = json.loads(response_path.read_text(encoding="utf-8"))
        if data.get("txid") != expected_txid:
            raise ValueError("fixture txid field does not match filename: %s" %
                             response_path.name)

        raw_response = None
        if (network == "insight_zcashtestnet" and
                int(data["version"]) == 2 and data.get("vjoinsplit")):
            raw_response = fixture_dir / (
                "%s_rawtx_%s.json" % (network, expected_txid))
            raw_data = json.loads(raw_response.read_text(encoding="utf-8"))
            raw = bytes.fromhex(raw_data["rawtx"])
        else:
            raw = serialize_insight_transaction(data, network)

        computed_txid, algorithm = transaction_id(network, raw)
        if computed_txid != expected_txid:
            raise ValueError(
                "canonical transaction ID mismatch for %s: got %s" %
                (response_path.name, computed_txid))

        required_by = _referencing_tests(tests_dir, expected_txid)
        if not required_by:
            raise ValueError("unreferenced transaction fixture: %s" %
                             response_path.name)

        entry = {
            "algorithm": algorithm,
            "canonical_hex": raw.hex(),
            "canonical_sha256": hashlib.sha256(raw).hexdigest(),
            "network": network,
            "required_by": required_by,
            "response": response_path.name,
            "response_sha256": _sha256(response_path),
            "txid": expected_txid,
        }
        accounted_files.add(response_path.name)
        if raw_response is not None:
            entry["raw_response"] = raw_response.name
            entry["raw_response_sha256"] = _sha256(raw_response)
            accounted_files.add(raw_response.name)
        entries.append(entry)

    fixture_json = {
        path.name for path in fixture_dir.glob("*.json")
        if path.name != "manifest.json"
    }
    if accounted_files != fixture_json:
        raise ValueError(
            "unaccounted fixture files: missing=%s extra=%s" %
            (sorted(fixture_json - accounted_files),
             sorted(accounted_files - fixture_json)))

    return {
        "entries": entries,
        "schema": 1,
    }


def write_manifest(fixture_dir):
    fixture_dir = Path(fixture_dir).resolve()
    manifest = build_manifest(fixture_dir)
    output = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    (fixture_dir / "manifest.json").write_text(output, encoding="utf-8")


def check_manifest(fixture_dir):
    fixture_dir = Path(fixture_dir).resolve()
    validate_test_network_surface(fixture_dir.parent)
    manifest_path = fixture_dir / "manifest.json"
    expected = build_manifest(fixture_dir)
    actual = json.loads(manifest_path.read_text(encoding="utf-8"))
    if actual != expected:
        raise SystemExit(
            "fixture manifest is stale; run tests/tx_fixture_manifest.py")
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    print("fixture-manifest-sha256: %s" % digest)
    return digest


if __name__ == "__main__":
    fixture_root = Path(__file__).resolve().parent / "txcache"
    if "--check" in sys.argv[1:]:
        check_manifest(fixture_root)
    else:
        write_manifest(fixture_root)
