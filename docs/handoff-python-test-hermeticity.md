# Handoff: authoritative python-keepkey tests must be fully offline

## Non-negotiable release rule

The authoritative Python suite must never depend on an explorer, RPC service,
DNS, TLS, remote retention, or the caller's working directory. A missing input
is a named fixture failure, not permission to fetch mutable data. Optional live
compatibility probes may exist only in a separate, non-authoritative workflow;
they must never contribute release JUnit, report totals, artifacts, or a
GO/NO-GO decision.

This work must be ported to the upstream keepkey/python-keepkey repository by
reviewed PR. The fork implementation is the reference; no upstream branch was
modified while preparing it.

## Fork reference implementation

Branch: BitHighlander/python-keepkey:fix/hermetic-release-tests

The implementation is intentionally isolated from the 7.14.2 Solana/TON
disclosure and PDF-report branches. Reconcile those branches only after this
one is reviewed, then repin firmware to the durable Python merge commit.

Affected surfaces:

- keepkeylib/tx_api.py adds configure_offline_fixtures(path), resolves a fixed
  absolute fixture root, and raises OfflineFixtureError naming the complete key
  instead of falling through to HTTP.
- tests/common.py makes tests/txcache module-relative and enables offline-only
  mode for every KeepKeyTest.
- tests/conftest.py rejects external DNS, socket, and HTTP access per test while
  permitting only loopback emulator traffic and Unix-domain sockets.
- .github/workflows/ci.yml checks fixture integrity, permits the exact local
  emulator container IP, rejects every other new non-loopback connection during
  authoritative pytest, and records the manifest SHA-256 in every summary.
- tests/tx_fixture_manifest.py and tests/test_tx_fixture_integrity.py account
  for every fixture, reconstruct canonical transactions, recompute every txid,
  test cwd independence and fail-closed misses, and statically reject new
  network-capable helpers even when pytest would not collect them.
- tests/test_sign_typed_data.py and tests/test_verify_typed_data.py resolve JSON
  fixtures from their module directory.
- The unused tests/zcash_rpc.py live-node helper was removed. It was not
  collected by pytest, contained a fixed private-node endpoint and embedded
  RPC credentials, and had no place in authoritative test infrastructure.

## Fixture rules

Each manifest entry records:

- source network and transaction ID;
- response filename and SHA-256;
- raw-response filename and SHA-256 where Zcash JoinSplit reconstruction needs
  it;
- canonical serialized bytes and their SHA-256;
- transaction-ID algorithm;
- every authoritative test file that references it.

Bitcoin, Testnet, Bitcoin Gold, Dash, and pre-Overwinter Zcash transaction IDs
use double SHA-256. Groestlcoin transaction IDs use one SHA-256 round, matching
the current Groestlcoin Core HashWriter::GetHash() implementation:
https://github.com/Groestlcoin/groestlcoin/blob/master/src/hash.h

Do not accept a fixture merely because its JSON txid field agrees with its
filename. The canonical serialization must independently hash to the same ID.

The fork audit found and corrected one latent synthetic-fixture defect:
6e320339...a6ee37 advertised a txid computed with the null outpoint index
0xffffffff, while its decoded fixture said index 0. The corrected decoded
fixture now agrees with its canonical bytes and txid. Two cache files with no
authoritative references were removed.

## Required upstream migration

1. Port the fork commits without weakening the fail-closed behavior.
2. Preserve public live TxApi clients for non-test callers, but ensure
   authoritative tests enable offline-only mode before constructing clients.
3. Run python tests/tx_fixture_manifest.py --check as an early CI gate.
4. Run all authoritative emulator suites with both the pytest network-denial
   control and OS-level outbound-new-connection denial.
5. Treat a new transaction input as a fixture change requiring canonical-byte,
   response-hash, txid, reference, and manifest review.
6. Feed the exact manifest SHA-256 into the release evidence/report pipeline.
   The report job must fail if the manifest is missing, stale, mutated, or not
   listed in provenance.
7. Keep optional explorer/RPC probes in a separately named workflow that
   cannot satisfy or influence a required release check. Store them outside
   tests/ and obtain endpoints and credentials from the workflow environment;
   never commit either value.

## Acceptance criteria

- A clean checkout with an empty user cache runs the authoritative suite while
  outbound networking is denied.
- Zero DNS, external socket, HTTP, explorer, or RPC attempt occurs.
- A missing network/txid fixture fails immediately and names the requesting
  key; no HTTP fallback is possible.
- Running from the repository root and from tests/ produces identical test
  counts, statuses, signed outputs, and manifest digest.
- Every fixture source is content-hashed, every canonical transaction is
  retained, every txid is independently recomputed, and every fixture has at
  least one authoritative test reference.
- No test is skipped or xfailed because a live service or fixture is
  unavailable.
- Full Python JUnit is green before the Python commit is eligible for a
  firmware submodule repin.
- The release report and provenance manifest contain the exact transaction
  fixture-manifest SHA-256.

## Upstream handback

Return the upstream PR URL, exact head and merge commits, full offline JUnit
totals, fixture-manifest SHA-256, the network-denial result, CI run URL, and
git diff --check. Call out any historical response that cannot be reconstructed
exactly; do not silently replace, weaken, delete, or skip it.
