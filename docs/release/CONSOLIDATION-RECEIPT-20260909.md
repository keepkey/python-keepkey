# python-keepkey consolidation receipt — 2026-09-09

Single shared head for the 7.14.2 / 7.14.3 / 7.15 develop-flow release program.

## Why

Six python-keepkey heads were in play. The same test changes had been
cherry-picked onto several of them, and each copy was gated at whatever release
its branch was cut for — so the version gate recorded which branch a test lived
on rather than which firmware carries the fix. The report atlas
(`scripts/generate-test-report.py`), which defines what the release PDF must
contain, had forked three ways along with them.

## Prior identities

| Head | Pinned by | Relation to canonical `9c3982035` |
| --- | --- | --- |
| `9c3982035` | upstream fw #475/#476 | canonical (`keepkey:reconcile/upstream-sync`, PR #197 → master) |
| `7f46aa207` | fork fw `release/7.14.3-bitcoin-only` | +4, 0 behind |
| `5dae186a3` | fork fw `audit/7143-scope-repair` | +9, 0 behind |
| `08e491c60` | fork fw `release/7.15` | +8, 0 behind |
| `6268e38a3` | fork fw `audit/715-scope-repair` | +13, 0 behind |
| `d3b26aee6` | fork fw `release/7.14.2`, `audit/7142-scope-repair` | **diverged**: 66 behind / 7 ahead |
| `2ed835472` | fork fw `develop`, `alpha` | **diverged**: 50 behind / 52 ahead |

## Assembly

Base `5dae186a3`, merged `6268e38a3`. Merge base `7f46aa207`. Two conflicts,
one line each; nothing else conflicted.

Duplicate pairs across the two tips: `test(reset)` dice grouping and
`test(storage)` CRC framing are byte-identical (equal patch-ids) and deduped on
merge. `test(ping)` message presence and `test(ripple)` displayed-address
differed **only** in the gate string.

### Conflict resolutions

Both resolved to `7.14.2`, below either side's value:

- `tests/test_msg_ping.py::test_protected_ping_preserves_message_presence_after_debug_read`
  — three copies existed, gated `7.14.2` / `7.14.3` / `7.15.0`. `fsm_msgPing` is
  byte-identical between the 7.14.2 and 7.14.3 candidates, so the fix is on all
  three products and the lowest gate is the correct one.
- `tests/test_msg_ripple_get_address.py` — same shape. The response-arena fix is
  present in `lib/firmware/fsm_msg_ripple.h` on the 7.14.2 candidate
  (`8c13ed24f`) as well. The comment claiming "older release backports are
  separate" was false and was rewritten; `1ce4d3961` (7.14.3) and `885609fbe`
  (7.15) reach the same end state.

`tests/test_msg_ripple_sign_tx.py` was **not** a duplicate: `0f4c839db` asserts
memo rejection below 7.15 and self-skips above it, `fb968836b` un-skips the
THORChain memo test at 7.15.0. Complementary, auto-merged, both kept.

## Coverage proof — nothing dropped

Every test function on all six prior heads was diffed against the consolidated
head. Three gaps were found and each is a deliberate supersession, not a loss:

- `d3b26aee6` EOS work: `tests/test_msg_eos_signtx.py` and
  `tests/unit/test_eos_updateauth_vector.py` are **blob-identical** to the
  consolidated head. Its `test_msg_signing_boundaries.py` is superseded by the
  class-based rewrite, which is a strict superset (adds
  `test_clear_session_aborts_every_txrequest_stage`,
  `test_invalid_multisig_outputs_never_serialize_or_sign`).
- `d3b26aee6` Zcash: 6 older PCZT tests replaced on canonical's line by 12
  stricter ones, including `test_ironwood_v6_metadata_is_forwarded_exactly`
  (the NU/branch-id rot fix). Consolidated blob equals canonical blob exactly.
- `test_full_715_accepts_pre_release_solana_lut_skip` was replaced by `08e491c`
  with two stricter tests: `test_full_7143_accepts_unimplemented_solana_lut_skip`
  and `test_full_715_requires_solana_lut_coverage`.

`2ed835472` (fork develop/alpha) is the one head **not** covered — see exclusions.

## Report atlas

Single atlas at blob `b88c99396`. `MUST_RUN_MODULES['test_msg_solana_lut_attestation']`
resolves to `7.15.0`, not canonical's stale `7.16.0`: `lib/firmware/solana.c`
and `fsm_msg_solana.h` on `bd5e509cd` (7.15) carry the LUT attestation path,
while `0fe01bc1b` (7.14.3) and `8c13ed24f` (7.14.2) do not. Canonical's floor
would have let the 7.15 product silently skip its own LUT coverage.

## Defect fixed in the same pass

`keepkeylib/eth/ethereum_tokens.py` was fail-open. `build()` verified neither
that the vetted `ethereum-lists` source was present nor that the scan produced
anything. Measured: on a non-recursive checkout the old path yields **0 tokens
and raises nothing**, so the firmware would build green with an empty token
table and the device would show raw addresses and unknown decimals for every
ERC-20. Restored the fail-closed form already present on the fork develop line,
plus its regression test — which fails without the change (control run).

The sibling `return` → `continue` in `add_tokens()` is corrected but is
**latent, not live**: the currently pinned `ethereum-lists` has no non-file
entries in any scanned directory, and the table is 1378 tokens either way.

## Checks executed

Offline suites on the consolidated head, real `ethereum-lists` checked out:

- `tests/test_token_table_generators.py` — 5 passed, 0 skipped
- `tests/test_report_variant_validation.py` — 4 passed
- `tests/unit`, `tests/test_network_policy.py` — 4 passed, 2 subtests
  (`PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python`; the local env has a
  protobuf ≠ 3.20.3)
- Control: the token guard test fails without the fix, passes with it.

Device/emulator suites were **not** run here. No firmware branch is re-pinned by
this change, so no CI was dispatched.

## Exclusions

- **`2ed835472` (fork develop/alpha) is not merged.** It diverges 50/52 with
  zero patch-id equivalence in either direction. It carries four fail-closed
  library changes and eight test functions that exist nowhere else, all
  `requires_firmware("7.16.0")`-shaped: the EIP-712 `MAX_IDENTIFIER_BYTES = 31`
  identifier/duplicate-member validation, the `SolanaSignTx` field-13
  `clearsign_certificate` binding, and the WETH uniswap entry. Re-pinning
  develop straight to this head would silently revert them **and** delete their
  guarding tests in the same change. That is its own unit.
- The report-atlas union with develop (J4 streamed-calldata commitment, section
  K seed-generation hardening, `screenshot_count_audit` frame-count gate,
  the GH #516 uniswap must-run entry) is deferred with it.
- `TD4` is a genuine policy contradiction, not a merge conflict: canonical has
  `test_advanced_mode_gates_the_endpoint`, develop has
  `test_advanced_mode_is_not_required_for_structured_review`. Needs a decision,
  not a resolution.

## Sequencing constraint

The collapsed gates are satisfied by any firmware reporting ≥ 7.14.2, including
release branches that have **not** taken the `audit/*-scope-repair` fixes.
Against those builds these tests will fail rather than skip. That failure is
correct — they are real regressions — but the release branches must take the
audit fixes **before** any firmware branch re-pins to this head, or the
consolidation will be blamed for the red.
