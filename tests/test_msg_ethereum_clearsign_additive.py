"""
EVM Clear Signing — the ADDITIVE INVARIANT.

The whole clear-sign tier rests on one property:

    A runtime-loaded provider may ADD screens. It may never REMOVE one.

A provider signer is loaded at runtime (LoadClearsignSigner, RAM-only,
user-confirmed) and is NOT verified by KeepKey. Its metadata is therefore
annotation, not authority: after the decoded who/what/why screens the device
must still run the ordinary unverified review — the amount/recipient screen,
the raw-calldata screen and the fee screen a user would have seen with no
metadata at all. If a lying provider could suppress any of those, a runtime
schema would be a screen-substitution oracle: "supply 10.5 DAI to Aave" on the
glass, arbitrary calldata under the signature.

lib/firmware/ethereum.c:828 is where this is enforced:

    if (signed_metadata_from_loaded_signer()) {
        needs_confirm = true;        /* forced back ON */
        data_needs_confirm = true;   /* forced back ON */
    } else {
        needs_confirm = signed_metadata_schema_moves_value();
        data_needs_confirm = false;  /* raw review SUPPRESSED */
    }

The else-branch is reserved for a future firmware-PINNED signer and must not be
reachable by anything a host can load today.

HOW THESE TESTS MEASURE SCREENS
-------------------------------
Screen counts are never modelled here, they are compared. Every test signs the
SAME transaction twice against the SAME device state — once with no metadata
(the baseline) and once with metadata — and records the raw 2048-byte OLED
framebuffer at each ButtonRequest (ScreenRecorder below, which reads the layout
before the debuglink auto-press). The proof of "nothing was removed" is that
the baseline frames reappear BYTE-FOR-BYTE as the tail of the clear-signed run.
That is immune to pagination and to value-dependent rendering: whatever the
baseline drew, the clear-signed run must still draw, in the same order, last.

Existing coverage in test_msg_ethereum_clear_signing.py is adjacent but not
this: V5 covers "no metadata -> blind sign", V10 covers replay rejection, V12
covers cancel-clears-metadata. None of them proves the raw review FOLLOWS a
SUCCESSFUL decode.
"""

import time
import unittest

try:
    import common
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    import common

from keepkeylib.signed_metadata import (
    serialize_metadata,
    serialize_schema_metadata,
    sign_metadata,
    eth_sighash_legacy,
    # aliased: a module-level name starting with 'test_' would be
    # collected as a test function by pytest.
    test_signer_compressed_pubkey as signer_pubkey,
    ARG_FORMAT_ADDRESS,
    ARG_FORMAT_AMOUNT,
    ARG_FORMAT_TOKEN_AMOUNT,
    CLASSIFICATION_VERIFIED,
    CLASSIFICATION_MALFORMED,
)
from keepkeylib.tools import parse_path

# Fixtures and helpers shared with the main clear-sign suite. Imported rather
# than duplicated so a change to the reference vectors cannot leave this
# section quietly testing a different transaction than the atlas describes.
from test_msg_ethereum_clear_signing import (
    AAVE_V3_POOL,
    AAVE_SUPPLY_SELECTOR,
    CI_SIGNER_ALIAS,
    DEFAULT_ARGS,
    DEVICE_PATH,
    TEST_KEY_ID,
    aave_supply_calldata,
    recover_eth_signer,
)

# METADATA_MAX_KEYS in include/keepkey/firmware/signed_metadata.h.
METADATA_MAX_KEYS = 4

# RC18 verifies runtime metadata, but the successful-decode path did not yet
# guarantee that the ordinary raw review survived byte-for-byte. That security
# invariant landed after RC18 and first ships on the 7.16 line.
ADDITIVE_REVIEW_FIRMWARE = "7.16.0"

# The Aave V3 supply() transaction every additive test signs. Real ABI
# calldata (selector + 4 x 32-byte words), so the metadata below binds a
# genuine transaction rather than a toy payload.
TX = dict(chain_id=1, nonce=7, gas_price=20000000000, gas_limit=200000,
          value=0)
SUPPLY_AMOUNT = 10500000000000000000  # 10.5 DAI (18 decimals)


class ScreenRecorder(object):
    """Record the OLED framebuffer of every confirm screen an operation draws.

    Wraps callback_ButtonRequest: reads the layout over DebugLink BEFORE the
    normal auto-press (which would replace the screen), then delegates to the
    original callback so screenshot capture and the button press still happen
    exactly as they do in every other test.
    """

    # The firmware emits ButtonRequest immediately before drawing; the same
    # settle used by the screenshot path (client.SCREENSHOT_SETTLE_SECONDS)
    # keeps a half-drawn frame out of the comparison.
    SETTLE = 0.3

    def __init__(self, client):
        self.client = client
        self.frames = []  # list of (ButtonRequestType, 2048-byte layout)

    def __enter__(self):
        original = self.client.callback_ButtonRequest

        def record(msg):
            time.sleep(self.SETTLE)
            self.frames.append((msg.code, bytes(self.client.debug.read_layout())))
            return original(msg)

        # Instance attribute shadows the bound method; client.call() resolves
        # the handler with getattr(self, 'callback_ButtonRequest').
        self.client.callback_ButtonRequest = record
        return self

    def __exit__(self, *exc):
        del self.client.callback_ButtonRequest
        return False

    @property
    def codes(self):
        return [code for code, _ in self.frames]

    @property
    def layouts(self):
        return [layout for _, layout in self.frames]


def bound_supply_metadata(tx_hash, key_id=TEST_KEY_ID):
    """v1 metadata committing to a specific real Aave supply() sighash."""
    return sign_metadata(serialize_metadata(
        chain_id=TX['chain_id'],
        contract_address=AAVE_V3_POOL,
        selector=AAVE_SUPPLY_SELECTOR,
        tx_hash=tx_hash,
        method_name='supply',
        args=DEFAULT_ARGS,
        key_id=key_id,
    ))


class TestClearSignAdditiveInvariant(common.KeepKeyTest):
    """A runtime provider adds screens; it never removes one."""

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.15.0")
        self.requires_message("EthereumTxMetadata")
        self.requires_message("LoadClearsignSigner")
        self.setup_mnemonic_nopin_nopassphrase()
        # AdvancedMode is required both for the raw-calldata review to be
        # reachable at all and for a runtime signer to verify anything.
        # apply_policy() re-Initializes, which clears RAM-only signers, so it
        # must come BEFORE any load_clearsign_signer() call.
        self.client.apply_policy("AdvancedMode", 1)
        self.n = parse_path(DEVICE_PATH)
        self.data = aave_supply_calldata(SUPPLY_AMOUNT)
        self.tx_hash = eth_sighash_legacy(
            TX['nonce'], TX['gas_price'], TX['gas_limit'], AAVE_V3_POOL,
            TX['value'], self.data, TX['chain_id'])

    def _load_signer(self, key_id=TEST_KEY_ID, alias=CI_SIGNER_ALIAS):
        self.client.load_clearsign_signer(
            key_id=key_id, pubkey=signer_pubkey(), alias=alias)

    def _sign_supply(self):
        return self.client.ethereum_sign_tx(
            n=self.n, to=AAVE_V3_POOL, data=self.data, **TX)

    def _record_supply(self):
        """Sign the fixture tx, returning (ScreenRecorder, (v, r, s))."""
        with ScreenRecorder(self.client) as rec:
            sig = self._sign_supply()
        return rec, sig

    def _assert_recovers(self, sig, tx_hash=None):
        sig_v, sig_r, sig_s = sig
        self.assertIsNotNone(sig_r)
        self.assertIsNotNone(sig_s)
        signer = recover_eth_signer(sig_r, sig_s, sig_v,
                                    tx_hash or self.tx_hash, TX['chain_id'])
        self.assertEqual(signer, self.client.ethereum_get_address(self.n))

    def _assert_baseline_survives(self, baseline, observed):
        """The core assertion: every baseline screen still appears, unchanged,
        in order, as the TAIL of the clear-signed run."""
        self.assertTrue(len(observed.frames) > len(baseline.frames))
        self.assertEqual(observed.frames[-len(baseline.frames):],
                         baseline.frames)
        # And the extra frames really are extra — no baseline screen was
        # merely re-drawn earlier to pad the count.
        added = observed.frames[:-len(baseline.frames)]
        for code, layout in added:
            self.assertTrue(layout not in baseline.layouts)

    # ── the invariant ────────────────────────────────────────────────

    def test_successful_decode_still_runs_the_raw_review(self):
        """A VERIFIED v1 decode from a runtime provider ADDS its who/what/why
        screens in front of the ordinary unverified review — it replaces none
        of them.

        Measured on the emulator for this fixture: the baseline (no metadata)
        run draws 3 screens — amount/recipient, raw contract data, fee. The
        clear-signed run draws 10: identity, 'Call: supply', contract address,
        one screen per attested argument (4), then the SAME 3 baseline frames,
        byte-for-byte. 3 + num_args is the structural minimum from
        signed_metadata_confirm_screens(); pagination can only raise it.
        """
        self.requires_firmware(ADDITIVE_REVIEW_FIRMWARE)
        self._load_signer()
        self._drop_setup_screenshots()

        # Baseline: the exact same transaction with no metadata in play.
        baseline, sig = self._record_supply()
        self._assert_recovers(sig)

        blob = bound_supply_metadata(self.tx_hash)
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob, metadata_version=1, key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)

        observed, sig = self._record_supply()
        self._assert_recovers(sig)

        self._assert_baseline_survives(baseline, observed)
        # Identity + method + contract + one screen per attested argument.
        added = len(observed.frames) - len(baseline.frames)
        self.assertTrue(added >= 3 + len(DEFAULT_ARGS))

    def test_failed_signature_falls_back_to_the_unverified_review(self):
        """Metadata whose signature does not verify must leave the signing
        flow EXACTLY as it was: the ordinary unverified review, no refusal and
        no partial decoded information.

        The device classifies the tampered blob MALFORMED and the subsequent
        signing run draws frames byte-identical to the baseline — which is the
        strongest available statement of 'nothing decoded leaked onto the
        glass', since any decoded screen would be a frame the baseline does
        not contain.
        """
        self._load_signer()
        self._drop_setup_screenshots()

        baseline, sig = self._record_supply()
        self._assert_recovers(sig)

        tampered = bytearray(bound_supply_metadata(self.tx_hash))
        tampered[10] ^= 0xFF  # inside the signed region
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=bytes(tampered), metadata_version=1,
            key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_MALFORMED)

        observed, sig = self._record_supply()
        self._assert_recovers(sig)
        self.assertEqual(observed.frames, baseline.frames)

    def test_no_runtime_slot_can_reach_the_suppression_branch(self):
        """Every key slot is additive, so signed_metadata_from_loaded_signer()
        is true for every VERIFIED blob this firmware can produce.

        The suppression else-branch is gated on a signer that is NOT runtime-
        loaded. This test walks all METADATA_MAX_KEYS slots: each one is loaded
        at runtime and each one still shows the full baseline review after its
        decode. A slot that suppressed would be caught as a missing tail frame.
        """
        self.requires_firmware(ADDITIVE_REVIEW_FIRMWARE)
        for key_id in range(METADATA_MAX_KEYS):
            self._load_signer(key_id=key_id, alias='CI Slot %d' % key_id)
        self._drop_setup_screenshots()

        baseline, sig = self._record_supply()
        self._assert_recovers(sig)

        for key_id in range(METADATA_MAX_KEYS):
            with self.subTest(key_id=key_id):
                blob = bound_supply_metadata(self.tx_hash, key_id=key_id)
                resp = self.client.ethereum_send_tx_metadata(
                    signed_payload=blob, metadata_version=1, key_id=key_id)
                self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)
                observed, sig = self._record_supply()
                self._assert_recovers(sig)
                self._assert_baseline_survives(baseline, observed)

    def test_no_slot_verifies_without_a_runtime_load(self):
        """The complementary half: with no signer loaded, NO slot verifies
        anything, so there is no firmware-pinned signer in this build that
        could take the suppression branch.

        Phase 1 ships with every built-in METADATA_PUBKEYS slot zeroed;
        metadata_pubkey_for() returns NULL for an unloaded slot and
        signed_metadata_process() classifies MALFORMED. Sending metadata draws
        nothing, so the empty screenshot list for this test is deliberate — the
        setUp policy-confirm frame is dropped below so the capture directory
        stays empty rather than offering an unrelated screen as evidence.
        """
        self._drop_setup_screenshots()
        for key_id in range(METADATA_MAX_KEYS):
            with self.subTest(key_id=key_id):
                blob = bound_supply_metadata(self.tx_hash, key_id=key_id)
                resp = self.client.ethereum_send_tx_metadata(
                    signed_payload=blob, metadata_version=1, key_id=key_id)
                self.assertEqual(resp.classification, CLASSIFICATION_MALFORMED)

    def test_v2_schema_decode_still_runs_the_raw_review(self):
        """The v2 (static schema) path is additive too.

        v2 is where suppression would be most tempting: the schema attests a
        decode shape and no tx_hash, so the else-branch drops the raw review
        outright (data_needs_confirm = false) and keeps the amount screen only
        if signed_metadata_schema_moves_value(). For a runtime signer that
        branch is not taken — the decoded screens are followed by the SAME
        amount, raw-calldata and fee screens the baseline drew.

        Deliberately schema-decoded against the Aave supply() fixture rather
        than an ERC-20 transfer: a recognized token contract has no raw-data
        screen in its own baseline (the token path already skips it), so it
        could not show that the raw review survives.
        """
        self.requires_firmware(ADDITIVE_REVIEW_FIRMWARE)
        self._load_signer()
        self._drop_setup_screenshots()

        baseline, sig = self._record_supply()
        self._assert_recovers(sig)

        # Same 132-byte supply() calldata, described as a 4-word static
        # schema: the device decodes the values from the bytes it signs.
        v2_args = [
            {'name': 'asset', 'format': ARG_FORMAT_ADDRESS},
            {'name': 'amount', 'format': ARG_FORMAT_TOKEN_AMOUNT,
             'decimals': 18, 'symbol': 'DAI'},
            {'name': 'onBehalfOf', 'format': ARG_FORMAT_ADDRESS},
            {'name': 'referral', 'format': ARG_FORMAT_AMOUNT},
        ]
        blob = sign_metadata(serialize_schema_metadata(
            chain_id=TX['chain_id'], contract_address=AAVE_V3_POOL,
            selector=AAVE_SUPPLY_SELECTOR, method_name='supply',
            args=v2_args, timestamp=0, key_id=TEST_KEY_ID))
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=blob, metadata_version=1, key_id=TEST_KEY_ID)
        self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)

        observed, sig = self._record_supply()
        self._assert_recovers(sig)
        self._assert_baseline_survives(baseline, observed)
        added = len(observed.frames) - len(baseline.frames)
        self.assertTrue(added >= 3 + len(v2_args))


if __name__ == '__main__':
    unittest.main()
