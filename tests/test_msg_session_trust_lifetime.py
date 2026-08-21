"""
Session and Trust Lifetime — provider trust must die on its own.

Two claims in the 7.15 clear-sign design have never been tested end to end:

  1. AdvancedMode is SESSION state, never a flash bit.  storage.c writes bit 12
     of the storage flags word as zero and ignores it on read (four sites:
     storage_writeStorageV11, storage_readStorageV11,
     storage_writeStorageV16Plaintext, storage_readStorageV16Plaintext), each
     with a comment saying the policy is session-scoped now.  The only proof of
     that is a power cycle: enable it, restart the firmware, and it must be OFF
     while everything else in the same flags word survives.

  2. A runtime clear-sign signer (LoadClearsignSigner) lives in RAM only and is
     revoked by session teardown.  session_clear() calls
     signed_metadata_clear_signers() unconditionally, so both Initialize
     (clear_pin=false) and ClearSession (clear_pin=true) drop it, and a reboot
     drops it by construction.

MODELLING A POWER CYCLE.  The emulator's flash is an mmap of `emulator.img` in
its working directory (lib/emulator/setup.c).  Killing and relaunching the
process WITHOUT touching that file is a REBOOT: flash contents survive, RAM and
every session variable do not.  Deleting the image first would be a FACTORY WIPE
instead, and a wipe proves nothing here — every policy reads back off on a blank
device whether or not it was ever persisted.  _power_cycle() therefore keeps the
image, and each power-cycle test asserts a persisted control value came back to
prove the flash really did survive the restart.

WHY THE POLICY CALLS ARE RAW.  ProtocolMixin.apply_policy() sends Initialize
afterwards to refresh Features, and Initialize is itself one of the teardown
paths under test — using it would clear the signer as a side effect and make
every assertion below vacuous.  _apply_policy_raw() sends the bare ApplyPolicies
and reads state back with GetFeatures, which touches no session state.

test_msg_ethereum_clear_signing.py covers loading a signer, the persist=true
refusal and the wipe path.  Nothing here duplicates that: this file is only
about how loaded trust DIES.
"""

from __future__ import print_function

import os
import subprocess
import time
import unittest

import common
import config

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types
from keepkeylib.client import CallException, KeepKeyDebuglinkClient
from keepkeylib.transport_udp import UDPTransport
from keepkeylib.signed_metadata import (
    ARG_FORMAT_STRING,
    CLASSIFICATION_MALFORMED,
    CLASSIFICATION_VERIFIED,
    serialize_metadata,
    sign_metadata,
    # aliased: pytest would otherwise collect the helper as a test function
    test_signer_compressed_pubkey as signer_compressed_pubkey,
)

# Same CI slot/alias the clear-sign suite uses. Phase-1 firmware ships with no
# built-in keys, so slot 3 is empty until LoadClearsignSigner fills it.
TEST_KEY_ID = 3
CI_SIGNER_ALIAS = 'CI Test'

AAVE_V3_POOL = bytes.fromhex('7d2768de32b0b80b7a3454c06bdac94a69ddc7a9')
AAVE_SUPPLY_SELECTOR = bytes.fromhex('617ba037')
PROBE_ARGS = [
    {'name': 'protocol', 'format': ARG_FORMAT_STRING, 'value': b'Aave V3'},
]


def probe_blob():
    """A VERIFIED-classification blob signed by the CI test key for slot 3.

    Used only as an oracle for "is the signer still in the slot?": the device
    answers VERIFIED while the slot holds the matching pubkey and MALFORMED once
    it does not.  No transaction is signed, so no tx_hash binding is needed.
    """
    return sign_metadata(serialize_metadata(
        chain_id=1,
        contract_address=AAVE_V3_POOL,
        selector=AAVE_SUPPLY_SELECTOR,
        tx_hash=b'\x00' * 32,
        method_name='supply',
        args=PROBE_ARGS,
        key_id=TEST_KEY_ID,
    ))


def _emulator_process(port):
    """(pid, exe, cwd) of the process BOUND to udp/port, or None.

    Skips this test client's own connected socket, which lsof also reports on
    the same port but as a `local->remote` pair rather than a bare bind.
    """
    try:
        out = subprocess.run(['lsof', '-nP', '-iUDP:%d' % port, '-Fpn'],
                             capture_output=True, text=True).stdout
    except FileNotFoundError:
        raise RuntimeError(
            "lsof is required to find and restart the emulator for the "
            "power-cycle tests; install it or run these against a device you "
            "can power-cycle by hand")
    pid = None
    for line in out.splitlines():
        if line.startswith('p'):
            pid = int(line[1:])
        elif line.startswith('n') and pid is not None:
            name = line[1:]
            if '->' in name or not name.endswith(':%d' % port):
                continue
            exe = subprocess.run(['ps', '-o', 'comm=', '-p', str(pid)],
                                 capture_output=True, text=True).stdout.strip()
            cwd_out = subprocess.run(
                ['lsof', '-a', '-p', str(pid), '-d', 'cwd', '-Fn'],
                capture_output=True, text=True).stdout
            cwd = None
            for cwd_line in cwd_out.splitlines():
                if cwd_line.startswith('n'):
                    cwd = cwd_line[1:]
            return pid, exe, cwd
    return None


class TestSessionTrustLifetime(common.KeepKeyTest):

    MIN_FIRMWARE = "7.15.0"

    def setUp(self):
        super(TestSessionTrustLifetime, self).setUp()
        self.requires_firmware(self.MIN_FIRMWARE)

    # ── helpers ────────────────────────────────────────────────────────

    def _apply_policy_raw(self, name, enabled):
        """ApplyPolicies with NO trailing Initialize. See module docstring."""
        return self.client.call(proto.ApplyPolicies(
            policy=[proto_types.PolicyType(policy_name=name, enabled=enabled)]))

    def _policy(self, name):
        """Read a policy back with GetFeatures — touches no session state."""
        features = self.client.call(proto.GetFeatures())
        for policy in features.policies:
            if policy.policy_name == name:
                return policy.enabled
        self.fail("no such policy: %s" % name)

    def _signer_still_loaded(self):
        """VERIFIED => slot 3 still holds the CI signer; MALFORMED => empty.

        Requires AdvancedMode ON: fsm_msgEthereumTxMetadata refuses outright
        without it, which is a different answer from "the slot is empty" and is
        asserted separately where it matters.
        """
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=probe_blob(), metadata_version=1,
            key_id=TEST_KEY_ID)
        return resp.classification

    def _assertClassification(self, expected, why):
        """assertEqual with a message. common.KeepKeyTest narrows assertEqual to
        two positional args, so the reason a lifetime assertion matters would
        otherwise be lost at the point it fails."""
        got = self._signer_still_loaded()
        self.assertTrue(got == expected,
                        "%s (classification %d, expected %d)" % (why, got, expected))

    def _arm_session(self):
        """Seed the device, turn AdvancedMode on, load the CI signer, and prove
        the signer really is live before anything tries to revoke it."""
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self._apply_policy_raw("AdvancedMode", True)
        self.client.load_clearsign_signer(
            key_id=TEST_KEY_ID, pubkey=signer_compressed_pubkey(),
            alias=CI_SIGNER_ALIAS)
        self._assertClassification(
            CLASSIFICATION_VERIFIED,
            "the CI signer did not take — nothing below can be evidence about "
            "revoking trust that was never armed")

    def _persist_marker_across_all_sectors(self):
        """Set the Experimental policy, then commit enough times that EVERY
        storage sector holds a record written after it was set.

        This exists because of a real emulator/firmware interaction that would
        otherwise make every power-cycle assertion below vacuous.
        storage_commit() calls wear_leveling_shift(), so consecutive commits
        land in FLASH_STORAGE1 -> 2 -> 3 -> 1, and each commit erases the
        sector it leaves.  On the emulator flash_erase_word() is compiled out
        entirely (keepkey_flash.c is `#ifndef EMULATOR`), so the abandoned
        sectors keep their "stor" magic — and find_active_storage() takes the
        FIRST sector carrying that magic.  A rebooted emulator therefore reads
        whichever record last happened to land in STORAGE1, which can be two
        commits stale.

        Consequence if ignored: an AdvancedMode bit written one commit before
        the restart lands in STORAGE2 or STORAGE3, boot reads the older
        STORAGE1 record, and the policy reads back OFF for a reason that has
        nothing to do with it being session-scoped.  The test would pass on a
        firmware that persisted it.  Padding the commits removes the ambiguity,
        and the Experimental marker is what proves it was removed: it is set
        AFTER AdvancedMode, so any record containing it was written while
        AdvancedMode was on in RAM.  Assert the marker came back before
        asserting anything about AdvancedMode.
        """
        for _ in range(4):
            self._apply_policy_raw("Experimental", True)

    def _power_cycle(self):
        """Kill and relaunch the firmware, KEEPING its flash image.

        This is a reboot, not a wipe: emulator.img is left alone, so anything
        committed to flash comes back and anything that only lived in RAM does
        not.  There is no protocol message that reboots a KeepKey, so on a
        transport that is not a local UDP emulator this fails loudly rather than
        skipping — a skipped lifetime test is indistinguishable from a passing
        one in the report, and that is exactly how a real defect stayed hidden
        for a release.
        """
        if config.TRANSPORT is not UDPTransport:
            self.fail("power cycle requires the local UDP emulator; on real "
                      "hardware this is an operator step (unplug/replug) and "
                      "must be recorded as manual evidence, not skipped")

        port = int(str(config.TRANSPORT_ARGS[0]).split(':')[1])
        found = _emulator_process(port)
        self.assertIsNotNone(
            found, "no emulator process is bound to udp/%d" % port)
        pid, exe, cwd = found

        self.client.close()
        subprocess.run(['kill', str(pid)])
        for _ in range(100):
            if _emulator_process(port) is None:
                break
            time.sleep(0.1)
        self.assertIsNone(_emulator_process(port),
                          "emulator pid %d did not exit" % pid)

        env = dict(os.environ)
        env['KEEPKEY_UDP_PORT'] = str(port)
        subprocess.Popen([exe], cwd=cwd, env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait for the new instance to answer before reconnecting.
        deadline = time.time() + 20
        while time.time() < deadline:
            if _emulator_process(port) is not None:
                break
            time.sleep(0.1)
        self.assertIsNotNone(_emulator_process(port),
                             "emulator did not come back on udp/%d" % port)
        time.sleep(0.5)

        transport = config.TRANSPORT(*config.TRANSPORT_ARGS,
                                     **config.TRANSPORT_KWARGS)
        debug_transport = config.DEBUG_TRANSPORT(*config.DEBUG_TRANSPORT_ARGS,
                                                 **config.DEBUG_TRANSPORT_KWARGS)
        client = KeepKeyDebuglinkClient(transport)
        client.set_debuglink(debug_transport)
        client.screenshot_dir = getattr(self.client, 'screenshot_dir', None)
        client.screenshot_id = getattr(self.client, 'screenshot_id', 0)
        self.client = client
        self.client.init_device()

    # ── 1. AdvancedMode lifetime ───────────────────────────────────────

    def test_advanced_mode_is_off_after_power_cycle(self):
        """AdvancedMode must not survive a reboot, and the control must.

        Experimental and AdvancedMode are neighbouring bits of the SAME storage
        flags word (11 and 12), set by the SAME ApplyPolicies message, written
        by the SAME storage_writeStorageV16Plaintext call.  Turning both on and
        rebooting separates a persisted policy from a session one: Experimental
        comes back, AdvancedMode must not.  Experimental is set AFTER
        AdvancedMode, so the record it came back from was written while
        AdvancedMode was armed — bit 12 was offered to the writer and dropped.
        The seed and label surviving are the second control: without them a
        reboot would be indistinguishable from a factory wipe, which turns every
        policy off for the wrong reason.
        """
        self.setup_mnemonic_nopin_nopassphrase()
        self._apply_policy_raw("AdvancedMode", True)
        self._persist_marker_across_all_sectors()
        self.assertTrue(self._policy("AdvancedMode"))
        self.assertTrue(self._policy("Experimental"))

        self._power_cycle()

        self.assertTrue(self.client.features.initialized,
                        "reboot lost the seed — this modelled a wipe, not a "
                        "power cycle, and proves nothing about persistence")
        self.assertEqual(self.client.features.label, 'test')
        self.assertTrue(self._policy("Experimental"),
                        "the marker policy did not come back, so the record "
                        "read at boot predates the AdvancedMode change and no "
                        "conclusion about bit 12 can be drawn from it")
        self.assertFalse(self._policy("AdvancedMode"),
                         "AdvancedMode came back ON after a power cycle — it "
                         "is being persisted to flash, which storage.c "
                         "explicitly forbids (bit 12 is burned)")

    def test_advanced_mode_survives_initialize_but_not_clear_session(self):
        """The asymmetry in session_clear() is deliberate; pin it down.

        session_clear_impl() disarms AdvancedMode only when clear_pin is set.
        ClearSession passes true, Initialize passes false.  Hosts send
        Initialize before nearly every operation, so disarming there would cost
        a fresh button press each time; ClearSession is an explicit lock and
        must revoke the capability.  If this ever inverts, blind signing either
        becomes unusable or outlives the lock.
        """
        self.setup_mnemonic_nopin_nopassphrase()
        self._apply_policy_raw("AdvancedMode", True)

        self.client.call(proto.Initialize())
        self.assertTrue(self._policy("AdvancedMode"),
                        "Initialize disarmed AdvancedMode — every host sends "
                        "it routinely, so the policy would be unusable")

        self.client.clear_session()
        self.assertFalse(self._policy("AdvancedMode"),
                         "ClearSession left AdvancedMode armed — an explicit "
                         "lock must revoke the blind-signing capability")

    # ── 2. Loaded-signer lifetime ──────────────────────────────────────

    def test_signer_dropped_by_initialize(self):
        """Session teardown revokes the signer while the policy stays armed.

        The MALFORMED here is unambiguous: AdvancedMode is asserted still ON
        immediately before the probe, so the metadata gate cannot be what
        refused it — the slot is empty.  The GetFeatures probe first is the
        negative control: merely exchanging messages must NOT drop a signer, or
        this test would pass for the wrong reason.
        """
        self._arm_session()

        self.client.call(proto.GetFeatures())
        self._assertClassification(
            CLASSIFICATION_VERIFIED,
            "an ordinary message dropped the signer; the teardown assertion "
            "below would then prove nothing")

        self.client.call(proto.Initialize())
        self.assertTrue(self._policy("AdvancedMode"))
        self._assertClassification(
            CLASSIFICATION_MALFORMED,
            "the signer survived session teardown — runtime trust must not "
            "outlive the session that consented to it")

    def test_signer_dropped_by_clear_session(self):
        """ClearSession revokes both halves of the trust.

        Right after the lock the metadata message is refused outright, because
        ClearSession also disarmed AdvancedMode — that Failure is the policy
        gate, not evidence about the slot.  Re-arming the policy WITHOUT an
        Initialize isolates the slot: MALFORMED then means the signer itself is
        gone.
        """
        self._arm_session()

        self.client.clear_session()

        with self.assertRaises(CallException) as ctx:
            self._signer_still_loaded()
        self.assertIn("AdvancedMode required", str(ctx.exception))

        self._apply_policy_raw("AdvancedMode", True)
        self._assertClassification(
            CLASSIFICATION_MALFORMED,
            "the signer survived ClearSession — an explicit lock left provider "
            "trust loaded in RAM")

    def test_signer_dropped_by_power_cycle(self):
        """Reboot drops the signer; the seed proves it was a reboot.

        Loaded signers are RAM only, so this should be true by construction —
        but "by construction" is exactly the claim a persist=true bug would
        break, and the report needs the reboot on record rather than inferred.
        Storage is preserved (see _power_cycle), so the surviving seed, label
        and marker policy rule out a wipe having done the work.  The marker is
        set after the signer is loaded, so the record the device boots into is
        one that was written while the signer was live — if a build ever did
        persist signers, this is the record it would have persisted them into.
        """
        self._arm_session()
        self._persist_marker_across_all_sectors()

        self._power_cycle()

        self.assertTrue(self.client.features.initialized,
                        "reboot lost the seed — this modelled a wipe, not a "
                        "power cycle")
        self.assertEqual(self.client.features.label, 'test')
        self.assertTrue(self._policy("Experimental"),
                        "the marker policy did not come back, so flash was not "
                        "preserved across the restart")
        self.assertFalse(self._policy("AdvancedMode"))

        self._apply_policy_raw("AdvancedMode", True)
        self._assertClassification(
            CLASSIFICATION_MALFORMED,
            "the signer came back after a power cycle — it was written to flash")

    def test_disabling_advanced_mode_makes_signer_inert_not_erased(self):
        """MEASURED behaviour, and it is NOT "disabling AdvancedMode clears the
        signer".

        Turning the policy off does make the signer unusable: every consumer in
        signed_metadata.c (signed_metadata_process, _verify_attestation,
        _signer_fingerprint) refuses a runtime slot while AdvancedMode is off,
        so the metadata message fails closed.  But nothing erases the slot —
        storage_setPolicy() only flips a policy bit, and only session_clear()
        calls signed_metadata_clear_signers().  Turn the policy back on and the
        old signer verifies again, with NO second trust screen: the expected
        response list below is exactly one ApplyPolicies ButtonRequest and a
        Success, so the "Trust 'CI Test' (…) NOT verified by KeepKey" consent is
        provably not re-shown.

        Why the host path looks otherwise: ProtocolMixin.apply_policy() follows
        every policy change with Initialize, and it is that Initialize — not the
        policy change — that clears the signer (test_signer_dropped_by_initialize).
        A host that sends the bare message gets the behaviour asserted here.

        Consequence to weigh at release: a user who disables AdvancedMode to
        revoke a provider has not revoked it, only suspended it.  Re-enabling
        the policy costs one button press whose screen names the policy and
        never names the signer it silently re-arms.
        """
        self._arm_session()

        self._apply_policy_raw("AdvancedMode", False)
        with self.assertRaises(CallException) as ctx:
            self._signer_still_loaded()
        self.assertIn("AdvancedMode required", str(ctx.exception))

        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(
                    code=proto_types.ButtonRequest_ApplyPolicies),
                proto.Success(),
            ])
            self._apply_policy_raw("AdvancedMode", True)

        self._assertClassification(
            CLASSIFICATION_VERIFIED,
            "the signer did NOT survive the policy toggle. That is stricter "
            "than the code path allows today, so something changed: re-read "
            "storage_setPolicy() and signed_metadata_clear_signers() before "
            "loosening this assertion")


if __name__ == '__main__':
    unittest.main()
