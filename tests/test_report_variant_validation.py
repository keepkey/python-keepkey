import importlib.util
import os
import unittest


REPORT_SCRIPT = os.path.join(
    os.path.dirname(__file__), '..', 'scripts', 'generate-test-report.py')
SPEC = importlib.util.spec_from_file_location('generate_test_report',
                                               REPORT_SCRIPT)
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


def catalog_results_with_solana_lut_skipped(fw_version):
    results = {}
    for _, _, min_fw, _, _, tests in REPORT.SECTIONS:
        if not REPORT.ver_ge(fw_version, min_fw):
            continue
        for _, module, method, _, _, _ in tests:
            results['%s::%s' % (module, method)] = 'pass'
    for key in list(results):
        if key.startswith('test_msg_solana_lut_attestation::'):
            results[key] = 'skip'
    return results


class TestReportVariantValidation(unittest.TestCase):

    def setUp(self):
        self._original_missing_capabilities = os.environ.get(
            'KK_RELEASE_MISSING_CAPABILITIES')
        os.environ.pop('KK_RELEASE_MISSING_CAPABILITIES', None)

    def tearDown(self):
        if self._original_missing_capabilities is None:
            os.environ.pop('KK_RELEASE_MISSING_CAPABILITIES', None)
        else:
            os.environ['KK_RELEASE_MISSING_CAPABILITIES'] = (
                self._original_missing_capabilities)

    def test_full_7143_accepts_unimplemented_solana_lut_skip(self):
        result = REPORT.validate_junit(
            '7.14.3', catalog_results_with_solana_lut_skipped('7.14.3'),
            'full')
        self.assertEqual((True, []), result)

    def test_full_715_requires_solana_lut_coverage(self):
        ok, failures = REPORT.validate_junit(
            '7.15.0', catalog_results_with_solana_lut_skipped('7.15.0'),
            'full')
        self.assertFalse(ok)
        self.assertEqual(4, len(failures))
        self.assertTrue(all(item[3] == 'skipped-but-required'
                            for item in failures))

    def test_full_716_requires_solana_lut_coverage(self):
        ok, failures = REPORT.validate_junit(
            '7.16.0', catalog_results_with_solana_lut_skipped('7.16.0'),
            'full')
        self.assertFalse(ok)
        self.assertEqual(4, len(failures))
        self.assertTrue(all(item[3] == 'skipped-but-required'
                            for item in failures))

    def test_bitcoin_only_accepts_absent_solana_lut_handlers(self):
        result = REPORT.validate_junit(
            '7.16.0', catalog_results_with_solana_lut_skipped('7.16.0'),
            'bitcoin-only')
        self.assertEqual((True, []), result)

    def test_staged_capabilities_accept_only_their_mapped_controls(self):
        results = catalog_results_with_solana_lut_skipped('7.15.0')
        for method in (
                'PinKdfRewrapsToActiveVersionAfterCorrectPin',
                'PinUnlocksAfterRebootUnderV17',
                'PinKdfV2FlagIsVersionedInV19'):
            del results['Storage::' + method]
        os.environ['KK_RELEASE_MISSING_CAPABILITIES'] = (
            'solana-lut-attestation,storage-v19-kdf')
        self.assertEqual(
            (True, []),
            REPORT.validate_junit('7.15.0', results, 'full'))

    def test_complete_release_still_requires_staged_controls(self):
        results = catalog_results_with_solana_lut_skipped('7.15.0')
        for method in (
                'PinKdfRewrapsToActiveVersionAfterCorrectPin',
                'PinUnlocksAfterRebootUnderV17',
                'PinKdfV2FlagIsVersionedInV19'):
            del results['Storage::' + method]
        ok, failures = REPORT.validate_junit('7.15.0', results, 'full')
        self.assertFalse(ok)
        failed = {(module, method, status)
                  for _, module, method, status in failures}
        self.assertIn(
            ('Storage', 'PinKdfV2FlagIsVersionedInV19', 'missing'), failed)
        self.assertIn(
            ('test_msg_solana_lut_attestation',
             'test_attestation_does_not_replay_onto_another_transaction',
             'skipped-but-required'), failed)


class TestReportVariantEnvironmentIsolation(unittest.TestCase):

    def test_fixture_cleanup_restores_staged_capabilities(self):
        key = 'KK_RELEASE_MISSING_CAPABILITIES'
        original = os.environ.get(key)
        try:
            os.environ[key] = 'prompt-workflow-unwind,storage-v19-kdf'
            case = TestReportVariantValidation(
                'test_staged_capabilities_accept_only_their_mapped_controls')
            case.setUp()
            self.assertNotIn(key, os.environ)
            os.environ[key] = 'temporary-test-value'
            case.tearDown()
            self.assertEqual(
                'prompt-workflow-unwind,storage-v19-kdf',
                os.environ.get(key))
        finally:
            if original is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original


if __name__ == '__main__':
    unittest.main()
