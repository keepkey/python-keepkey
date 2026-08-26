import importlib.util
import os
import unittest


REPORT_SCRIPT = os.path.join(
    os.path.dirname(__file__), '..', 'scripts', 'generate-test-report.py')
SPEC = importlib.util.spec_from_file_location('generate_test_report',
                                               REPORT_SCRIPT)
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


def catalog_results_with_solana_lut_skipped():
    results = {}
    for _, _, min_fw, _, _, tests in REPORT.SECTIONS:
        if not REPORT.ver_ge('7.15.0', min_fw):
            continue
        for _, module, method, _, _, _ in tests:
            results['%s::%s' % (module, method)] = 'pass'
    for key in list(results):
        if key.startswith('test_msg_solana_lut_attestation::'):
            results[key] = 'skip'
    return results


class TestReportVariantValidation(unittest.TestCase):

    def test_full_product_requires_solana_lut_coverage(self):
        ok, failures = REPORT.validate_junit(
            '7.15.0', catalog_results_with_solana_lut_skipped(), 'full')
        self.assertFalse(ok)
        self.assertEqual(4, len(failures))
        self.assertTrue(all(item[3] == 'skipped-but-required'
                            for item in failures))

    def test_bitcoin_only_accepts_absent_solana_lut_handlers(self):
        result = REPORT.validate_junit(
            '7.15.0', catalog_results_with_solana_lut_skipped(),
            'bitcoin-only')
        self.assertEqual((True, []), result)


if __name__ == '__main__':
    unittest.main()
