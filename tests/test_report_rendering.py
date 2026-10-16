"""Regression checks for clipped report text and ambiguous product covers."""
import importlib.util
import pathlib
import re
import tempfile
import unittest
import zlib
from unittest import mock

SCRIPT = pathlib.Path(__file__).parents[1] / 'scripts/generate-test-report.py'
SPEC = importlib.util.spec_from_file_location('report_rendering', SCRIPT)
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


class TestReportRendering(unittest.TestCase):
    def test_wide_unbroken_heading_wraps_without_losing_its_tail(self):
        pdf = REPORT.PDF()
        builder = REPORT.PB(pdf)
        heading = 'W' * 128 + 'TAIL'
        builder.text(20, heading)
        lines = [item[2] for item in builder.lines]
        self.assertGreater(len(lines), 1)
        self.assertEqual(heading, ''.join(lines))
        # Helvetica W is 944/1000 em: only 28 fit in 532pt at 20pt.
        self.assertTrue(all(len(line) <= 28 for line in lines))
        builder.finish()
        self.assertIn('TAIL', pdf.pages[-1][0])

    def test_wrapped_test_labels_preserve_their_outcome_and_identity(self):
        label = 'Z99 ' + 'W' * 180 + 'TAIL'
        for status, color in [('pass', REPORT.GREEN), ('fail', REPORT.RED),
                              ('skip', REPORT.GRAY), ('', REPORT.GRAY)]:
            with self.subTest(status=status):
                builder = REPORT.PB(REPORT.PDF())
                builder.check(9, label, status)
                text = [item for item in builder.lines if item[3] != 'ding']
                self.assertGreater(len(text), 1)
                rendered = re.sub(r'\s+', '', ''.join(item[2] for item in text))
                self.assertEqual(label.replace(' ', ''),
                                 rendered[2:] if rendered.startswith('--') else rendered)
                self.assertTrue(all(item[4] == color for item in text))
                symbols = [item for item in builder.lines if item[3] == 'ding']
                self.assertEqual(int(status in ('pass', 'fail')), len(symbols))

    def test_rendered_cover_identifies_each_product(self):
        section = ('B', 'Bitcoin', '0.0.0', 'Bitcoin protocol control.', [],
                   [('B1', 'test_control', 'test_sign', 'Signature control',
                     'Requires the expected signature.', [])])
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(REPORT, 'SECTIONS', [section]), \
                mock.patch.dict(REPORT.JUNIT_CENSUS, ran=0, native=0,
                                skipped=0):
            for variant, expected in [('full', 'Product: Full firmware'),
                                      ('bitcoin-only', 'Product: Bitcoin-only')]:
                target = pathlib.Path(directory) / (variant + '.pdf')
                REPORT.render(str(target), '7.15.0',
                              {'test_control::test_sign': 'pass'},
                              variant=variant)
                streams = re.findall(rb'stream\n(.*?)\nendstream',
                                     target.read_bytes(), re.S)
                content = b'\n'.join(zlib.decompress(s) for s in streams)
                self.assertIn(expected.encode('ascii'), content)


if __name__ == '__main__':
    unittest.main()
