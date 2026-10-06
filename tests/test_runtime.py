"""Unsupported resource measurements remain absent, without weakening semantics."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from analyze import peak_rss, semantic


class RuntimeTests(unittest.TestCase):
    def test_missing_rss_is_not_fabricated(self):
        self.assertIsNone(peak_rss([{'policies': [{'peak_rss_kib': None}]}]))
        self.assertEqual(peak_rss([{'policies': [{'peak_rss_kib': None},
                                               {'peak_rss_kib': 123}]}]), 123)

    def test_host_provenance_excluded_but_logical_observations_retained(self):
        result = {'runtime': {'platform': 'Windows'}, 'issued': 2,
                  'policy': {'serve': False, 'peak_rss_kib': None}}
        self.assertEqual(semantic(result), {'issued': 2, 'policy': {'serve': False}})
