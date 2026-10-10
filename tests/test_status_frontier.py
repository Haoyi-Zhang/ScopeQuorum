"""Small metadata-only coherence checks; no signing, histories, or network."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import status_reference


def report(namespace, count):
    return {'body': {'ns': namespace, 'count': count, 'issued': 4,
                     'objects': []}, 'signature': 'unused-mocked-signature'}


class StatusFrontierTests(unittest.TestCase):
    def check(self, *reports):
        with patch.object(status_reference, 'verify', return_value=True):
            return status_reference.check_status(
                dict(enumerate(reports)), 'n1/absent', 5, {})

    def test_equal_batches_reach_missing_object_check(self):
        result = self.check(report('n1', 2), report('n1', 2))
        self.assertEqual(result['reason'], 'INVALID_OR_MISSING_STATUS')
        self.assertEqual(result['observed'], {'n1': 2})

    def test_unequal_batch_counts_fail_in_either_order(self):
        for counts in ((2, 3), (3, 2)):
            with self.subTest(counts=counts):
                result = self.check(*(report('n1', n) for n in counts))
                self.assertEqual(result['reason'], 'BAD_STATUS')
                self.assertFalse(result['serve'])

    def test_different_namespaces_keep_independent_frontiers(self):
        result = self.check(report('n1', 2), report('n2', 3))
        self.assertEqual(result['reason'], 'INVALID_OR_MISSING_STATUS')
        self.assertEqual(result['observed'], {'n1': 2, 'n2': 3})


if __name__ == '__main__':
    unittest.main()
