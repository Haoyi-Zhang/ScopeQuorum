"""Regression checks for the witnessed cost/fault matrix."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from witness_study import actual_adversarial_checks, fixed_length_parity, run_trace


class WitnessStudyTests(unittest.TestCase):
    def test_all_actual_fault_contract_checks_pass(self):
        checks = actual_adversarial_checks()
        self.assertEqual(checks['passed'], checks['count'])
        self.assertGreaterEqual(checks['count'], 9)

    def test_fixed_token_certificates_match_real_lengths(self):
        parity = fixed_length_parity()
        self.assertTrue(parity['all_equal'])
        self.assertEqual(parity['count'], 2)

    def test_client_savings_do_not_imply_total_plane_savings(self):
        row = run_trace('public-lock', 1, 'increasing', 0)
        self.assertLess(
            row['client_totals']['witnessed-scope']['wire_bytes'],
            row['client_totals']['witnessed-prefix']['wire_bytes'])
        self.assertGreater(
            row['total_plane']['witnessed-scope']['wire_bytes'],
            row['total_plane']['witnessed-prefix']['wire_bytes'])

    def test_heavy_unrelated_churn_can_pay_for_projection(self):
        row = run_trace('public-lock', 1, 'hot', 16)
        self.assertLess(
            row['client_totals']['witnessed-scope']['wire_bytes'],
            row['client_totals']['witnessed-prefix']['wire_bytes'])
        self.assertLess(
            row['total_plane']['witnessed-scope']['wire_bytes'],
            row['total_plane']['witnessed-prefix']['wire_bytes'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
