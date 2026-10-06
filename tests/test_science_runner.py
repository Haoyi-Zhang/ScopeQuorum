"""Bounded benign command execution and complete independent-census regressions."""
from pathlib import Path
import os
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from scientific_checks import quorum_complete, run_owned


class ScienceRunnerTests(unittest.TestCase):
    def run_command(self, statement, timeout=10):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            return run_owned([sys.executable, '-B', '-c', statement], cwd=root,
                             env=dict(os.environ), log=root / 'command.log', timeout=timeout)

    def test_success_is_recorded(self):
        row = self.run_command("print('owned fixture completed')")
        self.assertEqual((row['outcome'], row['exit_code']), ('EXIT', 0))

    def test_nonzero_is_not_success(self):
        row = self.run_command('raise SystemExit(7)')
        self.assertEqual((row['outcome'], row['exit_code']), ('EXIT', 7))

    def test_timeout_reaps_owned_process(self):
        row = self.run_command('import time; time.sleep(30)', timeout=0.2)
        self.assertEqual(row['outcome'], 'TIMEOUT')
        self.assertNotEqual(row['exit_code'], 0)
        self.assertLess(row['elapsed_seconds_host_diagnostic'], 20)

    def test_census_requires_all_counts_and_zero_failures(self):
        expected = {'parameter_rows': 385, 'quorum_pair_checks': 250942,
                    'existence_checks': 55, 'failures': 0}
        self.assertTrue(quorum_complete(expected))
        for key in expected:
            changed = {**expected, key: expected[key] + 1}
            self.assertFalse(quorum_complete(changed))
