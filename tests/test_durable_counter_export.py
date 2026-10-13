"""CSV accounting covers every measured durable-network counter."""
import csv
import json
from dataclasses import asdict
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from durable_witness_network import DurableNetworkCounters
from durable_witness_study import _fork_recovery_fields, _write_csv


class DurableCounterExportTests(unittest.TestCase):
    def test_all_counter_columns_are_retained(self):
        counters = asdict(DurableNetworkCounters(history_events=17))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'cases.csv'
            _write_csv(path, [{'case': 'owned-export', **counters}])
            with path.open(newline='') as stream:
                rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 1)
        self.assertTrue(set(counters).issubset(rows[0]))
        self.assertEqual(rows[0]['history_events'], '17')

    def test_fork_frontier_names_the_checked_honest_witness_not_committee_minimum(self):
        retained = {'w0': 24, 'w1': 24, 'w2': 24, 'w3': 0}
        fields = _fork_recovery_fields(retained, 24)
        self.assertEqual(fields['recovered_witness'], 'w1')
        self.assertEqual(fields['recovered_count_before_retry'], 24)
        self.assertEqual(fields['expected_recovered_count'], 24)
        self.assertEqual(fields['recovered_frontiers'], retained)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'cases.csv'
            _write_csv(path, [{'case': 'owned-frontier-export', **fields}])
            with path.open(newline='') as stream:
                row = next(csv.DictReader(stream))
        self.assertEqual(json.loads(row['recovered_frontiers']), retained)
        self.assertEqual(row['recovered_count_before_retry'], row['expected_recovered_count'])

    def test_missing_checked_witness_is_not_reported_as_successful_recovery(self):
        fields = _fork_recovery_fields({'w3': 0}, 24)
        self.assertEqual(fields['recovered_count_before_retry'], -1)


if __name__ == '__main__':
    unittest.main()
