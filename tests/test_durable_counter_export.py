"""CSV accounting covers every measured durable-network counter."""
import csv
from dataclasses import asdict
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from durable_witness_network import DurableNetworkCounters
from durable_witness_study import _write_csv


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


if __name__ == '__main__':
    unittest.main()
