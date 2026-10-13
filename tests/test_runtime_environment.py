import json
import subprocess
import unittest
from unittest.mock import patch

from runtime_environment import cpu_metadata, current_environment


class RuntimeEnvironmentTests(unittest.TestCase):
    def test_linux_model_is_read_not_inferred(self):
        with patch('runtime_environment.sys.platform', 'linux'), \
             patch('runtime_environment.os.cpu_count', return_value=2), \
             patch('runtime_environment.Path.read_text', return_value=
                   'model name : Example CPU\nmodel name : Example CPU\n'):
            self.assertEqual(cpu_metadata(), {'models': ['Example CPU'],
                             'physical_cores': None, 'logical_processors': 2,
                             'source': '/proc/cpuinfo'})

    def test_missing_linux_source_remains_unknown(self):
        with patch('runtime_environment.sys.platform', 'linux'), \
             patch('runtime_environment.Path.read_text', side_effect=OSError):
            self.assertEqual(cpu_metadata()['models'], [])
            self.assertIsNone(cpu_metadata()['source'])

    def test_windows_cim_uses_actual_fields(self):
        result = subprocess.CompletedProcess([], 0, json.dumps(
            {'Name': 'Example CPU', 'NumberOfCores': 3, 'NumberOfLogicalProcessors': 6}))
        with patch('runtime_environment.sys.platform', 'win32'), \
             patch('runtime_environment.subprocess.run', return_value=result):
            self.assertEqual(cpu_metadata(), {'models': ['Example CPU'],
                             'physical_cores': 3, 'logical_processors': 6,
                             'source': 'Win32_Processor'})

    def test_windows_invalid_or_failed_source_remains_unknown(self):
        for outcome in ('not JSON', json.dumps({'Name': 'CPU', 'NumberOfCores': True,
                                               'NumberOfLogicalProcessors': 4})):
            with self.subTest(outcome=outcome), \
                 patch('runtime_environment.sys.platform', 'win32'), \
                 patch('runtime_environment.subprocess.run', return_value=
                       subprocess.CompletedProcess([], 0, outcome)):
                self.assertEqual(cpu_metadata()['models'], [])
                self.assertIsNone(cpu_metadata()['physical_cores'])
        with patch('runtime_environment.sys.platform', 'win32'), \
             patch('runtime_environment.subprocess.run', side_effect=
                   subprocess.TimeoutExpired('powershell', 15)):
            self.assertEqual(cpu_metadata()['models'], [])

    def test_environment_does_not_guess_affinity(self):
        with patch('runtime_environment.cpu_metadata', return_value={'models': []}), \
             patch('runtime_environment.os.sched_getaffinity', create=True,
                   side_effect=OSError):
            self.assertIsNone(current_environment()['available_affinity_processors'])


if __name__ == '__main__':
    unittest.main()
