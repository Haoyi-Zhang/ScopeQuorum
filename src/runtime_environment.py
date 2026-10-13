"""Collect current host metadata without inferring missing historical hardware."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
import sys

import cryptography


def cpu_metadata() -> dict:
    result = {'models': [], 'physical_cores': None,
              'logical_processors': os.cpu_count(), 'source': None}
    if sys.platform.startswith('linux'):
        try:
            text = Path('/proc/cpuinfo').read_text(encoding='utf-8')
            result['models'] = sorted({line.split(':', 1)[1].strip()
                                      for line in text.splitlines()
                                      if line.split(':', 1)[0].strip() in
                                      {'model name', 'Hardware'} and ':' in line
                                      and line.split(':', 1)[1].strip()})
            result['source'] = '/proc/cpuinfo'
        except OSError:
            pass
    elif sys.platform == 'win32':
        try:
            command = ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                       '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; '
                       '@(Get-CimInstance Win32_Processor | Select-Object Name, '
                       'NumberOfCores,NumberOfLogicalProcessors) | ConvertTo-Json -Compress']
            response = subprocess.run(command, check=True, capture_output=True,
                                      encoding='utf-8-sig', timeout=15)
            rows = json.loads(response.stdout)
            if type(rows) is dict:
                rows = [rows]
            if (type(rows) is list and rows
                    and all(type(r) is dict and type(r.get('Name')) is str
                            and r['Name'].strip()
                            and type(r.get('NumberOfCores')) is int
                            and r['NumberOfCores'] > 0
                            and type(r.get('NumberOfLogicalProcessors')) is int
                            and r['NumberOfLogicalProcessors'] > 0 for r in rows)):
                result.update(models=sorted({r['Name'].strip() for r in rows}),
                              physical_cores=sum(r['NumberOfCores'] for r in rows),
                              logical_processors=sum(r['NumberOfLogicalProcessors'] for r in rows),
                              source='Win32_Processor')
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    return result


def current_environment() -> dict:
    value = {'python': sys.version, 'platform': platform.platform(),
             'machine': platform.machine(), 'cryptography': cryptography.__version__,
             'executable': sys.executable, 'bytecode_disabled': sys.dont_write_bytecode,
             'python_optimization': sys.flags.optimize, 'cpu': cpu_metadata()}
    value['available_affinity_processors'] = None
    if hasattr(os, 'sched_getaffinity'):
        try:
            value['available_affinity_processors'] = len(os.sched_getaffinity(0))
        except OSError:
            pass
    return value
