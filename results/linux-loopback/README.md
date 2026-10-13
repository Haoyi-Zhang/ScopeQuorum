# Current Linux protocol observations

These JSON files are exact selected members of the owned scientific run
38474378008, using source commit
`1679d4054efbe6b1ee9a81292b92c164c9c3d37a` in the public ScopeQuorum repository.
They were retrieved from its uploaded scientific artifact and checked against
the archive digest supplied by GitHub. The original older records are not
rewritten.

`run.json` records thirteen successful commands, actual environment, parameter
choices and result checks. `unit.json` records 175 tests, all passing with no
skips; `quick-verification.json` separately reruns its current inventory gate
and finite checks. The main semantic reproduction matches the 48-case reference.

`durable-summary.json` contains all 33 process-isolated outcomes: 24 crash
windows, six full restarts, two damaged-state cases and one clock rollback.
The six full-restart rows expose every node's frontier; w1 and w2 retain the
certified branch, untouched w3 remains zero, and the later conflicting proposal
gets two signatures. Incremental transport totals are 1,598 certification
messages and 3,511,524 certification bytes. Harness-control traffic is separate.

`network-summary.json` contains all 45 listener cases and 24 cache-state checks,
with 2,176 messages and 6,696,031 framed bytes. These are target-scope protocol
paths; `read-summary.json` and `read-accounting.json` cover the separate full-root
two-plane experiment. Its 120 paired decisions agree, with 72 serve and 48 deny
per mode. Prefix totals 5,135,621 application bytes and scope 5,616,627; scope
reduces client traffic in twelve traces and total traffic in one.

The measured host is Linux 6.17.0-1022-azure with Python 3.12.15 and cryptography
50.0.2. `/proc/cpuinfo` reports AMD EPYC 9V45; the runner has four available
logical processors. The physical core count is unknown. Clock inputs are
logical; the recovery processes share one host and retained storage. CPU/RSS
diagnostics are not production throughput or physical write measurements.

The workflow retains raw logs and per-read exports; the public Windows
TCP-read collection provides the complete same-schedule per-read observations
used for the paper's instrumented Windows timings. Linux repeats the same
decisions and framed-byte totals. Neither collection is a native external
registry, WAN or independent-machine deployment study.
