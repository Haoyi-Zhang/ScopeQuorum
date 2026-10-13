# Witnessed prefix and exact-scope reads

The read study compares two clients under the same fixed four-witness,
three-signature contract. Both use Ed25519 verification, signed receipt
commitments, count/tip frontiers, remembered floors and the witnessed
three-epsilon freshness guard. A fifth loopback listener carries client
requests and replies alongside the four memory-backed witness listeners.
All listeners share one host and Python process.

The prefix client retains complete authenticated history and an indexed
status view, and receives suffix receipts plus a witnessed checkpoint.
The scope client retains exact-key status and uses registration, extension,
renewal or unchanged-count heads. Prefix replay checks admission independently
of the scope projection, then both clients use the same closure checker.
The experiment is therefore a same-contract representation comparison,
not two independently implemented security systems.

## Workload and observation

Two graph families, namespace spans 1/3 and unrelated churn 0/1/4 give twelve
paired traces, with ten reads per mode. The lockfile family preserves the
retained ripgrep dependency topology; authority placement, schedule and faults
are authored. A common finite manifest catalogue supplies request plans.
At the fifth read two witnesses are unreachable and prior evidence is expired;
the sixth reconnects them without clearing accepted refusal state. The seventh
introduces a key revocation, capability revocation or conflicting publication.
Churn and invalidator type are paired, rather than independently randomized.

All 120 paired decisions, cached scoped statuses and count/tip/time frontiers
agree: 72 serve and 48 deny per mode. Scope reduces client bytes in every trace
and total bytes in one. The total scope/prefix ratio has median 1.1302 and
range 0.9776–1.2263.

| Framed bytes | Cached prefix | Scope |
|---|---:|---:|
| Client |1,079,145|472,175|
| Witness |4,056,476|5,144,452|
| Both planes |5,135,621|5,616,627|

Median peak aggregate serialized protocol state is 732,395 versus 675,111 bytes.
Accepted witness envelopes increase from 285,180 to 302,704 median peak bytes.
Both modes perform 1,116 signature-associated snapshot serializations, totalling
24,522,894 versus25,734,694 bytes. A lower client transfer or aggregate encoded
state is not a lower certification-plane cost.

## Accounting and reproduction

Network counts include canonical requests, replies, signatures, metadata and
newlines, including partial quorum attempts. They exclude TCP/IP, TLS,
compression and socket-setup bytes. Serialized state includes authority logs
and capability tables, retained scopes/slots, client histories/indexes/checkpoints,
accepted witness envelopes and staging. Component peak medians need not sum
to the median aggregate peak. Python heap and traced-allocation diagnostics
have distinct boundaries and exclude native/interpreter/kernel RSS.

Snapshot byte and CPU diagnostics serialize the durable envelope for each
returned witness signature. They do not perform disk writes or directory
fsync. Read CPU includes tracing and snapshot serialization; state-diagnostic
CPU is outside the read timer. These are instrumented single-run measurements,
not throughput or a statistical speedup result.

The retained raw study and validated accounting are in `results/tcp-read-20261014/`
and `results/tcp-read-accounting-20261014/`. Their environment is CPython 3.12.14,
Windows 11 build 28000, cryptography 50.0.2, Intel i7-12700KF, 12 physical cores and
20 logical processors. This study uses no device, remote deployment or native
CoSi/CHAINIAC/WAVE implementation. Earlier process-isolated fsync experiments
have a separate execution and cost boundary.

```sh
PYTHONDONTWRITEBYTECODE=1 python -B src/witness_read_study.py --output FRESH_READ_OUTPUT
PYTHONDONTWRITEBYTECODE=1 python -B src/witness_read_report.py --source FRESH_READ_OUTPUT --output FRESH_ACCOUNTING_OUTPUT --generated OWNED_GENERATED_OUTPUT
python -B -m unittest discover -s tests -p test_witness_read_study.py -v
```

Use new output directories. The report checks every pair and framed-byte
component before generating tables. Seven read regressions check exact
checkpoint binding, failure-atomic suffix admission, signer uniqueness,
freshness/floors, adapter parity and real cross-namespace invalidation.
Three export regressions additionally verify that restart records name the
honest witness whose frontier is checked, preserve every endpoint count and
retain all CSV counters. The protocol signature, branch, clock and
persist-before-sign predicates are unchanged by that reporting repair.

## Related mechanisms

Leases require write approval or expiry; OCSP and delta CRLs use an authorized
status responder or issuer. WAVE combines revocation commitments and audited
map obligations. CoSi supplies witness cosigning and aggregation; CHAINIAC
adds collectively verified update history and build correspondence. Our
executed reference is cached witnessed-prefix replay under the exact same
committee and freshness contract, rather than a native benchmark of these systems.
The manuscript bibliography contains the original papers and RFCs.

Deployment evidence would require current fsync execution, complete process
memory and I/O accounting, representative workloads, controlled timing and
independent failure domains. Transport reset preserves accepted branches and
does not reconcile a split committee, tolerate storage loss or implement
scope reclamation, committee change or reinstall recovery.
