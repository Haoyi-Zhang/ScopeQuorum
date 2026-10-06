# Crash-durable witnessed provenance-closed registry reads

This repository studies freshness, revocation, acknowledgement, and evidence transfer for immutable cross-namespace registry dependencies. It keeps two contracts separate:

- an **honest single-sequencer** model used to compare complete prefixes, signed status, coherent caching, and issuer-computed ScopeDelta; and
- a **3-of-4 witnessed crash-recovery** model in which witnesses independently replay exact-scope projections, durably commit accepted branch/slot state before releasing a signature, and recover that state after fail-stop restart.

The implementation uses the Python standard library plus `cryptography`, declared in `requirements.txt`. All keys and histories are public deterministic test fixtures. No private registry, external service, GPU, model API, or public deployment is used.

## Quick verification

From the repository root:

```sh
python -m unittest discover -s tests -p 'test_*.py' -v
python tests/finite.py --output ../verification-finite.json
python tests/differential.py \
  --output ../verification-differential.json \
  --iterations 500 --seed 20260910
python tests/witness_finite.py \
  --output ../verification-witness-finite.json
```

Expected current results are:

- 134 directed tests in the current suite; a supported POSIX host is required for all durability tests. The 130-test Windows campaign passes 113 and explicitly skips 17 POSIX durability tests; four subsequently added command-runner regressions also pass separately;
- 5,880 fixed delivery orders with zero protected-predicate violation;
- 500 random differential histories with zero prefix/status/oracle decision mismatch;
- 80 ordered witness quorum/fault checks and 32 concurrent-fork first-arrival assignments with zero safety failure; and
- 2,625 witnessed clock assignments with zero `3*epsilon` failure, while the deliberately weakened `2*epsilon` guard preserves five unsafe negative controls.

## Rebuild the bounded studies

For a new complete bounded run, including all 48 six-listener cases, use a previously nonexistent output directory:

```sh
python -B src/scientific_checks.py --output ../scientific-checks
```

This runner preserves command logs, raw observations, dependency versions, and platform metadata. It enforces a 30-minute overall wall-time budget and a 15-minute bound per command; it never compiles the paper or overwrites retained results. On Windows it runs the full portable semantic campaign, records unavailable Linux RSS as null, and explicitly omits the 33-case directory-fsync durability study and 17 related unit tests. POSIX CPU/address-space limits are not applied on Windows; that absence is recorded, not simulated. The Go checker runs only when a local toolchain exists, with network toolchain/module downloads disabled.

The `scientific-checks.yml` workflow runs on pushes to `main` or manual dispatch. It uses Ubuntu 24.04 and Python 3.12, installs the declared Python dependency in a runner-temporary virtual environment, runs into a unique `RUNNER_TEMP` directory, and uploads raw output even on failure. The complete current run passed all 134 tests without skips, all 33 durability cases, the 48-case/336-policy logical reproduction, and the separate Go census (385 rows, 250,942 quorum pairs, 55 existence cases). Its raw results and actual environment are in `results/current/`. The earlier Windows portable summary is `results/local-checks.json`; it does not claim unsupported durability or Go execution.

```sh
python src/renewal_study.py \
  --output ../verification-renewal \
  --generated ../verification-generated

python src/selector_study.py \
  --renewal-traces ../verification-renewal/traces.json.gz \
  --output-dir ../verification-selector \
  --paper-generated ../verification-generated

python src/witness_study.py \
  --output ../verification-witness \
  --generated ../verification-generated

python src/witness_network_study.py \
  --output ../verification-witness-network

python src/durable_witness_study.py \
  --output ../verification-durable-witness \
  --generated ../verification-generated
```

The witness-network study runs 45 actual-Ed25519 cases over four distinct loopback listeners in one Python process. Its 24 valid-update rows now also compare the actual client cache's manifests, validity, count, tip, and issuance time with the accepted-history reference. A dropped-client-renewal regression confirms that signer counts alone cannot pass this check. The validity check is namespace-local, not a whole multi-namespace root serve decision. The historical process-isolated crash-recovery study instead runs four witness services in **four separate Python processes**, each with a separate TCP listener and state directory. It executes 33 cases:

- 24 injected crashes at `before-commit`, `after-temp-fsync`, and `after-replace` windows;
- six full-committee restarts followed by a conflicting-fork attempt;
- two damaged-state fail-closed cases; and
- one persisted logical-clock rollback case.

All 33 retained outcomes pass. The persist-before-sign path writes a canonical snapshot to a temporary file, flushes and fsyncs it, atomically replaces the prior snapshot, fsyncs the containing directory, and only then releases a signature. Reload validates snapshot identity and commitment, canonical one-namespace scopes, retained-history/tip bindings, report slots against available history, temporal consistency with the durable logical clock, and the signed-slot cardinality bound. Additional unit fault injection covers temporary-file fsync failure, replace failure, and directory-fsync failure after replacement. Pre-replace errors roll back and remain usable; a post-replace durability error releases no signature and poisons the process-local witness until restart. A retry after restart is idempotent for the same body and rejects a conflicting body for the same stable slot.

## Reload the canonical 48-case campaign

The complete retained main campaign is under `results/case-01.json.gz` through `results/case-48.json.gz`. Reload and compare it without rerunning the several-minute campaign:

```sh
python src/analyze.py \
  --results results \
  --output ../verification-analysis \
  --compare results/clean-repetition \
  --compare-semantic results/semantic-reference.json.gz
```

To execute selected campaigns again:

```sh
python src/reproduce.py --cases 1:2 --output ../verification-cases --resume
```

Run remaining ranges in bounded chunks. `src/reproduce.py` uses atomic checkpoints. The retained campaign is deterministic in logical observations; host timing and peak RSS are diagnostics and are excluded from semantic comparison.

## Result map

- `results/analysis/summary.json`: seven-policy single-sequencer campaign summary.
- `results/renewal/`: 96 honest renewal traces, fault matrix, real-object length checks, and causal selector results.
- `results/witness/`: 96 witnessed-prefix versus witnessed-scope traces, adversarial checks, and separated client/certification byte accounting.
- `results/witness-network/summary.json`: 45 in-process four-listener cases and wire counters.
- `results/durable-witness/`: 33 process-isolated crash/restart/corruption cases and their summary.
- `results/witness-finite.json`: committee, reachability, and clock enumeration.
- `results/local-checks.json`: fresh Windows execution summary, with unsupported durability/Go checks separated from completed studies.
- `proofs/theorems.md`: assumptions and handwritten arguments, including persist-before-sign crash atomicity.
- `claim_evidence_ledger.csv`: claim-to-evidence mapping.
- `external_resources.csv`: scholarly, standards, software, and data sources.

## Main bounded findings

Under one honest sequencer, dependency-scoped prefixes and signed object status make the same 192 main decisions in the canonical campaign. Both have zero bounded violations; root-only freshness has 18. Honest ScopeDelta is smaller than full-prefix transfer in all 96 original renewal traces, but cached status remains cheaper in 42 traces.

Under the witnessed contract, an omitted exact revocation, capability revocation, or conflict obtains only the configured Byzantine witness's signature, not a quorum. Any two 3-of-4 quorums intersect in an honest witness when at most one witness is Byzantine. A quorum-acknowledged revocation therefore cannot later be hidden by a stale fork, including after all four witness-process states have been reloaded from retained stable storage.

The honest ScopeDelta protocol evidence contains **30 actual-signature checks counted once**: 24 update cases and six extension cases. The 500-history differential generator instead compares prefix, full signed status, and the independent oracle; it does not model random ScopeDelta state transitions.

The 33 crash-recovery cases refine that statement:

- crashes before the atomic replace recover the old state and return no signature;
- crashes after the durable replace recover the new state, so repeating the request is safe;
- six full-committee restarts preserve the original quorum branch and block a conflicting fork;
- unreadable or commitment-mismatched state refuses service rather than silently resetting; and
- a persisted logical clock rejects a post-restart backstep.

In the incremental-history encoding model, witnessed exact-scope deltas transfer fewer client bytes than witnessed prefixes in 87/96 traces (median ratio 0.46). Counting witness synchronization and certification gives 48/96 total-byte wins and a median ratio of approximately 1.00; certification is 89.9% of scope traffic at the median. The model sends unseen history in 128-event suffix batches, then a body-only signing request. Both TCP prototypes instead resend complete histories per certification. These wins and crossover describe the incremental model, not their measured transport.

Witness state is accounted separately as canonical durable payload bytes summed across all four witnesses. The model retains full logs, every immutable old/current scope handle, stable slot/digest entries, witness identity, clock, and clock epsilon. It matches actual protocol objects at registration (6,144 B), extension (7,376 B), state-changing renewal (9,056 B), and same-slot retry (9,056 B with no growth). Across 96 traces the corrected median is 531.5 KiB and maximum 6,939.9 KiB. This state correction does not alter the verified traffic win counts above.

## Assumptions and limits

Crash durability assumes fail-stop processes and a retained, non-malicious local state file with filesystem semantics sufficient for flushed temporary-file creation, atomic replacement, and directory fsync. Manifests use sorted duplicate-free string dependencies; evidence issuance cannot precede the latest accepted event; and each witness retains at most 65,536 distinct stable signed slots, preserving only same-slot idempotent retry at the bound. The artifact fails closed on the ordinary I/O errors it injects; it does **not** claim tolerance of disk loss, malicious stable-storage rollback, a filesystem or kernel that violates those primitives, dynamically reconfigured committees, key rotation, cross-namespace atomic commit, aggregate signatures, TLS, compression, multitenant scope reclamation, WAN latency, or production load.

The four durable witnesses are separate processes but still share one host, kernel, and storage subsystem. The timing fields in `results/durable-witness/summary.json` are retained host diagnostics, not portable performance results. A quorum-visible history remains the contract boundary: the mechanism cannot reveal a receipt that the sequencer never presents to an honest witness.

See `docs/model-and-evidence.md` before reusing any claim.

## License

The artifact implementation and documentation are under the license in `LICENSE`. The retained public lockfile projection and its upstream notices are under `data/licenses/`.

## Journal safety/availability boundary checks

The manuscript targets IEEE Transactions on Dependable and Secure Computing. The underlying artifact is standalone and does not require the paper directory.

```sh
python src/boundary_study.py --output ../verification-boundary.json
GOMAXPROCS=2 go run checks/quorum.go > ../verification-quorum.json
python src/verify_artifact.py --output ../verification-artifact
```

The Go checker requires a local Go toolchain and only the Go standard library; it makes no network requests and imports no Python prototype code. It enumerates 385 fixed-threshold parameter rows, 250,942 quorum-pair checks and 55 existence cases. This is independent set enumeration, not an independent registry reimplementation.

The eight actual-signature cases distinguish threshold feasibility from progress. A Byzantine sequencer can split reachable honest witnesses between two individually valid, uncertified branches. With the Byzantine witness withholding, the 2-to-1 and 1-to-2 assignments both prevent a certificate. These are expected counterexamples, not test failures or fixed liveness bugs. No unsafe branch reset is implemented.

`results/journal-repetition/` retains an earlier bounded repetition. Its witness, durability and 96-trace outputs were compared with the canonical results; six main campaigns were compared individually with the canonical 48-case campaign. The canonical 48 cases and their earlier complete repetition remain under `results/` and `results/clean-repetition/`. That earlier journal repetition did not rerun all 48 cases. An interrupted 5,000-history attempt yielded no completed result; its completed differential check contains 500 histories. Interrupted invocations and resumptions remain disclosed in its execution record. The distinct fresh Windows run is identified by `results/local-checks.json` and is not used to refresh unsupported durability or Go observations.

The quick verifier checks retained consistency and reruns tests, finite checks, actual boundary signatures and the Go program. It does not rerun every long network study. The explicit commands above are the complete study entry points; never equate a quick verifier pass with a complete new experimental campaign. Do not run Python with `-O`, because the experimental checks use assertions.
