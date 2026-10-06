# Model and evidence boundary

## Two explicit acknowledgement contracts

The artifact keeps a **single-sequencer** contract and a separate **witnessed crash-recovery** contract. Results from one are not silently relabeled as evidence for the other.

Under the single-sequencer contract, each namespace has one honest, non-forking authority. Its in-memory acceptance is the event frontier. Complete prefixes, signed object status, and honest ScopeDelta are compared at identical frontiers. These experiments establish representation and freshness boundaries only under issuer completeness.

Under the witnessed contract, the sequencer may be Byzantine. Each namespace has four fixed witnesses and at most one is Byzantine. A client accepts only an authority-signed exact body with three distinct designated witness signatures. An honest witness independently validates the complete candidate history, replays authority transitions, recomputes the exact-key projection, enforces append-only branch extension and stable-slot consistency, and checks the common timestamp against a local bounded clock.

Before an honest witness releases a signature, it persists the accepted history, scope table, signed-slot digest, and logical clock. Persistence uses a flushed and fsynced temporary file, atomic replacement of the previous snapshot, and directory fsync. A crash before replacement leaves the old snapshot authoritative and releases no signature; after replacement and directory synchronization complete, a crash recovers the new snapshot. An ordinary failure before replacement rolls memory back. A post-replacement directory-durability failure returns no signature and marks the live object unavailable until restart, preventing memory/disk divergence from becoming a signing oracle. A repeated proposal is idempotent, whereas a different body for the same stable slot is rejected after recovery.

An event is effective only after it appears in a quorum-certified checkpoint or report. A private sequencer receipt is not an acknowledgement under this contract. The contract assumes fail-stop witness processes and retained non-malicious stable storage. It is not dynamic Byzantine consensus, malicious-storage protection, disk-loss tolerance, committee reconfiguration, aggregate signing, or cross-namespace atomic commit.

## Serving predicate and time frontiers

A read names an immutable root key. It is served only when all exact manifest dependencies are present and valid at coherent authenticated namespace frontiers, the reached graph is acyclic and within bounds, remembered namespace floors are not rolled back, and every reached namespace has fresh evidence. Manifest dependencies are strings in strictly sorted, duplicate-free order at authority, witness, and client boundaries. Acceptance times are nondecreasing.

Implemented issuance-frontier checks are stated interface by interface rather than as a blanket claim. The honest authority head, full signed-status producer, compact signed-status producer, and ScopeService registration, renewal, and extension reject `issued` before the latest accepted event. Registration and extension perform that check before allocating a new handle; stale renewal/extension attempts leave service state unchanged. Equality with the latest accepted event is valid. Witness report bodies are checked separately by each witness against the replayed candidate history, and durable reload validates time against the retained logical clock.

For one honest issuer and endpoint error `epsilon`, the guard is:

```text
client_now - issued + 2*epsilon < Delta
```

For a witnessed certificate, one extra comparison between the sequencer's common timestamp and an honest witness's local clock is included:

```text
client_now - issued + 3*epsilon < Delta
```

Certificate admission and every later witnessed-cache serve decision use the witnessed guard. A public-API regression with `epsilon=2` and `Delta=10` admits a certificate issued at 14 against witness reading 12 and client reading 10, serves at client reading 17, rejects the strict endpoint 18, quorum-acknowledges a revocation, and rejects the isolated old cache at reading 19. A separate public-API regression confirms that the honest-issuer scope path retains its `2*epsilon` policy, serving at 19 and expiring at 20. The 2,625-assignment checker finds no violation with `3*epsilon` and preserves five unsafe `2*epsilon` negative controls; it supplements rather than substitutes for the real API tests. The logical clock stored by a durable witness is monotonic across restart; a backstep is rejected.

## Scope and invalidators

Artifact keys identify a namespace. Publications are immutable. A second distinct manifest for one key, exact-key revocation, and revocation of the capability that admitted a manifest are permanent invalidators. Owner transfer affects later admissions but does not retroactively invalidate an admitted immutable publication. Exact duplicate publication is status-neutral.

A ScopeDelta scope is one bounded exact-key set in one namespace. Its handle commits to namespace and sorted keys. Registration and extension return complete state; renewal returns the exact relevant conflicts and revocations. Content-derived immutable handles make a lost extension response retry-safe. Extension preserves the old handle rather than overwriting it. The durable witness snapshot retains every old and current scope handle required to validate retries and later projections.

## What each evidence path proves

- A complete prefix lets its verifier replay every presented event, authority transition, conflict, and revocation.
- Honest signed status lets one trusted issuer perform that fold.
- Honest ScopeDelta lets the issuer project only causes that can change a remembered exact scope.
- Witnessed ScopeDelta moves replay and projection checking to a 3-of-4 committee, tolerating a Byzantine sequencer and at most one Byzantine witness for quorum-visible history.
- Persist-before-sign durable witnesses preserve the honest signer's branch and stable-slot refusal state across fail-stop restart, provided the snapshot is retained and not maliciously rewritten.

No path proves that an event outside its declared acknowledgement history exists. Full prefixes expose richer historical witnesses to the client; witnessed deltas expose much less history and shift storage, replay, traffic, and durable commit work to the certification plane.

## State and traffic accounting

Witness traffic and witness state are separate quantities. Traffic counts canonical uncompressed request/response JSON for the client and sequencer-to-witness planes. Witness state sums canonical durable-state payload bytes across **all four witnesses** in every used namespace. The payload includes witness identity, retained full log, every immutable scope handle, stable slot/digest entries, logical clock, and clock epsilon. It excludes the outer commitment envelope and newline, filesystem metadata, allocator overhead, RSS, compression, and physical write amplification.

The state model is compared with actual protocol objects at four transitions. Registration is 6,144 aggregate bytes with four scope and four slot entries; extension is 7,376 bytes with eight scope and eight slot entries; a state-changing renewal is 9,056 bytes with eight scopes and twelve slots; an idempotent retry of that same stable slot remains 9,056 bytes and adds no entry. Across 96 traces the corrected aggregate state median is 544,248 bytes (531.5 KiB) and maximum is 7,106,444 bytes (6,939.9 KiB). The client-plane and total-plane traffic win counts remain 87/96 and 48/96 respectively; state correction is not used to rewrite those traffic results.

## Retained evidence

- 48 single-sequencer network campaigns and 336 policy runs.
- 96 honest renewal traces and 96 charged causal selector traces.
- 30 actual-signature honest ScopeDelta checks: 24 updates plus six extensions, counted once.
- 96 witnessed cost traces with client and certification planes separated.
- Four actual/model state-accounting transitions covering registration, extension, state change, and same-slot retry.
- 45 actual-Ed25519 witness-network cases across four distinct loopback listeners in one process, including 18 omission attacks.
- 33 actual-Ed25519 process-isolated durability cases across four witness processes and listeners.
- The current 134-test suite passes in full without skips on Linux. Earlier 125-test and 130-test Windows records retain their original scope; the latter passes 113 and skips 17 POSIX durability tests.
- 5,880 original fixed delivery orders and 500 random differential histories comparing prefix, full signed status, and oracle only.
- 80 ordered quorum/fault checks and 2,625 witnessed clock assignments.

The durability matrix consists of 24 injected crashes across three commit windows, six full-committee restarts followed by conflicting forks, two damaged-state cases, and one post-restart logical-clock rollback. All 33 outcomes match expectation. It exchanges 560 certification messages and 6,292,402 certification application bytes; 1,284 harness-control messages and 134,885 control bytes are reported separately. Timing fields are host diagnostics and support no latency claim.

## Explicit limits

The four crash-durable witnesses run in separate Python processes and retain separate state files, but they share one host, kernel, scheduler, and storage subsystem. Histories, closures, manifests, paths, scopes, service scope tables, frames, counters, and signed-slot tables are explicitly bounded; the signed-slot table permits 65,536 distinct stable slots and then accepts only an idempotent retry of an existing slot. The experiment does not model machine-independent failure domains, disk loss, malicious snapshot rollback, torn writes outside the stated filesystem assumptions, WAN delay, throughput, load, committee changes, key rotation, garbage collection, or production storage engines.

Proofs are handwritten and executable checks are finite checks, not a mechanized proof or independent reimplementation. The random differential generator does not implement random ScopeDelta state transitions and no such claim is made.

## Reachability and branch compatibility

All three honest witnesses being reachable is necessary but not sufficient for progress. Valid but uncertified competing histories can lock the honest witnesses 2-to-1. Under Byzantine withholding neither branch then reaches quorum. `results/journal-boundary.json` contains eight actual-signature cases, including two such counterexamples and unanimous controls. No view change, branch reset, or recovery from this split is implemented; readers fail closed once evidence expires. The independent Go enumerator checks standard threshold-set conditions only.

Current finite reachability output therefore reports `honest_signer_threshold_rows_by_reachable_count`, not guaranteed liveness. Signing also needs compatible retained branches, a timely valid body, available state capacity, and successful persistence. Historical JSON is preserved unchanged rather than retroactively relabelled as newly executed evidence.

## Current portable re-execution

`src/scientific_checks.py` runs all reviewed finite semantic/encoded-size studies and the complete 48-case six-listener campaign into a new directory. The four-listener study now checks the actual target-namespace cache against accepted-history status and frontier data in each of 24 valid updates; a regression deliberately drops renewal and detects the mismatch even with quorum signatures. This is a scope-local predicate, not a whole-root serving check. The fresh platform summary is `results/local-checks.json`.

On Windows, Linux RSS is null and POSIX address-space/CPU limits are not applied; the runner supplies a bounded wall-time budget instead. That run does not execute directory-fsync durability or Go. The complete Linux run in `results/current/` executes both paths: all 33 durability cases and the independent Go census pass, alongside 134 unit tests and the complete 48-case/336-policy semantic reproduction. Host timings remain separate, and the stated storage assumptions and negative controls still apply.
