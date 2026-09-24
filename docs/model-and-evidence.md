# Model and evidence boundary

## Two explicit acknowledgement contracts

The artifact keeps a **single-sequencer** contract and a separate **witnessed crash-recovery** contract. Results from one are not silently relabeled as evidence for the other.

Under the single-sequencer contract, each namespace has one honest, non-forking authority. Its in-memory acceptance is the event frontier. Complete prefixes, signed object status, and honest ScopeDelta are compared at identical frontiers. These experiments establish representation and freshness boundaries only under issuer completeness.

Under the witnessed contract, the sequencer may be Byzantine. Each namespace has four fixed witnesses and at most one is Byzantine. A client accepts only an authority-signed exact body with three distinct designated witness signatures. An honest witness independently validates the complete candidate history, replays authority transitions, recomputes the exact-key projection, enforces append-only branch extension and stable-slot consistency, and checks the common timestamp against a local bounded clock.

Before an honest witness releases a signature, it persists the accepted history, scope table, signed-slot digest, and logical clock. Persistence uses a flushed and fsynced temporary file, atomic replacement of the previous snapshot, and directory fsync. A crash before replacement leaves the old snapshot authoritative and releases no signature; after replacement and directory synchronization complete, a crash recovers the new snapshot. An ordinary failure before replacement rolls memory back. A post-replacement directory-durability failure returns no signature and marks the live object unavailable until restart, preventing memory/disk divergence from becoming a signing oracle. A repeated proposal is idempotent, whereas a different body for the same stable slot is rejected after recovery.

An event is effective only after it appears in a quorum-certified checkpoint or report. A private sequencer receipt is not an acknowledgement under this contract. The contract assumes fail-stop witness processes and retained non-malicious stable storage. It is not dynamic Byzantine consensus, malicious-storage protection, disk-loss tolerance, committee reconfiguration, aggregate signing, or cross-namespace atomic commit.

## Serving predicate

A read names an immutable root key. It is served only when all exact manifest dependencies are present and valid at coherent authenticated namespace frontiers, the reached graph is acyclic and within bounds, remembered namespace floors are not rolled back, and every reached namespace has fresh evidence. Manifest dependencies are strings in strictly sorted, duplicate-free order at authority, witness, and client boundaries. Acceptance times are nondecreasing, and authority or witnessed evidence is rejected when its issuance time precedes the last accepted event it authenticates.

For one honest issuer and endpoint error `epsilon`, the guard is:

```text
client_now - issued + 2*epsilon < Delta
```

For a witnessed certificate, one extra comparison between the sequencer's common timestamp and an honest witness's local clock is included:

```text
client_now - issued + 3*epsilon < Delta
```

The finite checker finds no violation in 2,625 bounded assignments with `3*epsilon` and preserves five unsafe cases as a negative control when `2*epsilon` is substituted. The logical clock stored by a durable witness is monotonic across restart; a backstep is rejected.

## Scope and invalidators

Artifact keys identify a namespace. Publications are immutable. A second distinct manifest for one key, exact-key revocation, and revocation of the capability that admitted a manifest are permanent invalidators. Owner transfer affects later admissions but does not retroactively invalidate an admitted immutable publication. Exact duplicate publication is status-neutral.

A ScopeDelta scope is one bounded exact-key set in one namespace. Its handle commits to namespace and sorted keys. Registration and extension return complete state; renewal returns the exact relevant conflicts and revocations. Content-derived immutable handles make a lost extension response retry-safe. The durable witness snapshot retains the scope table needed to recompute future deltas after restart.

## What each evidence path proves

- A complete prefix lets its verifier replay every presented event, authority transition, conflict, and revocation.
- Honest signed status lets one trusted issuer perform that fold.
- Honest ScopeDelta lets the issuer project only causes that can change a remembered exact scope.
- Witnessed ScopeDelta moves replay and projection checking to a 3-of-4 committee, tolerating a Byzantine sequencer and at most one Byzantine witness for quorum-visible history.
- Persist-before-sign durable witnesses preserve the honest signer's branch and stable-slot refusal state across fail-stop restart, provided the snapshot is retained and not maliciously rewritten.

No path proves that an event outside its declared acknowledgement history exists. Full prefixes expose richer historical witnesses to the client; witnessed deltas expose much less history and shift storage, replay, traffic, and durable commit work to the certification plane.

## Retained evidence

- 48 single-sequencer network campaigns and 336 policy runs.
- 96 honest renewal traces and 96 charged causal selector traces.
- 96 witnessed cost traces with client and certification planes separated.
- 45 actual-Ed25519 witness-network cases across four distinct loopback listeners in one process, including 18 omission attacks.
- 33 actual-Ed25519 process-isolated durability cases across four witness processes and listeners.
- 118 directed unit tests, including canonical dependency encoding, temporal-frontier checks, uncertain durable commit, semantic snapshot validation, and bounded signed-slot retention.
- 5,880 original fixed delivery orders and 500 random differential histories.
- 80 ordered quorum/fault checks and 2,625 witnessed clock assignments.

The durability matrix consists of 24 injected crashes across three commit windows, six full-committee restarts followed by conflicting forks, two damaged-state cases, and one post-restart logical-clock rollback. All 33 outcomes match expectation. It exchanges 560 certification messages and 6,292,402 certification application bytes; 1,284 harness-control messages and 134,885 control bytes are reported separately. Timing fields are host diagnostics and support no latency claim.

## Explicit limits

The four crash-durable witnesses run in separate Python processes and retain separate state files, but they share one host, kernel, scheduler, and storage subsystem. Histories, closures, manifests, paths, scopes, service scope tables, frames, counters, and signed-slot tables are explicitly bounded; the signed-slot table permits 65,536 distinct stable slots and then accepts only an idempotent retry of an existing slot. The experiment does not model machine-independent failure domains, disk loss, malicious snapshot rollback, torn writes outside the stated filesystem assumptions, WAN delay, throughput, load, committee changes, key rotation, garbage collection, or production storage engines.

Byte studies use canonical uncompressed application JSON. Logical state bytes are encoded snapshots, not resident memory or physical disk amplification. Proofs are handwritten and executable checks are finite checks, not a mechanized proof or independent reimplementation.

## Reachability and branch compatibility

All three honest witnesses being reachable is necessary but not sufficient for progress. Valid but uncertified competing histories can lock the honest witnesses 2-to-1. Under Byzantine withholding neither branch then reaches quorum. `results/journal-boundary.json` contains eight actual-signature cases, including two such counterexamples and unanimous controls. No view change, branch reset, or recovery from this split is implemented; readers fail closed once evidence expires. The independent Go enumerator checks standard threshold-set conditions only.

The final TDSC release reran the complete unit and finite checks, 500 fresh-seed differential histories, all 96 renewal, selector, and witnessed traces, and all 45 network and 33 durable cases. It reanalyzed the retained 48-case main campaign and its retained complete repetition. Six main cases were also executed again; those six are not mislabeled as a new complete 48-case campaign.
