# Model, arguments, and counterexamples

These are handwritten arguments for the finite model implemented in `src/`. The executable checks exercise bounded instances and parser paths; they are not a mechanized proof of the mathematics or of the Python implementation. The design combines established authenticated-log, lease, delta-status, and witness-cosigning ideas. No theorem below is claimed as a new general cryptographic primitive.

## 1. State, frontiers, and acknowledgement

Let `N` be a finite namespace set. Each artifact key fixes its namespace. A manifest contains an exact immutable key, dependencies, owner epoch, publisher, publication capability, and symbolic content tag. Grants authorize publication in one namespace and epoch. Transfer advances the epoch but does not retroactively invalidate an admitted immutable publication. Exact-key revocation, capability revocation, and a second distinct manifest for one immutable key are permanent invalidators; an exact repeated manifest is status-neutral.

An event has a consecutive sequence number, predecessor commitment, nondecreasing acceptance time, kind, and payload. Manifest dependencies are strings in strictly sorted, duplicate-free order; authority admission, client verification, and witness replay reject any alternative representation. A head or report may not be issued before the latest accepted event it authenticates. The cryptographic interface assumes unforgeable signatures and binding commitments. The implementation uses deterministic public Ed25519 test keys and SHA-256. Relays and publishers may omit, delay, replay, reorder, or duplicate authentic objects. Publishers may submit conflicting manifests.

The artifact evaluates two acknowledgement contracts:

1. **Single-sequencer contract.** One honest, non-forking sequencer owns the accepted history `H_n`. In-memory acceptance is the event frontier. This is the contract used by the original 48 network campaigns and the prefix/status/ScopeDelta comparison.
2. **Witnessed crash-recovery contract.** The sequencer may be Byzantine. Each namespace has four designated witnesses; at most one is Byzantine. An event becomes effective only once it appears in a contiguous checkpoint or exact-scope certificate signed by at least three distinct witnesses. Honest witnesses independently replay the full candidate history, verify event admission, reject rollback or forks relative to their retained branch, recompute the exact projection, and check the common timestamp against their own bounded clock. Before returning a signature, an honest witness atomically persists its accepted branch, scope table, signed-slot digest, and logical clock. A sequencer-only receipt is not an effective acknowledgement.

The witnessed contract assumes fail-stop processes and retained non-malicious stable storage. It is not general consensus, storage-loss tolerance, committee reconfiguration, aggregate signatures, or WAN deployment. It makes the acknowledgement point, crash ordering, and additional availability cost explicit.

## 2. Authenticated prefixes and frontier-relative closure

A namespace head authenticates `(n,c,tip,issued)`. A complete certificate stream contains exactly `c` receipts, begins at sequence one, has consecutive predecessor commitments, and ends at `tip`.

**Lemma 1 (prefix integrity).** Under the signature and commitment assumptions, every stream accepted against one authentic head is exactly the presented length-`c` chain.

**Argument.** The head binds count and terminal commitment. Sequence and predecessor checks bind each position. Deletion, insertion, permutation, truncation, or substitution changes a checked field unless a signature is forged or a commitment collides. This establishes integrity of the presented chain; it does not establish freshness or global completeness.

For a frontier vector `F`, fold each namespace prefix in order. A key is locally valid when exactly one distinct manifest has been admitted, the key is not revoked, and its capability is not revoked. Starting at root `r`, repeatedly add the dependencies of the unique manifest. `Closed(F,r)` requires every reached key to be present and valid, every reached namespace stream to be complete, the graph to be acyclic, and all representation bounds to hold.

**Theorem 2 (frontier-relative prefix soundness).** If the prefix verifier serves `r`, then `Closed(F,r)` holds for the authenticated frontier supplied to it.

**Argument.** Lemma 1 supplies ordered streams. The verifier reconstructs grants and epochs before publication, accumulates permanent invalidators, and rejects distinct manifests. Breadth-first traversal reaches every dependency. Missing keys, missing namespaces, revocations, revoked capabilities, conflicts, cycles, and excessive paths deny. Hence every conjunct of `Closed` holds.

**Lemma 3 (namespace-footprint locality).** Holding all reached namespace frontiers fixed, changes outside the dependency footprint cannot change `Closed(F,r)`.

**Argument.** Every consulted fact is scoped to a reached key's namespace and every next edge is fixed by an already reached immutable manifest. Induction over dependency paths gives the result. The lemma assumes no federation-wide policy coupling unrelated namespaces.

## 3. Freshness and revocation-effective time

Under the single-sequencer contract, an invalidator accepted at real time `a` must stop serving by `a+Delta`. Issuer and client clock errors lie in `[-epsilon,+epsilon]`. If a head carries issuer reading `i` and the client reads `u`, the verifier requires, for every reached namespace,

```
u - i + 2 epsilon < Delta.
```

The endpoint is strict. Experiments use an injected logical clock and `epsilon=0`; a finite arithmetic enumeration checks nonzero error.

**Temporal-frontier invariant.** Authority heads reject issuance below the latest accepted event time; an honest witness rejects a candidate whose latest accepted event exceeds the report issuance time; and durable reload rejects a retained history whose event time exceeds the persisted logical clock plus the allowed endpoint error. Thus a freshly signed wrapper cannot make a future-dated event appear to have existed earlier. This is an implementation invariant checked at all three boundaries, not a physical clock-synchronization guarantee.

**Theorem 4 (single-sequencer bounded safety).** If a closure is served with the guard above for every reached namespace, no invalidator accepted at or before `t-Delta` can affect a reached key without appearing in the decision.

**Argument.** If issuance occurred at real time `s`, endpoint errors give `t-s <= u-i+2epsilon < Delta`; therefore `s>t-Delta`. Any older invalidator preceded issuance and an honest sequencer includes it in the complete prefix or complete fold. The argument applies independently to every reached namespace.

**Proposition 5 (immediate unseen revocation).** No isolated algorithm using only cached evidence can both always serve and enforce immediate effect for an invalidator accepted after that evidence.

**Argument.** Two executions are indistinguishable to the cache: one has no later event, one accepts a remote revocation during the partition. The same decision either violates immediate effect or sacrifices availability. A live authority or quorum changes the information and acknowledgement contract.

## 4. Honest folded status, coherent caching, and ScopeDelta

An honest issuer can sign the result of folding its length-`c` prefix for a key set: manifest (or remembered commitment), validity, count, and issuance time.

**Theorem 6 (prefix/status predicate equivalence).** With one honest sequencer, identical frontiers, reached keys, freshness checks, and floors, complete prefix replay and complete signed object status produce the same serving decision.

**Argument.** The status producer performs the same per-key fold as the prefix verifier. The client then performs the same dependency fixed point and graph checks. Prefixes retain more historical explanation, but the Boolean state agrees.

A coherent cache stores `(manifest,valid,count,issued)` per key. A head renews time only for entries already at that exact count.

**Lemma 7 (subset-refresh isolation).** Refreshing subset `A` cannot advance an unrefreshed cached key outside `A`.

**Argument.** Only named entries receive the new count. Older reports are rejected. A closure mixing two counts from one namespace fails closed. Thus a harmless subset refresh cannot make a stale revoked object appear current.

A ScopeDelta scope is a bounded sorted exact-key set `S` in one namespace. Registration returns valid manifests and a content-derived handle. Renewal from `c` to `c'` lists each scoped conflict, exact revocation, and relevant capability revocation. Extension creates a new immutable handle and retains the old one.

**Theorem 8 (honest ScopeDelta fold equivalence).** Let `G(P,k)` retain the first admitted immutable manifest and combined Boolean validity for key `k`. Starting from `G(P_c,k)`, applying a complete honest projection for `(c,c']` yields `G(P_c',k)`, the same abstraction of full-prefix replay.

**Argument.** Grants and transfers cannot alter already admitted immutable manifests. Outside-scope publications are irrelevant. Exact duplicates are neutral. While a scoped manifest is valid, a distinct publication, exact revocation, or relevant capability revocation is included and makes validity permanently false. Further invalidators cannot change `G` after that transition. Induction over suffix events proves equality of the retained manifest/validity pairs; separate cause bits and complete historical explanations are not retained.

**Corollary 9 (honest serving equivalence).** With coherent frontiers, equal freshness and floors, and a complete honest projection, ScopeDelta and prefix replay make the same decision for a closure contained in the scopes.

**Proposition 10 (retry-safe extension).** A lost extension response leaves the old scope usable, and repeating the same extension yields the same new handle.

**Argument.** The new handle commits to namespace and sorted union. The old immutable entry is not mutated. Client replacement occurs only after complete validation.

**Proposition 11 (no universal zero-regret acquisition decision).** When registration has positive cost and future unrelated churn is unknown, no deterministic causal choice between staying with cached status and registering immediately is no worse than both choices on every continuation.

**Argument.** Two continuations share the same observation prefix. Immediate termination makes registration strictly wasteful; sufficiently long unrelated churn makes early registration cheaper. A causal algorithm chooses identically on both prefixes and loses on one. This is not a competitive-ratio or randomized lower bound.

## 5. Quorum-witnessed exact-scope deltas

For namespace `n`, let the committee contain `N=4` witnesses, quorum `q=3`, and at most `f=1` Byzantine witness. Witness identities are fixed in the bounded model. An honest witness signs body `B` only after all of the following:

1. the authority history is authentic, contiguous, namespace-correct, and extends the witness's retained branch;
2. every grant, publication, transfer, and revocation is admitted by an independent replay;
3. `count` and `tip` exactly name that candidate history;
4. registration or extension binds the exact sorted key set and valid state;
5. renewal contains exactly the status-changing projection for the registered scope;
6. the body timestamp is within `epsilon` of the witness's local reading; and
7. the witness has not signed a conflicting stable state for the same certified slot; and
8. the validated branch, scope table, slot digest, and logical clock have been durably committed before the signature is returned.

The client accepts only the authority signature plus at least three valid signatures from distinct designated witnesses over the exact body. It rejects duplicate or unknown signers. A malformed proposal is validated transactionally: it cannot advance an honest witness's retained branch before every check succeeds. The implementation writes a canonical snapshot to a new file, fsyncs it, atomically replaces the prior file, and fsyncs the directory. A corrupt snapshot makes that witness unavailable instead of silently resetting it.

**Lemma 12 (witnessed projection completeness).** Every accepted 3-of-4 ScopeDelta certificate contains the exact projection of at least one honest witness's replayed candidate history.

**Argument.** A quorum of three contains at least two honest witnesses when at most one is Byzantine. Each honest signer recomputes the projection from the complete candidate history and signs only equality with the proposal. Therefore an omitted scoped invalidator, invented cause, wrong frontier, or wrong exact key set cannot obtain three signatures unless an honest witness violates its algorithm or a signature/commitment assumption fails.

**Lemma 13 (quorum non-equivocation).** Two 3-of-4 quorums intersect in at least two witnesses. With at most one Byzantine witness, at least one honest witness lies in their intersection; consequently two conflicting extensions of the same retained branch/slot cannot both be certified.

**Argument.** For sets of size three in a universe of four, `|Q1 intersect Q2| >= 2`. At most one intersection member is Byzantine. The other honest member rejects a candidate that rolls back or forks its retained branch, or a conflicting state for the same slot. The finite checker enumerates all 16 ordered quorum pairs and all five fault sets.

**Theorem 14 (acknowledged witnessed-delta safety).** Under the committee assumptions, an accepted certificate for scope `S` is equivalent to folding the quorum-visible authenticated history named by the certificate, even if the sequencer and one witness are Byzantine.

**Argument.** Lemma 12 gives an honest independently replayed exact projection. Theorem 8's event-case induction then applies to that projection. Lemma 13 prevents a later conflicting quorum certificate at the same branch position. Events visible only to the sequencer are deliberately outside the effective history until a quorum certificate acknowledges them.

**Lemma 15 (persist-before-sign crash atomicity).** For an honest witness, a crash before the atomic replace leaves the previous durable state and returns no signature; a crash after replacement and directory synchronization complete but before the reply leaves the new state durable. An ordinary persistence failure before replace rolls the tentative in-memory mutation back. If replace succeeds but directory durability cannot be confirmed, no signature is returned and that in-process witness refuses further operations until it is reopened. Repeating the same proposal after recovery is idempotent, while a conflicting proposal for the same slot remains rejected.

**Argument.** Validation and in-memory mutation precede persistence, but the signature is not released until persistence completes. A temporary file is fsynced before `replace`; therefore a crash before `replace` cannot make the new snapshot authoritative. The renamed file and containing directory are fsynced before return; therefore a crash after completed persistence recovers the new snapshot. A directory-fsync error after replacement has an uncertain old/new recovery outcome, so the implementation neither returns a signature nor restores an old in-memory state and continue signing; it poisons the live object until reopen. The signed-slot map binds the stable body digest while excluding only the fresh issuance timestamp. Three injected crash windows plus ordinary fsync/replace error tests exercise these orderings.

**Theorem 16 (crash-recovered quorum non-equivocation).** If an accepted 3-of-4 certificate is returned and stable storage is retained, arbitrary later fail-stop crashes and restarts cannot enable a conflicting certificate for the same branch position when at most one witness is Byzantine.

**Argument.** The accepted quorum contains at least two honest witnesses, and each persisted its branch and slot digest before its signature escaped. Any later quorum intersects the original quorum in at least two identities, at least one of which is honest. After recovery that honest witness reloads the durable state and rejects the conflicting branch or slot digest. The six full-committee restart cases exercise both quorum overlap and recovery. Storage loss or malicious rollback is outside the assumption.

Witness timestamp validation adds a third clock-error term. Let report field `i` be within `epsilon` of an honest witness's local clock at real signing time `s`, and let the witness and client clocks each differ from real time by at most `epsilon`. Then `t-s <= u-i+3epsilon`.

**Theorem 17 (witnessed bounded-effective-time safety).** If the client requires

```
u - i + 3 epsilon < Delta
```

for every reached namespace, no quorum-acknowledged invalidator effective at or before `t-Delta` can be omitted from an accepted witnessed decision.

**Argument.** The timestamp relation gives `s>t-Delta`. Any earlier effective invalidator belongs to a quorum-visible history. By Lemmas 12 and 13 it is included in the exact projection or prevents a later stale branch from reaching quorum. The finite clock checker enumerates 2,625 assignments with zero failures for `3 epsilon`; replacing it by `2 epsilon` leaves five unsafe negative controls.

**Proposition 18 (threshold feasibility is not liveness).** Fewer than three signatures cannot certify. Three mutually compatible honest signers can certify a valid fresh proposal if delivery and durable writes succeed and all state bounds admit it. All three honest witnesses being reachable is necessary against a withholding Byzantine witness, but is not sufficient for progress.

**Counterexample.** Start from one common checkpoint. Let two honest witnesses validate and persist valid extension A, and the third validate and persist conflicting valid extension B at the same next sequence position. Neither initial partial set forms a certificate. After every honest witness is reachable, the first two refuse B and the third refuses A. If the Byzantine witness withholds, neither branch reaches three signatures. Persist-before-sign preserves these refusals after restart; it does not reconcile them. Clearing retained state would invalidate the non-equivocation argument and is not an allowed repair. The actual-signature eight-case study includes both mixed assignments and unanimous positive controls.

**Lemma 19 (standard fixed-threshold intersection).** For n fixed identities, at most f Byzantine identities, and threshold q, every pair of q-sets contains an honest identity exactly when 2q-n>f. An all-honest threshold can exist despite f non-signers exactly when q<=n-f. Some q satisfies both exactly when n>3f. This is a standard quorum condition, not a new consensus theorem.

**Argument.** Two q-subsets intersect in at least max(0,2q-n) elements. If this minimum exceeds f, at least one common identity is honest. Otherwise, choose two sets attaining the minimum and put their intersection among the faulty identities; intersection alone provides no honest common refusal state. Honest-threshold feasibility counts the n-f remaining identities. Combining the inequalities gives n>3f, and q=n-f supplies the converse. `checks/quorum.go` independently enumerates all q-subsets for n<=10, 385 triples and 250,942 pair checks, without importing the prototype. It verifies this finite specialization, not the infinite theorem or registry code.

## 6. Convergence, rollback, and what history still buys

Replica stores union authentic `(namespace,sequence)` entries. A different receipt at one position quarantines the namespace. Union is associative, commutative, and idempotent; deterministic reconstruction converges after equal finite inputs. This says nothing about time to convergence or fresh reads during a partition. The separate witnessed path adds crash durability only for each witness's accepted branch and slot state under retained local storage; it does not make registry replicas or committees generally durable.

Client floors reject a count below a remembered authenticated count. They do not help a first-time or state-lost client and do not make an old count fresh.

Full prefixes provide event-level replay, historical authority, dependency paths, and conflict positions. Witnessed ScopeDelta shifts that replay to committee members and gives the client only initial states and projected causes. It therefore reduces client transfer in many workloads but pays certification-plane traffic, witness state, and durable commit work. Neither representation proves events outside the declared quorum-visible history. Broader accountability still requires checkpoint gossip, authenticated maps, committee administration, and protection against storage loss or rollback.

## 7. Cost boundaries

An empty exact-scope renewal has constant schema shape apart from integer/text lengths, but the mechanism is not byte optimal. Requests, independent signatures, key names, history synchronization, batching, witness storage, scope churn, and alternative authenticated dictionaries move the crossover.

The retained 96-trace witness study counts canonical JSON request and response bytes separately for the client plane and the sequencer-to-four-witness certification plane. Witness durable-state bytes are a separate four-witness aggregate over canonical payload fields, including every retained scope handle and stable slot/digest; four actual/model transitions agree byte-for-byte. Witnessed scope transfer is smaller than witnessed prefix transfer in 87/96 traces on the client plane but only 48/96 when both counted planes are included. Its median scope/prefix ratio changes from 0.46 to approximately 1.00, and certification traffic is 89.9% of witnessed-scope total traffic at the median. This is encoded-byte evidence, not latency, CPU, throughput, WAN, compression, or storage-engine performance.

## 8. Evidence-to-code map and bounded evidence

- Prefix integrity and closure: `src/client.py`, `tests/test_protocol.py`.
- Honest status and coherent cache: `src/status_reference.py`, `src/cached_status.py`, `tests/test_cached_status.py`.
- Honest ScopeDelta: `src/scope_delta.py`, `tests/test_scope_delta.py`.
- Witnessed ScopeDelta: `src/witness_delta.py`, `tests/test_witness_delta.py`.
- Four in-process loopback witness endpoints: `src/witness_network.py`, `src/witness_network_study.py`, `tests/test_witness_network.py`.
- Crash-durable process-isolated witnesses: `src/durable_witness.py`, `src/durable_witness_network.py`, `src/durable_witness_study.py`, `tests/test_durable_witness.py`, `tests/test_durable_witness_network.py`, `results/durable-witness/`.
- Committee, reachability, and clock enumeration: `tests/witness_finite.py`, `results/witness-finite.json`.
- Witness cost and adversarial study: `src/witness_study.py`, `tests/test_witness_study.py`, `results/witness/`.
- Single-sequencer replication campaign: `src/model.py`, `src/transport.py`, `src/campaign.py`, `results/case-*.json.gz`.
- Original finite and random differential checks: `tests/finite.py`, `tests/differential.py`.
- Honest renewal and causal selector: `src/renewal_study.py`, `src/selector_study.py`, `results/renewal/`.

The retained Linux run records 134 directed tests in `results/current/unit/unit.json`; the separate six-test batch-fold regression is not part of that historical receipt. The bounded corpus also contains 5,880 original delivery orders, 500 random differential histories, 96 honest renewal traces, 96 selector traces, 96 witnessed cost traces, 80 ordered quorum/fault checks, 32 concurrent-fork first-arrival assignments, 2,625 witnessed clock assignments, 45 actual-Ed25519 in-process listener cases, and 33 process-isolated durability cases. The durability matrix injects 24 crashes at three commit windows, six full-committee restarts followed by conflicting forks, two corrupt-state cases, and one clock rollback; directed tests separately inject fsync and replace errors, canonical dependency rejection at three trust boundaries, future-event/issuance rejection, semantic durable-state reload, uncertain post-replace commit fail-stop behavior, and the 65,536-slot exhaustion boundary with same-slot idempotent retry. These results do not establish a mechanized proof, independent implementation, storage-loss tolerance, dynamic membership, WAN behavior, ecosystem prevalence, production performance, or universal byte optimality.

The implementation bounds a namespace history at 4,096 events, a closure at 4,096 keys, a manifest at 256 dependencies, a dependency path at 32 edges, an exact scope at 256 keys, one service at 256 scopes, and one witness at 65,536 distinct signed slots. At the slot bound, an existing identical body remains retryable while a new slot is denied; this bounds retained anti-equivocation metadata but does not implement reclamation.
