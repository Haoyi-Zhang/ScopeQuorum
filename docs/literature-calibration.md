# Related mechanisms and experimental comparators

The manuscript studies a read rooted at an immutable registry key. Its predicate
combines publication authority, transitive dependencies, permanent invalidators,
and freshness at authenticated namespace frontiers. The mechanisms below address
adjacent obligations; they are references, not executed external-system baselines.

## Witnesses and release history

CoSi distributes validation of authority statements and aggregates witness
signatures. CHAINIAC applies collective validation to software-release histories
and verified builds. Their published descriptions establish witness cosigning
and collective release validation as prior mechanisms. This prototype uses
individual Ed25519 signatures and fixed exact-scope projections, with
persist-before-sign local refusal state. The measurements therefore compare
its own same-contract representations, not native CoSi or CHAINIAC throughput.

## Status, authorization, and transparency

OCSP, delta CRLs, and CRLite are established status-distribution mechanisms.
WAVE addresses decentralized transitive authorization and revocation; its
audited-map substrate differs from the fixed committee studied here.
Transparency logs and verifiable directories support consistency and audit.
These references motivate separating status validity, historical disclosure,
and bounded-effective time rather than attributing all three to a signature.

## Replication and stronger acknowledgement

Causal replication governs visibility of updates. Shared logs and consensus
provide broader ordering contracts. The prototype certifies one retained
namespace history: honest signers preserve their accepted branch, and a
split-branch construction shows why reachability alone is insufficient for
progress. It retains the fixed-membership and non-malicious-storage assumptions
specified in `model-and-evidence.md`.

## Same-contract measured baseline

The TCP read comparison gives both readers the same catalogue, query schedule,
frontiers, signatures, quorum, clock guard, and invalidation history. The
cached-prefix reader obtains new receipts plus witnessed checkpoints and
maintains a derived status index. The scoped reader obtains initial status and
projected changes. Twelve traces produce 120 matching read pairs. Scope reduces
client traffic in every trace but total client-plus-witness traffic in one.
`witness-reads.md` defines the accounting boundary and retained raw inputs.

Reference identities and scholarly URLs are recorded in `external_resources.csv`.
The manuscript bibliography and its structural checks belong to the separate
local paper package, not the standalone artifact repository. Bibliographic
identity checks do not establish empirical reproduction of a cited system.
