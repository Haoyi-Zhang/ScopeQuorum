# Exact consumed input and selection

## Public topology

The consumed public scientific input is the package-name/version/dependency
projection of the complete Cargo.lock in the immutable ripgrep 14.1.1 source:

https://raw.githubusercontent.com/BurntSushi/ripgrep/14.1.1/Cargo.lock

The web text contained 526 lines. All 61 package records, their versions, and
131 named dependency edges were transcribed into `data/lock_projection.json`
and cross-checked against the complete source text. This was a same-executor
manual semantic transcription, **not a byte-exact raw download or an independent
automated extraction**. Package checksums and source fields were not consumed
and are intentionally absent. Names plus versions distinguish source package
identities; no package code is executed or redistributed here.

The JSON is the exact consumed input. The generator maps records in sorted order
to immutable fixture keys and distributes dependency packages over 1, 3 or 6
namespaces. It adds one generated wrapper root in namespace n0 and twelve
unrelated generated publications. Public topology has 74 vertices and 132 edges
including these additions; only 62 vertices are reachable from the query root.
Namespace identities, ownership, grants, signatures, times, revocations, transfers,
equivocations, missing objects, cycles and partitions are entirely synthetic.

The upstream project offers MIT or Unlicense licensing. This artifact uses the
MIT option. Original MIT and COPYING notices are in `data/licenses/`. The source
and license URLs are in `external_resources.csv`. No upstream implementation was
modified to obtain a favorable result.

## Generated topology and faults

The second family is a deterministic 128-vertex layered graph plus a generated
top, wrapper, and twelve unrelated objects (142 vertices, 241 edges, 130 reached
vertices). The source generator specifies every edge; no sampled seed or private
cache is needed. Eight fault scenarios crossed with two families and three
namespace placements yield exactly 48 cases. Each of seven policies receives a
fresh world and the same accepted authoritative event history and link schedule.

There are two shapes, not 48 independent real-world workloads. The public input
supplies dependency shape only. These experiments do not establish package-manager
resolution correctness, biological/model safety, software-build provenance,
real-world attacker behavior, or an Internet-scale workload.

## Acquisition limits

Public source text and scholarly pages were read through web retrieval. A
university-hosted public abstract and proceedings/DOI metadata verify the
AI4DVault title, authors, venue, architecture-level motivation, and the abstract's
statement that implementation remains work in progress. The institutional record lists a 2.48 MB author postprint, but direct retrieval of
the supplied full-text endpoint repeatedly timed out in this environment. The
complete paper's detailed protocol and implementation boundaries were therefore
not independently verified. No
missing source is fabricated or treated as read; the source is cited as
application motivation, not as an executed federated baseline or completed
research ancestor.
