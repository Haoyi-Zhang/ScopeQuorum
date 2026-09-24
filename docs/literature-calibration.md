# Primary-paper narrative and evidence calibration

This source-calibration matrix records 22 primary research papers used to calibrate the manuscript's systems narrative and evidence contract. It is a targeted writing/evaluation calibration, not a systematic review, novelty certificate, cover-to-cover reading certification, or reproduction of each paper's artifact. For each selected paper, the abstract and claim-relevant introduction, system/model, evaluation, and limitation/discussion passages available from its primary or official record were inspected; the matrix does not claim that every page or artifact was re-executed. Exact bibliographic records and scholarly URLs are in `external_resources.csv` and `paper/references.bib` in the project package.

The passage-reading descriptions below record the inspected evidence boundary and do not claim cover-to-cover reading of all 22 papers. Structural and primary-record checks are documented in `docs/bibliography-audit.md`. This matrix is a narrative and methodological comparison, not an acceptance certificate.

## Twelve closest primary papers

| Paper | Why close | Sections used for calibration | Pattern adopted or deliberately rejected |
|---|---|---|---|
| TUF, *Survivable Key Compromise in Software Update Systems* | Update metadata, delegated roles, compromise recovery | Abstract; threat model; role design; evaluation/discussion | State the exact trust and compromise model before claiming survivability; do not conflate metadata authenticity with dependency freshness. |
| Diplomat | Delegated repository authority and community operations | Introduction; delegation model; implementation; evaluation | Connect a security mechanism to repository workflow, while separating operational usability from the present synthetic registry model. |
| Mercury | Rollback defense with bandwidth accounting | Introduction; protocol; bandwidth evaluation; limitations | Treat rollback prevention and transfer cost together; report the accounting boundary instead of only certificate size. |
| CHAINIAC | Collectively witnessed software-update histories | Introduction; threat model; skipchain/witness protocol; evaluation | Explicitly acknowledge witness cosigning as prior art; define what becomes collectively acknowledged and what remains unavailable. |
| Contour | Binary transparency with practical system measurements | Introduction; architecture; evaluation; deployment discussion | Use a concrete attack-to-mechanism narrative and distinguish path coverage from production deployment. |
| Software Distribution Transparency and Auditability | Release transparency and verifiable history | Motivation; protocol model; security analysis; discussion | Separate append-only audit from current read freshness and forced disclosure. |
| in-toto | End-to-end supply-chain layout/link provenance | Introduction; model; verification flow; case studies | Preserve terminology boundaries: build-step provenance is adjacent to, not replaced by, registry dependency closure. |
| Sigstore | Deployable identity-bound software signing | Introduction; architecture; threat model; evaluation | Explain the operational trust simplification, but do not import identity or public-log properties not implemented here. |
| Speranza | Privacy-preserving signing usability and deployment | Introduction; design; security goals; evaluation | Keep security, privacy, and usability goals distinct; avoid claiming privacy or human usability from protocol-only evidence. |
| Merkle² | Low-latency transparency log design | Introduction; data structure; consistency argument; evaluation | Couple a compact proof design with end-to-end cost accounting and explicit consistency assumptions. |
| Parakeet | Practical key transparency for messaging | Introduction; system architecture; threat model; evaluation | Describe client/server/witness responsibilities and the recovery boundary; avoid treating key-transparency deployment evidence as registry evidence. |
| GlassDB | Verifiable ledger database transactions | Introduction; model; protocol; experiments; limitations | Explain which semantics are obtained from a stronger ledger substrate and why the present fixed witness layer is narrower. |

## Five demonstrably influential systems papers

These papers are used as influential calibration examples rather than as direct registry baselines.

| Paper | Calibration role | Sections used | Pattern adopted or boundary retained |
|---|---|---|---|
| Dynamo | Partition-tolerant system narrative | Introduction; design principles; consistency; experience | Begin from explicit availability choices and expose reconciliation costs; do not imply that eventual propagation meets a revocation deadline. |
| Spanner | Clock and acknowledgement assumptions | Introduction; TrueTime model; transactions; evaluation | Put the clock inequality and uncertainty source in the model before using time in a guarantee. |
| COPS | Dependency visibility and scalable causal consistency | Introduction; causal model; protocol; evaluation | Use one dependency example throughout, while distinguishing causal visibility from unseen-invalidating-event freshness. |
| PBFT | Byzantine fault model and evaluation contract | Introduction; system model; protocol; experiments | State fault threshold, quorum intersection, and liveness assumptions precisely; do not label projection validation as full BFT replication. |
| Raft | Understandable consensus exposition | Introduction; replicated-state model; safety; evaluation | Use a small set of named invariants and a single running failure scenario; keep the mechanism's scope narrower than consensus. |

## Five adjacent security/accountability papers

| Paper | Adjacent lesson | Sections used | Pattern adopted or rejected |
|---|---|---|---|
| CoSi | Witness cosigning | Introduction; protocol; security; evaluation | Attribute cosigning directly and focus this manuscript's delta on exact dependency scopes, durable acknowledgement, and accounting. |
| CRLite | Compressed revocation distribution | Introduction; construction; measurements; deployment limits | Treat compact status as an established family and report false assumptions/coverage boundaries rather than claiming a new revocation primitive. |
| CONIKS | Verifiable directory views and consistency | Introduction; threat model; audits; evaluation | Separate a user's verifiable view from universal disclosure and from a freshness lease. |
| PeerReview | Evidence-based accountability | Introduction; model; protocol; evaluation | Distinguish preventing an accepted fork from later producing evidence that identifies a faulty participant. |
| WAVE | Delegated authorization with revocation deadlines | Introduction; authorization model; revocation semantics; evaluation | Name the revocation-effective-time contract explicitly and avoid universal authorization claims outside exact registry scopes. |

## Cross-paper pattern matrix

| Dimension | Common strong-paper pattern | Manuscript application |
|---|---|---|
| Motivating problem | One concrete failure that the old interface cannot distinguish | Root in one namespace depends on a remotely revoked artifact in another. |
| General principle | A short contract or invariant before mechanism detail | Quorum-visible acknowledgement, exact dependency scope, and per-namespace freshness. |
| Proof/performance argument | Safety assumptions and cost accounting use matching boundaries | Handwritten quorum/clock/crash arguments are paired with finite checks and separate client/certification traffic. |
| Practical connection | Real system path or protocol objects are exercised | Ed25519 wire objects, TCP listeners, four witness processes, and persisted snapshots are executed; no WAN claim follows. |
| Evaluation breadth | Positive cases, adversarial cases, negative controls, and sensitivity | Omission attacks, post-quorum forks, three crash windows, corrupted state, clock rollback, and churn sensitivity. |
| Artifact strength | Deterministic commands, retained raw results, and clean-tree reconstruction | All bounded studies are runnable; generated tables are linked to raw JSON/CSV; final package is clean-extraction checked. |
| Narrative sequence | Failure → contract → design → correctness → implementation → evaluation → limits | The paper follows this order within eight main sections. |
| Figure/table role | Diagrams carry architecture semantics; tables carry exact measured values | Two TikZ diagrams explain dependency and witness flows; booktabs tables preserve exact outcomes and costs. |
| Bibliography role | Closest work narrows claims rather than decorating them | CoSi/CHAINIAC/delta-status systems explicitly constrain novelty claims. |

## Calibration outcome

The matrix forced four manuscript repairs:

1. witness cosigning and delta status are presented as inherited mechanism families, not firstness claims;
2. quorum-visible acknowledgement is defined before safety claims;
3. durable commit ordering and stable-storage assumptions are now explicit rather than hidden behind `sign`;
4. client-plane savings and certification-plane costs remain separate throughout the abstract, evaluation, and conclusion.

The matrix does not establish acceptance, exhaustive related-work coverage, or independent review.
