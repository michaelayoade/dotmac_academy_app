# ADR 0005 — One assessment engine owns exam logic; banks own questions

Date: 2026-08-07 · Status: proposed (awaiting Michael)

## Context

There is no assessment engine. There are two half-engines that share a single
function, and each has capabilities the other lacks.

`grade_submission` is the only piece both paths use — called from
`app/services/assessment.py:79` for course activities and from
`app/services/entrance_exam.py:419` for applicants. Everything else about what
an exam *is* has been decided twice, or once:

| concern | course path | entrance path |
| --- | --- | --- |
| grading | `grade_submission` | `grade_submission` |
| question selection | `attempts.open_or_create_attempt` — flat random, persisted in `ActivityAttempt` | `entrance_exam.sample_for` — stratified by competency, deterministic, derived |
| option order | **none — identical for every learner** | `options_for`, shuffled per sitter |
| validity gate | **none** | `check_validity` — near-chance, too-fast |
| attempt policy | `Activity.max_attempts` | one sitting, enforced by a `raise` |
| per-domain profile | **none** | `applicants.assessment_profile` |
| result banding | `pass_threshold` | `LEVELS` percentile bands |
| answer reveal | `assessment_mode` | not applicable |

Two of those gaps are live defects, not merely asymmetries:

- **Course learners see a fixed option order.** "The answer is the third one"
  transfers between learners and stays true. `options_for` exists precisely to
  stop that, and the graded finals do not use it.
- **Course sittings have no validity gate.** A forty-second final scoring at
  chance is stored as a genuine result. The entrance exam rejects exactly that
  case as an absence of data, because ranking a guesser pollutes the pool it
  feeds.

The split has a real cause: applicants are not `Person` rows, so the entrance
flow cannot use `submit_activity` and grades directly. That is an identity
boundary, and it is the thing an engine abstracts — not a reason to keep two
implementations of everything above it.

### How it got worse

On 2026-08-06, closing a genuine hole — the entrance exam served every question
in its bank, so growing the bank lengthened the exam rather than refreshing it —
`sample_for` was added to `entrance_exam.py` rather than generalising the pooling
that already existed in `attempts.py`. Stratification, determinism and the
per-competency profile all demanded behaviour `attempts.py` did not have. The
local fix was right; the architectural effect was a **second sampler**.

That is the same parallel-derivation failure recorded in
`academy-assessment-quality-needs-a-reconciler-not-just-a-gate`, one layer up:
a decision with two implementations that will drift the moment either moves.

## Decision

### 1. One engine owns every exam decision

A single service decides, for any sitting:

- **Eligibility** — may this sitter start, given prior attempts and any limit.
- **Selection** — which questions, how many, drawn how (whole bank, flat pool,
  or stratified by domain), and whether the draw is persisted or derived.
- **Presentation** — the order of questions and of options, per sitter.
- **Grading** — delegated to `grade_submission`, which stays a pure function.
- **Validity** — whether the sitting is signal or an absence of data.
- **Meaning** — threshold, band, and per-domain profile.
- **Disclosure** — what may be revealed, and when.

### 2. Banks own questions, and only questions

A bank is the facts: stem, options, correct answer, competency, rubric level,
explanation, weight. It carries no logic. The existing arrangement stands —
files are authoritative, `load_bank` is the single canonical writer, the
database is a rebuildable projection.

`policy:` in a bank stays a *declaration* consumed by the engine, not behaviour
implemented by the bank.

### 3. `learn.py` and `apply.py` become adapters

Both resolve a **sitter** — an identity with an id, whether backed by `Person`
or `Applicant` — hand it to the engine with a policy, and render what comes
back. Neither decides anything about the exam.

### 4. Capabilities stop being per-path

Once the engine owns these, each becomes available everywhere rather than
wherever it happened to be written:

- Option shuffling applies to course finals, closing the fixed-order leak.
- Validity gating applies to graded course assessments.
- Stratified selection is available to any bank carrying competency tags —
  which, since the `competency:` fix, is 252 technical banks.
- Attempt policy applies to the entrance exam as policy rather than a `raise`.

## Consequences

**The selection question must be settled deliberately.** `ActivityAttempt`
persists the drawn subset so a resumed attempt shows the same paper; the
entrance exam derives it from a hash of `(sitter, question)` and stores
nothing. Both are defensible. Persisted survives a change to the bank
mid-attempt; derived needs no write path and cannot orphan rows. The engine
picks one and the other is retired — carrying both is how this ADR's problem
recurs.

**The entrance exam moves last.** It is live and ranking real candidates: 218
applicants, 112 sat, 109 valid sittings. It moves behind tests that pin current
behaviour, after the course path is on the engine, never in one step.

**This is not a plugin framework.** One service, a policy object, two adapters.
The failure mode of this decision is over-abstraction, and the guard is that
nothing may be configurable that no caller varies.

**Scope discipline.** The engine does not absorb labs (`lab_*`), certificates,
or the gradebook. Those consume assessment results; they do not decide them.

## Alternatives considered

**Leave the split and document it.** Cheapest, and it preserves two live
defects — fixed option order and ungated course sittings — while guaranteeing
the next capability added to one path is absent from the other.

**Fold the entrance exam into `Activity`/`Person`.** Removes the duplication by
removing the distinction, but requires an applicant to become a `Person` before
being admitted, which inverts the admissions model and puts unadmitted
candidates in the learner tables.

**Extract only the sampler.** Fixes the specific harm caused on 2026-08-06 and
leaves option order, validity and profiles unaddressed. Worth doing first if
the full engine is deferred, since it is the one duplication actively growing.

## What changes in the relationship map

`docs/SOT_RELATIONSHIP_MAP.md` already records the split — not as an accident,
but as two named owners of one concern:

| row | current owner |
| --- | --- |
| Entrance assessment result | `entrance_exam.grade_and_record` |
| Learner assessment attempts | `assessment.submit_activity`, `attempts.open_or_create_attempt` |

Under this ADR those collapse to one owner for exam decisions, with
`grade_and_record` and `submit_activity` retained as the two adapters that
persist a result against an `Applicant` and a `Person` respectively. Accepting
this ADR requires that edit; the map, not this document, is the enforceable
statement.

## Relationship to the content work

This is orthogonal to, and more foundational than, the content remediation in
progress. That work — the distractor rule, the CI gate, the `audit-banks`
reconciler — asks whether the questions are good. This asks what an exam is.
Both are needed; only one of them currently has two owners.

Recommended sequencing: land the reconciler (#75), then this engine, **ahead of**
remediating the ~1,700 questions in courses with no enrolments. The engine gap
affects every sitting by every active learner today; those courses affect nobody.
