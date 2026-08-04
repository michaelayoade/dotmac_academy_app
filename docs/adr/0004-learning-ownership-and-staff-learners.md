# ADR 0004 — The Academy owns learning; ERP owns employment; staff learners are first-class

Date: 2026-08-04 · Status: accepted (Michael, 2026-08-04)

## Context

Two findings on 2026-08-04 forced this decision.

**A second LMS exists.** `dotmac_erp` carries ~5,400 lines of learning domain
under `app/models/people/training/` and `app/services/people/training/`:
`TrainingCourse`, `TrainingCourseModule`, `TrainingLesson`,
`TrainingAssessment`, `TrainingQuestionBank`, `TrainingQuestion`,
`TrainingCoursePrerequisite`, `TrainingCourseAssignment`,
`TrainingProgressStatus`, plus `TrainingProgram` / `TrainingEvent` /
`TrainingAttendee` with attendance tracking. Every one of those concepts is
also owned by this Academy. Nothing today states which system decides. Under
the Dotmac source-of-truth standard that is an unresolved parallel authority,
and it blocks any staff-reporting work: building staff progress reporting into
either system while both claim the domain entrenches the drift.

**Staff learners are invisible as a class.** Of 200 active student enrolments,
164 are Dotmac staff and 36 are external. The Academy holds no marker
distinguishing them — no employee link, no audience field, no cohort type.
The only available signal is whether the email ends `@dotmac.ng`, which is a
heuristic, not a fact: it silently misclassifies a staff member using a
personal address and an external learner issued a work address. 179 of those
200 enrolments have no `Applicant` row at all, having been created directly
from an ERP roster import, so intake data cannot substitute either.

The consequences are already measurable. Staff engage roughly four times worse
than external learners (10% vs 44% ever-active), there have been zero course
completions in either group, and HR has received nothing from the Academy since
the training sync went live on 2026-07-11 — `erp_synced_at` is null on all 50
completion rows, because the sync only emits `course_completed` and no course
has been completed.

## Decision

### 1. The Academy is the sole authority for learning

The Academy owns curriculum, enrolment, learning activity, assessment,
progress, completion, and certificate issue — for staff and external learners
alike. There is one LMS.

`dotmac_erp`'s learning-side tables (`training_course`, `training_course_module`,
`training_lesson`, `training_assessment`, `training_question_bank`,
`training_question`, `training_course_prerequisite`, and their APIs and web
services) are **declared non-authoritative**. They are not to receive new
writers, new callers, or new features. Retirement is tracked separately; this
ADR removes their claim to the domain, it does not schedule the deletion.

ERP retains authority over **employment**: who is an employee, their role,
department and manager, what training is *required of them*, and the credential
record. Concretely ERP keeps `Employee`, `EmployeeCertification`,
`TrainingCourseAssignment` (as an assignment/requirement record, not a
progress engine), and `TrainingProgram` / `TrainingEvent` / `TrainingAttendee`
for in-person events the Academy does not run.

The boundary in one sentence: **the Academy decides what a learner has done;
ERP decides what an employee is required to do and what credential they hold.**

### 2. Staff status is a fact carried on the enrolment, not inferred

`Enrollment` gains an explicit `audience` (`staff` | `external`), set at
enrolment time and required. Email domain is never used to infer audience in
code, reports, or queries.

Where an enrolment is `staff`, it carries a stable `employee_ref` supplied by
ERP at enrolment. Identity between the two systems is that reference, not a
lowercased email string. An email match may be used to *propose* a link during
backfill; it may not be the stored link.

Backfill: existing enrolments are classified once, by ERP roster membership
rather than by domain, and rows ERP cannot confirm are marked `external` and
listed for human review rather than guessed.

### 3. Reporting is projected outward, per audience

- The **Academy** projects staff learning state to ERP over the existing
  HMAC webhook, widened beyond `course_completed` to carry enrolment,
  activation and progress. ERP lands it on `TrainingCourseAssignment` and, on
  completion, `EmployeeCertification`.
- **HR reporting is a staff-only roll-up** to `hr@dotmac.ng`, separate from
  the admin activity report. Different audience, different action: HR needs
  who has not activated and who has stalled, by department. It must not be a
  filtered copy of the admissions report.
- Staff learning accountability runs through **assignment and management
  visibility in ERP**, not through Academy email nudges. The evidence for this
  is direct: 192 inactivity emails to this population produced no measurable
  change, and the reminder is structurally incapable of sending a second one.

### 4. Labs are part of a course; the certificate standard does not move

Completion continues to require every activity passed, labs included. A Dotmac
Academy certificate asserts that the holder configured the thing, not only that
they answered questions about it — dropping the hands-on requirement to make the
number go up would forfeit the only property that makes the credential worth
holding.

The consequence is accepted deliberately: no one completes a course until the
lab path works for real learners. That is a reason to keep lab infrastructure
healthy, not a reason to lower the bar. Nested virtualisation on the lab host is
therefore load-bearing, not best-effort — a `vr-ros` node that cannot boot blocks
every certificate in the technical programme.

### 5. The integration contract is versioned and fails loudly

- Event payloads carry an explicit `version`, and the receiver dispatches from
  an event registry rather than an `if event_type != "course_completed"` branch.
- An unmatched employee is **not** a success. ERP currently returns HTTP 200
  with `{"status": "ignored"}`, and the Academy stamps `erp_synced_at` on any
  2xx — so an event HR never received is recorded as delivered. Unmatched must
  return non-2xx, or the Academy must inspect the body; either way the outcome
  is counted and surfaced, never silently dropped.
- `ISSUING_AUTHORITY` and the webhook route prefix move to configuration. The
  current hardcoded `"Dotmac Fiber Academy"` is stale branding stamped onto
  every certificate.

## Consequences

- ERP's learning tables become dead weight until retired. That cost is
  accepted: leaving them authoritative-by-ambiguity is worse than leaving them
  unused-and-declared.
- `Enrollment.audience` is required, so every enrolment path — admin UI, bulk
  enrol, CLI, admissions acceptance — must supply it. A migration must
  classify existing rows before the constraint lands.
- Making unmatched events non-2xx means the Academy will retry them forever
  until the identity link is fixed. That is intended: a permanently retrying
  event is a visible defect, a silently discarded one is not.
- Staff and external learners diverge in reporting but **not** in curriculum,
  assessment or certification. A certificate means the same thing regardless of
  who paid for the seat.
- This ADR does not decide whether the Academy needs identity verification.
  No government ID, NIN, photo or document upload exists today, and the
  certificate chain currently carries no verified identity. That is recorded
  as a known limitation and deferred until certificates carry value outside
  Dotmac.

## Sequencing

The ownership decision above is a prerequisite for the work it enables; the
implementation order is deliberately not "build reporting first":

1. This ADR accepted.
2. Reactivate the 103 enrolled learners who hold no credential and have never
   signed in (`reinvite-stranded`) — no downstream signal is meaningful while
   half the roster cannot log in.
3. Drive the first course completion end-to-end. Two learners sit five
   activities short on a 27-activity course. Completion → certificate → webhook
   → `EmployeeCertification` has never executed in production once; the silent
   `ignored`-as-success defect above survived precisely because nothing ever
   traversed it. Prove the chain before scaling through it.
4. `Enrollment.audience` + `employee_ref` + backfill.
5. Widened event contract, HR roll-up, ERP assignment projection.

New enrolments are held until step 3 completes. Adding learners to a pipeline
with a 0% completion rate grows the dormant population, and dormancy is
self-reinforcing here — a learner who ignores the first nudge cannot currently
be sent a second.

## Authority change record

- **Old owner:** ambiguous — the Academy and `dotmac_erp`'s training module
  both modelled courses, lessons, assessments and progress, with no stated
  precedence.
- **New owner:** the Academy for all learning state; `dotmac_erp` for
  employment, requirement and credential state.
- **Verification:** ERP learning tables carry no new writers; the Academy's
  projection is idempotent and rebuildable from Academy state.
- **Drift prevention:** `docs/SOT_RELATIONSHIP_MAP.md` names both owners; the
  ERP-side contract fails loudly on unmatched identity rather than recording a
  false success.
- **Fallback retirement:** ERP learning tables retired under a separate change
  once no caller remains.
