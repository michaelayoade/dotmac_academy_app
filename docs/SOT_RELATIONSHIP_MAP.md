# Dotmac Academy source-of-truth relationship map

This map names the canonical owner for each business decision, derived field,
external consequence, and repair path. Routes, templates, CLI commands, timers,
and SMTP are adapters around these owners.

| Domain/state | Authoritative input and owner | Canonical writer | Derived/projection state | Reconciler/backstop |
|---|---|---|---|---|
| Academy deployment identity | Configured `ACADEMY_TENANT_SLUG` plus offline `Tenant` row | Offline bootstrap/operator | `request.state.tenant` | Tenant resolver rejects every other production slug; RLS fails closed |
| User identity and roles | `Person`, `UserCredential`, `Role`, `PersonRole` | Account/lifecycle services | Auth sessions and navigation permissions | Tenant-bound token/session checks; admin invitation workflow |
| Login abuse state | Credential failure count and `locked_until` | `web_auth.authenticate` | Login response | Credential row lock and successful-login reset |
| Applicant intake | Public `/apply` facts | `admissions.submit_application` | Applicant profile completeness and display `program` | Idempotent email-key intake; admin review for legacy gaps |
| Curriculum placement | Active `Track` + `CohortTrack` | Public canonical selection or audited `assign_applicant_intake` | `Applicant.track_id`, `Enrollment.track_id`, `program` snapshot | Composite FKs; acceptance/enrolment gate; admin placement correction |
| Admissions decision | Applicant facts, assessment validity, configured threshold | `admissions.transition_applicant` / `apply_assessment_policy` | Current applicant status | `AuditEvent` transition ledger; admin detail history |
| Entrance assessment time | Server `assessment_started_at` | `entrance_exam.start_exam` | Elapsed snapshot, remaining time, exceeded flag | Server wall-clock recomputation; admin reset |
| Entrance assessment result | Canonical question bank and submitted answers | `entrance_exam.grade_and_record` | Score, level, competency profile, validity | Applicant row lock; single-sitting guard |
| Learner assessment attempts | Activity policy, canonical person/activity rows | `assessment.submit_activity`, `attempts.open_or_create_attempt` | Best score, completion | Person row locks; unique attempt/open-sitting constraints |
| Course completion/certificate | Best scores and completion rules | Completion service | Completion record and certificate | Idempotent recomputation; certificate outbox attachment generation |
| Email consequence | Committed domain transaction | `email_outbox.enqueue_email` | Pending/sent/failed delivery ledger | Timer worker, exponential retries, stable Message-ID, manual requeue |
| SMTP delivery | One outbox row | `email_outbox.deliver_pending` | `sent_at`, sanitized error class, invite delivery projection | `academy-email-outbox.timer`; SMTP is transport only |
| Academy settings | Environment defaults plus `platform_settings` overrides | Academy admin settings route using restricted settings-writer role | Effective SMTP/branding/policy/lab config | DB-over-env resolver; blank secret fields preserve existing value |
| Official operational history | Domain service facts | `write_audit_event` | Admin audit and applicant decision history | Migration baseline plus append-only application behavior |
| Student reminder consequence | Canonical enrollment/deadline/session/grade/completion state + `ReminderPreference` | `reminders.sweep` (sole decision owner; ledger `ReminderLog` enforces once-per-occurrence) | In-app notification + outbox email (immediate/digest/quiet-hours pacing) | `academy-reminders.timer` re-sweeps idempotently; admin history + audited resend; outbox stays delivery owner |
| Public catalog visibility | `Course.listed` + `status='published'` (ADR 0003) | Course import/authoring services | Anonymous landing and `/courses` projection | `catalog.public_catalog` is the only reader; routes add no extra filters; external marketing pages are 301 redirects, never copies |
| Learning observations | Meaningful learner actions at their owning services' commit points | `learning_events.record` (append-only; INSERT-only grants) | Learner activity + cohort insight projections (`insights.py`) | Savepoint-isolated `emit` — ledger failure never breaks the owner; consequences stay with reminders/queue owners |
| Learner intervention state | Deterministic rules over ledger + canonical records | `success_queue.sweep` / `success_queue.transition` | Success Queue page, queue CSVs, weekly digest attachments | Idempotent sweep refresh + auto-resolve when a rule stops firing; audited lifecycle |
| Segment messaging consequence | Instructor action on a deterministic segment | `success_queue.message_segment` | In-app notifications + outbox rows | Audited action id; outbox idempotency per action+person; delivery stays with the outbox worker |
| Stranded-learner reactivation | Active student enrolment with no `UserCredential` and no `AuthSession` ever | `reengagement.reinvite_stranded` (owns *who is locked out*; token minting stays `lifecycle._issue_token`) | Fresh `AccountToken(kind='invite')` + `account_invite` outbox row | Re-runnable — a new token supersedes the stale link that stranded them; never an at-risk rule, which stays `success_queue.sweep` |
| Admin activity reporting | Canonical pipeline records, learning-event ledger, open Success Queue | `admin_reports.send_activity_report` | Daily admin email (engagement rates, top movers, attention list) | Read-only projection — re-derives no threshold; a wrong queue is wrong here too, by design |
| Learning state for staff and external learners (ADR 0004) | Academy curriculum, enrolment, activity, assessment, completion | This Academy — sole LMS; `dotmac_erp`'s `training_course`/`lesson`/`assessment` tree is non-authoritative | ERP `TrainingCourseAssignment` + `EmployeeCertification` projections | Webhook projection is idempotent and rebuildable from Academy state; unmatched identity must fail loudly, never record a false success |
| Employment, training requirement and credential state (ADR 0004) | ERP `Employee`, department/manager, assigned training | `dotmac_erp` | Academy `Enrollment.audience` + `employee_ref` supplied at enrolment | Identity is the employee reference, never a lowercased email match |

## Adapter rules

- Public and admin web routes validate input, call the owning service, and
  render its result. They do not duplicate transition or delivery policy.
- API routes require a tenant-bound authenticated admin for management data.
  Public intake exists only at `/apply`.
- CLI commands do not print raw invite, reset, assessment, or onboarding
  tokens. They request a queued consequence and report counts.
- Email templates and SMTP do not decide business outcomes.
- Imported identifiers, display strings, cached elapsed values, and current
  status alone are not authoritative substitutes for their owning records.

## Authority changes

Any future move to multi-customer hosting, a different admissions owner, an
external LMS decision engine, or an external notification control plane must
name the old and new owner, shadow verification, cutover gate, drift repair,
fallback retirement, and boundary tests in an ADR before cutover.
