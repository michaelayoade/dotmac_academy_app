# ADR 0002 — Single-Academy Deployment

**Status:** Accepted  
**Date:** 2026-07-29  
**Supersedes:** ADR 0001 for deployment topology, tenant lifecycle, and settings ownership

## Context

Dotmac Academy currently serves one Dotmac Academy instance, not multiple
customer tenants. The inherited starter exposed platform tenant provisioning,
public account registration, and global settings through abstractions intended
for a multi-customer SaaS product. Those paths created unnecessary authority and
made global SMTP and branding settings ambiguous.

The tenant-aware schema is already pervasive and PostgreSQL RLS provides useful
defence in depth. Removing those database controls would add migration risk
without improving the single-Academy product.

## Decision

The application has exactly one configured Academy tenant in production.

- `TENANCY=single` declares the topology. The kernel startup assertion requires
  exactly one tenant row and binds that database-owned slug; configuration does
  not carry a second copy of the tenant identity.
- Tenant provisioning is offline through the bootstrap command. There is no
  request-path `/platform/tenants` control plane.
- There is no public `/auth/register`. Academy admins invite accounts; accepted
  applicants activate accounts through single-use links.
- SMTP, branding, email policy, and lab limits apply to the one Academy
  instance. Academy admins own the browser workflow. A restricted database
  settings-writer role (historically named `platform_api`) remains separate
  from the ordinary RLS request role.
- The tenant-aware schema, composite foreign keys, tenant-bound sessions, and
  RLS policies remain mandatory isolation controls and test canaries.

Supporting a second independently administered Academy/customer is a future
architecture change. It requires a new ADR, explicit settings ownership,
tenant lifecycle and support contracts, a shadow/verification phase, and a
cutover plan. Adding another tenant row is not sufficient authorization.

## Source-of-truth boundaries

- `app.services.admissions` owns applicant state transitions and admin review
  consequences. `AuditEvent` is the official transition/decision history.
- `Track` plus `CohortTrack` owns curriculum placement. `Applicant.track_id`
  and `Enrollment.track_id` reference that canonical pair; `program` is only a
  display snapshot.
- `app.services.entrance_exam` owns the assessment clock. Elapsed time and
  expiry derive from the server-stamped start time; browser durations are
  observations that are ignored.
- `app.services.assessment` and `app.services.attempts` own learner attempts.
  Row locks serialize writers, while unique database constraints backstop
  concurrent requests.
- `EmailOutbox` owns committed email intent, retry state, and delivery evidence.
  SMTP is transport only. Domain transactions enqueue; the outbox timer
  reconciles delivery after commit.
- `app.services.web_auth` owns login lockout state. Routes are adapters that
  must allow failed-attempt updates to commit.

The detailed relationship map is
[`docs/SOT_RELATIONSHIP_MAP.md`](../SOT_RELATIONSHIP_MAP.md).

## Migration and cutover

| Concern | Previous path | Current owner/cutover |
|---|---|---|
| Tenant creation | Public platform API | Offline bootstrap only; public router removed |
| Account creation | Public first-user registration | Admin invitation and applicant activation |
| Academy settings | Platform-token browser gate | Authenticated Academy admin plus settings-writer DB role |
| Applicant track | Free-text program and nullable enrollment track | Active `CohortTrack` pair; ambiguous legacy rows require audited admin assignment |
| Exam timing | Browser-reported elapsed/heartbeat pause | Server wall clock from explicit start |
| Email | Synchronous, pre-commit SMTP | Transactional outbox and retry timer |
| Admissions history | Mutable notes/current status | Append-only audit events with migration baseline |

Migration `0041_review_remediation` backfills unambiguous applicant tracks,
seeds transition baselines, repairs duplicate historical attempts, and creates
the outbox and concurrency constraints. Ambiguous legacy applications stay
unassigned and cannot be accepted until an admin records a cohort/track
placement.

## Operational consequences

- Production startup fails if single-tenancy, host restrictions, secrets,
  CSRF, or rate limiting are not configured safely.
- `academy-email-outbox.timer` must be enabled anywhere email is expected.
  Failed rows retain sanitized error classes and can be requeued without
  exposing message tokens in CLI output.
- The kernel-owned security middleware writes CSP, clickjacking, MIME-sniffing,
  referrer, permissions, HTTPS HSTS, and the Academy-declared COOP/CORP policy
  from kernel a38's `ProductSecurityPolicy` contract.
- The remaining cross-tenant tests are deliberate database isolation canaries,
  not a statement that the product currently supports multiple tenants.
