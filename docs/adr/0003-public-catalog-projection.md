# ADR 0003 — The public web presence is a projection of the courses table

Date: 2026-07-29 · Status: accepted

## Context

The academy's public marketing pages lived on the company WordPress sites and
were maintained by hand. They drifted structurally: the catalog copy was five,
then nine, courses behind production, because it duplicated facts the courses
table already owned. Meanwhile academy.dotmac.io's apex only redirected
anonymous visitors to /login.

## Decision

The academy application serves its own public presence:

- Anonymous `GET /` renders a public landing page; signed-in users keep the
  Learn Home. `GET /courses` renders the public catalog.
- The catalog is a **read-only projection of the courses table**. Its single
  canonical selector is `Course.listed` (added in migration 0042) combined
  with `status = 'published'`. Routes and templates must not layer extra
  slug or discipline filters on top; changing what is public means changing
  `listed`, nowhere else.
- Internal material stays unlisted: the instructor guide, entrance-assessment
  shells, and the internal `management` discipline (backfilled unlisted).
- The WordPress academy pages become 301 redirects to academy.dotmac.io. The
  company sites remain the ISP's marketing presence; they no longer carry
  academy course copy.

## Consequences

- The catalog can no longer go stale: importing or unlisting a course is the
  only publishing act.
- The public router (`app/web/public.py`) owns no writes and must stay
  read-only; it sits behind the same tenant resolution, RLS priming, and
  rate limiting as `/apply`.
- Course visibility gains one more state dimension (`listed`) orthogonal to
  authoring `status`: drafts are never public regardless of `listed`;
  published-but-unlisted courses are for enrolled learners only.

## Amendment — 2026-07-29 (same day)

The management discipline is now **publicly listed**: the academy presents two
program pillars (Technical Academy; Management & Professional Development) and
the catalog groups courses accordingly. `listed` semantics are unchanged — it
remains the single selector; this amendment changes the *data decision* for
`discipline = 'management'` rows, not the mechanism. Public listing does not
grant access: enrolment stays cohort/offering-gated, and management enrolment
is arranged by contact. The landing page intentionally lists no individual
courses — programs on the landing, courses in the catalog.
