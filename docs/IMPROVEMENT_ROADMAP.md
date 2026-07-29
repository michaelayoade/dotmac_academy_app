# Dotmac Academy — consolidated improvement roadmap

Adopted 2026-07-29 (Michael). Execution order: P0 scheduling correctness →
Learner Success Hub → reminder engine → learning-event ledger + analytics →
attendance → practical assignments + competency mastery → verifiable
credentials → accessibility/offline → external integrations. Deterministic,
explainable rules before any predictive ML. Each slice follows the SOT
standard: one owner per decision, thin adapters, boundary tests.

## Priority 0 — Correct existing scheduling
1. Treat timetable input as Africa/Lagos time before storing UTC (was attached UTC-direct in app/web/instructor.py).
2. Add a learner timetable/session-detail page.
3. Replace the nonexistent /timetable calendar fallback in app/services/agenda.py.
4. Give live sessions their own calendar styling and direct Join action.
5. Add timezone, session-link and calendar regression tests.

## Priority 1 — Learner Success Hub
6. My Courses as the primary learner dashboard: in-progress/upcoming/completed/expired/locked filters; progress, current grade, passing grade; next activity + deadline; last accessed chapter; upcoming live session; certificate status; Resume/Start/Review actions.
7. Unified To Do timeline: overdue; due today; next 7 days; next 30 days; live sessions; newly graded; unread feedback; course open/close dates.
8. Continue Learning resumes the actual last meaningful activity across devices.
9. Learner progress page: course/activity names; overall weighted grade; passing threshold; attempts used/remaining; detailed feedback; completion %; upcoming/overdue; trend; certificate eligibility + download.
10. Authenticated iCalendar feed export.
11. Bookmarks and personal notes for course content.

## Priority 2 — Student reminders
12. Configurable reminder-policy service (assignment, course starting, due 72/24h, overdue, session 24h/1h, inactivity, graded, completed, certificate issued/expiring).
13. Delivery through the transactional email outbox.
14. Frequency preferences: immediate, daily digest, weekly digest, quiet hours, per-event opt-outs.
15. Reminder history, delivery status, retry evidence, authorized resend.
16. Real student-reminder timer (at-risk-sweep currently has no checked-in timer, in-app only).
17. WhatsApp/SMS later as an additional transport behind the same policy — never a second decision system.

## Priority 3 — Actionable analytics
18. Canonical learning-event ledger (viewed, chapter completed, activity started, submitted, graded, lab launched, lab check pass/fail, session attended, certificate earned).
19. Learner analytics: weekly activity, completion velocity, grade trend, time since last activity, strong/weak competencies, attendance, blockers + recommended next action.
20. Instructor analytics: active vs inactive; submitted/overdue/not-attempted; averages; completion/dropout funnels; question difficulty + discrimination; lab failure patterns; cohort/track comparisons; weekly trends.
21. Replace boolean at-risk with an explainable Success Queue (learner, reason, facts, severity, freshness, owner, recommended action; open/acknowledged/resolved).
22. "Message these learners" actions for deterministic segments (no activity 7d, overdue, below passing, failed final, low attendance, almost complete).
23. Scheduled cohort/track/Academy reports with CSV export.
24. No predictive ML initially — deterministic, explainable rules fit the data volume.

## Priority 4 — Live training and attendance
25. Attendance records per session/learner (present/late/absent/excused, minutes, reason/notes, marked by/at).
26. Fast instructor register: mark all present, record exceptions.
27. Finalize, reopen, audited corrections.
28. Learner-visible attendance history and percentage.
29. Cohort attendance reports and printable registers.
30. Attendance feeds the shared intervention queue.
31. Defer QR/geolocation/self-check-in until the instructor-owned register and anti-fraud policy exist.

## Priority 5 — Assignments and practical skills
32. Real assignment submissions (written, files, photos, OTDR traces, splicing evidence, diagrams; instructor comments; returned work).
33. Reusable grading rubrics (criteria × performance levels).
34. Submission states: draft, submitted, returned, resubmitted, graded.
35. Due dates, extensions, late policy.
36. Competency framework for technical skills.
37. Associate courses/chapters/assessments/lab checks/assignments with competencies.
38. Single mastery resolver deriving competency state from canonical evidence.
39. Learner and instructor skill matrices (mastered/developing/missing).
40. Completion/certification may require specific practical competencies, not merely quiz passes.
41. Competency identifiers/rubrics designed for 1EdTech CASE compatibility (https://standards.1edtech.org/case/).

## Priority 6 — Credentials and employability
42. Public certificate-verification page + QR.
43. Credential criteria, evidence, issue/expiry, revocation status.
44. Skill-level Open Badges 3.0 once competency evidence exists (https://www.1edtech.org/standards/open-badges).
45. Learner skills passport (courses, competencies, practical evidence, credentials).
46. Keep projecting employee training completions to ERP; Academy stays authoritative for learning evidence.

## Priority 7 — Content and engagement
47. Course evaluations and post-training surveys.
48. Instructor feedback forms; satisfaction trends.
49. Moderated course Q&A/discussions if WhatsApp proves insufficient.
50. Reusable course templates, question banks, rubric libraries.
51. Content-review workflow: draft → review requested → approved → published → retired.
52. Content-effectiveness analytics linking weak outcomes to specific chapters/questions/labs.
53. Adaptive remediation paths: failed competency → recommended reading/practice/lab.

## Priority 8 — Accessibility and low-bandwidth learning
54. WCAG 2.2 AA as UI baseline (https://www.w3.org/TR/WCAG22/).
55. Automated accessibility checks in CI.
56. Audit keyboard nav, focus, forms, tables, contrast, assessment interactions.
57. Captions/transcripts for instructional media.
58. Installable mobile web app.
59. Explicit offline download of published course content by course version.
60. Assessments, attendance submission and labs stay online (server authority).
61. Optimize images/media/pages for low bandwidth.

## Priority 9 — Integrations, when justified
62. LTI for specific external tools.
63. xAPI/LRS if external simulators/field systems must emit learning evidence.
64. SCORM import only if vendor packages require it.
65. CASE import/export for external competency frameworks.
66. HR/ERP learning-path assignment under an approved employment-training contract.
67. Google/Outlook/mobile calendar integration.
