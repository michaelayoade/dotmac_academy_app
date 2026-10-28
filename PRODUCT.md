# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- Learners completing assigned courses, assessments, schedules, announcements, hands-on labs, progress reviews, and certificates.
- Instructors managing cohorts, curriculum, announcements, grading, reports, success interventions, and lab activity.
- Academy administrators operating admissions, user access, audit history, reminders, platform settings, and service health.

## Product Purpose

Dotmac Academy is Dotmac's single-instance admissions and learning application. It carries applicants from public application and entrance assessment through audited review, onboarding, coursework, grading, labs, completion, certificates, and instructor reporting. Success means each role can understand current state and complete its work without losing context, data, or accountability.

## Positioning

Academy joins governed admissions and identity workflows with technical training delivery and real hands-on lab operations in one audited system, rather than treating learning content, operational practice, and administrative evidence as separate products.

## Operating Context

The product is used throughout an Academy workday: learners resume courses and labs; instructors monitor cohorts, submissions, results, and interventions; administrators review applications, audit decisions, inspect delivery history, and configure platform services. Dense tables, filters, statuses, long identifiers, and operational error states are ordinary product material, not edge cases.

## Capabilities and Constraints

- Production has exactly one configured Academy tenant; tenant-aware schema and PostgreSQL row-level security remain defence-in-depth controls.
- Accounts are created through Academy administration or accepted-applicant activation; there is no public registration path.
- Existing routes, permissions, forms, buttons, links, HTMX behavior, data fields, empty states, audit evidence, and operational statuses must remain functional and visible through UI changes.
- The application is server-rendered FastAPI/Jinja with Tailwind CSS, HTMX, a shared role-aware shell, and self-hosted production assets.
- Learner, Teaching, and Admin navigation is role-aware and must preserve familiar web-product affordances across desktop and mobile.
- Accessibility, keyboard operation, visible focus, reduced motion, responsive data presentation, and complete table access are release requirements.

## Brand Commitments

- Preserve the Dotmac Academy name and the existing Dotmac Academy logo in the application header.
- The user-provided Stitch Academic Modernist redesign is the approved visual authority for this redesign.
- Product language remains calm, direct, operational, and academically credible; factual copy and product claims are not invented during design work.

## Evidence on Hand

- Real production templates, route behavior, tests, data models, and product documentation in this repository.
- User-provided Stitch reference package at `C:\Users\kaygo\Downloads\stitch_minimalist_app_ui_redesign`, containing an Academic Modernist design specification, reference HTML, and representative Learner, Teaching, and Admin screens.
- Existing Dotmac logo and Academy imagery under `static/img/`.
- No fabricated customers, testimonials, benchmarks, pricing, or operational claims may be added.

## Product Principles

1. Preserve product truth and accountability: state, permissions, history, and consequences remain explicit.
2. Make dense operational work calm and scannable without hiding data or actions.
3. Keep role navigation predictable while allowing each workspace to foreground its own work.
4. Treat hands-on learning and lab operations as first-class Academy workflows.
5. Prefer durable, accessible interaction patterns over decorative novelty.

## Accessibility & Inclusion

The web interface must support keyboard navigation, visible focus, semantic controls, reduced-motion preferences, readable contrast, touch-sized targets, responsive layouts, and complete access to wide or dense data at small viewports.
