# Dotmac Academy — Management Short Courses (outline for review)

Industry-neutral management curriculum — no ISP-specific terminology; examples
drawn from general business operations so the courses work for any learner.

Proposed discipline tag: `management`. Short-course format: 5–6 chapters, one MCQ
bank per chapter (practice, threshold 0), one final assessment bank (pass ≥ 70%).
No labs. Import path per course:

```
python -m app.cli import-manual --tenant-slug <tenant> --slug <slug> \
  --title "<title>" --discipline management --chapters-dir <dir>
python -m app.cli load-banks --tenant-slug <tenant> --banks-dir <dir>/banks
```

Chapter files: `chapter-NN.md` with frontmatter `chapter:`, `title:`, `part:`.

Two groups: **functional** courses and **skills** courses. Suggested part tags:
`Function` / `Skills`.

---

## Functional courses

### 1. Leading a Team: First-Time Manager Essentials — `mgmt-team-leadership`
For anyone stepping from individual contributor into supervision.

1. **From Doer to Manager** — what changes in the role; why "best performer
   does everything" fails; a manager's actual outputs (team throughput,
   quality, ownership of outcomes).
2. **Delegation & Accountability** — assigning work, defining done, following
   up without micromanaging; one owner per task.
3. **Organising the Team's Work** — workload planning, rotas and coverage,
   handovers, making sure nothing is dropped between people.
4. **Coaching & Performance** — giving usable feedback, developing junior
   staff, documenting and handling underperformance.
5. **Leading Under Pressure** — keeping the team effective during crises and
   deadlines, communication cadence, blameless reviews afterwards.

### 2. Project Management Essentials — `mgmt-project-management`
Practical PM for team leads and coordinators, any industry.

1. **What Makes a Project** — scope, stakeholders, success criteria; why
   projects overrun.
2. **Planning the Work** — breaking work down, estimating, milestones and
   dependencies; realistic scheduling.
3. **Stakeholders & Approvals** — mapping who must agree, permissions and
   sign-offs, managing expectations before they become blockers.
4. **Managing Suppliers & Quality** — external contractors, service-level
   agreements, inspection and acceptance without stalling delivery.
5. **Tracking, Risk & Change Control** — progress reporting, a working risk
   register, handling scope changes without silent drift.
6. **Closeout & Handover** — documentation, acceptance, transferring the
   result to whoever operates it day-to-day.

### 3. Finance for Non-Financial Managers — `mgmt-finance-fundamentals`
The money view every manager needs, no accounting background assumed.

1. **How a Business Makes Money** — revenue, cost structure, fixed vs variable
   costs, capital vs operating spend.
2. **Unit Economics** — cost and margin per customer/product, payback period,
   knowing which activities actually earn.
3. **Customer Retention Economics** — cost of losing a customer vs keeping
   one, lifetime value, cohort thinking.
4. **Billing, Collections & Cash Flow** — invoicing discipline, receivables,
   why profitable businesses still run out of cash.
5. **Budgets & Business Cases** — building and defending a case for spending,
   equipment, or headcount.

### 4. Customer Experience & Service Management — `mgmt-customer-experience`
Owning the customer relationship at manager level.

1. **The Customer Journey** — every touchpoint from first contact to renewal;
   where experience is won and lost.
2. **Complaint Lifecycle & Ownership** — intake, categorisation, resolution,
   confirmation; one owner per complaint.
3. **Service Commitments** — service-level agreements, what to promise, how to
   measure and honour it, service recovery when you miss.
4. **Consumer Rights & Compliance** — regulatory and contractual obligations
   to customers, complaint-handling standards, what regulators generally
   expect of managers.
5. **Measuring Experience** — satisfaction and loyalty metrics (CSAT/NPS),
   complaint analytics, closing the loop with the wider business.

### 5. Vendor & Procurement Management — `mgmt-vendor-procurement`
Requisition-to-custody for managers who buy goods and services.

1. **Procurement Basics** — requisition → approval → purchase order; why
   approval discipline exists.
2. **Sourcing & Quotations** — writing specifications, comparing quotes, total
   cost of ownership vs lowest price.
3. **Contracts & Supplier SLAs** — key terms, penalties, renewals.
4. **Receiving, Inventory & Asset Custody** — goods receipt, custody chains,
   shrinkage prevention.
5. **Supplier Performance & Relationships** — scorecards, escalation, when to
   consolidate or switch suppliers.
6. **Procurement Ethics & Controls** — conflicts of interest, gifts and
   hospitality, bribery and facilitation payments, separation of duties,
   red flags and how to report.

---

## Skills courses

### 6. Decision Making & Problem Solving — `mgmt-decision-making`

1. **How Decisions Go Wrong** — common biases, urgency traps, decision debt,
   deciding by default.
2. **Structured Decision Frameworks** — decision matrix, cost–benefit,
   reversible vs irreversible decisions, who decides vs who is consulted.
3. **Root-Cause Problem Solving** — 5 whys, fishbone, separating symptom from
   cause; fixing the class of problem, not the instance.
4. **Deciding Under Uncertainty** — acting on incomplete information,
   escalation thresholds, when to wait for data and when waiting is the worst
   choice.
5. **Group Decisions & Buy-In** — meetings that actually decide, recording
   decisions and rationale, disagree-and-commit.

### 7. Communication & Reporting for Managers — `mgmt-communication`

1. **Communicating as a Manager** — audience/channel fit, upward vs downward
   vs lateral, what changes when you speak for a team.
2. **Written Reports That Get Read** — status and operational reports; lead
   with the outcome; structure and brevity.
3. **Briefing Up** — executive summaries, recommendations vs option lists,
   answering the question that was asked.
4. **Running Effective Meetings** — agendas, timeboxes, decisions and actions
   captured, killing standing meetings that earn nothing.
5. **Difficult Conversations** — performance feedback, conflict between team
   members, escalations from unhappy customers.

### 8. Managing with Data & KPIs — `mgmt-data-kpis`

1. **Why Measure** — leading vs lagging indicators, vanity vs actionable
   metrics.
2. **Choosing the Right KPIs** — a small set that reflects the team's real
   job: output, quality, speed, cost, customer satisfaction; what each
   actually tells you.
3. **Targets & Baselines** — setting targets that stretch without breaking,
   baselining before promising.
4. **Reading Dashboards & Reports** — trends vs snapshots, outliers,
   seasonality, knowing when a number is lying.
5. **From Metric to Action** — operational reviews, corrective actions,
   avoiding metric gaming.

### 9. Sales Essentials — `mgmt-sales-fundamentals` (PROPOSED, per Michael 2026-07-29)
Practical selling for anyone who talks to customers about buying, any industry.

1. **How Selling Works** — the sales process from prospect to close; pipeline
   thinking; selling as problem-solving, not persuasion; why activity at the
   top of the pipeline decides results at the bottom.
2. **Understanding the Customer** — discovery questions, listening before
   pitching, qualifying (need, budget, authority, timing), and walking away
   early from deals that will never close.
3. **Presenting Value** — features vs benefits, tailoring the proposal to the
   discovered need, writing quotes that get answered, talking about price
   with confidence.
4. **Objections & Negotiation** — the common objection types and honest
   responses; negotiation basics; protecting margin; concessions that get
   something in return; when to walk.
5. **Closing & Follow-Through** — asking for the decision, reading readiness,
   after-sale follow-up that produces referrals, and the pipeline discipline
   (records, next actions, honest stages) that makes numbers predictable.

---

## Assessment plan (all courses)

- Per-chapter MCQ bank: 8–10 questions, `kind: chapter` (practice, no gate).
- Final assessment: 20–25 questions across all chapters, `kind: final`
  (pass ≥ 70%, auto-created activity).
- 6-chapter courses (project management) optionally add a `kind: mid`
  checkpoint (≥ 60%).
- No labs; optional short written activities can be added later if wanted.

## Open items for Michael

- Audience: internal staff only, or public/paid? (Affects certificates,
  catalogue page, and website copy — not the authoring.)
- Trim or add to the skills group (6–8). Candidates not included: time/priority
  management (partly covered by 6 & 7), negotiation (partly in 5).
- Order of authoring — recommend starting with Leading a Team (1) and
  Decision Making (6) as the highest-leverage pair.
