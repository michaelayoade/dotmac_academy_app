# Recipient, applicant history, and lab account source ports

Source only. Learning certificate-read and required Kernel V3 dependencies remain
UNALLOCATED/UNRELEASED. Hosted tests are authored, not run; installed assembly,
physical FK compatibility, migration/adoption and retirement remain unqualified.

`app.services.email_outbox._attachments` uses public Learning `get_course` and
`get_certificate` facts. Academy's purpose-specific `certificate_recipient`
selects canonical tenant/id Party plus PartyPerson contact fields without an
Academy profile, active-account, or completion eligibility condition, preserving
historical queued-delivery behavior. PDF name formatting, issued serial/time,
filename, MIME type, payload errors and missing-state failures remain unchanged.

`applicant_transition_history` consumes the canonical audit facade's full
applicant history. Application invitation export consumes its newest event over
the historical five-action selection and retains applicant-source fallback.
Tenant, applicant entity type/id, seven/five action memberships and created-at
DESC ordering stay in SQL, with no generic web pagination cap or new tie order.
Historical `applicant.transition_baseline` is a read identity, not a registered
writer action. The generic audit writer is unchanged.

Lab handlers and helper annotations now describe the existing genuine
`AcademyCurrentAccount` web dependency, whose id is the canonical Party id.
Existing ownership, tenant, activity and Learning entitlement gates are retained.
No lab policy, writer, credential authority, new kernel API, or role policy was
introduced by this port.
