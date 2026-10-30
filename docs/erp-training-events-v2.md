# Staff training events, version 2

Academy preserves main's stable employee-reference projection while Learning
owns curriculum, participation and completion. ERP receives a replaceable
projection; it does not become the learning writer. Version 1's email matching
does not provide version 2 identity.

An eligible active staff enrollment supplies `employee_ref`. The sender checks
the tenant, person, active course offering and enrollment identity again under
the product checkpoint lock. Conflicting eligible identities refuse rather than
selecting an arbitrary enrollment. Progress uses Learning's fractional `pct`
and emits percentage units rounded to two decimal places.

The common event fields are `version`, `event`, `employee_ref`,
`academy_enrollment_ref`, `academy_course_ref`, `course_title`, `course_version`,
`progress_pct`, `status`, and `occurred_at`. A completion event also includes
`passed`, `completed_on`, and `certificate_ref`. The exact serialized body is
HMAC-signed. Only explicit `recorded`, `updated`, or `duplicate` acknowledgements
advance delivery markers; unmatched/refused replies and transport failures
preserve previous markers.

Academy stores `erp_synced_at` and `erp_synced_pct` in its checkpoint, never in
Learning's completion row. An existing completion acknowledgement suppresses
replay without changing its original timestamp. Accepted percentage snapshots
prevent queued senders from sending the same progress after acquiring the lock.
HTTP acceptance followed by local rollback remains at-least-once delivery;
receiver deduplication is still required.

The existing offline admin-session sweep retains its hourly schedule. Web and
lab-worker roles receive no new checkpoint or imported-membership writes. The
candidate a011 migration and missing imported-checkpoint invariant are described
in [checkpoint custody](runbooks/ERP_COMPLETION_CHECKPOINT.md). This source
contract does not authorize production adoption or sender rollout.
