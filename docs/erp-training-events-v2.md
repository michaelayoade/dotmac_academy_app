# ERP staff training projection contract v2

The Academy is authoritative for learning state. ERP is authoritative for
employees, required assignments, and credentials. The hourly Academy sweep
projects changed staff course percentages to ERP over the existing signed
webhook.

## Identity and mapping

- `employee_ref` is the ERP `Employee.employee_code` supplied on the Academy
  staff enrolment. Email is not an integration key.
- `academy_course_ref` is the Academy `Course.source_ref`. Before enabling the
  Academy v2 sender, ERP must set the matching `TrainingCourse.academy_course_ref`.
- `academy_enrollment_ref` is the Academy enrollment UUID and becomes the ERP
  assignment source reference.

Unmapped employees or courses return HTTP 422 and are not marked as delivered.

## Events

ERP accepts `training_enrolled`, `training_progress_updated`, and
`course_completed` at version 2. The current state-derived Academy sender emits
changed `training_progress_updated` snapshots and `course_completed` snapshots.
Completion additionally carries `passed`, `completed_on`, and
`certificate_ref`.

`progress_pct` is a number from 0 through 100. ERP upserts
`TrainingCourseAssignment` and `TrainingCourseProgress`; a completion also
upserts `EmployeeCertification`. Replaying the same state is safe.

## Deployment order

1. Deploy the ERP migration and backward-compatible v2 receiver.
2. Populate ERP course `academy_course_ref` mappings and confirm employee codes
   match Academy `employee_ref` values.
3. Deploy the Academy migration and v2 sender.
4. Run `python -m app.cli erp-training-sync` once for reconciliation, then
   verify synced, unmatched, and failed counts before relying on the timer.
