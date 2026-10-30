"""Hosted real owner projections; requires canonical installed owners/a004/factory.

Authored only. No replacement principals, DTO mocks or duplicated query engine.
"""
import csv
import io
from datetime import UTC, datetime, timedelta

from dotmac_kernel.models import PartyPerson

from app.models.learning_event import LearningEvent
from app.models.success_queue import SuccessQueueEntry
from app.services import csv_reports, insights, settings_store
from tests.services.test_reports_owner import _seed
from tests.web.test_settings_access_policy import _restore_settings

assert _restore_settings


def test_roster_csv_keeps_best_grade_and_neutralizes_cells(current_account):
    a = current_account
    course, cohort, activity, lab, pa, pb = _seed(a.admin, a.tid)
    a.admin.get(PartyPerson, pa.id).first_name = "=SUM(1,1)"
    # A later zero attempt must not replace the owner's higher best score.
    from app.models.assessment import Score, Submission
    sub = Submission(tenant_id=a.tid, activity_id=activity.id, person_id=pb.id,
                     answers={}, attempt_no=2)
    a.admin.add(sub)
    a.admin.flush()
    a.admin.add(Score(tenant_id=a.tid, submission_id=sub.id, score=0, max_score=10,
                      fraction=0, passed=False, per_item=[], source="auto"))
    a.admin.flush()
    root = a.admin.get_transaction()
    name, text = csv_reports.cohort_roster_csv(a.admin, tenant_id=a.tid, cohort_id=cohort.id)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert name == "roster-progress-abuja-2026.csv" and len(rows) == 2
    assert rows[0]["name"].startswith("'=SUM")
    assert rows[0]["courses"] == "1" and rows[0]["avg_grade_pct"] == "70"
    assert rows[1]["avg_grade_pct"] == "90"  # lower later score is not the best
    assert a.admin.get_transaction() is root
    assert csv_reports.sanitize_cell("@formula") == "'@formula"
    assert csv_reports.sanitize_cell(0) == 0


def test_insights_and_csv_honor_fresh_configured_windows(current_account):
    a = current_account
    course, cohort, activity, lab, pa, pb = _seed(a.admin, a.tid)
    now = datetime(2026, 10, 19, tzinfo=UTC)
    a.admin.add(LearningEvent(tenant_id=a.tid, person_id=pa.id, course_id=course.id,
                              kind="course_viewed", occurred_at=now - timedelta(days=4)))
    settings_store.set_many(a.admin, {"learning_active_window_days": "3",
                                     "learning_comparison_prior_weeks": "2"})
    a.admin.flush()
    narrow = insights.cohort_overview(a.admin, tenant_id=a.tid, cohort_id=cohort.id, now=now)
    assert narrow["learners"] == 2 and narrow["active"] == 0
    assert "3 days" in narrow["active_rule"]
    settings_store.set_many(a.admin, {"learning_active_window_days": "5"})
    wide = insights.cohort_overview(a.admin, tenant_id=a.tid, cohort_id=cohort.id, now=now)
    assert wide["active"] == 1 and wide["inactive"] == 1
    comparison = insights.cohorts_comparison(a.admin, tenant_id=a.tid, now=now)
    assert next(r for r in comparison if r["cohort"].id == cohort.id)["active"] == 1
    _, text = csv_reports.cohort_funnel_csv(a.admin, tenant_id=a.tid, cohort_id=cohort.id, now=now)
    rows = dict(list(csv.reader(io.StringIO(text)))[1:])
    assert rows["active_last_7d"] == "1" and "events_prior_4wk_avg" in rows
    _, text = csv_reports.academy_summary_csv(a.admin, tenant_id=a.tid, now=now)
    assert next(iter(csv.DictReader(io.StringIO(text))))["active_last_7d"] == "1"


def test_queue_csv_renders_canonical_open_history_and_attachments(current_account):
    a = current_account
    course, cohort, activity, lab, pa, pb = _seed(a.admin, a.tid)
    for person, state in [(pa, "acknowledged"), (pb, "resolved")]:
        a.admin.add(SuccessQueueEntry(tenant_id=a.tid, person_id=person.id, cohort_id=cohort.id,
                    reason_kind="inactivity", severity="high", status=state,
                    detected_at=datetime.now(UTC), recommended_action="@call",
                    supporting_facts={"days_inactive": 9}))
    a.admin.flush()
    _, text = csv_reports.queue_summary_csv(a.admin, tenant_id=a.tid, cohort_id=cohort.id)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == 1 and rows[0]["email"] == pa.email
    assert rows[0]["status"] == "acknowledged" and rows[0]["recommended_action"] == "'@call"
    attachments = csv_reports.weekly_report_attachments(a.admin, tenant_id=a.tid, cohort_id=cohort.id)
    assert len(attachments) == 3 and all(content and mime == "text/csv" for _, content, mime in attachments)


def test_ordinary_caller_retains_transaction_tenant_and_read_scope(current_account, tenant_b):
    from sqlalchemy import text

    from app.services.reports import cohort_matrix, student_transcript

    a = current_account
    course, cohort, activity, lab, pa, pb = _seed(a.admin, a.tid)
    a.admin.commit()
    assert a.db.scalar(text("SELECT current_user")) == "app_user"
    root = a.db.get_transaction()
    assert cohort_matrix(a.db, tenant_id=a.tid, cohort_id=cohort.id)["rows"][0]["person_id"] == pa.id
    assert student_transcript(a.db, tenant_id=a.tid, person_id=pa.id)["person"].id == pa.id
    csv_reports.cohort_roster_csv(a.db, tenant_id=a.tid, cohort_id=cohort.id)
    csv_reports.queue_summary_csv(a.db, tenant_id=a.tid, cohort_id=cohort.id)
    assert a.db.get_transaction() is root
    assert a.db.scalar(text("SELECT current_setting('app.current_tenant')")) == str(a.tid)
