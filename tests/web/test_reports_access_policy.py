"""Genuine hosted Reports canaries; no local execution or schema substitution.

Requires installed canonical identity owners, a004 physical FK compatibility and
whole factory closure. Fixture/migration/installed acceptance remains unqualified.
"""
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from dotmac_kernel.models import AuthSession, PartyRoleGrant, Role
from fastapi import HTTPException
from sqlalchemy import select, update

from app.config import Settings
from app.models.platform_settings import PlatformSetting
from app.services import settings_store
from app.services.identity import AcademyCurrentAccount
from app.services.reports_access import require_reports_access
from app.services.web_auth import require_web_user
from tests.services.test_canonical_current_user import _request

KEY = "reports_access_roles"


@pytest.fixture(autouse=True)
def _restore_settings(request):
    if "current_account" not in request.fixturenames:
        yield
        return
    a = request.getfixturevalue("current_account")
    original = settings_store.get_all(a.admin)
    try:
        yield
    finally:
        a.db.rollback()
        a.admin.rollback()
        a.admin.query(PlatformSetting).delete()
        for key, value in original.items():
            a.admin.add(PlatformSetting(key=key, value=value))
        a.admin.commit()


def _grant(a, slug, tenant_id=None):
    tid = tenant_id or a.tid
    role = a.admin.scalars(select(Role).where(Role.tenant_id == tid, Role.slug == slug)).first()
    if role is None:
        role = Role(tenant_id=tid, slug=slug, name=slug)
        a.admin.add(role)
        a.admin.flush()
    grant = PartyRoleGrant(tenant_id=tid, party_id=a.pid, role_id=role.id)
    a.admin.add(grant)
    a.admin.commit()
    return grant.id


def _client(a, app_client):
    app_client.cookies.clear()
    app_client.cookies.set("session", a.token)
    headers = {"Host": "alpha.localhost"}
    app_client.get("/instructor/reports", headers=headers, follow_redirects=False)
    return {**headers, "x-csrf-token": app_client.cookies.get("csrf_token", "")}


def _all_routes(client, headers):
    cid = uuid4()
    paths = ["", f"/cohort/{cid}/analytics", f"/cohort/{cid}.csv", f"/cohort/{cid}",
             f"/student/{cid}", f"/cohort/{cid}/roster.csv", f"/cohort/{cid}/funnel.csv",
             f"/cohort/{cid}/queue.csv", "/academy-summary.csv"]
    responses = [client.get("/instructor/reports" + p, headers=headers, follow_redirects=False) for p in paths]
    responses.extend(client.post("/instructor/reports" + p, headers=headers, follow_redirects=False)
                     for p in [f"/student/{cid}/email", f"/cohort/{cid}/email"])
    return responses


def test_custom_role_live_policy_empty_deny_and_grant_withdrawal(current_account, app_client):
    a = current_account
    slug = f"settings-curator-{uuid4().hex}"
    grant_id = _grant(a, slug)
    settings_store.set_many(a.admin, {KEY: f'["{slug}"]'})
    a.admin.commit()
    request = _request(a.tenant, a.token)
    account = require_web_user(request, a.db)
    assert isinstance(require_reports_access(request, account, a.db), AcademyCurrentAccount)
    headers = _client(a, app_client)
    assert app_client.get("/instructor/reports", headers=headers).status_code == 200
    stale_policy = a.db.get(PlatformSetting, KEY)
    a.admin.execute(update(PlatformSetting).where(PlatformSetting.key == KEY).values(value="[]"))
    a.admin.commit()
    assert stale_policy.value == f'["{slug}"]'
    with pytest.raises(HTTPException) as caught:
        require_reports_access(request, account, a.db)
    assert caught.value.status_code == 403
    assert [r.status_code for r in _all_routes(app_client, headers)] == [403] * 11
    settings_store.set_many(a.admin, {KEY: f'["{slug}"]'})
    a.admin.commit()
    assert require_reports_access(request, account, a.db).id == a.pid
    stale_grant = a.db.get(PartyRoleGrant, grant_id)
    a.admin.delete(a.admin.get(PartyRoleGrant, grant_id))
    a.admin.commit()
    assert stale_grant.id == grant_id
    assert [r.status_code for r in _all_routes(app_client, headers)] == [403] * 11


def test_admin_has_no_implicit_override_and_foreign_tenant_roles_do_not_authorize(current_account, tenant_b):
    a = current_account
    _grant(a, "admin")
    settings_store.set_many(a.admin, {KEY: '["custom-settings-owner"]'})
    a.admin.add(Role(tenant_id=tenant_b.id, slug="custom-settings-owner", name="foreign role"))
    a.admin.commit()
    request = _request(a.tenant, a.token)
    account = require_web_user(request, a.db)
    with pytest.raises(HTTPException) as caught:
        require_reports_access(request, account, a.db)
    assert caught.value.status_code == 403
    with pytest.raises(HTTPException) as caught:
        require_web_user(_request(tenant_b, a.token), a.db)
    assert caught.value.status_code == 303


def test_revoked_session_denies_every_reports_route(current_account, app_client):
    a = current_account
    _grant(a, "admin")
    settings_store.set_many(a.admin, {KEY: '["admin"]'})
    a.admin.commit()
    headers = _client(a, app_client)
    assert app_client.get("/instructor/reports", headers=headers).status_code == 200
    stale_session = a.db.get(AuthSession, a.session_id)
    a.admin.execute(update(AuthSession).where(AuthSession.id == a.session_id).values(revoked_at=datetime.now(UTC)))
    a.admin.commit()
    assert stale_session.revoked_at is None
    responses = _all_routes(app_client, headers)
    assert [r.status_code for r in responses] == [303] * 11
    assert all(r.headers["Location"] == "/login" for r in responses)


@pytest.mark.parametrize("raw", [None, "null", "", "{}", "true", '["owner","owner"]', '[" owner"]', '[1]'])
def test_malformed_reports_access_policy_refuses_config_and_store(current_account, raw):
    a = current_account
    with pytest.raises(ValueError, match=KEY):
        Settings(**{KEY: raw})
    with pytest.raises(ValueError, match=KEY):
        settings_store.set_many(a.admin, {KEY: raw})
    a.admin.merge(PlatformSetting(key=KEY, value=raw))
    a.admin.commit()
    request = _request(a.tenant, a.token)
    with pytest.raises(ValueError, match=KEY):
        require_reports_access(request, require_web_user(request, a.db), a.db)


def test_policy_env_custom_slug_and_empty_list(monkeypatch):
    monkeypatch.setenv("REPORTS_ACCESS_ROLES", '["operator"]')
    assert Settings().reports_access_roles == ("operator",)
    monkeypatch.setenv("SETTINGS_ACCESS_ROLES", '["manager"]')
    settings = Settings()
    assert settings.settings_access_roles == ("manager",)
    assert settings.reports_access_roles == ("operator",)
    assert Settings(**{KEY: []}).reports_access_roles == ()




@pytest.mark.parametrize("state", ["inactive", "suspended"])
def test_live_disabled_account_denies_every_reports_route(current_account, app_client, state):
    from dotmac_kernel.models import Party

    from app.models.identity_extensions import AcademyAccountProfile

    a = current_account
    _grant(a, "reports-reviewer")
    settings_store.set_many(a.admin, {KEY: '["reports-reviewer"]'})
    a.admin.commit()
    headers = _client(a, app_client)
    assert app_client.get("/instructor/reports", headers=headers).status_code == 200
    if state == "inactive":
        a.admin.execute(update(Party).where(Party.id == a.pid).values(is_active=False))
    else:
        a.admin.execute(update(AcademyAccountProfile).where(AcademyAccountProfile.party_id == a.pid)
                        .values(status="suspended"))
    a.admin.commit()
    assert [r.status_code for r in _all_routes(app_client, headers)] == [303] * 11
