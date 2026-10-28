"""RouterOS WebFig through the per-lab console proxy (POST /jsproxy).

The upstream is a fake (httpx.MockTransport); no router is contacted. Checks the
method allow-list, owner/tenant gate for POST, SSRF/path escapes, body cap,
header and cookie confinement, redirect rewriting and the narrow CSRF bridge.
"""

from __future__ import annotations

import httpx
import pytest

from app.models.lab import LabInstance
from app.models.person import Person
from tests.web.test_console_proxy import _entitled_activity, _login, _make_person

MGMT = "10.123.0.10"  # RFC 1918 fake device; private on every supported Python
ORIGIN = {"Origin": "http://alpha.localhost"}


def _seed_ros(admin_session, tenant, person_id, mgmt=MGMT) -> LabInstance:
    li = LabInstance(
        tenant_id=tenant.id,
        activity_id=_entitled_activity(admin_session, tenant, person_id),
        person_id=person_id,
        instance_name="dal-ros",
        seed={"o": 5},
        status="active",
        runtime_presence="present",
        consoles={"r1": {"kind": "vr-ros", "mgmt": mgmt}},
    )
    admin_session.add(li)
    admin_session.commit()
    admin_session.refresh(li)
    return li


@pytest.fixture
def upstream(monkeypatch):
    """Fake RouterOS: records requests, answers via ``upstream.respond``."""
    calls: list[httpx.Request] = []

    class Fake:
        respond = staticmethod(lambda req: httpx.Response(200, content=b"ok"))

    fake = Fake()

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return fake.respond(req)

    class _Transport(httpx.AsyncBaseTransport):
        # MockTransport pre-reads the body, which breaks the proxy's aiter_raw();
        # hand back an unconsumed byte stream like a real connection does.
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            resp = handler(request)
            return httpx.Response(
                resp.status_code, headers=resp.headers.raw, stream=httpx.ByteStream(resp.content), request=request
            )

    monkeypatch.setattr(
        "app.web.labs._new_upstream_client",
        lambda: httpx.AsyncClient(transport=_Transport(), follow_redirects=False),
    )
    fake.calls = calls
    return fake


@pytest.fixture
def owned(app_client, admin_session, tenant_a):
    p = _make_person(admin_session, tenant_a, "ros-owner@a.edu")
    li = _seed_ros(admin_session, tenant_a, p.id)
    h = _login(app_client, "ros-owner@a.edu")
    app_client.get("/", headers=h)  # make sure the csrf_token cookie exists
    assert app_client.cookies.get("csrf_token")
    return li, h


def _url(li, path="jsproxy"):
    return f"/labs/instances/{li.id}/console/r1/{path}"


def test_post_jsproxy_passes_through(app_client, owned, upstream):
    li, h = owned
    upstream.respond = lambda req: httpx.Response(
        200, content=b"\x01reply", headers={"content-type": "application/octet-stream"}
    )
    r = app_client.post(
        _url(li), headers={**h, **ORIGIN, "content-type": "text/plain"}, content=b"\x00enc-session-blob"
    )
    assert r.status_code == 200 and r.content == b"\x01reply"
    (call,) = upstream.calls
    assert call.method == "POST" and str(call.url) == f"http://{MGMT}/jsproxy"
    assert call.content == b"\x00enc-session-blob"
    assert call.headers["content-type"] == "text/plain"


def test_get_and_head_still_work(app_client, owned, upstream):
    li, h = owned
    assert app_client.get(_url(li, "webfig/"), headers=h).status_code == 200
    assert app_client.head(_url(li, "webfig/"), headers=h).status_code == 200
    assert [c.method for c in upstream.calls] == ["GET", "HEAD"]


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
def test_other_methods_rejected(app_client, owned, upstream, method):
    li, h = owned
    tok = app_client.cookies.get("csrf_token")
    r = app_client.request(method, _url(li), headers={**h, "x-csrf-token": tok})
    assert r.status_code == 405 and not upstream.calls


def test_other_user_forbidden_on_post(app_client, admin_session, tenant_a, upstream):
    owner = _make_person(admin_session, tenant_a, "ros-o2@a.edu")
    _make_person(admin_session, tenant_a, "ros-intruder@a.edu")
    li = _seed_ros(admin_session, tenant_a, owner.id)
    h = _login(app_client, "ros-intruder@a.edu")
    app_client.get("/", headers=h)
    r = app_client.post(_url(li), headers={**h, **ORIGIN}, content=b"x")
    assert r.status_code == 403 and not upstream.calls


def test_cross_tenant_not_found_on_post(app_client, admin_session, tenant_a, tenant_b, upstream):
    _make_person(admin_session, tenant_a, "ros-o3@a.edu")
    pb = Person(tenant_id=tenant_b.id, email="o@b.edu", first_name="B", last_name="B")
    admin_session.add(pb)
    admin_session.flush()
    li = _seed_ros(admin_session, tenant_b, pb.id)
    h = _login(app_client, "ros-o3@a.edu")
    app_client.get("/", headers=h)
    r = app_client.post(_url(li), headers={**h, **ORIGIN}, content=b"x")
    assert r.status_code == 404 and not upstream.calls


def test_unauthenticated_post_never_proxied(app_client, admin_session, tenant_a, upstream):
    p = _make_person(admin_session, tenant_a, "ros-o4@a.edu")
    li = _seed_ros(admin_session, tenant_a, p.id)
    r = app_client.post(_url(li), headers={"Host": "alpha.localhost"}, content=b"x", follow_redirects=False)
    assert r.status_code in (303, 401, 403) and not upstream.calls


@pytest.mark.parametrize(
    "mgmt", ["localhost", "127.0.0.1", "169.254.169.254", "8.8.8.8", f"{MGMT}:8080", f"u@{MGMT}", "::1", f"{MGMT}/x"]
)
def test_unsafe_mgmt_address_has_no_target(app_client, admin_session, tenant_a, upstream, mgmt):
    p = _make_person(admin_session, tenant_a, f"ros-m{abs(hash(mgmt))}@a.edu")
    li = _seed_ros(admin_session, tenant_a, p.id, mgmt=mgmt)
    h = _login(app_client, f"ros-m{abs(hash(mgmt))}@a.edu")
    app_client.get("/", headers=h)
    r = app_client.post(_url(li), headers={**h, **ORIGIN}, content=b"x")
    assert r.status_code == 404 and not upstream.calls


@pytest.mark.parametrize("path", ["/evil.test/x", "http://evil.test/", "a%5Cb", "a%00b", "a//b"])
def test_path_escapes_rejected(app_client, owned, upstream, path):
    li, h = owned
    r = app_client.get(_url(li, path), headers=h)
    assert r.status_code in (400, 404) and not upstream.calls
    r = app_client.post(_url(li, path), headers={**h, **ORIGIN}, content=b"x")
    assert r.status_code in (400, 404) and not upstream.calls


@pytest.mark.parametrize("path", ["../x", "a/../b", "./x", "a/./b", "x/..", "/x", "a//b", "a\\b", "a\x00b", "a\nb"])
def test_safe_subpath_rejects_escapes(path):
    # httpx normalises dot-segments before sending, so exercise the validator
    # directly for the traversal forms a raw client could still deliver.
    from fastapi import HTTPException

    from app.web.console_proxy import safe_subpath

    with pytest.raises(HTTPException) as exc:
        safe_subpath(path)
    assert exc.value.status_code == 400


def test_safe_subpath_encodes_delimiters():
    from app.web.console_proxy import safe_subpath

    assert safe_subpath("a?b#c d") == "a%3Fb%23c%20d"
    assert safe_subpath("jsproxy/get") == "jsproxy/get"


def test_bridge_path_matcher_is_narrow():
    from app.kernel_runtime import _is_console_post_path as ok

    u = "12345678-1234-1234-1234-123456789abc"
    assert ok(f"/labs/instances/{u}/console/r1/jsproxy")
    assert not ok(f"/labs/instances/{u}/console/r1")
    assert not ok(f"/labs/instances/{u}/check")
    assert not ok(f"/labs/instances/{u}/console/r1/../../check")
    assert not ok("/login")


def test_encoded_query_chars_stay_in_path(app_client, owned, upstream):
    li, h = owned
    app_client.get(_url(li, "a%3Fb%23c"), headers=h)
    (call,) = upstream.calls
    assert call.url.host == MGMT and call.url.raw_path == b"/a%3Fb%23c"


def test_body_cap_content_length(app_client, owned, upstream, monkeypatch):
    li, h = owned
    monkeypatch.setattr("app.web.labs.settings.lab_console_max_body_bytes", 16)
    r = app_client.post(_url(li), headers={**h, **ORIGIN}, content=b"x" * 17)
    assert r.status_code == 413 and not upstream.calls
    assert app_client.post(_url(li), headers={**h, **ORIGIN}, content=b"x" * 16).status_code == 200


def test_body_cap_chunked(app_client, owned, upstream, monkeypatch):
    li, h = owned
    monkeypatch.setattr("app.web.labs.settings.lab_console_max_body_bytes", 16)
    r = app_client.post(_url(li), headers={**h, **ORIGIN}, content=(b"x" * 8 for _ in range(3)))
    assert r.status_code == 413 and not upstream.calls


def test_learner_credentials_not_forwarded_and_device_cookie_confined(app_client, owned, upstream):
    li, h = owned
    sess = app_client.cookies.get("session")
    assert sess
    upstream.respond = lambda req: httpx.Response(
        200,
        headers=[
            ("set-cookie", "sid=abc123; Path=/; Domain=evil.test; Max-Age=60"),
            ("set-cookie", "session=hijack; Path=/"),
            ("set-cookie", "bad name=1"),
        ],
    )
    app_client.cookies.set("wf_sid", "dev1")
    r = app_client.post(
        _url(li),
        headers={
            **h,
            **ORIGIN,
            "authorization": "Bearer learner-secret",
            "x-csrf-token": app_client.cookies["csrf_token"],
            "referer": "http://alpha.localhost/labs",
            "x-forwarded-for": "198.51.100.7",
        },
        content=b"x",
    )
    assert r.status_code == 200
    (call,) = upstream.calls
    sent = {k.lower(): v for k, v in call.headers.items()}
    assert sent.get("cookie") == "sid=dev1"  # device-namespaced cookie only
    for banned in ("authorization", "x-csrf-token", "origin", "referer", "x-forwarded-for"):
        assert banned not in sent
    assert sess not in str(call.headers)
    cookies = r.headers.get_list("set-cookie")
    wf = [c for c in cookies if c.startswith("wf_")]
    pre = f"Path=/labs/instances/{li.id}/console/r1/; HttpOnly; SameSite=Strict"
    # A device cannot overwrite Academy's own "session" cookie: it is namespaced.
    assert wf == [f"wf_sid=abc123; {pre}; Max-Age=60", f"wf_session=hijack; {pre}"]
    assert not any(c.startswith(("session=", "bad")) or "evil.test" in c for c in cookies)


def test_no_slash_console_url_redirects_for_routeros(app_client, owned, upstream):
    li, h = owned
    r = app_client.get(f"/labs/instances/{li.id}/console/r1?x=1", headers=h, follow_redirects=False)
    assert r.status_code == 308
    assert r.headers["location"] == f"/labs/instances/{li.id}/console/r1/?x=1"
    assert not upstream.calls
    assert app_client.get(f"/labs/instances/{li.id}/console/r1/", headers=h).status_code == 200


def test_console_link_template_has_trailing_slash():
    src = open("templates/labs/_status.html").read()
    assert 'console/{{ node }}/"' in src


def test_device_redirects_stay_inside_prefix(app_client, owned, upstream):
    li, h = owned
    pre = f"/labs/instances/{li.id}/console/r1"
    upstream.respond = lambda req: httpx.Response(302, headers={"location": "/webfig/"})
    r = app_client.get(_url(li, "x"), headers=h, follow_redirects=False)
    assert r.headers["location"] == f"{pre}/webfig/"
    upstream.respond = lambda req: httpx.Response(302, headers={"location": f"http://{MGMT}/webfig/?a=1"})
    r = app_client.get(_url(li, "x"), headers=h, follow_redirects=False)
    assert r.headers["location"] == f"{pre}/webfig/?a=1"
    upstream.respond = lambda req: httpx.Response(302, headers={"location": "http://evil.test/"})
    r = app_client.get(_url(li, "x"), headers=h, follow_redirects=False)
    assert "location" not in r.headers
    upstream.respond = lambda req: httpx.Response(302, headers={"location": "../../../../login?next=1"})
    r = app_client.get(_url(li, "nested/x"), headers=h, follow_redirects=False)
    assert r.headers["location"] == f"{pre}/login?next=1"


def test_javascript_root_redirect_stays_inside_console_prefix(app_client, owned, upstream):
    li, h = owned
    pre = f"/labs/instances/{li.id}/console/r1"
    body = b'window.location = "/webfig/";'
    upstream.respond = lambda req: httpx.Response(
        200,
        content=body,
        headers={
            "content-type": "application/javascript; charset=utf-8",
            "etag": '"device-script-v1"',
        },
    )

    r = app_client.get(_url(li, "assets/script.js"), headers=h)

    assert r.status_code == 200
    assert r.content == b'window.location = "' + pre.encode() + b'/webfig/";'
    assert "etag" not in r.headers

    upstream.respond = lambda req: httpx.Response(
        200,
        content=b"binary:/webfig/:payload",
        headers={"content-type": "application/octet-stream"},
    )
    binary = app_client.get(_url(li, "jsproxy"), headers=h)
    assert binary.content == b"binary:/webfig/:payload"


def test_upstream_down_is_502(app_client, owned, upstream):
    li, h = owned

    def boom(req):
        raise httpx.ConnectError("down")

    upstream.respond = boom
    assert app_client.get(_url(li, "x"), headers=h).status_code == 502


# -- CSRF: the bridge is narrow and fail-closed --------------------------------


def test_post_without_origin_still_csrf_rejected(app_client, owned, upstream):
    li, h = owned
    r = app_client.post(_url(li), headers=h, content=b"x")
    assert r.status_code == 403 and not upstream.calls


@pytest.mark.parametrize(
    "extra",
    [
        {"Origin": "http://evil.test"},
        {**ORIGIN, "Sec-Fetch-Site": "cross-site"},
        {"Origin": "null"},
        {"Origin": "https://alpha.localhost"},
        {"Origin": "http://alpha.localhost/path"},
    ],
)
def test_cross_site_post_csrf_rejected(app_client, owned, upstream, extra):
    li, h = owned
    r = app_client.post(_url(li), headers={**h, **extra}, content=b"x")
    assert r.status_code == 403 and not upstream.calls


def test_bridge_does_not_apply_to_other_routes(app_client, owned, upstream):
    li, h = owned
    r = app_client.post(f"/labs/instances/{li.id}/check", headers={**h, **ORIGIN})
    assert r.status_code == 403
    r = app_client.post(f"/labs/instances/{li.id}/console/r1", headers={**h, **ORIGIN})
    assert r.status_code in (403, 405)  # index route is GET-only; never bridged
