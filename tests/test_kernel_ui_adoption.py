# ruff: noqa: F811  # imported pytest fixtures are injected by name
"""Rendered Kernel UI contracts; run in hosted CI after the released pin changes."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from dotmac_kernel.middleware.csrf import CSRFMiddleware, require_csrf
from dotmac_kernel.query import pagination_context
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.services.exceptions import BadRequestError
from app.web import lifecycle
from app.web.templating import templates
from tests.issue2_wave1_fixtures import app_client  # noqa: F401


class Document(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.elements = []
        self.feed(body)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

    def one(self, tag, **attrs):
        matches = [
            values
            for name, values in self.elements
            if name == tag and all(values.get(k) == v for k, v in attrs.items())
        ]
        assert len(matches) == 1, (tag, attrs, matches)
        return matches[0]


@pytest.fixture
def browser(monkeypatch, app_client):
    # Exercise the real route handlers and signed Kernel CSRF transports over
    # HTTP. Existing hosted owner tests cover real credential/token mutations.
    app = FastAPI()
    app.add_middleware(CSRFMiddleware, secret="ui-contract-test-signing-secret", session_cookie_names=("session",))
    tenant = SimpleNamespace(id=uuid4())

    @app.middleware("http")
    async def tenant_context(request, call_next):
        request.state.tenant = tenant
        return await call_next(request)

    app.include_router(lifecycle.router, dependencies=[Depends(require_csrf)])
    app.dependency_overrides[get_db] = lambda: object()
    monkeypatch.setattr(lifecycle, "password_reset_policy", lambda db: SimpleNamespace(minimum_length=13))
    monkeypatch.setattr(lifecycle, "invitation_acceptance_policy", lambda db: SimpleNamespace(minimum_length=13))
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize(
    ("path", "card"), [("/forgot", "forgot-card"), ("/reset", "reset-card"), ("/accept-invite", "accept-card")]
)
def test_shared_forms_render_native_and_htmx_transports(browser, path, card):
    response = browser.get(path, params={"token": '<dummy>&"'})
    assert response.status_code == 200
    document = Document(response.text)
    document.one("div", id=card)
    form = document.one("form", action=path)
    assert form["method"] == "post" and form["hx-post"] == path
    assert form["hx-select"] == form["hx-target"] == f"#{card}"
    assert form["hx-swap"] == "outerHTML"
    proof = document.one("input", name="csrf_token")["value"]
    assert proof and proof == browser.cookies.get("csrf_token")
    if path != "/forgot":
        assert document.one("input", name="token")["value"] == '<dummy>&"'
        password = document.one("input", name="password")
        assert password["minlength"] == "13" and password["autocomplete"] == "new-password"
    document.one("a", href="/login")
    assert "<dummy>" not in response.text


@pytest.mark.parametrize("path", ["/forgot", "/reset", "/accept-invite"])
def test_lifecycle_post_requires_valid_csrf(browser, path):
    browser.get(path)
    for payload in ({}, {"csrf_token": "invalid-proof"}):
        response = browser.post(
            path, data={"email": "nobody@example.test", "token": "dummy", "password": "dummy-password", **payload}
        )
        assert response.status_code == 403
    proof = browser.cookies.get("csrf_token")
    response = browser.post(
        path,
        data={"email": "nobody@example.test", "token": "dummy", "password": "dummy-password"},
        headers={"x-csrf-token": proof, "Origin": "https://elsewhere.example"},
    )
    assert response.status_code == 403
    response = browser.post(path, data={"csrf_token": proof})
    assert response.status_code == 422
    browser.cookies.set("session", "different-dummy-session")
    response = browser.post(
        path,
        data={"email": "nobody@example.test", "token": "dummy", "password": "dummy-password"},
        headers={"x-csrf-token": proof},
    )
    assert response.status_code == 403


@pytest.mark.parametrize("hx", [False, True], ids=["native", "htmx"])
@pytest.mark.parametrize("valid", [False, True], ids=["invalid-token", "valid-token"])
@pytest.mark.parametrize(
    ("path", "card", "owner", "method", "title"),
    [
        ("/reset", "reset-card", "lifecycle", "reset_password", "Password"),
        ("/accept-invite", "accept-card", "invitation_claim", "accept_invite", "Account"),
    ],
)
def test_post_results_match_selected_card_without_echoing_material(
    browser, monkeypatch, hx, valid, path, card, owner, method, title
):
    calls = []

    def submit(db, **kwargs):
        calls.append(kwargs)
        if not valid:
            raise BadRequestError("This link is invalid or expired")

    monkeypatch.setattr(getattr(lifecycle, owner), method, submit)
    browser.get(path)
    proof = browser.cookies.get("csrf_token")
    headers = {"HX-Request": "true", "x-csrf-token": proof} if hx else {}
    data = {"token": "private-dummy-token", "password": "private-dummy-password"}
    if not hx:
        data["csrf_token"] = proof
    response = browser.post(path, data=data, headers=headers)
    assert response.status_code == 200
    document = Document(response.text)
    document.one("section", id=card)
    assert title in response.text
    assert ("This link is invalid or expired" in response.text) is not valid
    assert "private-dummy-token" not in response.text and "private-dummy-password" not in response.text
    assert calls[0]["raw"] == "private-dummy-token"
    if hx:
        assert response.headers["HX-Reselect"] == response.headers["HX-Retarget"] == f"#{card}"
        assert response.headers["HX-Reswap"] == "outerHTML"


@pytest.mark.parametrize("hx", [False, True], ids=["native", "htmx"])
def test_forgot_response_is_neutral_and_preserves_redirect_contract(browser, monkeypatch, hx):
    addresses = []

    def request_reset(db, **kwargs):
        addresses.append(kwargs["email"])
        return None

    monkeypatch.setattr(lifecycle.lifecycle, "request_password_reset", request_reset)
    browser.get("/forgot")
    proof = browser.cookies.get("csrf_token")
    headers = {"HX-Request": "true", "x-csrf-token": proof} if hx else {}
    responses = [
        browser.post("/forgot", data={"email": address, "csrf_token": proof}, headers=headers)
        for address in ("known@example.test", "unknown@example.test")
    ]
    assert responses[0].content == responses[1].content
    assert addresses == ["known@example.test", "unknown@example.test"]
    document = Document(responses[0].text)
    document.one("section", id="forgot-card")
    redirect = document.one("div", **{"data-redirect-after": "3000"})
    assert redirect["data-redirect-href"] == "/login"
    assert "on its way" in responses[0].text
    assert "known@example.test" not in responses[0].text


def test_kernel_lifecycle_stylesheet_is_served_without_spilling_into_product_pages(app_client, browser):
    document = Document(browser.get("/forgot").text)
    urls = [
        attrs["href"]
        for tag, attrs in document.elements
        if tag == "link" and attrs.get("href", "").startswith("/static/css/main.css?v=")
    ]
    assert len(urls) == 1
    url = urls[0]
    response = app_client.get(url)
    assert response.status_code == 200 and "text/css" in response.headers["content-type"]
    shell = templates.TemplateResponse(Request({"type": "http", "path": "/", "headers": []}), "base.html", {})
    assert url not in shell.body.decode()


@pytest.mark.parametrize(("total", "offset", "previous"), [(95, 100, 90), (0, 100, 0)])
def test_shared_pagination_recovers_stale_offsets_and_preserves_filters(total, offset, previous, app_client):
    page = pagination_context(total=total, limit=10, offset=offset)
    request = Request(
        {
            "type": "http",
            "scheme": "http",
            "server": ("example.test", 80),
            "path": "/admin/applications",
            "query_string": b"status=pending&offset=100&limit=10",
            "headers": [],
        }
    )
    rendered = templates.TemplateResponse(
        request,
        "admin/applications.html",
        {"pagination": page, "metrics": {}, "applicants": [], "selected_status": "pending"},
    ).body.decode()
    assert page["offset"] == 100 and page["page_start"] == page["page_end"] == 0
    document = Document(rendered)
    link = document.one("a", **{"aria-label": "Previous page"})
    assert f"offset={previous}" in link["href"] and "status=pending" in link["href"]
    document.one("input", name="status", value="pending")
    assert 'aria-current="page"' not in rendered


def test_product_has_no_second_pagination_owner():
    from app.web.pagination import pagination_context as compatibility_import

    assert compatibility_import is pagination_context
    root = Path(__file__).resolve().parents[1]
    assert not (root / "templates/components/_pagination.html").exists()
    assert not any("macro table_pagination(" in path.read_text() for path in (root / "templates").rglob("*.html"))


def test_shared_pagination_valid_window_keeps_navigation_and_filter(app_client):
    page = pagination_context(total=95, limit=10, offset=10)
    request = Request(
        {
            "type": "http",
            "scheme": "http",
            "server": ("example.test", 80),
            "path": "/admin/applications",
            "query_string": b"status=pending&offset=10&limit=10",
            "headers": [],
        }
    )
    response = templates.TemplateResponse(
        request,
        "admin/applications.html",
        {"pagination": page, "metrics": {}, "applicants": [], "selected_status": "pending"},
    )
    document = Document(response.body.decode())
    assert (page["page_start"], page["page_end"], page["current_page"]) == (11, 20, 2)
    assert "offset=0" in document.one("a", **{"aria-label": "Previous page"})["href"]
    next_page = document.one("a", **{"aria-label": "Next page"})["href"]
    assert "offset=20" in next_page and "status=pending" in next_page
    document.one("span", **{"aria-current": "page"})
    document.one("input", name="status", value="pending")


@pytest.mark.parametrize("convention", ["new-positional", "old-positional", "new-keyword", "old-keyword"])
def test_public_render_facade_preserves_call_conventions_precedence_status_and_escaping(
    app_client, monkeypatch, convention
):
    from app.web import templating

    monkeypatch.setattr(
        templating, "nav_context", lambda request: {"branding_name": "<Public & Academy>", "current_person": None}
    )
    request = Request({"type": "http", "path": "/", "headers": []})
    context = {"request": request, "branding_name": "caller-spoof", "academy_app_css_url": "/caller.css"}
    if convention == "new-positional":
        response = templates.TemplateResponse(request, "base.html", context, 409)
    elif convention == "old-positional":
        response = templates.TemplateResponse("base.html", context, status_code=409)
    elif convention == "new-keyword":
        response = templates.TemplateResponse(request=request, name="base.html", context=context, status_code=409)
    else:
        response = templates.TemplateResponse(name="base.html", context=context, status_code=409)
    assert response.status_code == 409
    assert response.context["branding_name"] == "<Public & Academy>"
    assert response.context["academy_app_css_url"] == "/caller.css"
    assert 'href="/caller.css"' in response.body.decode()
    assert "&lt;Public &amp; Academy&gt;" in response.body.decode()
    assert "caller-spoof" not in response.body.decode()


@pytest.mark.parametrize("unsupported", [{"headers": {}}, {"background": None}, {"media_type": "text/plain"}])
def test_public_render_facade_rejects_unsupported_options(unsupported):
    with pytest.raises(TypeError, match="unsupported TemplateResponse"):
        templates.TemplateResponse(
            Request({"type": "http", "path": "/", "headers": []}), "base.html", {}, **unsupported
        )


def test_shipped_redirect_scheduler_handles_native_and_htmx_results():
    import shutil
    import subprocess

    node = shutil.which("node")
    assert node is not None, "Node.js is required for the lifecycle browser contract"
    harness = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const events = {};
const timers = [];
function panel() {
  const attrs = {'data-redirect-after': '3000', 'data-redirect-href': '/login'};
  return {nodeType: 1, isConnected: true, querySelector: () => null, hasAttribute: key => key in attrs,
    getAttribute: key => attrs[key], setAttribute: (key, value) => {attrs[key] = value;}};
}
let nativePanel = panel();
const document = {
  querySelector: () => nativePanel,
  addEventListener: (name, callback) => {events[name] = callback;},
  body: {addEventListener: (name, callback) => {events[name] = callback;}}
};
const window = {location: {href: '/forgot'}};
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), {
  document, window, setTimeout: (callback, delay) => {timers.push({callback, delay});}
});
events.DOMContentLoaded();
assert.equal(timers.length, 1);
assert.equal(timers[0].delay, 3000);
assert.equal(window.location.href, '/forgot');
timers[0].callback();
assert.equal(window.location.href, '/login');
events.DOMContentLoaded();
assert.equal(timers.length, 1);
window.location.href = '/forgot';
const swappedPanel = panel();
const insertedCard = {nodeType: 1, isConnected: true, hasAttribute: () => false,
  querySelector: () => swappedPanel};
const detachedForm = {nodeType: 1, isConnected: false, hasAttribute: () => false,
  querySelector: () => null};
const swapEvent = {target: insertedCard, detail: {target: detachedForm, elt: insertedCard}};
events['htmx:afterSwap'](swapEvent);
assert.equal(timers.length, 2);
assert.equal(timers[1].delay, 3000);
timers[1].callback();
assert.equal(window.location.href, '/login');
events['htmx:afterSwap'](swapEvent);
assert.equal(timers.length, 2);
// If the event target is unavailable, detail.elt may itself own the marker.
window.location.href = '/forgot';
const insertedRoot = panel();
const rootEvent = {detail: {target: detachedForm, elt: insertedRoot}};
events['htmx:afterSwap'](rootEvent);
assert.equal(timers.length, 3);
assert.equal(timers[2].delay, 3000);
timers[2].callback();
assert.equal(window.location.href, '/login');
events['htmx:afterSwap'](rootEvent);
assert.equal(timers.length, 3);
"""
    subprocess.run(  # noqa: S603 - fixed harness and repository-owned source
        [node, "-e", harness, str(Path(__file__).resolve().parents[1] / "static/lifecycle.js")],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_composed_application_imports_in_a_fresh_process():
    import subprocess
    import sys

    subprocess.run(
        [sys.executable, "-c", "from app.main import app; assert app.routes"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize(
    ("status", "runtime_presence", "error", "show_console"),
    [
        ("active", "present", None, True),
        ("active", "absent", None, False),
        ("active", "present", "Infrastructure failure", False),
        ("error", "present", "Infrastructure failure", False),
    ],
)
def test_lab_status_http_fragment_keeps_console_policy_in_explicit_context(
    app_client, monkeypatch, status, runtime_presence, error, show_console
):
    from app.web import labs

    app = FastAPI()
    tenant, person = SimpleNamespace(id=uuid4()), SimpleNamespace(id=uuid4())
    instance = SimpleNamespace(
        id=uuid4(),
        status=status,
        runtime_presence=runtime_presence,
        error=error,
        consoles={"router1": {"kind": "vr-ros"}},
    )
    session = object()
    authorized = []

    @app.middleware("http")
    async def tenant_context(request, call_next):
        request.state.tenant = tenant
        return await call_next(request)

    def owned_instance(db, scoped_tenant, scoped_person, instance_id):
        assert db is session and scoped_tenant is tenant and scoped_person is person
        assert instance_id == instance.id
        authorized.append(instance_id)
        return instance

    monkeypatch.setattr(labs, "_owned_instance", owned_instance)
    monkeypatch.setattr(labs, "_result_context", lambda *args: {"recovered_operation": None, "saved_score": None})
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[labs.require_web_user] = lambda: person
    app.include_router(labs.router)
    with TestClient(app) as client:
        response = client.get(f"/labs/instances/{instance.id}/status", headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert authorized == [instance.id]
    assert response.context["lab_console_live"] is labs._console_live
    console_url = f"/labs/instances/{instance.id}/console/router1/"
    assert (console_url in response.text) is show_console
    if error:
        assert error in response.text


@pytest.mark.parametrize("page", ["base", "login", "lifecycle"])
def test_shared_request_feedback_assets_render_once_in_order_and_are_served(app_client, browser, page):
    if page == "lifecycle":
        response = browser.get("/forgot")
        body = response.text
    else:
        request = Request({"type": "http", "path": "/login" if page == "login" else "/", "headers": []})
        body = templates.TemplateResponse(request, f"{page}.html", {}).body.decode()
    document = Document(body)
    container = document.one("div", id="toast-container")
    assert container["x-data"] == "toastStore" and container["aria-live"] == "polite"
    scripts = [attrs for tag, attrs in document.elements if tag == "script"]
    shared = [attrs for attrs in scripts if attrs.get("src", "").startswith("/static/js/components.js?v=")]
    alpine = [attrs for attrs in scripts if attrs.get("src", "").startswith("/static/js/alpine.min.js?v=")]
    assert len(shared) == len(alpine) == 1
    assert scripts.index(shared[0]) < scripts.index(alpine[0])
    assert body.index(shared[0]["src"]) < body.index("</head>")
    assert body.index('id="toast-container"') > body.index("<body")
    assert "defer" in alpine[0]
    assert sum(attrs.get("src", "").startswith("/static/htmx.min.js") for attrs in scripts) == 1
    assert sum(attrs.get("src", "").startswith("/static/csrf.js") for attrs in scripts) == 1
    assert all(attrs.get("src") for attrs in scripts), "CSP forbids inline script blocks"
    styles = [attrs["href"] for tag, attrs in document.elements if tag == "link" and attrs.get("rel") == "stylesheet"]
    toast_css = [url for url in styles if url.startswith("/static/css/toasts.css?v=")]
    assert len(toast_css) == 1
    assert any(url.startswith("/static/css/main.css?v=") for url in styles) is (page == "lifecycle")
    for url in (shared[0]["src"], alpine[0]["src"], toast_css[0]):
        asset = app_client.get(url)
        assert asset.status_code == 200 and asset.content
    if page == "login":
        assert "/static/img/login-hero.png" in body


def test_product_templates_have_no_additional_alpine_expressions_requiring_eval():
    from app.config import ACADEMY_CONTENT_SECURITY_POLICY

    root = Path(__file__).resolve().parents[1]
    attributes = []
    for path in (root / "templates").rglob("*.html"):
        for _tag, attrs in Document(path.read_text()).elements:
            attributes.extend(
                (str(path.relative_to(root)), name) for name in attrs if name.startswith(("x-", "@", ":"))
            )
    assert attributes == [], attributes
    assert "script-src 'self'" in ACADEMY_CONTENT_SECURITY_POLICY
    assert "'unsafe-eval'" not in ACADEMY_CONTENT_SECURITY_POLICY


def test_shipped_shared_feedback_owns_single_submit_and_never_echoes_failed_body(app_client):
    import json
    import shutil
    import subprocess

    node = shutil.which("node")
    assert node is not None, "Node.js is required for shared browser feedback contracts"
    root = Path(__file__).resolve().parents[1]
    # Consume the asset actually served by the assembled app, not an upstream
    # checkout or a product copy of Kernel's event handlers.
    body = templates.TemplateResponse(
        Request({"type": "http", "path": "/", "headers": []}), "base.html", {}
    ).body.decode()
    document = Document(body)
    url = next(
        attrs["src"]
        for tag, attrs in document.elements
        if tag == "script" and attrs.get("src", "").startswith("/static/js/components.js?v=")
    )
    shared = app_client.get(url)
    assert shared.status_code == 200
    harness = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = JSON.parse(fs.readFileSync(0, 'utf8'));
const events = {};
const bodyEvents = {};
const notifications = [];
const add = (registry, name, callback) => { (registry[name] ||= []).push(callback); };
const document = {
  querySelector: () => null, querySelectorAll: () => [], getElementById: () => null,
  addEventListener: (name, callback) => add(events, name, callback),
  body: {addEventListener: (name, callback) => add(bodyEvents, name, callback)}
};
const window = {
  addEventListener: () => {},
  dispatchEvent: event => notifications.push(event)
};
class Element {
  hasAttribute(name) { return name === 'data-submit-on-change'; }
}
class CustomEvent { constructor(type, options) { this.type = type; this.detail = options.detail; } }
const context = vm.createContext({document, window, Element, CustomEvent});
vm.runInContext(source.shared, context);
vm.runInContext(source.product, context);
for (const callback of events.DOMContentLoaded || []) callback();
let submissions = 0;
const select = new Element();
select.form = {submit: () => submissions++};
for (const callback of events.change || []) callback({target: select});
assert.equal(submissions, 1, 'a shared rows-per-page control must submit only once');
for (const event of ['htmx:responseError', 'htmx:sendError']) {
  for (const callback of bodyEvents[event] || []) {
    callback({detail: {xhr: {responseText: '<private-response-body>token=secret-canary</private-response-body>'}}});
  }
}
assert.equal(notifications.length, 2);
for (const event of notifications) {
  assert.equal(event.type, 'show-toast');
  assert.equal(event.detail.message, 'Something went wrong. Please try again.');
  assert.equal(event.detail.type, 'error');
  assert.ok(!JSON.stringify(event).includes('secret-canary'));
}
"""
    subprocess.run(  # noqa: S603 - fixed harness and assembled/repository-owned sources
        [node, "-e", harness],
        input=json.dumps({"shared": shared.text, "product": (root / "static/academy.js").read_text()}),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
