# Kernel UI adoption (incubation)

This change is prepared against Academy main `c9cc6cb12c28992106e9a6b7324df6d6478a71b9`
(tree `10ec`) and Starter PR #1030 UI contracts, plus the pending public
`render(..., filters=...)` port being prepared upstream. That port is not yet a
published Kernel API. It is **not qualified for use with
Academy's current Kernel `0.1.0a108` pin**. No successor version has been assumed,
vended, or allocated here. Publication verification, an exact released pin and
lock update, and full hosted CI remain coordinator gates before pushing adoption.
There is no deployment or runtime qualification claim.

Kernel owns `dotmac_kernel.query.pagination_context` and
`components/table_macros.html::table_pagination`. Academy's Python module is only
a compatibility re-export for existing callers; the duplicate macro is removed.
Five product templates import the shared macro. Route queries and hidden filters
are unchanged. Stale offsets preserve the actual queried offset, display 0–0,
have no active page, and navigate directly to the last valid page (95 rows,
limit 10, offset 100 → Previous 90; an empty list → Previous 0).

Kernel owns the forgot/reset/accept form markup. Academy binds its existing route
paths, request CSRF proof, bearer token, effective password-policy minimum and
login path. Branding reads the existing Academy context owner and Kernel branding
owner; there is no second product name fallback. The product login hero remains
product owned. The product's `TemplateResponse` compatibility facade delegates only to Kernel's
public `render` API. Kernel retains the sole composed production loader and
render environment. The product passes its fixed three-filter mapping through
the pending owner-local filter port; it never reads Kernel's environment or
constructs a second production Jinja environment. Context precedence remains
UI/timezone defaults, then caller values, then authoritative navigation context.
Old/new positional and keyword call conventions and status codes are retained;
unsupported response options fail explicitly. Isolated legacy test harnesses use
test-only Jinja environments, without a production `.env` compatibility seam.
A full live caller census found one old environment-global writer in lab routes;
it is removed. All seven lab render paths now pass the same unchanged
`_console_live` policy callable explicitly. The census found 26 direct product
facade imports, 98 TemplateResponse calls, no aliases, and no remaining live
`.env` or `get_template` accesses.
Kernel's public Jinja global `static_asset_url('/static/css/main.css')` supplies the shared utility stylesheet
only on lifecycle pages, before the product UI and app stylesheets. The normal
shell does not acquire the Kernel stylesheet.

Academy retains result presentation and the three-second redirect contract.
The existing `static/lifecycle.js` scheduler now initializes on DOMContentLoaded
as well as HTMX swaps, so native forgot results also return to login. One shared
initializer schedules each result once; no Kernel script is forked. Each result has the corresponding `forgot-card`, `reset-card`
or `accept-card` ID. Explicit HX-Reselect, HX-Retarget and HX-Reswap headers match
the shared form's selection, so the browser never selects an absent fragment.
Handled domain validation results now return HTTP 200 for HTMX as well as native
forms: default HTMX does not swap the former 400 results. CSRF/authentication
failures, request-validation 422 responses, and unexpected errors retain their
security/error paths. Result pages do not echo submitted tokens or passwords.
The canonical credential and invitation service calls, anti-enumeration wording,
transaction ownership, savepoint recovery and outbox enqueue code are unchanged.
Kernel error layout/toast scripts remain Kernel owned; no copies are added.
Both the product base and standalone login include the public
`components/request_feedback_assets.html` head partial and
`components/toasts.html` body partial exactly once. Kernel owns scoped toast CSS,
components.js, the CSP Alpine core and toastStore. Product HTMX and CSRF assets
remain once each, with components registered before deferred Alpine runs. Normal
product and login pages gain only scoped toast CSS, not Kernel main.css.

The product's duplicate data-submit-on-change listener is removed from
static/academy.js; the shared handler now submits each page-size change once.
The script cache key advances so returning browsers do not retain the duplicate
listener. Sidebar, search, live-region and custom submit handlers remain intact.
The current product template census contains no Alpine directives or shorthand
expressions; only the shared toast partial contributes Alpine markup. The
existing script-src 'self' CSP remains unchanged, without unsafe-eval.

`tests/test_kernel_ui_adoption.py` adds **39 collected cases**: rendered form
contracts (3), missing/invalid/cross-origin/session-rebound CSRF rejection and unchanged 422 (3), native/HTMX valid
and invalid token results (8), neutral forgot and redirect contracts (2), served
shared stylesheet without default-shell spill (1), stale pagination (2), single
pagination owner (1), and valid filtered pagination (1), public-render call conventions/context/status/
escaping (4), explicit unsupported-option rejection (3), and a behavioral Node
canary executing the shipped native/HTMX redirect scheduler (1), a fresh-process composed app import (1), and actual lab status
HTTP fragments proving the unchanged console policy callable is explicitly
bound for live/absent/error cases (4), shared feedback assets/served-once contracts
for base/login/lifecycle pages (3), the product CSP Alpine directive census (1),
and a behavioral canary for single page-size submission and generic request
failure feedback without response-body echo (1). These UI HTTP tests use
the actual route handlers and signed Kernel CSRF middleware with service doubles;
existing hosted reset/invitation owner tests still verify real credentials,
token spending, policy enforcement, savepoints and transaction health. Their
presentation expectations now parse attributes and reflect the deliberate HTML
200 validation-result contract. The full hosted census must increase by 39;
there are no added skips or weakened security assertions.

Only static AST, pinned Ruff 0.16.10 lint/format, Node syntax and whitespace checks are permitted
for this incubation work. No app import, tests, dependency installation, build,
Docker operation, registry write or host mutation was performed locally. Tests
must run against the verified successor release in hosted CI, including the HTTP
check proving the composed static mount serves the Kernel stylesheet.
