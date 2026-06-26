"""Task 1 landing test — updated for Task 11.

GET / is now the dashboard (requires auth). Unauthenticated requests are
redirected to /login rather than served as a public page.
"""


def test_landing_redirects_unauthenticated(app_client, tenant_a):
    # tenant_a ensures the 'alpha' tenant exists so TenantResolverMiddleware resolves it.
    r = app_client.get("/", headers={"Host": "alpha.localhost"}, follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/login" in r.headers.get("location", "")
