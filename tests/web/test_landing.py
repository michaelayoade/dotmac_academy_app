def test_landing_renders(app_client):
    r = app_client.get("/", headers={"Host": "alpha.localhost"})
    assert r.status_code == 200
    assert "Dotmac Academy" in r.text
