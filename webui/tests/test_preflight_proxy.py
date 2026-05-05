import respx
from httpx import Response


def _login(client):
    client.post("/api/setup", json={"username": "admin", "password": "hunter2hunter2"})
    client.post("/api/login", json={"username": "admin", "password": "hunter2hunter2"})


@respx.mock
def test_proxy_ok_country_match(client):
    _login(client)
    respx.get("https://api.ipify.org").mock(return_value=Response(200, text="1.2.3.4"))
    respx.get("http://ip-api.com/json/1.2.3.4").mock(
        return_value=Response(200, json={"status": "success", "countryCode": "US", "country": "United States"})
    )
    r = client.post("/api/preflight/proxy", json={
        "mode": "manual",
        "url": "http://user:pw@127.0.0.1:1080",
        "expected_country": "US",
    })
    assert r.json()["status"] == "ok"


@respx.mock
def test_proxy_country_mismatch(client):
    _login(client)
    respx.get("https://api.ipify.org").mock(return_value=Response(200, text="1.2.3.4"))
    respx.get("http://ip-api.com/json/1.2.3.4").mock(
        return_value=Response(200, json={"status": "success", "countryCode": "DE", "country": "Germany"})
    )
    r = client.post("/api/preflight/proxy", json={
        "mode": "manual",
        "url": "http://user:pw@127.0.0.1:1080",
        "expected_country": "US",
    })
    assert r.json()["status"] == "warn"


@respx.mock
def test_proxy_multiline_picks_one_candidate(client, monkeypatch):
    _login(client)
    monkeypatch.setattr("webui.backend.preflight.proxy.random.choice", lambda items: items[1])
    respx.get("https://api.ipify.org").mock(return_value=Response(200, text="5.6.7.8"))
    respx.get("http://ip-api.com/json/5.6.7.8").mock(
        return_value=Response(200, json={"status": "success", "countryCode": "US", "country": "United States"})
    )
    r = client.post("/api/preflight/proxy", json={
        "mode": "manual",
        "url": "http://proxy-a.example:8080\nhttp://proxy-b.example:8080",
        "expected_country": "US",
    })

    body = r.json()
    assert body["status"] == "ok"
    assert any(
        check["name"] == "selected_proxy" and check["message"] == "http://proxy-b.example:8080"
        for check in body["checks"]
    )


def test_proxy_mode_none(client):
    _login(client)
    r = client.post("/api/preflight/proxy", json={"mode": "none"})
    assert r.json()["status"] == "ok"
