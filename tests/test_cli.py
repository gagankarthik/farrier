"""The command line: help text, version, and the SSH / crypto / certificate / approval commands run against
the local data directory with in-process TLS and SSH servers."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from test_ssh import FakeSSHServer

from farrier import __version__
from farrier.api.app import create_app
from farrier.cli import NOT_FOUND, main, _dashboard_dev_command


def run(capsys, data_dir, *argv) -> str:
    main(["--data", str(data_dir), *argv])
    return capsys.readouterr().out


def run_json(capsys, data_dir, *argv):
    return json.loads(run(capsys, data_dir, *argv, "--json"))


@pytest.fixture
def ssh_server():
    s = FakeSSHServer()
    yield s
    s.close()


# ---- help and version ---------------------------------------------------------------------------------

def test_help_describes_the_product_and_every_command(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--help"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    assert "Agentless machine identity automation" in out and "ACME can't reach" not in out
    for cmd in ("serve", "scan", "tick", "ssh", "crypto", "certs", "endpoints", "version"):
        assert cmd in out


def test_serve_help_does_not_claim_a_dashboard(capsys):
    with pytest.raises(SystemExit):
        main(["serve", "--help"])
    out = " ".join(capsys.readouterr().out.split())
    assert "engine API" in out and "dashboard is the separate web app" in out
    assert "run the API, dashboard" not in out


@pytest.mark.parametrize("argv", [["--version"], ["version"]])
def test_version(capsys, argv):
    try:
        main(argv)
    except SystemExit as e:
        assert e.code == 0
    assert capsys.readouterr().out.strip() == f"farrier {__version__}"


def test_serve_prints_where_the_api_and_dashboard_are(capsys, data_dir, monkeypatch):
    import signal

    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    monkeypatch.setattr("farrier.cli.sys.platform", "linux")  # the hint is platform-specific
    before = signal.getsignal(signal.SIGTERM)
    try:
        main(["--data", str(data_dir), "serve", "--port", "8799", "--grace", "0.1"])
    finally:
        signal.signal(signal.SIGTERM, before)
    out = capsys.readouterr().out
    assert "http://127.0.0.1:8799/api" in out and "http://127.0.0.1:8799/docs" in out
    assert "docker compose up" in out and "FARRIER_API_URL=http://127.0.0.1:8799 npm run dev" in out


@pytest.mark.parametrize("platform, expected", [
    ("linux", "cd web && FARRIER_API_URL=http://127.0.0.1:8799 npm run dev"),
    ("win32", 'cd web; $env:FARRIER_API_URL="http://127.0.0.1:8799"; npm run dev'),
])
def test_dashboard_start_hint_matches_shell_platform(monkeypatch, platform, expected):
    monkeypatch.setattr("farrier.cli.sys.platform", platform)
    assert _dashboard_dev_command("http://127.0.0.1:8799") == expected


def test_engine_root_explains_where_the_dashboard_is(engine):
    c = TestClient(create_app(engine))
    for path in ("/", "/dashboard"):
        r = c.get(path, follow_redirects=False)
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
        assert "This is the Farrier engine API" in r.text and 'href="/docs"' in r.text


# ---- ssh ----------------------------------------------------------------------------------------------

def test_ssh_scan_table_and_json(capsys, data_dir, ssh_server):
    target = f"127.0.0.1:{ssh_server.port}"
    out = run(capsys, data_dir, "ssh", "scan", target)
    line = next(ln for ln in out.splitlines() if ln.startswith(target))
    assert "SSH-2.0-OpenSSH_7.9p1" in line and "ssh-ed25519 256" in line and "yes" in line
    assert "1 scanned, 1 answered SSH, 1 stored" in out

    j = run_json(capsys, data_dir, "ssh", "scan", target)
    assert j["ssh"] == 1 and len(j["hosts"]) == 1
    h = j["hosts"][0]
    assert h["pqc_kex"] is True and h["findings"] and {k["type"] for k in h["host_keys"]} == {"ssh-ed25519", "ssh-rsa"}


def test_ssh_keys_lists_stored_keys(capsys, data_dir, engine):
    assert run_json(capsys, data_dir, "ssh", "keys") == []
    assert "no authorized keys" in run(capsys, data_dir, "ssh", "keys")


# ---- crypto -------------------------------------------------------------------------------------------

def test_crypto_scan_summary_and_cbom(capsys, data_dir, served, tmp_path):
    s, _ = served
    target = f"127.0.0.1:{s.port}"
    out = run(capsys, data_dir, "crypto", "scan", target, "--timeout", "3")
    assert target in out and "TLS versions: " in out and "TLSv1.3" in out and "PQC status:" in out

    j = run_json(capsys, data_dir, "crypto", "scan", target, "--timeout", "3")
    assert j["scanned"] == 1 and j["stored"] == 1
    [a] = j["assets"]
    assert a["target"] == target and "TLSv1.3" in a["protocol_versions"] and a["pqc"]["status"] and a["pqc"]["reasons"]

    summ = run_json(capsys, data_dir, "crypto", "summary")
    assert summ["total"] == 1 and sum(summ["by_status"].values()) == 1
    assert "1 assets" in run(capsys, data_dir, "crypto", "summary")

    dest = tmp_path / "cbom.json"
    main(["--data", str(data_dir), "crypto", "cbom", "-o", str(dest)])
    bom = json.loads(dest.read_text())
    assert bom["bomFormat"] == "CycloneDX" and bom["components"]
    assert json.loads(run(capsys, data_dir, "crypto", "cbom"))["bomFormat"] == "CycloneDX"


# ---- certificates and endpoints -----------------------------------------------------------------------

def test_certs_show(capsys, data_dir, engine, served):
    s, _ = served
    S = engine.store
    eid = S.upsert_endpoint({"name": "app", "host": "127.0.0.1", "port": s.port, "sni": "app.internal.test",
                             "common_name": "app.internal.test", "sans": ["app.internal.test"]})
    engine.observe(S.endpoint(eid))

    out = run(capsys, data_dir, "certs", "show", "app")
    assert "subject:     CN=app.internal.test" in out and "issuer:      CN=Farrier Local CA" in out
    assert "SANs:        app.internal.test" in out and "key:         EC 256 secp256r1" in out
    d = run_json(capsys, data_dir, "certs", "show", str(eid))
    assert d["endpoint_id"] == eid and d["common_name"] == "app.internal.test" and 8 <= d["days_left"] <= 9

    with pytest.raises(SystemExit) as e:
        main(["--data", str(data_dir), "certs", "show", "no-such-endpoint"])
    assert e.value.code == NOT_FOUND
    assert "no endpoint" in capsys.readouterr().err


def test_endpoints_approve_drops_the_discovered_tag(capsys, data_dir, engine):
    S = engine.store
    eid = S.upsert_endpoint({"name": "found", "host": "10.0.0.9", "port": 443, "connector": "manual",
                             "connector_config": {}, "tags": ["discovered", "edge"]})
    assert run_json(capsys, data_dir, "endpoints", "approve", "found") == {"ok": True, "endpoint_id": eid}
    assert S.endpoint(eid)["tags"] == ["edge"]
    assert any("approved for renewal by cli" in e["message"] for e in S.q("SELECT message FROM events"))

    with pytest.raises(SystemExit) as e:
        main(["--data", str(data_dir), "endpoints", "approve", "999999"])
    assert e.value.code == NOT_FOUND
